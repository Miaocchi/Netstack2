/**
 * @file runtime.cpp
 * @brief Runtime orchestration implementation.
 * @license GPL-3.0
 *
 * Start sequence:
 *   1. Validate config
 *   2. Create dispatcher
 *   3. Open queues from packet_io
 *   4. Create per-shard buffer pools (ADR-001 per-shard pool model)
 *   5. Inject each queue's pool via SetBufferPool (the pool belongs to the
 *      shard that owns the queue)
 *   6. Create shards (each with its own pool + queue)
 *   7. Set queue->shard mapping in dispatcher
 *   8. Start all shard threads (each shard sets SetOwnerThread in Run())
 *   9. Set recv handlers on queues (wake the owning shard)
 *  10. running_ = true
 *
 * Stop sequence:
 *   1. transition to Stopping and reject new work
 *   2. clear recv handlers and StopRx on every queue
 *   3. join shard threads after callback quiescence
 *   4. DrainTx on every queue before releasing any pool
 *   5. drain pool return queues and verify no outstanding leases
 *   6. destroy queues and pools only after all prior steps completed
 */

#include <core/runtime.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <core/dispatcher.h>
#include <core/shard.h>
#include <core/shard_lanes.h>

namespace tcpip2 {

namespace {

TcpHandshakeConfig MakeTcpConfig(const NetstackConfig& config) noexcept {
    TcpHandshakeConfig tcp;
    tcp.local_mss = config.tcp_mss;
    tcp.receive_window = config.initial_tcp_window;
    tcp.initial_rto_ms = config.rto_initial_ms;
    tcp.persist_timer_max_ms = config.persist_timeout_ms;
    tcp.persist_timer_base_ms = std::min<std::uint64_t>(500, config.persist_timeout_ms);
    tcp.timewait_ms = static_cast<std::uint32_t>(config.time_wait_ms);
    tcp.keepalive_ms = config.keepalive_ms;
    switch (config.tcp_cc) {
        case TcpCongestionAlgorithm::Bbr:
            tcp.cc_algorithm = CongestionAlgorithm::Bbr;
            break;
        case TcpCongestionAlgorithm::HybridBdpAimd:
            tcp.cc_algorithm = CongestionAlgorithm::HybridBdpAimd;
            break;
        case TcpCongestionAlgorithm::Kcc:
            tcp.cc_algorithm = CongestionAlgorithm::Kcc;
            tcp.kcc_turbo = config.kcc_turbo;
            tcp.kcc_ai_num = config.kcc_ai_num;
            tcp.kcc_ecn = config.kcc_ecn;
            tcp.kcc_kf_enable = config.kcc_kf_enable;
            break;
        default:
            tcp.cc_algorithm = CongestionAlgorithm::Aimd;
            break;
    }
    // Segment payload the TX pool can always carry; 0 if the pool slot is
    // too small to bound meaningfully.
    if (config.pool_slot_capacity > kIpTcpMaxHeaderOverhead) {
        const std::size_t cap = config.pool_slot_capacity - kIpTcpMaxHeaderOverhead;
        tcp.tx_payload_limit = cap < UINT16_MAX ? static_cast<std::uint16_t>(cap) : UINT16_MAX;
    }
    return tcp;
}

constexpr std::size_t kPacketLaneMessageCapacity = 1024;

std::size_t PacketLaneByteCapacity(const NetstackConfig& config) noexcept {
    if (config.pool_slot_capacity >
        std::numeric_limits<std::size_t>::max() / kPacketLaneMessageCapacity) {
        return std::numeric_limits<std::size_t>::max();
    }
    return config.pool_slot_capacity * kPacketLaneMessageCapacity;
}

std::size_t OutstandingTx(const std::vector<std::unique_ptr<IPacketQueue>>& queues) noexcept {
    std::size_t total = 0;
    for (const auto& queue : queues) {
        const std::size_t count = queue->OutstandingTx();
        if (count > std::numeric_limits<std::size_t>::max() - total) {
            return std::numeric_limits<std::size_t>::max();
        }
        total += count;
    }
    return total;
}

std::size_t OutstandingBuffers(
    const std::vector<std::unique_ptr<PktBufferPool>>& pools) noexcept {
    std::size_t total = 0;
    for (const auto& pool : pools) {
        const std::size_t count = pool->OutstandingCount();
        if (count > std::numeric_limits<std::size_t>::max() - total) {
            return std::numeric_limits<std::size_t>::max();
        }
        total += count;
    }
    return total;
}

} // namespace

Runtime::Runtime() noexcept = default;

Runtime::~Runtime() {
    StopOptions final_drain;
    final_drain.timeout_ms = 0;
    const StopResult result = Stop(final_drain);
    // Destruction may not free a pool still referenced by a backend. A backend
    // that cannot honor the unbounded final drain violates IPacketQueue.
    if (!result.IsComplete()) std::terminate();
}

bool Runtime::Start(NetstackConfig config, IPacketIo* packet_io) noexcept {
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (state_ != State::Stopped) return false;
        state_ = State::Starting;
    }

    bool started = false;
    if (config.Validate() && packet_io != nullptr &&
        packet_io->QueueCount() >= config.rx_queue_count) {
        RuntimeDependencies deps{};
        deps.packet_io = packet_io;
        // Legacy path keeps session_factory/clock/event_sink at their defaults.
        started = DoStart(config, deps);
    }

    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        state_ = started ? State::Running : State::Stopped;
    }
    lifecycle_cv_.notify_all();
    return started;
}

bool Runtime::Start(NetstackConfig config, const RuntimeDependencies& deps) noexcept {
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (state_ != State::Stopped) return false;
        state_ = State::Starting;
    }

    const bool started = config.Validate() && deps.Validate() &&
        deps.packet_io->QueueCount() >= config.rx_queue_count && DoStart(config, deps);
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        state_ = started ? State::Running : State::Stopped;
    }
    lifecycle_cv_.notify_all();
    return started;
}

bool Runtime::DoStart(NetstackConfig config, const RuntimeDependencies& deps) noexcept {
    shards_quiesced_ = false;
    config_ = config;
    packet_io_ = deps.packet_io;
    session_factory_ = deps.session_factory;
    clock_ = deps.clock ? deps.clock : DefaultClock();
    event_sink_ = deps.event_sink;

    // Step 1: Create dispatcher.
    dispatcher_ = std::unique_ptr<PacketDispatcher>(
        new PacketDispatcher(config.shard_count, config.rx_queue_count));

    // Step 2: Open queues.
    queues_.clear();
    queues_.reserve(config.rx_queue_count);
    for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
        auto q = packet_io_->OpenQueue(i);
        if (!q) {
            // Rollback.
            queues_.clear();
            dispatcher_.reset();
            return false;
        }
        queues_.push_back(std::move(q));
    }

    // Step 3: Create per-shard buffer pools. Each shard gets its own pool
    // so that Allocate()/ReturnBuffer() on the shard thread take the
    // lock-free fast path: the mutex is still acquired, but only the
    // owner shard thread contends for it (per-shard pool, ADR-001).
    // owner_thread_id_ is set in StackShard::Run().
    // Pool slots are not divided across shards: each shard gets the full
    // config_.pool_slot_count to avoid exhaustion under uneven load.
    shard_pools_.clear();
    shard_pools_.reserve(config.shard_count);
    for (std::size_t i = 0; i < config.shard_count; ++i) {
        shard_pools_.emplace_back(
            new PktBufferPool(config.pool_slot_count, config.pool_slot_capacity));
    }

    // Step 4: Inject the pool into each queue. Queue i maps to shard i
    // (or to the custom mapping); the pool must be the owning shard's pool
    // so that RX allocations are drained by the same shard.
    for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
        std::size_t owner_shard = i;
        if (!config.rx_queue_to_shard.empty()) {
            owner_shard = config.rx_queue_to_shard[i];
        }
        queues_[i]->SetBufferPool(shard_pools_[owner_shard].get());
    }

    // Step 5: Create shards. Each shard references its own pool, then receives
    // every RX queue explicitly mapped to it. Queue ownership is independent
    // from the queue index.
    std::vector<std::vector<IPacketQueue*>> shard_queues(config.shard_count);
    for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
        const std::size_t owner_shard = config.rx_queue_to_shard.empty()
            ? i
            : config.rx_queue_to_shard[i];
        shard_queues[owner_shard].push_back(queues_[i].get());
    }

    shards_.clear();
    shards_.reserve(config.shard_count);
    const TcpHandshakeConfig tcp_config = MakeTcpConfig(config);
    for (std::size_t i = 0; i < config.shard_count; ++i) {
        IPacketQueue* primary_queue = shard_queues[i].empty()
            ? nullptr
            : shard_queues[i].front();
        shards_.emplace_back(new StackShard(i, *shard_pools_[i], primary_queue, 1024,
                                              session_factory_, clock_, event_sink_, tcp_config));
        if (!shards_.back()->SetRxQueues(shard_queues[i])) {
            shards_.clear();
            shard_pools_.clear();
            queues_.clear();
            dispatcher_.reset();
            return false;
        }
    }

    // Step 6: Set queue->shard mapping.
    if (!config.rx_queue_to_shard.empty()) {
        for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
            dispatcher_->SetQueueShard(i, config.rx_queue_to_shard[i]);
        }
    }

    // Step 7: Give each shard only the TX queue pointers that it owns. Every
    // shard retains an index slot for every queue so flow-hash selection stays
    // deterministic, but a foreign queue has no callable pointer here.
    for (std::size_t shard_id = 0; shard_id < config.shard_count; ++shard_id) {
        std::vector<IPacketQueue*> tx_queues(config.rx_queue_count, nullptr);
        for (std::size_t queue_id = 0; queue_id < config.rx_queue_count; ++queue_id) {
            if (dispatcher_->QueueShard(queue_id) == shard_id) {
                tx_queues[queue_id] = queues_[queue_id].get();
            }
        }
        if (!shards_[shard_id]->SetTxQueues(tx_queues)) {
            shards_.clear();
            shard_pools_.clear();
            queues_.clear();
            dispatcher_.reset();
            return false;
        }
    }

    // Step 8: Create dedicated SPSC packet and egress lanes for every directed
    // shard pair. A target consumes each source lane independently; neither
    // packet direction uses an unsafe multi-producer SPSC inbox.
    try {
        packet_lanes_ = std::make_unique<ShardLanes>(
            config.shard_count, kPacketLaneMessageCapacity, PacketLaneByteCapacity(config));
        egress_lanes_ = std::make_unique<ShardEgressLanes>(
            config.shard_count, kPacketLaneMessageCapacity, PacketLaneByteCapacity(config));
        std::vector<StackShard*> shard_targets;
        shard_targets.reserve(shards_.size());
        for (const auto& shard : shards_) shard_targets.push_back(shard.get());

        for (std::size_t shard_id = 0; shard_id < config.shard_count; ++shard_id) {
            std::vector<ShardPacketLane*> inbound(config.shard_count, nullptr);
            std::vector<ShardPacketLane*> outbound(config.shard_count, nullptr);
            std::vector<ShardEgressLane*> inbound_egress(config.shard_count, nullptr);
            std::vector<ShardEgressLane*> outbound_egress(config.shard_count, nullptr);
            for (std::size_t peer = 0; peer < config.shard_count; ++peer) {
                inbound[peer] = packet_lanes_->Lane(peer, shard_id);
                outbound[peer] = packet_lanes_->Lane(shard_id, peer);
                inbound_egress[peer] = egress_lanes_->Lane(peer, shard_id);
                outbound_egress[peer] = egress_lanes_->Lane(shard_id, peer);
            }
            if (!shards_[shard_id]->SetPacketLanes(dispatcher_.get(), inbound, outbound,
                                                    shard_targets) ||
                !shards_[shard_id]->SetEgressLanes(inbound_egress, outbound_egress)) {
                egress_lanes_.reset();
                packet_lanes_.reset();
                shards_.clear();
                shard_pools_.clear();
                queues_.clear();
                dispatcher_.reset();
                return false;
            }
        }
    } catch (...) {
        egress_lanes_.reset();
        packet_lanes_.reset();
        shards_.clear();
        shard_pools_.clear();
        queues_.clear();
        dispatcher_.reset();
        return false;
    }

    // Step 9: Start all shard threads.
    for (auto& shard : shards_) {
        if (!shard->Start()) {
            // Roll back any shards that were already started before the
            // failure so the caller does not get a partially running runtime.
            for (auto& started : shards_) {
                if (started.get() == shard.get()) break;
                started->Stop();
            }
            // Clear queue recv handlers so they cannot wake a shard we are
            // about to discard; clear remaining resources.
            for (auto& q : queues_) {
                q->SetRecvHandler(nullptr);
            }
            shards_.clear();
            egress_lanes_.reset();
            packet_lanes_.reset();
            shard_pools_.clear();
            queues_.clear();
            dispatcher_.reset();
            return false;
        }
    }

    // Step 10: Set recv handlers — wake the owning shard.
    for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
        const std::size_t owner_shard = dispatcher_->QueueShard(i);
        StackShard* target = shards_[owner_shard].get();
        queues_[i]->SetRecvHandler([target]() { target->Wake(); });
    }

    return true;
}

bool Runtime::IsRunning() const noexcept {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    return state_ == State::Running;
}

bool Runtime::IsStopping() const noexcept {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    return state_ == State::Stopping;
}

StopResult Runtime::Stop(const StopOptions& options) noexcept {
    {
        std::unique_lock<std::mutex> lock(lifecycle_mutex_);
        bool waited_for_stop = false;
        while (state_ == State::Starting || stop_in_progress_) {
            if (stop_in_progress_) waited_for_stop = true;
            lifecycle_cv_.wait(lock);
        }
        if (waited_for_stop) return last_stop_result_;
        if (state_ == State::Stopped) return StopResult{};
        state_ = State::Stopping;
        stop_in_progress_ = true;
    }

    const StopResult result = DoStop(options);

    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        last_stop_result_ = result;
        state_ = result.IsComplete() ? State::Stopped : State::Stopping;
        stop_in_progress_ = false;
    }
    lifecycle_cv_.notify_all();
    return result;
}

StopResult Runtime::DoStop(const StopOptions& options) noexcept {
    QuiesceShards();
    return DrainTxAndFinalize(options);
}

void Runtime::QuiesceShards() noexcept {
    if (shards_quiesced_) return;

    // Clear event callbacks before StopRx so backend wakeups cannot race the
    // shard teardown. StopRx also prevents any new RX lease from being issued.
    for (auto& q : queues_) {
        q->SetRecvHandler(nullptr);
        q->StopRx();
    }

    // StackShard::Stop joins after TcpHandshakeEngine::Shutdown has deactivated
    // and cleared all session callbacks.
    for (auto& shard : shards_) {
        shard->Stop();
    }

    // Destroy lane and shard-owned envelopes while their source pools still
    // exist. This releases RX redirects and egress handoffs not consumed before
    // a target shard observed its stop message.
    egress_lanes_.reset();
    packet_lanes_.reset();
    shards_.clear();
    shards_quiesced_ = true;
}

StopResult Runtime::DrainTxAndFinalize(const StopOptions& options) noexcept {
    const bool bounded = options.timeout_ms != 0;
    const auto started_at = std::chrono::steady_clock::now();
    const auto max_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::time_point::max() - started_at).count();
    const std::uint64_t timeout_ms = bounded && max_timeout > 0
        ? std::min(options.timeout_ms, static_cast<std::uint64_t>(max_timeout))
        : 0;
    const auto deadline = bounded
        ? started_at + std::chrono::milliseconds(timeout_ms)
        : std::chrono::steady_clock::time_point::max();

    for (;;) {
        IoError first_error = IoError::None;
        std::size_t first_error_queue = std::numeric_limits<std::size_t>::max();
        bool fatal_error = false;

        for (const auto& queue : queues_) {
            std::uint64_t remaining_ms = 0;
            if (bounded) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline) {
                    StopResult result;
                    result.status = StopStatus::TimedOut;
                    result.drain_error = first_error == IoError::None
                        ? IoError::WouldBlock : first_error;
                    result.queue_id = first_error_queue;
                    result.outstanding_tx = OutstandingTx(queues_);
                    return result;
                }
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now).count();
                remaining_ms = remaining <= 0 ? 1 : static_cast<std::uint64_t>(remaining);
            }

            const IoError error = queue->DrainTx(remaining_ms);
            const std::size_t pending = queue->OutstandingTx();
            if (error != IoError::None && first_error == IoError::None) {
                first_error = error;
                first_error_queue = queue->QueueId();
            }
            if (pending != 0 && error != IoError::None && error != IoError::WouldBlock) {
                fatal_error = true;
            }
        }

        const std::size_t pending_tx = OutstandingTx(queues_);
        if (pending_tx == 0) {
            return FinalizeResources(first_error, first_error_queue);
        }

        if (fatal_error) {
            StopResult result;
            result.status = StopStatus::DrainFailed;
            result.drain_error = first_error;
            result.queue_id = first_error_queue;
            result.outstanding_tx = pending_tx;
            return result;
        }

        if (bounded && std::chrono::steady_clock::now() >= deadline) {
            StopResult result;
            result.status = StopStatus::TimedOut;
            result.drain_error = first_error == IoError::None
                ? IoError::WouldBlock : first_error;
            result.queue_id = first_error_queue;
            result.outstanding_tx = pending_tx;
            return result;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

StopResult Runtime::FinalizeResources(IoError drain_error, std::size_t queue_id) noexcept {
    for (auto& pool : shard_pools_) {
        pool->DrainReturnQueue();
    }

    const std::size_t outstanding_before_queue_destroy = OutstandingBuffers(shard_pools_);
    if (outstanding_before_queue_destroy != 0) {
        StopResult result;
        result.status = StopStatus::DrainFailed;
        result.drain_error = drain_error == IoError::None ? IoError::Internal : drain_error;
        result.queue_id = queue_id;
        result.outstanding_buffers = outstanding_before_queue_destroy;
        return result;
    }

    // Queues can only be destroyed after every accepted TX lease was returned.
    queues_.clear();
    for (auto& pool : shard_pools_) {
        pool->DrainReturnQueue();
    }

    const std::size_t outstanding_after_queue_destroy = OutstandingBuffers(shard_pools_);
    if (outstanding_after_queue_destroy != 0) {
        StopResult result;
        result.status = StopStatus::DrainFailed;
        result.drain_error = drain_error == IoError::None ? IoError::Internal : drain_error;
        result.queue_id = queue_id;
        result.outstanding_buffers = outstanding_after_queue_destroy;
        return result;
    }

    shard_pools_.clear();
    dispatcher_.reset();
    packet_io_ = nullptr;
    session_factory_ = nullptr;
    clock_ = nullptr;
    event_sink_ = nullptr;
    shards_quiesced_ = false;

    StopResult result;
    result.drain_error = drain_error;
    result.queue_id = queue_id;
    return result;
}

StackShard* Runtime::Shard(std::size_t i) const noexcept {
    if (i >= shards_.size()) return nullptr;
    return shards_[i].get();
}

PktBufferPool* Runtime::ShardPool(std::size_t i) const noexcept {
    if (i >= shard_pools_.size()) return nullptr;
    return shard_pools_[i].get();
}

} // namespace tcpip2
