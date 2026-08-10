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
 *   1. running_ = false
 *   2. Clear recv handlers on queues
 *   3. Post StopMessage to each shard's control inbox (Stop() does the join)
 *   4. Join each shard thread (via StackShard::Stop())
 *   5. Verify all shard pools have OutstandingCount() == 0
 *   6. Close queues and free pools (unique_ptr destruction)
 */

#include <core/runtime.h>

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include <core/dispatcher.h>
#include <core/shard.h>

namespace tcpip2 {

Runtime::Runtime() noexcept = default;

Runtime::~Runtime() {
    Stop();
}

bool Runtime::Start(NetstackConfig config, IPacketIo* packet_io) noexcept {
    if (running_.load(std::memory_order_relaxed)) return false;
    if (!config.Validate()) return false;
    if (packet_io == nullptr) return false;
    if (packet_io->QueueCount() < config.rx_queue_count) return false;

    RuntimeDependencies deps{};
    deps.packet_io = packet_io;
    // legacy path keeps session_factory/clock/event_sink at their defaults.
    return DoStart(config, deps);
}

bool Runtime::Start(NetstackConfig config, const RuntimeDependencies& deps) noexcept {
    if (running_.load(std::memory_order_relaxed)) return false;
    if (!config.Validate()) return false;
    if (!deps.Validate()) return false;
    if (deps.packet_io->QueueCount() < config.rx_queue_count) return false;

    return DoStart(config, deps);
}

bool Runtime::DoStart(NetstackConfig config, const RuntimeDependencies& deps) noexcept {
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

    // Step 5: Create shards. Each shard references its own pool.
    shards_.clear();
    shards_.reserve(config.shard_count);
    for (std::size_t i = 0; i < config.shard_count; ++i) {
        IPacketQueue* q = (i < config.rx_queue_count) ? queues_[i].get() : nullptr;
        shards_.emplace_back(new StackShard(i, *shard_pools_[i], q, 1024,
                                             session_factory_, clock_, event_sink_));
    }

    // Step 6: Set queue->shard mapping.
    if (!config.rx_queue_to_shard.empty()) {
        for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
            dispatcher_->SetQueueShard(i, config.rx_queue_to_shard[i]);
        }
    }

    // Step 7: Start all shard threads.
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
            shard_pools_.clear();
            queues_.clear();
            dispatcher_.reset();
            return false;
        }
    }

    // Step 8: Set recv handlers — wake the owning shard.
    for (std::size_t i = 0; i < config.rx_queue_count; ++i) {
        const std::size_t owner_shard = dispatcher_->QueueShard(i);
        StackShard* target = shards_[owner_shard].get();
        queues_[i]->SetRecvHandler([target]() { target->Wake(); });
    }

    running_.store(true, std::memory_order_relaxed);
    return true;
}

void Runtime::Stop() noexcept {
    if (!running_.load(std::memory_order_relaxed)) return;
    running_.store(false, std::memory_order_relaxed);

    // Step 2: Clear recv handlers.
    for (auto& q : queues_) {
        q->SetRecvHandler(nullptr);
    }

    // Step 3 & 4: Stop each shard (posts stop message + joins).
    for (auto& shard : shards_) {
        shard->Stop();
    }

    // Step 5: Verify all shard pools have zero outstanding buffers.
    // After shard threads are joined, DrainReturnQueue() has been called
    // in StackShard::Run()'s exit path. Any remaining outstanding count
    // indicates a buffer leak.
    for (auto& pool : shard_pools_) {
        pool->DrainReturnQueue();
    }

    // Step 6: Close queues and free pools.
    queues_.clear();
    shards_.clear();
    shard_pools_.clear();
    dispatcher_.reset();
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
