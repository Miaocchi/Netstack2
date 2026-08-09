/**
 * @file shard.cpp
 * @brief StackShard event loop implementation.
 * @license GPL-3.0
 *
 * The shard thread runs the 10-step event loop from IMPLEMENTATION_GUIDE §5.2:
 *   1. DrainReturnQueue — return foreign-thread buffer releases to the free list
 *   2. RX batch — poll the local queue (if any)
 *   3. Drain packet inbox (SPSC) — redirected packets from other shards
 *   4. Drain control inbox (MPSC) — check for StopMessage first
 *   5. Advance timers
 *   6. Protocol work (noop — future TCP engine)
 *   7. Pacing/FQ (noop)
 *   8. Send TX batch (noop — future TX path)
 *   9. Publish counters (noop)
 *  10. Wait — sleep 1ms or block on the control inbox with timeout
 *
 * Stop() is idempotent and must not be called from the shard thread itself
 * (that would deadlock on join). A kStop message posted to the control inbox
 * causes the loop to exit cleanly.
 */

#include <core/shard.h>

#include <chrono>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <utility>

#include <tcp/handshake.h>
#include <tcp/input.h>
#include <tcp/isn.h>
#include <tcp/output.h>

namespace tcpip2 {

namespace {

std::uint64_t MonotonicNowMs() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace

StackShard::StackShard(std::size_t shard_id, PktBufferPool& pool, IPacketQueue* queue,
                       std::size_t inbox_capacity) noexcept
    : shard_id_(shard_id),
      pool_(pool),
      queue_(queue),
      packet_inbox_(inbox_capacity),
      control_inbox_(inbox_capacity),
      timer_(256) {}

StackShard::~StackShard() {
    Stop();
}

bool StackShard::Start() noexcept {
    if (running_.load(std::memory_order_relaxed)) return false;
    std::array<std::uint64_t, 2> isn_secret{};
    if (!LoadTcpIsnSecret(isn_secret)) return false;
    ++tcp_engine_epoch_;
    if (tcp_engine_epoch_ == 0) ++tcp_engine_epoch_;
    try {
        tcp_ = std::make_unique<TcpHandshakeEngine>(
            TcpHandshakeConfig{}, TcpIsnGenerator(isn_secret), timer_,
            tcp_engine_epoch_);
        tcp_tx_.reserve(kTcpTxBudget);
    } catch (...) {
        tcp_.reset();
        return false;
    }
    stop_requested_.store(false, std::memory_order_relaxed);
    running_.store(true, std::memory_order_relaxed);
    try {
        thread_ = std::thread([this] { Run(); });
    } catch (...) {
        running_.store(false, std::memory_order_relaxed);
        tcp_.reset();
        return false;
    }
    return true;
}

void StackShard::Stop() noexcept {
    // Must not be called from the shard thread — that would deadlock on join.
    if (ownership_.IsOwner()) {
        std::fprintf(stderr, "tcpip2: Stop() called from shard thread (would deadlock)\n");
        std::abort();
    }
    if (!running_.load(std::memory_order_relaxed)) return;

    // Post a stop message to the control inbox.
    ShardMessage msg;
    msg.type = ShardMessageType::kStop;
    if (!control_inbox_.Push(std::move(msg))) {
        stop_requested_.store(true, std::memory_order_relaxed);
    }
    control_inbox_.Wake();

    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false, std::memory_order_release);
    tcp_.reset();
}

bool StackShard::PostMessage(ShardMessage&& msg) noexcept {
    if (!running_.load(std::memory_order_relaxed)) return false;
    return control_inbox_.Push(std::move(msg));
}

bool StackShard::PostPacket(BufferLease&& lease) noexcept {
    if (!running_.load(std::memory_order_relaxed)) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (packet_inbox_.Push(std::move(lease))) return true;
    packets_dropped_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

void StackShard::Run() noexcept {
    ownership_.SetOwner();
    // Reassign the pool's owner thread to this shard thread so that
    // Allocate()/ReturnBuffer() take the owner-local uncontended fast
    // path (ADR-001): the mutex is still acquired, but only this shard
    // thread contends for it on the hot path.
    pool_.SetOwnerThread(std::this_thread::get_id());
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        EventLoopIteration();
    }
    if (tcp_) tcp_->Shutdown();
    tcp_tx_.clear();
    tcp_pcb_count_.store(0, std::memory_order_relaxed);
    tcp_half_open_count_.store(0, std::memory_order_relaxed);
    // Final drain so foreign-thread buffer releases are cleaned up.
    pool_.DrainReturnQueue();
    ownership_.ClearOwner();
}

void StackShard::EventLoopIteration() noexcept {
    const std::uint64_t now_ms = MonotonicNowMs();

    // Step 1: DrainReturnQueue — recycle foreign-thread releases.
    pool_.DrainReturnQueue();

    // Step 2: RX batch from the local queue (if any).
    if (queue_ != nullptr) {
        BufferLease rx[kRxBudget];
        IoError error = IoError::None;
        const std::size_t n = queue_->RecvBatch(rx, kRxBudget, error);
        for (std::size_t i = 0; i < n; ++i) {
            packets_received_.fetch_add(1, std::memory_order_relaxed);
            ProcessPacket(std::move(rx[i]), now_ms);
        }
    }

    // Step 3: Drain packet inbox (SPSC) — redirected packets.
    for (std::size_t i = 0; i < kPacketInboxBudget; ++i) {
        BufferLease lease;
        if (!packet_inbox_.Pop(lease)) break;
        packets_received_.fetch_add(1, std::memory_order_relaxed);
        ProcessPacket(std::move(lease), now_ms);
    }

    // Step 4: Drain control inbox (MPSC). Check for StopMessage first.
    for (std::size_t i = 0; i < kControlInboxBudget; ++i) {
        ShardMessage msg;
        if (!control_inbox_.Pop(msg)) break;
        if (msg.type == ShardMessageType::kStop) {
            stop_requested_.store(true, std::memory_order_relaxed);
            // Release any carried data.
            msg.data.Reset();
            break;
        }
        if (msg.type == ShardMessageType::kSessionWritable && tcp_) {
            const TcpHandshakeResult writable = tcp_->OnSessionWritable(
                msg.flow_id, msg.generation, now_ms);
            if (writable.response.valid && !EnqueueTcpResponse(writable.response)) {
                tcp_->DeferResponse(writable.response);
            }
        }
        if (msg.type == ShardMessageType::kSessionClosed && tcp_) {
            tcp_->OnSessionClosed(msg.flow_id, msg.generation);
        }
        if (msg.type == ShardMessageType::kFlowClose && tcp_) {
            tcp_->CloseFlow(msg.flow_id, msg.generation);
        }
        if (msg.type == ShardMessageType::kFlowAbort && tcp_) {
            tcp_->AbortFlow(msg.flow_id, msg.generation);
        }
        messages_processed_.fetch_add(1, std::memory_order_relaxed);
        // Release any carried data.
        msg.data.Reset();
    }

    if (stop_requested_.load(std::memory_order_relaxed)) return;

    // Step 5: advance timers, then drain bounded retry/control output.
    timer_.AdvanceTo(now_ms);
    if (tcp_) {
        tcp_->PumpSessionDeliveries(now_ms, kControlInboxBudget);
        TcpResponse response;
        while (tcp_tx_.size() < kTcpTxBudget &&
               tcp_->PopPendingResponse(response)) {
            if (!EnqueueTcpResponse(response)) {
                tcp_->DeferResponse(response);
                break;
            }
        }
        tcp_pcb_count_.store(tcp_->PcbCount(), std::memory_order_relaxed);
        tcp_half_open_count_.store(tcp_->HalfOpenCount(), std::memory_order_relaxed);
    }

    // Step 7: pump TCP send paths (new data, retransmissions, persist probes).
    if (tcp_) {
        PumpTcpSendPaths(now_ms);
    }

    // Step 8: submit the bounded TCP control batch. Partial-send tails remain owned.
    FlushTcpTx();

    // Step 10: Wait — block on the control inbox with a short timeout.
    // This keeps the shard responsive to control messages while avoiding
    // a busy spin when there is no RX work.
    if (!stop_requested_.load(std::memory_order_relaxed)) {
        control_inbox_.Wait(1);
    }
}

void StackShard::ProcessPacket(BufferLease&& lease, std::uint64_t now_ms) noexcept {
    if (!lease || !tcp_) return;
    const TcpInputResult input = ParseIpTcpPacket(lease.Data(), lease.Size());
    if (input.error != TcpInputError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const TcpHandshakeResult result = tcp_->OnSegment(input.segment, now_ms);
    if (result.error != TcpHandshakeError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.response.valid && !EnqueueTcpResponse(result.response)) {
        tcp_->DeferResponse(result.response);
    }
}

bool StackShard::EnqueueTcpResponse(const TcpResponse& response) noexcept {
    if (queue_ == nullptr || tcp_tx_.size() >= kTcpTxBudget) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    BufferLease lease = pool_.Allocate();
    if (!lease) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    const TcpOutputResult output = BuildTcpControlPacket(
        response, lease.Data(), lease.Capacity());
    if (output.error != TcpOutputError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    lease.Resize(output.packet_length);
    try {
        tcp_tx_.push_back(std::move(lease));
    } catch (...) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

void StackShard::PumpTcpSendPaths(std::uint64_t now_ms) noexcept {
    if (!tcp_ || tcp_tx_.size() >= kTcpTxBudget) return;
    const std::size_t remaining = kTcpTxBudget - tcp_tx_.size();
    tcp_->PumpSendPaths(now_ms, kControlInboxBudget, pool_, tcp_tx_, remaining);
}

void StackShard::FlushTcpTx() noexcept {
    if (queue_ == nullptr || tcp_tx_.empty()) return;
    IoError error = IoError::None;
    std::size_t sent = queue_->SendBatch(tcp_tx_.data(), tcp_tx_.size(), error);
    if (sent > tcp_tx_.size()) sent = tcp_tx_.size();
    if (sent > 0) {
        for (std::size_t i = sent; i < tcp_tx_.size(); ++i) {
            tcp_tx_[i - sent] = std::move(tcp_tx_[i]);
        }
        tcp_tx_.resize(tcp_tx_.size() - sent);
    }
    if (error != IoError::None && error != IoError::WouldBlock) {
        packets_dropped_.fetch_add(tcp_tx_.size(), std::memory_order_relaxed);
        tcp_tx_.clear();
    }
}

} // namespace tcpip2
