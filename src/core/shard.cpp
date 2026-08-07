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
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace tcpip2 {

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
    stop_requested_.store(false, std::memory_order_relaxed);
    running_.store(true, std::memory_order_relaxed);
    thread_ = std::thread([this] { Run(); });
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
    control_inbox_.Push(std::move(msg));
    control_inbox_.Wake();

    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false, std::memory_order_relaxed);
}

bool StackShard::PostMessage(ShardMessage&& msg) noexcept {
    return control_inbox_.Push(std::move(msg));
}

bool StackShard::PostPacket(BufferLease&& lease) noexcept {
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
    // Final drain so foreign-thread buffer releases are cleaned up.
    pool_.DrainReturnQueue();
    ownership_.ClearOwner();
}

void StackShard::EventLoopIteration() noexcept {
    // Step 1: DrainReturnQueue — recycle foreign-thread releases.
    pool_.DrainReturnQueue();

    // Step 2: RX batch from the local queue (if any).
    if (queue_ != nullptr) {
        BufferLease rx[kRxBudget];
        IoError error = IoError::None;
        const std::size_t n = queue_->RecvBatch(rx, kRxBudget, error);
        for (std::size_t i = 0; i < n; ++i) {
            // Count the packet; the future TCP engine will parse headers here.
            packets_received_.fetch_add(1, std::memory_order_relaxed);
            // Release immediately — no protocol work yet.
            rx[i].Reset();
        }
    }

    // Step 3: Drain packet inbox (SPSC) — redirected packets.
    for (std::size_t i = 0; i < kPacketInboxBudget; ++i) {
        BufferLease lease;
        if (!packet_inbox_.Pop(lease)) break;
        packets_received_.fetch_add(1, std::memory_order_relaxed);
        // No protocol work yet — release immediately.
        lease.Reset();
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
        messages_processed_.fetch_add(1, std::memory_order_relaxed);
        // Release any carried data.
        msg.data.Reset();
    }

    // Step 5: Advance timers (no real clock — noop for now).
    // Step 6-9: Noop (protocol, pacing, TX, counters publish).
    (void)timer_;

    // Step 10: Wait — block on the control inbox with a short timeout.
    // This keeps the shard responsive to control messages while avoiding
    // a busy spin when there is no RX work.
    if (!stop_requested_.load(std::memory_order_relaxed)) {
        control_inbox_.Wait(1);
    }
}

} // namespace tcpip2
