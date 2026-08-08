#pragma once

/**
 * @file shard.h
 * @brief Typed inter-thread message and StackShard runtime for Netstack2.
 * @license GPL-3.0
 *
 * Internal header (not public API). Cross-thread communication is limited to
 * ShardMessage values: no arbitrary closures, no flow pointers escape, so the
 * single-ownership invariant cannot be bypassed.
 *
 * StackShard (NETSTACK2-004) owns a dedicated thread that runs the event loop
 * described in IMPLEMENTATION_GUIDE §5.2. Packets arrive via the SPSC inbox
 * (redirected from another shard's queue) or via the local RX queue. Control
 * messages arrive via the MPSC inbox. The shard is the sole owner of all
 * per-flow state on its thread.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/transport_session.h>

#include <core/inbox_mpsc.h>
#include <core/inbox_spsc.h>
#include <core/shard_message.h>
#include <core/thread_ownership.h>
#include <core/timer_wheel.h>

namespace tcpip2 {

class TcpHandshakeEngine;
struct TcpResponse;

class StackShard {
public:
    StackShard(std::size_t shard_id, PktBufferPool& pool, IPacketQueue* queue,
               std::size_t inbox_capacity = 1024) noexcept;
    ~StackShard();

    StackShard(const StackShard&) = delete;
    StackShard& operator=(const StackShard&) = delete;

    /** Start the shard thread. Returns false if already running. */
    bool Start() noexcept;

    /** Post a stop message and join. Idempotent. Must not be called from shard thread. */
    void Stop() noexcept;

    /** Post a message to the control inbox (any thread). */
    bool PostMessage(ShardMessage&& msg) noexcept;

    /** Post a packet to the SPSC inbox (producer thread). */
    bool PostPacket(BufferLease&& lease) noexcept;

    std::size_t ShardId() const noexcept { return shard_id_; }
    bool IsRunning() const noexcept { return running_.load(std::memory_order_relaxed); }
    bool IsShardThread() const noexcept { return ownership_.IsOwner(); }

    /** Wake the shard's control inbox wait (e.g. from a recv handler). */
    void Wake() noexcept { control_inbox_.Wake(); }

    // Counters (atomic: written on the shard thread, read from any thread)
    std::size_t PacketsReceived() const noexcept {
        return packets_received_.load(std::memory_order_relaxed);
    }
    std::size_t PacketsDropped() const noexcept {
        return packets_dropped_.load(std::memory_order_relaxed);
    }
    std::size_t MessagesProcessed() const noexcept {
        return messages_processed_.load(std::memory_order_relaxed);
    }
    std::size_t TcpPcbCount() const noexcept {
        return tcp_pcb_count_.load(std::memory_order_relaxed);
    }
    std::size_t TcpHalfOpenCount() const noexcept {
        return tcp_half_open_count_.load(std::memory_order_relaxed);
    }

    // Budgets
    static constexpr std::size_t kRxBudget = 64;
    static constexpr std::size_t kPacketInboxBudget = 64;
    static constexpr std::size_t kControlInboxBudget = 256;
    static constexpr std::size_t kTcpTxBudget = 64;

private:
    void Run() noexcept;
    void EventLoopIteration() noexcept;
    void ProcessPacket(BufferLease&& lease, std::uint64_t now_ms) noexcept;
    bool EnqueueTcpResponse(const TcpResponse& response) noexcept;
    void FlushTcpTx() noexcept;

    std::size_t shard_id_;
    PktBufferPool& pool_;
    IPacketQueue* queue_;  // may be nullptr for test
    InboxSpsc packet_inbox_;
    InboxMpsc control_inbox_;
    ThreadOwnershipGuard ownership_;
    TimerWheel timer_;
    std::unique_ptr<TcpHandshakeEngine> tcp_;
    std::vector<BufferLease> tcp_tx_;

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};

    // Counters (atomic: written on the shard thread, read from any thread)
    std::atomic<std::size_t> packets_received_{0};
    std::atomic<std::size_t> packets_dropped_{0};
    std::atomic<std::size_t> messages_processed_{0};
    std::atomic<std::size_t> tcp_pcb_count_{0};
    std::atomic<std::size_t> tcp_half_open_count_{0};
};

} // namespace tcpip2
