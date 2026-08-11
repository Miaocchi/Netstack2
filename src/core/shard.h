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
#include <tcpip2/clock.h>
#include <tcpip2/events.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/transport_session.h>

#include <core/inbox_mpsc.h>
#include <core/inbox_spsc.h>
#include <core/packet_envelope.h>
#include <core/shard_message.h>
#include <core/shard_lanes.h>
#include <core/thread_ownership.h>
#include <core/timer_wheel.h>
#include <ip/fragment.h>
#include <ip/icmpv4.h>
#include <ip/icmpv6.h>
#include <ip/pmtu.h>
#include <udp/input.h>

#include <tcp/fq_codel.h>
#include <tcp/handshake.h>

namespace tcpip2 {

class TcpHandshakeEngine;
class PacketDispatcher;
struct TcpSegmentView;
struct TcpResponse;

class StackShard {
public:
    StackShard(std::size_t shard_id, PktBufferPool& pool, IPacketQueue* queue,
                std::size_t inbox_capacity = 1024,
                ISessionFactory* session_factory = nullptr,
                IClock* clock = nullptr,
                IEventSink* event_sink = nullptr,
                TcpHandshakeConfig tcp_config = {}) noexcept;
    ~StackShard();

    StackShard(const StackShard&) = delete;
    StackShard& operator=(const StackShard&) = delete;

    /** Start the shard thread. Returns false if already running. */
    bool Start() noexcept;

    /** Post a stop message and join. Idempotent. Must not be called from shard thread. */
    void Stop() noexcept;

    /** Post a message to the control inbox (any thread). */
    bool PostMessage(ShardMessage&& msg) noexcept;

    /** Post a packet to the legacy single-producer inbox (test-only). */
    bool PostPacket(BufferLease&& lease) noexcept;

    /**
     * Assign the RX queues polled by this shard before Start(). An empty list
     * leaves the constructor-supplied queue in place for legacy unit tests.
     */
    bool SetRxQueues(const std::vector<IPacketQueue*>& queues) noexcept;

    /** Configure dedicated source->target packet lanes before Start(). */
    bool SetPacketLanes(PacketDispatcher* dispatcher,
                        const std::vector<ShardPacketLane*>& inbound,
                        const std::vector<ShardPacketLane*>& outbound,
                        const std::vector<StackShard*>& targets) noexcept;

    /**
     * Configure queue-owner-only TX access before Start(). Entries for queues
     * owned by another shard must be null; their packets use egress lanes.
     */
    bool SetTxQueues(const std::vector<IPacketQueue*>& queues) noexcept;

    /** Configure dedicated protocol-owner -> queue-owner TX lanes before Start(). */
    bool SetEgressLanes(const std::vector<ShardEgressLane*>& inbound,
                        const std::vector<ShardEgressLane*>& outbound) noexcept;

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
    std::size_t UdpDatagramsReceived() const noexcept {
        return udp_datagrams_received_.load(std::memory_order_relaxed);
    }
    std::size_t RedirectedPackets() const noexcept {
        return redirected_packets_.load(std::memory_order_relaxed);
    }
    std::size_t RedirectDrops() const noexcept {
        return redirect_drops_.load(std::memory_order_relaxed);
    }
    const TcpHandshakeConfig& TcpConfig() const noexcept { return tcp_config_; }

    /// Look up the cached PMTU for a destination.
    PmtuLookupResult LookupPmtu(const std::uint8_t* dst_ip, std::uint8_t ip_version,
                                std::uint64_t now_ms) const noexcept {
        return pmtu_cache_.Lookup(dst_ip, ip_version, now_ms);
    }

    // Budgets
    static constexpr std::size_t kRxBudget = 64;
    static constexpr std::size_t kPacketInboxBudget = 64;
    static constexpr std::size_t kControlInboxBudget = 256;
    static constexpr std::size_t kTcpTxBudget = 64;
    static constexpr std::size_t kRemoteReceiveLowWatermarkDivisor = 2;

private:
    void Run() noexcept;
    void EventLoopIteration() noexcept;
    void RouteRxPacket(BufferLease&& lease, std::uint64_t now_ms) noexcept;
    void ProcessPacket(BufferLease&& lease, std::uint64_t now_ms) noexcept;
    void ProcessEnvelope(PacketEnvelope&& envelope, std::uint64_t now_ms) noexcept;
    void ProcessTcpSegment(const TcpSegmentView& segment, std::uint64_t now_ms) noexcept;
    void HandleFragment(const std::uint8_t* packet, std::size_t length,
                         std::uint64_t now_ms) noexcept;
    void HandleIcmp(const std::uint8_t* packet, std::size_t length,
                    std::uint64_t now_ms) noexcept;
    void HandleUdp(BufferLease&& lease, std::uint64_t now_ms) noexcept;
    void HandleReassembledUdp(const IpAddress& source, const IpAddress& destination,
                               BufferLease&& lease) noexcept;
    bool RedirectPacket(std::size_t target_shard, PacketEnvelope&& envelope) noexcept;
    bool EnqueueTcpResponse(const TcpResponse& response) noexcept;
    void DrainEgressLanes() noexcept;
    bool RouteEgressPacket(const FqCoDelPacket& packet) noexcept;
    void FlushTcpTx() noexcept;
    void PumpTcpSendPaths(std::uint64_t now_ms) noexcept;

    std::size_t shard_id_;
    PktBufferPool& pool_;
    // Primary egress queue and legacy single-RX fallback; may be nullptr for tests.
    IPacketQueue* queue_;
    std::vector<IPacketQueue*> rx_queues_;
    std::size_t next_rx_queue_ = 0;
    PacketDispatcher* dispatcher_ = nullptr;
    std::vector<ShardPacketLane*> inbound_lanes_;
    std::vector<ShardPacketLane*> outbound_lanes_;
    std::vector<StackShard*> redirect_targets_;
    std::size_t next_inbound_lane_ = 0;
    // Indexed by queue id. Only queues owned by this shard are non-null.
    std::vector<IPacketQueue*> tx_queues_;
    std::vector<ShardEgressLane*> inbound_egress_lanes_;
    std::vector<ShardEgressLane*> outbound_egress_lanes_;
    std::size_t next_inbound_egress_lane_ = 0;
    ISessionFactory* session_factory_;  // may be nullptr (legacy Start)
    IClock* clock_;  // never null after construction (defaults to DefaultClock)
    IEventSink* event_sink_;  // may be nullptr (events silently dropped)
    TcpHandshakeConfig tcp_config_;
    InboxSpsc packet_inbox_;
    InboxMpsc control_inbox_;
    ThreadOwnershipGuard ownership_;
    TimerWheel timer_;
    std::unique_ptr<TcpHandshakeEngine> tcp_;
    FragmentReassembler reassembler_;
    PmtuCache pmtu_cache_;
    FqCoDelScheduler fq_codel_;
    std::vector<BufferLease> tcp_tx_;
    // A partially accepted remote-data message stays here until its tail can
    // enter the TCP send buffer. It remains bounded by one mailbox item.
    ShardMessage deferred_session_data_;

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::uint64_t tcp_engine_epoch_ = 0;
    std::uint64_t last_metric_snapshot_ms_ = 0;

    // Counters (atomic: written on the shard thread, read from any thread)
    std::atomic<std::size_t> packets_received_{0};
    std::atomic<std::size_t> packets_dropped_{0};
    std::atomic<std::size_t> messages_processed_{0};
    std::atomic<std::size_t> tcp_pcb_count_{0};
    std::atomic<std::size_t> tcp_half_open_count_{0};
    std::atomic<std::size_t> udp_datagrams_received_{0};
    std::atomic<std::size_t> redirected_packets_{0};
    std::atomic<std::size_t> redirect_drops_{0};
};

} // namespace tcpip2
