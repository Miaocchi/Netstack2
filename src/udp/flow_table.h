#pragma once

/**
 * @file flow_table.h
 * @brief Shard-local UDP flow table (R7).
 * @license GPL-3.0
 *
 * Tracks UDP flows by 4-tuple. On the first client datagram it opens the
 * adapter session via ISessionFactory::OpenUdp() (the returned void* handle is
 * an IDatagramSession* owned by the adapter), installs the remote-data and
 * closed callbacks, and forwards each client datagram to the remote session.
 *
 * Session callbacks may fire on the adapter's thread, so they never touch flow
 * state directly: they post a kUdpSessionData / kUdpSessionClosed message to
 * the owning shard's control inbox. The shard processes those on its thread by
 * calling OnRemoteData() / OnFlowClosed(), which use the shard-provided egress
 * emitter (serializing through the shared FQ-CoDel scheduler).
 *
 * Bounds: capacity + idle-timeout eviction. Single-threaded for the shard-side
 * methods (OnClientDatagram / OnRemoteData / PurgeExpired / Shutdown).
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include <core/shard_message.h>
#include <tcpip2/buffer.h>
#include <tcpip2/clock.h>
#include <tcpip2/datagram_session.h>
#include <tcpip2/flow.h>
#include <tcpip2/session_factory.h>

namespace tcpip2 {

struct UdpFlowConfig {
    std::size_t max_flows = 256;
    std::uint64_t idle_timeout_ms = 60000;
    /// When a client datagram cannot be dispatched (no session, factory
    /// refusal, or closed session), the shard emits an ICMP destination
    /// unreachable (port unreachable) back to the sender instead of silently
    /// dropping (R7 step 9). Controlled here so callers can opt out.
    bool emit_icmp_unreachable = true;
};

/// Observability snapshot of one UDP flow.
struct UdpFlowSnapshot {
    FlowKey flow;
    std::uint64_t flow_id = 0;
    bool session_bound = false;
    std::uint64_t last_activity_ms = 0;
    std::size_t client_datagrams = 0; ///< received from TUN, forwarded to remote.
    std::size_t remote_datagrams = 0; ///< received from remote, emitted to TUN.
};

/// Shard-local UDP flow table.
class UdpFlowTable {
  public:
    /// Function used to post a ShardMessage back to the owning shard (the
    /// callbacks run on the adapter's thread; the shard processes the message
    /// on its own thread).
    using PostMessageFn = std::function<bool(ShardMessage &&)>;

    /**
     * Serialize one remote datagram to the egress scheduler. Called on the
     * shard thread. On success the emitter moves @p payload out (leaving it
     * empty) and returns true; on failure (egress full / buffer exhausted) it
     * leaves @p payload intact and returns false.
     */
    using EgressEmitter = std::function<bool(const FlowKey &flow, BufferLease &payload)>;

    UdpFlowTable(const UdpFlowConfig &config, ISessionFactory *session_factory, IClock *clock,
                 PostMessageFn post_message) noexcept;

    UdpFlowTable(const UdpFlowTable &) = delete;
    UdpFlowTable &operator=(const UdpFlowTable &) = delete;

    enum class Dispatch {
        Accepted,   ///< payload forwarded to the remote session.
        WouldBlock, ///< remote session backpressured; caller may drop.
        Rejected,   ///< no factory / factory refused / session closed.
        NoCapacity, ///< flow table full with no expired entry to evict.
        Ignored,    ///< not a valid UDP flow (protocol/address family).
    };

    /// Handle one client datagram from the local side (shard thread).
    Dispatch OnClientDatagram(const FlowKey &flow, const std::uint8_t *payload, std::size_t payload_length,
                              std::uint64_t now_ms) noexcept;

    /// Install the egress emitter (remote datagram -> wire, shard thread).
    void SetEgressEmitter(EgressEmitter emitter) noexcept { emitter_ = std::move(emitter); }

    /// Shard-thread handling of a kUdpSessionData message.
    ReceiveStatus OnRemoteData(std::uint64_t flow_id, BufferLease &lease) noexcept;

    /// Shard-thread handling of a kUdpSessionClosed message.
    void OnFlowClosed(std::uint64_t flow_id) noexcept;

    /// Quiesce all session callbacks and drop every flow. Must run before the
    /// table (or the sessions) is destroyed.
    void Shutdown() noexcept;

    void PurgeExpired(std::uint64_t now_ms) noexcept;
    /// Thread-safe observability: number of tracked flows. Safe to read from
    /// any thread (the flow vector itself is shard-thread-only).
    std::size_t Size() const noexcept { return flow_count_.load(std::memory_order_relaxed); }
    std::size_t Capacity() const noexcept { return config_.max_flows; }
    bool Find(const FlowKey &flow, UdpFlowSnapshot &out) const noexcept;
    bool FindById(std::uint64_t flow_id, UdpFlowSnapshot &out) const noexcept;

  private:
    struct Flow {
        FlowKey flow;
        std::uint64_t flow_id = 0;
        IDatagramSession *session = nullptr; ///< owned by the adapter.
        bool session_bound = false;
        std::uint64_t last_activity_ms = 0;
        std::size_t client_datagrams = 0;
        std::size_t remote_datagrams = 0;
    };

    Flow *FindOrCreate(const FlowKey &flow, std::uint64_t now_ms);
    void Evict(std::size_t index);
    void UnbindSession(Flow &flow) noexcept;

    UdpFlowConfig config_;
    ISessionFactory *session_factory_;
    IClock *clock_;
    PostMessageFn post_message_fn_;
    EgressEmitter emitter_;
    std::vector<Flow> flows_;
    std::atomic<std::size_t> flow_count_{0};
    std::uint64_t next_flow_id_ = 1;
    bool shutdown_ = false;
};

} // namespace tcpip2
