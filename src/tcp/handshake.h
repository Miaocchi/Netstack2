#pragma once

/**
 * @file handshake.h
 * @brief Bounded shard-local passive TCP handshake state machine.
 * @license GPL-3.0
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/events.h>
#include <tcpip2/session_factory.h>

#include <functional>

#include <core/shard_message.h>
#include <core/timer_wheel.h>
#include <tcp/delivery.h>
#include <tcp/isn.h>
#include <tcp/options.h>
#include <tcp/congestion.h>
#include <tcp/receive.h>
#include <tcp/segment.h>
#include <tcp/send.h>

namespace tcpip2 {

enum class TcpState {
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
};

enum class TcpHandshakeError {
    None,
    InvalidFlags,
    InvalidOptions,
    BacklogFull,
    HalfOpenLimit,
    PcbLimit,
    TimerFailure,
    ReceiveBudget,
    InvalidSession,
    Shutdown,
};

struct TcpHandshakeConfig {
    std::size_t backlog_limit = 128;
    std::size_t half_open_limit = 256;
    std::size_t pcb_limit = 4096;
    std::size_t pending_response_limit = 256;
    std::uint16_t local_mss = 1460;
    std::uint16_t path_mtu = 1500;
    std::uint32_t receive_window = 65536;
    bool enable_window_scale = true;
    bool enable_sack = true;
    bool enable_timestamps = true;
    std::size_t receive_memory_budget = 16 * 1024 * 1024;
    std::size_t delivery_call_budget = 16;
    std::uint64_t delayed_ack_ms = 40;
    std::array<std::uint64_t, 4> syn_ack_retry_intervals_ms{{1000, 2000, 4000, 8000}};

    // Send path configuration
    std::size_t send_queue_limit = 256 * 1024;
    std::size_t retransmit_queue_limit = 256 * 1024;
    std::uint64_t initial_rto_ms = 1000;
    std::uint64_t min_rto_ms = 200;
    std::uint64_t max_rto_ms = 120000;
    std::uint64_t persist_timer_base_ms = 500;
    std::uint64_t persist_timer_max_ms = 60000;
    std::size_t max_retransmissions = 15;
    std::size_t max_persist_probes = 15;

    std::size_t max_timewait_entries = 4096;
    std::uint32_t timewait_ms = 120000;

    CongestionAlgorithm cc_algorithm = CongestionAlgorithm::Aimd;

    bool Validate() const noexcept;
};

struct TcpNegotiatedOptions {
    std::uint16_t peer_mss = 536;
    std::uint8_t send_window_scale = 0;
    std::uint8_t receive_window_scale = 0;
    bool window_scale = false;
    bool sack_permitted = false;
    bool timestamps = false;
    std::uint32_t peer_timestamp = 0;
};

struct TcpResponse {
    bool valid = false;
    FlowKey flow;
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgment = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
    TcpSynOptions syn_options;
    bool timestamp_present = false;
    std::uint32_t timestamp_value = 0;
    std::uint32_t timestamp_echo = 0;
    TcpSackBlockList sack_blocks;
    /// Optional payload for data segments (non-SYN packets).
    /// Must outlive the call to BuildTcpControlPacket.
    const std::uint8_t* payload = nullptr;
    std::size_t payload_length = 0;
};

struct TcpHandshakeResult {
    TcpHandshakeError error = TcpHandshakeError::None;
    bool state_changed = false;
    TcpResponse response;
};

struct TcpPcbSnapshot {
    TcpState state = TcpState::SynReceived;
    std::uint32_t iss = 0;
    std::uint32_t irs = 0;
    std::uint32_t snd_una = 0;
    std::uint32_t snd_nxt = 0;
    std::uint32_t rcv_nxt = 0;
    FlowId flow_id;
    std::uint64_t generation = 0;
    std::size_t receive_bytes = 0;
    std::size_t ready_bytes = 0;
    std::size_t out_of_order_bytes = 0;
    std::size_t advertised_window = 0;
    bool session_blocked = false;
    TcpNegotiatedOptions options;
};

/**
 * Function type used to post a ShardMessage back to the owning shard.
 * Session callbacks capture this to route writable/closed/data notifications
 * through the shard's MPSC control inbox rather than touching the engine
 * directly from a foreign thread.
 */
using PostMessageFn = std::function<bool(ShardMessage&&)>;

/**
 * One engine represents the transparent wildcard TCP listener on one shard.
 * It is single-threaded and must only be called by its owner shard.
 */
class TcpHandshakeEngine final {
public:
    TcpHandshakeEngine(const TcpHandshakeConfig& config,
                       const TcpIsnGenerator& isn,
                       TimerWheel& timers,
                        std::uint64_t generation_epoch = 1,
                        ISessionFactory* session_factory = nullptr,
                        PostMessageFn post_message = nullptr,
                        IEventSink* event_sink = nullptr);
    ~TcpHandshakeEngine();

    TcpHandshakeEngine(const TcpHandshakeEngine&) = delete;
    TcpHandshakeEngine& operator=(const TcpHandshakeEngine&) = delete;

    TcpHandshakeResult OnSegment(const TcpSegmentView& segment,
                                 std::uint64_t now_ms) noexcept;
    /** The engine retains @p session until the flow is removed. */
    TcpHandshakeResult AttachSession(const FlowKey& incoming_flow,
                                     std::shared_ptr<ITransportSession> session,
                                     std::uint64_t now_ms) noexcept;
    TcpHandshakeResult OnSessionWritable(FlowId flow_id,
                                         std::uint64_t generation,
                                         std::uint64_t now_ms) noexcept;
    bool OnSessionClosed(FlowId flow_id,
                          std::uint64_t generation,
                          SessionError error = SessionError::RemoteClosed) noexcept;
    void PumpSessionDeliveries(std::uint64_t now_ms,
                               std::size_t pcb_budget = 64) noexcept;

    /// Enqueue application data for transmission on an established PCB.
    /// Returns bytes accepted (0 if PCB not found or send buffer full).
    std::size_t EnqueueSendData(FlowId flow_id, const std::uint8_t* data,
                                 std::size_t length) noexcept;

    /// Enqueue application data from a session DataCallback (owning lease).
    /// Leaves an unaccepted tail in @p lease so the shard can retry it.
    bool EnqueueRemoteData(FlowId flow_id, std::uint64_t generation,
                           BufferLease& lease) noexcept;

    /** Resume sessions only when the caller has observed a low remote backlog. */
    void ResumeSessionReceives(std::size_t remote_backlog,
                               std::size_t remote_low_watermark) noexcept;

    /// Pump send paths for established PCBs: emit new data, retransmissions,
    /// and persist probes as serialized TX leases.
    void PumpSendPaths(std::uint64_t now_ms, std::size_t pcb_budget,
                       PktBufferPool& pool,
                       std::vector<BufferLease>& tx_leases,
                       std::size_t max_segments) noexcept;

    void CloseFlow(FlowId flow_id, std::uint64_t generation) noexcept;
    void AbortFlow(FlowId flow_id, std::uint64_t generation) noexcept;

    bool Find(const FlowKey& incoming_flow, TcpPcbSnapshot& out) const noexcept;
    bool PopPendingResponse(TcpResponse& out) noexcept;
    void DeferResponse(const TcpResponse& response) noexcept {
        QueueResponse(response);
    }
    void Shutdown() noexcept;

    std::size_t PcbCount() const noexcept { return pcbs_.size(); }
    std::size_t HalfOpenCount() const noexcept { return half_open_count_; }
    std::size_t EstablishedCount() const noexcept;
    std::size_t PendingResponseCount() const noexcept;
    std::size_t DroppedResponseCount() const noexcept {
        return dropped_responses_;
    }
    std::size_t ReceiveMemoryBytes() const noexcept {
        return receive_memory_bytes_;
    }

private:
    struct Pcb {
        FlowKey incoming_flow;
        TcpState state = TcpState::SynReceived;
        std::uint32_t iss = 0;
        std::uint32_t irs = 0;
        std::uint32_t snd_una = 0;
        std::uint32_t snd_nxt = 0;
        std::uint32_t rcv_nxt = 0;
        std::uint16_t peer_window = 0;
        std::uint16_t response_window = 0;
        std::uint32_t receive_window = 0;
        TcpNegotiatedOptions options;
        TcpSynOptions response_options;
        std::unique_ptr<TcpReceiveBuffer> receive;
        std::unique_ptr<TcpSendBuffer> send;
        std::shared_ptr<ITransportSession> session;
        bool session_bound = false;
        FlowId flow_id;
        std::uint64_t generation = 0;
        std::size_t retry_index = 0;
        TimerId retry_timer;
        TimerId delayed_ack_timer;
        bool delivery_pending = false;
        TcpResponse pending_ack;
        bool pending_ack_valid = false;
        TimerId timewait_timer;
        std::uint64_t timewait_deadline_ms = 0;
        bool fin_received = false;
        bool close_notified = false;
    };

    struct CallbackGate {
        mutable std::mutex mutex;
        std::condition_variable cv;
        PostMessageFn post_message;
        bool active = true;
        std::size_t in_flight_callbacks = 0;

        bool TryPost(ShardMessage&& msg) noexcept {
            std::unique_lock<std::mutex> lock(mutex);
            if (!active || !post_message) return false;
            ++in_flight_callbacks;
            bool posted = false;
            try {
                posted = post_message(std::move(msg));
            } catch (...) {
                posted = false;
            }
            --in_flight_callbacks;
            if (!active && in_flight_callbacks == 0) cv.notify_all();
            return posted;
        }

        template <typename Fn>
        void TryRun(Fn&& fn) noexcept {
            std::unique_lock<std::mutex> lock(mutex);
            if (!active) return;
            ++in_flight_callbacks;
            try {
                fn();
            } catch (...) {
                // Timer callbacks cannot let an external failure kill a shard.
            }
            --in_flight_callbacks;
            if (!active && in_flight_callbacks == 0) cv.notify_all();
        }

        bool IsActive() const noexcept {
            std::lock_guard<std::mutex> lock(mutex);
            return active && static_cast<bool>(post_message);
        }

        void Deactivate() noexcept {
            std::unique_lock<std::mutex> lock(mutex);
            active = false;
            post_message = nullptr;
            cv.wait(lock, [this] { return in_flight_callbacks == 0; });
        }
    };

    std::size_t FindIndex(const FlowKey& incoming_flow) const noexcept;
    std::size_t ListenerHalfOpenCount(const FlowKey& incoming_flow) const noexcept;
    TcpResponse BuildSynAck(Pcb& pcb, std::uint64_t now_ms) noexcept;
    TcpResponse BuildAck(Pcb& pcb, std::uint64_t now_ms) noexcept;
    static TcpResponse BuildReset(const TcpSegmentView& segment) noexcept;
    bool ScheduleRetry(Pcb& pcb, std::uint64_t deadline_ms) noexcept;
    void OnRetry(const FlowKey& incoming_flow, std::uint64_t generation) noexcept;
    bool ScheduleDelayedAck(Pcb& pcb, std::uint64_t now_ms) noexcept;
    void OnDelayedAck(const FlowKey& incoming_flow, std::uint64_t generation) noexcept;
    void OnTimeWaitExpired(const FlowKey& incoming_flow, std::uint64_t generation) noexcept;
    bool ScheduleTimeWait(std::size_t index, std::uint64_t now_ms) noexcept;
    void BindSessionCallbacks(Pcb& pcb) noexcept;
    TcpHandshakeResult ProcessEstablished(Pcb& pcb,
                                          const TcpSegmentView& segment,
                                          std::uint64_t now_ms) noexcept;
    TcpDeliveryResult DrainSession(Pcb& pcb) noexcept;
    void RemoveAt(std::size_t index) noexcept;
    void QueueResponse(const TcpResponse& response) noexcept;
    void EmitFlowEvent(FlowId flow_id, FlowEventType type) noexcept;

    TcpHandshakeConfig config_;
    TcpIsnGenerator isn_;
    TimerWheel& timers_;
    std::vector<Pcb> pcbs_;
    std::vector<TcpResponse> pending_responses_;
    std::shared_ptr<CallbackGate> callback_gate_;
    std::size_t half_open_count_ = 0;
    std::size_t dropped_responses_ = 0;
    std::size_t receive_memory_bytes_ = 0;
    std::uint64_t next_flow_id_ = 1;
    std::uint64_t generation_epoch_ = 1;
    ISessionFactory* session_factory_ = nullptr;
    PostMessageFn post_message_fn_;
    IEventSink* event_sink_ = nullptr;
    bool shutdown_ = false;
};

} // namespace tcpip2
