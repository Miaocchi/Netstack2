#pragma once

/**
 * @file handshake.h
 * @brief Bounded shard-local passive TCP handshake state machine.
 * @license GPL-3.0
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <core/timer_wheel.h>
#include <tcp/isn.h>
#include <tcp/options.h>
#include <tcp/segment.h>

namespace tcpip2 {

enum class TcpState {
    SynReceived,
    Established,
};

enum class TcpHandshakeError {
    None,
    InvalidFlags,
    InvalidOptions,
    BacklogFull,
    HalfOpenLimit,
    PcbLimit,
    TimerFailure,
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
    std::array<std::uint64_t, 4> syn_ack_retry_intervals_ms{{1000, 2000, 4000, 8000}};

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
    TcpNegotiatedOptions options;
};

/**
 * One engine represents the transparent wildcard TCP listener on one shard.
 * It is single-threaded and must only be called by its owner shard.
 */
class TcpHandshakeEngine final {
public:
    TcpHandshakeEngine(const TcpHandshakeConfig& config,
                       const TcpIsnGenerator& isn,
                       TimerWheel& timers);
    ~TcpHandshakeEngine();

    TcpHandshakeEngine(const TcpHandshakeEngine&) = delete;
    TcpHandshakeEngine& operator=(const TcpHandshakeEngine&) = delete;

    TcpHandshakeResult OnSegment(const TcpSegmentView& segment,
                                 std::uint64_t now_ms) noexcept;

    bool Find(const FlowKey& incoming_flow, TcpPcbSnapshot& out) const noexcept;
    bool PopPendingResponse(TcpResponse& out) noexcept;
    void Shutdown() noexcept;

    std::size_t PcbCount() const noexcept { return pcbs_.size(); }
    std::size_t HalfOpenCount() const noexcept { return half_open_count_; }
    std::size_t EstablishedCount() const noexcept;
    std::size_t PendingResponseCount() const noexcept {
        return pending_responses_.size();
    }
    std::size_t DroppedResponseCount() const noexcept {
        return dropped_responses_;
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
        std::uint64_t generation = 0;
        std::size_t retry_index = 0;
        TimerId retry_timer;
    };

    struct CallbackGate {
        TcpHandshakeEngine* owner = nullptr;
    };

    std::size_t FindIndex(const FlowKey& incoming_flow) const noexcept;
    std::size_t ListenerHalfOpenCount(const FlowKey& incoming_flow) const noexcept;
    TcpResponse BuildSynAck(Pcb& pcb, std::uint64_t now_ms) noexcept;
    static TcpResponse BuildReset(const TcpSegmentView& segment) noexcept;
    bool ScheduleRetry(Pcb& pcb, std::uint64_t deadline_ms) noexcept;
    void OnRetry(const FlowKey& incoming_flow, std::uint64_t generation) noexcept;
    void RemoveAt(std::size_t index) noexcept;
    void QueueResponse(const TcpResponse& response) noexcept;

    TcpHandshakeConfig config_;
    TcpIsnGenerator isn_;
    TimerWheel& timers_;
    std::vector<Pcb> pcbs_;
    std::vector<TcpResponse> pending_responses_;
    std::shared_ptr<CallbackGate> callback_gate_;
    std::size_t half_open_count_ = 0;
    std::size_t dropped_responses_ = 0;
    std::uint64_t next_generation_ = 1;
    bool shutdown_ = false;
};

} // namespace tcpip2
