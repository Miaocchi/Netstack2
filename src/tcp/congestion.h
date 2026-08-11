#pragma once

/**
 * @file congestion.h
 * @brief Pluggable congestion controller interface with AIMD and BBRv1.
 * @license GPL-3.0
 *
 * The congestion-control leg of TcpSendBuffer is delegated to a
 * controller selected at connection-creation time.  The interface is
 * designed so that the hot path can use std::variant<AimdController,
 * BbrController, KccController> without per-ACK virtual dispatch.
 *
 * This is a private header used only by src/tcp/ — not part of the
 * frozen public API.
 */

#include <cstddef>
#include <cstdint>

#include "tcp/rate_sampler.h"

namespace tcpip2 {

/// Algorithm selection (set at flow creation, immutable thereafter).
enum class CongestionAlgorithm {
    Aimd,   ///< RFC 5681 baseline (default, no pacing).
    Bbr,    ///< BBRv1 (with pacing).
    Kcc,    ///< KCC hybrid (BBR bandwidth estimation + AIMD loss response).
};

/// Information about a loss event passed to the controller.
struct LossEvent {
    /// Number of bytes lost in this event.
    std::uint64_t lost_bytes = 0;
    /// Total in-flight bytes at the time of loss.
    std::uint64_t inflight_bytes = 0;
    /// True if loss was detected via RTO (vs. triple-dup-ACK / SACK).
    bool is_rto = false;
};

/// Per-connection AIMD (RFC 5681) congestion controller.
///
/// Reproduces exactly the behaviour that was previously inlined in
/// TcpSendBuffer, so existing tests remain green.
class AimdController {
public:
    AimdController(std::uint16_t mss) noexcept;

    void OnPacketSent(std::uint64_t /*bytes*/) noexcept {}
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;

    std::uint32_t CongestionWindow() const noexcept { return cwnd_; }
    std::uint32_t Ssthresh() const noexcept { return ssthresh_; }
    /// AIMD does not pace; always returns 0.
    std::uint32_t PacingRate() const noexcept { return 0; }

    /// Called by TcpSendBuffer when entering fast recovery.
    void OnFastRecoveryEntry(std::uint32_t flight) noexcept;
    /// Called by TcpSendBuffer for each dup-ACK during recovery (inflate).
    void OnDupAck() noexcept;
    /// Called when exiting fast recovery (set cwnd = ssthresh).
    void OnFastRecoveryExit() noexcept;
    bool InFastRecovery() const noexcept { return fast_recovery_; }

    /// Update MSS (called when path MTU changes).
    void UpdateMss(std::uint16_t mss, bool pristine) noexcept;

    /// Reset to initial state.
    void Reset() noexcept;

private:
    std::uint32_t cwnd_;
    std::uint32_t ssthresh_;
    std::uint16_t mss_;
    bool fast_recovery_ = false;
};

/// BBRv1 congestion controller.
///
/// Implements the four-state machine: STARTUP → DRAIN → PROBE_BW ↔
/// PROBE_RTT.  Pacing rate is derived from BtlBw and RTprop.
///
/// Telemetry ID is "bbr_v1" to prevent confusion with BBRv2/v3.
class BbrController {
public:
    BbrController(std::uint16_t mss) noexcept;

    void OnPacketSent(std::uint64_t bytes) noexcept;
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;

    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t PacingRate() const noexcept;

    /// Telemetry string (always "bbr_v1").
    static const char* AlgorithmId() noexcept { return "bbr_v1"; }

    /// Reset to initial state.
    void Reset() noexcept;

    // BBR state for testing/telemetry.
    enum class State { Startup, Drain, ProbeBw, ProbeRtt };
    State CurrentState() const noexcept { return state_; }
    std::uint64_t BtlBw() const noexcept { return btlbw_; }
    std::uint64_t RTprop() const noexcept { return rtprop_; }

private:
    void UpdateBtlBw(const RateSample& rs) noexcept;
    void UpdateRTprop(const RateSample& rs) noexcept;
    void CheckStartupDone() noexcept;
    void CheckDrainDone() noexcept;
    void EnterProbeRtt(std::uint64_t now_ms) noexcept;
    void ExitProbeRtt(std::uint64_t now_ms) noexcept;
    void AdvanceCycle(std::uint64_t now_ms) noexcept;
    std::uint32_t PacingGain() const noexcept;
    std::uint32_t CwndGain() const noexcept;
    std::uint64_t Bdp() const noexcept;

    std::uint16_t mss_;

    // Estimated bottleneck bandwidth (bytes/sec) and min RTT (ms).
    std::uint64_t btlbw_ = 0;
    std::uint64_t rtprop_ = 0;  // 0 means "unknown"
    std::uint64_t rtprop_stamp_ms_ = 0;

    // State machine.
    State state_ = State::Startup;

    // STARTUP tracking.
    std::uint64_t startup_bw_samples_ = 0;
    std::uint64_t startup_max_bw_ = 0;
    std::uint8_t startup_rounds_no_growth_ = 0;
    std::uint64_t startup_round_start_bytes_ = 0;

    // PROBE_BW cycle.
    static constexpr std::uint8_t kCycleLen = 8;
    std::uint8_t cycle_index_ = 0;
    std::uint64_t cycle_start_ms_ = 0;

    // PROBE_RTT.
    std::uint64_t probe_rtt_enter_ms_ = 0;
    static constexpr std::uint64_t kProbeRttIntervalMs = 10000;
    static constexpr std::uint64_t kProbeRttDurationMs = 200;

    // Pacing.
    std::uint64_t pacing_rate_ = 0;
    std::uint64_t cwnd_ = 0;

    // Total bytes sent (for round counting).
    std::uint64_t bytes_sent_ = 0;
    std::uint64_t round_start_bytes_ = 0;
    std::uint64_t delivered_at_round_start_ = 0;
    bool round_started_ = false;
};

/// KCC hybrid congestion controller.
///
/// Combines BBR-style bandwidth estimation (BtlBw max-filter + RTprop
/// min-filter for BDP estimation) with AIMD-style loss response (fast
/// retransmit/recovery).  In normal operation cwnd = max(BDP, 4*MSS);
/// on loss, ssthresh = max(flight/2, 2*MSS) and cwnd = ssthresh + 3*MSS
/// (fast recovery); on RTO, cwnd = 1*MSS.  Pacing rate = BtlBw * 1.0
/// (no gain inflation, conservative).
///
/// Telemetry ID is "kcc_v1".
class KccController {
public:
    KccController(std::uint16_t mss) noexcept;

    void OnPacketSent(std::uint64_t bytes) noexcept;
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;

    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t Ssthresh() const noexcept { return ssthresh_; }
    std::uint32_t PacingRate() const noexcept;

    /// Telemetry string (always "kcc_v1").
    static const char* AlgorithmId() noexcept { return "kcc_v1"; }

    /// Called by TcpSendBuffer when entering fast recovery.
    void OnFastRecoveryEntry(std::uint32_t flight) noexcept;
    /// Called by TcpSendBuffer for each dup-ACK during recovery (inflate).
    void OnDupAck() noexcept;
    /// Called when exiting fast recovery (set cwnd = ssthresh).
    void OnFastRecoveryExit() noexcept;
    bool InFastRecovery() const noexcept { return fast_recovery_; }

    /// Update MSS (called when path MTU changes).
    void UpdateMss(std::uint16_t mss, bool pristine) noexcept;

    /// Reset to initial state.
    void Reset() noexcept;

    // KCC state for testing/telemetry.
    std::uint64_t BtlBw() const noexcept { return btlbw_; }
    std::uint64_t RTprop() const noexcept { return rtprop_; }

private:
    void UpdateBtlBw(const RateSample& rs) noexcept;
    void UpdateRTprop(const RateSample& rs) noexcept;
    std::uint64_t Bdp() const noexcept;
    void RecomputeCwnd() noexcept;

    std::uint16_t mss_;

    // Estimated bottleneck bandwidth (bytes/sec) and min RTT (ms).
    std::uint64_t btlbw_ = 0;
    std::uint64_t rtprop_ = 0;  // 0 means "unknown"

    // Congestion window and ssthresh.
    std::uint32_t cwnd_;
    std::uint32_t ssthresh_;
    bool fast_recovery_ = false;

    // Pacing rate (bytes/sec), derived from BtlBw.
    std::uint64_t pacing_rate_ = 0;
};

} // namespace tcpip2
