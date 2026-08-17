#pragma once

/**
 * @file congestion.h
 * @brief Pluggable congestion controller interface with AIMD and BBRv1.
 * @license GPL-3.0
 *
 * The congestion-control leg of TcpSendBuffer is delegated to a
 * controller selected at connection-creation time.  The interface is
 * designed so that the hot path can use std::variant<AimdController,
 * BbrController, HybridBdpAimdController> without per-ACK virtual dispatch.
 *
 * This is a private header used only by src/tcp/ — not part of the
 * frozen public API.
 */

#include <cstddef>
#include <cstdint>
#include <limits>

#include "tcp/rate_sampler.h"

namespace tcpip2 {

/// Algorithm selection (set at flow creation, immutable thereafter).
enum class CongestionAlgorithm {
    Aimd,            ///< RFC 5681 baseline (default, no pacing).
    Bbr,             ///< BBRv1 (with pacing).
    HybridBdpAimd,   ///< Hybrid: BDP-based (BBR-style) cwnd with AIMD loss response.
    Kcc,             ///< KCC v2.0 geodesic congestion control (ported from tcp_kcc.c).
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
    /// RFC 3168 §6.1.2: an ECE on an ACK is a congestion signal — halve the
    /// window as for a packet loss (the sender then echoes CWR).
    void OnEcnCe() noexcept;

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
    /// RFC 3168 §6.1.2 ECE congestion response: cut cwnd.
    void OnEcnCe() noexcept;

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
    // Timestamped min filter over the last ~kRtpropSampleCount samples;
    // samples older than kRtpropWindowMs expire so the estimate re-measures
    // after path changes (R5 requirement: not a lifetime monotonic minimum).
    std::uint64_t rtprop_ = 0;  // 0 means "unknown"
    std::uint64_t rtprop_stamp_ms_ = 0;
    static constexpr std::uint64_t kRtpropWindowMs = 10000;
    static constexpr std::uint8_t kRtpropSampleCount = 16;
    struct RtpropSample {
        std::uint64_t rtt_ms;
        std::uint64_t time_ms;
    };
    RtpropSample rtprop_samples_[kRtpropSampleCount] = {};
    std::uint8_t rtprop_count_ = 0;
    std::uint8_t rtprop_pos_ = 0;

    // State machine.
    State state_ = State::Startup;

    // STARTUP tracking.
    std::uint64_t startup_prev_round_max_bw_ = 0;
    std::uint64_t startup_round_max_bw_ = 0;
    std::uint8_t startup_rounds_no_growth_ = 0;

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

/// Hybrid BDP-based AIMD congestion controller.
///
/// Combines BBR-style bandwidth estimation with an AIMD-style loss response.
/// BtlBw is a finite max filter over the last ~10 rounds (windowed max, so
/// stale peaks eventually decay); RTprop is a timestamped min filter over a
/// 10-second window (samples expire, so the estimate re-measures after path
/// changes).  In normal operation cwnd = max(BDP, 4*MSS); on loss,
/// ssthresh = max(flight/2, 2*MSS) and cwnd = ssthresh + 3*MSS (fast
/// recovery); on RTO, cwnd = 1*MSS and the estimates are invalidated so the
/// flow re-measures.  Pacing rate = BtlBw * 1.0 (no gain inflation,
/// conservative).
///
/// Telemetry ID is "hybrid_bdp_aimd_v1".
class HybridBdpAimdController {
public:
    HybridBdpAimdController(std::uint16_t mss) noexcept;

    void OnPacketSent(std::uint64_t bytes) noexcept;
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;
    /// RFC 3168 §6.1.2 ECE congestion response: halve cwnd as for a loss.
    void OnEcnCe() noexcept;

    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t Ssthresh() const noexcept { return ssthresh_; }
    std::uint32_t PacingRate() const noexcept;

    /// Telemetry string (always "hybrid_bdp_aimd_v1").
    static const char* AlgorithmId() noexcept { return "hybrid_bdp_aimd_v1"; }
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

    // Hybrid state for testing/telemetry.
    std::uint64_t BtlBw() const noexcept { return btlbw_; }
    std::uint64_t RTprop() const noexcept { return rtprop_; }

private:
    void UpdateBtlBw(const RateSample& rs) noexcept;
    /// Advance to the next filter round: fold the current round's max
    /// bandwidth into the windowed max filter and recompute BtlBw.
    void EndRound() noexcept;
    void UpdateRTprop(const RateSample& rs) noexcept;
    std::uint64_t Bdp() const noexcept;
    void RecomputeCwnd() noexcept;

    std::uint16_t mss_;

    // Estimated bottleneck bandwidth (bytes/sec): windowed max over the
    // last ~kBtlBwWindowRounds rounds.  round_btlbw_current_ holds the max
    // bandwidth sample within the current (in-progress) round.
    std::uint64_t btlbw_ = 0;
    static constexpr std::uint8_t kBtlBwWindowRounds = 10;
    std::uint64_t round_btlbw_window_[kBtlBwWindowRounds] = {};
    std::uint8_t round_btlbw_pos_ = 0;
    std::uint8_t round_btlbw_count_ = 0;
    std::uint64_t round_btlbw_current_ = 0;

    // Round tracking: a round completes once ~cwnd bytes have been newly
    // acknowledged since the round started (acked-based proxy for BBR's
    // delivered counter — works even when OnPacketSent is not called).
    std::uint64_t delivered_ = 0;
    std::uint64_t round_start_delivered_ = 0;
    std::uint64_t round_target_bytes_ = 0;
    bool round_started_ = false;

    // Estimated min RTT (ms): timestamped min filter over the last
    // kRtpropSampleCount samples; samples older than kRtpropWindowMs expire
    // so the estimate refreshes after path changes.  0 means "unknown".
    std::uint64_t rtprop_ = 0;
    std::uint64_t rtprop_stamp_ms_ = 0;
    static constexpr std::uint64_t kRtpropWindowMs = 10000;
    static constexpr std::uint8_t kRtpropSampleCount = 16;
    struct RtpropSample {
        std::uint64_t rtt_ms;
        std::uint64_t time_ms;
    };
    RtpropSample rtprop_samples_[kRtpropSampleCount] = {};
    std::uint8_t rtprop_count_ = 0;
    std::uint8_t rtprop_pos_ = 0;

    // Congestion window and ssthresh.
    std::uint32_t cwnd_;
    std::uint32_t ssthresh_;
    bool fast_recovery_ = false;

    // Pacing rate (bytes/sec), derived from BtlBw.
    std::uint64_t pacing_rate_ = 0;
};

/// Forward declaration (defined below; KccConfig holds a pointer to it).
class KccKalmanFilter;

/// Tunables for KCC v2.0 (ported from the upstream module parameters; the
/// KF-related sysctls are folded into KccKalmanFilter).
struct KccConfig {
    /// kcc_turbo: 1.88x BDP cwnd floor in PROBE_BW (upstream default 1).
    bool turbo = true;
    /// kcc_ai_num: PROBE_BW additive-increase numerator over KCC_PG_AI_DEN
    /// (800). 25 = 3.125%/round (upstream default 25).
    std::uint32_t ai_num = 25;
    /// KCC ECN EWMA backoff. Upstream KCC_ECN_ENABLE=0; Netstack2 enables it
    /// because the RFC 3168 data path (ECT/CE/ECE/CWR) is verified, so the
    /// proactive cwnd_gain backoff is functional rather than dead code.
    bool ecn = true;
    /// Per-shard cross-connection bandwidth filter (may be null = disabled).
    KccKalmanFilter* kf = nullptr;
};

/// Per-shard cross-connection bandwidth estimator (KCC Forwarding, KF).
///
/// Port of the upstream global KF (`kcc_kf_*` state in tcp_kcc.c) adapted to
/// Netstack2's ownership model: one instance per shard, accessed only by the
/// shard thread, so the atomic pair + spinlock of the kernel version are not
/// needed.  New flows on the shard can bootstrap from a fair-share estimate
/// learned from the shard's other connections (discounted, gain-compensated),
/// avoiding cold-start ramp-up on shared bottlenecks.
///
/// Disabled by default (matches upstream `kcc_kf_enable = 0`); enable via
/// `KccConfig::kf` pointing at an instance with `enabled = true`.
class KccKalmanFilter {
public:
    /// Master switch (upstream kcc_kf_enable).
    bool enabled = false;
    /// 0 = peak-tracking, 1 = instant (upstream kcc_kf_steady_mode).
    bool steady_mode = false;
    /// Fair-share discount ratio (upstream kcc_kf_discount_num/den = 50/100).
    std::uint32_t discount_num = 50;
    std::uint32_t discount_den = 100;

    /// Feed a bandwidth sample (BW_UNIT = 1<<24 segments/usec). Returns the
    /// updated state estimate. @p r_pct is the measurement-noise percentage
    /// (startup 15, steady 5); @p check enables the chi-squared innovation
    /// gate (steady state only, matching upstream).
    std::uint64_t Update(std::uint64_t z, std::uint32_t r_pct, bool check) noexcept;

    /// Discounted, gain-compensated fair-share initial bandwidth (BW_UNIT)
    /// for a new connection, or 0 if the estimate is unavailable or too
    /// conservative for the local cwnd-derived floor.
    std::uint64_t GetInitBw(std::uint32_t cwnd_segs, std::uint32_t srtt_us) const noexcept;

    /// True once at least one bandwidth sample has been accepted.
    bool Active() const noexcept { return active_; }

    /// Reset filter state (e.g. on shard restart).
    void Reset() noexcept;

private:
    std::uint64_t x_ = 0;       ///< state estimate (BW_UNIT)
    std::uint64_t p_ = 0;       ///< error covariance
    std::uint64_t peak_ = 0;    ///< steady-mode peak (BW_UNIT)
    bool active_ = false;
};

/// KCC v2.0 geodesic congestion control.
///
/// Faithful C++ port of the `tcp_kcc.c` Linux congestion-control module
/// (liulilittle/kcc, commit 227a20b, BSD/GPL dual license).  Core mechanisms:
///   - Three-component RTT model (T_prop / T_queue / T_noise) with the
///     geodesic G1/G2/G3 estimator (instant downward min, capped 12.2%/RTT
///     upward growth, dual-threshold path-increase confirmation).
///   - Three-state FSM: STARTUP -> DRAIN -> PROBE_BW with a closed-loop
///     AI/MD PI controller (physical queue-driven, not an open-loop cycle).
///   - LT-BW policer detection (preserves a rate floor through lossy
///     intervals), confidence-gated ACK-aggregation compensation, and the
///     alone-on-path single-flow bypass.
///   - BDP = min(x_est >> 10, min_rtt_us) — the geodesic model RTT never
///     exceeds the physical floor (G4 safety), so queue-inflated RTT cannot
///     inflate cwnd.
///
/// Kernel-only subsystems are not ported: the global cross-connection
/// Kalman filter (KF, default disabled upstream), TSO/GSO burst control,
/// /proc diagnostics, and sysctl.  ECN EWMA backoff is retained but gated
/// behind the same KCC_ECN_ENABLE=0 default as upstream.
///
/// The port works in the segment domain internally (BW_UNIT = 1<<24 segments
/// per usec, as upstream); byte inputs from RateSample are converted via MSS.
/// Microsecond RTT/interval values are derived from the ms clock multiplied
/// by 1000 (sub-ms precision is bounded by the injected IClock).
///
/// Telemetry ID is "kcc" (the canonical upstream algorithm name).
class KccController {
public:
    explicit KccController(std::uint16_t mss,
                           KccConfig config = {}) noexcept;

    void OnPacketSent(std::uint64_t bytes) noexcept;
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;
    /// KCC keeps ECN disabled by default (upstream KCC_ECN_ENABLE=0); ECE is
    /// not reacted to by the controller itself.
    void OnEcnCe() noexcept;

    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t Ssthresh() const noexcept { return std::numeric_limits<std::uint32_t>::max(); }
    std::uint32_t PacingRate() const noexcept;

    /// Telemetry string (always "kcc").
    static const char* AlgorithmId() noexcept { return "kcc"; }

    void OnFastRecoveryEntry(std::uint32_t flight) noexcept;
    void OnDupAck() noexcept;
    void OnFastRecoveryExit() noexcept;
    bool InFastRecovery() const noexcept { return packet_conservation_; }

    void UpdateMss(std::uint16_t mss, bool pristine) noexcept;
    void Reset() noexcept;

    // ---- KCC state for testing / telemetry ----
    enum class Mode { Startup = 0, ProbeBw = 1, Drain = 2 };
    Mode CurrentMode() const noexcept { return static_cast<Mode>(mode_); }
    std::uint32_t MinRttUs() const noexcept { return min_rtt_us_; }
    std::uint64_t BtlBw() const noexcept;
    std::uint64_t XEstUs() const noexcept { return x_est_ >> kKccScaleShift; }
    std::uint32_t PacingGain() const noexcept { return pacing_gain_; }
    std::uint32_t CwndGain() const noexcept { return cwnd_gain_; }
    std::uint32_t QdelayAvgUs() const noexcept { return qdelay_avg_; }
    std::uint32_t JitterEwmaUs() const noexcept { return jitter_ewma_; }
    std::uint32_t SampleCount() const noexcept { return sample_cnt_; }
    bool AloneOnPath() const noexcept { return alone_on_path_; }
    std::uint32_t RoundRttMinUs() const noexcept { return round_rtt_min_; }
    std::uint32_t PrevRoundRttMinUs() const noexcept { return prev_round_rtt_min_; }

private:
    // win_minmax sliding-window max (Linux include/linux/win_minmax.h).
    struct MinmaxSample {
        std::uint32_t t = 0;
        std::uint32_t v = 0;
    };
    struct Minmax {
        MinmaxSample s[3];
        void Reset(std::uint32_t t, std::uint32_t meas) noexcept;
        std::uint32_t Get() const noexcept { return s[2].v; }
        void RunningMax(std::uint32_t win, std::uint32_t t,
                        std::uint32_t meas) noexcept;
    };

    // Scale constants (upstream #defines).
    static constexpr std::uint32_t kBandwidthScale = 24;
    static constexpr std::uint64_t kBandwidthUnit = std::uint64_t{1} << kBandwidthScale;
    static constexpr std::uint32_t kBbrScale = 8;
    static constexpr std::uint32_t kBbrUnit = 1u << kBbrScale;
    static constexpr std::uint32_t kKccScaleShift = 10;
    static constexpr std::uint64_t kG2GrowthNum = 122;
    static constexpr std::uint64_t kG2GrowthDen = 1000;
    static constexpr std::uint64_t kG3FastThNum = 11;
    static constexpr std::uint64_t kG3FastThDen = 10;
    static constexpr std::uint64_t kG3SlowThNum = 21;
    static constexpr std::uint64_t kG3SlowThDen = 20;
    static constexpr std::uint64_t kPdNoiseGateNum = 95;
    static constexpr std::uint64_t kPdNoiseGateDen = 100;
    static constexpr std::uint32_t kModeStartup = 0;
    static constexpr std::uint32_t kModeProbeBw = 1;
    static constexpr std::uint32_t kModeDrain = 2;
    static constexpr std::uint32_t kG3FastCnt = 3;
    static constexpr std::uint32_t kG3SlowCnt = 4;
    static constexpr std::uint32_t kRttMinFloorUs = 1;
    static constexpr std::uint32_t kRttSampleMaxUs = 500000;
    static constexpr std::uint32_t kMinRttFastFallCnt = 5;
    static constexpr std::uint32_t kMinRttFastFallDiv = 4;
    static constexpr std::uint64_t kMinRttStickyNum = 75;
    static constexpr std::uint64_t kMinRttStickyDen = 100;
    static constexpr std::uint64_t kMinRttSrttGuardNum = 90;
    static constexpr std::uint64_t kMinRttSrttGuardDen = 100;
    static constexpr std::uint64_t kProbeRttFilterMs = 10000;
    static constexpr std::uint32_t kMinSamples = 5;
    static constexpr std::uint32_t kPestInit = 1000;
    static constexpr std::uint32_t kPestFloor = 10;
    static constexpr std::uint32_t kPestMax = 1000000;
    static constexpr std::uint32_t kPestDecayShift = 4;
    static constexpr std::uint32_t kPestGrowthShift = 3;
    static constexpr std::uint32_t kStalenessRnds = 128;
    static constexpr std::uint64_t kEwmaJitterNum = 7;
    static constexpr std::uint64_t kEwmaJitterDen = 8;
    static constexpr std::uint64_t kEwmaQdelayNum = 7;
    static constexpr std::uint64_t kEwmaQdelayDen = 8;
    static constexpr std::uint32_t kJitterSeedShift = 2;
    static constexpr std::uint32_t kQdelayCleanBp = 1000;
    static constexpr std::uint32_t kQdelayCongBp = 2500;
    static constexpr std::uint32_t kQdelayBpBase = 10000;
    static constexpr std::uint32_t kQdelayFloorUs = 500;

    // FSM gains / AI-MD.
    static constexpr std::uint32_t kStartupGain = (kBbrUnit * 289u) / 100u;      // 2.89x
    static constexpr std::uint32_t kCwndPulseInit = (kBbrUnit * 125u) / 100u;    // 1.25x
    static constexpr std::uint32_t kCwndPulseGrowthNum = 125;
    static constexpr std::uint32_t kCwndPulseGrowthDen = 100;
    static constexpr std::uint32_t kCwndPulseMax = kBbrUnit * 2u;
    static constexpr std::uint32_t kCwndPulseBwStable = 3;
    static constexpr std::uint32_t kCwndPulseExitRnds = 2;
    static constexpr std::uint32_t kProbeRoundMax = 7;
    static constexpr std::uint32_t kFpCooldown = 8;
    static constexpr std::uint32_t kProbeBwMdNum = 1;
    static constexpr std::uint32_t kProbeBwMdDen = 1;
    static constexpr std::uint32_t kPgMin = (kBbrUnit * 3u) / 4u;
    static constexpr std::uint32_t kPgMax = (kBbrUnit * 5u) / 4u;
    static constexpr std::uint32_t kPgAiDen = 800;
    static constexpr std::uint32_t kDrainDecayNum = 92;
    static constexpr std::uint32_t kDrainDecayDen = 100;
    static constexpr std::uint32_t kPeriodicDrainInterval = 128;
    static constexpr std::uint32_t kPeriodicDrainMask = kPeriodicDrainInterval - 1;
    static constexpr std::uint32_t kPeriodicDrainPg = (kBbrUnit * 75u) / 100u;
    static constexpr std::uint32_t kExcessTargetDiv = 128;
    static constexpr std::uint32_t kExcessDrainDiv = 32;
    static constexpr std::uint32_t kDrainExitRnds = 4;
    static constexpr std::uint32_t kProbeBwCompeteRatio = 188;

    // LT-BW.
    static constexpr std::uint32_t kLtBwMaxRtts = 48;
    static constexpr std::uint64_t kLtBwRatioNum = 1;
    static constexpr std::uint64_t kLtBwRatioDen = 8;
    static constexpr std::uint32_t kLtBwDiff = 500;
    static constexpr std::uint32_t kLtBwEmaNum = 1;
    static constexpr std::uint32_t kLtBwEmaDen = 2;
    static constexpr std::uint32_t kLtIntvlMinRtts = 4;
    static constexpr std::uint32_t kLtIntvlMaxMult = 4;
    static constexpr std::uint32_t kLtLossThresh = 25;

    // ACK aggregation.
    static constexpr std::uint32_t kAggIdle = 0;
    static constexpr std::uint32_t kAggSuspected = 1;
    static constexpr std::uint32_t kAggConfirmed = 2;
    static constexpr std::uint32_t kAggTrusted = 3;
    static constexpr std::uint32_t kAggConfidenceMax = 1u << 10;
    static constexpr std::uint32_t kAggFactorWeight = kAggConfidenceMax >> 2;
    static constexpr std::uint32_t kAggConfidenceThresh = kAggConfidenceMax >> 1;
    static constexpr std::uint32_t kAggExtraAckedGainNum = 1;
    static constexpr std::uint32_t kAggExtraAckedGainDen = 1;
    static constexpr std::uint32_t kAggExtraAckedMaxMsNum = 150;
    static constexpr std::uint32_t kAggExtraAckedMaxMsDen = 1;
    static constexpr std::uint32_t kAggExtraAckedWinRttsMax = 31;
    static constexpr std::uint32_t kAggWindowRotationRtts = 5;
    static constexpr std::uint32_t kAggEpochMax = 0xFFFFFu;
    static constexpr std::uint32_t kAggMaxWindowMs = 100;
    static constexpr std::uint32_t kAggMaxCompDuration = 8;
    static constexpr std::uint32_t kAggMaxCompRatio = 50;
    static constexpr std::uint32_t kAggMaxDecayPct = 75;
    static constexpr std::uint32_t kAggSafetyBdpMult = 3;
    static constexpr std::uint32_t kAggFactor4RatioNum = 3;
    static constexpr std::uint32_t kAggFactor4RatioDen = 2;
    static constexpr std::uint32_t kAggMaxPerAckDecay = 128;
    static constexpr std::uint32_t kAggMaxPerAckDecayDen = 128;
    static constexpr std::uint32_t kAloneConfirmRounds = 3;
    static constexpr std::uint32_t kAloneExitThresh = 3;

    // BDP / cwnd.
    static constexpr std::uint32_t kBdpMinRttUs = 1;
    static constexpr std::uint32_t kCwndMinTarget = 4;
    static constexpr std::uint32_t kCwndAbsoluteMin = 1;
    static constexpr std::uint32_t kBwRtCycleLen = 10;
    static constexpr std::uint32_t kTsoHeadroomMult = 3;
    static constexpr std::uint32_t kProbeCwndBonus = 2;
    static constexpr std::uint32_t kTsoSegsGoal = 1;   // no TSO/GSO in Netstack2

    // CA states (subset of Linux TCP_CA_*).
    enum class CaState { Open, Recovery, Loss };

    static std::uint32_t Segments(std::uint64_t bytes, std::uint16_t mss) noexcept;
    static bool Before(std::uint32_t a, std::uint32_t b) noexcept {
        return static_cast<std::int32_t>(a - b) < 0;
    }
    std::uint64_t RateBytesPerSec(std::uint64_t rate, std::uint32_t gain) const noexcept;
    std::uint32_t MaxBw() const noexcept { return bw_.Get(); }
    std::uint32_t ActiveBw() const noexcept { return lt_use_bw_ ? lt_bw_ : MaxBw(); }
    std::uint32_t ModelRtt() const noexcept;
    std::uint32_t Bdp(std::uint32_t bw, std::uint32_t gain) const noexcept;
    std::uint32_t QuantizationBudget(std::uint32_t cwnd) const noexcept;
    std::uint32_t CleanThresh() const noexcept;
    std::uint32_t CongThresh() const noexcept;
    void InitPacingRateFromRtt() noexcept;
    void SetPacingRate(std::uint32_t bw, std::uint32_t gain) noexcept;
    void SaveCwnd() noexcept { prior_cwnd_ = cwnd_; }
    void ResetMode() noexcept;
    void ResetLtBwSamplingInterval() noexcept;
    void ResetLtBwSampling() noexcept;
    void LtBwIntervalDone(std::uint64_t bw) noexcept;
    void LtBwSampling(std::uint32_t lost_seg, bool is_app_limited) noexcept;
    void UpdateBw(const RateSample& rs, std::uint32_t acked_seg,
                  std::uint32_t prior_delivered_seg) noexcept;
    void Update(const RateSample& rs) noexcept;
    void UpdateMinRtt(const RateSample& rs) noexcept;
    void UpdateAckAggregation(const RateSample& rs,
                              std::uint32_t acked_seg) noexcept;
    std::uint32_t AckAggregationCwnd(std::uint32_t bw) noexcept;
    std::uint32_t MeasureAckAggregation(const RateSample& rs,
                                        std::uint32_t acked_seg) noexcept;
    std::uint16_t EvaluateAggConfidence(std::uint32_t extra_acked,
                                        std::uint32_t pre_max) const noexcept;
    std::uint8_t AggStateFromConfidence(std::uint16_t confidence) const noexcept;
    bool AggSafetyCheck(std::uint32_t bw) const noexcept;
    std::uint32_t AggCwndCompensation(std::uint32_t extra_acked,
                                      std::uint16_t confidence,
                                      std::uint32_t bw) const noexcept;
    void AggWatchdog() noexcept;
    void UpdateEcnEwma(const RateSample& rs) noexcept;
    void EcnBackoff() noexcept;
    void UpdateGainsV2() noexcept;
    void UpdateModel(const RateSample& rs, std::uint32_t acked_seg,
                     std::uint32_t prior_delivered_seg) noexcept;
    void AloneOnPathEval() noexcept;
    bool SetCwndToRecoverOrRestore(std::uint32_t acked_seg,
                                   std::uint32_t lost_seg,
                                   std::uint32_t* new_cwnd) noexcept;
    void SetCwnd(const RateSample& rs, std::uint32_t acked_seg,
                 std::uint32_t bw, std::uint32_t gain) noexcept;
    void ApplyCwndConstraints() noexcept;
    void RecomputePacingRate(std::uint32_t bw) noexcept;
    void FeedKalman(const RateSample& rs, std::uint32_t acked_seg) noexcept;
    void SeedFromKf() noexcept;

    std::uint16_t mss_;

    // ---- struct kcc fields ----
    std::uint32_t min_rtt_us_ = 0;
    std::uint64_t min_rtt_stamp_ms_ = 0;
    Minmax bw_;
    std::uint32_t rtt_cnt_ = 0;
    std::uint32_t next_rtt_delivered_ = 0;
    std::uint8_t mode_ = kModeStartup;
    CaState prev_ca_state_ = CaState::Open;
    bool round_start_ = false;
    bool idle_restart_ = false;
    bool packet_conservation_ = false;
    bool lt_is_sampling_ = false;
    std::uint32_t lt_rtt_cnt_ = 0;
    std::uint8_t min_rtt_fast_fall_cnt_ = 0;
    std::uint8_t probe_round_ = 0;
    std::uint8_t probe_cooldown_ = 0;
    bool has_seen_rtt_ = false;
    bool lt_use_bw_ = false;
    std::uint32_t pacing_gain_ = kStartupGain;
    std::uint32_t cwnd_gain_ = kCwndPulseInit;
    bool alone_on_path_ = false;
    std::uint8_t drain_ok_rounds_ = 0;
    std::uint32_t prior_cwnd_ = 0;
    std::uint32_t bw_stable_rounds_ = 0;
    std::uint32_t drain_entry_pg_ = std::numeric_limits<std::uint32_t>::max();
    std::uint32_t lt_bw_ = 0;
    std::uint32_t lt_last_delivered_ = 0;
    std::uint32_t lt_last_stamp_ms_ = 0;
    std::uint32_t lt_last_lost_ = 0;
    std::uint32_t round_rtt_min_ = std::numeric_limits<std::uint32_t>::max();
    std::uint32_t prev_round_rtt_min_ = std::numeric_limits<std::uint32_t>::max();

    // ---- struct kcc_ext fields ----
    std::uint64_t x_est_ = 0;
    std::uint8_t confirm_cnt_ = 0;
    std::uint8_t confirm_slow_cnt_ = 0;
    std::uint32_t mr_update_rtt_cnt_ = 0;
    std::uint32_t p_est_ = kPestInit;
    std::uint32_t qdelay_avg_ = 0;
    std::uint32_t sample_cnt_ = 0;
    std::uint32_t jitter_ewma_ = 0;
    // ECN EWMA (upstream: disabled by KCC_ECN_ENABLE=0; here enabled via
    // KccConfig::ecn). ewma is in BBR_UNIT (256 = 100% CE ratio).
    std::uint32_t ecn_ewma_ = 0;
    std::uint32_t last_delivered_ce_ = 0;
    std::uint64_t ack_epoch_mstamp_us_ = 0;
    std::uint32_t extra_acked_[2] = {};
    std::uint32_t ack_epoch_acked_ = 0;
    std::uint32_t extra_acked_win_rtts_ = 0;
    std::uint32_t extra_acked_win_idx_ = 0;
    std::uint32_t agg_extra_acked_ = 0;
    std::uint32_t agg_extra_acked_max_ = 0;
    std::uint16_t agg_confidence_ = 0;
    std::uint8_t agg_state_ = kAggIdle;
    std::uint8_t agg_comp_duration_ = 0;
    std::uint8_t alone_confirm_cnt_ = 0;
    std::uint8_t alone_exit_cnt_ = 0;

    // ---- Netstack2 adapters (kernel tp/sk field equivalents) ----
    KccConfig config_;            ///< tunables (turbo/ai_num/ecn/kf)
    bool kf_seeded_ = false;      ///< KF fair-share bootstrap already applied
    std::uint32_t cwnd_ = 0;                 // tp->snd_cwnd (segments)
    std::uint64_t pacing_rate_ = 0;          // sk->sk_pacing_rate (bytes/sec)
    std::uint32_t srtt_us_ = 0;              // tp->srtt_us >> 3 (us)
    std::uint32_t delivered_segments_ = 0;   // tp->delivered (cumulative segments)
    std::uint32_t lost_segments_ = 0;        // tp->lost (cumulative segments)
    std::uint64_t delivered_mstamp_us_ = 0;  // tp->delivered_mstamp (us)
    std::uint32_t inflight_segments_ = 0;    // tcp_packets_in_flight(tp)
    bool initialized_ = false;
};

} // namespace tcpip2
