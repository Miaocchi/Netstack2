#include "congestion.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

namespace tcpip2 {

// ---------------------------------------------------------------------------
// AimdController
// ---------------------------------------------------------------------------

AimdController::AimdController(std::uint16_t mss) noexcept
    : cwnd_(static_cast<std::uint32_t>(mss) * 2U), ssthresh_(std::numeric_limits<std::uint32_t>::max()), mss_(mss) {}

void AimdController::OnAck(const RateSample &rs) noexcept {
    const std::uint64_t acknowledged_payload = rs.acked_bytes;
    if (acknowledged_payload == 0)
        return;

    if (fast_recovery_) {
        // During fast recovery, cwnd was already inflated; do not grow
        // further on normal ACKs.  The exit happens via OnFastRecoveryExit().
        return;
    }

    if (cwnd_ < ssthresh_) {
        // Slow start: increase by min(acked, MSS) per ACK.
        const std::uint32_t increase = static_cast<std::uint32_t>(std::min<std::uint64_t>(acknowledged_payload, mss_));
        cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase ? std::numeric_limits<std::uint32_t>::max()
                                                                             : cwnd_ + increase;
    } else {
        // Congestion avoidance: cwnd += MSS*MSS/cwnd per ACK.
        if (cwnd_ != 0) {
            const std::uint32_t increase = std::max<std::uint32_t>(
                1U, static_cast<std::uint32_t>((static_cast<std::uint64_t>(mss_) * mss_) / cwnd_));
            cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                        ? std::numeric_limits<std::uint32_t>::max()
                        : cwnd_ + increase;
        }
    }
}

void AimdController::OnLoss(const LossEvent &ev) noexcept {
    (void)ev;
    // Fast retransmit path: set ssthresh and recovery window.
    // Called by TcpSendBuffer when dup_ack_count == 3.
    // The flight size is provided via OnFastRecoveryEntry().
}

void AimdController::OnFastRecoveryEntry(std::uint32_t flight) noexcept {
    ssthresh_ = std::max<std::uint32_t>(flight / 2U, static_cast<std::uint32_t>(mss_) * 2U);
    const std::uint64_t recovery_window = static_cast<std::uint64_t>(ssthresh_) + static_cast<std::uint64_t>(mss_) * 3U;
    cwnd_ = recovery_window > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                                        : static_cast<std::uint32_t>(recovery_window);
    fast_recovery_ = true;
}

void AimdController::OnDupAck() noexcept {
    if (fast_recovery_) {
        // Inflate cwnd by 1 MSS per dup ACK during recovery (RFC 5681).
        const std::uint64_t inflated = static_cast<std::uint64_t>(cwnd_) + mss_;
        cwnd_ = inflated > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                                     : static_cast<std::uint32_t>(inflated);
    }
}

void AimdController::OnFastRecoveryExit() noexcept {
    cwnd_ = ssthresh_;
    fast_recovery_ = false;
}

void AimdController::OnRto() noexcept {
    // RTO: ssthresh = max(flight/2, 2*MSS), cwnd = 1 MSS.
    // flight is passed in via the LossEvent or computed by caller;
    // here we just set cwnd = MSS and let the caller set ssthresh.
    // Actually, the caller (TcpSendBuffer) sets ssthresh before calling.
    cwnd_ = mss_;
    fast_recovery_ = false;
}

void AimdController::OnEcnCe() noexcept {
    // RFC 3168 §6.1.2: reduce cwnd/ssthresh as for a packet loss (RFC 5681).
    ssthresh_ = std::max<std::uint32_t>(cwnd_ / 2U, static_cast<std::uint32_t>(mss_) * 2U);
    cwnd_ = ssthresh_;
}

void AimdController::UpdateMss(std::uint16_t mss, bool pristine) noexcept {
    if (mss == 0 || mss == mss_)
        return;
    const std::uint16_t old_mss = mss_;
    mss_ = mss;
    if (pristine) {
        cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    } else if (mss_ < old_mss) {
        const std::uint64_t scaled = static_cast<std::uint64_t>(cwnd_) * mss_ / old_mss;
        cwnd_ = std::max<std::uint32_t>(mss_, static_cast<std::uint32_t>(scaled));
    }
}

void AimdController::Reset() noexcept {
    cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    ssthresh_ = std::numeric_limits<std::uint32_t>::max();
    fast_recovery_ = false;
}

// ---------------------------------------------------------------------------
// BbrController
// ---------------------------------------------------------------------------

namespace {

// STARTUP gain: 2/ln(2) ≈ 2.885
constexpr std::uint64_t kStartupGainQ8 = 738; // 2.885 * 256 ≈ 739, round down

// DRAIN gain: 1/kStartupGain ≈ 0.347
constexpr std::uint64_t kDrainGainQ8 = 89; // 0.347 * 256 ≈ 89

// PROBE_BW pacing gains (Q8 fixed-point):
// [1.25, 0.75, 1, 1, 1, 1, 1, 1] — the canonical BBRv1 cycle.
constexpr std::uint64_t kProbeBwGainsQ8[] = {320, 192, 256, 256, 256, 256, 256, 256};

std::uint64_t SaturatingMulDiv(std::uint64_t a, std::uint64_t num, std::uint64_t den) noexcept {
    if (den == 0 || a == 0 || num == 0)
        return 0;
    if (a > std::numeric_limits<std::uint64_t>::max() / num) {
        return std::numeric_limits<std::uint64_t>::max() / den;
    }
    return (a * num) / den;
}

/// Kernel mul_u64_u32_shr(): multiply a 64-bit value by a 32-bit multiplier
/// and right-shift, without overflow of the 96-bit intermediate.
std::uint64_t MulU64U32Shr(std::uint64_t a, std::uint32_t mul, std::uint32_t shift) noexcept {
    const std::uint32_t ah = static_cast<std::uint32_t>(a >> 32);
    const std::uint32_t al = static_cast<std::uint32_t>(a);
    std::uint64_t ret = static_cast<std::uint64_t>(al) * mul;
    ret >>= shift;
    if (ah != 0) {
        ret += static_cast<std::uint64_t>(ah) * mul << (32 - shift);
    }
    return ret;
}

} // namespace

BbrController::BbrController(std::uint16_t mss) noexcept : mss_(mss), cwnd_(static_cast<std::uint64_t>(mss) * 2U) {}

void BbrController::OnPacketSent(std::uint64_t bytes) noexcept { bytes_sent_ += bytes; }

void BbrController::OnAck(const RateSample &rs) noexcept {
    // Detect round start: a new round begins when we see an ACK for data
    // sent after the last round start.
    if (!round_started_ && rs.acked_bytes > 0) {
        round_started_ = true;
        round_start_bytes_ = bytes_sent_;
    }

    // Update bandwidth and RTT estimates.
    UpdateBtlBw(rs);
    UpdateRTprop(rs);

    // State machine transitions.
    switch (state_) {
    case State::Startup:
        // STARTUP exit is checked at the end of each round (see below).
        break;
    case State::Drain:
        // Transition to PROBE_BW once cwnd has been reduced to BDP or
        // less.  Check below after recomputing cwnd_, and again here so
        // that a round where we immediately drain exits without waiting
        // for the next ACK.
        break;
    case State::ProbeBw:
        AdvanceCycle(rs.now_ms);
        // Check if it's time to enter PROBE_RTT.
        if (rs.now_ms - rtprop_stamp_ms_ >= kProbeRttIntervalMs) {
            EnterProbeRtt(rs.now_ms);
        }
        break;
    case State::ProbeRtt:
        // Exit PROBE_RTT after the duration has elapsed.
        if (rs.now_ms - probe_rtt_enter_ms_ >= kProbeRttDurationMs) {
            ExitProbeRtt(rs.now_ms);
        }
        break;
    }

    // Recompute pacing rate and cwnd.
    if (btlbw_ > 0) {
        const std::uint64_t gain = state_ == State::Startup    ? kStartupGainQ8
                                   : state_ == State::Drain    ? kDrainGainQ8
                                   : state_ == State::ProbeRtt ? 256
                                                               : kProbeBwGainsQ8[cycle_index_];

        pacing_rate_ = SaturatingMulDiv(btlbw_, gain, 256);
    }

    const std::uint64_t bdp = Bdp();
    const std::uint64_t cwnd_gain = state_ == State::Startup    ? kStartupGainQ8
                                    : state_ == State::Drain    ? kDrainGainQ8
                                    : state_ == State::ProbeRtt ? 256
                                                                : kProbeBwGainsQ8[cycle_index_];

    // cwnd = max(BDP * gain, 4 * MSS)
    const std::uint64_t cwnd_from_bdp = SaturatingMulDiv(bdp, cwnd_gain, 256);
    cwnd_ = std::max<std::uint64_t>(cwnd_from_bdp, static_cast<std::uint64_t>(mss_) * 4U);

    // DRAIN exit is checked after recomputing cwnd, since the transition
    // depends on cwnd_ <= BDP.
    if (state_ == State::Drain) {
        CheckDrainDone();
    }

    // Round accounting.  A round ends after we've sent at least a round's
    // worth of additional bytes.  In the unit-test path (no OnPacketSent)
    // bytes_sent_ equals round_start_bytes_ at round start, so the round
    // ends on the same ACK and CheckStartupDone is invoked per-ACK.
    if (round_started_ && bytes_sent_ - round_start_bytes_ >= round_start_bytes_) {
        round_started_ = false;
        if (state_ == State::Startup) {
            CheckStartupDone();
        }
    }

    (void)rs.app_limited; // app-limited packets don't update BtlBw
}

void BbrController::UpdateBtlBw(const RateSample &rs) noexcept {
    if (rs.delivery_rate_bytes_per_sec == 0)
        return;
    if (rs.app_limited)
        return; // Don't update BtlBw on app-limited samples

    if (rs.delivery_rate_bytes_per_sec > btlbw_) {
        btlbw_ = rs.delivery_rate_bytes_per_sec;
    }

    // Track the maximum bandwidth sample seen during the current round.
    if (rs.delivery_rate_bytes_per_sec > startup_round_max_bw_) {
        startup_round_max_bw_ = rs.delivery_rate_bytes_per_sec;
    }
}

void BbrController::UpdateRTprop(const RateSample &rs) noexcept {
    if (rs.rtt_ms == 0)
        return;

    // Timestamped min filter over the last kRtpropWindowMs: samples older
    // than the window expire so the estimate re-measures after a path change
    // (R5 requirement 5, not a lifetime monotonic minimum).
    const std::uint64_t now = rs.now_ms;
    const std::uint8_t pos = rtprop_pos_;
    rtprop_pos_ = static_cast<std::uint8_t>((rtprop_pos_ + 1U) % kRtpropSampleCount);
    if (rtprop_count_ < kRtpropSampleCount)
        ++rtprop_count_;
    rtprop_samples_[pos] = RtpropSample{rs.rtt_ms, now};

    std::uint64_t min_rtt = 0;
    std::uint64_t min_time = 0;
    for (std::uint8_t i = 0; i < rtprop_count_; ++i) {
        const RtpropSample &s = rtprop_samples_[i];
        if (now - s.time_ms > kRtpropWindowMs)
            continue; // expired
        if (min_rtt == 0 || s.rtt_ms < min_rtt) {
            min_rtt = s.rtt_ms;
            min_time = s.time_ms;
        }
    }
    rtprop_ = min_rtt;
    rtprop_stamp_ms_ = min_time;
}

void BbrController::CheckStartupDone() noexcept {
    // Exit STARTUP after 3 rounds where the per-round max bandwidth does not
    // grow by more than 25% over the previous round's max bandwidth.
    const std::uint64_t current = startup_round_max_bw_;
    const std::uint64_t previous = startup_prev_round_max_bw_;

    if (previous > 0 && current > 0) {
        const std::uint64_t threshold = SaturatingMulDiv(previous, 5, 4); // 1.25x
        if (current <= threshold) {
            ++startup_rounds_no_growth_;
        } else {
            startup_rounds_no_growth_ = 0;
        }
    }

    startup_prev_round_max_bw_ = current;
    startup_round_max_bw_ = 0;

    if (startup_rounds_no_growth_ >= 3) {
        state_ = State::Drain;
        startup_rounds_no_growth_ = 0;
    }
}

void BbrController::CheckDrainDone() noexcept {
    // Exit DRAIN when in-flight <= BDP.
    const std::uint64_t bdp = Bdp();
    // We approximate inflight via the RateSample; this is checked by the
    // caller. For now, transition when BDP is known and cwnd is at BDP.
    if (bdp > 0 && cwnd_ <= bdp) {
        state_ = State::ProbeBw;
        cycle_index_ = 0;
        cycle_start_ms_ = 0;
    }
}

void BbrController::EnterProbeRtt(std::uint64_t now_ms) noexcept {
    state_ = State::ProbeRtt;
    probe_rtt_enter_ms_ = now_ms;
}

void BbrController::ExitProbeRtt(std::uint64_t now_ms) noexcept {
    rtprop_stamp_ms_ = now_ms;
    state_ = State::ProbeBw;
    cycle_index_ = 0;
    cycle_start_ms_ = now_ms;
}

void BbrController::AdvanceCycle(std::uint64_t now_ms) noexcept {
    if (cycle_start_ms_ == 0) {
        cycle_start_ms_ = now_ms;
        return;
    }
    // Each phase lasts RTprop (min RTT), but since we may not have a
    // stable RTprop, use a minimum of 1 ms per phase.
    const std::uint64_t phase_duration = rtprop_ > 0 ? rtprop_ : 1;
    if (now_ms - cycle_start_ms_ >= phase_duration) {
        cycle_start_ms_ = now_ms;
        cycle_index_ = (cycle_index_ + 1) % kCycleLen;
    }
}

std::uint32_t BbrController::CongestionWindow() const noexcept {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(cwnd_, std::numeric_limits<std::uint32_t>::max()));
}

std::uint32_t BbrController::PacingRate() const noexcept {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(pacing_rate_, std::numeric_limits<std::uint32_t>::max()));
}

std::uint64_t BbrController::Bdp() const noexcept {
    if (btlbw_ == 0 || rtprop_ == 0)
        return 0;
    return SaturatingMulDiv(btlbw_, rtprop_, 1000);
}

void BbrController::OnLoss(const LossEvent & /*ev*/) noexcept {
    // BBR does not reduce cwnd on loss (unlike AIMD).
    // Loss is used only to update the lost_bytes in RateSample.
}

void BbrController::OnRto() noexcept {
    // BBR should not typically experience RTO; if we do, it indicates
    // a severe issue. Reset to a conservative state.
    cwnd_ = static_cast<std::uint64_t>(mss_);
    pacing_rate_ = 0;
}

void BbrController::OnEcnCe() noexcept {
    // RFC 3168 §6.1.2: ECE signals congestion; cut cwnd to half (floor 2 MSS).
    cwnd_ = std::max<std::uint64_t>(cwnd_ / 2U, static_cast<std::uint64_t>(mss_) * 2U);
}

void BbrController::Reset() noexcept {
    btlbw_ = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
    rtprop_pos_ = 0;
    rtprop_count_ = 0;
    for (auto &s : rtprop_samples_)
        s = RtpropSample{};
    state_ = State::Startup;
    startup_rounds_no_growth_ = 0;
    startup_prev_round_max_bw_ = 0;
    startup_round_max_bw_ = 0;
    cycle_index_ = 0;
    cycle_start_ms_ = 0;
    probe_rtt_enter_ms_ = 0;
    pacing_rate_ = 0;
    cwnd_ = static_cast<std::uint64_t>(mss_) * 2U;
    bytes_sent_ = 0;
    round_start_bytes_ = 0;
    round_started_ = false;
}

// ---------------------------------------------------------------------------
// HybridBdpAimdController
// ---------------------------------------------------------------------------

HybridBdpAimdController::HybridBdpAimdController(std::uint16_t mss) noexcept
    : mss_(mss), round_target_bytes_(static_cast<std::uint64_t>(mss) * 2U), cwnd_(static_cast<std::uint32_t>(mss) * 2U),
      ssthresh_(std::numeric_limits<std::uint32_t>::max()) {}

void HybridBdpAimdController::OnPacketSent(std::uint64_t /*bytes*/) noexcept {
    // Round detection is ACK-based (see OnAck), so send-side bookkeeping is
    // not required.  This hook is kept for interface symmetry with BBR.
}

void HybridBdpAimdController::EndRound() noexcept {
    // Fold the current round's max bandwidth into the windowed max filter and
    // recompute BtlBw as the max over the last ~kBtlBwWindowRounds rounds.
    round_btlbw_window_[round_btlbw_pos_] = round_btlbw_current_;
    round_btlbw_pos_ = (round_btlbw_pos_ + 1U) % kBtlBwWindowRounds;
    if (round_btlbw_count_ < kBtlBwWindowRounds)
        ++round_btlbw_count_;

    round_btlbw_current_ = 0;

    std::uint64_t max_bw = 0;
    for (std::uint8_t i = 0; i < round_btlbw_count_; ++i) {
        max_bw = std::max(max_bw, round_btlbw_window_[i]);
    }
    btlbw_ = max_bw;

    round_start_delivered_ = delivered_;
    // The next round's target is the cwnd observed during the round just
    // completed (BBR-style: a round is one window's worth of delivery).
    round_target_bytes_ = cwnd_;
}

void HybridBdpAimdController::UpdateBtlBw(const RateSample &rs) noexcept {
    if (rs.delivery_rate_bytes_per_sec == 0)
        return;
    if (rs.app_limited)
        return; // Don't update BtlBw on app-limited samples

    // Accumulate into the current (in-progress) round's max.
    if (rs.delivery_rate_bytes_per_sec > round_btlbw_current_) {
        round_btlbw_current_ = rs.delivery_rate_bytes_per_sec;
    }
}

void HybridBdpAimdController::UpdateRTprop(const RateSample &rs) noexcept {
    if (rs.rtt_ms == 0)
        return;

    // Timestamped min filter: drop samples older than kRtpropWindowMs so the
    // estimate re-measures after a path change.
    const std::uint64_t now = rs.now_ms;
    const std::uint8_t pos = rtprop_pos_;
    rtprop_pos_ = (rtprop_pos_ + 1U) % kRtpropSampleCount;
    if (rtprop_count_ < kRtpropSampleCount)
        ++rtprop_count_;
    rtprop_samples_[pos] = RtpropSample{rs.rtt_ms, now};

    std::uint64_t min_rtt = 0;
    std::uint64_t min_time = 0;
    for (std::uint8_t i = 0; i < rtprop_count_; ++i) {
        const RtpropSample &s = rtprop_samples_[i];
        if (now - s.time_ms > kRtpropWindowMs)
            continue; // expired
        if (min_rtt == 0 || s.rtt_ms < min_rtt) {
            min_rtt = s.rtt_ms;
            min_time = s.time_ms;
        }
    }
    rtprop_ = min_rtt;
    rtprop_stamp_ms_ = min_time;
}

std::uint64_t HybridBdpAimdController::Bdp() const noexcept {
    if (btlbw_ == 0 || rtprop_ == 0)
        return 0;
    // BDP = btlbw (bytes/sec) * rtprop (ms) / 1000
    if (btlbw_ > std::numeric_limits<std::uint64_t>::max() / rtprop_) {
        return std::numeric_limits<std::uint64_t>::max() / 1000;
    }
    return (btlbw_ * rtprop_) / 1000;
}

void HybridBdpAimdController::RecomputeCwnd() noexcept {
    // cwnd = max(BDP, 4*MSS) in normal operation.
    const std::uint64_t bdp = Bdp();
    const std::uint64_t floor = static_cast<std::uint64_t>(mss_) * 4U;
    const std::uint64_t target = std::max(bdp, floor);
    cwnd_ = target > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                               : static_cast<std::uint32_t>(target);
}

void HybridBdpAimdController::OnAck(const RateSample &rs) noexcept {
    if (fast_recovery_) {
        // During fast recovery, cwnd was already inflated; do not grow
        // further on normal ACKs.  The exit happens via OnFastRecoveryExit().
        return;
    }

    if (!round_started_) {
        round_started_ = true;
        round_start_delivered_ = delivered_;
        round_target_bytes_ = cwnd_;
    }

    // Update bandwidth and RTT estimates.
    UpdateBtlBw(rs);
    UpdateRTprop(rs);

    delivered_ += rs.acked_bytes;

    // Close the round once ~cwnd bytes have been acknowledged since it began,
    // folding the round's max bandwidth into the windowed filter.
    if (delivered_ - round_start_delivered_ >= round_target_bytes_) {
        EndRound();
    }

    // Update pacing rate: BtlBw * 1.0 (conservative, no gain inflation).
    pacing_rate_ = btlbw_;

    if (btlbw_ == 0 || rtprop_ == 0) {
        // BtlBw not yet known: slow start (increase by acked bytes, up to MSS).
        if (rs.acked_bytes > 0) {
            const std::uint32_t increase = static_cast<std::uint32_t>(std::min<std::uint64_t>(rs.acked_bytes, mss_));
            cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                        ? std::numeric_limits<std::uint32_t>::max()
                        : cwnd_ + increase;
        }
    } else {
        // BDP is known: cwnd = max(BDP, 4*MSS).
        RecomputeCwnd();
    }
}

void HybridBdpAimdController::OnLoss(const LossEvent & /*ev*/) noexcept {
    // Fast retransmit path: set ssthresh and recovery window.
    // Called by TcpSendBuffer when dup_ack_count == 3.
    // The flight size is provided via OnFastRecoveryEntry().
}

void HybridBdpAimdController::OnFastRecoveryEntry(std::uint32_t flight) noexcept {
    ssthresh_ = std::max<std::uint32_t>(flight / 2U, static_cast<std::uint32_t>(mss_) * 2U);
    const std::uint64_t recovery_window = static_cast<std::uint64_t>(ssthresh_) + static_cast<std::uint64_t>(mss_) * 3U;
    cwnd_ = recovery_window > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                                        : static_cast<std::uint32_t>(recovery_window);
    fast_recovery_ = true;
}

void HybridBdpAimdController::OnDupAck() noexcept {
    if (fast_recovery_) {
        // Inflate cwnd by 1 MSS per dup ACK during recovery (RFC 5681).
        const std::uint64_t inflated = static_cast<std::uint64_t>(cwnd_) + mss_;
        cwnd_ = inflated > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                                     : static_cast<std::uint32_t>(inflated);
    }
}

void HybridBdpAimdController::OnFastRecoveryExit() noexcept {
    cwnd_ = ssthresh_;
    fast_recovery_ = false;
}

void HybridBdpAimdController::OnRto() noexcept {
    // RTO: cwnd = 1 MSS, exit fast recovery, and invalidate the estimates so
    // the flow re-measures the path.
    cwnd_ = mss_;
    fast_recovery_ = false;
    pacing_rate_ = 0;
    btlbw_ = 0;
    round_btlbw_current_ = 0;
    round_btlbw_pos_ = 0;
    round_btlbw_count_ = 0;
    for (auto &v : round_btlbw_window_)
        v = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
    rtprop_pos_ = 0;
    rtprop_count_ = 0;
    for (auto &s : rtprop_samples_)
        s = RtpropSample{};
    delivered_ = 0;
    round_start_delivered_ = 0;
    round_target_bytes_ = static_cast<std::uint64_t>(mss_) * 2U;
    round_started_ = false;
}

void HybridBdpAimdController::OnEcnCe() noexcept {
    // RFC 3168 §6.1.2: reduce cwnd/ssthresh as for a packet loss (RFC 5681).
    ssthresh_ = std::max<std::uint32_t>(cwnd_ / 2U, static_cast<std::uint32_t>(mss_) * 2U);
    cwnd_ = ssthresh_;
}

std::uint32_t HybridBdpAimdController::CongestionWindow() const noexcept { return cwnd_; }

std::uint32_t HybridBdpAimdController::PacingRate() const noexcept {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(pacing_rate_, std::numeric_limits<std::uint32_t>::max()));
}

void HybridBdpAimdController::UpdateMss(std::uint16_t mss, bool pristine) noexcept {
    if (mss == 0 || mss == mss_)
        return;
    const std::uint16_t old_mss = mss_;
    mss_ = mss;
    if (pristine) {
        cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    } else if (mss_ < old_mss) {
        const std::uint64_t scaled = static_cast<std::uint64_t>(cwnd_) * mss_ / old_mss;
        cwnd_ = std::max<std::uint32_t>(mss_, static_cast<std::uint32_t>(scaled));
    }
    round_target_bytes_ = cwnd_;
}

void HybridBdpAimdController::Reset() noexcept {
    btlbw_ = 0;
    round_btlbw_current_ = 0;
    round_btlbw_pos_ = 0;
    round_btlbw_count_ = 0;
    for (auto &v : round_btlbw_window_)
        v = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
    rtprop_pos_ = 0;
    rtprop_count_ = 0;
    for (auto &s : rtprop_samples_)
        s = RtpropSample{};
    cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    ssthresh_ = std::numeric_limits<std::uint32_t>::max();
    fast_recovery_ = false;
    pacing_rate_ = 0;
    delivered_ = 0;
    round_start_delivered_ = 0;
    round_target_bytes_ = static_cast<std::uint64_t>(mss_) * 2U;
    round_started_ = false;
}

// ---------------------------------------------------------------------------
// KccController — KCC v2.0 geodesic congestion control.
//
// Faithful port of liulilittle/kcc tcp_kcc.c (commit 227a20b, BSD/GPL dual
// license).  All state lives in the controller; kernel-only subsystems
// (global KF, TSO, /proc, sysctl) are omitted.  Segment-domain arithmetic
// (BW_UNIT = 1<<24 segments/usec) matches upstream exactly.
// ---------------------------------------------------------------------------

namespace {

// Kernel div_u64(a, b): 64/64 division with 64-bit result.
std::uint64_t DivU64(std::uint64_t a, std::uint64_t b) noexcept { return b == 0 ? 0 : a / b; }

} // namespace

std::uint32_t KccController::Segments(std::uint64_t bytes, std::uint16_t mss) noexcept {
    if (mss == 0)
        return 0;
    return static_cast<std::uint32_t>(bytes / mss);
}

std::uint64_t KccController::RateBytesPerSec(std::uint64_t rate, std::uint32_t gain) const noexcept {
    rate *= mss_;
    rate = MulU64U32Shr(rate, gain, kBbrScale);
    rate = MulU64U32Shr(rate, 1000000, kBandwidthScale);
    return rate;
}

void KccController::Minmax::Reset(std::uint32_t t, std::uint32_t meas) noexcept {
    s[0].t = s[1].t = s[2].t = t;
    s[0].v = s[1].v = s[2].v = meas;
}

void KccController::Minmax::RunningMax(std::uint32_t win, std::uint32_t t, std::uint32_t meas) noexcept {
    if (s[0].t == s[1].t) {
        if (meas > s[0].v)
            s[0].v = meas;
    } else {
        s[0].t = s[1].t;
        s[0].v = s[1].v;
    }
    if (s[0].v >= s[1].v && s[0].v >= s[2].v) {
        s[1].v = s[0].v;
        s[1].t = t;
    }
    if (meas >= s[2].v) {
        s[2].v = meas;
        s[2].t = t;
    }
    if (KccController::Before(t, s[0].t)) {
        s[0] = s[1];
        s[1] = s[2];
        s[2].v = meas;
        s[2].t = t;
    }
    if (KccController::Before(s[0].t, t - win)) {
        s[0] = s[1];
        s[1] = s[2];
        s[2].v = meas;
        s[2].t = t;
    }
}

KccController::KccController(std::uint16_t mss, KccConfig config) noexcept : mss_(mss), config_(config) { Reset(); }

std::uint32_t KccController::CongestionWindow() const noexcept {
    const std::uint64_t bytes = static_cast<std::uint64_t>(cwnd_) * mss_;
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(bytes, std::numeric_limits<std::uint32_t>::max()));
}

std::uint32_t KccController::PacingRate() const noexcept {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(pacing_rate_, std::numeric_limits<std::uint32_t>::max()));
}

std::uint64_t KccController::BtlBw() const noexcept { return RateBytesPerSec(ActiveBw(), kBbrUnit); }

void KccController::OnPacketSent(std::uint64_t /*bytes*/) noexcept {
    // KCC bandwidth estimation is ACK-driven (delivered counter); no
    // send-side bookkeeping is required.
}

void KccController::OnAck(const RateSample &rs) noexcept {
    if (!initialized_)
        return;

    inflight_segments_ = Segments(rs.inflight_bytes, mss_);
    if (rs.rtt_us > 0) {
        srtt_us_ = srtt_us_ == 0 ? static_cast<std::uint32_t>(rs.rtt_us)
                                 : static_cast<std::uint32_t>((7ULL * srtt_us_ + rs.rtt_us) / 8ULL);
        // Fair-share bootstrap from the per-shard KF once the first RTT is
        // known (the controller has no handshake measurement to seed from).
        if (!kf_seeded_) {
            SeedFromKf();
        }
    }

    const std::uint32_t acked_seg = Segments(rs.acked_bytes, mss_);
    const std::uint32_t lost_seg = Segments(rs.lost_bytes, mss_);
    lost_segments_ = static_cast<std::uint32_t>(lost_segments_ + lost_seg);
    delivered_mstamp_us_ = rs.now_us;

    const std::uint32_t prior_delivered_seg = delivered_segments_;
    delivered_segments_ = static_cast<std::uint32_t>(delivered_segments_ + acked_seg);

    // ---- kcc_main() ----
    UpdateModel(rs, acked_seg, prior_delivered_seg);

    // ACK aggregation confidence evaluation (uses fresh round_start from the
    // model update; snapshot pre_max BEFORE measure updates it).
    if (kAggExtraAckedGainNum != 0) {
        const std::uint32_t pre_max = agg_extra_acked_max_;
        const std::uint32_t extra = MeasureAckAggregation(rs, acked_seg);
        const std::uint16_t conf = EvaluateAggConfidence(extra, pre_max);
        agg_confidence_ = conf;
        agg_state_ = AggStateFromConfidence(conf);
        if (round_start_) {
            AggWatchdog();
        }
    }

    // Cross-connection KF feed at round boundary in PROBE_BW (upstream
    // kcc_main step 3); no-op when kf is null or disabled.
    FeedKalman(rs, acked_seg);

    ApplyCwndConstraints();

    const std::uint32_t bw = ActiveBw();
    SetPacingRate(bw, pacing_gain_);
    SetCwnd(rs, acked_seg, bw, cwnd_gain_);
}

void KccController::OnEcnCe() noexcept {
    // KCC reacts to ECN via the proactive EWMA cwnd_gain backoff
    // (kcc_update_ecn_ewma / kcc_ecn_backoff in the per-ACK path), not via a
    // reactive per-ECE window reduction — matching upstream. The send-buffer
    // ECE/CWR loop still runs; the controller deliberately does not halve the
    // window here.
}

void KccController::OnLoss(const LossEvent &ev) noexcept {
    const std::uint32_t lost_seg = Segments(ev.lost_bytes, mss_);
    lost_segments_ = static_cast<std::uint32_t>(lost_segments_ + lost_seg);
    if (lost_seg > 0 && !lt_bw_ && !lt_use_bw_) {
        LtBwSampling(lost_seg, false);
    }
}

void KccController::OnRto() noexcept {
    // kcc_set_state(TCP_CA_Loss): seed LT-BW sampling with a synthetic loss
    // event and treat the RTO as the end of a round.  KCC preserves pipe
    // capacity through loss (no cwnd collapse), matching upstream.
    prev_ca_state_ = CaState::Loss;
    round_start_ = true;
    if (!lt_bw_ || !lt_use_bw_) {
        LtBwSampling(1, false);
    }
}

void KccController::OnFastRecoveryEntry(std::uint32_t flight) noexcept {
    prior_cwnd_ = cwnd_;
    prev_ca_state_ = CaState::Recovery;
    packet_conservation_ = true;
    next_rtt_delivered_ = delivered_segments_;
    inflight_segments_ = Segments(flight, mss_);
    // cwnd = inflight + acked (acked ~ 0 at entry).
    cwnd_ = std::max<std::uint32_t>(inflight_segments_, kCwndAbsoluteMin);
}

void KccController::OnDupAck() noexcept {
    // KCC uses packet conservation during recovery; no per-dup-ACK inflation.
}

void KccController::OnFastRecoveryExit() noexcept {
    cwnd_ = std::max(cwnd_, prior_cwnd_);
    packet_conservation_ = false;
    ResetMode();
}

void KccController::UpdateMss(std::uint16_t mss, bool pristine) noexcept {
    if (mss == 0 || mss == mss_)
        return;
    mss_ = mss;
    // cwnd is tracked in segments; the byte window scales naturally with the
    // new MSS. On a pristine window (nothing in flight) reset to INIT_CWND.
    if (pristine) {
        cwnd_ = 10;
    }
}

void KccController::Reset() noexcept {
    min_rtt_us_ = 0;
    min_rtt_stamp_ms_ = 0;
    bw_.Reset(0, 0);
    rtt_cnt_ = 0;
    next_rtt_delivered_ = 0;
    mode_ = kModeStartup;
    prev_ca_state_ = CaState::Open;
    round_start_ = false;
    idle_restart_ = false;
    packet_conservation_ = false;
    lt_is_sampling_ = false;
    lt_rtt_cnt_ = 0;
    min_rtt_fast_fall_cnt_ = 0;
    probe_round_ = 0;
    probe_cooldown_ = 0;
    has_seen_rtt_ = false;
    lt_use_bw_ = false;
    pacing_gain_ = kStartupGain;
    cwnd_gain_ = kCwndPulseInit;
    alone_on_path_ = false;
    drain_ok_rounds_ = 0;
    prior_cwnd_ = 0;
    bw_stable_rounds_ = 0;
    drain_entry_pg_ = std::numeric_limits<std::uint32_t>::max();
    lt_bw_ = 0;
    lt_last_delivered_ = 0;
    lt_last_stamp_ms_ = 0;
    lt_last_lost_ = 0;
    round_rtt_min_ = std::numeric_limits<std::uint32_t>::max();
    prev_round_rtt_min_ = std::numeric_limits<std::uint32_t>::max();
    x_est_ = 0;
    confirm_cnt_ = 0;
    confirm_slow_cnt_ = 0;
    mr_update_rtt_cnt_ = 0;
    p_est_ = kPestInit;
    qdelay_avg_ = 0;
    sample_cnt_ = 0;
    jitter_ewma_ = 0;
    ecn_ewma_ = 0;
    last_delivered_ce_ = 0;
    ack_epoch_mstamp_us_ = 0;
    extra_acked_[0] = 0;
    extra_acked_[1] = 0;
    ack_epoch_acked_ = 0;
    extra_acked_win_rtts_ = 0;
    extra_acked_win_idx_ = 0;
    agg_extra_acked_ = 0;
    agg_extra_acked_max_ = 0;
    agg_confidence_ = 0;
    agg_state_ = kAggIdle;
    agg_comp_duration_ = 0;
    alone_confirm_cnt_ = 0;
    alone_exit_cnt_ = 0;
    // Kernel TCP_INIT_CWND = 10.
    cwnd_ = 10;
    pacing_rate_ = 0;
    srtt_us_ = 0;
    delivered_segments_ = 0;
    lost_segments_ = 0;
    delivered_mstamp_us_ = 0;
    inflight_segments_ = 0;
    initialized_ = true;
    // KF fair-share bootstrap runs on the first data ACK once RTT is known
    // (see OnAck); kf_seeded_ guards against re-seeding on later resets.
}

std::uint32_t KccController::ModelRtt() const noexcept {
    if (x_est_ == 0 || sample_cnt_ < kMinSamples) {
        return min_rtt_us_;
    }
    return std::min<std::uint32_t>(static_cast<std::uint32_t>(x_est_ >> kKccScaleShift), min_rtt_us_);
}

std::uint32_t KccController::Bdp(std::uint32_t bw, std::uint32_t gain) const noexcept {
    std::uint32_t model_rtt = ModelRtt();
    if (!(x_est_ != 0 && sample_cnt_ >= kMinSamples) && model_rtt < kBdpMinRttUs) {
        model_rtt = kBdpMinRttUs;
    }
    const std::uint64_t w = static_cast<std::uint64_t>(bw) * model_rtt;
    std::uint64_t bdp64 = MulU64U32Shr(w, gain, kBbrScale);
    bdp64 += kBandwidthUnit - 1;
    return static_cast<std::uint32_t>(bdp64 >> kBandwidthScale);
}

std::uint32_t KccController::QuantizationBudget(std::uint32_t cwnd) const noexcept {
    // Burst headroom: replace the upstream TSO/GSO burst term (3 * tso_segs_goal)
    // with an equivalent pacing-interval budget, since Netstack2 transmits
    // per-packet with no GSO. One pacing interval's worth of segments (~1 ms),
    // capped at the upstream TSO burst ceiling of 64 segments.
    std::uint32_t burst_segs = 1;
    if (pacing_rate_ > 0 && mss_ > 0) {
        burst_segs = static_cast<std::uint32_t>(std::max<std::uint64_t>(1ULL, pacing_rate_ / 1000 / mss_));
        burst_segs = std::min(burst_segs, 64U);
    }
    cwnd += kTsoHeadroomMult * burst_segs;
    cwnd = (cwnd + 1U) & ~1U;
    if (mode_ == kModeStartup) {
        cwnd += kProbeCwndBonus;
    }
    return cwnd;
}

std::uint32_t KccController::CleanThresh() const noexcept {
    return std::max<std::uint32_t>(
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(min_rtt_us_) * kQdelayCleanBp / kQdelayBpBase),
        kQdelayFloorUs);
}

std::uint32_t KccController::CongThresh() const noexcept {
    return std::max<std::uint32_t>(
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(min_rtt_us_) * kQdelayCongBp / kQdelayBpBase),
        kQdelayFloorUs);
}

void KccController::InitPacingRateFromRtt() noexcept {
    const std::uint32_t rtt_us = srtt_us_ != 0 ? std::max(srtt_us_, kRttMinFloorUs) : 1000 /* KCC_DEFAULT_RTT_US */;
    if (srtt_us_ != 0) {
        has_seen_rtt_ = true;
    }
    std::uint64_t bw = static_cast<std::uint64_t>(cwnd_) << kBandwidthScale;
    bw = DivU64(bw, rtt_us);
    pacing_rate_ = RateBytesPerSec(bw, 739 /* KCC_PACING_INIT_GAIN */);
}

void KccController::SetPacingRate(std::uint32_t bw, std::uint32_t gain) noexcept {
    if (!has_seen_rtt_ && srtt_us_ != 0) {
        InitPacingRateFromRtt();
        return;
    }
    pacing_rate_ = RateBytesPerSec(bw, gain);
}

void KccController::ResetMode() noexcept {
    mode_ = kModeProbeBw;
    pacing_gain_ = kBbrUnit;
    cwnd_gain_ = kBbrUnit;
    probe_round_ = 0;
    probe_cooldown_ = 0;
    drain_ok_rounds_ = 0;
    drain_entry_pg_ = std::numeric_limits<std::uint32_t>::max();
    bw_stable_rounds_ = 0;
    prev_ca_state_ = CaState::Open;
    packet_conservation_ = false;
    min_rtt_fast_fall_cnt_ = 0;
}

void KccController::ResetLtBwSamplingInterval() noexcept {
    lt_last_stamp_ms_ = static_cast<std::uint32_t>(DivU64(delivered_mstamp_us_ + 500, 1000));
    lt_last_delivered_ = delivered_segments_;
    lt_last_lost_ = lost_segments_;
    lt_rtt_cnt_ = 0;
}

void KccController::ResetLtBwSampling() noexcept {
    lt_bw_ = 0;
    lt_use_bw_ = false;
    lt_is_sampling_ = false;
    ResetLtBwSamplingInterval();
}

void KccController::LtBwIntervalDone(std::uint64_t bw) noexcept {
    if (lt_bw_ != 0) {
        const std::uint64_t diff = bw > lt_bw_ ? bw - lt_bw_ : lt_bw_ - bw;
        const std::uint64_t rel_tol = (static_cast<std::uint64_t>(kLtBwRatioNum) << kBbrScale) * lt_bw_ / kLtBwRatioDen;
        if (((diff << kBbrScale) <= rel_tol) || RateBytesPerSec(diff, kBbrUnit) <= kLtBwDiff) {
            lt_bw_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                (bw * kLtBwEmaNum + static_cast<std::uint64_t>(lt_bw_) * (kLtBwEmaDen - kLtBwEmaNum)) / kLtBwEmaDen,
                std::numeric_limits<std::uint32_t>::max()));
            const std::uint32_t qthresh = CongThresh();
            const std::uint32_t ithresh = CongThresh();
            if (qdelay_avg_ > qthresh) {
                ResetLtBwSampling();
                return;
            }
            if (srtt_us_ != 0 && srtt_us_ > min_rtt_us_ + ithresh) {
                ResetLtBwSampling();
                return;
            }
            lt_bw_ = std::max<std::uint32_t>(lt_bw_, 1U);
            lt_use_bw_ = true;
            pacing_gain_ = kBbrUnit;
            lt_rtt_cnt_ = 0;
            return;
        }
    }
    lt_bw_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(bw, std::numeric_limits<std::uint32_t>::max()));
    ResetLtBwSamplingInterval();
}

void KccController::LtBwSampling(std::uint32_t lost_seg, bool is_app_limited) noexcept {
    // Mode A: LT BW already active — periodically re-probe the path.
    if (lt_use_bw_) {
        if (mode_ == kModeProbeBw && round_start_) {
            std::uint32_t cnt = lt_rtt_cnt_ + 1;
            if (cnt > 4095)
                cnt = 4095;
            lt_rtt_cnt_ = cnt;
            if (cnt >= kLtBwMaxRtts) {
                ResetLtBwSampling();
                ResetMode();
            }
        }
        return;
    }

    // Mode B: not active — trigger on first loss.
    if (!lt_is_sampling_) {
        if (lost_seg == 0)
            return;
        ResetLtBwSamplingInterval();
        lt_is_sampling_ = true;
    }

    if (is_app_limited) {
        ResetLtBwSampling();
        return;
    }

    if (round_start_) {
        lt_rtt_cnt_ = std::min<std::uint32_t>(lt_rtt_cnt_ + 1, 4095);
    }
    if (lt_rtt_cnt_ < kLtIntvlMinRtts)
        return;
    if (lt_rtt_cnt_ >= kLtIntvlMaxMult * kLtIntvlMinRtts) {
        ResetLtBwSampling();
        return;
    }

    const std::uint32_t lost = static_cast<std::uint32_t>(lost_segments_ - lt_last_lost_);
    const std::uint32_t delivered = static_cast<std::uint32_t>(delivered_segments_ - lt_last_delivered_);
    if (delivered == 0 ||
        (static_cast<std::uint64_t>(lost) << kBbrScale) < (static_cast<std::uint64_t>(kLtLossThresh) * delivered)) {
        return;
    }

    const std::uint64_t t_us = (DivU64(delivered_mstamp_us_ + 500, 1000) - lt_last_stamp_ms_) * 1000;
    if (t_us < 1000)
        return;

    std::uint64_t bw = static_cast<std::uint64_t>(delivered) << kBandwidthScale;
    bw = DivU64(bw, t_us);
    LtBwIntervalDone(bw);
}

void KccController::UpdateBw(const RateSample &rs, std::uint32_t acked_seg,
                             std::uint32_t prior_delivered_seg) noexcept {
    round_start_ = false;
    if (rs.interval_us <= 0)
        return;

    if (!Before(prior_delivered_seg, next_rtt_delivered_)) {
        next_rtt_delivered_ = delivered_segments_;
        ++rtt_cnt_;
        round_start_ = true;
        packet_conservation_ = false;
        prev_round_rtt_min_ = round_rtt_min_;
        round_rtt_min_ = std::numeric_limits<std::uint32_t>::max();
        if (rtt_cnt_ > 1)
            ++bw_stable_rounds_;
        if (probe_cooldown_ > 0)
            --probe_cooldown_;
    }

    LtBwSampling(Segments(rs.lost_bytes, mss_), rs.app_limited);

    const std::uint64_t bw = DivU64(static_cast<std::uint64_t>(acked_seg) << kBandwidthScale, rs.interval_us);
    const std::uint32_t prev_max = MaxBw();
    if (!rs.app_limited || bw >= prev_max) {
        bw_.RunningMax(
            kBwRtCycleLen, rtt_cnt_,
            static_cast<std::uint32_t>(std::min<std::uint64_t>(bw, std::numeric_limits<std::uint32_t>::max())));
    }
    if (MaxBw() > prev_max) {
        bw_stable_rounds_ = 0;
    }
}

void KccController::Update(const RateSample &rs) noexcept {
    const std::uint32_t rtt_us = std::max<std::uint32_t>(static_cast<std::uint32_t>(rs.rtt_us), kRttMinFloorUs);
    const std::uint64_t z = static_cast<std::uint64_t>(rtt_us) << kKccScaleShift;

    if (sample_cnt_ == 0) {
        x_est_ = z;
        p_est_ = kPestInit;
        qdelay_avg_ = 0;
        jitter_ewma_ = std::max<std::uint32_t>(rtt_us >> kJitterSeedShift, kRttMinFloorUs);
        sample_cnt_ = 1;
        return;
    }

    if (sample_cnt_ == 1 && min_rtt_us_ != 0) {
        const std::uint64_t ceiling = static_cast<std::uint64_t>(min_rtt_us_) << kKccScaleShift;
        if (x_est_ > ceiling)
            x_est_ = ceiling;
    }

    const std::int64_t innovation = static_cast<std::int64_t>(z) - static_cast<std::int64_t>(x_est_);
    const std::uint64_t abs_innov =
        innovation >= 0 ? static_cast<std::uint64_t>(innovation) : static_cast<std::uint64_t>(-innovation);

    // [G1] downward: instant minimum; [G2] upward: capped 12.2%/RTT growth.
    if (innovation <= 0) {
        x_est_ = std::min(x_est_, z);
    } else {
        const std::uint64_t growth = x_est_ * kG2GrowthNum / kG2GrowthDen;
        x_est_ = std::min(x_est_ + growth, z);
    }

    // Staleness guard: if min_rtt hasn't been refreshed for 128+ rounds and
    // x_est sits near min_rtt, force a reset to prevent drift lock.
    if (rtt_cnt_ - mr_update_rtt_cnt_ >= kStalenessRnds) {
        const std::uint64_t mr_scaled = static_cast<std::uint64_t>(min_rtt_us_) << kKccScaleShift;
        if (x_est_ <= mr_scaled * kG3FastThNum / kG3FastThDen) {
            x_est_ = mr_scaled * kPdNoiseGateNum / kPdNoiseGateDen;
            mr_update_rtt_cnt_ = rtt_cnt_;
        }
    }

    // Jitter EWMA from the accepted innovation.
    {
        const std::uint32_t raw_jitter = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(abs_innov >> kKccScaleShift, std::numeric_limits<std::uint32_t>::max()));
        jitter_ewma_ =
            sample_cnt_ > 1
                ? static_cast<std::uint32_t>((static_cast<std::uint64_t>(jitter_ewma_) * kEwmaJitterNum + raw_jitter) /
                                             kEwmaJitterDen)
                : raw_jitter;
    }
    jitter_ewma_ = std::min<std::uint32_t>(jitter_ewma_, std::max<std::uint32_t>(min_rtt_us_, kRttSampleMaxUs));

    // EWMA queuing delay (T_queue proxy).
    {
        const std::uint64_t t_prop_scaled = x_est_;
        const std::uint32_t qdelay_instant =
            z > t_prop_scaled ? static_cast<std::uint32_t>((z - t_prop_scaled) >> kKccScaleShift) : 0;
        qdelay_avg_ =
            sample_cnt_ == 1
                ? qdelay_instant
                : static_cast<std::uint32_t>(
                      (static_cast<std::uint64_t>(qdelay_avg_) * kEwmaQdelayNum + qdelay_instant) / kEwmaQdelayDen);
    }

    if (sample_cnt_ < std::numeric_limits<std::uint32_t>::max()) {
        ++sample_cnt_;
    }

    // p_est convergence proxy: decay when stable, grow on path increase.
    if (sample_cnt_ >= kMinSamples) {
        const std::uint64_t x_est_us = x_est_ >> kKccScaleShift;
        if (x_est_us <= static_cast<std::uint64_t>(min_rtt_us_) * kG3SlowThNum / kG3SlowThDen && confirm_cnt_ == 0 &&
            confirm_slow_cnt_ == 0) {
            const std::uint32_t delta = p_est_ > kPestFloor ? (p_est_ - kPestFloor) >> kPestDecayShift : 0;
            if (p_est_ > kPestFloor + delta) {
                p_est_ -= std::max<std::uint32_t>(delta, 1U);
            }
        } else if (x_est_us > static_cast<std::uint64_t>(min_rtt_us_) * kG3FastThNum / kG3FastThDen) {
            const std::uint32_t delta = p_est_ < kPestInit ? (kPestInit - p_est_) >> kPestGrowthShift : 0;
            if (p_est_ + delta < kPestMax) {
                p_est_ += std::max<std::uint32_t>(delta, 1U);
            }
        }
    }
}

void KccController::UpdateMinRtt(const RateSample &rs) noexcept {
    if (rs.rtt_us == 0)
        return; // invalid sample (upstream: rtt_us < 0)

    // Upstream seeds min_rtt_us from the TCP handshake RTT (tcp_min_rtt).
    // The controller has no handshake measurement, so seed from the first
    // valid data-ACK RTT sample to give the G3 baseline a non-zero anchor.
    if (min_rtt_us_ == 0) {
        min_rtt_us_ = std::max<std::uint32_t>(static_cast<std::uint32_t>(rs.rtt_us), kRttMinFloorUs);
        min_rtt_stamp_ms_ = rs.now_ms;
        mr_update_rtt_cnt_ = rtt_cnt_;
    }

    const std::uint32_t mr_snapshot = min_rtt_us_;
    std::uint32_t rtt_clamped = static_cast<std::uint32_t>(rs.rtt_us);
    const std::uint64_t now_ms = rs.now_ms;

    const bool filter_expired = now_ms >= min_rtt_stamp_ms_ + kProbeRttFilterMs;

    Update(rs); // geodesic G1/G2 on every valid RTT sample

    // [G3] dual-threshold path-increase detection.
    if (x_est_ >= static_cast<std::uint64_t>(min_rtt_us_) * (1u << kKccScaleShift) * kG3FastThNum / kG3FastThDen) {
        if (confirm_cnt_ < 255)
            ++confirm_cnt_;
        if (confirm_slow_cnt_ < 255)
            ++confirm_slow_cnt_;
    } else if (x_est_ >=
               static_cast<std::uint64_t>(min_rtt_us_) * (1u << kKccScaleShift) * kG3SlowThNum / kG3SlowThDen) {
        confirm_cnt_ = 0;
        if (confirm_slow_cnt_ < 255)
            ++confirm_slow_cnt_;
    } else {
        confirm_cnt_ = 0;
    }
    if (x_est_ <= static_cast<std::uint64_t>(min_rtt_us_) * (1u << kKccScaleShift)) {
        confirm_cnt_ = 0;
        confirm_slow_cnt_ = 0;
    }

    if (confirm_cnt_ >= kG3FastCnt) {
        min_rtt_us_ = static_cast<std::uint32_t>(x_est_ >> kKccScaleShift);
        min_rtt_stamp_ms_ = now_ms;
        confirm_cnt_ = 0;
        confirm_slow_cnt_ = 0;
        p_est_ = kPestInit;
        mr_update_rtt_cnt_ = rtt_cnt_;
    } else if (confirm_slow_cnt_ >= kG3SlowCnt) {
        min_rtt_us_ = static_cast<std::uint32_t>(x_est_ >> kKccScaleShift);
        min_rtt_stamp_ms_ = now_ms;
        confirm_cnt_ = 0;
        confirm_slow_cnt_ = 0;
        p_est_ = kPestInit;
        mr_update_rtt_cnt_ = rtt_cnt_;
    }

    // [G3] lock: counters non-zero freeze min_rtt manipulation.
    if (confirm_cnt_ > 0 || confirm_slow_cnt_ > 0) {
        return;
    }

    // ---- Traditional windowed min_rtt update ----
    bool min_fall_cnt_incr = false;
    if (rtt_clamped <= min_rtt_us_ || filter_expired) {
        rtt_clamped = std::max(rtt_clamped, kRttMinFloorUs);
        if (rtt_clamped < static_cast<std::uint64_t>(min_rtt_us_) * kMinRttStickyNum / kMinRttStickyDen) {
            if (rtt_clamped < min_rtt_us_ / kMinRttFastFallDiv) {
                min_rtt_us_ = rtt_clamped;
                min_rtt_fast_fall_cnt_ = 0;
            } else {
                min_rtt_fast_fall_cnt_ = std::min<std::uint8_t>(min_rtt_fast_fall_cnt_ + 1, 7);
                min_fall_cnt_incr = true;
                if (min_rtt_fast_fall_cnt_ >= kMinRttFastFallCnt) {
                    min_rtt_us_ = rtt_clamped;
                    min_rtt_fast_fall_cnt_ = 0;
                } else if (round_start_) {
                    min_rtt_us_ = std::max<std::uint32_t>(
                        kRttMinFloorUs, static_cast<std::uint32_t>(static_cast<std::uint64_t>(min_rtt_us_) *
                                                                   kMinRttStickyNum / kMinRttStickyDen));
                }
            }
        } else {
            min_rtt_us_ = rtt_clamped;
            min_rtt_fast_fall_cnt_ = 0;
        }
        min_rtt_stamp_ms_ = now_ms;
    } else if (!filter_expired && rtt_clamped >= min_rtt_us_) {
        min_rtt_fast_fall_cnt_ = 0;
    }

    // ---- SRTT guard ----
    if (srtt_us_ != 0 && min_rtt_us_ != 0) {
        const std::uint32_t srtt_shifted = std::max<std::uint32_t>(srtt_us_, kRttMinFloorUs);
        if (srtt_shifted < static_cast<std::uint64_t>(min_rtt_us_) * kMinRttSrttGuardNum / kMinRttSrttGuardDen) {
            min_rtt_us_ = srtt_shifted;
            min_rtt_stamp_ms_ = now_ms;
        }
    }

    if (rs.acked_bytes > 0) {
        idle_restart_ = false;
    }

    // ---- Geodesic min-rtt pull-down ----
    if (x_est_ != 0 && sample_cnt_ >= kMinSamples) {
        const std::uint32_t krtt = static_cast<std::uint32_t>(x_est_ >> kKccScaleShift);
        if (krtt < min_rtt_us_ && krtt < static_cast<std::uint64_t>(min_rtt_us_) * kPdNoiseGateNum / kPdNoiseGateDen) {
            if (!min_fall_cnt_incr) {
                min_rtt_fast_fall_cnt_ = std::min<std::uint8_t>(min_rtt_fast_fall_cnt_ + 1, 7);
                if (min_rtt_fast_fall_cnt_ >= kMinRttFastFallCnt) {
                    min_rtt_us_ = krtt;
                    min_rtt_fast_fall_cnt_ = 0;
                    min_rtt_stamp_ms_ = now_ms;
                    mr_update_rtt_cnt_ = rtt_cnt_;
                }
            }
        } else {
            min_rtt_fast_fall_cnt_ = 0;
        }
    }
    if (min_rtt_us_ != mr_snapshot) {
        mr_update_rtt_cnt_ = rtt_cnt_;
    }
}

void KccController::UpdateAckAggregation(const RateSample &rs, std::uint32_t acked_seg) noexcept {
    if (kAggExtraAckedGainNum == 0)
        return;
    if (acked_seg == 0 || rs.interval_us <= 0)
        return;

    if (round_start_) {
        extra_acked_win_rtts_ = std::min<std::uint32_t>(extra_acked_win_rtts_ + 1, kAggExtraAckedWinRttsMax);
        if (extra_acked_win_rtts_ >= kAggWindowRotationRtts) {
            extra_acked_win_rtts_ = 0;
            extra_acked_win_idx_ = extra_acked_win_idx_ ? 0 : 1;
            extra_acked_[extra_acked_win_idx_] = 0;
        }
    }

    const std::uint64_t epoch_us =
        delivered_mstamp_us_ > ack_epoch_mstamp_us_ ? delivered_mstamp_us_ - ack_epoch_mstamp_us_ : 0;
    std::uint32_t expected_acked;
    {
        const std::uint64_t bw_val = ActiveBw();
        expected_acked = static_cast<std::uint32_t>(
            std::min<std::uint64_t>((bw_val * epoch_us) >> kBandwidthScale, std::numeric_limits<std::uint32_t>::max()));
    }

    if (ack_epoch_acked_ <= expected_acked || ack_epoch_acked_ >= kAggEpochMax) {
        ack_epoch_acked_ = 0;
        ack_epoch_mstamp_us_ = delivered_mstamp_us_;
        expected_acked = 0;
    }
    ack_epoch_acked_ = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(kAggEpochMax, static_cast<std::uint64_t>(ack_epoch_acked_) + acked_seg));

    std::uint32_t extra_acked = ack_epoch_acked_ > expected_acked ? ack_epoch_acked_ - expected_acked : 0;
    extra_acked = std::min(extra_acked, cwnd_);
    if (extra_acked > extra_acked_[extra_acked_win_idx_]) {
        extra_acked_[extra_acked_win_idx_] = extra_acked;
    }
}

std::uint32_t KccController::AckAggregationCwnd(std::uint32_t bw) noexcept {
    std::uint32_t max_aggr_cwnd = 0;
    std::uint32_t aggr_cwnd = 0;
    const std::uint64_t gain = (static_cast<std::uint64_t>(kAggExtraAckedGainNum) << kBbrScale) / kAggExtraAckedGainDen;
    if (gain != 0) {
        const std::uint64_t max_ms = static_cast<std::uint64_t>(kAggExtraAckedMaxMsNum / kAggExtraAckedMaxMsDen) * 1000;
        const std::uint64_t product =
            max_ms == 0 ? std::numeric_limits<std::uint64_t>::max() : static_cast<std::uint64_t>(bw) * max_ms;
        max_aggr_cwnd = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(product >> kBandwidthScale, std::numeric_limits<std::uint32_t>::max()));
        const std::uint64_t aggr64 = (gain * std::max(extra_acked_[0], extra_acked_[1])) >> kBbrScale;
        aggr_cwnd = static_cast<std::uint32_t>(std::min<std::uint64_t>(aggr64, max_aggr_cwnd));
    }
    return aggr_cwnd;
}

std::uint32_t KccController::MeasureAckAggregation(const RateSample &rs, std::uint32_t acked_seg) noexcept {
    if (rs.interval_us <= 0)
        return 0;
    const std::uint32_t cur_bw = ActiveBw();
    const std::uint32_t expected_acked =
        static_cast<std::uint32_t>((static_cast<std::uint64_t>(cur_bw) * rs.interval_us) >> kBandwidthScale);
    std::uint32_t extra = acked_seg > expected_acked ? acked_seg - expected_acked : 0;
    extra = std::min(extra, cwnd_);
    const std::uint64_t max_ms2 = static_cast<std::uint64_t>(kAggMaxWindowMs) * 1000;
    const std::uint64_t bw_cap = (static_cast<std::uint64_t>(cur_bw) * max_ms2) >> kBandwidthScale;
    extra = std::min<std::uint32_t>(extra, static_cast<std::uint32_t>(bw_cap));
    if (extra > agg_extra_acked_max_)
        agg_extra_acked_max_ = extra;
    agg_extra_acked_ = extra;
    return extra;
}

std::uint16_t KccController::EvaluateAggConfidence(std::uint32_t extra_acked, std::uint32_t pre_max) const noexcept {
    std::uint16_t conf = 0;
    // Factor 1: estimator converged (p_est <= KCC_CONVERGED_MIN=1).  The
    // p_est floor is 10 upstream, so this never fires in v2.0 — kept faithful.
    if (p_est_ <= 1 && sample_cnt_ >= kMinSamples) {
        conf = static_cast<std::uint16_t>(conf + kAggFactorWeight);
    }
    // Factor 2: no loss recovery.
    if (!packet_conservation_) {
        conf = static_cast<std::uint16_t>(conf + kAggFactorWeight);
    }
    // Factor 3: no sustained queue delay (x_est near min_rtt).
    if (x_est_ > 0) {
        const std::uint32_t est_rtt = static_cast<std::uint32_t>(x_est_ >> kKccScaleShift);
        if (est_rtt <= min_rtt_us_ + CleanThresh()) {
            conf = static_cast<std::uint16_t>(conf + kAggFactorWeight);
        }
    }
    // Factor 4: not a transient spike vs history.
    if (extra_acked == 0 || pre_max == 0 ||
        static_cast<std::uint64_t>(extra_acked) * kAggFactor4RatioDen <=
            static_cast<std::uint64_t>(pre_max) * kAggFactor4RatioNum) {
        conf = static_cast<std::uint16_t>(conf + kAggFactorWeight);
    }
    return conf;
}

std::uint8_t KccController::AggStateFromConfidence(std::uint16_t confidence) const noexcept {
    if (confidence >= (kAggConfidenceMax - kAggFactorWeight)) {
        return kAggTrusted;
    }
    if (confidence >= kAggConfidenceThresh) {
        return kAggConfirmed;
    }
    if (confidence >= kAggFactorWeight) {
        return kAggSuspected;
    }
    return kAggIdle;
}

bool KccController::AggSafetyCheck(std::uint32_t bw) const noexcept {
    if (x_est_ > 0) {
        const std::uint32_t est_rtt = static_cast<std::uint32_t>(x_est_ >> kKccScaleShift);
        if (static_cast<std::uint64_t>(est_rtt) > static_cast<std::uint64_t>(min_rtt_us_) + CongThresh()) {
            return false;
        }
    }
    if (packet_conservation_)
        return false;
    const std::uint64_t bdp_est = (static_cast<std::uint64_t>(bw) * min_rtt_us_) >> kBandwidthScale;
    const std::uint32_t safe_cwnd = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(bdp_est * kAggSafetyBdpMult, std::numeric_limits<std::uint32_t>::max()));
    if (cwnd_ >= safe_cwnd)
        return false;
    if (static_cast<std::uint64_t>(inflight_segments_) >= static_cast<std::uint64_t>(safe_cwnd) + kTsoSegsGoal) {
        return false;
    }
    return true;
}

std::uint32_t KccController::AggCwndCompensation(std::uint32_t extra_acked, std::uint16_t confidence,
                                                 std::uint32_t bw) const noexcept {
    const std::uint32_t thr = kAggConfidenceThresh;
    if (confidence < thr)
        return 0;
    if (!AggSafetyCheck(bw))
        return 0;
    const std::uint32_t agg_est = std::max(extra_acked, agg_extra_acked_max_);
    std::uint32_t comp = 0;
    if (thr < kAggConfidenceMax) {
        comp = static_cast<std::uint32_t>(static_cast<std::uint64_t>(agg_est) * (confidence - thr) /
                                          (kAggConfidenceMax - thr));
    }
    const std::uint64_t bdp64 = (static_cast<std::uint64_t>(bw) * min_rtt_us_) >> kBandwidthScale;
    const std::uint32_t max_comp =
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(bdp64) * kAggMaxCompRatio / 100);
    comp = std::min(comp, max_comp);
    return comp;
}

void KccController::UpdateEcnEwma(const RateSample &rs) noexcept {
    // Port of kcc_update_ecn_ewma(). Reads the cumulative CE-marked segment
    // count from the rate sample (Netstack2's tp->delivered_ce) and maintains
    // an EWMA of the CE ratio in BBR_UNIT (256 = 100%).
    if (!config_.ecn)
        return;
    const std::uint32_t cur_ce = static_cast<std::uint32_t>(rs.delivered_ce);
    if (delivered_segments_ == 0)
        return;
    const std::uint64_t total = static_cast<std::uint64_t>(delivered_segments_) + lost_segments_;
    const std::uint32_t ce_delta = cur_ce - last_delivered_ce_;
    last_delivered_ce_ = cur_ce;

    if (ce_delta > 0) {
        const std::uint32_t instant =
            static_cast<std::uint32_t>((static_cast<std::uint64_t>(ce_delta) << kBbrScale) / total);
        if (ecn_ewma_ == 0) {
            ecn_ewma_ = instant;
        } else {
            ecn_ewma_ = (ecn_ewma_ * 3U + instant) / 4U;
        }
    } else if (ecn_ewma_ > 0) {
        if (round_start_) {
            ecn_ewma_ = ecn_ewma_ * 3U / 4U;
        } else if (ecn_ewma_ < 4U) {
            ecn_ewma_ = 0;
        } else {
            ecn_ewma_ = static_cast<std::uint32_t>(static_cast<std::uint64_t>(ecn_ewma_) * 31U / 32U);
        }
    }
}

void KccController::EcnBackoff() noexcept {
    // Port of kcc_ecn_backoff(). Netstack2 deviation: upstream's convergence
    // gate `p_est >= KCC_CONVERGED_MIN(1)` can never fire because the p_est
    // floor is 10, making the backoff dead code upstream. We drop that gate
    // and rely on the sample-count / qdelay / ewma checks so the backoff is
    // actually functional once CE marks coincide with queue buildup.
    if (!config_.ecn)
        return;
    if (sample_cnt_ < kMinSamples)
        return;
    if (ecn_ewma_ == 0)
        return;

    std::uint32_t ecn_backoff = (static_cast<std::uint64_t>(20U) << kBbrScale) / 100U;
    if (pacing_gain_ > kBbrUnit) {
        const std::uint32_t ecn_scale = (1U << (kBbrScale + kBbrScale)) / pacing_gain_;
        ecn_backoff = ecn_backoff * ecn_scale >> kBbrScale;
    }
    const std::uint32_t factor = kBbrUnit - std::min(ecn_backoff, kBbrUnit);
    if (qdelay_avg_ > CongThresh()) {
        cwnd_gain_ = std::min(cwnd_gain_, std::max<std::uint32_t>(1U, cwnd_gain_ * factor >> kBbrScale));
    }
}

void KccController::ApplyCwndConstraints() noexcept { EcnBackoff(); }

void KccController::FeedKalman(const RateSample &rs, std::uint32_t acked_seg) noexcept {
    if (config_.kf == nullptr || !config_.kf->enabled)
        return;
    if (!round_start_ || mode_ != kModeProbeBw)
        return;
    if (rs.interval_us == 0 || acked_seg == 0)
        return;
    // Upstream feeds the cumulative delivered counter over the sample
    // interval (kcc_main step 3); kept faithful.
    const std::uint64_t kbw = (static_cast<std::uint64_t>(delivered_segments_) << kBandwidthScale) / rs.interval_us;
    if (!config_.kf->Active()) {
        config_.kf->Update(kbw, 15U /* KCC_KF_STARTUP_R_PCT */, false);
    } else {
        config_.kf->Update(kbw, 5U /* KCC_KF_STEADY_R_PCT */, true);
    }
}

void KccController::SeedFromKf() noexcept {
    // Port of the KF-injection block in kcc_init(): bootstrap the sliding-window
    // max-BW filter, pacing rate and initial cwnd from the per-shard fair-share
    // estimate, if the estimate is available and above the local cwnd floor.
    if (config_.kf == nullptr || !config_.kf->enabled || !config_.kf->Active() || srtt_us_ == 0) {
        return;
    }
    const std::uint64_t init_bw = config_.kf->GetInitBw(cwnd_, srtt_us_);
    if (init_bw == 0)
        return;
    bw_.RunningMax(
        kBwRtCycleLen, 0,
        static_cast<std::uint32_t>(std::min<std::uint64_t>(init_bw, std::numeric_limits<std::uint32_t>::max())));
    pacing_rate_ = RateBytesPerSec(
        static_cast<std::uint32_t>(std::min<std::uint64_t>(init_bw, std::numeric_limits<std::uint32_t>::max())),
        kBbrUnit);
    const std::uint32_t lo = std::max(cwnd_, 10U);
    const std::uint32_t init_cwnd = std::max(lo, std::min(Bdp(static_cast<std::uint32_t>(std::min<std::uint64_t>(
                                                                  init_bw, std::numeric_limits<std::uint32_t>::max())),
                                                              kBbrUnit),
                                                          20000U));
    cwnd_ = init_cwnd;
    has_seen_rtt_ = true;
    kf_seeded_ = true;
}

void KccController::AggWatchdog() noexcept {
    if (!round_start_)
        return;
    agg_extra_acked_max_ =
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(agg_extra_acked_max_) * kAggMaxDecayPct / 100);
    if (agg_state_ >= kAggConfirmed) {
        if (agg_comp_duration_ < 255)
            ++agg_comp_duration_;
        if (agg_comp_duration_ > kAggMaxCompDuration) {
            agg_state_ = kAggSuspected;
            agg_comp_duration_ = 0;
        }
    } else {
        agg_comp_duration_ = 0;
    }
}

void KccController::UpdateGainsV2() noexcept {
    const std::uint32_t qdelay = prev_round_rtt_min_ > min_rtt_us_ ? prev_round_rtt_min_ - min_rtt_us_ : 0;
    const std::uint32_t excess = qdelay;
    const std::uint32_t tprop = std::max(min_rtt_us_, 1U);
    std::uint32_t pg = pacing_gain_;

    switch (mode_) {
    case kModeProbeBw: {
        if (excess < tprop / kExcessTargetDiv) {
            pg = std::min<std::uint32_t>(
                pg + static_cast<std::uint32_t>(static_cast<std::uint64_t>(kBbrUnit) * config_.ai_num / kPgAiDen),
                kPgMax);
        } else {
            const std::uint32_t md =
                static_cast<std::uint32_t>(static_cast<std::uint64_t>(pg) * excess * kProbeBwMdNum /
                                           (static_cast<std::uint64_t>(tprop) * kProbeBwMdDen));
            pg = pg > md ? std::max<std::uint32_t>(pg - md, kPgMin) : kPgMin;
        }
        if ((rtt_cnt_ & kPeriodicDrainMask) == 0) {
            pg = kPeriodicDrainPg;
        }
        // kcc_turbo (config, default on): 1.88x BDP cwnd floor.
        cwnd_gain_ = std::max<std::uint32_t>(pg, config_.turbo ? (kBbrUnit * kProbeBwCompeteRatio / 100) : kBbrUnit);
        if (excess >= tprop / kExcessDrainDiv && probe_cooldown_ == 0) {
            mode_ = kModeDrain;
            drain_ok_rounds_ = 0;
            drain_entry_pg_ = std::numeric_limits<std::uint32_t>::max();
        }
        break;
    }
    case kModeStartup: {
        std::uint32_t cg = pg;
        ++probe_round_;
        if (probe_round_ > kProbeRoundMax)
            probe_round_ = kProbeRoundMax;
        if (probe_round_ == 1) {
            pg = kStartupGain;
            cg = pg;
        }
        for (std::uint8_t i = 0; i < probe_round_; ++i) {
            cg = static_cast<std::uint32_t>(static_cast<std::uint64_t>(cg) * kCwndPulseGrowthNum / kCwndPulseGrowthDen);
        }
        if (probe_round_ == 1 && probe_cooldown_ == 0) {
            cg = std::min(cg, kStartupGain);
        } else {
            cg = std::min(cg, kCwndPulseMax);
        }
        cwnd_gain_ = cg;
        if (probe_cooldown_ == 0) {
            pg = std::min(cg, kStartupGain);
        } else {
            pg = std::min(cg, kPgMax);
        }
        if (excess >= tprop / 4) {
            probe_cooldown_ = kFpCooldown;
            mode_ = kModeDrain;
            drain_entry_pg_ = std::numeric_limits<std::uint32_t>::max();
            drain_ok_rounds_ = 0;
        } else if (bw_stable_rounds_ >= kCwndPulseBwStable && probe_round_ >= kCwndPulseExitRnds) {
            mode_ = kModeProbeBw;
            probe_cooldown_ = kFpCooldown;
        }
        break;
    }
    case kModeDrain: {
        if (drain_entry_pg_ == std::numeric_limits<std::uint32_t>::max()) {
            pg = kPeriodicDrainPg;
        } else {
            pg = std::max<std::uint32_t>(
                static_cast<std::uint32_t>(static_cast<std::uint64_t>(pg) * kDrainDecayNum / kDrainDecayDen), kPgMin);
        }
        cwnd_gain_ = static_cast<std::uint32_t>(static_cast<std::uint64_t>(pg) * pg / kBbrUnit);
        if (excess <= tprop / kExcessTargetDiv) {
            ++drain_ok_rounds_;
        } else if (excess < drain_entry_pg_) {
            ++drain_ok_rounds_;
        } else {
            drain_ok_rounds_ = 0;
        }
        drain_entry_pg_ = excess;
        if (drain_ok_rounds_ >= kDrainExitRnds) {
            mode_ = kModeProbeBw;
            probe_cooldown_ = kFpCooldown;
        }
        break;
    }
    default:
        pg = std::max<std::uint32_t>(std::min(pg, kPgMax), kPgMin);
        break;
    }

    pacing_gain_ = pg;
    if (mode_ != kModeStartup && mode_ != kModeProbeBw) {
        cwnd_gain_ = static_cast<std::uint32_t>(static_cast<std::uint64_t>(pg) * pg / kBbrUnit);
    }
}

void KccController::AloneOnPathEval() noexcept {
    if (!round_start_)
        return;
    if (pacing_gain_ != kBbrUnit)
        return;

    // KCC_ALONE_AGG_STATE_LEVEL = 1 -> default -> SUSPECTED.
    const std::uint8_t max_agg = kAggSuspected;
    if (sample_cnt_ >= kMinSamples && qdelay_avg_ < CleanThresh() && jitter_ewma_ < CongThresh() && ecn_ewma_ == 0 &&
        /* KCC_ALONE_BYPASS_LT_BW = 1 */ true && agg_state_ <= max_agg) {
        alone_exit_cnt_ = 0;
        if (alone_confirm_cnt_ < 255)
            ++alone_confirm_cnt_;
        if (alone_confirm_cnt_ >= kAloneConfirmRounds) {
            alone_on_path_ = true;
        }
    } else {
        if (alone_on_path_) {
            if (alone_exit_cnt_ < 255)
                ++alone_exit_cnt_;
            if (alone_exit_cnt_ >= kAloneExitThresh) {
                alone_on_path_ = false;
                alone_exit_cnt_ = 0;
                alone_confirm_cnt_ = 0;
            }
        } else {
            alone_confirm_cnt_ = 0;
        }
    }
}

void KccController::UpdateModel(const RateSample &rs, std::uint32_t acked_seg,
                                std::uint32_t prior_delivered_seg) noexcept {
    UpdateBw(rs, acked_seg, prior_delivered_seg);
    UpdateEcnEwma(rs);
    UpdateAckAggregation(rs, acked_seg);
    UpdateMinRtt(rs);

    // Per-round min RTT filter.
    if (rs.rtt_us > 0) {
        const std::uint32_t rtt_us = static_cast<std::uint32_t>(rs.rtt_us);
        if (rtt_us < round_rtt_min_)
            round_rtt_min_ = rtt_us;
    }

    if (prev_round_rtt_min_ < std::numeric_limits<std::uint32_t>::max()) {
        UpdateGainsV2();
    }

    AloneOnPathEval();
}

bool KccController::SetCwndToRecoverOrRestore(std::uint32_t acked_seg, std::uint32_t lost_seg,
                                              std::uint32_t *new_cwnd) noexcept {
    std::uint32_t cwnd = cwnd_;
    if (lost_seg > 0) {
        if (cwnd > lost_seg) {
            cwnd -= lost_seg;
        } else {
            cwnd = kCwndAbsoluteMin;
        }
    }
    // Recovery entry/exit transitions are driven by the send buffer via
    // OnFastRecoveryEntry/OnFastRecoveryExit; during a normal OnAck the flow
    // is always in Open state, so only the loss-reduction path is active here.
    if (packet_conservation_) {
        *new_cwnd = std::max<std::uint32_t>(cwnd, inflight_segments_ + acked_seg);
        return true;
    }
    *new_cwnd = cwnd;
    return false;
}

void KccController::SetCwnd(const RateSample &rs, std::uint32_t acked_seg, std::uint32_t bw,
                            std::uint32_t gain) noexcept {
    std::uint32_t cwnd = cwnd_;
    if (acked_seg == 0)
        goto done;
    if (SetCwndToRecoverOrRestore(acked_seg, Segments(rs.lost_bytes, mss_), &cwnd)) {
        goto done;
    }

    {
        std::uint32_t target = Bdp(bw, gain);
        const bool bdp_ready = bw > 0;
        target = QuantizationBudget(target);
        if (bdp_ready) {
            target += AckAggregationCwnd(bw);
            if (agg_state_ >= kAggConfirmed) {
                const std::uint32_t agg_comp = AggCwndCompensation(agg_extra_acked_, agg_confidence_, bw);
                target = std::min<std::uint32_t>(target + agg_comp, std::numeric_limits<std::uint32_t>::max());
            }
        }
        if (mode_ == kModeStartup) {
            cwnd = cwnd + acked_seg;
        } else {
            cwnd = std::min(cwnd + acked_seg, target);
        }
        cwnd = std::max(cwnd, kCwndMinTarget);
    }

done:
    cwnd_ = cwnd;
}

// ---------------------------------------------------------------------------
// KccKalmanFilter — per-shard cross-connection bandwidth filter (KCC KF).
//
// Port of the upstream global KF (kcc_kf_compute_R / kcc_kf_update /
// kcc_kf_get_init_bw) adapted to Netstack2's single-threaded-per-shard model:
// the upstream spinlock + atomic64 pair collapse to plain members because the
// filter is only touched by its owning shard thread.
// ---------------------------------------------------------------------------

namespace {

// Chi-squared gate: reject when nu^2/S > num/den (cross-multiplied).
constexpr std::uint64_t kKfChi2Num = 384;
constexpr std::uint64_t kKfChi2Den = 100;
constexpr std::uint32_t kKfQShift = 20;      // Q = 1<<20 (random-walk process noise)
constexpr std::uint32_t kKfSteadyRPct = 5;   // steady-state measurement noise %
constexpr std::uint32_t kKfStartupRPct = 15; // startup measurement noise %
constexpr std::uint32_t kKfInnovShift = 10;  // innovation downshift before ratio
constexpr std::uint32_t kKfVarShift = 20;    // 2 * kKfInnovShift
constexpr std::uint64_t kKfInnovSqCap = 3000000000ULL;
constexpr std::uint64_t kKfOverflowGuard = 1ULL << 31;
constexpr std::uint32_t kKfCwndSegsMax = 20000;
constexpr std::uint64_t kKfPacingInitGain = 739;

std::uint64_t KfComputeR(std::uint64_t z, std::uint32_t pct) noexcept {
    std::uint64_t r = z * pct / 100;
    if (r > std::numeric_limits<std::uint32_t>::max()) {
        r = std::numeric_limits<std::uint32_t>::max();
    }
    return r * r;
}

} // namespace

std::uint64_t KccKalmanFilter::Update(std::uint64_t z, std::uint32_t r_pct, bool check) noexcept {
    if (!enabled || z == 0)
        return x_;

    std::uint64_t P = p_;
    std::uint64_t x = x_;
    const std::uint64_t R = KfComputeR(z, r_pct);

    // Predict step: P = P + Q (random-walk).
    P += 1ULL << kKfQShift;

    // First sample: seed.
    if (!active_) {
        x = z;
        P = std::max<std::uint64_t>(R, 1ULL);
        active_ = true;
        p_ = P;
        x_ = x;
        if (steady_mode && x > peak_)
            peak_ = x;
        return x;
    }

    if (check) {
        const std::int64_t delta = static_cast<std::int64_t>(z) - static_cast<std::int64_t>(x);
        const std::uint64_t nu = delta < 0 ? static_cast<std::uint64_t>(-delta) : static_cast<std::uint64_t>(delta);
        std::uint64_t S = P + R;
        std::uint64_t nu2 = std::min(nu, kKfInnovSqCap);
        nu2 = (nu2 >> kKfInnovShift) * (nu2 >> kKfInnovShift);
        S >>= kKfVarShift;
        // Chi-squared gate: nu^2/S > num/den <=> nu^2*den > num*S.
        if (S > 0 && nu2 * kKfChi2Den > kKfChi2Num * S) {
            return x; // reject outlier, keep estimate
        }
    }

    std::uint64_t Pcopy = P;
    std::uint64_t Rcopy = R;
    std::uint64_t xcopy = x;
    std::uint64_t zcopy = z;
    std::uint32_t shift = 0;
    std::uint64_t max_v = Pcopy + Rcopy;
    while (max_v >= kKfOverflowGuard) {
        Pcopy >>= 1;
        Rcopy >>= 1;
        max_v >>= 1;
        ++shift;
    }
    xcopy >>= shift;
    zcopy >>= shift;

    const std::uint64_t denom = Pcopy + Rcopy;
    x = (xcopy * Rcopy + zcopy * Pcopy) / denom;
    P = Pcopy * Rcopy / denom;
    if (shift > 0) {
        x <<= shift;
        P <<= shift;
    }
    const std::uint64_t q = 1ULL << kKfQShift;
    if (P < q)
        P = q; // floor covariance at Q

    if (x > 0) {
        x_ = x;
        p_ = P;
        if (steady_mode && x > peak_)
            peak_ = x;
    }
    return x_;
}

std::uint64_t KccKalmanFilter::GetInitBw(std::uint32_t cwnd_segs, std::uint32_t srtt_us) const noexcept {
    if (!enabled || !active_ || x_ == 0)
        return 0;

    std::uint64_t fair = x_;
    if (steady_mode && peak_ > fair) {
        fair = peak_;
    }
    // Apply the fair-share discount, then divide out the startup pacing gain.
    std::uint64_t init_bw = fair * discount_num / discount_den;
    init_bw = (init_bw << 8) / kKfPacingInitGain;

    const std::uint64_t local_floor =
        (static_cast<std::uint64_t>(cwnd_segs) << 24) / std::max<std::uint32_t>(srtt_us, 1U);
    if (init_bw < local_floor) {
        return 0; // global estimate too conservative for this connection
    }
    return std::min<std::uint64_t>(init_bw, std::numeric_limits<std::uint32_t>::max());
}

void KccKalmanFilter::Reset() noexcept {
    x_ = 0;
    p_ = 0;
    peak_ = 0;
    active_ = false;
}

} // namespace tcpip2
