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
    : cwnd_(static_cast<std::uint32_t>(mss) * 2U),
      ssthresh_(std::numeric_limits<std::uint32_t>::max()),
      mss_(mss) {}

void AimdController::OnAck(const RateSample& rs) noexcept {
    const std::uint64_t acknowledged_payload = rs.acked_bytes;
    if (acknowledged_payload == 0) return;

    if (fast_recovery_) {
        // During fast recovery, cwnd was already inflated; do not grow
        // further on normal ACKs.  The exit happens via OnFastRecoveryExit().
        return;
    }

    if (cwnd_ < ssthresh_) {
        // Slow start: increase by min(acked, MSS) per ACK.
        const std::uint32_t increase = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(acknowledged_payload, mss_));
        cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                    ? std::numeric_limits<std::uint32_t>::max()
                    : cwnd_ + increase;
    } else {
        // Congestion avoidance: cwnd += MSS*MSS/cwnd per ACK.
        if (cwnd_ != 0) {
            const std::uint32_t increase = std::max<std::uint32_t>(
                1U, static_cast<std::uint32_t>(
                        (static_cast<std::uint64_t>(mss_) * mss_) / cwnd_));
            cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                        ? std::numeric_limits<std::uint32_t>::max()
                        : cwnd_ + increase;
        }
    }
}

void AimdController::OnLoss(const LossEvent& ev) noexcept {
    (void)ev;
    // Fast retransmit path: set ssthresh and recovery window.
    // Called by TcpSendBuffer when dup_ack_count == 3.
    // The flight size is provided via OnFastRecoveryEntry().
}

void AimdController::OnFastRecoveryEntry(std::uint32_t flight) noexcept {
    ssthresh_ = std::max<std::uint32_t>(flight / 2U,
                                         static_cast<std::uint32_t>(mss_) * 2U);
    const std::uint64_t recovery_window =
        static_cast<std::uint64_t>(ssthresh_) +
        static_cast<std::uint64_t>(mss_) * 3U;
    cwnd_ = recovery_window > std::numeric_limits<std::uint32_t>::max()
                ? std::numeric_limits<std::uint32_t>::max()
                : static_cast<std::uint32_t>(recovery_window);
    fast_recovery_ = true;
}

void AimdController::OnDupAck() noexcept {
    if (fast_recovery_) {
        // Inflate cwnd by 1 MSS per dup ACK during recovery (RFC 5681).
        const std::uint64_t inflated =
            static_cast<std::uint64_t>(cwnd_) + mss_;
        cwnd_ = inflated > std::numeric_limits<std::uint32_t>::max()
                    ? std::numeric_limits<std::uint32_t>::max()
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
    ssthresh_ = std::max<std::uint32_t>(cwnd_ / 2U,
                                        static_cast<std::uint32_t>(mss_) * 2U);
    cwnd_ = ssthresh_;
}

void AimdController::UpdateMss(std::uint16_t mss, bool pristine) noexcept {
    if (mss == 0 || mss == mss_) return;
    const std::uint16_t old_mss = mss_;
    mss_ = mss;
    if (pristine) {
        cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    } else if (mss_ < old_mss) {
        const std::uint64_t scaled =
            static_cast<std::uint64_t>(cwnd_) * mss_ / old_mss;
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
constexpr std::uint64_t kStartupGainQ8 = 738;  // 2.885 * 256 ≈ 739, round down

// DRAIN gain: 1/kStartupGain ≈ 0.347
constexpr std::uint64_t kDrainGainQ8 = 89;   // 0.347 * 256 ≈ 89

// PROBE_BW pacing gains (Q8 fixed-point):
// [1.25, 0.75, 1, 1, 1, 1, 1, 1] — the canonical BBRv1 cycle.
constexpr std::uint64_t kProbeBwGainsQ8[] = {
    320, 192, 256, 256, 256, 256, 256, 256
};

std::uint64_t SaturatingMulDiv(std::uint64_t a, std::uint64_t num,
                                std::uint64_t den) noexcept {
    if (den == 0 || a == 0 || num == 0) return 0;
    if (a > std::numeric_limits<std::uint64_t>::max() / num) {
        return std::numeric_limits<std::uint64_t>::max() / den;
    }
    return (a * num) / den;
}

} // namespace

BbrController::BbrController(std::uint16_t mss) noexcept
    : mss_(mss),
      cwnd_(static_cast<std::uint64_t>(mss) * 2U) {}

void BbrController::OnPacketSent(std::uint64_t bytes) noexcept {
    bytes_sent_ += bytes;
}

void BbrController::OnAck(const RateSample& rs) noexcept {
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
        const std::uint64_t gain =
            state_ == State::Startup ? kStartupGainQ8 :
            state_ == State::Drain   ? kDrainGainQ8 :
            state_ == State::ProbeRtt ? 256 :
            kProbeBwGainsQ8[cycle_index_];

        pacing_rate_ = SaturatingMulDiv(btlbw_, gain, 256);
    }

    const std::uint64_t bdp = Bdp();
    const std::uint64_t cwnd_gain =
        state_ == State::Startup ? kStartupGainQ8 :
        state_ == State::Drain   ? kDrainGainQ8 :
        state_ == State::ProbeRtt ? 256 :
        kProbeBwGainsQ8[cycle_index_];

    // cwnd = max(BDP * gain, 4 * MSS)
    const std::uint64_t cwnd_from_bdp =
        SaturatingMulDiv(bdp, cwnd_gain, 256);
    cwnd_ = std::max<std::uint64_t>(cwnd_from_bdp,
                                     static_cast<std::uint64_t>(mss_) * 4U);

    // DRAIN exit is checked after recomputing cwnd, since the transition
    // depends on cwnd_ <= BDP.
    if (state_ == State::Drain) {
        CheckDrainDone();
    }

    // Round accounting.  A round ends after we've sent at least a round's
    // worth of additional bytes.  In the unit-test path (no OnPacketSent)
    // bytes_sent_ equals round_start_bytes_ at round start, so the round
    // ends on the same ACK and CheckStartupDone is invoked per-ACK.
    if (round_started_ &&
        bytes_sent_ - round_start_bytes_ >= round_start_bytes_) {
        round_started_ = false;
        if (state_ == State::Startup) {
            CheckStartupDone();
        }
    }

    (void)rs.app_limited;  // app-limited packets don't update BtlBw
}

void BbrController::UpdateBtlBw(const RateSample& rs) noexcept {
    if (rs.delivery_rate_bytes_per_sec == 0) return;
    if (rs.app_limited) return;  // Don't update BtlBw on app-limited samples

    if (rs.delivery_rate_bytes_per_sec > btlbw_) {
        btlbw_ = rs.delivery_rate_bytes_per_sec;
    }

    // Track the maximum bandwidth sample seen during the current round.
    if (rs.delivery_rate_bytes_per_sec > startup_round_max_bw_) {
        startup_round_max_bw_ = rs.delivery_rate_bytes_per_sec;
    }
}

void BbrController::UpdateRTprop(const RateSample& rs) noexcept {
    if (rs.rtt_ms == 0) return;
    if (rtprop_ == 0 || rs.rtt_ms < rtprop_) {
        rtprop_ = rs.rtt_ms;
        rtprop_stamp_ms_ = rs.now_ms;
    }
}

void BbrController::CheckStartupDone() noexcept {
    // Exit STARTUP after 3 rounds where the per-round max bandwidth does not
    // grow by more than 25% over the previous round's max bandwidth.
    const std::uint64_t current = startup_round_max_bw_;
    const std::uint64_t previous = startup_prev_round_max_bw_;

    if (previous > 0 && current > 0) {
        const std::uint64_t threshold =
            SaturatingMulDiv(previous, 5, 4);  // 1.25x
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
    return static_cast<std::uint32_t>(
        std::min<std::uint64_t>(cwnd_, std::numeric_limits<std::uint32_t>::max()));
}

std::uint32_t BbrController::PacingRate() const noexcept {
    return static_cast<std::uint32_t>(
        std::min<std::uint64_t>(pacing_rate_, std::numeric_limits<std::uint32_t>::max()));
}

std::uint64_t BbrController::Bdp() const noexcept {
    if (btlbw_ == 0 || rtprop_ == 0) return 0;
    return SaturatingMulDiv(btlbw_, rtprop_, 1000);
}

void BbrController::OnLoss(const LossEvent& /*ev*/) noexcept {
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
    cwnd_ = std::max<std::uint64_t>(cwnd_ / 2U,
                                    static_cast<std::uint64_t>(mss_) * 2U);
}

void BbrController::Reset() noexcept {
    btlbw_ = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
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
    : mss_(mss),
      round_target_bytes_(static_cast<std::uint64_t>(mss) * 2U),
      cwnd_(static_cast<std::uint32_t>(mss) * 2U),
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
    if (round_btlbw_count_ < kBtlBwWindowRounds) ++round_btlbw_count_;

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

void HybridBdpAimdController::UpdateBtlBw(const RateSample& rs) noexcept {
    if (rs.delivery_rate_bytes_per_sec == 0) return;
    if (rs.app_limited) return;  // Don't update BtlBw on app-limited samples

    // Accumulate into the current (in-progress) round's max.
    if (rs.delivery_rate_bytes_per_sec > round_btlbw_current_) {
        round_btlbw_current_ = rs.delivery_rate_bytes_per_sec;
    }
}

void HybridBdpAimdController::UpdateRTprop(const RateSample& rs) noexcept {
    if (rs.rtt_ms == 0) return;

    // Timestamped min filter: drop samples older than kRtpropWindowMs so the
    // estimate re-measures after a path change.
    const std::uint64_t now = rs.now_ms;
    const std::uint8_t pos = rtprop_pos_;
    rtprop_pos_ = (rtprop_pos_ + 1U) % kRtpropSampleCount;
    if (rtprop_count_ < kRtpropSampleCount) ++rtprop_count_;
    rtprop_samples_[pos] = RtpropSample{rs.rtt_ms, now};

    std::uint64_t min_rtt = 0;
    std::uint64_t min_time = 0;
    for (std::uint8_t i = 0; i < rtprop_count_; ++i) {
        const RtpropSample& s = rtprop_samples_[i];
        if (now - s.time_ms > kRtpropWindowMs) continue;  // expired
        if (min_rtt == 0 || s.rtt_ms < min_rtt) {
            min_rtt = s.rtt_ms;
            min_time = s.time_ms;
        }
    }
    rtprop_ = min_rtt;
    rtprop_stamp_ms_ = min_time;
}

std::uint64_t HybridBdpAimdController::Bdp() const noexcept {
    if (btlbw_ == 0 || rtprop_ == 0) return 0;
    // BDP = btlbw (bytes/sec) * rtprop (ms) / 1000
    if (btlbw_ > std::numeric_limits<std::uint64_t>::max() / rtprop_) {
        return std::numeric_limits<std::uint64_t>::max() / 1000;
    }
    return (btlbw_ * rtprop_) / 1000;
}

void HybridBdpAimdController::RecomputeCwnd() noexcept {
    // cwnd = max(BDP, 4*MSS) in normal operation.
    const std::uint64_t bdp = Bdp();
    const std::uint64_t floor =
        static_cast<std::uint64_t>(mss_) * 4U;
    const std::uint64_t target = std::max(bdp, floor);
    cwnd_ = target > std::numeric_limits<std::uint32_t>::max()
                ? std::numeric_limits<std::uint32_t>::max()
                : static_cast<std::uint32_t>(target);
}

void HybridBdpAimdController::OnAck(const RateSample& rs) noexcept {
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
            const std::uint32_t increase = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(rs.acked_bytes, mss_));
            cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                        ? std::numeric_limits<std::uint32_t>::max()
                        : cwnd_ + increase;
        }
    } else {
        // BDP is known: cwnd = max(BDP, 4*MSS).
        RecomputeCwnd();
    }
}

void HybridBdpAimdController::OnLoss(const LossEvent& /*ev*/) noexcept {
    // Fast retransmit path: set ssthresh and recovery window.
    // Called by TcpSendBuffer when dup_ack_count == 3.
    // The flight size is provided via OnFastRecoveryEntry().
}

void HybridBdpAimdController::OnFastRecoveryEntry(std::uint32_t flight) noexcept {
    ssthresh_ = std::max<std::uint32_t>(flight / 2U,
                                         static_cast<std::uint32_t>(mss_) * 2U);
    const std::uint64_t recovery_window =
        static_cast<std::uint64_t>(ssthresh_) +
        static_cast<std::uint64_t>(mss_) * 3U;
    cwnd_ = recovery_window > std::numeric_limits<std::uint32_t>::max()
                ? std::numeric_limits<std::uint32_t>::max()
                : static_cast<std::uint32_t>(recovery_window);
    fast_recovery_ = true;
}

void HybridBdpAimdController::OnDupAck() noexcept {
    if (fast_recovery_) {
        // Inflate cwnd by 1 MSS per dup ACK during recovery (RFC 5681).
        const std::uint64_t inflated =
            static_cast<std::uint64_t>(cwnd_) + mss_;
        cwnd_ = inflated > std::numeric_limits<std::uint32_t>::max()
                    ? std::numeric_limits<std::uint32_t>::max()
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
    for (auto& v : round_btlbw_window_) v = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
    rtprop_pos_ = 0;
    rtprop_count_ = 0;
    for (auto& s : rtprop_samples_) s = RtpropSample{};
    delivered_ = 0;
    round_start_delivered_ = 0;
    round_target_bytes_ = static_cast<std::uint64_t>(mss_) * 2U;
    round_started_ = false;
}

void HybridBdpAimdController::OnEcnCe() noexcept {
    // RFC 3168 §6.1.2: reduce cwnd/ssthresh as for a packet loss (RFC 5681).
    ssthresh_ = std::max<std::uint32_t>(cwnd_ / 2U,
                                        static_cast<std::uint32_t>(mss_) * 2U);
    cwnd_ = ssthresh_;
}

std::uint32_t HybridBdpAimdController::CongestionWindow() const noexcept {
    return cwnd_;
}

std::uint32_t HybridBdpAimdController::PacingRate() const noexcept {
    return static_cast<std::uint32_t>(
        std::min<std::uint64_t>(pacing_rate_, std::numeric_limits<std::uint32_t>::max()));
}

void HybridBdpAimdController::UpdateMss(std::uint16_t mss, bool pristine) noexcept {
    if (mss == 0 || mss == mss_) return;
    const std::uint16_t old_mss = mss_;
    mss_ = mss;
    if (pristine) {
        cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    } else if (mss_ < old_mss) {
        const std::uint64_t scaled =
            static_cast<std::uint64_t>(cwnd_) * mss_ / old_mss;
        cwnd_ = std::max<std::uint32_t>(mss_, static_cast<std::uint32_t>(scaled));
    }
    round_target_bytes_ = cwnd_;
}

void HybridBdpAimdController::Reset() noexcept {
    btlbw_ = 0;
    round_btlbw_current_ = 0;
    round_btlbw_pos_ = 0;
    round_btlbw_count_ = 0;
    for (auto& v : round_btlbw_window_) v = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
    rtprop_pos_ = 0;
    rtprop_count_ = 0;
    for (auto& s : rtprop_samples_) s = RtpropSample{};
    cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    ssthresh_ = std::numeric_limits<std::uint32_t>::max();
    fast_recovery_ = false;
    pacing_rate_ = 0;
    delivered_ = 0;
    round_start_delivered_ = 0;
    round_target_bytes_ = static_cast<std::uint64_t>(mss_) * 2U;
    round_started_ = false;
}

} // namespace tcpip2
