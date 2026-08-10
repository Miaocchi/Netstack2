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
        delivered_at_round_start_ = 0;  // will be compared against delivered
    }

    // Update bandwidth and RTT estimates.
    UpdateBtlBw(rs);
    UpdateRTprop(rs);

    // State machine transitions.
    switch (state_) {
        case State::Startup:
            CheckStartupDone();
            break;
        case State::Drain:
            CheckDrainDone();
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

    // Round accounting.
    if (round_started_ && bytes_sent_ >= round_start_bytes_) {
        round_started_ = false;
    }

    (void)rs.app_limited;  // app-limited packets don't update BtlBw
}

void BbrController::UpdateBtlBw(const RateSample& rs) noexcept {
    if (rs.delivery_rate_bytes_per_sec == 0) return;
    if (rs.app_limited) return;  // Don't update BtlBw on app-limited samples

    if (rs.delivery_rate_bytes_per_sec > btlbw_) {
        btlbw_ = rs.delivery_rate_bytes_per_sec;
        startup_rounds_no_growth_ = 0;
    } else {
        // Track max within a round for STARTUP exit detection.
        if (rs.delivery_rate_bytes_per_sec > startup_max_bw_) {
            startup_max_bw_ = rs.delivery_rate_bytes_per_sec;
        }
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
    // Exit STARTUP after 3 rounds where BtlBw doesn't grow by >25%.
    // Simplified: count rounds where the latest sample doesn't exceed
    // the startup max by a significant margin.
    if (btlbw_ > 0 && startup_max_bw_ > 0) {
        const std::uint64_t threshold =
            SaturatingMulDiv(startup_max_bw_, 5, 4);  // 1.25x
        if (btlbw_ < threshold) {
            ++startup_rounds_no_growth_;
        } else {
            startup_rounds_no_growth_ = 0;
        }
    }
    startup_max_bw_ = btlbw_;

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

void BbrController::Reset() noexcept {
    btlbw_ = 0;
    rtprop_ = 0;
    rtprop_stamp_ms_ = 0;
    state_ = State::Startup;
    startup_rounds_no_growth_ = 0;
    startup_max_bw_ = 0;
    cycle_index_ = 0;
    cycle_start_ms_ = 0;
    probe_rtt_enter_ms_ = 0;
    pacing_rate_ = 0;
    cwnd_ = static_cast<std::uint64_t>(mss_) * 2U;
    bytes_sent_ = 0;
    round_start_bytes_ = 0;
    round_started_ = false;
}

} // namespace tcpip2
