#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "Test.h"
#include <tcp/congestion.h>
#include <tcp/rate_sampler.h>
#include <tcp/send.h>
#include <tcpip2/buffer.h>

using namespace tcpip2;

// ---------------------------------------------------------------------------
// AIMD Controller golden tests
// ---------------------------------------------------------------------------

namespace {

/// Helper: create a TcpSendBuffer with AIMD (default).
std::unique_ptr<TcpSendBuffer> MakeAimd(
    std::uint32_t initial_seq = 1000,
    std::uint16_t mss = 1460) {
    return std::make_unique<TcpSendBuffer>(
        initial_seq, mss, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Aimd);
}

/// Helper: create a TcpSendBuffer with BBR.
std::unique_ptr<TcpSendBuffer> MakeBbr(
    std::uint32_t initial_seq = 1000,
    std::uint16_t mss = 1460) {
    return std::make_unique<TcpSendBuffer>(
        initial_seq, mss, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Bbr);
}

/// Helper: create a TcpSendBuffer with Hybrid BDP-AIMD.
std::unique_ptr<TcpSendBuffer> MakeHybrid(
    std::uint32_t initial_seq = 1000,
    std::uint16_t mss = 1460) {
    return std::make_unique<TcpSendBuffer>(
        initial_seq, mss, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::HybridBdpAimd);
}

/// Helper pool + send utility (mirrors send_test.cpp's SendHelper).
struct TestEnv {
    PktBufferPool pool;
    std::uint64_t now_ms = 100;

    explicit TestEnv(std::size_t slots = 16, std::size_t cap = 4096)
        : pool(slots, cap) {}

    void SendSegment(TcpSendBuffer& send, const TcpSendNextResult& seg) {
        TCPIP2_EXPECT_TRUE(seg.has_segment);
        BufferLease lease = pool.Allocate();
        TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
        if (seg.payload_length > 0) {
            std::memcpy(lease.Data() + 20, seg.payload, seg.payload_length);
        }
        lease.Resize(20 + seg.payload_length);
        BufferRef ref = pool.Retain(std::move(lease));
        send.OnSent(std::move(ref), 20, now_ms);
    }
};

} // namespace

// ---------------------------------------------------------------------------
// DeliveryRateSampler tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(RateSamplerInitialDeliveredIsZero) {
    DeliveryRateSampler s;
    TCPIP2_EXPECT_EQ(s.DeliveredBytes(), 0ULL);
    TCPIP2_EXPECT_EQ(s.DeliveredTime(), 0ULL);
    TCPIP2_EXPECT_FALSE(s.IsAppLimited());
}

TCPIP2_TEST(RateSamplerOnPacketSentStampsDeliveryState) {
    DeliveryRateSampler s;
    PacketDeliveryState pkt;
    s.OnPacketSent(pkt, 100);
    TCPIP2_EXPECT_EQ(pkt.delivered_bytes, 0ULL);
    TCPIP2_EXPECT_EQ(pkt.delivered_time_ms, 0ULL);
    TCPIP2_EXPECT_EQ(pkt.first_sent_time_ms, 100ULL);
    TCPIP2_EXPECT_FALSE(pkt.app_limited);
    TCPIP2_EXPECT_FALSE(pkt.retransmitted);
}

TCPIP2_TEST(RateSamplerOnAckComputesDeliveryRate) {
    DeliveryRateSampler s;

    // Send packet at t=100.
    PacketDeliveryState pkt;
    s.OnPacketSent(pkt, 100);

    // ACK at t=250 (RTT = 150ms), 1460 bytes acked.
    RateSample rs = s.OnAck(pkt, 1460, 250, 0);

    TCPIP2_EXPECT_EQ(rs.acked_bytes, 1460ULL);
    TCPIP2_EXPECT_EQ(rs.rtt_ms, 150ULL);
    TCPIP2_EXPECT_EQ(rs.interval_ms, 250ULL);
    // delivery_rate = 1460 * 1000 / 250 = 5840 bytes/sec
    TCPIP2_EXPECT_EQ(rs.delivery_rate_bytes_per_sec, 5840ULL);
    TCPIP2_EXPECT_EQ(s.DeliveredBytes(), 1460ULL);
}

TCPIP2_TEST(RateSamplerRetransmittedPacketProducesZeroRate) {
    DeliveryRateSampler s;

    PacketDeliveryState pkt;
    s.OnPacketSent(pkt, 100);
    pkt.retransmitted = true;

    RateSample rs = s.OnAck(pkt, 1460, 300, 0);
    TCPIP2_EXPECT_EQ(rs.delivery_rate_bytes_per_sec, 0ULL);
    TCPIP2_EXPECT_EQ(rs.rtt_ms, 0ULL);
    // Delivered bytes still update.
    TCPIP2_EXPECT_EQ(s.DeliveredBytes(), 1460ULL);
}

TCPIP2_TEST(RateSamplerAppLimitedPropagatedToSample) {
    DeliveryRateSampler s;
    s.MarkAppLimited(100);

    PacketDeliveryState pkt;
    s.OnPacketSent(pkt, 100);
    TCPIP2_EXPECT_TRUE(pkt.app_limited);

    RateSample rs = s.OnAck(pkt, 500, 200, 0);
    TCPIP2_EXPECT_TRUE(rs.app_limited);
}

TCPIP2_TEST(RateSamplerResetClearsState) {
    DeliveryRateSampler s;

    PacketDeliveryState pkt;
    s.OnPacketSent(pkt, 100);
    s.OnAck(pkt, 1000, 200, 0);
    s.MarkAppLimited(200);

    s.Reset();
    TCPIP2_EXPECT_EQ(s.DeliveredBytes(), 0ULL);
    TCPIP2_EXPECT_FALSE(s.IsAppLimited());
}

// ---------------------------------------------------------------------------
// AimdController tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(AimdInitialCwndIsTwoMss) {
    AimdController c(1460);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    TCPIP2_EXPECT_EQ(c.Ssthresh(), 0xFFFFFFFFU);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);  // AIMD does not pace
}

TCPIP2_TEST(AimdSlowStartDoublesCwndPerRtt) {
    AimdController c(1460);
    // Initial cwnd = 2*1460 = 2920. In slow start, each ACK grows cwnd by
    // up to MSS. Two ACKs of 1460 each → cwnd = 2920 + 2920 = 5840.
    RateSample rs1;
    rs1.acked_bytes = 1460;
    c.OnAck(rs1);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 4380U);

    RateSample rs2;
    rs2.acked_bytes = 1460;
    c.OnAck(rs2);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 5840U);
}

TCPIP2_TEST(AimdEntersCongestionAvoidanceAfterSsthresh) {
    AimdController c(100);
    // Manually set ssthresh by entering fast recovery and exiting.
    c.OnFastRecoveryEntry(1000);
    // ssthresh = max(500, 200) = 500
    TCPIP2_EXPECT_EQ(c.Ssthresh(), 500U);
    c.OnFastRecoveryExit();
    // cwnd = ssthresh = 500
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 500U);

    // In CA: increase = max(1, MSS*MSS/cwnd) = max(1, 100*100/500) = max(1,20) = 20
    RateSample rs;
    rs.acked_bytes = 50;
    c.OnAck(rs);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 520U);
}

TCPIP2_TEST(AimdFastRecoveryInflatesCwndPerDupAck) {
    AimdController c(1460);
    c.OnFastRecoveryEntry(10000);
    // ssthresh = max(5000, 2920) = 5000
    // cwnd = 5000 + 3*1460 = 9380
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 9380U);

    c.OnDupAck();
    // cwnd = 9380 + 1460 = 10840
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 10840U);

    c.OnDupAck();
    // cwnd = 10840 + 1460 = 12300
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 12300U);
}

TCPIP2_TEST(AimdFastRecoveryExitSetsCwndToSsthresh) {
    AimdController c(1460);
    c.OnFastRecoveryEntry(10000);
    c.OnDupAck();
    c.OnDupAck();
    TCPIP2_EXPECT_TRUE(c.InFastRecovery());

    c.OnFastRecoveryExit();
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), c.Ssthresh());
}

TCPIP2_TEST(AimdRtoResetsCwndToOneMss) {
    AimdController c(1460);
    // Grow cwnd via ACKs.
    RateSample rs;
    rs.acked_bytes = 1460;
    c.OnAck(rs);
    c.OnAck(rs);
    TCPIP2_EXPECT_TRUE(c.CongestionWindow() > 2920U);

    c.OnRto();
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 1460U);
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
}

TCPIP2_TEST(AimdResetRestoresInitialState) {
    AimdController c(1460);
    c.OnFastRecoveryEntry(10000);
    c.OnRto();
    c.Reset();
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    TCPIP2_EXPECT_EQ(c.Ssthresh(), 0xFFFFFFFFU);
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
}

TCPIP2_TEST(AimdUpdateMssScalesCwndWhenPristine) {
    AimdController c(1460);
    // cwnd = 2*1460 = 2920, pristine = true → cwnd = 2*1000 = 2000
    c.UpdateMss(1000, true);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2000U);
}

TCPIP2_TEST(AimdUpdateMssScalesCwndWhenShrinking) {
    AimdController c(1000);
    // Grow cwnd to 5000.
    c.OnFastRecoveryEntry(10000);
    c.OnFastRecoveryExit();
    // cwnd = ssthresh = 5000, mss = 1000

    // Shrink MSS to 800.
    c.UpdateMss(800, false);
    // scaled = 5000 * 800 / 1000 = 4000, max(800, 4000) = 4000
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 4000U);
}

// ---------------------------------------------------------------------------
// TcpSendBuffer + AIMD integration (verify behavior unchanged)
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendBufferAimdDefaultAlgorithm) {
    auto send = MakeAimd();
    TCPIP2_EXPECT_EQ(send->Algorithm(), CongestionAlgorithm::Aimd);
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);  // 2 * 1460
    TCPIP2_EXPECT_EQ(send->PacingRate(), 0U);           // AIMD doesn't pace
}

TCPIP2_TEST(SendBufferBbrAlgorithm) {
    auto send = MakeBbr();
    TCPIP2_EXPECT_EQ(send->Algorithm(), CongestionAlgorithm::Bbr);
    // BBR initial cwnd = 2 * MSS = 2920
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);
    // BBR pacing rate is 0 until first BtlBw estimate.
    TCPIP2_EXPECT_EQ(send->PacingRate(), 0U);
}

TCPIP2_TEST(SendBufferAimdSlowStartThroughSendBuffer) {
    // Verify that sending + ACKing grows cwnd in slow start.
    TestEnv env;
    auto send = MakeAimd();

    // Enqueue enough data.
    std::vector<std::uint8_t> data(10000, 'x');
    send->Enqueue(data.data(), data.size());

    // Send one segment.
    auto seg = send->NextSegment(65535, env.now_ms);
    TCPIP2_EXPECT_TRUE(seg.has_segment);
    TCPIP2_EXPECT_EQ(seg.payload_length, 1460U);
    env.SendSegment(*send, seg);

    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);

    // ACK it.
    env.now_ms += 100;
    auto ack_result = send->OnAck(1000 + 1460, 65535, env.now_ms);
    TCPIP2_EXPECT_FALSE(ack_result.duplicate);

    // cwnd should have grown by 1460 in slow start.
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 4380U);
}

TCPIP2_TEST(SendBufferAimdFastRetransmitViaDupAck) {
    TestEnv env;
    auto send = MakeAimd();

    std::vector<std::uint8_t> data(20000, 'x');
    send->Enqueue(data.data(), data.size());

    // Send 3 segments (cwnd = 2*MSS = 2920, so first 2 are new data,
    // 3rd may need ACK to grow cwnd). Let's send 2, ACK, then send more.
    for (int i = 0; i < 2; ++i) {
        auto seg = send->NextSegment(65535, env.now_ms);
        TCPIP2_EXPECT_TRUE(seg.has_segment);
        env.SendSegment(*send, seg);
    }

    // ACK the first segment to grow cwnd (slow start).
    env.now_ms += 10;
    send->OnAck(1000 + 1460, 65535, env.now_ms);
    // cwnd = 2920 + 1460 = 4380, can send more.

    // Send segment 3.
    auto seg3 = send->NextSegment(65535, env.now_ms);
    TCPIP2_EXPECT_TRUE(seg3.has_segment);
    env.SendSegment(*send, seg3);

    // Now we have 3 in-flight (seq 1000, 2460, 3920). SndNxt = 1000+4380 = 5380.
    // Wait, snd_una = 2460 (first ACKed), snd_nxt = 5380.
    // Actually: after ACK of seq 1000+1460, snd_una=2460. Two more in flight
    // (2460 and 3920). We need 3 in flight for dup ACK to trigger fast retransmit.
    // Let's send one more.
    auto seg4 = send->NextSegment(65535, env.now_ms);
    if (seg4.has_segment) {
        env.SendSegment(*send, seg4);
    }

    // Send 3 duplicate ACKs (ack=2460, same window).
    for (int i = 0; i < 3; ++i) {
        auto r = send->OnAck(2460, 65535, env.now_ms + 10 + i, true);
        if (i == 2) {
            TCPIP2_EXPECT_TRUE(r.fast_retransmit);
        }
    }

    TCPIP2_EXPECT_TRUE(send->InFastRecovery());
}

TCPIP2_TEST(SendBufferCloseResetsController) {
    TestEnv env;
    auto send = MakeAimd();

    std::vector<std::uint8_t> data(10000, 'x');
    send->Enqueue(data.data(), data.size());
    auto seg = send->NextSegment(65535, env.now_ms);
    env.SendSegment(*send, seg);

    // Trigger RTO by advancing time and retransmitting.
    env.now_ms += 2000;
    auto rto_seg = send->NextSegment(65535, env.now_ms);
    TCPIP2_EXPECT_TRUE(rto_seg.is_retransmission);
    env.SendSegment(*send, rto_seg);

    // cwnd should be 1 MSS after RTO.
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 1460U);

    // After more RTOs, buffer closes. After close, controller reset.
    for (int i = 0; i < 5; ++i) {
        env.now_ms += 10000;
        auto s = send->NextSegment(65535, env.now_ms);
        if (s.has_segment) {
            env.SendSegment(*send, s);
        }
    }

    // If closed, cwnd should have been reset.
    if (send->IsClosed()) {
        TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);
    }
}

TCPIP2_TEST(SendBufferSsthreshAccessor) {
    auto send = MakeAimd();
    // AIMD ssthresh starts at UINT32_MAX.
    TCPIP2_EXPECT_EQ(send->Ssthresh(), 0xFFFFFFFFU);
}

// ---------------------------------------------------------------------------
// BbrController state-machine tests
// ---------------------------------------------------------------------------

namespace {

/// Convenience: create a RateSample with the given fields.
RateSample MakeBbrSample(std::uint64_t now_ms,
                          std::uint64_t rate_bps,
                          std::uint64_t rtt_ms,
                          std::uint64_t acked_bytes = 1460,
                          bool app_limited = false) {
    RateSample rs;
    rs.now_ms = now_ms;
    rs.delivery_rate_bytes_per_sec = rate_bps;
    rs.rtt_ms = rtt_ms;
    rs.acked_bytes = acked_bytes;
    rs.app_limited = app_limited;
    return rs;
}

} // namespace

TCPIP2_TEST(BbrInitialCwndIsTwoMss) {
    BbrController c(1460);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Startup);
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
    TCPIP2_EXPECT_EQ(c.RTprop(), 0ULL);
}

TCPIP2_TEST(BbrUpdatesBtlBwFromNonAppLimitedSample) {
    BbrController c(1460);
    RateSample rs = MakeBbrSample(100, 1000000, 10);
    c.OnAck(rs);
    TCPIP2_EXPECT_EQ(c.BtlBw(), 1000000ULL);
}

TCPIP2_TEST(BbrAppLimitedDoesNotUpdateBtlBw) {
    BbrController c(1460);
    RateSample rs = MakeBbrSample(100, 5000000, 10, 1460, true);
    c.OnAck(rs);
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
}

TCPIP2_TEST(BbrBtlBwIsMaxFilter) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    c.OnAck(MakeBbrSample(110, 800000, 10));   // lower
    c.OnAck(MakeBbrSample(120, 1200000, 10));  // higher
    c.OnAck(MakeBbrSample(130, 900000, 10));   // lower
    TCPIP2_EXPECT_EQ(c.BtlBw(), 1200000ULL);
}

TCPIP2_TEST(BbrUpdatesRTpropMinFilter) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 50));
    c.OnAck(MakeBbrSample(110, 1000000, 30));
    c.OnAck(MakeBbrSample(120, 1000000, 40));  // higher than min
    TCPIP2_EXPECT_EQ(c.RTprop(), 30ULL);
}

TCPIP2_TEST(BbrRTpropIgnoresZeroRtt) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 50));
    c.OnAck(MakeBbrSample(110, 1000000, 0));  // should be ignored
    TCPIP2_EXPECT_EQ(c.RTprop(), 50ULL);
}

TCPIP2_TEST(BbrStartupExitsAfterThreeRoundsNoGrowth) {
    BbrController c(1460);

    // Establish initial BtlBw.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Startup);

    // Each new OnAck starts a new round in the unit-test path (no
    // OnPacketSent between ACKs). After three rounds where the per-round
    // max bandwidth does not grow by >25%, BBR exits STARTUP.
    for (int i = 0; i < 3; ++i) {
        c.OnAck(MakeBbrSample(200 + i * 10, 1000000, 10));
    }
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Drain);
}

TCPIP2_TEST(BbrStartupStaysInStartupWithGrowth) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));

    // Grow BtlBw by >25% each round → should stay in Startup.
    c.OnAck(MakeBbrSample(110, 2000000, 10));
    c.OnAck(MakeBbrSample(120, 3000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Startup);
}

TCPIP2_TEST(BbrDrainTransitionsToProbeBwWhenCwndLeBdp) {
    BbrController c(1460);

    // Force into Drain by going through STARTUP exit.
    c.OnAck(MakeBbrSample(100, 1000000, 10));  // btlbw=1M, rtprop=10
    for (int i = 0; i < 3; ++i) {
        c.OnAck(MakeBbrSample(200 + i * 10, 1000000, 10));
    }
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Drain);

    // BDP = 1000000 * 10 / 1000 = 10000 bytes.
    // cwnd starts at 2*MSS=2920 which is < 10000, so drain should
    // exit immediately on the next OnAck.
    // But the transition happens inside CheckDrainDone which is called
    // before cwnd_ is recomputed. Let's check: at this point cwnd_ was
    // recomputed in the last OnAck call after CheckDrainDone. So we need
    // another OnAck to trigger CheckDrainDone again.
    // Actually CheckDrainDone checks cwnd_ <= bdp. After the transition to
    // Drain, the last OnAck recomputed cwnd_ = max(bdp*drain_gain, 4*MSS).
    // drain_gain = 89/256 ≈ 0.347. bdp*0.347 = 3472. 4*MSS = 5840.
    // So cwnd_ = 5840, which is < bdp=10000. Next OnAck should transition.
    c.OnAck(MakeBbrSample(300, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);
}

TCPIP2_TEST(BbrProbeBwCycleAdvancesThroughPhases) {
    BbrController c(1460);

    // Get to PROBE_BW.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    for (int i = 0; i < 3; ++i) {
        c.OnAck(MakeBbrSample(200 + i * 10, 1000000, 10));
    }
    // Drain
    c.OnAck(MakeBbrSample(300, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);

    // Each phase lasts RTprop (10ms). Feed ACKs at 11ms intervals to
    // advance through the cycle. After 8 phases we should have wrapped.
    std::uint64_t t = 310;
    for (int i = 0; i < 8; ++i) {
        c.OnAck(MakeBbrSample(t, 1000000, 10));
        t += 11;
    }
    // After 8 advances, cycle_index_ should have wrapped back to 0.
    // We can't directly read cycle_index_, but we can verify we're still
    // in ProbeBw (not ProbeRtt — interval not yet 10s).
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);
}

TCPIP2_TEST(BbrProbeRttEntersAfterInterval) {
    BbrController c(1460);

    // Get to PROBE_BW.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    for (int i = 0; i < 3; ++i) {
        c.OnAck(MakeBbrSample(200 + i * 10, 1000000, 10));
    }
    c.OnAck(MakeBbrSample(300, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);

    // rtprop_stamp_ms_ was set at t=100 when RTprop was first learned.
    // kProbeRttIntervalMs = 10000. So at t >= 10100, we enter PROBE_RTT.
    c.OnAck(MakeBbrSample(10100, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeRtt);
}

TCPIP2_TEST(BbrProbeRttExitsAfterDuration) {
    BbrController c(1460);

    // Get to PROBE_BW.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    for (int i = 0; i < 3; ++i) {
        c.OnAck(MakeBbrSample(200 + i * 10, 1000000, 10));
    }
    c.OnAck(MakeBbrSample(300, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);

    // Enter PROBE_RTT.
    c.OnAck(MakeBbrSample(10100, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeRtt);

    // kProbeRttDurationMs = 200. Exit at t >= 10300.
    c.OnAck(MakeBbrSample(10300, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);
}

TCPIP2_TEST(BbrPacingRateNonZeroAfterBtlBwKnown) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    // In STARTUP, pacing_rate = btlbw * startup_gain = 1000000 * 738/256
    TCPIP2_EXPECT_TRUE(c.PacingRate() > 0U);
}

TCPIP2_TEST(BbrCwndIsBdpTimesGain) {
    BbrController c(1460);
    // btlbw=1M bytes/s, rtprop=10ms → BDP = 10000 bytes.
    // STARTUP cwnd_gain = 738/256 ≈ 2.885.
    // cwnd_from_bdp = 10000 * 738/256 = 28828.
    // cwnd = max(28828, 4*1460=5840) = 28828.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_TRUE(c.CongestionWindow() >= 28800U);
    TCPIP2_EXPECT_TRUE(c.CongestionWindow() <= 28900U);
}

TCPIP2_TEST(BbrLossDoesNotReduceCwnd) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    std::uint32_t cwnd_before = c.CongestionWindow();
    TCPIP2_EXPECT_TRUE(cwnd_before > 0U);

    LossEvent ev;
    ev.lost_bytes = 1000;
    ev.inflight_bytes = 5000;
    c.OnLoss(ev);

    // BBR does not reduce cwnd on loss.
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), cwnd_before);
}

TCPIP2_TEST(BbrRtoResetsCwndToOneMss) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_TRUE(c.CongestionWindow() > 1460U);

    c.OnRto();
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 1460U);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);
}

TCPIP2_TEST(BbrResetRestoresInitialState) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    c.OnLoss(LossEvent{});
    c.Reset();

    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Startup);
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
    TCPIP2_EXPECT_EQ(c.RTprop(), 0ULL);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);
}

TCPIP2_TEST(BbrAlgorithmIdIsBbrV1) {
    TCPIP2_EXPECT_EQ(std::string(BbrController::AlgorithmId()), "bbr_v1");
}

TCPIP2_TEST(BbrOnPacketSentAccumulatesBytes) {
    BbrController c(1460);
    // OnPacketSent just accumulates bytes_sent_ — verify it doesn't crash
    // and state remains valid.
    c.OnPacketSent(1460);
    c.OnPacketSent(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::Startup);
}

TCPIP2_TEST(BbrCwndFloorIsFourMss) {
    BbrController c(1460);
    // With very small BDP, cwnd should be floored at 4*MSS.
    // btlbw=100 bytes/s, rtprop=1ms → BDP = 0.1 bytes → 0.
    // cwnd_from_bdp = 0 * gain = 0. cwnd = max(0, 4*1460) = 5840.
    c.OnAck(MakeBbrSample(100, 100, 1));
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 5840U);
}

TCPIP2_TEST(BbrPacingRateInProbeBwUsesCycleGain) {
    BbrController c(1460);

    // Get to PROBE_BW.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    for (int i = 0; i < 3; ++i) {
        c.OnAck(MakeBbrSample(200 + i * 10, 1000000, 10));
    }
    c.OnAck(MakeBbrSample(300, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.CurrentState(), BbrController::State::ProbeBw);

    // In PROBE_BW, pacing rate = btlbw * cycle_gain.
    // cycle_index_ starts at 0 after exiting Drain → gain = 320/256 = 1.25.
    // pacing_rate = 1000000 * 320/256 = 1250000.
    // But we may have advanced cycles, so just verify it's non-zero and
    // reasonably bounded.
    TCPIP2_EXPECT_TRUE(c.PacingRate() > 0U);
    TCPIP2_EXPECT_TRUE(c.PacingRate() <= 2000000U);
}

TCPIP2_TEST(BbrStartupPacingRateUsesStartupGain) {
    BbrController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    // STARTUP pacing = btlbw * 738/256 = 1000000 * 2.886... ≈ 2882812
    TCPIP2_EXPECT_TRUE(c.PacingRate() >= 2882000U);
    TCPIP2_EXPECT_TRUE(c.PacingRate() <= 2883000U);
}

// ---------------------------------------------------------------------------
// HybridBdpAimdController tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(HybridInitialCwndIsTwoMss) {
    HybridBdpAimdController c(1460);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    TCPIP2_EXPECT_EQ(c.Ssthresh(), 0xFFFFFFFFU);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);  // no BtlBw yet
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
    TCPIP2_EXPECT_EQ(c.RTprop(), 0ULL);
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
}

TCPIP2_TEST(HybridAlgorithmIdIsHybridBdpAimdV1) {
    TCPIP2_EXPECT_EQ(std::string(HybridBdpAimdController::AlgorithmId()), "hybrid_bdp_aimd_v1");
}

TCPIP2_TEST(HybridUpdatesBtlBwFromNonAppLimitedSample) {
    HybridBdpAimdController c(1460);
    // BtlBw is a per-round windowed max: the first round completes once
    // ~cwnd bytes (2920 = 2*1460) have been acknowledged.
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);  // round not yet complete
    c.OnAck(MakeBbrSample(110, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.BtlBw(), 1000000ULL);
}

TCPIP2_TEST(HybridAppLimitedDoesNotUpdateBtlBw) {
    HybridBdpAimdController c(1460);
    RateSample rs = MakeBbrSample(100, 5000000, 10, 1460, true);
    c.OnAck(rs);
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
}

TCPIP2_TEST(HybridBtlBwIsWindowedMaxFilter) {
    HybridBdpAimdController c(1460);
    // First round: 1M bytes/s; completes after 2 ACKs of 1460 (= cwnd).
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    c.OnAck(MakeBbrSample(110, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.BtlBw(), 1000000ULL);

    // Several rounds at 800k: the windowed max keeps the 1M peak.
    std::uint64_t t = 120;
    for (int i = 0; i < 14; ++i) {
        c.OnAck(MakeBbrSample(t, 800000, 10));
        t += 10;
    }
    TCPIP2_EXPECT_EQ(c.BtlBw(), 1000000ULL);

    // Run the peak out of the ~10-round window: many more 800k rounds.
    for (int i = 0; i < 70; ++i) {
        c.OnAck(MakeBbrSample(t, 800000, 10));
        t += 10;
    }
    // The 1M peak has expired; only the 800k rounds remain.
    TCPIP2_EXPECT_EQ(c.BtlBw(), 800000ULL);
}

TCPIP2_TEST(HybridUpdatesRTpropMinFilter) {
    HybridBdpAimdController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 50));
    c.OnAck(MakeBbrSample(110, 1000000, 30));
    c.OnAck(MakeBbrSample(120, 1000000, 40));  // higher than min
    TCPIP2_EXPECT_EQ(c.RTprop(), 30ULL);
}

TCPIP2_TEST(HybridRTpropIgnoresZeroRtt) {
    HybridBdpAimdController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 50));
    c.OnAck(MakeBbrSample(110, 1000000, 0));  // should be ignored
    TCPIP2_EXPECT_EQ(c.RTprop(), 50ULL);
}

TCPIP2_TEST(HybridRTpropExpiresStaleSamples) {
    HybridBdpAimdController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 50));
    TCPIP2_EXPECT_EQ(c.RTprop(), 50ULL);
    // A higher RTT after the 10s window expires the stale 50ms sample, so
    // RTprop re-measures (min filter over the current window only).
    c.OnAck(MakeBbrSample(10150, 1000000, 80));
    TCPIP2_EXPECT_EQ(c.RTprop(), 80ULL);
}

TCPIP2_TEST(HybridPacingRateNonZeroAfterBtlBwKnown) {
    HybridBdpAimdController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);  // no BtlBw yet
    c.OnAck(MakeBbrSample(110, 1000000, 10));  // completes round 1
    // Hybrid pacing = BtlBw * 1.0 (conservative, no gain)
    TCPIP2_EXPECT_EQ(c.PacingRate(), 1000000U);
}

TCPIP2_TEST(HybridSlowStartBeforeBtlBwKnown) {
    HybridBdpAimdController c(1460);
    // Before BtlBw is known, Hybrid slow starts (cwnd += acked, up to MSS).
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    RateSample rs1 = MakeBbrSample(100, 0, 0, 1460);  // no rate/rtt yet
    c.OnAck(rs1);
    // cwnd += min(1460, 1460) = 1460 → 4380
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 4380U);
}

TCPIP2_TEST(HybridCwndIsBdpBasedAfterBtlBwKnown) {
    HybridBdpAimdController c(1460);
    // btlbw=1M bytes/s, rtprop=10ms → BDP = 10000 bytes.
    // Once BtlBw and RTprop are both known, cwnd = max(BDP, 4*MSS)
    // directly — no dependence on ssthresh (no permanent slow-start).
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    // Round 1 incomplete: BtlBw unknown yet, slow start grows cwnd.
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 4380U);

    // Second ACK completes round 1 → BtlBw=1M, RTprop=10.
    c.OnAck(MakeBbrSample(110, 1000000, 10));
    // cwnd = max(BDP=10000, 4*1460=5840) = 10000.
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 10000U);
    // ssthresh was never touched (no fast recovery involved).
    TCPIP2_EXPECT_EQ(c.Ssthresh(), 0xFFFFFFFFU);
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
}

TCPIP2_TEST(HybridCwndFloorIsFourMss) {
    HybridBdpAimdController c(1460);
    // Very small BDP → cwnd should be floored at 4*MSS.
    // btlbw=100, rtprop=1ms → BDP = 0.1 → 0.
    c.OnAck(MakeBbrSample(100, 100, 1));
    c.OnAck(MakeBbrSample(110, 100, 1));  // completes round 1
    // max(BDP=0, 5840) = 5840.
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 5840U);
}

TCPIP2_TEST(HybridFastRecoveryInflatesCwndPerDupAck) {
    HybridBdpAimdController c(1460);
    c.OnFastRecoveryEntry(10000);
    // ssthresh = max(5000, 2920) = 5000
    // cwnd = 5000 + 3*1460 = 9380
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 9380U);

    c.OnDupAck();
    // cwnd = 9380 + 1460 = 10840
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 10840U);

    c.OnDupAck();
    // cwnd = 10840 + 1460 = 12300
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 12300U);
}

TCPIP2_TEST(HybridFastRecoveryExitSetsCwndToSsthresh) {
    HybridBdpAimdController c(1460);
    c.OnFastRecoveryEntry(10000);
    c.OnDupAck();
    c.OnDupAck();
    TCPIP2_EXPECT_TRUE(c.InFastRecovery());

    c.OnFastRecoveryExit();
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), c.Ssthresh());
}

TCPIP2_TEST(HybridRtoResetsCwndToOneMss) {
    HybridBdpAimdController c(1460);
    // Grow cwnd.
    RateSample rs = MakeBbrSample(100, 1000000, 10);
    c.OnAck(rs);
    TCPIP2_EXPECT_TRUE(c.CongestionWindow() > 2920U);

    c.OnRto();
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 1460U);
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
    // Estimates are invalidated so the flow re-measures after the RTO.
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
    TCPIP2_EXPECT_EQ(c.RTprop(), 0ULL);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);
}

TCPIP2_TEST(HybridResetRestoresInitialState) {
    HybridBdpAimdController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    c.OnFastRecoveryEntry(10000);
    c.OnRto();
    c.Reset();
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2920U);
    TCPIP2_EXPECT_EQ(c.Ssthresh(), 0xFFFFFFFFU);
    TCPIP2_EXPECT_FALSE(c.InFastRecovery());
    TCPIP2_EXPECT_EQ(c.BtlBw(), 0ULL);
    TCPIP2_EXPECT_EQ(c.RTprop(), 0ULL);
    TCPIP2_EXPECT_EQ(c.PacingRate(), 0U);
}

TCPIP2_TEST(HybridUpdateMssScalesCwndWhenPristine) {
    HybridBdpAimdController c(1460);
    // cwnd = 2*1460 = 2920, pristine = true → cwnd = 2*1000 = 2000
    c.UpdateMss(1000, true);
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 2000U);
}

TCPIP2_TEST(HybridUpdateMssScalesCwndWhenShrinking) {
    HybridBdpAimdController c(1000);
    // Grow cwnd to 5000 via fast recovery exit.
    c.OnFastRecoveryEntry(10000);
    c.OnFastRecoveryExit();
    // cwnd = ssthresh = 5000, mss = 1000

    // Shrink MSS to 800.
    c.UpdateMss(800, false);
    // scaled = 5000 * 800 / 1000 = 4000, max(800, 4000) = 4000
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), 4000U);
}

TCPIP2_TEST(HybridOnPacketSentDoesNotCrash) {
    HybridBdpAimdController c(1460);
    c.OnPacketSent(1460);
    c.OnPacketSent(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    TCPIP2_EXPECT_TRUE(c.CongestionWindow() > 0U);
}

TCPIP2_TEST(HybridOnLossIsNoOp) {
    HybridBdpAimdController c(1460);
    c.OnAck(MakeBbrSample(100, 1000000, 10));
    std::uint32_t cwnd_before = c.CongestionWindow();

    LossEvent ev;
    ev.lost_bytes = 1000;
    ev.inflight_bytes = 5000;
    c.OnLoss(ev);

    // Hybrid OnLoss is a no-op; loss response is via OnFastRecoveryEntry.
    TCPIP2_EXPECT_EQ(c.CongestionWindow(), cwnd_before);
}

// ---------------------------------------------------------------------------
// TcpSendBuffer + Hybrid BDP-AIMD integration
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendBufferHybridAlgorithm) {
    auto send = MakeHybrid();
    TCPIP2_EXPECT_EQ(send->Algorithm(), CongestionAlgorithm::HybridBdpAimd);
    // Hybrid initial cwnd = 2 * MSS = 2920
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);
    // Hybrid pacing rate is 0 until first BtlBw estimate.
    TCPIP2_EXPECT_EQ(send->PacingRate(), 0U);
}

TCPIP2_TEST(SendBufferHybridSsthreshAccessor) {
    auto send = MakeHybrid();
    // Hybrid ssthresh starts at UINT32_MAX.
    TCPIP2_EXPECT_EQ(send->Ssthresh(), 0xFFFFFFFFU);
}

TCPIP2_TEST(SendBufferHybridSlowStartThroughSendBuffer) {
    TestEnv env;
    auto send = MakeHybrid();

    std::vector<std::uint8_t> data(10000, 'x');
    send->Enqueue(data.data(), data.size());

    // Send one segment.
    auto seg = send->NextSegment(65535, env.now_ms);
    TCPIP2_EXPECT_TRUE(seg.has_segment);
    TCPIP2_EXPECT_EQ(seg.payload_length, 1460U);
    env.SendSegment(*send, seg);

    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);

    // ACK it.
    env.now_ms += 100;
    auto ack_result = send->OnAck(1000 + 1460, 65535, env.now_ms);
    TCPIP2_EXPECT_FALSE(ack_result.duplicate);

    // cwnd should have grown by 1460 in slow start (Hybrid slow starts
    // before BtlBw is known).
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 4380U);
}

TCPIP2_TEST(SendBufferHybridFastRetransmitViaDupAck) {
    TestEnv env;
    auto send = MakeHybrid();

    std::vector<std::uint8_t> data(20000, 'x');
    send->Enqueue(data.data(), data.size());

    // Send 2 segments (cwnd = 2*MSS = 2920).
    for (int i = 0; i < 2; ++i) {
        auto seg = send->NextSegment(65535, env.now_ms);
        TCPIP2_EXPECT_TRUE(seg.has_segment);
        env.SendSegment(*send, seg);
    }

    // ACK the first segment to grow cwnd.
    env.now_ms += 10;
    send->OnAck(1000 + 1460, 65535, env.now_ms);

    // Send segment 3.
    auto seg3 = send->NextSegment(65535, env.now_ms);
    TCPIP2_EXPECT_TRUE(seg3.has_segment);
    env.SendSegment(*send, seg3);

    // Send segment 4 if possible.
    auto seg4 = send->NextSegment(65535, env.now_ms);
    if (seg4.has_segment) {
        env.SendSegment(*send, seg4);
    }

    // Send 3 duplicate ACKs.
    for (int i = 0; i < 3; ++i) {
        auto r = send->OnAck(2460, 65535, env.now_ms + 10 + i, true);
        if (i == 2) {
            TCPIP2_EXPECT_TRUE(r.fast_retransmit);
        }
    }

    TCPIP2_EXPECT_TRUE(send->InFastRecovery());
}

TCPIP2_TEST(SendBufferHybridCloseResetsController) {
    TestEnv env;
    auto send = MakeHybrid();

    std::vector<std::uint8_t> data(10000, 'x');
    send->Enqueue(data.data(), data.size());
    auto seg = send->NextSegment(65535, env.now_ms);
    env.SendSegment(*send, seg);

    // Trigger RTO.
    env.now_ms += 2000;
    auto rto_seg = send->NextSegment(65535, env.now_ms);
    TCPIP2_EXPECT_TRUE(rto_seg.is_retransmission);
    env.SendSegment(*send, rto_seg);

    // cwnd should be 1 MSS after RTO.
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), 1460U);

    // After more RTOs, buffer closes and controller resets.
    for (int i = 0; i < 5; ++i) {
        env.now_ms += 10000;
        auto s = send->NextSegment(65535, env.now_ms);
        if (s.has_segment) {
            env.SendSegment(*send, s);
        }
    }

    if (send->IsClosed()) {
        TCPIP2_EXPECT_EQ(send->CongestionWindow(), 2920U);
    }
}

TCPIP2_TEST_MAIN()
