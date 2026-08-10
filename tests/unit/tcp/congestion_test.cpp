#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
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

TCPIP2_TEST_MAIN()
