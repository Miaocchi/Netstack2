/**
 * @file fq_codel_test.cpp
 * @brief Unit tests for the FQ-CoDel scheduler.
 * @license GPL-3.0
 */

#include "Test.h"

#include <qos/fq_codel.h>
#include <tcpip2/buffer.h>
#include <ip/checksum.h>

#include <cstring>
#include <vector>

namespace {

/// Pool used by every test. Slot count and capacity are generous so that
/// none of the tests hits pool exhaustion.
tcpip2::PktBufferPool& TestPool() {
    static tcpip2::PktBufferPool pool(256, 2048);
    return pool;
}

/// Allocate a BufferLease filled with @p fill, length @p size.
tcpip2::BufferLease MakeLease(std::uint8_t fill, std::size_t size) {
    auto lease = TestPool().Allocate();
    if (lease) {
        std::memset(lease.Data(), fill, size);
        lease.Resize(size);
    }
    return lease;
}

} // namespace

TCPIP2_TEST(FqCoDelEmptyOnConstruction) {
    tcpip2::FqCoDelScheduler sched;
    TCPIP2_EXPECT_TRUE(sched.Empty());
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(0));
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(0));
}

TCPIP2_TEST(FqCoDelSingleFlowFifoOrdering) {
    tcpip2::FqCoDelScheduler sched;
    const auto flow = static_cast<std::uint32_t>(1);

    // Enqueue 5 packets with distinct payloads.
    for (std::uint8_t i = 0; i < 5; ++i) {
        auto lease = MakeLease(i, 64);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));
    }
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(5));
    TCPIP2_EXPECT_FALSE(sched.Empty());

    // Dequeue all — should come out in FIFO order (low sojourn, no drops).
    for (std::uint8_t i = 0; i < 5; ++i) {
        auto pkt = sched.Dequeue(1); // now_ms=1 so sojourn=1 < target=5
        TCPIP2_EXPECT_TRUE(pkt.has_value());
        if (pkt) {
            TCPIP2_EXPECT_EQ(pkt->Size(), static_cast<std::size_t>(64));
            TCPIP2_EXPECT_EQ(pkt->Data()[0], i);
        }
    }
    TCPIP2_EXPECT_TRUE(sched.Empty());
}

TCPIP2_TEST(FqCoDelDequeuedPacketPreservesFlowHash) {
    tcpip2::FqCoDelScheduler sched;
    const std::uint32_t flow_hash = 0x93ab47d1u;
    auto lease = MakeLease(0x42, 32);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow_hash, 0));

    const auto packet = sched.Dequeue(1);
    TCPIP2_EXPECT_TRUE(packet.has_value());
    if (packet) {
        TCPIP2_EXPECT_EQ(flow_hash, packet->flow_hash);
    }
}

TCPIP2_TEST(FqCoDelMultipleFlowRoundRobin) {
    tcpip2::FqCoDelConfig config;
    config.quantum = 100; // small quantum so each flow sends ~1 packet/round
    tcpip2::FqCoDelScheduler sched(config);

    // Two flows with 3 packets each.
    const std::uint32_t flow_a = 10;
    const std::uint32_t flow_b = 20;

    for (int i = 0; i < 3; ++i) {
        auto pa = MakeLease(static_cast<std::uint8_t>('A' + i), 50);
        auto pb = MakeLease(static_cast<std::uint8_t>('a' + i), 50);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(pa), flow_a, 0));
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(pb), flow_b, 0));
    }

    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(2));

    // Dequeue 6 packets. With deficit round-robin, the two flows should
    // interleave (A, B, A, B, A, B) or close to it — each packet is 50
    // bytes and quantum is 100, so each flow gets one packet per round.
    std::vector<std::uint8_t> first_byte;
    for (int i = 0; i < 6; ++i) {
        auto pkt = sched.Dequeue(1);
        TCPIP2_EXPECT_TRUE(pkt.has_value());
        if (pkt) {
            first_byte.push_back(pkt->Data()[0]);
        }
    }

    // Verify both flows are represented: should have 3 'A'-'C' and 3 'a'-'c'.
    int upper = 0, lower = 0;
    for (auto b : first_byte) {
        if (b >= 'A' && b <= 'C') ++upper;
        else if (b >= 'a' && b <= 'c') ++lower;
    }
    TCPIP2_EXPECT_EQ(upper, 3);
    TCPIP2_EXPECT_EQ(lower, 3);
}

TCPIP2_TEST(FqCoDelCoDelDropsHighSojourn) {
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 10;
    config.quantum = 1514;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 42;

    // Enqueue 20 packets at t=0.
    for (int i = 0; i < 20; ++i) {
        auto lease = MakeLease(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));
    }

    // Dequeue at t=100 — sojourn=100ms, far above target=5ms.
    // CoDel should start dropping after the interval (10ms) elapses.
    // first_above_time is set to 100+10=110 on the first packet.
    // Since now_ms=100 < 110, the first packet is NOT dropped.
    // We advance time with each dequeue so we eventually cross 110.
    std::size_t delivered = 0;
    std::uint64_t now = 100;
    while (true) {
        auto pkt = sched.Dequeue(now);
        if (!pkt) break;
        ++delivered;
        now += 15; // advance past interval to trigger drops
    }

    // With 20 packets, CoDel should drop at least some (sojourn >> target).
    TCPIP2_EXPECT_TRUE(delivered < 20);
}

TCPIP2_TEST(FqCoDelNoDropsWhenLowSojourn) {
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 10;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 99;

    for (int i = 0; i < 10; ++i) {
        auto lease = MakeLease(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow,
                                         static_cast<std::uint64_t>(i)));
    }

    std::size_t delivered = 0;
    for (int i = 0; i < 10; ++i) {
        auto pkt = sched.Dequeue(static_cast<std::uint64_t>(i + 1));
        if (pkt) ++delivered;
    }
    TCPIP2_EXPECT_EQ(delivered, static_cast<std::size_t>(10));
}

TCPIP2_TEST(FqCoDelResetClearsState) {
    tcpip2::FqCoDelScheduler sched;

    const std::uint32_t flow = 7;
    for (int i = 0; i < 5; ++i) {
        auto lease = MakeLease(static_cast<std::uint8_t>(i), 64);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));
    }
    TCPIP2_EXPECT_FALSE(sched.Empty());

    sched.Reset();
    TCPIP2_EXPECT_TRUE(sched.Empty());
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(0));
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(0));

    // Scheduler should still work after reset.
    auto lease = MakeLease(0xFF, 64);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));
    TCPIP2_EXPECT_FALSE(sched.Empty());
    auto pkt = sched.Dequeue(1);
    TCPIP2_EXPECT_TRUE(pkt.has_value());
}

TCPIP2_TEST(FqCoDelQueueLengthTracking) {
    tcpip2::FqCoDelScheduler sched;

    const std::uint32_t flow1 = 100;
    const std::uint32_t flow2 = 200;

    auto p1 = MakeLease(1, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p1), flow1, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(1));

    auto p2 = MakeLease(2, 200);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p2), flow2, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(2));

    auto p3 = MakeLease(3, 50);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p3), flow1, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(3));

    // Dequeue one.
    auto pkt = sched.Dequeue(1);
    TCPIP2_EXPECT_TRUE(pkt.has_value());
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(2));
}

TCPIP2_TEST(FqCoDelMaxQueueLengthRejects) {
    tcpip2::FqCoDelConfig config;
    config.max_queue_length = 3;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 300;
    for (int i = 0; i < 3; ++i) {
        auto lease = MakeLease(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));
    }

    // Fourth packet should be rejected.
    auto lease = MakeLease(99, 32);
    TCPIP2_EXPECT_FALSE(sched.Enqueue(std::move(lease), flow, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(3));
}

TCPIP2_TEST(FqCoDelRejectsEmptyLease) {
    tcpip2::FqCoDelScheduler sched;
    tcpip2::BufferLease empty; // not allocated
    TCPIP2_EXPECT_FALSE(sched.Enqueue(std::move(empty), 1, 0));
}

TCPIP2_TEST(FqCoDelDequeueEmptyReturnsNullopt) {
    tcpip2::FqCoDelScheduler sched;
    auto pkt = sched.Dequeue(100);
    TCPIP2_EXPECT_FALSE(pkt.has_value());
}

TCPIP2_TEST(FqCoDelLargePacketRequiresMultipleRounds) {
    tcpip2::FqCoDelConfig config;
    config.quantum = 64; // smaller than the packet
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 500;
    // Packet larger than quantum: 200 bytes, quantum=64.
    auto lease = MakeLease(0xAA, 200);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));

    // With a single flow, the scheduler accumulates deficit across rounds
    // until it has enough to dequeue the packet. The first Dequeue call
    // should eventually succeed after internal rotations.
    auto pkt = sched.Dequeue(1);
    TCPIP2_EXPECT_TRUE(pkt.has_value());
    if (pkt) {
        TCPIP2_EXPECT_EQ(pkt->Size(), static_cast<std::size_t>(200));
    }
}

TCPIP2_TEST(FqCoDelCoDelExitDroppingOnLowSojourn) {
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 10;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 600;

    // Enqueue 20 packets at t=0, dequeue starting at t=100 with advancing
    // time to trigger CoDel drops.
    for (int i = 0; i < 20; ++i) {
        auto lease = MakeLease(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 0));
    }

    std::size_t first_round = 0;
    std::uint64_t now = 100;
    while (true) {
        auto pkt = sched.Dequeue(now);
        if (!pkt) break;
        ++first_round;
        now += 15;
    }

    // Some packets should have been dropped.
    TCPIP2_EXPECT_TRUE(first_round < 20);

    // Enqueue 5 more at t=500, dequeue at t=501 (sojourn=1 < target=5).
    // No drops should occur even if CoDel was previously in dropping state.
    for (int i = 0; i < 5; ++i) {
        auto lease = MakeLease(static_cast<std::uint8_t>(10 + i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(lease), flow, 500));
    }

    std::size_t second_round = 0;
    while (true) {
        auto pkt = sched.Dequeue(501);
        if (!pkt) break;
        ++second_round;
    }

    // All 5 should be delivered (no drops on low sojourn).
    TCPIP2_EXPECT_EQ(second_round, static_cast<std::size_t>(5));
}

TCPIP2_TEST(FqCoDelActiveFlowCount) {
    tcpip2::FqCoDelScheduler sched;
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(0));

    auto p1 = MakeLease(1, 100);
    sched.Enqueue(std::move(p1), 1, 0);
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(1));

    auto p2 = MakeLease(2, 100);
    sched.Enqueue(std::move(p2), 2, 0);
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(2));

    // Same flow — should not increase count.
    auto p3 = MakeLease(3, 100);
    sched.Enqueue(std::move(p3), 1, 0);
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(2));
}

TCPIP2_TEST(FqCoDelDifferentFlowsCanEnqueueBeyondSingleFlowLimit) {
    tcpip2::FqCoDelConfig config;
    config.max_queue_length = 2;
    tcpip2::FqCoDelScheduler sched(config);

    auto p1 = MakeLease(1, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p1), 1, 0));
    auto p2 = MakeLease(2, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p2), 1, 0));
    auto p3 = MakeLease(3, 100);
    TCPIP2_EXPECT_FALSE(sched.Enqueue(std::move(p3), 1, 0)); // flow 1 full

    // Flow 2 should still be able to enqueue.
    auto p4 = MakeLease(4, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p4), 2, 0));
    auto p5 = MakeLease(5, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(std::move(p5), 2, 0));
}

TCPIP2_TEST(FqCoDelMixedSizesFairByBytes) {
    tcpip2::FqCoDelConfig config;
    config.quantum = 1000;
    tcpip2::FqCoDelScheduler sched(config);

    // Flow A: 5 x 200-byte packets = 1000 bytes total.
    for (int i = 0; i < 5; ++i) {
        auto p = MakeLease(0xA0, 200);
        sched.Enqueue(std::move(p), 100, 0);
    }
    // Flow B: 5 x 200-byte packets = 1000 bytes total.
    for (int i = 0; i < 5; ++i) {
        auto p = MakeLease(0xB0, 200);
        sched.Enqueue(std::move(p), 200, 0);
    }

    // Dequeue all 10 packets.
    int flow_a = 0, flow_b = 0;
    for (int i = 0; i < 10; ++i) {
        auto pkt = sched.Dequeue(1);
        if (!pkt) break;
        if (pkt->Data()[0] == 0xA0) ++flow_a;
        else ++flow_b;
    }

    // Both flows should have delivered all 5 packets.
    TCPIP2_EXPECT_EQ(flow_a, 5);
    TCPIP2_EXPECT_EQ(flow_b, 5);
}

// ---------------------------------------------------------------------------
// R6: byte limits (per-flow and scheduler-wide hard caps)
// ---------------------------------------------------------------------------

TCPIP2_TEST(FqCoDelFlowByteLimitRejects) {
    tcpip2::FqCoDelConfig config;
    config.max_flow_queue_bytes = 200;
    tcpip2::FqCoDelScheduler sched(config);

    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(1, 120), 1, 0));
    TCPIP2_EXPECT_EQ(sched.QueueBytes(), static_cast<std::size_t>(120));
    // 120 + 90 would exceed the 200-byte per-flow cap.
    TCPIP2_EXPECT_FALSE(sched.Enqueue(MakeLease(2, 90), 1, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(1));
    // A different flow is unaffected by the first flow's byte cap.
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(3, 90), 2, 0));
}

TCPIP2_TEST(FqCoDelTotalLimitsReject) {
    tcpip2::FqCoDelConfig config;
    config.max_total_bytes = 300;
    config.max_total_packets = 3;
    tcpip2::FqCoDelScheduler sched(config);

    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(1, 150), 1, 0));
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(2, 150), 2, 0));
    // Byte cap hit even though only two packets are queued.
    TCPIP2_EXPECT_FALSE(sched.Enqueue(MakeLease(3, 10), 3, 0));
}

TCPIP2_TEST(FqCoDelTotalPacketLimitRejects) {
    tcpip2::FqCoDelConfig config;
    config.max_total_packets = 2;
    tcpip2::FqCoDelScheduler sched(config);

    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(1, 10), 1, 0));
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(2, 10), 2, 0));
    TCPIP2_EXPECT_FALSE(sched.Enqueue(MakeLease(3, 10), 3, 0));
    TCPIP2_EXPECT_EQ(sched.QueueBytes(), static_cast<std::size_t>(20));
}

// ---------------------------------------------------------------------------
// R6: RFC 8290 new-flow priority over old flows
// ---------------------------------------------------------------------------

TCPIP2_TEST(FqCoDelNewFlowHasPriorityOverOldFlow) {
    tcpip2::FqCoDelConfig config;
    config.quantum = 64; // smaller than the elephant packet below
    tcpip2::FqCoDelScheduler sched(config);

    // Flow 1 enqueues a 200-byte packet: on the first dequeue it lacks
    // deficit credit and matures into the old-flow list.
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(0xAA, 200), 1, 0));
    // Flow 2 arrives with a small packet.
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(0xBB, 32), 2, 0));

    // First dequeue serves the small new flow before the matured elephant.
    auto first = sched.Dequeue(1);
    TCPIP2_EXPECT_TRUE(first.has_value());
    if (first) {
        TCPIP2_EXPECT_EQ(static_cast<std::uint32_t>(2), first->flow_hash);
    }
    // The elephant is served afterwards through the old-flow DRR list.
    auto second = sched.Dequeue(2);
    TCPIP2_EXPECT_TRUE(second.has_value());
    if (second) {
        TCPIP2_EXPECT_EQ(static_cast<std::uint32_t>(1), second->flow_hash);
        TCPIP2_EXPECT_EQ(static_cast<std::size_t>(200), second->Size());
    }
}

// ---------------------------------------------------------------------------
// R6: RFC 8289 interval/sqrt(count) drop cadence
// ---------------------------------------------------------------------------

TCPIP2_TEST(FqCoDelControlLawDropsOnSchedule) {
    // Interval 100ms, target 5ms, one flow of 14 packets enqueued at t=0.
    // Dequeue cadence 50ms starting at t=200. The state machine then drops
    // at t=300 (enter dropping, count=1, next=+100), t=400 (count=2,
    // next=+100/isqrt(2)=+100), t=500 (count=3, +100), t=600 (count=4,
    // next=+50): 9 deliveries, 5 drops, queue empty after t=650.
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 100;
    config.ecn_ce_marking = false;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 7;
    for (int i = 0; i < 14; ++i) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeLease(static_cast<std::uint8_t>(i), 32),
                                         flow, 0));
    }

    std::size_t delivered = 0;
    for (std::uint64_t t = 200, i = 0; i < 10; t += 50, ++i) {
        auto pkt = sched.Dequeue(t);
        if (pkt) {
            ++delivered;
            TCPIP2_EXPECT_FALSE(pkt->ce_marked);
        }
    }
    // 14 packets in: 9 delivered, 5 dropped by the control law.
    TCPIP2_EXPECT_EQ(delivered, static_cast<std::size_t>(9));
    TCPIP2_EXPECT_TRUE(sched.Empty());
}

// ---------------------------------------------------------------------------
// R6: ECN CE marking instead of dropping
// ---------------------------------------------------------------------------

namespace {

/// Build an IPv4 packet lease with the given ECN bits in the TOS byte and a
/// valid header checksum.
tcpip2::BufferLease MakeIpv4Lease(std::uint8_t ecn_bits, std::uint8_t fill) {
    auto lease = TestPool().Allocate();
    if (!lease) return lease;
    const std::size_t len = 40; // 20 IPv4 + 20 TCP placeholder
    lease.Resize(len);
    std::memset(lease.Data(), fill, len);
    std::uint8_t* const p = lease.Data();
    p[0] = 0x45;                           // version 4, IHL 5
    p[1] = static_cast<std::uint8_t>(ecn_bits & 0x03u);
    p[2] = 0x00;
    p[3] = static_cast<std::uint8_t>(len); // total length
    p[8] = 64;                             // TTL
    p[9] = 6;                              // protocol TCP
    p[10] = 0;
    p[11] = 0;
    const std::uint16_t cksum = tcpip2::InternetChecksum(p, 20, 0);
    p[10] = static_cast<std::uint8_t>(cksum >> 8);
    p[11] = static_cast<std::uint8_t>(cksum & 0xFFu);
    return lease;
}

/// Build an IPv6 packet lease with ECN bits placed in the traffic class
/// (bits 4-5 of the second byte).
tcpip2::BufferLease MakeIpv6Lease(std::uint8_t ecn_bits, std::uint8_t fill) {
    auto lease = TestPool().Allocate();
    if (!lease) return lease;
    const std::size_t len = 48; // 40 fixed header + 8 placeholder
    lease.Resize(len);
    std::memset(lease.Data(), fill, len);
    std::uint8_t* const p = lease.Data();
    p[0] = 0x60;                                          // version 6
    p[1] = static_cast<std::uint8_t>((ecn_bits & 0x03u) << 4);
    p[4] = 0x00;
    p[5] = 0x08;                                          // payload length
    p[6] = 6;                                             // next header TCP
    p[7] = 64;                                            // hop limit
    return lease;
}

} // namespace

TCPIP2_TEST(FqCoDelMarksCeInsteadOfDropForEct) {
    // target 5ms, interval 100ms. Four ECT(0) packets at t=0 dequeued at
    // t=150/250/350/450: the first is delivered normally (it sets the
    // over-target window); the next three hit the dropping state and must be
    // CE-marked and delivered rather than dropped.
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 100;
    config.ecn_ce_marking = true;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 9;
    for (int i = 0; i < 4; ++i) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(
            MakeIpv4Lease(0x02, static_cast<std::uint8_t>(0xC1 + i)), flow, 0));
    }

    std::size_t delivered = 0;
    std::size_t marked = 0;
    const std::uint64_t times[4] = {150, 250, 350, 450};
    for (std::uint64_t t : times) {
        auto pkt = sched.Dequeue(t);
        TCPIP2_EXPECT_TRUE(pkt.has_value());
        if (!pkt) continue;
        ++delivered;
        if (pkt->ce_marked) {
            ++marked;
            // ECN bits flipped to CE (0x03) and IPv4 header checksum valid.
            const std::uint8_t* p = pkt->Data();
            TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(p[1] & 0x03u),
                             static_cast<std::uint8_t>(0x03));
            TCPIP2_EXPECT_EQ(tcpip2::InternetChecksum(p, 20, 0),
                             static_cast<std::uint16_t>(0));
        } else {
            // The first packet carries the original ECT(0) bits.
            TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(pkt->Data()[1] & 0x03u),
                             static_cast<std::uint8_t>(0x02));
        }
    }
    // Delivered instead of dropped: all four arrive, three CE-marked.
    TCPIP2_EXPECT_EQ(delivered, static_cast<std::size_t>(4));
    TCPIP2_EXPECT_EQ(marked, static_cast<std::size_t>(3));
    TCPIP2_EXPECT_TRUE(sched.Empty());
}

TCPIP2_TEST(FqCoDelMarksCeOnIpv6Ect) {
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 100;
    config.ecn_ce_marking = true;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 11;
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeIpv6Lease(0x02, 0xD1), flow, 0));
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeIpv6Lease(0x02, 0xD2), flow, 0));

    // t=150: delivered normally (sets the over-target window).
    auto first = sched.Dequeue(150);
    TCPIP2_EXPECT_TRUE(first.has_value());
    if (first) {
        TCPIP2_EXPECT_FALSE(first->ce_marked);
    }
    // t=250: dropping state -> CE mark instead of drop.
    auto second = sched.Dequeue(250);
    TCPIP2_EXPECT_TRUE(second.has_value());
    if (second) {
        TCPIP2_EXPECT_TRUE(second->ce_marked);
        TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>((second->Data()[1] >> 4) & 0x03u),
                         static_cast<std::uint8_t>(0x03));
    }
}

TCPIP2_TEST(FqCoDelEctPacketsDeliveredWhenMarkingDisabled) {
    // With ecn_ce_marking off, ECT packets in the dropping state are dropped
    // exactly like Not-ECT packets.
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 100;
    config.ecn_ce_marking = false;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 12;
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeIpv4Lease(0x02, 0xE1), flow, 0));
    TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeIpv4Lease(0x02, 0xE2), flow, 0));

    TCPIP2_EXPECT_TRUE(sched.Dequeue(150).has_value());
    // Second packet hits the dropping state and is dropped (no CE marking).
    TCPIP2_EXPECT_FALSE(sched.Dequeue(250).has_value());
    TCPIP2_EXPECT_TRUE(sched.Empty());
}

TCPIP2_TEST(FqCoDelNotEctPacketsAreDroppedNotMarked) {
    // Not-ECT (ECN bits 00) packets cannot be CE-marked; CoDel drops them
    // once the sustained-sojourn condition holds. Same schedule as the CE
    // test: deliveries at 150/250/350/450 with drops interleaved inside
    // each dequeue after the first.
    tcpip2::FqCoDelConfig config;
    config.target_ms = 5;
    config.interval_ms = 100;
    config.ecn_ce_marking = true;
    tcpip2::FqCoDelScheduler sched(config);

    const std::uint32_t flow = 13;
    for (int i = 0; i < 8; ++i) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(MakeIpv4Lease(0x00, static_cast<std::uint8_t>(i)),
                                         flow, 0));
    }

    std::size_t delivered = 0;
    const std::uint64_t times[5] = {150, 250, 350, 450, 550};
    for (std::uint64_t t : times) {
        auto pkt = sched.Dequeue(t);
        if (pkt) {
            ++delivered;
            TCPIP2_EXPECT_FALSE(pkt->ce_marked);
        }
    }
    // Four deliveries, four drops; queue drains by t=550.
    TCPIP2_EXPECT_EQ(delivered, static_cast<std::size_t>(4));
    TCPIP2_EXPECT_TRUE(sched.Empty());
}

TCPIP2_TEST_MAIN()
