/**
 * @file fq_codel_test.cpp
 * @brief Unit tests for the FQ-CoDel scheduler.
 * @license GPL-3.0
 */

#include "Test.h"

#include <tcp/fq_codel.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace {

/// Build a payload of the given size filled with a repeating byte pattern.
std::vector<std::uint8_t> MakePayload(std::uint8_t fill, std::size_t size) {
    return std::vector<std::uint8_t>(size, fill);
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
        auto payload = MakePayload(i, 64);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
    }
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(5));
    TCPIP2_EXPECT_FALSE(sched.Empty());

    // Dequeue all — should come out in FIFO order (low sojourn, no drops).
    for (std::uint8_t i = 0; i < 5; ++i) {
        auto pkt = sched.Dequeue(1); // now_ms=1 so sojourn=1 < target=5
        TCPIP2_EXPECT_TRUE(pkt.has_value());
        if (pkt) {
            TCPIP2_EXPECT_EQ(pkt->Size(), static_cast<std::size_t>(64));
            TCPIP2_EXPECT_EQ(pkt->data[0], i);
        }
    }
    TCPIP2_EXPECT_TRUE(sched.Empty());
}

TCPIP2_TEST(FqCoDelDequeuedPacketPreservesFlowHash) {
    tcpip2::FqCoDelScheduler sched;
    const std::uint32_t flow_hash = 0x93ab47d1u;
    const auto payload = MakePayload(0x42, 32);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow_hash, 0));

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
        auto pa = MakePayload(static_cast<std::uint8_t>('A' + i), 50);
        auto pb = MakePayload(static_cast<std::uint8_t>('a' + i), 50);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(pa.data(), pa.size(), flow_a, 0));
        TCPIP2_EXPECT_TRUE(sched.Enqueue(pb.data(), pb.size(), flow_b, 0));
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
            first_byte.push_back(pkt->data[0]);
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
        auto payload = MakePayload(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
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
        auto payload = MakePayload(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow,
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
        auto payload = MakePayload(static_cast<std::uint8_t>(i), 64);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
    }
    TCPIP2_EXPECT_FALSE(sched.Empty());

    sched.Reset();
    TCPIP2_EXPECT_TRUE(sched.Empty());
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(0));
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(0));

    // Scheduler should still work after reset.
    auto payload = MakePayload(0xFF, 64);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
    TCPIP2_EXPECT_FALSE(sched.Empty());
    auto pkt = sched.Dequeue(1);
    TCPIP2_EXPECT_TRUE(pkt.has_value());
}

TCPIP2_TEST(FqCoDelQueueLengthTracking) {
    tcpip2::FqCoDelScheduler sched;

    const std::uint32_t flow1 = 100;
    const std::uint32_t flow2 = 200;

    auto p1 = MakePayload(1, 100);
    auto p2 = MakePayload(2, 200);
    auto p3 = MakePayload(3, 50);

    TCPIP2_EXPECT_TRUE(sched.Enqueue(p1.data(), p1.size(), flow1, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(1));

    TCPIP2_EXPECT_TRUE(sched.Enqueue(p2.data(), p2.size(), flow2, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(2));

    TCPIP2_EXPECT_TRUE(sched.Enqueue(p3.data(), p3.size(), flow1, 0));
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
        auto payload = MakePayload(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
    }

    // Fourth packet should be rejected.
    auto payload = MakePayload(99, 32);
    TCPIP2_EXPECT_FALSE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
    TCPIP2_EXPECT_EQ(sched.QueueLength(), static_cast<std::size_t>(3));
}

TCPIP2_TEST(FqCoDelRejectsNullAndZeroLength) {
    tcpip2::FqCoDelScheduler sched;
    TCPIP2_EXPECT_FALSE(sched.Enqueue(nullptr, 100, 1, 0));
    auto payload = MakePayload(1, 32);
    TCPIP2_EXPECT_FALSE(sched.Enqueue(payload.data(), 0, 1, 0));
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
    auto payload = MakePayload(0xAA, 200);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));

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
        auto payload = MakePayload(static_cast<std::uint8_t>(i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 0));
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
        auto payload = MakePayload(static_cast<std::uint8_t>(10 + i), 32);
        TCPIP2_EXPECT_TRUE(sched.Enqueue(payload.data(), payload.size(), flow, 500));
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

    auto p1 = MakePayload(1, 100);
    sched.Enqueue(p1.data(), p1.size(), 1, 0);
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(1));

    auto p2 = MakePayload(2, 100);
    sched.Enqueue(p2.data(), p2.size(), 2, 0);
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(2));

    // Same flow — should not increase count.
    auto p3 = MakePayload(3, 100);
    sched.Enqueue(p3.data(), p3.size(), 1, 0);
    TCPIP2_EXPECT_EQ(sched.ActiveFlowCount(), static_cast<std::size_t>(2));
}

TCPIP2_TEST(FqCoDelDifferentFlowsCanEnqueueBeyondSingleFlowLimit) {
    tcpip2::FqCoDelConfig config;
    config.max_queue_length = 2;
    tcpip2::FqCoDelScheduler sched(config);

    auto p1 = MakePayload(1, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(p1.data(), p1.size(), 1, 0));
    auto p2 = MakePayload(2, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(p2.data(), p2.size(), 1, 0));
    auto p3 = MakePayload(3, 100);
    TCPIP2_EXPECT_FALSE(sched.Enqueue(p3.data(), p3.size(), 1, 0)); // flow 1 full

    // Flow 2 should still be able to enqueue.
    auto p4 = MakePayload(4, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(p4.data(), p4.size(), 2, 0));
    auto p5 = MakePayload(5, 100);
    TCPIP2_EXPECT_TRUE(sched.Enqueue(p5.data(), p5.size(), 2, 0));
}

TCPIP2_TEST(FqCoDelMixedSizesFairByBytes) {
    tcpip2::FqCoDelConfig config;
    config.quantum = 1000;
    tcpip2::FqCoDelScheduler sched(config);

    // Flow A: 5 x 200-byte packets = 1000 bytes total.
    for (int i = 0; i < 5; ++i) {
        auto p = MakePayload(0xA0, 200);
        sched.Enqueue(p.data(), p.size(), 100, 0);
    }
    // Flow B: 5 x 200-byte packets = 1000 bytes total.
    for (int i = 0; i < 5; ++i) {
        auto p = MakePayload(0xB0, 200);
        sched.Enqueue(p.data(), p.size(), 200, 0);
    }

    // Dequeue all 10 packets.
    int flow_a = 0, flow_b = 0;
    for (int i = 0; i < 10; ++i) {
        auto pkt = sched.Dequeue(1);
        if (!pkt) break;
        if (pkt->data[0] == 0xA0) ++flow_a;
        else ++flow_b;
    }

    // Both flows should have delivered all 5 packets.
    TCPIP2_EXPECT_EQ(flow_a, 5);
    TCPIP2_EXPECT_EQ(flow_b, 5);
}

TCPIP2_TEST_MAIN()
