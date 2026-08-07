#include <cstddef>

#include <tcpip2/address.h>
#include <tcpip2/flow.h>

#include <core/dispatcher.h>
#include <core/shard.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(DispatcherQueueShardIdentity) {
    PacketDispatcher d(4, 4);
    for (std::size_t i = 0; i < 4; ++i) {
        TCPIP2_EXPECT_EQ(i, d.QueueShard(i));
    }
    TCPIP2_EXPECT_EQ(std::size_t{4}, d.ShardCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, d.QueueCount());
}

TCPIP2_TEST(DispatcherQueueShardCustom) {
    PacketDispatcher d(4, 4);
    d.SetQueueShard(0, 2);
    d.SetQueueShard(1, 3);
    d.SetQueueShard(2, 0);
    d.SetQueueShard(3, 1);

    TCPIP2_EXPECT_EQ(std::size_t{2}, d.QueueShard(0));
    TCPIP2_EXPECT_EQ(std::size_t{3}, d.QueueShard(1));
    TCPIP2_EXPECT_EQ(std::size_t{0}, d.QueueShard(2));
    TCPIP2_EXPECT_EQ(std::size_t{1}, d.QueueShard(3));
}

TCPIP2_TEST(DispatcherFlowShardBidirectional) {
    PacketDispatcher d(8, 1);

    FlowKey ab;
    ab.source = IpAddress::Ipv4(10, 0, 0, 1);
    ab.destination = IpAddress::Ipv4(10, 0, 0, 2);
    ab.source_port = 1000;
    ab.destination_port = 80;
    ab.protocol = 6;

    FlowKey ba;
    ba.source = IpAddress::Ipv4(10, 0, 0, 2);
    ba.destination = IpAddress::Ipv4(10, 0, 0, 1);
    ba.source_port = 80;
    ba.destination_port = 1000;
    ba.protocol = 6;

    TCPIP2_EXPECT_EQ(d.FlowShard(ab), d.FlowShard(ba));
}

TCPIP2_TEST(DispatcherFlowShardDistribution) {
    PacketDispatcher d(4, 1);
    std::size_t counts[4] = {0, 0, 0, 0};
    for (std::size_t i = 0; i < 1000; ++i) {
        FlowKey fk;
        fk.source = IpAddress::Ipv4(static_cast<std::uint8_t>(i & 0xFF),
                                    static_cast<std::uint8_t>((i >> 8) & 0xFF),
                                    static_cast<std::uint8_t>(i & 0x7F),
                                    static_cast<std::uint8_t>(i % 200 + 1));
        fk.destination = IpAddress::Ipv4(static_cast<std::uint8_t>((i * 7) & 0xFF),
                                    static_cast<std::uint8_t>((i * 13) & 0xFF),
                                    static_cast<std::uint8_t>((i * 3) & 0xFF),
                                    static_cast<std::uint8_t>((i % 250) + 1));
        fk.source_port = static_cast<std::uint16_t>(i + 1024);
        fk.destination_port = static_cast<std::uint16_t>((i * 17) % 60000 + 1);
        fk.protocol = 6;
        const std::size_t shard = d.FlowShard(fk);
        TCPIP2_EXPECT_TRUE(shard < 4);
        ++counts[shard];
    }
    // No shard should be starved.
    for (std::size_t s = 0; s < 4; ++s) {
        TCPIP2_EXPECT_TRUE(counts[s] > 0);
    }
}

TCPIP2_TEST(DispatcherDirectVsRedirect) {
    PacketDispatcher d(4, 4);
    // Default identity mapping: queue i -> shard i.

    FlowKey fk;
    fk.source = IpAddress::Ipv4(10, 0, 0, 1);
    fk.destination = IpAddress::Ipv4(10, 0, 0, 2);
    fk.source_port = 1000;
    fk.destination_port = 80;
    fk.protocol = 6;

    const std::size_t flow_shard = d.FlowShard(fk);

    // Test on the queue that matches the flow's shard — should be direct.
    StackShard* shards[4] = {nullptr, nullptr, nullptr, nullptr};
    const bool direct = d.Dispatch(flow_shard, fk, shards);
    TCPIP2_EXPECT_TRUE(direct);

    // Test on a different queue — should be redirect (false).
    for (std::size_t q = 0; q < 4; ++q) {
        if (q == flow_shard) continue;
        const bool redirected = d.Dispatch(q, fk, shards);
        TCPIP2_EXPECT_FALSE(redirected);
    }
}

TCPIP2_TEST(DispatcherInvalidQueueShard) {
    PacketDispatcher d(4, 2);
    // Setting out-of-range queue or shard should be a no-op.
    d.SetQueueShard(10, 0);  // invalid queue
    d.SetQueueShard(0, 10);  // invalid shard
    // Identity mapping still holds.
    TCPIP2_EXPECT_EQ(std::size_t{0}, d.QueueShard(0));
    TCPIP2_EXPECT_EQ(std::size_t{1}, d.QueueShard(1));
}

TCPIP2_TEST(DispatcherQueueShardOutOfRange) {
    PacketDispatcher d(4, 4);
    // Out-of-range queue_id should return 0 (safe fallback).
    TCPIP2_EXPECT_EQ(std::size_t{0}, d.QueueShard(100));
}

TCPIP2_TEST_MAIN();
