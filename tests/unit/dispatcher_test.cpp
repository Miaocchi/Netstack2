#include <cstddef>
#include <cstdint>
#include <vector>

#include <tcpip2/address.h>
#include <tcpip2/flow.h>

#include <core/dispatcher.h>

#include "PacketBuilder.h"
#include "Test.h"

using namespace tcpip2;

namespace {

std::vector<std::uint8_t> BuildIpv4Udp(std::uint32_t source, std::uint32_t destination, std::uint16_t source_port,
                                       std::uint16_t destination_port) {
    std::vector<std::uint8_t> packet(28, 0);
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = static_cast<std::uint8_t>(source >> 24);
    packet[13] = static_cast<std::uint8_t>(source >> 16);
    packet[14] = static_cast<std::uint8_t>(source >> 8);
    packet[15] = static_cast<std::uint8_t>(source);
    packet[16] = static_cast<std::uint8_t>(destination >> 24);
    packet[17] = static_cast<std::uint8_t>(destination >> 16);
    packet[18] = static_cast<std::uint8_t>(destination >> 8);
    packet[19] = static_cast<std::uint8_t>(destination);
    packet[20] = static_cast<std::uint8_t>(source_port >> 8);
    packet[21] = static_cast<std::uint8_t>(source_port);
    packet[22] = static_cast<std::uint8_t>(destination_port >> 8);
    packet[23] = static_cast<std::uint8_t>(destination_port);
    packet[24] = 0;
    packet[25] = 8;
    return packet;
}

} // namespace

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
        fk.source = IpAddress::Ipv4(static_cast<std::uint8_t>(i & 0xFF), static_cast<std::uint8_t>((i >> 8) & 0xFF),
                                    static_cast<std::uint8_t>(i & 0x7F), static_cast<std::uint8_t>(i % 200 + 1));
        fk.destination =
            IpAddress::Ipv4(static_cast<std::uint8_t>((i * 7) & 0xFF), static_cast<std::uint8_t>((i * 13) & 0xFF),
                            static_cast<std::uint8_t>((i * 3) & 0xFF), static_cast<std::uint8_t>((i % 250) + 1));
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
    const std::vector<std::uint8_t> packet =
        test::PacketBuilder::BuildIpv4Tcp(0x0a000001u, 0x0a000002u, 1000, 80, 1, 0, test::TcpFlags::Syn, {});
    const PacketClassification classified = d.ClassifyPacket(packet.data(), packet.size());
    TCPIP2_EXPECT_TRUE(classified.error == PacketClassificationError::None);
    TCPIP2_EXPECT_TRUE(classified.packet_class == PacketClass::kTcp);
    TCPIP2_EXPECT_TRUE(classified.IsRoutable());

    const DispatchDecision direct = d.Dispatch(classified.owner_shard, packet.data(), packet.size());
    TCPIP2_EXPECT_TRUE(direct.action == DispatchAction::kLocal);

    for (std::size_t source = 0; source < 4; ++source) {
        if (source == classified.owner_shard)
            continue;
        const DispatchDecision redirect = d.Dispatch(source, packet.data(), packet.size());
        TCPIP2_EXPECT_TRUE(redirect.action == DispatchAction::kRedirect);
        TCPIP2_EXPECT_EQ(classified.owner_shard, redirect.classification.owner_shard);
    }
}

TCPIP2_TEST(DispatcherClassifiesCanonicalTcpAndUdpFlows) {
    PacketDispatcher d(8, 1);
    const std::vector<std::uint8_t> tcp =
        test::PacketBuilder::BuildIpv4Tcp(0x0a000002u, 0x0a000001u, 443, 40000, 1, 0, test::TcpFlags::Syn, {});
    const PacketClassification tcp_class = d.ClassifyPacket(tcp.data(), tcp.size());
    TCPIP2_EXPECT_TRUE(tcp_class.packet_class == PacketClass::kTcp);
    TCPIP2_EXPECT_TRUE(tcp_class.flow == tcp_class.flow.Canonical());
    TCPIP2_EXPECT_EQ(tcp_class.owner_shard, d.FlowShard(tcp_class.flow));

    const std::vector<std::uint8_t> udp = BuildIpv4Udp(0x0a000002u, 0x0a000001u, 53, 50000);
    const PacketClassification udp_class = d.ClassifyPacket(udp.data(), udp.size());
    TCPIP2_EXPECT_TRUE(udp_class.error == PacketClassificationError::None);
    TCPIP2_EXPECT_TRUE(udp_class.packet_class == PacketClass::kUdp);
    TCPIP2_EXPECT_TRUE(udp_class.flow == udp_class.flow.Canonical());
    TCPIP2_EXPECT_EQ(udp_class.owner_shard, d.FlowShard(udp_class.flow));
}

TCPIP2_TEST(DispatcherClassifiesFragmentsByStableFragmentKey) {
    PacketDispatcher d(4, 1);
    const std::vector<std::uint8_t> syn =
        test::PacketBuilder::BuildIpv4Tcp(0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0, test::TcpFlags::Syn, {});
    const std::vector<std::uint8_t> first_segment(syn.begin() + 20, syn.begin() + 28);
    const std::vector<std::uint8_t> fragment =
        test::PacketBuilder::BuildIpv4TcpFragment(0x0a000001u, 0x0a000002u, 0x1234, 0, true, first_segment);

    const PacketClassification classified = d.ClassifyPacket(fragment.data(), fragment.size());
    TCPIP2_EXPECT_TRUE(classified.error == PacketClassificationError::None);
    TCPIP2_EXPECT_TRUE(classified.packet_class == PacketClass::kFragment);
    TCPIP2_EXPECT_TRUE(classified.IsRoutable());
    TCPIP2_EXPECT_EQ(classified.owner_shard, d.FragmentShard(classified.fragment));
}

TCPIP2_TEST(DispatcherInvalidQueueShard) {
    PacketDispatcher d(4, 2);
    // Setting out-of-range queue or shard should be a no-op.
    d.SetQueueShard(10, 0); // invalid queue
    d.SetQueueShard(0, 10); // invalid shard
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
