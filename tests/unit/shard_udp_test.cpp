/**
 * @file shard_udp_test.cpp
 * @brief Tests for UDP packet handling in the StackShard RX path.
 * @license GPL-3.0
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/packet_io.h>

#include <core/shard.h>
#include <ip/ipv4.h>
#include <udp/udp.h>

#include "FakeUdpSession.h"
#include "Test.h"

using namespace tcpip2;

bool WaitFor(const std::function<bool()>& predicate) {
    for (int i = 0; i < 300; ++i) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return predicate();
}

namespace {

// ---------------------------------------------------------------------------
// Inline helpers for building raw packets.
// ---------------------------------------------------------------------------

std::uint16_t InlineChecksum(const std::uint8_t* data, std::size_t len, std::uint32_t seed) {
    std::uint32_t acc = seed;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        acc += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1]);
    }
    if (i < len) {
        acc += static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[i]) << 8);
    }
    while ((acc >> 16) != 0) {
        acc = (acc & 0xFFFFu) + (acc >> 16);
    }
    return static_cast<std::uint16_t>(~acc & 0xFFFFu);
}

void AppendU16(std::vector<std::uint8_t>& v, std::uint16_t val) {
    v.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFFu));
    v.push_back(static_cast<std::uint8_t>(val & 0xFFu));
}

void AppendU32(std::vector<std::uint8_t>& v, std::uint32_t val) {
    v.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFFu));
    v.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFFu));
    v.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFFu));
    v.push_back(static_cast<std::uint8_t>(val & 0xFFu));
}

/// Build a valid IPv4+UDP packet with correct checksums.
std::vector<std::uint8_t> BuildValidIpv4Udp(
    std::uint32_t src_ip, std::uint32_t dst_ip,
    std::uint16_t src_port, std::uint16_t dst_port) {

    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    const std::size_t udp_len = 8 + payload.size();
    const std::size_t total_len = 20 + udp_len;

    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);
    AppendU16(pkt, 0x0000);
    pkt.push_back(64);
    pkt.push_back(0x11);  // protocol = UDP
    AppendU16(pkt, 0);
    AppendU32(pkt, src_ip);
    AppendU32(pkt, dst_ip);

    AppendU16(pkt, src_port);
    AppendU16(pkt, dst_port);
    AppendU16(pkt, static_cast<std::uint16_t>(udp_len));
    AppendU16(pkt, 0);  // checksum placeholder
    for (auto b : payload) pkt.push_back(b);

    // IPv4 header checksum
    pkt[10] = 0;
    pkt[11] = 0;
    const std::uint16_t ip_cksum = InlineChecksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_cksum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_cksum & 0xFFu);

    // UDP checksum (correct)
    const std::uint8_t src_bytes[4] = {
        static_cast<std::uint8_t>((src_ip >> 24) & 0xFF),
        static_cast<std::uint8_t>((src_ip >> 16) & 0xFF),
        static_cast<std::uint8_t>((src_ip >> 8) & 0xFF),
        static_cast<std::uint8_t>(src_ip & 0xFF)};
    const std::uint8_t dst_bytes[4] = {
        static_cast<std::uint8_t>((dst_ip >> 24) & 0xFF),
        static_cast<std::uint8_t>((dst_ip >> 16) & 0xFF),
        static_cast<std::uint8_t>((dst_ip >> 8) & 0xFF),
        static_cast<std::uint8_t>(dst_ip & 0xFF)};
    std::uint32_t seed = 0;
    // Inline pseudo-header computation
    seed += static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(src_bytes[0]) << 8) | src_bytes[1]);
    seed += static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(src_bytes[2]) << 8) | src_bytes[3]);
    seed += static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(dst_bytes[0]) << 8) | dst_bytes[1]);
    seed += static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(dst_bytes[2]) << 8) | dst_bytes[3]);
    seed += 17;  // protocol
    seed += static_cast<std::uint16_t>(udp_len);

    std::uint16_t udp_cksum = InlineChecksum(pkt.data() + 20, udp_len, seed);
    if (udp_cksum == 0) udp_cksum = 0xFFFF;
    pkt[26] = static_cast<std::uint8_t>((udp_cksum >> 8) & 0xFFu);
    pkt[27] = static_cast<std::uint8_t>(udp_cksum & 0xFFu);

    return pkt;
}

/// Build an IPv4 packet with an unknown protocol (255).
std::vector<std::uint8_t> BuildIpv4UnknownProtocol(
    std::uint32_t src_ip, std::uint32_t dst_ip) {

    const std::size_t total_len = 20 + 4;
    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);
    AppendU16(pkt, 0x0000);
    pkt.push_back(64);
    pkt.push_back(255);  // unknown protocol
    AppendU16(pkt, 0);
    AppendU32(pkt, src_ip);
    AppendU32(pkt, dst_ip);
    pkt.push_back(0);
    pkt.push_back(0);
    pkt.push_back(0);
    pkt.push_back(0);

    pkt[10] = 0;
    pkt[11] = 0;
    const std::uint16_t ip_cksum = InlineChecksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_cksum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_cksum & 0xFFu);

    return pkt;
}

} // namespace

// ---------------------------------------------------------------------------
// Test 1: UDP packet received by shard — UdpDatagramsReceived increments
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardUdpPacketReceived) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::size_t udp_before = shard.UdpDatagramsReceived();

    const std::vector<std::uint8_t> pkt = BuildValidIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    TCPIP2_EXPECT_TRUE(shard.UdpDatagramsReceived() > udp_before);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 2: Non-UDP non-TCP packet (protocol=255) is dropped
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardNonUdpNonTcpDropped) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::size_t dropped_before = shard.PacketsDropped();
    const std::size_t udp_before = shard.UdpDatagramsReceived();

    const std::vector<std::uint8_t> pkt = BuildIpv4UnknownProtocol(
        0x0a000001u, 0x0a000002u);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    TCPIP2_EXPECT_TRUE(shard.PacketsDropped() > dropped_before);
    TCPIP2_EXPECT_EQ(udp_before, shard.UdpDatagramsReceived());

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// R7: UDP flow table integration through the StackShard
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardUdpFlowOpensSessionAndForwardsDatagram) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    test::FakeSessionFactory factory;
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128, &factory);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::vector<std::uint8_t> pkt = BuildValidIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    // First client datagram opens the adapter session and forwards the payload.
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return factory.SessionCount() == 1; }));
    TCPIP2_EXPECT_EQ(std::size_t{1}, shard.UdpFlowCount());
    shard.Stop();

    TCPIP2_EXPECT_EQ(std::size_t{1}, factory.OpenCalls());
    const auto session = factory.Session(0);
    TCPIP2_EXPECT_EQ(std::size_t{1}, session->SendCalls());
    // BuildValidIpv4Udp carries payload {1,2,3,4}.
    TCPIP2_EXPECT_EQ(std::size_t{4}, session->Received().size());
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, session->Received()[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, session->Received()[3]);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ShardUdpRemoteDatagramEgressesThroughScheduler) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    test::FakeSessionFactory factory;
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128, &factory);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // Client datagram opens the flow/session.
    const std::vector<std::uint8_t> pkt = BuildValidIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return factory.SessionCount() == 1; }));

    // A remote datagram arrives through the session's data callback. The
    // shard serializes it (reversed flow: 10.0.0.2:53 -> 10.0.0.1:12345) and
    // routes it through the shared FQ-CoDel egress scheduler.
    const std::vector<std::uint8_t> remote = {0xAA, 0xBB, 0xCC, 0xDD};
    const ReceiveStatus st = factory.Session(0)->PushRemote(remote, pool);
    TCPIP2_EXPECT_EQ(ReceiveStatus::Accepted, st);
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return io.EgressSnapshot(0).size() > 0; }));
    shard.Stop();

    const auto egress = io.EgressSnapshot(0);
    TCPIP2_EXPECT_EQ(std::size_t{1}, egress.size());
    if (egress.empty()) {
        pool.DrainReturnQueue();
        return;
    }
    const auto& emitted = egress[0];
    const Ipv4ParseResult ip = ParseIpv4(emitted.data(), emitted.size());
    TCPIP2_EXPECT_EQ(Ipv4ParseError::None, ip.error);
    if (ip.error != Ipv4ParseError::None) {
        pool.DrainReturnQueue();
        return;
    }
    // Reversed flow: source = remote endpoint 10.0.0.2:53.
    TCPIP2_EXPECT_EQ(std::uint8_t{0x0a}, ip.header.src_ip[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, ip.header.src_ip[3]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x0a}, ip.header.dst_ip[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, ip.header.dst_ip[3]);
    const UdpParseResult udp = ParseUdpDatagram(
        IpAddress::Ipv4(ip.header.src_ip[0], ip.header.src_ip[1],
                        ip.header.src_ip[2], ip.header.src_ip[3]),
        IpAddress::Ipv4(ip.header.dst_ip[0], ip.header.dst_ip[1],
                        ip.header.dst_ip[2], ip.header.dst_ip[3]),
        ip.payload, ip.header.payload_length, false);
    TCPIP2_EXPECT_EQ(UdpParseError::None, udp.error);
    if (udp.error != UdpParseError::None) {
        pool.DrainReturnQueue();
        return;
    }
    TCPIP2_EXPECT_EQ(std::uint16_t{53}, udp.header.src_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{12345}, udp.header.dst_port);
    TCPIP2_EXPECT_EQ(remote, std::vector<std::uint8_t>(
        udp.payload, udp.payload + udp.payload_length));

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
