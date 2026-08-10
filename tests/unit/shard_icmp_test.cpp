/**
 * @file shard_icmp_test.cpp
 * @brief Tests for ICMP processing and PMTU updates in the StackShard RX path.
 * @license GPL-3.0
 */

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/packet_io.h>

#include <core/shard.h>

#include "PacketBuilder.h"
#include "Test.h"

using namespace tcpip2;

namespace {

// ---------------------------------------------------------------------------
// Raw packet construction helpers for ICMP (PacketBuilder has no ICMP support).
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

std::uint64_t NowMs() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

/// Build an IPv4 ICMP Destination Unreachable (FragNeeded) packet.
/// @param icmp_src  IPv4 source of the ICMP message (uint32 big-endian host order)
/// @param icmp_dst  IPv4 destination of the ICMP message
/// @param mtu       next-hop MTU to report
/// @param quoted_dst  original destination IP to embed in the quoted IPv4 header
/// @param quoted_len  length of the quoted payload to include (min 20 for a valid
///                    IPv4 header; shorter values test robustness)
std::vector<std::uint8_t> BuildIpv4IcmpFragNeeded(
    std::uint32_t icmp_src, std::uint32_t icmp_dst,
    std::uint16_t mtu, std::uint32_t quoted_dst,
    std::size_t quoted_len = 28) {

    // Build the quoted payload: a minimal IPv4 header with the given dst_ip.
    std::vector<std::uint8_t> quoted;
    quoted.reserve(quoted_len);
    // Minimal IPv4 header (20 bytes) — version 4, IHL 5, protocol 6 (TCP)
    quoted.push_back(0x45);
    quoted.push_back(0x00);
    AppendU16(quoted, static_cast<std::uint16_t>(20));  // total_length
    AppendU16(quoted, 0x1234);                           // identification
    AppendU16(quoted, 0x0000);                           // flags + frag offset
    quoted.push_back(64);                                 // TTL
    quoted.push_back(0x06);                               // protocol = TCP
    AppendU16(quoted, 0);                                 // checksum placeholder
    AppendU32(quoted, 0x0a000001u);                       // src_ip (arbitrary)
    AppendU32(quoted, quoted_dst);                         // dst_ip (the target)
    // Pad with zeros if quoted_len > 20
    while (quoted.size() < quoted_len) {
        quoted.push_back(0);
    }
    // Truncate if needed
    if (quoted.size() > quoted_len) {
        quoted.resize(quoted_len);
    }

    // Build ICMP message: type(1) + code(1) + checksum(2) + unused(2) + mtu(2) + quoted
    std::vector<std::uint8_t> icmp;
    icmp.push_back(3);   // type = Destination Unreachable
    icmp.push_back(4);   // code = Fragmentation Needed
    AppendU16(icmp, 0);  // checksum placeholder
    AppendU16(icmp, 0);  // unused
    AppendU16(icmp, mtu);
    for (std::uint8_t b : quoted) icmp.push_back(b);

    // Compute ICMP checksum
    const std::uint16_t cksum = InlineChecksum(icmp.data(), icmp.size(), 0);
    icmp[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFFu);
    icmp[3] = static_cast<std::uint8_t>(cksum & 0xFFu);

    // Build IPv4 header (20 bytes) wrapping the ICMP message
    const std::size_t total_len = 20 + icmp.size();
    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);           // identification
    AppendU16(pkt, 0x0000);      // flags + frag offset
    pkt.push_back(64);           // TTL
    pkt.push_back(0x01);         // protocol = ICMP
    AppendU16(pkt, 0);           // checksum placeholder
    AppendU32(pkt, icmp_src);
    AppendU32(pkt, icmp_dst);

    for (std::uint8_t b : icmp) pkt.push_back(b);

    // Compute IPv4 header checksum
    const std::uint16_t ip_cksum = InlineChecksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_cksum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_cksum & 0xFFu);

    return pkt;
}

/// Build an IPv6 ICMPv6 Packet Too Big packet with a correct ICMPv6 checksum.
/// @param icmp6_src  source IPv6 of the ICMPv6 message (16 bytes)
/// @param icmp6_dst  destination IPv6 of the ICMPv6 message (16 bytes)
/// @param mtu        MTU to report
/// @param quoted_dst original destination IPv6 to embed in the quoted IPv6 header
std::vector<std::uint8_t> BuildIpv6IcmpPacketTooBig(
    const std::uint8_t icmp6_src[16], const std::uint8_t icmp6_dst[16],
    std::uint32_t mtu, const std::uint8_t quoted_dst[16]) {

    // Build the quoted payload: a minimal IPv6 fixed header (40 bytes)
    std::vector<std::uint8_t> quoted;
    quoted.reserve(40);
    quoted.push_back(0x60);  // version 6
    quoted.push_back(0x00);
    quoted.push_back(0x00);
    quoted.push_back(0x00);  // flow label
    AppendU16(quoted, 20);   // payload length (minimal)
    quoted.push_back(0x06);  // next header = TCP
    quoted.push_back(64);    // hop limit
    for (int i = 0; i < 16; ++i) quoted.push_back(0);  // src_ip (arbitrary ::)
    for (int i = 0; i < 16; ++i) quoted.push_back(quoted_dst[i]);

    // Build ICMPv6 message: type(1) + code(1) + checksum(2) + mtu(4) + quoted
    std::vector<std::uint8_t> icmp;
    icmp.push_back(2);   // type = Packet Too Big
    icmp.push_back(0);   // code = 0
    AppendU16(icmp, 0);  // checksum placeholder
    AppendU32(icmp, mtu);
    for (std::uint8_t b : quoted) icmp.push_back(b);

    // Compute ICMPv6 checksum with pseudo-header
    std::uint32_t seed = 0;
    for (int i = 0; i < 16; i += 2) {
        seed += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(icmp6_src[i]) << 8) | icmp6_src[i + 1]);
    }
    for (int i = 0; i < 16; i += 2) {
        seed += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(icmp6_dst[i]) << 8) | icmp6_dst[i + 1]);
    }
    seed += static_cast<std::uint16_t>((icmp.size() >> 16) & 0xFFFF);
    seed += static_cast<std::uint16_t>(icmp.size() & 0xFFFF);
    seed += 58;  // protocol = ICMPv6

    const std::uint16_t cksum = InlineChecksum(icmp.data(), icmp.size(), seed);
    icmp[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFFu);
    icmp[3] = static_cast<std::uint8_t>(cksum & 0xFFu);

    // Build IPv6 fixed header (40 bytes)
    const std::size_t payload_len = icmp.size();
    std::vector<std::uint8_t> pkt;
    pkt.reserve(40 + payload_len);
    pkt.push_back(0x60);
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(payload_len));
    pkt.push_back(58);  // next header = ICMPv6
    pkt.push_back(64);  // hop limit
    for (int i = 0; i < 16; ++i) pkt.push_back(icmp6_src[i]);
    for (int i = 0; i < 16; ++i) pkt.push_back(icmp6_dst[i]);

    for (std::uint8_t b : icmp) pkt.push_back(b);

    return pkt;
}

/// Build a minimal IPv4 UDP packet (non-TCP, non-ICMP) for the drop test.
std::vector<std::uint8_t> BuildIpv4Udp(std::uint32_t src_ip, std::uint32_t dst_ip) {
    const std::size_t udp_len = 8;  // UDP header only, no payload
    const std::size_t total_len = 20 + udp_len;

    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);
    AppendU16(pkt, 0x0000);
    pkt.push_back(64);
    pkt.push_back(0x11);  // protocol = UDP (17)
    AppendU16(pkt, 0);    // checksum placeholder
    AppendU32(pkt, src_ip);
    AppendU32(pkt, dst_ip);

    // UDP header
    AppendU16(pkt, 12345);  // src port
    AppendU16(pkt, 53);     // dst port
    AppendU16(pkt, static_cast<std::uint16_t>(udp_len));
    AppendU16(pkt, 0);      // checksum (0 = not computed)

    // IPv4 header checksum
    pkt[10] = 0;
    pkt[11] = 0;
    const std::uint16_t ip_cksum = InlineChecksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_cksum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_cksum & 0xFFu);

    return pkt;
}

} // namespace

// ---------------------------------------------------------------------------
// Test 1: ICMPv4 FragNeeded updates PMTU
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv4FragNeededUpdatesPmtu) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // Build an ICMPv4 DestUnreachable/FragNeeded with MTU=1200.
    // The quoted IPv4 header has dst_ip = 1.2.3.4 (0x01020304).
    const std::uint32_t quoted_dst = 0x01020304u;
    const std::vector<std::uint8_t> pkt = BuildIpv4IcmpFragNeeded(
        0x0a000001u, 0x0a000002u, 1200, quoted_dst);

    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    // Verify PMTU was updated for the quoted original destination.
    const std::uint8_t dst_bytes[4] = {1, 2, 3, 4};
    const PmtuLookupResult result = shard.LookupPmtu(dst_bytes, 4, NowMs());
    TCPIP2_EXPECT_TRUE(result.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1200}, result.pmtu);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 2: ICMPv6 PacketTooBig updates PMTU
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv6PacketTooBigUpdatesPmtu) {
    const std::uint8_t icmp6_src[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t icmp6_dst[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    // The original destination in the quoted IPv6 header
    const std::uint8_t quoted_dst[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::vector<std::uint8_t> pkt = BuildIpv6IcmpPacketTooBig(
        icmp6_src, icmp6_dst, 1280, quoted_dst);

    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const PmtuLookupResult result = shard.LookupPmtu(quoted_dst, 6, NowMs());
    TCPIP2_EXPECT_TRUE(result.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1280}, result.pmtu);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 3: UDP protocol is now handled (not dropped), no PMTU entry
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardNonIcmpProtocolDropped) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::size_t udp_before = shard.UdpDatagramsReceived();

    const std::vector<std::uint8_t> pkt = BuildIpv4Udp(0x0a000001u, 0x0a000002u);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    // UDP is now handled by the shard, not dropped.
    TCPIP2_EXPECT_TRUE(shard.UdpDatagramsReceived() > udp_before);

    // No PMTU entry should exist for 10.0.0.2
    const std::uint8_t dst_bytes[4] = {10, 0, 0, 2};
    const PmtuLookupResult result = shard.LookupPmtu(dst_bytes, 4, NowMs());
    TCPIP2_EXPECT_FALSE(result.found);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 4: ICMPv4 FragNeeded with short quoted payload doesn't crash
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv4ShortQuotedPayloadNoCrash) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // quoted_len = 4: far too short to contain an IPv4 header (needs 20 bytes).
    // The quoted payload will be 4 bytes of zeros. HandleIcmp should bail out
    // gracefully without reading out of bounds.
    const std::vector<std::uint8_t> pkt = BuildIpv4IcmpFragNeeded(
        0x0a000001u, 0x0a000002u, 1200, 0x01020304u, 4);

    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), pkt.data(), pkt.size());
    lease.Resize(pkt.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    // No PMTU entry should have been created (quoted payload was too short).
    const std::uint8_t dst_bytes[4] = {1, 2, 3, 4};
    const PmtuLookupResult result = shard.LookupPmtu(dst_bytes, 4, NowMs());
    TCPIP2_EXPECT_FALSE(result.found);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
