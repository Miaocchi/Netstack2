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

/// Allocate a lease, copy @p bytes into it, and inject on queue 0.
void Inject(NullPacketIo& io, PktBufferPool& pool,
            const std::vector<std::uint8_t>& bytes) {
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), bytes.data(), bytes.size());
    lease.Resize(bytes.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));
}

/// Poll until the shard reports @p want half-open TCP connections.
bool WaitForHalfOpen(StackShard& shard, std::size_t want) {
    for (int i = 0; i < 200; ++i) {
        if (shard.TcpHalfOpenCount() == want) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return shard.TcpHalfOpenCount() == want;
}

/// Build an IPv4 ICMP Destination Unreachable (FragNeeded) packet.
/// @param icmp_src  IPv4 source of the ICMP message (uint32 big-endian host order)
/// @param icmp_dst  IPv4 destination of the ICMP message
/// @param mtu       next-hop MTU to report
/// @param orig_src  source IP of the quoted (original, sent-by-us) packet
/// @param orig_dst  destination IP of the quoted packet (PMTU cache key)
/// @param orig_src_port our port on the original packet
/// @param orig_dst_port the peer's port on the original packet
/// @param quoted_len length of the quoted payload (min 28 = IPv4 header + 8
///                   transport bytes for flow attribution; shorter values test
///                   robustness)
std::vector<std::uint8_t> BuildIpv4IcmpFragNeeded(
    std::uint32_t icmp_src, std::uint32_t icmp_dst,
    std::uint16_t mtu, std::uint32_t orig_src, std::uint32_t orig_dst,
    std::uint16_t orig_src_port, std::uint16_t orig_dst_port,
    std::size_t quoted_len = 28) {

    // Build the quoted payload: IPv4 header (20 bytes) + the first 8 bytes of
    // the original TCP header (RFC 1191 requires at least IP header + 8).
    std::vector<std::uint8_t> quoted;
    quoted.reserve(quoted_len);
    quoted.push_back(0x45);
    quoted.push_back(0x00);
    AppendU16(quoted, static_cast<std::uint16_t>(28));  // total_length
    AppendU16(quoted, 0x1234);                           // identification
    AppendU16(quoted, 0x4000);                           // DF set, no fragment
    quoted.push_back(64);                                 // TTL
    quoted.push_back(0x06);                               // protocol = TCP
    AppendU16(quoted, 0);                                 // checksum (not validated)
    AppendU32(quoted, orig_src);
    AppendU32(quoted, orig_dst);
    // First 8 bytes of the original TCP header: ports + start of seq.
    AppendU16(quoted, orig_src_port);
    AppendU16(quoted, orig_dst_port);
    AppendU32(quoted, 0);                                 // seq (unused here)
    while (quoted.size() < quoted_len) {
        quoted.push_back(0);
    }
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
/// @param icmp6_src   source IPv6 of the ICMPv6 message (16 bytes)
/// @param icmp6_dst   destination IPv6 of the ICMPv6 message (16 bytes)
/// @param mtu         MTU to report
/// @param orig_src    source IPv6 of the quoted (original, sent-by-us) packet
/// @param orig_dst    destination IPv6 of the quoted packet (PMTU cache key)
/// @param orig_src_port our port on the original packet
/// @param orig_dst_port the peer's port on the original packet
std::vector<std::uint8_t> BuildIpv6IcmpPacketTooBig(
    const std::uint8_t icmp6_src[16], const std::uint8_t icmp6_dst[16],
    std::uint32_t mtu, const std::uint8_t orig_src[16],
    const std::uint8_t orig_dst[16], std::uint16_t orig_src_port,
    std::uint16_t orig_dst_port) {

    // Build the quoted payload: IPv6 fixed header (40 bytes) + the first 8
    // bytes of the original TCP header (needed for flow attribution).
    std::vector<std::uint8_t> quoted;
    quoted.reserve(48);
    quoted.push_back(0x60);  // version 6
    quoted.push_back(0x00);
    quoted.push_back(0x00);
    quoted.push_back(0x00);  // flow label
    AppendU16(quoted, 8);    // payload length (first 8 transport bytes)
    quoted.push_back(0x06);  // next header = TCP
    quoted.push_back(64);    // hop limit
    for (int i = 0; i < 16; ++i) quoted.push_back(orig_src[i]);
    for (int i = 0; i < 16; ++i) quoted.push_back(orig_dst[i]);
    AppendU16(quoted, orig_src_port);
    AppendU16(quoted, orig_dst_port);
    AppendU32(quoted, 0);    // seq (unused here)

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
// Echo helpers
// ---------------------------------------------------------------------------

namespace {

/// Build an IPv4 ICMP Echo Request with a valid ICMP + IP checksum.
std::vector<std::uint8_t> BuildIpv4IcmpEcho(
    std::uint32_t src, std::uint32_t dst,
    std::uint16_t id, std::uint16_t seq,
    const std::vector<std::uint8_t>& payload) {

    std::vector<std::uint8_t> icmp;
    icmp.push_back(Icmpv4Type::Echo);
    icmp.push_back(0);
    AppendU16(icmp, 0);
    AppendU16(icmp, id);
    AppendU16(icmp, seq);
    for (std::uint8_t b : payload) icmp.push_back(b);
    const std::uint16_t cksum = InlineChecksum(icmp.data(), icmp.size(), 0);
    icmp[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFFu);
    icmp[3] = static_cast<std::uint8_t>(cksum & 0xFFu);

    const std::size_t total_len = 20 + icmp.size();
    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);
    AppendU16(pkt, 0x0000);
    pkt.push_back(64);
    pkt.push_back(0x01);  // protocol = ICMP
    AppendU16(pkt, 0);    // checksum placeholder
    AppendU32(pkt, src);
    AppendU32(pkt, dst);
    for (std::uint8_t b : icmp) pkt.push_back(b);
    const std::uint16_t ip_cksum = InlineChecksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_cksum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_cksum & 0xFFu);
    return pkt;
}

/// Build an IPv6 ICMPv6 Echo Request with a valid ICMPv6 checksum.
std::vector<std::uint8_t> BuildIpv6IcmpEchoRequest(
    const std::uint8_t src[16], const std::uint8_t dst[16],
    std::uint16_t id, std::uint16_t seq,
    const std::vector<std::uint8_t>& payload) {

    std::vector<std::uint8_t> icmp;
    icmp.push_back(Icmpv6Type::EchoRequest);
    icmp.push_back(0);
    AppendU16(icmp, 0);
    AppendU16(icmp, id);
    AppendU16(icmp, seq);
    for (std::uint8_t b : payload) icmp.push_back(b);

    std::uint32_t seed = 0;
    for (int i = 0; i < 16; i += 2) {
        seed += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(src[i]) << 8) | src[i + 1]);
    }
    for (int i = 0; i < 16; i += 2) {
        seed += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(dst[i]) << 8) | dst[i + 1]);
    }
    seed += static_cast<std::uint16_t>((icmp.size() >> 16) & 0xFFFF);
    seed += static_cast<std::uint16_t>(icmp.size() & 0xFFFF);
    seed += 58;
    const std::uint16_t cksum = InlineChecksum(icmp.data(), icmp.size(), seed);
    icmp[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFFu);
    icmp[3] = static_cast<std::uint8_t>(cksum & 0xFFu);

    std::vector<std::uint8_t> pkt;
    pkt.reserve(40 + icmp.size());
    pkt.push_back(0x60);
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(icmp.size()));
    pkt.push_back(58);  // next header = ICMPv6
    pkt.push_back(64);
    for (int i = 0; i < 16; ++i) pkt.push_back(src[i]);
    for (int i = 0; i < 16; ++i) pkt.push_back(dst[i]);
    for (std::uint8_t b : icmp) pkt.push_back(b);
    return pkt;
}

} // namespace

// ---------------------------------------------------------------------------
// Test 6: IPv4 Echo Request gets an Echo Reply through the egress scheduler
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv4EchoRequestGetsReply) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::vector<std::uint8_t> payload = {0x11, 0x22, 0x33, 0x44};
    const std::vector<std::uint8_t> pkt = BuildIpv4IcmpEcho(
        0x0a000001u, 0x0a000002u, 0x1234, 7, payload);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const auto& egress = io.Egress(0);
    TCPIP2_EXPECT_EQ(std::size_t{1}, egress.size());
    if (!egress.empty()) {
        const std::vector<std::uint8_t>& r = egress[0];
        TCPIP2_EXPECT_TRUE(r.size() >= 28);
        if (r.size() >= 28) {
            // Addresses swapped: reply is 10.0.0.2 -> 10.0.0.1.
            TCPIP2_EXPECT_EQ(std::uint8_t{0x0a}, r[12]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, r[15]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x0a}, r[16]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, r[19]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, r[9]);   // protocol ICMP
            TCPIP2_EXPECT_EQ(std::uint8_t{64}, r[8]);      // refreshed TTL
            // Echo Reply: type 0, code 0, id/seq preserved.
            TCPIP2_EXPECT_EQ(std::uint8_t{0}, r[20]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0}, r[21]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x12}, r[24]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x34}, r[25]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0}, r[26]);
            TCPIP2_EXPECT_EQ(std::uint8_t{7}, r[27]);
            // Payload preserved.
            TCPIP2_EXPECT_EQ(std::size_t{4}, r.size() - 28);
            TCPIP2_EXPECT_EQ(std::uint8_t{0x11}, r[28]);
            // Checksums valid (folded one's complement over the field == 0).
            TCPIP2_EXPECT_EQ(std::uint16_t{0}, InlineChecksum(r.data(), 20, 0));
            TCPIP2_EXPECT_EQ(std::uint16_t{0},
                             InlineChecksum(r.data() + 20, r.size() - 20, 0));
        }
    }

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 7: IPv6 Echo Request gets an Echo Reply through the egress scheduler
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv6EchoRequestGetsReply) {
    const std::uint8_t src[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t dst[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::vector<std::uint8_t> payload = {0xAA, 0xBB};
    const std::vector<std::uint8_t> pkt = BuildIpv6IcmpEchoRequest(
        src, dst, 0xBEEF, 3, payload);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const auto& egress = io.Egress(0);
    TCPIP2_EXPECT_EQ(std::size_t{1}, egress.size());
    if (!egress.empty()) {
        const std::vector<std::uint8_t>& r = egress[0];
        TCPIP2_EXPECT_TRUE(r.size() >= 48);
        if (r.size() >= 48) {
            // Addresses swapped: reply is dst -> src.
            TCPIP2_EXPECT_EQ(std::uint8_t{2}, r[8 + 15]);
            TCPIP2_EXPECT_EQ(std::uint8_t{1}, r[24 + 15]);
            TCPIP2_EXPECT_EQ(std::uint8_t{64}, r[7]);     // refreshed hop limit
            // Echo Reply: type 129, code 0, id/seq preserved.
            TCPIP2_EXPECT_EQ(std::uint8_t{129}, r[40]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0}, r[41]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0xBE}, r[44]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0xEF}, r[45]);
            // Payload preserved.
            TCPIP2_EXPECT_EQ(std::uint8_t{0xAA}, r[48]);
            TCPIP2_EXPECT_EQ(std::uint8_t{0xBB}, r[49]);
            // ICMPv6 checksum valid under the swapped pseudo-header.
            std::uint32_t seed = 0;
            for (int i = 0; i < 16; i += 2) {
                seed += static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(r[8 + i]) << 8) | r[8 + i + 1]);
            }
            for (int i = 0; i < 16; i += 2) {
                seed += static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(r[24 + i]) << 8) | r[24 + i + 1]);
            }
            const std::size_t icmp_len = r.size() - 40;
            seed += static_cast<std::uint16_t>((icmp_len >> 16) & 0xFFFF);
            seed += static_cast<std::uint16_t>(icmp_len & 0xFFFF);
            seed += 58;
            TCPIP2_EXPECT_EQ(std::uint16_t{0},
                             InlineChecksum(r.data() + 40, icmp_len, seed));
        }
    }

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 8: multicast-bound echo requests are not answered
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv4MulticastEchoGetsNoReply) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // Destination 224.0.0.1 (all-hosts multicast) must not be answered.
    const std::vector<std::uint8_t> pkt = BuildIpv4IcmpEcho(
        0x0a000001u, 0xe0000001u, 1, 1, {0x01});
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    TCPIP2_EXPECT_EQ(std::size_t{0}, io.Egress(0).size());

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ShardIcmpv4FragNeededUpdatesPmtu) {
    const std::uint32_t us = 0x0a000002u;    // 10.0.0.2
    const std::uint32_t peer = 0x01020304u;  // 1.2.3.4
    const std::uint16_t our_port = 443;
    const std::uint16_t peer_port = 40000;

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // Establish a half-open flow from the peer so the ICMP can be attributed.
    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        peer, us, peer_port, our_port, 1000, 0, test::TcpFlags::Syn, {});
    Inject(io, pool, syn);
    TCPIP2_EXPECT_TRUE(WaitForHalfOpen(shard, 1));

    // FragNeeded quoting our original packet (us -> peer, ports 443->40000).
    const std::vector<std::uint8_t> pkt = BuildIpv4IcmpFragNeeded(
        0x0a000099u, us, 1200, us, peer, our_port, peer_port);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const std::uint8_t dst_bytes[4] = {1, 2, 3, 4};
    const PmtuLookupResult result = shard.LookupPmtu(dst_bytes, 4, NowMs());
    TCPIP2_EXPECT_TRUE(result.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1200}, result.pmtu);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 1b: ICMPv4 for a peer with no matching flow must NOT update PMTU
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv4FragNeededIgnoredWithoutFlow) {
    const std::uint32_t us = 0x0a000002u;
    const std::uint32_t peer = 0x01020304u;

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // No flow established. The well-formed ICMP must be dropped by
    // attribution and must not create/lower a PMTU entry.
    const std::vector<std::uint8_t> pkt = BuildIpv4IcmpFragNeeded(
        0x0a000099u, us, 1200, us, peer, 443, 40000);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const std::uint8_t dst_bytes[4] = {1, 2, 3, 4};
    const PmtuLookupResult result = shard.LookupPmtu(dst_bytes, 4, NowMs());
    TCPIP2_EXPECT_FALSE(result.found);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 2: ICMPv6 PacketTooBig updates PMTU for an attributed flow
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv6PacketTooBigUpdatesPmtu) {
    const std::uint8_t icmp6_src[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t icmp6_dst[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    // Our address and the peer's address (quoted original packet endpoints).
    const std::uint8_t us6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::uint8_t peer6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint16_t our_port = 443;
    const std::uint16_t peer_port = 40000;

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // Establish a half-open flow from the peer so the ICMP can be attributed.
    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv6Tcp(
        peer6, us6, peer_port, our_port, 1000, 0, test::TcpFlags::Syn, {});
    Inject(io, pool, syn);
    TCPIP2_EXPECT_TRUE(WaitForHalfOpen(shard, 1));

    // PacketTooBig quoting our original packet (us6 -> peer6, ports 443->40000).
    const std::vector<std::uint8_t> pkt = BuildIpv6IcmpPacketTooBig(
        icmp6_src, icmp6_dst, 1280, us6, peer6, our_port, peer_port);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const PmtuLookupResult result = shard.LookupPmtu(peer6, 6, NowMs());
    TCPIP2_EXPECT_TRUE(result.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1280}, result.pmtu);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// Test 2b: ICMPv6 for a peer with no matching flow must NOT update PMTU
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv6PacketTooBigIgnoredWithoutFlow) {
    const std::uint8_t icmp6_src[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t icmp6_dst[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::uint8_t us6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::uint8_t peer6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::vector<std::uint8_t> pkt = BuildIpv6IcmpPacketTooBig(
        icmp6_src, icmp6_dst, 1280, us6, peer6, 443, 40000);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    const PmtuLookupResult result = shard.LookupPmtu(peer6, 6, NowMs());
    TCPIP2_EXPECT_FALSE(result.found);

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
        0x0a000001u, 0x0a000002u, 1200, 0x0a000002u, 0x01020304u, 443, 40000, 4);

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

// ---------------------------------------------------------------------------
// Test 5: ICMPv4 with a corrupted checksum must NOT update PMTU
// ---------------------------------------------------------------------------

TCPIP2_TEST(ShardIcmpv4BadChecksumDoesNotUpdatePmtu) {
    const std::uint32_t us = 0x0a000002u;
    const std::uint32_t peer = 0x01020304u;
    const std::uint16_t our_port = 443;
    const std::uint16_t peer_port = 40000;

    NullPacketIo io(1);
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    TCPIP2_EXPECT_TRUE(shard.Start());

    // Establish the flow first so attribution would succeed; the corrupted
    // checksum must then be the sole reason the PMTU stays untouched.
    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        peer, us, peer_port, our_port, 1000, 0, test::TcpFlags::Syn, {});
    Inject(io, pool, syn);
    TCPIP2_EXPECT_TRUE(WaitForHalfOpen(shard, 1));

    // Build a valid ICMPv4 FragNeeded (checksum computed correctly), then
    // corrupt the ICMP checksum field (ICMP header starts at IP offset 20,
    // checksum occupies ICMP bytes [2..3] → packet bytes [22..23]).
    std::vector<std::uint8_t> pkt = BuildIpv4IcmpFragNeeded(
        0x0a000001u, us, 1200, us, peer, our_port, peer_port);
    pkt[22] = static_cast<std::uint8_t>(pkt[22] ^ 0xFFu);
    Inject(io, pool, pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard.Stop();

    // PMTU must NOT have been updated for the quoted destination.
    const std::uint8_t dst_bytes[4] = {1, 2, 3, 4};
    const PmtuLookupResult result = shard.LookupPmtu(dst_bytes, 4, NowMs());
    TCPIP2_EXPECT_FALSE(result.found);

    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
