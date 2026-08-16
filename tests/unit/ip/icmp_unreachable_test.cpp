/**
 * @file icmp_unreachable_test.cpp
 * @brief Unit tests for the ICMP Destination-Unreachable builder (R7 step 9).
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "Test.h"
#include <ip/checksum.h>
#include <ip/icmp_unreachable.h>
#include <ip/icmpv4.h>
#include <ip/icmpv6.h>
#include <ip/ipv4.h>
#include <ip/ipv6.h>

using namespace tcpip2;

namespace {

/// Build a minimal IPv4 UDP original packet: src 10.0.0.1:12345 -> 10.0.0.2:53.
void FillIpv4Original(std::uint8_t* buf, std::size_t cap, std::size_t& len) {
    std::memset(buf, 0, cap);
    buf[0] = 0x45;
    buf[9] = 17;
    buf[12] = 10; buf[13] = 0; buf[14] = 0; buf[15] = 1;   // 10.0.0.1
    buf[16] = 10; buf[17] = 0; buf[18] = 0; buf[19] = 2;   // 10.0.0.2
    buf[20] = 0x30; buf[21] = 0x39;  // src port 12345
    buf[22] = 0;    buf[23] = 53;    // dst port 53
    len = 28;
}

void FillIpv6Original(std::uint8_t* buf, std::size_t cap, std::size_t& len) {
    std::memset(buf, 0, cap);
    buf[0] = 0x60;
    buf[6] = 17;
    // src 2001:db8::1
    buf[8] = 0x20; buf[9] = 0x01; buf[10] = 0x0d; buf[11] = 0xb8;
    buf[23] = 0x01;
    // dst 2001:db8::2
    buf[24] = 0x20; buf[25] = 0x01; buf[26] = 0x0d; buf[27] = 0xb8;
    buf[39] = 0x02;
    buf[40] = 0x30; buf[41] = 0x39;  // src port 12345
    buf[42] = 0;    buf[43] = 53;    // dst port 53
    len = 48;
}

} // namespace

TCPIP2_TEST(Icmpv4UnreachablePortFormat) {
    std::uint8_t original[28];
    std::size_t original_len = 0;
    FillIpv4Original(original, sizeof(original), original_len);

    std::uint8_t out[128];
    const IcmpUnreachableResult r = BuildIcmpv4Unreachable(
        original, original_len, Icmpv4DestUnreachableCode::Port, 0,
        out, sizeof(out));
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::None, r.error);
    // 20 (IP) + 8 (ICMP) + 28 (quoted header+8) = 56.
    TCPIP2_EXPECT_EQ(std::size_t{56}, r.packet_length);

    // Outer IPv4 header: protocol ICMP, src/dst swapped.
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, out[0] >> 4);
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, out[9]);
    TCPIP2_EXPECT_EQ(std::uint8_t{10}, out[12]);
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, out[15]);   // src = 10.0.0.2
    TCPIP2_EXPECT_EQ(std::uint8_t{10}, out[16]);
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, out[19]);   // dst = 10.0.0.1

    // ICMP type/code = Destination Unreachable / Port.
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, out[20]);
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, out[21]);

    // Both checksums valid.
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, InternetChecksum(out, 20));
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, InternetChecksum(out + 20, r.packet_length - 20));

    // Quoted payload = original IP header (20) + first 8 transport bytes.
    TCPIP2_EXPECT_EQ(std::uint8_t{0x45}, out[28]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x30}, out[48]);  // quoted src port high
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, out[50]);     // quoted dst port high
    TCPIP2_EXPECT_EQ(std::uint8_t{53}, out[51]);    // quoted dst port low
}

TCPIP2_TEST(Icmpv4UnreachableRejectsBadInput) {
    std::uint8_t out[128];
    // Null original.
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::InvalidOriginal,
                     BuildIcmpv4Unreachable(nullptr, 28, 3, 0, out, sizeof(out)).error);
    // Too short (< 20).
    std::uint8_t short_orig[10] = {};
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::InvalidOriginal,
                     BuildIcmpv4Unreachable(short_orig, sizeof(short_orig), 3, 0,
                                            out, sizeof(out)).error);
    // Wrong version.
    std::uint8_t orig[28] = {};
    orig[0] = 0x60;
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::InvalidOriginal,
                     BuildIcmpv4Unreachable(orig, sizeof(orig), 3, 0, out, sizeof(out)).error);
    // Buffer too small.
    std::uint8_t original[28];
    std::size_t len = 0;
    FillIpv4Original(original, sizeof(original), len);
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::BufferTooSmall,
                     BuildIcmpv4Unreachable(original, len, 3, 0, out, 40).error);
}

TCPIP2_TEST(Icmpv6UnreachablePortFormat) {
    std::uint8_t original[48];
    std::size_t original_len = 0;
    FillIpv6Original(original, sizeof(original), original_len);

    std::uint8_t out[160];
    const IcmpUnreachableResult r = BuildIcmpv6Unreachable(
        original, original_len, Icmpv6DestUnreachableCode::PortUnreachable,
        out, sizeof(out));
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::None, r.error);
    // 40 (IP) + 8 (ICMP) + 48 (quoted header+8) = 96.
    TCPIP2_EXPECT_EQ(std::size_t{96}, r.packet_length);

    // IPv6 header: next header ICMPv6, src/dst swapped.
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, out[0] >> 4);
    TCPIP2_EXPECT_EQ(std::uint8_t{58}, out[6]);
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, out[23]);   // src last byte = 2001:db8::2
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, out[39]);   // dst last byte = 2001:db8::1

    // ICMPv6 type/code = Destination Unreachable / Port Unreachable.
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, out[40]);
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, out[41]);

    // ICMPv6 checksum valid under the (swapped) pseudo-header.
    const std::uint32_t seed = Ipv6PseudoHeaderSeed(
        out + 8, out + 24, 58, static_cast<std::uint32_t>(r.packet_length - 40));
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, InternetChecksum(out + 40, r.packet_length - 40, seed));
}

TCPIP2_TEST(Icmpv6PacketTooBigFormat) {
    std::uint8_t original[48];
    std::size_t original_len = 0;
    FillIpv6Original(original, sizeof(original), original_len);

    std::uint8_t out[160];
    const IcmpUnreachableResult r = BuildIcmpv6PacketTooBig(
        original, original_len, 1280, out, sizeof(out));
    TCPIP2_EXPECT_EQ(IcmpUnreachableError::None, r.error);
    TCPIP2_EXPECT_EQ(std::size_t{96}, r.packet_length);

    // Type 2 (Packet Too Big), MTU field = 1280.
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, out[40]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, out[41]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, out[44]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, out[45]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x05}, out[46]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, out[47]);

    // src/dst swapped.
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, out[23]);   // src = 2001:db8::2
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, out[39]);   // dst = 2001:db8::1

    // ICMPv6 checksum valid under the (swapped) pseudo-header.
    const std::uint32_t seed = Ipv6PseudoHeaderSeed(
        out + 8, out + 24, 58, static_cast<std::uint32_t>(r.packet_length - 40));
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, InternetChecksum(out + 40, r.packet_length - 40, seed));
}

TCPIP2_TEST_MAIN()
