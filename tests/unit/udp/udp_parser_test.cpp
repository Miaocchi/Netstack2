/**
 * @file udp_parser_test.cpp
 * @brief Tests for UDP datagram parsing and checksum validation.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstring>
#include <vector>

#include <tcpip2/address.h>
#include <udp/input.h>
#include <udp/udp.h>
#include <ip/checksum.h>
#include <ip/ipv4.h>
#include <ip/ipv6.h>

#include "Test.h"

using namespace tcpip2;

namespace {

// ---------------------------------------------------------------------------
// Inline helpers for building raw packets (no PacketBuilder dependency).
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

/// Build a minimal IPv4+UDP packet.
/// @param src_ip  source IPv4 as uint32 (host byte order, e.g. 0x0a000001)
/// @param dst_ip  destination IPv4
/// @param src_port  UDP source port
/// @param dst_port  UDP destination port
/// @param payload   UDP payload bytes
/// @param udp_checksum  value to place in the UDP checksum field (0 = not computed)
/// @param compute_correct_checksum  if true, compute and set a correct UDP checksum
/// @param bad_checksum  if true, set a deliberately wrong non-zero checksum
std::vector<std::uint8_t> BuildIpv4Udp(
    std::uint32_t src_ip, std::uint32_t dst_ip,
    std::uint16_t src_port, std::uint16_t dst_port,
    const std::vector<std::uint8_t>& payload,
    bool compute_correct_checksum = true,
    bool bad_checksum = false) {

    const std::size_t udp_len = 8 + payload.size();
    const std::size_t total_len = 20 + udp_len;

    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);

    // IPv4 header
    pkt.push_back(0x45);  // version 4, IHL 5
    pkt.push_back(0x00);  // DSCP/ECN
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);       // identification
    AppendU16(pkt, 0x0000);  // flags + frag offset
    pkt.push_back(64);       // TTL
    pkt.push_back(0x11);     // protocol = UDP (17)
    AppendU16(pkt, 0);       // checksum placeholder
    AppendU32(pkt, src_ip);
    AppendU32(pkt, dst_ip);

    // UDP header
    AppendU16(pkt, src_port);
    AppendU16(pkt, dst_port);
    AppendU16(pkt, static_cast<std::uint16_t>(udp_len));
    AppendU16(pkt, 0);  // checksum placeholder

    // UDP payload
    for (auto b : payload) pkt.push_back(b);

    // Compute IPv4 header checksum
    pkt[10] = 0;
    pkt[11] = 0;
    const std::uint16_t ip_cksum = InlineChecksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_cksum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_cksum & 0xFFu);

    // Compute UDP checksum if requested
    if (compute_correct_checksum || bad_checksum) {
        // Build the pseudo-header seed
        std::uint32_t seed = 0;
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
        seed = Ipv4PseudoHeaderSeed(src_bytes, dst_bytes, 17,
                                     static_cast<std::uint16_t>(udp_len));
        std::uint16_t udp_cksum = InlineChecksum(pkt.data() + 20, udp_len, seed);
        if (udp_cksum == 0) udp_cksum = 0xFFFF;
        if (bad_checksum) udp_cksum = udp_cksum ^ 0x00FF;  // corrupt it
        pkt[26] = static_cast<std::uint8_t>((udp_cksum >> 8) & 0xFFu);
        pkt[27] = static_cast<std::uint8_t>(udp_cksum & 0xFFu);
    }

    return pkt;
}

/// Build a minimal IPv6+UDP packet.
std::vector<std::uint8_t> BuildIpv6Udp(
    const std::uint8_t src_ip[16], const std::uint8_t dst_ip[16],
    std::uint16_t src_port, std::uint16_t dst_port,
    const std::vector<std::uint8_t>& payload,
    bool compute_correct_checksum = true,
    bool bad_checksum = false) {

    const std::size_t udp_len = 8 + payload.size();
    const std::size_t payload_len = udp_len;  // IPv6 payload length = UDP length

    std::vector<std::uint8_t> pkt;
    pkt.reserve(40 + udp_len);

    // IPv6 fixed header
    pkt.push_back(0x60);  // version 6
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x00);  // flow label
    AppendU16(pkt, static_cast<std::uint16_t>(payload_len));
    pkt.push_back(17);   // next header = UDP
    pkt.push_back(64);   // hop limit
    for (int i = 0; i < 16; ++i) pkt.push_back(src_ip[i]);
    for (int i = 0; i < 16; ++i) pkt.push_back(dst_ip[i]);

    // UDP header
    AppendU16(pkt, src_port);
    AppendU16(pkt, dst_port);
    AppendU16(pkt, static_cast<std::uint16_t>(udp_len));
    AppendU16(pkt, 0);  // checksum placeholder

    // UDP payload
    for (auto b : payload) pkt.push_back(b);

    // Compute UDP checksum (mandatory for IPv6)
    if (compute_correct_checksum || bad_checksum) {
        std::uint32_t seed = Ipv6PseudoHeaderSeed(src_ip, dst_ip, 17,
                                     static_cast<std::uint32_t>(udp_len));
        std::uint16_t udp_cksum = InlineChecksum(pkt.data() + 40, udp_len, seed);
        if (udp_cksum == 0) udp_cksum = 0xFFFF;
        if (bad_checksum) udp_cksum = udp_cksum ^ 0x00FF;
        pkt[46] = static_cast<std::uint8_t>((udp_cksum >> 8) & 0xFFu);
        pkt[47] = static_cast<std::uint8_t>(udp_cksum & 0xFFu);
    }

    return pkt;
}

/// Build an IPv4 packet with a specified protocol (for NotUdp testing).
std::vector<std::uint8_t> BuildIpv4WithProtocol(
    std::uint32_t src_ip, std::uint32_t dst_ip, std::uint8_t protocol) {

    const std::size_t total_len = 20 + 4;  // minimal payload
    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    AppendU16(pkt, static_cast<std::uint16_t>(total_len));
    AppendU16(pkt, 0);
    AppendU16(pkt, 0x0000);
    pkt.push_back(64);
    pkt.push_back(protocol);
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
// Test 1: Valid IPv4 UDP parse
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpIpv4ValidParse) {
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<std::uint8_t> pkt = BuildIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53, payload);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::None),
                     static_cast<int>(result.error));
    TCPIP2_EXPECT_EQ(std::uint16_t{12345}, result.datagram.header.src_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{53}, result.datagram.header.dst_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{12}, result.datagram.header.length);  // 8 + 4
}

// ---------------------------------------------------------------------------
// Test 2: Valid IPv6 UDP parse
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpIpv6ValidParse) {
    const std::uint8_t src_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t dst_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    const std::vector<std::uint8_t> pkt = BuildIpv6Udp(
        src_ip, dst_ip, 5353, 53, payload);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::None),
                     static_cast<int>(result.error));
    TCPIP2_EXPECT_EQ(std::uint16_t{5353}, result.datagram.header.src_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{53}, result.datagram.header.dst_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{11}, result.datagram.header.length);  // 8 + 3
}

// ---------------------------------------------------------------------------
// Test 3: UDP too short (7 bytes)
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpTooShort) {
    const IpAddress src = IpAddress::Ipv4(10, 0, 0, 1);
    const IpAddress dst = IpAddress::Ipv4(10, 0, 0, 2);
    const std::uint8_t data[7] = {0, 0, 0, 0, 0, 0, 0};
    const UdpParseResult result = ParseUdpDatagram(src, dst, data, 7, false);
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpParseError::TooShort),
                     static_cast<int>(result.error));
}

// ---------------------------------------------------------------------------
// Test 4: UDP length mismatch (header says 100 but only 20 bytes available)
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpLengthMismatch) {
    const IpAddress src = IpAddress::Ipv4(10, 0, 0, 1);
    const IpAddress dst = IpAddress::Ipv4(10, 0, 0, 2);
    // 20 bytes of UDP data, but length field says 100
    std::uint8_t data[20] = {};
    data[0] = 0; data[1] = 0;       // src port
    data[2] = 0; data[3] = 53;      // dst port
    data[4] = 0; data[5] = 100;     // length = 100
    data[6] = 0; data[7] = 0;       // checksum = 0
    const UdpParseResult result = ParseUdpDatagram(src, dst, data, 20, false);
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpParseError::LengthMismatch),
                     static_cast<int>(result.error));
}

// ---------------------------------------------------------------------------
// Test 5: IPv4 zero checksum accepted
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpIpv4ZeroChecksumAccepted) {
    const std::vector<std::uint8_t> payload = {0x01, 0x02};
    // Build with no checksum (compute_correct_checksum=false, bad_checksum=false)
    const std::vector<std::uint8_t> pkt = BuildIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53, payload, false, false);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::None),
                     static_cast<int>(result.error));
}

// ---------------------------------------------------------------------------
// Test 6: IPv6 zero checksum rejected
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpIpv6ZeroChecksumRejected) {
    const std::uint8_t src_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t dst_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::vector<std::uint8_t> payload = {0x01, 0x02};
    // Build with no checksum (zero checksum)
    const std::vector<std::uint8_t> pkt = BuildIpv6Udp(
        src_ip, dst_ip, 5353, 53, payload, false, false);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::BadChecksum),
                     static_cast<int>(result.error));
}

// ---------------------------------------------------------------------------
// Test 7: IPv4 bad checksum rejected
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpIpv4BadChecksumRejected) {
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    const std::vector<std::uint8_t> pkt = BuildIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53, payload, true, true);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::BadChecksum),
                     static_cast<int>(result.error));
}

// ---------------------------------------------------------------------------
// Test 8: IPv6 bad checksum rejected
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpIpv6BadChecksumRejected) {
    const std::uint8_t src_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t dst_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    const std::vector<std::uint8_t> pkt = BuildIpv6Udp(
        src_ip, dst_ip, 5353, 53, payload, true, true);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::BadChecksum),
                     static_cast<int>(result.error));
}

// ---------------------------------------------------------------------------
// Test 9: Payload correctly extracted
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpPayloadExtracted) {
    const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    const std::vector<std::uint8_t> pkt = BuildIpv4Udp(
        0x0a000001u, 0x0a000002u, 12345, 53, payload);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::None),
                     static_cast<int>(result.error));
    TCPIP2_EXPECT_TRUE(result.datagram.payload != nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{5}, result.datagram.payload_length);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xAA}, result.datagram.payload[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xEE}, result.datagram.payload[4]);
}

// ---------------------------------------------------------------------------
// Test 10: ParseIpUdpPacket on non-UDP packet (protocol=6 TCP → NotUdp)
// ---------------------------------------------------------------------------

TCPIP2_TEST(UdpNotUdpProtocol) {
    // Build an IPv4 packet with protocol=6 (TCP)
    const std::vector<std::uint8_t> pkt = BuildIpv4WithProtocol(
        0x0a000001u, 0x0a000002u, 6);

    const UdpInputResult result = ParseIpUdpPacket(pkt.data(), pkt.size());
    TCPIP2_EXPECT_EQ(static_cast<int>(UdpInputResult::Error::NotUdp),
                     static_cast<int>(result.error));
}

TCPIP2_TEST_MAIN();
