#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/checksum.h>
#include <ip/ipv4.h>

using namespace tcpip2;

namespace {

/// Build a minimal IPv4 header (no payload) with a valid checksum.
/// Parameters allow overriding IHL, total_length, protocol, and TTL.
static std::vector<std::uint8_t> BuildIpv4Header(std::uint8_t ihl = 5,
                                                   std::uint16_t total_len = 20,
                                                   std::uint8_t protocol = 6,
                                                   std::uint8_t ttl = 64) {
    std::vector<std::uint8_t> hdr(static_cast<std::size_t>(ihl) * 4, 0);
    hdr[0] = static_cast<std::uint8_t>(0x40 | (ihl & 0x0F)); // version 4 + IHL
    hdr[1] = 0x00;                                            // DSCP/ECN
    hdr[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xFF);
    hdr[3] = static_cast<std::uint8_t>(total_len & 0xFF);
    hdr[4] = 0x00; hdr[5] = 0x01; // identification = 1
    hdr[6] = 0x00; hdr[7] = 0x00; // flags/frag = 0
    hdr[8] = ttl;
    hdr[9] = protocol;
    // checksum at [10..11] left as 0 for now
    hdr[12] = 0x0A; hdr[13] = 0x00; hdr[14] = 0x00; hdr[15] = 0x01; // src 10.0.0.1
    hdr[16] = 0x0A; hdr[17] = 0x00; hdr[18] = 0x00; hdr[19] = 0x02; // dst 10.0.0.2

    // Compute and place checksum
    std::uint16_t cs = InternetChecksum(hdr.data(), hdr.size(), 0);
    hdr[10] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    hdr[11] = static_cast<std::uint8_t>(cs & 0xFF);
    return hdr;
}

} // namespace

TCPIP2_TEST(ValidMinimalHeader) {
    auto hdr = BuildIpv4Header(5, 20, 6, 64);
    auto result = ParseIpv4(hdr.data(), hdr.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, result.header.version);
    TCPIP2_EXPECT_EQ(std::uint8_t{5}, result.header.ihl);
    TCPIP2_EXPECT_EQ(std::uint8_t{64}, result.header.ttl);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.header.protocol);
    TCPIP2_EXPECT_EQ(std::uint16_t{20}, result.header.total_length);
    TCPIP2_EXPECT_EQ(std::uint16_t{1}, result.header.identification);
    TCPIP2_EXPECT_EQ(std::size_t{20}, result.header.header_length);
    TCPIP2_EXPECT_EQ(std::size_t{20}, result.header.payload_offset);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.header.payload_length);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_TRUE(result.payload == hdr.data() + 20);

    // Verify source/destination IPs
    TCPIP2_EXPECT_EQ(std::uint8_t{0x0A}, result.header.src_ip[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, result.header.src_ip[1]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, result.header.src_ip[2]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, result.header.src_ip[3]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x0A}, result.header.dst_ip[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, result.header.dst_ip[1]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x00}, result.header.dst_ip[2]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, result.header.dst_ip[3]);
}

TCPIP2_TEST(ValidWithPayload) {
    auto hdr = BuildIpv4Header(5, 24, 6, 64);
    // Append 4 bytes of payload
    hdr.push_back(0xDE);
    hdr.push_back(0xAD);
    hdr.push_back(0xBE);
    hdr.push_back(0xEF);

    auto result = ParseIpv4(hdr.data(), hdr.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::size_t{4}, result.header.payload_length);
    TCPIP2_EXPECT_EQ(std::size_t{20}, result.header.payload_offset);
    TCPIP2_EXPECT_TRUE(result.payload == hdr.data() + 20);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
}

TCPIP2_TEST(ValidWithOptions) {
    // IHL=6 → 24-byte header with 4 bytes of options (padded to 0)
    auto hdr = BuildIpv4Header(6, 24, 6, 64);
    // Options bytes [20..23] are already zero-padded by BuildIpv4Header

    auto result = ParseIpv4(hdr.data(), hdr.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.header.ihl);
    TCPIP2_EXPECT_EQ(std::size_t{24}, result.header.header_length);
    TCPIP2_EXPECT_EQ(std::size_t{24}, result.header.payload_offset);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.header.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == hdr.data() + 24);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
}

TCPIP2_TEST(TooShort) {
    // Only 19 bytes — fewer than the minimum 20
    std::vector<std::uint8_t> hdr(19, 0);
    hdr[0] = 0x45; // version 4, IHL 5

    auto result = ParseIpv4(hdr.data(), hdr.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::TooShort);
}

TCPIP2_TEST(BadVersion) {
    auto hdr = BuildIpv4Header(5, 20, 6, 64);
    // Change version to 6: byte[0] = 0x65 (version 6, IHL 5)
    hdr[0] = 0x65;
    // Checksum is now invalid but that doesn't matter — BadVersion fires first

    auto result = ParseIpv4(hdr.data(), hdr.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::BadVersion);
}

TCPIP2_TEST(BadIhl) {
    auto hdr = BuildIpv4Header(5, 20, 6, 64);
    // IHL=4 (< 5), version stays 4: byte[0] = 0x44
    hdr[0] = 0x44;

    auto result = ParseIpv4(hdr.data(), hdr.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::BadIhl);
}

TCPIP2_TEST(BadChecksum) {
    auto hdr = BuildIpv4Header(5, 20, 6, 64);
    // Flip a bit in the TTL field to corrupt the checksum
    hdr[8] = static_cast<std::uint8_t>(hdr[8] ^ 0x01);

    auto result = ParseIpv4(hdr.data(), hdr.size());
    // Parsing succeeds (the error only covers structural problems)
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::None);
    TCPIP2_EXPECT_FALSE(result.checksum_ok);
}

TCPIP2_TEST(TruncatedByTotalLength) {
    auto hdr = BuildIpv4Header(5, 40, 6, 64);
    // Buffer is only 20 bytes but total_length says 40
    hdr.resize(20);

    auto result = ParseIpv4(hdr.data(), hdr.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::TruncatedTotal);
}

TCPIP2_TEST(TruncatedHeader) {
    // IHL=6 → header should be 24 bytes, but provide only 22
    std::vector<std::uint8_t> hdr(22, 0);
    hdr[0] = 0x46; // version 4, IHL 6
    hdr[1] = 0x00;
    hdr[2] = 0x00; hdr[3] = 0x18; // total_length = 24
    hdr[4] = 0x00; hdr[5] = 0x01; // identification
    hdr[6] = 0x00; hdr[7] = 0x00; // flags/frag
    hdr[8] = 0x40; // TTL
    hdr[9] = 0x06; // protocol = TCP
    hdr[10] = 0x00; hdr[11] = 0x00; // checksum (placeholder)
    hdr[12] = 0x0A; hdr[13] = 0x00; hdr[14] = 0x00; hdr[15] = 0x01;
    hdr[16] = 0x0A; hdr[17] = 0x00; hdr[18] = 0x00; hdr[19] = 0x02;
    // Bytes 20-21 are option bytes; header needs 24 but only 22 available

    auto result = ParseIpv4(hdr.data(), hdr.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::TruncatedHeader);
}

TCPIP2_TEST(FragmentOffset) {
    // Build a header with MF flag set and fragment_offset=185
    auto hdr = BuildIpv4Header(5, 20, 6, 64);

    // Flags (3 bits) + fragment offset (13 bits) in bytes [6..7]
    // MF=1 → flags bit 1 (0b010) → flags<<13 = 0x2000
    // fragment_offset=185 → 0x00B9
    // Combined: 0x2000 | 0x00B9 = 0x20B9
    std::uint16_t flags_frag = static_cast<std::uint16_t>(0x2000U | 185U);
    hdr[6] = static_cast<std::uint8_t>((flags_frag >> 8) & 0xFF);
    hdr[7] = static_cast<std::uint8_t>(flags_frag & 0xFF);

    // Recompute checksum since bytes changed
    hdr[10] = 0x00;
    hdr[11] = 0x00;
    std::uint16_t cs = InternetChecksum(hdr.data(), hdr.size(), 0);
    hdr[10] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    hdr[11] = static_cast<std::uint8_t>(cs & 0xFF);

    auto result = ParseIpv4(hdr.data(), hdr.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, result.header.flags); // MF=1 → flags=0b001=1
    TCPIP2_EXPECT_EQ(std::uint16_t{185}, result.header.fragment_offset);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
}

TCPIP2_TEST_MAIN();
