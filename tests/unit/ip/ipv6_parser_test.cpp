#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/ipv6.h>

using namespace tcpip2;

namespace {

/// Build an IPv6 packet with a fixed 40-byte header, optional extension headers,
/// and a payload of the given length.
///
/// @param first_nh       value for the fixed header's next_header field (byte 6)
/// @param after_fixed    raw bytes placed immediately after the 40-byte fixed header
///                        (extension headers, or payload if no ext headers)
/// @param payload_len    number of zero-padded payload bytes to append after `after_fixed`
static std::vector<std::uint8_t> BuildIpv6(std::uint8_t first_nh,
                                             const std::vector<std::uint8_t>& after_fixed,
                                             std::size_t payload_len) {
    std::size_t total = 40 + after_fixed.size() + payload_len;
    std::vector<std::uint8_t> pkt(total, 0);

    // Fixed header
    pkt[0] = 0x60; // version 6, traffic class 0, flow label 0
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    std::uint16_t plen = static_cast<std::uint16_t>(after_fixed.size() + payload_len);
    pkt[4] = static_cast<std::uint8_t>((plen >> 8) & 0xFF);
    pkt[5] = static_cast<std::uint8_t>(plen & 0xFF);
    pkt[6] = first_nh;
    pkt[7] = 64; // hop limit
    // src = ::1  (bytes 8–23, last byte = 1)
    pkt[23] = 0x01;
    // dst = ::2  (bytes 24–39, last byte = 2)
    pkt[39] = 0x02;

    // Copy extension headers / payload after the fixed header
    if (!after_fixed.empty()) {
        std::memcpy(pkt.data() + 40, after_fixed.data(), after_fixed.size());
    }

    return pkt;
}

/// Build a single generic extension header (non-Fragment).
/// Size must be a multiple of 8 and >= 8.
///
/// @param next_nh   next header value to place in byte[0] of this ext header
/// @param size_bytes total size of this extension header in bytes
static std::vector<std::uint8_t> BuildExtHeader(std::uint8_t next_nh,
                                                  std::size_t size_bytes) {
    std::vector<std::uint8_t> eh(size_bytes, 0);
    eh[0] = next_nh;
    eh[1] = static_cast<std::uint8_t>((size_bytes / 8) - 1); // hdr_ext_len
    return eh;
}

/// Build a Fragment extension header (always 8 bytes).
static std::vector<std::uint8_t> BuildFragmentHeader(std::uint8_t next_nh) {
    std::vector<std::uint8_t> fh(8, 0);
    fh[0] = next_nh;
    // fh[1] = reserved, fh[2..3] = fragment offset (0), fh[4..7] = identification (0)
    return fh;
}

} // namespace

TCPIP2_TEST(ValidMinimalHeader) {
    // 40-byte fixed header, no extension headers, next_header=TCP(6)
    auto pkt = BuildIpv6(6, {}, 0);

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.header.version);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.header.next_header);
    TCPIP2_EXPECT_EQ(std::uint8_t{64}, result.header.hop_limit);
    TCPIP2_EXPECT_EQ(std::size_t{40}, result.header.header_length);
    TCPIP2_EXPECT_EQ(std::size_t{40}, result.payload_offset);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.ext_header_count);
    TCPIP2_EXPECT_TRUE(result.payload == pkt.data() + 40);

    // Verify source = ::1 and destination = ::2
    TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, result.header.src_ip[15]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, result.header.dst_ip[15]);
}

TCPIP2_TEST(TooShort) {
    // Only 39 bytes — fewer than the minimum 40
    std::vector<std::uint8_t> pkt(39, 0);
    pkt[0] = 0x60; // version 6

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::TooShort);
}

TCPIP2_TEST(BadVersion) {
    auto pkt = BuildIpv6(6, {}, 0);
    // Change version to 4: byte[0] = 0x40 (version 4, traffic class 0, flow label 0)
    pkt[0] = 0x40;

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::BadVersion);
}

TCPIP2_TEST(ValidWithPayload) {
    // 40-byte header + 20 bytes payload
    auto pkt = BuildIpv6(6, {}, 20);

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{20}, result.payload_length);
    TCPIP2_EXPECT_EQ(std::size_t{40}, result.payload_offset);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_TRUE(result.payload == pkt.data() + 40);
}

TCPIP2_TEST(TruncatedPayload) {
    // payload_length says 60 but buffer only has 40+10=50 bytes
    std::vector<std::uint8_t> pkt(50, 0);
    pkt[0] = 0x60; // version 6
    pkt[4] = 0x00;
    pkt[5] = 0x3C; // payload_length = 60
    pkt[6] = 6;    // next_header = TCP
    pkt[7] = 64;   // hop limit

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::TruncatedPayload);
}

TCPIP2_TEST(HopByHopExtHeader) {
    // Fixed header (nh=0) → HopByHop (8 bytes, next_nh=6/TCP) → no payload
    std::vector<std::uint8_t> exts;
    std::vector<std::uint8_t> eh = BuildExtHeader(6, 8); // next_nh=TCP, 8 bytes
    exts.insert(exts.end(), eh.begin(), eh.end());

    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, exts, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{1}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{48}, result.payload_offset);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == pkt.data() + 48);
}

TCPIP2_TEST(FragmentExtHeader) {
    // Fixed header (nh=44) → Fragment (8 bytes, next_nh=17/UDP) → no payload
    std::vector<std::uint8_t> exts;
    std::vector<std::uint8_t> fh = BuildFragmentHeader(17); // next_nh=UDP
    exts.insert(exts.end(), fh.begin(), fh.end());

    auto pkt = BuildIpv6(Ipv6ExtHeaderType::Fragment, exts, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{1}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{17}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{48}, result.payload_offset);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == pkt.data() + 48);
}

TCPIP2_TEST(MultipleExtHeaders) {
    // Fixed header (nh=0) → HopByHop (8 bytes, nh=43) → Routing (16 bytes, nh=6/TCP)
    std::vector<std::uint8_t> exts;
    std::vector<std::uint8_t> eh1 = BuildExtHeader(Ipv6ExtHeaderType::Routing, 8); // 8 bytes
    std::vector<std::uint8_t> eh2 = BuildExtHeader(6, 16); // 16 bytes, next_nh=TCP
    exts.insert(exts.end(), eh1.begin(), eh1.end());
    exts.insert(exts.end(), eh2.begin(), eh2.end());

    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, exts, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{2}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{64}, result.payload_offset); // 40 + 8 + 16
    TCPIP2_EXPECT_TRUE(result.payload == pkt.data() + 64);
}

TCPIP2_TEST(ExtHeaderLoop) {
    // Fixed header (nh=0) → HopByHop (nh=0, another HopByHop) → HopByHop (nh=6/TCP)
    // The second HopByHop (type 0) was already visited → loop detected.
    std::vector<std::uint8_t> exts;
    std::vector<std::uint8_t> eh1(8, 0); // first HopByHop, next_nh=0
    eh1[1] = 0;                          // hdr_ext_len=0 → 8 bytes
    std::vector<std::uint8_t> eh2(8, 0); // second HopByHop, next_nh=6
    eh2[0] = 6;
    eh2[1] = 0;                          // hdr_ext_len=0 → 8 bytes
    exts.insert(exts.end(), eh1.begin(), eh1.end());
    exts.insert(exts.end(), eh2.begin(), eh2.end());

    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, exts, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::ExtHeaderLoop);
}

TCPIP2_TEST(ExtHeaderTruncated) {
    // Extension header claims 16 bytes but buffer only has 8 bytes after fixed header.
    // Build a Routing ext header with hdr_ext_len=1 (→ 16 bytes), but only provide
    // 8 bytes in the buffer.
    std::vector<std::uint8_t> pkt(48, 0); // 40 fixed + 8 ext bytes
    pkt[0] = 0x60;                        // version 6
    std::uint16_t plen = 8;
    pkt[4] = static_cast<std::uint8_t>((plen >> 8) & 0xFF);
    pkt[5] = static_cast<std::uint8_t>(plen & 0xFF);
    pkt[6] = Ipv6ExtHeaderType::Routing; // first ext = Routing
    pkt[7] = 64;                         // hop limit

    // Extension header at offset 40:
    // byte[0] = next_nh (TCP=6, terminal)
    // byte[1] = hdr_ext_len = 1 → (1+1)*8 = 16 bytes needed, only 8 available
    pkt[40] = 6;
    pkt[41] = 1;

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::TruncatedExtHeader);
}

TCPIP2_TEST(ExtHeaderTooLong) {
    // A single extension header whose size exceeds kIpv6MaxExtHeaderBytes (1024).
    // hdr_ext_len = 255 → (255 + 1) * 8 = 2048 bytes, which exceeds the 1024-byte limit.
    // The TooLong check fires before the bounds check, so we only need enough
    // buffer to read the 2-byte ext header prefix (offset 40 + 2 = 42 bytes).
    std::vector<std::uint8_t> pkt(42, 0);
    pkt[0] = 0x60; // version 6
    std::uint16_t plen = 2; // payload_length claims 2 bytes (the ext header prefix)
    pkt[4] = static_cast<std::uint8_t>((plen >> 8) & 0xFF);
    pkt[5] = static_cast<std::uint8_t>(plen & 0xFF);
    pkt[6] = Ipv6ExtHeaderType::HopByHop; // first ext = HopByHop
    pkt[7] = 64;                          // hop limit

    // Extension header at offset 40:
    // byte[0] = next_nh (TCP=6, terminal)
    // byte[1] = hdr_ext_len = 255 → (255 + 1) * 8 = 2048 bytes
    pkt[40] = 6;
    pkt[41] = 255;

    auto result = ParseIpv6(pkt.data(), pkt.size());
    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::ExtHeaderTooLong);
}

TCPIP2_TEST_MAIN();
