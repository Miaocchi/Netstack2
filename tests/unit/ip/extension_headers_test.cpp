#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/ipv6.h>
#include <ip/extension_headers.h>

using namespace tcpip2;

namespace {

/// Build an IPv6 packet with a fixed 40-byte header, optional extension headers,
/// and a payload of the given length.
static std::vector<std::uint8_t> BuildIpv6(std::uint8_t first_nh, const std::vector<std::uint8_t> &after_fixed,
                                           std::size_t payload_len) {
    std::size_t total = 40 + after_fixed.size() + payload_len;
    std::vector<std::uint8_t> pkt(total, 0);

    pkt[0] = 0x60; // version 6, traffic class 0, flow label 0
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    std::uint16_t plen = static_cast<std::uint16_t>(after_fixed.size() + payload_len);
    pkt[4] = static_cast<std::uint8_t>((plen >> 8) & 0xFF);
    pkt[5] = static_cast<std::uint8_t>(plen & 0xFF);
    pkt[6] = first_nh;
    pkt[7] = 64;    // hop limit
    pkt[23] = 0x01; // src = ::1
    pkt[39] = 0x02; // dst = ::2

    if (!after_fixed.empty()) {
        std::memcpy(pkt.data() + 40, after_fixed.data(), after_fixed.size());
    }

    return pkt;
}

/// Build a generic extension header (non-Fragment).
/// Size must be a multiple of 8 and >= 8.
static std::vector<std::uint8_t> BuildExtHeader(std::uint8_t next_nh, std::size_t size_bytes) {
    std::vector<std::uint8_t> eh(size_bytes, 0);
    eh[0] = next_nh;
    eh[1] = static_cast<std::uint8_t>((size_bytes / 8) - 1);
    return eh;
}

/// Build a HopByHop extension header with TLV option content.
/// The header is always a multiple of 8 bytes, minimum 8.
/// @param next_nh    next header value in byte[0]
/// @param options    raw option bytes placed after the 2-byte prefix
static std::vector<std::uint8_t> BuildHopByHopWithOptions(std::uint8_t next_nh,
                                                          const std::vector<std::uint8_t> &options) {
    // Total size must be a multiple of 8 and >= 8.
    std::size_t raw = 2 + options.size();
    std::size_t total = ((raw + 7) / 8) * 8;
    if (total < 8)
        total = 8;
    std::vector<std::uint8_t> eh(total, 0);
    eh[0] = next_nh;
    eh[1] = static_cast<std::uint8_t>((total / 8) - 1);
    if (!options.empty()) {
        std::memcpy(eh.data() + 2, options.data(), options.size());
    }
    return eh;
}

/// Build a single PadN option of the given padding size.
/// PadN: type=1, length=N-2, data=N-2 zero bytes.
/// Total option size = N bytes.
static std::vector<std::uint8_t> BuildPadN(std::size_t total_bytes) {
    if (total_bytes < 2) {
        // Use Pad1 (single byte) for 1 byte of padding.
        return {0};
    }
    std::vector<std::uint8_t> opt(total_bytes, 0);
    opt[0] = 1; // PadN type
    opt[1] = static_cast<std::uint8_t>(total_bytes - 2);
    return opt;
}

/// Build a Jumbo Payload option (type=0xC2, length=4, data=4-byte big-endian length).
static std::vector<std::uint8_t> BuildJumboOption(std::uint32_t jumbo_len) {
    std::vector<std::uint8_t> opt(6, 0);
    opt[0] = Ipv6OptionType::JumboPayload;
    opt[1] = 4;
    opt[2] = static_cast<std::uint8_t>((jumbo_len >> 24) & 0xFF);
    opt[3] = static_cast<std::uint8_t>((jumbo_len >> 16) & 0xFF);
    opt[4] = static_cast<std::uint8_t>((jumbo_len >> 8) & 0xFF);
    opt[5] = static_cast<std::uint8_t>(jumbo_len & 0xFF);
    return opt;
}

/// Build a Router Alert option (type=5, length=2, data=2-byte value).
static std::vector<std::uint8_t> BuildRouterAlert(std::uint16_t value) {
    std::vector<std::uint8_t> opt(4, 0);
    opt[0] = Ipv6OptionType::RouterAlert;
    opt[1] = 2;
    opt[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    opt[3] = static_cast<std::uint8_t>(value & 0xFF);
    return opt;
}

/// Build a Routing extension header with the given routing type and segments left.
/// The body is padded to a multiple of 8 bytes.
static std::vector<std::uint8_t> BuildRoutingHeader(std::uint8_t next_nh, std::uint8_t routing_type,
                                                    std::uint8_t segments_left,
                                                    const std::vector<std::uint8_t> &type_specific) {
    std::size_t raw = 4 + type_specific.size(); // 2 prefix + 2 fixed + type-specific
    std::size_t total = ((raw + 7) / 8) * 8;
    if (total < 8)
        total = 8;
    std::vector<std::uint8_t> eh(total, 0);
    eh[0] = next_nh;
    eh[1] = static_cast<std::uint8_t>((total / 8) - 1);
    eh[2] = routing_type;
    eh[3] = segments_left;
    if (!type_specific.empty()) {
        std::memcpy(eh.data() + 4, type_specific.data(), type_specific.size());
    }
    return eh;
}

} // namespace

// ---------------------------------------------------------------------------
// HopByHop option parsing
// ---------------------------------------------------------------------------

TCPIP2_TEST(HopByHopWithPad1AndPadN) {
    // HopByHop with Pad1 (1 byte) + PadN(4 bytes) + RouterAlert(4 bytes) = 9 bytes
    // Padded to 16 bytes total (2 prefix + 14 option area, but actually
    // 2 + 9 = 11, round up to 16).
    std::vector<std::uint8_t> opts;
    opts.push_back(0);        // Pad1
    auto padn = BuildPadN(4); // PadN, 4 bytes
    opts.insert(opts.end(), padn.begin(), padn.end());
    auto ra = BuildRouterAlert(0); // Router Alert, 4 bytes
    opts.insert(opts.end(), ra.begin(), ra.end());

    auto hbh = BuildHopByHopWithOptions(6, opts); // next_nh = TCP
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, hbh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{1}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_TRUE(result.hopbyhop_option_count >= 3);
}

TCPIP2_TEST(HopByHopWithRouterAlert) {
    // HopByHop with a single Router Alert option (value=1, MLD).
    auto ra = BuildRouterAlert(1);
    auto hbh = BuildHopByHopWithOptions(6, ra);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, hbh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_TRUE(result.hopbyhop_option_count >= 1);

    // Find the RouterAlert option.
    bool found_ra = false;
    for (std::size_t i = 0; i < result.hopbyhop_option_count; ++i) {
        if (result.hopbyhop_options[i].type == Ipv6OptionType::RouterAlert) {
            found_ra = true;
            TCPIP2_EXPECT_EQ(std::uint8_t{2}, result.hopbyhop_options[i].length);
            TCPIP2_EXPECT_TRUE(result.hopbyhop_options[i].data != nullptr);
            std::uint16_t val =
                static_cast<std::uint16_t>((static_cast<std::uint16_t>(result.hopbyhop_options[i].data[0]) << 8) |
                                           result.hopbyhop_options[i].data[1]);
            TCPIP2_EXPECT_EQ(std::uint16_t{1}, val);
        }
    }
    TCPIP2_EXPECT_TRUE(found_ra);
}

TCPIP2_TEST(HopByHopBadOptionTruncated) {
    // Build a HopByHop where an option claims more data than available.
    // Option: type=5, length=10, but only 2 bytes of data follow.
    std::vector<std::uint8_t> opts;
    opts.push_back(5);  // type
    opts.push_back(10); // length = 10, but only 2 bytes of data below
    opts.push_back(0);
    opts.push_back(0);
    // Pad to make the ext header at least 8 bytes.
    while (opts.size() < 6)
        opts.push_back(0);

    auto hbh = BuildHopByHopWithOptions(6, opts);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, hbh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::BadExtHeaderOption);
}

// ---------------------------------------------------------------------------
// Destination Options parsing
// ---------------------------------------------------------------------------

TCPIP2_TEST(DestinationOptionsWithPadN) {
    // DestinationOptions with PadN(6 bytes) + RouterAlert(4 bytes) = 10 bytes
    // Padded to 16 bytes total.
    std::vector<std::uint8_t> opts;
    auto padn = BuildPadN(6);
    opts.insert(opts.end(), padn.begin(), padn.end());
    auto ra = BuildRouterAlert(0);
    opts.insert(opts.end(), ra.begin(), ra.end());

    auto dh = BuildHopByHopWithOptions(6, opts); // same format, next_nh=TCP
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::DestinationOptions, dh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{1}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_TRUE(result.dest_option_count >= 2);

    // Verify no hopbyhop options were populated.
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.hopbyhop_option_count);
}

TCPIP2_TEST(DestinationOptionsBadOption) {
    // DestinationOptions with a truncated option.
    std::vector<std::uint8_t> opts;
    opts.push_back(100); // type
    opts.push_back(20);  // length = 20, but only 0 bytes of data
    while (opts.size() < 6)
        opts.push_back(0);

    auto dh = BuildHopByHopWithOptions(6, opts);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::DestinationOptions, dh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::BadExtHeaderOption);
}

// ---------------------------------------------------------------------------
// Routing header parsing
// ---------------------------------------------------------------------------

TCPIP2_TEST(RoutingHeaderParsed) {
    // Routing header with routing_type=0, segments_left=2, and 4 bytes of type-specific data.
    std::vector<std::uint8_t> type_specific = {0x01, 0x02, 0x03, 0x04};
    auto rh = BuildRoutingHeader(6, 0, 2, type_specific);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::Routing, rh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_TRUE(result.routing_header_present);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, result.routing_header.routing_type);
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, result.routing_header.segments_left);
    TCPIP2_EXPECT_EQ(std::size_t{4}, result.routing_header.type_specific_length);
    TCPIP2_EXPECT_TRUE(result.routing_header.type_specific_data != nullptr);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, result.routing_header.type_specific_data[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x04}, result.routing_header.type_specific_data[3]);
}

TCPIP2_TEST(RoutingHeaderWithPayload) {
    // Routing header followed by 20 bytes of TCP payload.
    std::vector<std::uint8_t> type_specific = {0xAA, 0xBB};
    auto rh = BuildRoutingHeader(6, 3, 1, type_specific);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::Routing, rh, 20);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_TRUE(result.routing_header_present);
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, result.routing_header.routing_type);
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, result.routing_header.segments_left);
    TCPIP2_EXPECT_EQ(std::size_t{20}, result.payload_length);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
}

// ---------------------------------------------------------------------------
// Jumbo Payload (RFC 2675)
// ---------------------------------------------------------------------------

TCPIP2_TEST(JumboPayloadValid) {
    // Build a jumbogram: payload_length=0, HopByHop with JumboPayload option.
    // jumbo_len = 100 bytes after the fixed header (8 bytes HopByHop + 92 bytes payload).
    const std::uint32_t jumbo_len = 100;
    auto jumbo_opt = BuildJumboOption(jumbo_len);
    auto hbh = BuildHopByHopWithOptions(6, jumbo_opt); // next_nh=TCP

    // Total after fixed = hbh.size() + 92 = 100
    std::size_t payload_len = jumbo_len - hbh.size();
    std::size_t total = 40 + hbh.size() + payload_len;
    std::vector<std::uint8_t> pkt(total, 0);

    pkt[0] = 0x60;
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4] = 0x00; // payload_length = 0 (jumbogram)
    pkt[5] = 0x00;
    pkt[6] = Ipv6ExtHeaderType::HopByHop;
    pkt[7] = 64;
    pkt[23] = 0x01;
    pkt[39] = 0x02;
    std::memcpy(pkt.data() + 40, hbh.data(), hbh.size());

    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_TRUE(result.jumbo_payload_present);
    TCPIP2_EXPECT_EQ(jumbo_len, result.jumbo_payload_length);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_EQ(payload_len, result.payload_length);

    // Verify the JumboPayload option was parsed in hopbyhop_options.
    bool found_jumbo = false;
    for (std::size_t i = 0; i < result.hopbyhop_option_count; ++i) {
        if (result.hopbyhop_options[i].type == Ipv6OptionType::JumboPayload) {
            found_jumbo = true;
            TCPIP2_EXPECT_EQ(std::uint8_t{4}, result.hopbyhop_options[i].length);
        }
    }
    TCPIP2_EXPECT_TRUE(found_jumbo);
}

TCPIP2_TEST(JumboPayloadWithNonZeroPayloadLength) {
    // BadJumboPayload: payload_length != 0 but JumboPayload option present.
    auto jumbo_opt = BuildJumboOption(1000);
    auto hbh = BuildHopByHopWithOptions(6, jumbo_opt);

    std::size_t total = 40 + hbh.size();
    std::vector<std::uint8_t> pkt(total, 0);

    pkt[0] = 0x60;
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    // payload_length = hbh.size() (non-zero!) — this should trigger BadJumboPayload
    std::uint16_t plen = static_cast<std::uint16_t>(hbh.size());
    pkt[4] = static_cast<std::uint8_t>((plen >> 8) & 0xFF);
    pkt[5] = static_cast<std::uint8_t>(plen & 0xFF);
    pkt[6] = Ipv6ExtHeaderType::HopByHop;
    pkt[7] = 64;
    pkt[23] = 0x01;
    pkt[39] = 0x02;
    std::memcpy(pkt.data() + 40, hbh.data(), hbh.size());

    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::BadJumboPayload);
}

// ---------------------------------------------------------------------------
// NoNextHeader (59)
// ---------------------------------------------------------------------------

TCPIP2_TEST(NoNextHeader) {
    // HopByHop ext header with next_nh=59 (NoNextHeader).
    auto hbh = BuildExtHeader(Ipv6ExtHeaderType::NoNextHeader, 8);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, hbh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{1}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{59}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == nullptr);
}

TCPIP2_TEST(NoNextHeaderDirect) {
    // Fixed header with next_header=59 directly (no extension headers).
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::NoNextHeader, {}, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{59}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == nullptr);
}

// ---------------------------------------------------------------------------
// Combined chains
// ---------------------------------------------------------------------------

TCPIP2_TEST(HopByHopRoutingFragmentChain) {
    // HopByHop → Routing → Fragment → TCP
    std::vector<std::uint8_t> exts;

    // HopByHop with RouterAlert, next_nh=Routing
    auto ra = BuildRouterAlert(0);
    auto hbh = BuildHopByHopWithOptions(Ipv6ExtHeaderType::Routing, ra);
    exts.insert(exts.end(), hbh.begin(), hbh.end());

    // Routing, next_nh=Fragment
    auto rh = BuildRoutingHeader(Ipv6ExtHeaderType::Fragment, 0, 1, {0x11, 0x22});
    exts.insert(exts.end(), rh.begin(), rh.end());

    // Fragment (8 bytes), next_nh=TCP
    std::vector<std::uint8_t> fh(8, 0);
    fh[0] = 6; // next_nh=TCP
    exts.insert(exts.end(), fh.begin(), fh.end());

    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, exts, 20);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{3}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_TRUE(result.fragment_header_present);
    TCPIP2_EXPECT_TRUE(result.routing_header_present);
    TCPIP2_EXPECT_TRUE(result.hopbyhop_option_count >= 1);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.dest_option_count);
}

TCPIP2_TEST(HopByHopAndDestOptionsChain) {
    // HopByHop → DestOptions → TCP
    std::vector<std::uint8_t> exts;

    // HopByHop with RouterAlert, next_nh=DestOptions
    auto ra = BuildRouterAlert(0);
    auto hbh = BuildHopByHopWithOptions(Ipv6ExtHeaderType::DestinationOptions, ra);
    exts.insert(exts.end(), hbh.begin(), hbh.end());

    // DestOptions with PadN, next_nh=TCP
    auto padn = BuildPadN(6);
    auto dh = BuildHopByHopWithOptions(6, padn);
    exts.insert(exts.end(), dh.begin(), dh.end());

    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, exts, 10);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{2}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_TRUE(result.hopbyhop_option_count >= 1);
    TCPIP2_EXPECT_TRUE(result.dest_option_count >= 1);
    TCPIP2_EXPECT_FALSE(result.routing_header_present);
    TCPIP2_EXPECT_FALSE(result.fragment_header_present);
    TCPIP2_EXPECT_EQ(std::size_t{10}, result.payload_length);
}

// ---------------------------------------------------------------------------
// Pad1 handling
// ---------------------------------------------------------------------------

TCPIP2_TEST(HopByHopWithOnlyPad1) {
    // HopByHop with all Pad1 bytes (just zeros after the 2-byte prefix).
    // 8-byte ext header: 2 prefix + 6 bytes of Pad1 (type=0).
    auto hbh = BuildExtHeader(6, 8); // all zeros = 6 Pad1 options
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, hbh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{6}, result.hopbyhop_option_count);
    // All should be Pad1 (type=0).
    for (std::size_t i = 0; i < result.hopbyhop_option_count; ++i) {
        TCPIP2_EXPECT_EQ(std::uint8_t{0}, result.hopbyhop_options[i].type);
        TCPIP2_EXPECT_EQ(std::uint8_t{0}, result.hopbyhop_options[i].length);
        TCPIP2_EXPECT_TRUE(result.hopbyhop_options[i].data == nullptr);
    }
}

// ---------------------------------------------------------------------------
// Backward compatibility: existing simple HopByHop still works
// ---------------------------------------------------------------------------

TCPIP2_TEST(SimpleHopByHopStillParses) {
    // The existing test pattern: a bare HopByHop with no real options (all Pad1).
    auto eh = BuildExtHeader(6, 8);
    auto pkt = BuildIpv6(Ipv6ExtHeaderType::HopByHop, eh, 0);
    auto result = ParseIpv6(pkt.data(), pkt.size());

    TCPIP2_EXPECT_TRUE(result.error == Ipv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::size_t{1}, result.ext_header_count);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, result.final_next_header);
    TCPIP2_EXPECT_EQ(std::size_t{48}, result.payload_offset);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == pkt.data() + 48);
}

TCPIP2_TEST_MAIN();
