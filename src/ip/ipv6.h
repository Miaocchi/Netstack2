#pragma once

/**
 * @file ipv6.h
 * @brief Bounded IPv6 header and extension header parser.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>

#include <ip/checked.h>
#include <ip/extension_headers.h>

namespace tcpip2 {

/// IPv6 extension header types relevant to parsing.
struct Ipv6ExtHeaderType {
    enum : std::uint8_t {
        HopByHop = 0,
        Routing = 43,
        Fragment = 44,
        DestinationOptions = 60,
        NoNextHeader = 59, // RFC 8200 — no payload follows
        Esp = 50,          // Encapsulating Security Payload (terminal)
        Ah = 51,           // Authentication Header (terminal)
        Mobility = 135,    // Mobility Header (terminal)
    };
};

/// Result of IPv6 header parsing.
struct Ipv6Header {
    std::uint8_t version = 0; // always 6
    std::uint8_t traffic_class = 0;
    std::uint32_t flow_label = 0;     // 20-bit
    std::uint16_t payload_length = 0; // excluding the 40-byte fixed header
    std::uint8_t next_header = 0;     // from the fixed header
    std::uint8_t hop_limit = 0;
    std::uint8_t src_ip[16] = {};   // network byte order
    std::uint8_t dst_ip[16] = {};   // network byte order
    std::size_t header_length = 40; // fixed header is always 40 bytes
};

/// Extended header info after walking extension headers.
struct Ipv6ParseResult {
    enum class Error {
        None,
        TooShort,           // fewer than 40 bytes
        BadVersion,         // version is not 6
        TruncatedPayload,   // buffer shorter than 40 + payload_length
        TruncatedExtHeader, // extension header extends beyond buffer
        ExtHeaderLoop,      // extension header chain loops
        ExtHeaderTooMany,   // too many extension headers (>8)
        ExtHeaderTooLong,   // total extension header bytes exceed limit
        BadExtHeaderOption, // malformed TLV option in HopByHop/DestOptions
        BadJumboPayload,    // Jumbo Payload option present with non-zero payload_length
    };

    Error error = Error::None;
    Ipv6Header header;
    std::uint8_t final_next_header = 0;    // terminal protocol (TCP, UDP, ICMPv6, etc.)
    std::size_t ext_header_count = 0;      // number of extension headers walked
    bool fragment_header_present = false;  // true when the chain contains a Fragment header
    std::size_t payload_offset = 0;        // offset to upper-layer payload
    std::size_t payload_length = 0;        // bytes of upper-layer payload
    const std::uint8_t *payload = nullptr; // points into input buffer

    // Fragment header details (valid when fragment_header_present == true).
    std::uint16_t fragment_offset = 0;              // 8-byte units (13-bit value from wire)
    bool fragment_more = false;                     // MF bit
    std::uint32_t fragment_identification = 0;      // 32-bit identification
    const std::uint8_t *fragment_payload = nullptr; // data after the Fragment header
    std::size_t fragment_payload_length = 0;

    // HopByHop options (valid when ext_header_count > 0 and chain includes HopByHop).
    Ipv6Option hopbyhop_options[kIpv6MaxOptions];
    std::size_t hopbyhop_option_count = 0;

    // Destination Options (valid when chain includes DestinationOptions).
    Ipv6Option dest_options[kIpv6MaxOptions];
    std::size_t dest_option_count = 0;

    // Routing header (valid when routing_header_present == true).
    bool routing_header_present = false;
    Ipv6RoutingHeader routing_header;

    // Jumbo Payload (RFC 2675) — present when the HopByHop JumboPayload option
    // is found and the fixed-header payload_length is 0.
    bool jumbo_payload_present = false;
    std::uint32_t jumbo_payload_length = 0; // total bytes after the 40-byte fixed header
};

/// Maximum number of extension headers to walk before declaring a loop.
constexpr std::size_t kIpv6MaxExtHeaders = 8;

/// Maximum total bytes consumed by extension headers.
constexpr std::size_t kIpv6MaxExtHeaderBytes = 1024;

/// Parse an IPv6 packet, walking bounded extension headers.
/// @param data pointer to the first byte of the IPv6 fixed header
/// @param len number of bytes available
/// @return parse result with payload pointing into the input buffer on success
Ipv6ParseResult ParseIpv6(const std::uint8_t *data, std::size_t len) noexcept;

} // namespace tcpip2
