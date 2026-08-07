#pragma once

/**
 * @file ipv6.h
 * @brief Bounded IPv6 header and extension header parser.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>

#include <ip/checked.h>

namespace tcpip2 {

/// IPv6 extension header types relevant to parsing.
struct Ipv6ExtHeaderType {
    enum : std::uint8_t {
        HopByHop = 0,
        Routing = 43,
        Fragment = 44,
        DestinationOptions = 60,
        // Others are treated as terminal (upper-layer protocol).
    };
};

/// Result of IPv6 header parsing.
struct Ipv6Header {
    std::uint8_t version = 0;         // always 6
    std::uint8_t traffic_class = 0;
    std::uint32_t flow_label = 0;     // 20-bit
    std::uint16_t payload_length = 0; // excluding the 40-byte fixed header
    std::uint8_t next_header = 0;     // from the fixed header
    std::uint8_t hop_limit = 0;
    std::uint8_t src_ip[16] = {};     // network byte order
    std::uint8_t dst_ip[16] = {};     // network byte order
    std::size_t header_length = 40;   // fixed header is always 40 bytes
};

/// Extended header info after walking extension headers.
struct Ipv6ParseResult {
    enum class Error {
        None,
        TooShort,            // fewer than 40 bytes
        BadVersion,          // version is not 6
        TruncatedPayload,    // buffer shorter than 40 + payload_length
        TruncatedExtHeader,  // extension header extends beyond buffer
        ExtHeaderLoop,       // extension header chain loops
        ExtHeaderTooMany,    // too many extension headers (>8)
        ExtHeaderTooLong,    // total extension header bytes exceed limit
    };

    Error error = Error::None;
    Ipv6Header header;
    std::uint8_t final_next_header = 0;  // terminal protocol (TCP, UDP, ICMPv6, etc.)
    std::size_t ext_header_count = 0;    // number of extension headers walked
    std::size_t payload_offset = 0;      // offset to upper-layer payload
    std::size_t payload_length = 0;      // bytes of upper-layer payload
    const std::uint8_t* payload = nullptr; // points into input buffer
};

/// Maximum number of extension headers to walk before declaring a loop.
constexpr std::size_t kIpv6MaxExtHeaders = 8;

/// Maximum total bytes consumed by extension headers.
constexpr std::size_t kIpv6MaxExtHeaderBytes = 1024;

/// Parse an IPv6 packet, walking bounded extension headers.
/// @param data pointer to the first byte of the IPv6 fixed header
/// @param len number of bytes available
/// @return parse result with payload pointing into the input buffer on success
Ipv6ParseResult ParseIpv6(const std::uint8_t* data, std::size_t len) noexcept;

} // namespace tcpip2
