#pragma once

/**
 * @file extension_headers.h
 * @brief Structured parsing for IPv6 extension header options and routing headers.
 * @license GPL-3.0
 *
 * The IPv6 parser walks HopByHop, Routing, and DestinationOptions extension
 * headers. This header provides the types and free functions used to parse the
 * TLV option fields within HopByHop / DestinationOptions and the fixed fields
 * of the Routing header.
 */

#include <cstdint>
#include <cstddef>

#include <ip/checked.h>

namespace tcpip2 {

/// Well-known IPv6 HopByHop / Destination option types (RFC 8200).
struct Ipv6OptionType {
    enum : std::uint8_t {
        Pad1 = 0,         // Special: 1 byte, no length/value
        PadN = 1,         // N bytes of padding
        RouterAlert = 5,  // Router Alert (RFC 2711)
        JumboPayload = 0xC2, // Jumbo Payload Length (RFC 2675)
    };
};

/// A single parsed TLV option within a HopByHop or Destination Options header.
/// The data pointer references the input buffer; it is valid for the same
/// lifetime as the buffer passed to ParseIpv6.
struct Ipv6Option {
    std::uint8_t type = 0;
    std::uint8_t length = 0;          // number of data bytes (excludes type+length)
    const std::uint8_t* data = nullptr; // points into input buffer; nullptr for Pad1
};

/// Parsed Routing extension header (RFC 8200 §4.4).
struct Ipv6RoutingHeader {
    std::uint8_t routing_type = 0;
    std::uint8_t segments_left = 0;
    const std::uint8_t* type_specific_data = nullptr;
    std::size_t type_specific_length = 0; // bytes after the 4-byte fixed prefix
};

/// Maximum number of TLV options to parse per extension header.
constexpr std::size_t kIpv6MaxOptions = 64;

/// Parse TLV options from a HopByHop or Destination Options body.
///
/// @param data       pointer to the first option byte (after next_header + hdr_ext_len)
/// @param len        number of option bytes
/// @param out        array of at least kIpv6MaxOptions entries
/// @param out_count  receives the number of options written
/// @return true on success, false if the option encoding is malformed/truncated
bool ParseIpv6Options(const std::uint8_t* data, std::size_t len,
                      Ipv6Option* out, std::size_t& out_count) noexcept;

/// Parse a Routing extension header body.
///
/// @param data  pointer to the first byte after next_header + hdr_ext_len
/// @param len   number of bytes in the routing header body (ext_size - 2)
/// @return parsed routing header; routing_type is 0 and data is nullptr if len < 2
Ipv6RoutingHeader ParseIpv6RoutingHeader(const std::uint8_t* data,
                                          std::size_t len) noexcept;

} // namespace tcpip2
