#pragma once

/**
 * @file ipv4.h
 * @brief Bounded IPv4 header parser with checked arithmetic.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>

#include <ip/checked.h>

namespace tcpip2 {

/// Result of IPv4 header parsing.
struct Ipv4Header {
    std::uint8_t version = 0;       // always 4
    std::uint8_t ihl = 0;           // header length in 32-bit words (5-15)
    std::uint8_t dscp = 0;          // differentiated services code point
    std::uint8_t ecn = 0;           // explicit congestion notification
    std::uint16_t total_length = 0; // total IP packet length in bytes
    std::uint16_t identification = 0;
    std::uint8_t flags = 0;            // 3-bit flags (reserved, DF, MF)
    std::uint16_t fragment_offset = 0; // 13-bit offset in 8-byte units
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint16_t header_checksum = 0; // raw checksum from the wire
    std::uint8_t src_ip[4] = {};       // network byte order
    std::uint8_t dst_ip[4] = {};       // network byte order
    std::size_t header_length = 0;     // IHL * 4 (validated: 20-60)
    std::size_t payload_offset = 0;    // offset to payload in the buffer
    std::size_t payload_length = 0;    // total_length - header_length
};

enum class Ipv4ParseError {
    None,              // success
    TooShort,          // fewer than 20 bytes
    BadVersion,        // version field is not 4
    BadIhl,            // IHL < 5
    TruncatedHeader,   // total_length < IHL*4 or buffer shorter than IHL*4
    TruncatedTotal,    // buffer shorter than total_length
    BadFragmentOffset, // non-zero fragment offset with MF=0 on non-first fragment (actually we don't reject this; we
                       // just report)
};

struct Ipv4ParseResult {
    Ipv4ParseError error = Ipv4ParseError::None;
    Ipv4Header header;
    bool checksum_ok = false;              // true if internet checksum validates
    const std::uint8_t *payload = nullptr; // points into the input buffer
};

/// Parse an IPv4 packet from a raw byte buffer.
/// @param data pointer to the first byte of the IP header
/// @param len number of bytes available
/// @return parse result; on success, payload points into the input buffer
Ipv4ParseResult ParseIpv4(const std::uint8_t *data, std::size_t len) noexcept;

} // namespace tcpip2
