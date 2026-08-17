#pragma once

/**
 * @file icmpv4.h
 * @brief Bounded ICMPv4 header parser.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>

#include <ip/checked.h>

namespace tcpip2 {

/// ICMPv4 message types (RFC 792).
struct Icmpv4Type {
    static constexpr std::uint8_t EchoReply = 0;
    static constexpr std::uint8_t DestinationUnreachable = 3;
    static constexpr std::uint8_t Echo = 8;
    static constexpr std::uint8_t TimeExceeded = 11;
    static constexpr std::uint8_t ParameterProblem = 12;
};

/// Destination Unreachable codes (RFC 792).
struct Icmpv4DestUnreachableCode {
    static constexpr std::uint8_t Network = 0;
    static constexpr std::uint8_t Host = 1;
    static constexpr std::uint8_t Protocol = 2;
    static constexpr std::uint8_t Port = 3;
    static constexpr std::uint8_t FragmentationNeeded = 4;
    static constexpr std::uint8_t SourceRouteFailed = 5;
};

/// Result of ICMPv4 header parsing.
struct Icmpv4Header {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    std::uint16_t checksum = 0;                   // raw checksum from the wire
    std::uint16_t id = 0;                         // for Echo / Echo Reply
    std::uint16_t sequence = 0;                   // for Echo / Echo Reply
    std::uint16_t mtu = 0;                        // for Destination Unreachable, code 4
    const std::uint8_t *quoted_payload = nullptr; // points into input buffer
    std::size_t quoted_payload_len = 0;
};

enum class Icmpv4ParseError {
    None,        // success
    TooShort,    // fewer than 8 bytes
    BadChecksum, // reported via checksum_ok flag, not a parse failure
};

struct Icmpv4ParseResult {
    Icmpv4ParseError error = Icmpv4ParseError::None;
    Icmpv4Header header;
    bool checksum_ok = false;              // true if internet checksum validates
    const std::uint8_t *payload = nullptr; // data after the 8-byte header (for echo)
    std::size_t payload_length = 0;
};

/// Parse an ICMPv4 message from a raw byte buffer.
/// @param data pointer to the first byte of the ICMP header
/// @param len number of bytes available
/// @return parse result; on success, payload/quoted_payload point into the input buffer
Icmpv4ParseResult ParseIcmpv4(const std::uint8_t *data, std::size_t len) noexcept;

} // namespace tcpip2
