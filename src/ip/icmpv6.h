#pragma once

/**
 * @file icmpv6.h
 * @brief Bounded ICMPv6 message parser.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>

#include <ip/checked.h>

namespace tcpip2 {

/// ICMPv6 message types (RFC 4443).
struct Icmpv6Type {
    static constexpr std::uint8_t DestinationUnreachable = 1;
    static constexpr std::uint8_t PacketTooBig = 2;
    static constexpr std::uint8_t TimeExceeded = 3;
    static constexpr std::uint8_t ParameterProblem = 4;
    static constexpr std::uint8_t EchoRequest = 128;
    static constexpr std::uint8_t EchoReply = 129;
};

/// Destination Unreachable codes (RFC 4443).
struct Icmpv6DestUnreachableCode {
    static constexpr std::uint8_t NoRoute = 0;
    static constexpr std::uint8_t AdminProhibited = 1;
    static constexpr std::uint8_t BeyondScope = 2;
    static constexpr std::uint8_t AddressUnreachable = 3;
    static constexpr std::uint8_t PortUnreachable = 4;
};

/// Parsed ICMPv6 header fields.
struct Icmpv6Header {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    std::uint16_t checksum = 0;
    std::uint32_t mtu = 0;                        // Packet Too Big (type 2)
    std::uint32_t pointer = 0;                    // Parameter Problem (type 4)
    std::uint16_t id = 0;                         // Echo Request/Reply
    std::uint16_t sequence = 0;                   // Echo Request/Reply
    const std::uint8_t *quoted_payload = nullptr; // error messages: points into input
    std::size_t quoted_payload_len = 0;
};

/// Result of ICMPv6 message parsing.
struct Icmpv6ParseResult {
    enum class Error {
        None,
        TooShort, // fewer than 8 bytes
    };

    Error error = Error::None;
    Icmpv6Header header;
    bool checksum_ok = true;               // placeholder; use VerifyIcmpv6Checksum
    const std::uint8_t *payload = nullptr; // echo: data after 8-byte header
    std::size_t payload_length = 0;
};

/// Parse an ICMPv6 message.
/// @param data pointer to the first byte of the ICMPv6 message
/// @param len number of bytes available
/// @return parse result with payload/quoted_payload pointing into the input buffer on success
Icmpv6ParseResult ParseIcmpv6(const std::uint8_t *data, std::size_t len) noexcept;

/// Verify the ICMPv6 checksum (includes the IPv6 pseudo-header).
/// @param data pointer to the first byte of the ICMPv6 message
/// @param len number of bytes available
/// @param src_ip source IPv6 address (16 bytes)
/// @param dst_ip destination IPv6 address (16 bytes)
/// @return true if the checksum is valid
bool VerifyIcmpv6Checksum(const std::uint8_t *data, std::size_t len, const std::uint8_t src_ip[16],
                          const std::uint8_t dst_ip[16]) noexcept;

} // namespace tcpip2
