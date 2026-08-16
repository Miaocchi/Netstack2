#pragma once

/**
 * @file icmp_unreachable.h
 * @brief Bounded ICMP Destination-Unreachable response builder (RFC 792 / 4443).
 * @license GPL-3.0
 *
 * Builds a complete IPv4 or IPv6 packet carrying an ICMP destination
 * unreachable message that quotes the original datagram's IP header plus the
 * first 8 bytes of its transport header. Used by the UDP engine to report a
 * policy/port rejection back to the sender (R7 step 9).
 */

#include <cstddef>
#include <cstdint>

namespace tcpip2 {

enum class IcmpUnreachableError {
    None,
    InvalidOriginal,  ///< null pointer / too short to quote an IP header.
    BufferTooSmall,   ///< capacity < the built response size.
};

struct IcmpUnreachableResult {
    IcmpUnreachableError error = IcmpUnreachableError::None;
    std::size_t packet_length = 0;
};

/**
 * Build an IPv4 ICMP Destination Unreachable response.
 * @param original      the original (client) IPv4 packet; source/destination
 *                      are swapped in the reply and its header + first 8 bytes
 *                      are quoted.
 * @param original_len  length of @p original.
 * @param code          Icmpv4DestUnreachableCode (Port=3, FragmentationNeeded=4).
 * @param mtu           next-hop MTU for code 4; ignored otherwise.
 * @param output        destination buffer.
 * @param capacity      bytes available at @p output.
 * @param hop_limit     IPv4 TTL for the reply.
 */
IcmpUnreachableResult BuildIcmpv4Unreachable(const std::uint8_t* original,
                                             std::size_t original_len,
                                             std::uint8_t code,
                                             std::uint16_t mtu,
                                             std::uint8_t* output,
                                             std::size_t capacity,
                                             std::uint8_t hop_limit = 64) noexcept;

/**
 * Build an IPv6 ICMPv6 Destination Unreachable response (pseudo-header
 * checksum, RFC 4443).
 * @param original      the original (client) IPv6 packet.
 * @param original_len  length of @p original.
 * @param code          Icmpv6DestUnreachableCode (PortUnreachable=4, etc.).
 * @param output        destination buffer.
 * @param capacity      bytes available at @p output.
 * @param hop_limit     IPv6 hop limit for the reply.
 */
IcmpUnreachableResult BuildIcmpv6Unreachable(const std::uint8_t* original,
                                             std::size_t original_len,
                                             std::uint8_t code,
                                             std::uint8_t* output,
                                             std::size_t capacity,
                                             std::uint8_t hop_limit = 64) noexcept;

} // namespace tcpip2
