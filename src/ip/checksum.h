#pragma once

/**
 * @file checksum.h
 * @brief Internet checksum (RFC 1071) and TCP/UDP pseudo-header helpers.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>

namespace tcpip2 {

/// Compute the internet checksum over data[0..len) with an optional seed.
/// The seed allows accumulating a pseudo-header before the segment data.
/// Returns the one's complement of the 16-bit sum.
std::uint16_t InternetChecksum(const std::uint8_t *data, std::size_t len, std::uint32_t seed = 0) noexcept;

/// Build the IPv4 pseudo-header for TCP/UDP checksum computation.
/// Returns the 12-byte pseudo-header as a uint32_t seed for InternetChecksum.
/// @param src_ip source IPv4 address in network byte order (big-endian bytes)
/// @param dst_ip destination IPv4 address in network byte order
/// @param protocol IP protocol number (6=TCP, 17=UDP)
/// @param transport_len length of the TCP/UDP segment including header
std::uint32_t Ipv4PseudoHeaderSeed(const std::uint8_t src_ip[4], const std::uint8_t dst_ip[4], std::uint8_t protocol,
                                   std::uint16_t transport_len) noexcept;

/// Build the IPv6 pseudo-header for TCP/UDP checksum computation.
/// Returns the seed for InternetChecksum.
/// @param src_ip source IPv6 address (16 bytes)
/// @param dst_ip destination IPv6 address (16 bytes)
/// @param protocol upper-layer protocol number
/// @param upper_len upper-layer payload length (corresponds to IPv6 Payload Length)
std::uint32_t Ipv6PseudoHeaderSeed(const std::uint8_t src_ip[16], const std::uint8_t dst_ip[16], std::uint8_t protocol,
                                   std::uint32_t upper_len) noexcept;

} // namespace tcpip2
