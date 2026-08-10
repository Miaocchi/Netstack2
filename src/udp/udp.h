#pragma once

/**
 * @file udp.h
 * @brief Bounded UDP datagram parser and checksum validation.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/address.h>
#include <tcpip2/flow.h>

namespace tcpip2 {

/// UDP parse errors.
enum class UdpParseError {
    None,
    NullData,
    TooShort,           // fewer than 8 bytes (UDP header)
    LengthMismatch,     // declared length doesn't match available data
    BadChecksum,        // checksum validation failed (IPv6 only mandatory)
};

/// Parsed UDP header fields.
struct UdpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length = 0;       // total UDP length (header + data)
    std::uint16_t checksum = 0;     // raw checksum from wire
};

/// Result of UDP parsing.
struct UdpParseResult {
    UdpParseError error = UdpParseError::None;
    UdpHeader header;
    FlowKey flow;
    const std::uint8_t* payload = nullptr;  // data after 8-byte header
    std::size_t payload_length = 0;
};

/// Parse a UDP datagram.
/// @param source source IP address
/// @param destination destination IP address
/// @param data pointer to the first byte of the UDP header
/// @param length number of bytes available
/// @param validate_checksum if true, verify checksum (mandatory for IPv6)
/// @return parse result with payload pointing into the input buffer on success
UdpParseResult ParseUdpDatagram(const IpAddress& source,
                                 const IpAddress& destination,
                                 const std::uint8_t* data,
                                 std::size_t length,
                                 bool validate_checksum) noexcept;

/// Compute the UDP checksum (for TX use).
/// @param source source IP address
/// @param destination destination IP address
/// @param data UDP header + payload
/// @param length total UDP length
/// @return computed checksum value (0 if computation fails)
std::uint16_t ComputeUdpChecksum(const IpAddress& source,
                                  const IpAddress& destination,
                                  const std::uint8_t* data,
                                  std::size_t length) noexcept;

} // namespace tcpip2
