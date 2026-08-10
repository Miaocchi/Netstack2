#pragma once

/**
 * @file input.h
 * @brief IPv4/IPv6 packet validation and UDP input normalization.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/address.h>
#include <udp/udp.h>

namespace tcpip2 {

/// Result of parsing an IP packet as UDP.
struct UdpInputResult {
    enum class Error {
        None,
        NotUdp,             // protocol is not UDP
        MalformedIp,
        MalformedUdp,
        BadChecksum,
    };
    Error error = Error::None;
    UdpParseResult datagram;
};

/// Parse an IP packet (raw bytes) as a UDP datagram.
UdpInputResult ParseIpUdpPacket(const std::uint8_t* packet, std::size_t length) noexcept;

} // namespace tcpip2
