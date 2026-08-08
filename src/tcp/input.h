#pragma once

/**
 * @file input.h
 * @brief IPv4/IPv6 packet validation and TCP input normalization.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcp/segment.h>

namespace tcpip2 {

enum class TcpInputError {
    None,
    NullData,
    UnsupportedIpVersion,
    MalformedIp,
    BadIpv4Checksum,
    NotTcp,
    FragmentRequiresReassembly,
    MalformedTcp,
};

struct TcpInputResult {
    TcpInputError error = TcpInputError::None;
    TcpParseError tcp_error = TcpParseError::None;
    TcpSegmentView segment;
};

TcpInputResult ParseIpTcpPacket(const std::uint8_t* packet,
                                std::size_t length) noexcept;

} // namespace tcpip2
