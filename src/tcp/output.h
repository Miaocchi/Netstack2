#pragma once

/**
 * @file output.h
 * @brief Bounded IPv4/IPv6 TCP control-packet serialization.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcp/handshake.h>

namespace tcpip2 {

enum class TcpOutputError {
    None,
    InvalidResponse,
    AddressFamilyMismatch,
    BufferTooSmall,
    OptionsTooLong,
};

struct TcpOutputResult {
    TcpOutputError error = TcpOutputError::None;
    std::size_t packet_length = 0;
};

TcpOutputResult BuildTcpControlPacket(const TcpResponse& response,
                                      std::uint8_t* output,
                                      std::size_t capacity,
                                      std::uint16_t ipv4_id = 0,
                                      std::uint8_t hop_limit = 64) noexcept;

} // namespace tcpip2
