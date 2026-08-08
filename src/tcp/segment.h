#pragma once

/**
 * @file segment.h
 * @brief Bounded TCP segment parser and checksum validation.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/address.h>
#include <tcpip2/flow.h>

namespace tcpip2 {

struct TcpFlag {
    enum : std::uint8_t {
        Fin = 0x01,
        Syn = 0x02,
        Rst = 0x04,
        Psh = 0x08,
        Ack = 0x10,
        Urg = 0x20,
        Ece = 0x40,
        Cwr = 0x80,
    };
};

enum class TcpParseError {
    None,
    NullData,
    AddressFamilyMismatch,
    TooShort,
    TooLong,
    BadDataOffset,
    BadChecksum,
};

struct TcpSegmentView {
    FlowKey flow;
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgment = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
    std::uint16_t urgent_pointer = 0;
    const std::uint8_t* options = nullptr;
    std::size_t options_length = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t payload_length = 0;

    bool HasFlag(std::uint8_t flag) const noexcept {
        return (flags & flag) != 0;
    }
};

struct TcpParseResult {
    TcpParseError error = TcpParseError::None;
    TcpSegmentView segment;
};

TcpParseResult ParseTcpSegment(const IpAddress& source,
                               const IpAddress& destination,
                               const std::uint8_t* data,
                               std::size_t length) noexcept;

} // namespace tcpip2
