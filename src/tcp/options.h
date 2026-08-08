#pragma once

/**
 * @file options.h
 * @brief Allocation-free TCP SYN option parsing.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

namespace tcpip2 {

enum class TcpOptionError {
    None,
    NullData,
    TooLong,
    Truncated,
    InvalidLength,
    DuplicateOption,
    InvalidMss,
};

struct TcpSynOptions {
    bool mss_present = false;
    std::uint16_t mss = 0;
    bool window_scale_present = false;
    std::uint8_t window_scale = 0;
    bool sack_permitted = false;
    bool timestamp_present = false;
    std::uint32_t timestamp_value = 0;
    std::uint32_t timestamp_echo = 0;
};

struct TcpOptionParseResult {
    TcpOptionError error = TcpOptionError::None;
    TcpSynOptions options;
};

TcpOptionParseResult ParseTcpSynOptions(const std::uint8_t* data,
                                        std::size_t length) noexcept;

} // namespace tcpip2
