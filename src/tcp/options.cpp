#include <tcp/options.h>

namespace tcpip2 {
namespace {

std::uint16_t Read16(const std::uint8_t* data) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) |
        static_cast<std::uint16_t>(data[1]));
}

std::uint32_t Read32(const std::uint8_t* data) noexcept {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

} // namespace

TcpOptionParseResult ParseTcpSynOptions(const std::uint8_t* data,
                                        std::size_t length) noexcept {
    TcpOptionParseResult result;
    if (length == 0) return result;
    if (data == nullptr) {
        result.error = TcpOptionError::NullData;
        return result;
    }
    if (length > 40) {
        result.error = TcpOptionError::TooLong;
        return result;
    }

    std::size_t offset = 0;
    while (offset < length) {
        const std::uint8_t kind = data[offset];
        if (kind == 0) break;
        if (kind == 1) {
            ++offset;
            continue;
        }
        if (length - offset < 2) {
            result.error = TcpOptionError::Truncated;
            return result;
        }

        const std::size_t option_length = data[offset + 1];
        if (option_length < 2) {
            result.error = TcpOptionError::InvalidLength;
            return result;
        }
        if (option_length > length - offset) {
            result.error = TcpOptionError::Truncated;
            return result;
        }

        switch (kind) {
        case 2:
            if (option_length != 4) {
                result.error = TcpOptionError::InvalidLength;
                return result;
            }
            if (result.options.mss_present) {
                result.error = TcpOptionError::DuplicateOption;
                return result;
            }
            result.options.mss = Read16(data + offset + 2);
            if (result.options.mss == 0) {
                result.error = TcpOptionError::InvalidMss;
                return result;
            }
            result.options.mss_present = true;
            break;
        case 3:
            if (option_length != 3) {
                result.error = TcpOptionError::InvalidLength;
                return result;
            }
            if (result.options.window_scale_present) {
                result.error = TcpOptionError::DuplicateOption;
                return result;
            }
            result.options.window_scale_present = true;
            result.options.window_scale = data[offset + 2] > 14
                ? std::uint8_t{14} : data[offset + 2];
            break;
        case 4:
            if (option_length != 2) {
                result.error = TcpOptionError::InvalidLength;
                return result;
            }
            if (result.options.sack_permitted) {
                result.error = TcpOptionError::DuplicateOption;
                return result;
            }
            result.options.sack_permitted = true;
            break;
        case 8:
            if (option_length != 10) {
                result.error = TcpOptionError::InvalidLength;
                return result;
            }
            if (result.options.timestamp_present) {
                result.error = TcpOptionError::DuplicateOption;
                return result;
            }
            result.options.timestamp_present = true;
            result.options.timestamp_value = Read32(data + offset + 2);
            result.options.timestamp_echo = Read32(data + offset + 6);
            break;
        default:
            break;
        }
        offset += option_length;
    }

    return result;
}

} // namespace tcpip2
