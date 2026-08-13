#include <tcp/segment.h>

#include <limits>

#include <ip/checksum.h>

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

TcpParseResult ParseTcpSegment(const IpAddress& source,
                               const IpAddress& destination,
                               const std::uint8_t* data,
                               std::size_t length,
                               std::uint8_t ip_ecn) noexcept {
    TcpParseResult result;
    if (data == nullptr) {
        result.error = TcpParseError::NullData;
        return result;
    }
    if (source.family() != destination.family()) {
        result.error = TcpParseError::AddressFamilyMismatch;
        return result;
    }
    if (length < 20) {
        result.error = TcpParseError::TooShort;
        return result;
    }
    if (length > std::numeric_limits<std::uint32_t>::max() ||
        (source.IsIpv4() && length > std::numeric_limits<std::uint16_t>::max())) {
        result.error = TcpParseError::TooLong;
        return result;
    }

    const std::size_t header_length =
        static_cast<std::size_t>(data[12] >> 4) * 4;
    if (header_length < 20 || header_length > length) {
        result.error = TcpParseError::BadDataOffset;
        return result;
    }
    std::uint32_t checksum_seed = 0;
    if (source.IsIpv4()) {
        checksum_seed = Ipv4PseudoHeaderSeed(
            source.Bytes(), destination.Bytes(), 6,
            static_cast<std::uint16_t>(length));
    } else {
        checksum_seed = Ipv6PseudoHeaderSeed(
            source.Bytes(), destination.Bytes(), 6,
            static_cast<std::uint32_t>(length));
    }
    if (InternetChecksum(data, length, checksum_seed) != 0) {
        result.error = TcpParseError::BadChecksum;
        return result;
    }

    result.segment.flow.source = source;
    result.segment.flow.destination = destination;
    result.segment.flow.source_port = Read16(data);
    result.segment.flow.destination_port = Read16(data + 2);
    result.segment.flow.protocol = 6;
    result.segment.sequence = Read32(data + 4);
    result.segment.acknowledgment = Read32(data + 8);
    result.segment.flags = data[13];
    result.segment.window = Read16(data + 14);
    result.segment.urgent_pointer = Read16(data + 18);
    result.segment.ip_ecn = static_cast<std::uint8_t>(ip_ecn & 0x03u);
    result.segment.options = data + 20;
    result.segment.options_length = header_length - 20;
    result.segment.payload = data + header_length;
    result.segment.payload_length = length - header_length;
    return result;
}

} // namespace tcpip2
