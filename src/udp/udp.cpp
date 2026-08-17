#include <udp/udp.h>

#include <limits>

#include <ip/checksum.h>

namespace tcpip2 {
namespace {

std::uint16_t Read16(const std::uint8_t *data) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | static_cast<std::uint16_t>(data[1]));
}

} // namespace

UdpParseResult ParseUdpDatagram(const IpAddress &source, const IpAddress &destination, const std::uint8_t *data,
                                std::size_t length, bool validate_checksum) noexcept {
    UdpParseResult result;
    if (data == nullptr) {
        result.error = UdpParseError::NullData;
        return result;
    }
    if (source.family() != destination.family()) {
        result.error = UdpParseError::NullData;
        return result;
    }
    if (length < 8) {
        result.error = UdpParseError::TooShort;
        return result;
    }

    const std::uint16_t src_port = Read16(data);
    const std::uint16_t dst_port = Read16(data + 2);
    const std::uint16_t udp_length = Read16(data + 4);
    const std::uint16_t checksum = Read16(data + 6);

    // The UDP length field covers the entire datagram (header + data).
    if (udp_length < 8 || udp_length > length) {
        result.error = UdpParseError::LengthMismatch;
        return result;
    }

    // Checksum validation.
    // IPv4: checksum 0 means "not computed" and is accepted.
    // IPv6: checksum 0 is invalid (checksum is mandatory).
    if (validate_checksum) {
        if (checksum == 0) {
            if (source.IsIpv6()) {
                result.error = UdpParseError::BadChecksum;
                return result;
            }
            // IPv4 with checksum 0: accepted as "not computed".
        } else {
            std::uint32_t seed = 0;
            if (source.IsIpv4()) {
                seed = Ipv4PseudoHeaderSeed(source.Bytes(), destination.Bytes(), 17, udp_length);
            } else {
                seed = Ipv6PseudoHeaderSeed(source.Bytes(), destination.Bytes(), 17,
                                            static_cast<std::uint32_t>(udp_length));
            }
            if (InternetChecksum(data, udp_length, seed) != 0) {
                result.error = UdpParseError::BadChecksum;
                return result;
            }
        }
    }

    result.header.src_port = src_port;
    result.header.dst_port = dst_port;
    result.header.length = udp_length;
    result.header.checksum = checksum;

    result.flow.source = source;
    result.flow.destination = destination;
    result.flow.source_port = src_port;
    result.flow.destination_port = dst_port;
    result.flow.protocol = 17;

    result.payload = data + 8;
    result.payload_length = static_cast<std::size_t>(udp_length) - 8;
    return result;
}

std::uint16_t ComputeUdpChecksum(const IpAddress &source, const IpAddress &destination, const std::uint8_t *data,
                                 std::size_t length) noexcept {
    if (data == nullptr || length < 8)
        return 0;
    if (source.family() != destination.family())
        return 0;

    std::uint32_t seed = 0;
    if (source.IsIpv4()) {
        seed = Ipv4PseudoHeaderSeed(source.Bytes(), destination.Bytes(), 17, static_cast<std::uint16_t>(length));
    } else {
        seed = Ipv6PseudoHeaderSeed(source.Bytes(), destination.Bytes(), 17, static_cast<std::uint32_t>(length));
    }

    const std::uint16_t computed = InternetChecksum(data, length, seed);
    // UDP uses 0 to mean "no checksum" on IPv4. If the computed value is 0,
    // transmit 0xFFFF instead (RFC 768).
    if (computed == 0)
        return 0xFFFF;
    return computed;
}

} // namespace tcpip2
