#include <udp/output.h>

#include <cstring>
#include <limits>

#include <ip/checksum.h>
#include <udp/udp.h>

namespace tcpip2 {
namespace {

void Write16(std::uint8_t* output, std::uint16_t value) noexcept {
    output[0] = static_cast<std::uint8_t>(value >> 8);
    output[1] = static_cast<std::uint8_t>(value & 0xffu);
}

} // namespace

UdpOutputResult BuildUdpPacket(const FlowKey& flow,
                               const std::uint8_t* payload,
                               std::size_t payload_length,
                               std::uint8_t* output,
                               std::size_t capacity,
                               std::uint16_t ipv4_id,
                               std::uint8_t hop_limit) noexcept {
    UdpOutputResult result;
    if (output == nullptr || flow.protocol != 17 ||
        flow.source.family() != flow.destination.family()) {
        result.error = UdpOutputError::InvalidFlow;
        return result;
    }
    if (payload == nullptr && payload_length != 0) {
        result.error = UdpOutputError::InvalidFlow;
        return result;
    }

    const std::uint64_t udp_length = static_cast<std::uint64_t>(payload_length) + 8;
    if (udp_length > std::numeric_limits<std::uint16_t>::max()) {
        result.error = UdpOutputError::PayloadTooLarge;
        return result;
    }

    const std::size_t ip_header_length = flow.source.IsIpv4() ? 20 : 40;
    const std::size_t packet_length = ip_header_length + static_cast<std::size_t>(udp_length);
    if (capacity < packet_length) {
        result.error = UdpOutputError::BufferTooSmall;
        return result;
    }

    std::memset(output, 0, ip_header_length + 8);
    std::uint8_t* const udp = output + ip_header_length;
    Write16(udp, flow.source_port);
    Write16(udp + 2, flow.destination_port);
    Write16(udp + 4, static_cast<std::uint16_t>(udp_length));
    if (payload_length != 0) {
        std::memcpy(udp + 8, payload, payload_length);
    }

    // UDP checksum: always computed (mandatory for IPv6). 0 -> 0xFFFF.
    std::uint16_t checksum = 0;
    if (flow.source.IsIpv4()) {
        const std::uint32_t seed = Ipv4PseudoHeaderSeed(
            flow.source.Bytes(), flow.destination.Bytes(), 17,
            static_cast<std::uint16_t>(udp_length));
        checksum = InternetChecksum(udp, static_cast<std::size_t>(udp_length), seed);
    } else {
        const std::uint32_t seed = Ipv6PseudoHeaderSeed(
            flow.source.Bytes(), flow.destination.Bytes(), 17,
            static_cast<std::uint32_t>(udp_length));
        checksum = InternetChecksum(udp, static_cast<std::size_t>(udp_length), seed);
    }
    Write16(udp + 6, checksum == 0 ? 0xFFFF : checksum);

    if (flow.source.IsIpv4()) {
        output[0] = 0x45;
        Write16(output + 2, static_cast<std::uint16_t>(packet_length));
        Write16(output + 4, ipv4_id);
        // Flags: Don't Fragment (0x40) — RFC 1191 PMTU for IPv4 UDP.
        Write16(output + 6, 0x4000);
        output[8] = hop_limit;
        output[9] = 17;
        std::memcpy(output + 12, flow.source.Bytes(), 4);
        std::memcpy(output + 16, flow.destination.Bytes(), 4);
        Write16(output + 10, InternetChecksum(output, 20));
    } else {
        output[0] = 0x60;
        Write16(output + 4, static_cast<std::uint16_t>(udp_length));
        output[6] = 17;
        output[7] = hop_limit;
        std::memcpy(output + 8, flow.source.Bytes(), 16);
        std::memcpy(output + 24, flow.destination.Bytes(), 16);
    }

    result.packet_length = packet_length;
    return result;
}

} // namespace tcpip2
