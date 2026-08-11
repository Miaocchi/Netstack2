#include <udp/input.h>

#include <ip/ipv4.h>
#include <ip/ipv6.h>

namespace tcpip2 {

UdpInputResult ParseIpUdpPacket(const std::uint8_t* packet,
                                std::size_t length) noexcept {
    UdpInputResult result;
    if (packet == nullptr || length == 0) {
        result.error = UdpInputResult::Error::MalformedIp;
        return result;
    }

    const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);
    if (version == 4) {
        const Ipv4ParseResult ip = ParseIpv4(packet, length);
        if (ip.error != Ipv4ParseError::None) {
            result.error = UdpInputResult::Error::MalformedIp;
            return result;
        }
        if (ip.header.protocol != 17) {
            result.error = UdpInputResult::Error::NotUdp;
            return result;
        }
        if (ip.header.fragment_offset != 0 || (ip.header.flags & 0x01u) != 0) {
            result.error = UdpInputResult::Error::MalformedIp;
            return result;
        }
        const IpAddress src = IpAddress::Ipv4(
            ip.header.src_ip[0], ip.header.src_ip[1],
            ip.header.src_ip[2], ip.header.src_ip[3]);
        const IpAddress dst = IpAddress::Ipv4(
            ip.header.dst_ip[0], ip.header.dst_ip[1],
            ip.header.dst_ip[2], ip.header.dst_ip[3]);

        // IPv4: validate checksum only if the UDP checksum field is non-zero.
        // We need to peek at the checksum field (byte offset 6-7 in the UDP
        // header) to decide.
        bool validate_checksum = false;
        if (ip.header.payload_length >= 8 && ip.payload != nullptr) {
            const std::uint16_t udp_checksum =
                static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(ip.payload[6]) << 8) |
                    static_cast<std::uint16_t>(ip.payload[7]));
            validate_checksum = (udp_checksum != 0);
        }

        const UdpParseResult udp = ParseUdpDatagram(
            src, dst, ip.payload, ip.header.payload_length, validate_checksum);
        if (udp.error == UdpParseError::BadChecksum) {
            result.error = UdpInputResult::Error::BadChecksum;
            return result;
        }
        if (udp.error != UdpParseError::None) {
            result.error = UdpInputResult::Error::MalformedUdp;
            return result;
        }
        result.datagram = udp;
        return result;
    } else if (version == 6) {
        const Ipv6ParseResult ip = ParseIpv6(packet, length);
        if (ip.error != Ipv6ParseResult::Error::None) {
            result.error = UdpInputResult::Error::MalformedIp;
            return result;
        }
        if (ip.final_next_header != 17) {
            result.error = UdpInputResult::Error::NotUdp;
            return result;
        }
        if (ip.fragment_header_present) {
            result.error = UdpInputResult::Error::MalformedIp;
            return result;
        }
        const IpAddress src = IpAddress::Ipv6(ip.header.src_ip);
        const IpAddress dst = IpAddress::Ipv6(ip.header.dst_ip);

        // IPv6: checksum is always mandatory.
        const UdpParseResult udp = ParseUdpDatagram(
            src, dst, ip.payload, ip.payload_length, true);
        if (udp.error == UdpParseError::BadChecksum) {
            result.error = UdpInputResult::Error::BadChecksum;
            return result;
        }
        if (udp.error != UdpParseError::None) {
            result.error = UdpInputResult::Error::MalformedUdp;
            return result;
        }
        result.datagram = udp;
        return result;
    } else {
        result.error = UdpInputResult::Error::MalformedIp;
        return result;
    }
}

} // namespace tcpip2
