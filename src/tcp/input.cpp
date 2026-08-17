#include <tcp/input.h>

#include <cstring>

#include <ip/ipv4.h>
#include <ip/ipv6.h>

namespace tcpip2 {

TcpInputResult ParseIpTcpPacket(const std::uint8_t *packet, std::size_t length) noexcept {
    TcpInputResult result;
    if (packet == nullptr) {
        result.error = TcpInputError::NullData;
        return result;
    }
    if (length == 0) {
        result.error = TcpInputError::MalformedIp;
        return result;
    }

    const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);
    TcpParseResult tcp;
    if (version == 4) {
        const Ipv4ParseResult ip = ParseIpv4(packet, length);
        if (ip.error != Ipv4ParseError::None) {
            result.error = TcpInputError::MalformedIp;
            return result;
        }
        if (!ip.checksum_ok) {
            result.error = TcpInputError::BadIpv4Checksum;
            return result;
        }
        if (ip.header.protocol != 6) {
            result.error = TcpInputError::NotTcp;
            return result;
        }
        if (ip.header.fragment_offset != 0 || (ip.header.flags & 0x01u) != 0) {
            result.error = TcpInputError::FragmentRequiresReassembly;
            return result;
        }
        tcp = ParseTcpSegment(
            IpAddress::Ipv4(ip.header.src_ip[0], ip.header.src_ip[1], ip.header.src_ip[2], ip.header.src_ip[3]),
            IpAddress::Ipv4(ip.header.dst_ip[0], ip.header.dst_ip[1], ip.header.dst_ip[2], ip.header.dst_ip[3]),
            ip.payload, ip.header.payload_length, ip.header.ecn);
    } else if (version == 6) {
        const Ipv6ParseResult ip = ParseIpv6(packet, length);
        if (ip.error != Ipv6ParseResult::Error::None) {
            result.error = TcpInputError::MalformedIp;
            return result;
        }
        if (ip.final_next_header != 6) {
            result.error = TcpInputError::NotTcp;
            return result;
        }
        if (ip.fragment_header_present) {
            result.error = TcpInputError::FragmentRequiresReassembly;
            return result;
        }
        tcp = ParseTcpSegment(IpAddress::Ipv6(ip.header.src_ip), IpAddress::Ipv6(ip.header.dst_ip), ip.payload,
                              ip.payload_length, static_cast<std::uint8_t>(ip.header.traffic_class & 0x03u));
    } else {
        result.error = TcpInputError::UnsupportedIpVersion;
        return result;
    }

    if (tcp.error != TcpParseError::None) {
        result.error = TcpInputError::MalformedTcp;
        result.tcp_error = tcp.error;
        return result;
    }
    result.segment = tcp.segment;
    return result;
}

FragmentInfo ExtractFragmentInfo(const std::uint8_t *packet, std::size_t length) noexcept {
    FragmentInfo info;
    if (packet == nullptr || length == 0)
        return info;

    const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);
    if (version == 4) {
        const Ipv4ParseResult ip = ParseIpv4(packet, length);
        if (ip.error != Ipv4ParseError::None)
            return info;
        info.ip_version = 4;
        std::memcpy(info.src_ip, ip.header.src_ip, 4);
        std::memcpy(info.dst_ip, ip.header.dst_ip, 4);
        info.protocol = ip.header.protocol;
        info.identification = ip.header.identification;
        info.fragment_offset = ip.header.fragment_offset;
        info.more_fragments = (ip.header.flags & 0x01u) != 0;
        info.payload = ip.payload;
        info.payload_length = ip.header.payload_length;
        info.ecn = ip.header.ecn;
        info.valid = true;
    } else if (version == 6) {
        const Ipv6ParseResult ip = ParseIpv6(packet, length);
        if (ip.error != Ipv6ParseResult::Error::None)
            return info;
        if (!ip.fragment_header_present)
            return info;
        info.ip_version = 6;
        std::memcpy(info.src_ip, ip.header.src_ip, 16);
        std::memcpy(info.dst_ip, ip.header.dst_ip, 16);
        info.protocol = ip.final_next_header;
        info.identification = ip.fragment_identification;
        info.fragment_offset = ip.fragment_offset;
        info.more_fragments = ip.fragment_more;
        info.payload = ip.fragment_payload;
        info.payload_length = ip.fragment_payload_length;
        info.ecn = static_cast<std::uint8_t>(ip.header.traffic_class & 0x03u);
        info.valid = true;
    }
    return info;
}

} // namespace tcpip2
