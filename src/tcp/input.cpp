#include <tcp/input.h>

#include <ip/ipv4.h>
#include <ip/ipv6.h>

namespace tcpip2 {

TcpInputResult ParseIpTcpPacket(const std::uint8_t* packet,
                                std::size_t length) noexcept {
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
            IpAddress::Ipv4(ip.header.src_ip[0], ip.header.src_ip[1],
                            ip.header.src_ip[2], ip.header.src_ip[3]),
            IpAddress::Ipv4(ip.header.dst_ip[0], ip.header.dst_ip[1],
                            ip.header.dst_ip[2], ip.header.dst_ip[3]),
            ip.payload, ip.header.payload_length);
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
        tcp = ParseTcpSegment(
            IpAddress::Ipv6(ip.header.src_ip), IpAddress::Ipv6(ip.header.dst_ip),
            ip.payload, ip.payload_length);
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

} // namespace tcpip2
