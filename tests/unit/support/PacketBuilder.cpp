/**
 * @file PacketBuilder.cpp
 * @brief IPv4/TCP wire-format builder and parser.
 * @license GPL-3.0
 */

#include "PacketBuilder.h"

#include <cstdint>

namespace tcpip2 {
namespace test {

namespace {

// Internet checksum (RFC 1071). @p sum seeds a TCP pseudo-header accumulation.
std::uint16_t Checksum(const std::uint8_t* data, std::size_t len, std::uint32_t sum) {
    std::uint32_t acc = sum;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        const std::uint16_t word =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1]);
        acc += word;
    }
    if (i < len) {
        acc += static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[i]) << 8);
    }
    while ((acc >> 16) != 0) {
        acc = (acc & 0xFFFFu) + (acc >> 16);
    }
    return static_cast<std::uint16_t>(~acc & 0xFFFFu);
}

std::uint16_t Read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t Read32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

void Append16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

void Append32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

} // namespace

std::vector<std::uint8_t> PacketBuilder::BuildIpv4Tcp(std::uint32_t src_ip,
                                                      std::uint32_t dst_ip,
                                                      std::uint16_t src_port,
                                                      std::uint16_t dst_port,
                                                      std::uint32_t seq,
                                                      std::uint32_t ack,
                                                      std::uint8_t flags,
                                                      const std::vector<std::uint8_t>& payload,
                                                      std::uint16_t ip_id,
                                                      std::uint8_t ttl) {
    const std::size_t tcp_len = 20 + payload.size();
    const std::size_t total_len = 20 + tcp_len;

    std::vector<std::uint8_t> pkt;
    pkt.reserve(total_len);

    // IPv4 header (20 bytes, checksum field zeroed for now).
    pkt.push_back(0x45); // version 4, IHL 5
    pkt.push_back(0x00); // DSCP/ECN
    Append16(pkt, static_cast<std::uint16_t>(total_len));
    Append16(pkt, ip_id);
    pkt.push_back(0x00); // flags/frag offset high byte
    pkt.push_back(0x00); // frag offset low byte
    pkt.push_back(ttl);
    pkt.push_back(0x06); // protocol TCP
    Append16(pkt, 0);    // checksum placeholder
    Append32(pkt, src_ip);
    Append32(pkt, dst_ip);

    // TCP header (20 bytes, checksum field zeroed for now).
    Append16(pkt, src_port);
    Append16(pkt, dst_port);
    Append32(pkt, seq);
    Append32(pkt, ack);
    pkt.push_back(0x50); // data offset 5, reserved bits 0
    pkt.push_back(static_cast<std::uint8_t>(flags & 0x3F));
    Append16(pkt, 65535); // window
    Append16(pkt, 0);      // checksum placeholder
    Append16(pkt, 0);      // urgent pointer

    for (std::uint8_t b : payload) pkt.push_back(b);

    // TCP checksum over pseudo-header + TCP segment (padded to even length).
    std::uint32_t sum = 0;
    const std::uint8_t pseudo[12] = {
        static_cast<std::uint8_t>((src_ip >> 24) & 0xFFu),
        static_cast<std::uint8_t>((src_ip >> 16) & 0xFFu),
        static_cast<std::uint8_t>((src_ip >> 8) & 0xFFu),
        static_cast<std::uint8_t>(src_ip & 0xFFu),
        static_cast<std::uint8_t>((dst_ip >> 24) & 0xFFu),
        static_cast<std::uint8_t>((dst_ip >> 16) & 0xFFu),
        static_cast<std::uint8_t>((dst_ip >> 8) & 0xFFu),
        static_cast<std::uint8_t>(dst_ip & 0xFFu),
        0,
        6,
        static_cast<std::uint8_t>((tcp_len >> 8) & 0xFFu),
        static_cast<std::uint8_t>(tcp_len & 0xFFu),
    };
    sum = 0;
    for (std::size_t i = 0; i + 1 < sizeof(pseudo); i += 2) {
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(pseudo[i]) << 8) | pseudo[i + 1]);
    }
    const std::uint16_t tcp_sum = Checksum(pkt.data() + 20, tcp_len, sum);
    pkt[36] = static_cast<std::uint8_t>((tcp_sum >> 8) & 0xFFu);
    pkt[37] = static_cast<std::uint8_t>(tcp_sum & 0xFFu);

    // IPv4 header checksum over the 20-byte header.
    pkt[10] = 0;
    pkt[11] = 0;
    const std::uint16_t ip_sum = Checksum(pkt.data(), 20, 0);
    pkt[10] = static_cast<std::uint8_t>((ip_sum >> 8) & 0xFFu);
    pkt[11] = static_cast<std::uint8_t>(ip_sum & 0xFFu);

    return pkt;
}

ParsedPacket PacketParser::ParseIpv4Tcp(const std::vector<std::uint8_t>& bytes) {
    ParsedPacket out;
    if (bytes.size() < 40) return out;
    if ((bytes[0] >> 4) != 4) return out;
    if (bytes[9] != 6) return out; // protocol TCP
    const std::size_t ihl = static_cast<std::size_t>(bytes[0] & 0x0F) * 4;
    if (ihl < 20 || bytes.size() < ihl + 20) return out;
    const std::size_t tcp_off = ihl;
    const std::uint8_t tcp_hdr_len = static_cast<std::uint8_t>((bytes[tcp_off + 12] >> 4) * 4);
    if (bytes.size() < tcp_off + tcp_hdr_len) return out;

    out.ip_checksum_ok = Checksum(bytes.data(), ihl, 0) == 0;
    out.src_ip = Read32(bytes.data() + 12);
    out.dst_ip = Read32(bytes.data() + 16);
    out.ip_id = Read16(bytes.data() + 4);

    out.src_port = Read16(bytes.data() + tcp_off);
    out.dst_port = Read16(bytes.data() + tcp_off + 2);
    out.seq = Read32(bytes.data() + tcp_off + 4);
    out.ack = Read32(bytes.data() + tcp_off + 8);
    out.flags = static_cast<std::uint8_t>(bytes[tcp_off + 13] & 0x3F);
    out.window = Read16(bytes.data() + tcp_off + 14);

    // Verify TCP checksum via pseudo-header accumulation.
    const std::size_t tcp_len = bytes.size() - tcp_off;
    std::uint32_t sum = 0;
    const std::uint8_t pseudo[12] = {
        bytes[12], bytes[13], bytes[14], bytes[15],
        bytes[16], bytes[17], bytes[18], bytes[19],
        0, 6,
        static_cast<std::uint8_t>((tcp_len >> 8) & 0xFFu),
        static_cast<std::uint8_t>(tcp_len & 0xFFu),
    };
    for (std::size_t i = 0; i + 1 < sizeof(pseudo); i += 2) {
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(pseudo[i]) << 8) | pseudo[i + 1]);
    }
    out.tcp_checksum_ok = Checksum(bytes.data() + tcp_off, tcp_len, sum) == 0;

    out.valid = out.ip_checksum_ok && out.tcp_checksum_ok;
    out.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(tcp_off + tcp_hdr_len),
                       bytes.end());
    return out;
}

} // namespace test
} // namespace tcpip2
