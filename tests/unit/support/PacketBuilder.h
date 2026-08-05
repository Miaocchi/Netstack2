#pragma once

/**
 * @file PacketBuilder.h
 * @brief Construct and parse IPv4/TCP test packets.
 * @license GPL-3.0
 *
 * PacketBuilder builds wire-format IPv4+TCP packets (with correct IPv4 and
 * TCP checksums) so the IP layer and TCP engine tests can inject realistic
 * traffic without a full stack. PacketParser decodes the same format and
 * independently recomputes both checksums to validate the builder.
 *
 * Endianness: all multi-byte fields on the wire are big-endian; addresses and
 * ports are passed in host byte order.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcpip2 {
namespace test {

struct TcpFlags {
    enum : std::uint8_t {
        Fin = 0x01,
        Syn = 0x02,
        Rst = 0x04,
        Psh = 0x08,
        Ack = 0x10,
        Urg = 0x20,
    };
};

class PacketBuilder final {
public:
    static std::vector<std::uint8_t> BuildIpv4Tcp(
        std::uint32_t src_ip,
        std::uint32_t dst_ip,
        std::uint16_t src_port,
        std::uint16_t dst_port,
        std::uint32_t seq,
        std::uint32_t ack,
        std::uint8_t flags,
        const std::vector<std::uint8_t>& payload,
        std::uint16_t ip_id = 0,
        std::uint8_t ttl = 64);
};

struct ParsedPacket {
    bool valid = false;
    bool ip_checksum_ok = false;
    bool tcp_checksum_ok = false;

    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
    std::uint16_t ip_id = 0;

    std::vector<std::uint8_t> payload;
};

class PacketParser final {
public:
    static ParsedPacket ParseIpv4Tcp(const std::vector<std::uint8_t>& bytes);
};

} // namespace test
} // namespace tcpip2
