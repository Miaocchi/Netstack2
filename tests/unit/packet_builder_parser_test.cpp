#include <cstdint>
#include <vector>

#include "PacketBuilder.h"
#include "Test.h"

using namespace tcpip2;
using namespace tcpip2::test;

TCPIP2_TEST(RoundTripSyn) {
    const std::uint32_t src = 0x0A000001u;
    const std::uint32_t dst = 0x0A000002u;
    std::vector<std::uint8_t> bytes =
        PacketBuilder::BuildIpv4Tcp(src, dst, 1234, 443, 1000, 0, TcpFlags::Syn, {});
    TCPIP2_EXPECT_EQ(std::size_t{40}, bytes.size());
    ParsedPacket p = PacketParser::ParseIpv4Tcp(bytes);
    TCPIP2_EXPECT_TRUE(p.valid);
    TCPIP2_EXPECT_TRUE(p.ip_checksum_ok);
    TCPIP2_EXPECT_TRUE(p.tcp_checksum_ok);
    TCPIP2_EXPECT_EQ(src, p.src_ip);
    TCPIP2_EXPECT_EQ(dst, p.dst_ip);
    TCPIP2_EXPECT_EQ(std::uint16_t{1234}, p.src_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{443}, p.dst_port);
    TCPIP2_EXPECT_EQ(std::uint32_t{1000}, p.seq);
    TCPIP2_EXPECT_EQ(std::uint32_t{0}, p.ack);
    TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(TcpFlags::Syn), p.flags);
    TCPIP2_EXPECT_EQ(std::size_t{0}, p.payload.size());
}

TCPIP2_TEST(RoundTripWithPayload) {
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05,
                                               'h',  'e',  'l',  'l',  'o'};
    const std::vector<std::uint8_t> bytes = PacketBuilder::BuildIpv4Tcp(
        0xC0A80001u, 0xC0A80064u, 80, 8080, 1, 2,
        static_cast<std::uint8_t>(TcpFlags::Ack | TcpFlags::Psh), payload, 7, 32);
    ParsedPacket p = PacketParser::ParseIpv4Tcp(bytes);
    TCPIP2_EXPECT_TRUE(p.valid);
    TCPIP2_EXPECT_TRUE(p.ip_checksum_ok);
    TCPIP2_EXPECT_TRUE(p.tcp_checksum_ok);
    TCPIP2_EXPECT_EQ(std::uint16_t{80}, p.src_port);
    TCPIP2_EXPECT_EQ(std::uint16_t{8080}, p.dst_port);
    TCPIP2_EXPECT_EQ(std::uint32_t{1}, p.seq);
    TCPIP2_EXPECT_EQ(std::uint32_t{2}, p.ack);
    TCPIP2_EXPECT_EQ(std::uint16_t{7}, p.ip_id);
    TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(TcpFlags::Ack | TcpFlags::Psh), p.flags);
    TCPIP2_EXPECT_EQ(std::size_t{10}, p.payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        TCPIP2_EXPECT_EQ(payload[i], p.payload[i]);
    }
}

TCPIP2_TEST(RoundTripRstFin) {
    const std::vector<std::uint8_t> bytes = PacketBuilder::BuildIpv4Tcp(
        0, 0, 1111, 2222, 0xFFFFFFFFu, 0x7FFFFFFFu,
        static_cast<std::uint8_t>(TcpFlags::Rst | TcpFlags::Fin), {0xAB});
    ParsedPacket p = PacketParser::ParseIpv4Tcp(bytes);
    TCPIP2_EXPECT_TRUE(p.valid);
    TCPIP2_EXPECT_EQ(std::uint32_t{0xFFFFFFFFu}, p.seq);
    TCPIP2_EXPECT_EQ(std::uint32_t{0x7FFFFFFFu}, p.ack);
    TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(TcpFlags::Rst | TcpFlags::Fin), p.flags);
    TCPIP2_EXPECT_EQ(std::size_t{1}, p.payload.size());
    TCPIP2_EXPECT_EQ(std::uint8_t{0xAB}, p.payload[0]);
}

TCPIP2_TEST(TooShortIsInvalid) {
    const std::vector<std::uint8_t> short_bytes(20, 0);
    ParsedPacket p = PacketParser::ParseIpv4Tcp(short_bytes);
    TCPIP2_EXPECT_FALSE(p.valid);
}

TCPIP2_TEST(TruncatedPayloadFailsChecksum) {
    std::vector<std::uint8_t> bytes =
        PacketBuilder::BuildIpv4Tcp(1, 2, 3, 4, 5, 6, TcpFlags::Ack, {0xDE, 0xAD});
    bytes.pop_back();
    ParsedPacket p = PacketParser::ParseIpv4Tcp(bytes);
    TCPIP2_EXPECT_FALSE(p.valid);
    TCPIP2_EXPECT_FALSE(p.tcp_checksum_ok);
}

TCPIP2_TEST(WrongProtocolIsInvalid) {
    std::vector<std::uint8_t> bytes =
        PacketBuilder::BuildIpv4Tcp(1, 2, 3, 4, 5, 6, TcpFlags::Ack, {0x01});
    bytes[9] = 0x11; // UDP protocol number
    ParsedPacket p = PacketParser::ParseIpv4Tcp(bytes);
    TCPIP2_EXPECT_FALSE(p.valid);
}

TCPIP2_TEST_MAIN();
