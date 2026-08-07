#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/checksum.h>
#include <ip/icmpv4.h>

using namespace tcpip2;

namespace {

/// Build an ICMP Echo request with a valid checksum and optional payload.
static std::vector<std::uint8_t> BuildEcho(std::uint8_t type = Icmpv4Type::Echo,
                                           std::uint16_t id = 0x1234,
                                           std::uint16_t seq = 1,
                                           const std::vector<std::uint8_t>& payload = {}) {
    std::vector<std::uint8_t> msg(8 + payload.size(), 0);
    msg[0] = type;
    msg[1] = 0; // code
    msg[2] = 0; msg[3] = 0; // checksum placeholder
    msg[4] = static_cast<std::uint8_t>((id >> 8) & 0xFF);
    msg[5] = static_cast<std::uint8_t>(id & 0xFF);
    msg[6] = static_cast<std::uint8_t>((seq >> 8) & 0xFF);
    msg[7] = static_cast<std::uint8_t>(seq & 0xFF);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        msg[8 + i] = payload[i];
    }

    std::uint16_t cs = InternetChecksum(msg.data(), msg.size(), 0);
    msg[2] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(cs & 0xFF);
    return msg;
}

/// Build a Destination Unreachable message with quoted payload.
static std::vector<std::uint8_t> BuildDestUnreachable(
    std::uint8_t code = Icmpv4DestUnreachableCode::Port,
    std::uint16_t mtu = 0,
    const std::vector<std::uint8_t>& quoted = {}) {
    std::vector<std::uint8_t> msg(8 + quoted.size(), 0);
    msg[0] = Icmpv4Type::DestinationUnreachable;
    msg[1] = code;
    msg[2] = 0; msg[3] = 0; // checksum placeholder
    if (code == Icmpv4DestUnreachableCode::FragmentationNeeded) {
        msg[4] = 0; msg[5] = 0; // unused
        msg[6] = static_cast<std::uint8_t>((mtu >> 8) & 0xFF);
        msg[7] = static_cast<std::uint8_t>(mtu & 0xFF);
    }
    for (std::size_t i = 0; i < quoted.size(); ++i) {
        msg[8 + i] = quoted[i];
    }

    std::uint16_t cs = InternetChecksum(msg.data(), msg.size(), 0);
    msg[2] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(cs & 0xFF);
    return msg;
}

} // namespace

TCPIP2_TEST(ValidEchoRequest) {
    auto msg = BuildEcho(Icmpv4Type::Echo, 0x1234, 1);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::Echo}, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, result.header.code);
    TCPIP2_EXPECT_EQ(std::uint16_t{0x1234}, result.header.id);
    TCPIP2_EXPECT_EQ(std::uint16_t{1}, result.header.sequence);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == msg.data() + 8);
}

TCPIP2_TEST(ValidEchoRequestWithPayload) {
    std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    auto msg = BuildEcho(Icmpv4Type::Echo, 0xABCD, 42, payload);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::Echo}, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint16_t{0xABCD}, result.header.id);
    TCPIP2_EXPECT_EQ(std::uint16_t{42}, result.header.sequence);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_EQ(std::size_t{4}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == msg.data() + 8);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xDE}, result.payload[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xEF}, result.payload[3]);
}

TCPIP2_TEST(ValidEchoReply) {
    auto msg = BuildEcho(Icmpv4Type::EchoReply, 0x5678, 99);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::EchoReply}, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint16_t{0x5678}, result.header.id);
    TCPIP2_EXPECT_EQ(std::uint16_t{99}, result.header.sequence);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
}

TCPIP2_TEST(TooShort) {
    std::vector<std::uint8_t> msg(7, 0);
    msg[0] = Icmpv4Type::Echo;

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::TooShort);
}

TCPIP2_TEST(BadChecksum) {
    auto msg = BuildEcho(Icmpv4Type::Echo, 0x1234, 1);
    // Flip a bit in the id field to corrupt the checksum
    msg[4] = static_cast<std::uint8_t>(msg[4] ^ 0x01);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    // Parsing still succeeds — bad checksum is reported via the flag.
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_FALSE(result.checksum_ok);
}

TCPIP2_TEST(DestUnreachablePort) {
    std::vector<std::uint8_t> quoted = {0x45, 0x00, 0x00, 0x14}; // simulated IP header start
    auto msg = BuildDestUnreachable(Icmpv4DestUnreachableCode::Port, 0, quoted);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::DestinationUnreachable}, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4DestUnreachableCode::Port}, result.header.code);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_EQ(std::size_t{4}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x45}, result.header.quoted_payload[0]);
}

TCPIP2_TEST(DestUnreachableFragNeeded) {
    auto msg = BuildDestUnreachable(Icmpv4DestUnreachableCode::FragmentationNeeded, 1492);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::DestinationUnreachable}, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4DestUnreachableCode::FragmentationNeeded}, result.header.code);
    TCPIP2_EXPECT_EQ(std::uint16_t{1492}, result.header.mtu);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.header.quoted_payload_len);
}

TCPIP2_TEST(TimeExceeded) {
    std::vector<std::uint8_t> quoted = {0x45, 0x00};
    std::vector<std::uint8_t> msg(8 + quoted.size(), 0);
    msg[0] = Icmpv4Type::TimeExceeded;
    msg[1] = 0; // code
    msg[2] = 0; msg[3] = 0;
    msg[4] = 0; msg[5] = 0; msg[6] = 0; msg[7] = 0; // unused
    msg[8] = 0x45; msg[9] = 0x00;

    std::uint16_t cs = InternetChecksum(msg.data(), msg.size(), 0);
    msg[2] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(cs & 0xFF);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::TimeExceeded}, result.header.type);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_EQ(std::size_t{2}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
}

TCPIP2_TEST(ParameterProblem) {
    std::vector<std::uint8_t> quoted = {0x45, 0x00};
    std::vector<std::uint8_t> msg(8 + quoted.size(), 0);
    msg[0] = Icmpv4Type::ParameterProblem;
    msg[1] = 0; // code
    msg[2] = 0; msg[3] = 0;
    msg[4] = 5; // pointer = 5
    msg[5] = 0; msg[6] = 0; msg[7] = 0; // unused
    msg[8] = 0x45; msg[9] = 0x00;

    std::uint16_t cs = InternetChecksum(msg.data(), msg.size(), 0);
    msg[2] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(cs & 0xFF);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::uint8_t{Icmpv4Type::ParameterProblem}, result.header.type);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
    TCPIP2_EXPECT_EQ(std::size_t{2}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
}

TCPIP2_TEST(MinimalEightByteEcho) {
    // Exactly 8 bytes — no payload, should succeed.
    auto msg = BuildEcho(Icmpv4Type::Echo, 0x0001, 0);

    auto result = ParseIcmpv4(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv4ParseError::None);
    TCPIP2_EXPECT_EQ(std::size_t{8}, msg.size());
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
}

TCPIP2_TEST_MAIN();
