#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/icmpv6.h>
#include <ip/checksum.h>

using namespace tcpip2;

namespace {

/// Build an ICMPv6 message with a 4-byte header and optional body.
static std::vector<std::uint8_t> BuildIcmpv6(std::uint8_t type, std::uint8_t code,
                                             const std::vector<std::uint8_t> &body) {
    std::vector<std::uint8_t> msg(4 + body.size(), 0);
    msg[0] = type;
    msg[1] = code;
    // checksum = 0 (not verified by parser)
    std::memcpy(msg.data() + 4, body.data(), body.size());
    return msg;
}

} // namespace

TCPIP2_TEST(TooShort) {
    // 7 bytes — fewer than the minimum 8
    std::vector<std::uint8_t> msg(7, 0);
    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::TooShort);
}

TCPIP2_TEST(EchoRequest) {
    // type=128, code=0, id=0x1234, seq=0x0005, payload = "hello"
    std::vector<std::uint8_t> body = {0x12, 0x34, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
    auto msg = BuildIcmpv6(Icmpv6Type::EchoRequest, 0, body);

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(Icmpv6Type::EchoRequest, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, result.header.code);
    TCPIP2_EXPECT_EQ(std::uint16_t{0x1234}, result.header.id);
    TCPIP2_EXPECT_EQ(std::uint16_t{0x0005}, result.header.sequence);
    TCPIP2_EXPECT_EQ(std::size_t{5}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == msg.data() + 8);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.header.quoted_payload_len);
}

TCPIP2_TEST(EchoReply) {
    // type=129, code=0, id=0xABCD, seq=0x0100, no payload
    std::vector<std::uint8_t> body = {0xAB, 0xCD, 0x01, 0x00};
    auto msg = BuildIcmpv6(Icmpv6Type::EchoReply, 0, body);

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(Icmpv6Type::EchoReply, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint16_t{0xABCD}, result.header.id);
    TCPIP2_EXPECT_EQ(std::uint16_t{0x0100}, result.header.sequence);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
    TCPIP2_EXPECT_TRUE(result.payload == msg.data() + 8);
}

TCPIP2_TEST(DestinationUnreachable) {
    // type=1, code=4 (PortUnreachable), quoted packet = 40 bytes of zeros
    std::vector<std::uint8_t> quoted(40, 0);
    // bytes [4..7] are unused (zeros)
    std::vector<std::uint8_t> body(4, 0);
    body.insert(body.end(), quoted.begin(), quoted.end());
    auto msg = BuildIcmpv6(Icmpv6Type::DestinationUnreachable, Icmpv6DestUnreachableCode::PortUnreachable, body);

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(Icmpv6Type::DestinationUnreachable, result.header.type);
    TCPIP2_EXPECT_EQ(Icmpv6DestUnreachableCode::PortUnreachable, result.header.code);
    TCPIP2_EXPECT_EQ(std::size_t{40}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
    TCPIP2_EXPECT_TRUE(result.payload == nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
}

TCPIP2_TEST(PacketTooBig) {
    // type=2, code=0, MTU=1280, quoted packet = 20 bytes
    std::uint32_t mtu = 1280;
    std::vector<std::uint8_t> body(4, 0);
    body[0] = static_cast<std::uint8_t>((mtu >> 24) & 0xFF);
    body[1] = static_cast<std::uint8_t>((mtu >> 16) & 0xFF);
    body[2] = static_cast<std::uint8_t>((mtu >> 8) & 0xFF);
    body[3] = static_cast<std::uint8_t>(mtu & 0xFF);
    std::vector<std::uint8_t> quoted(20, 0);
    body.insert(body.end(), quoted.begin(), quoted.end());
    auto msg = BuildIcmpv6(Icmpv6Type::PacketTooBig, 0, body);

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(Icmpv6Type::PacketTooBig, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint32_t{1280}, result.header.mtu);
    TCPIP2_EXPECT_EQ(std::size_t{20}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
}

TCPIP2_TEST(TimeExceeded) {
    // type=3, code=0, quoted packet = 48 bytes
    std::vector<std::uint8_t> quoted(48, 0);
    std::vector<std::uint8_t> body(4, 0); // unused
    body.insert(body.end(), quoted.begin(), quoted.end());
    auto msg = BuildIcmpv6(Icmpv6Type::TimeExceeded, 0, body);

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(Icmpv6Type::TimeExceeded, result.header.type);
    TCPIP2_EXPECT_EQ(std::size_t{48}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
}

TCPIP2_TEST(ParameterProblem) {
    // type=4, code=0, pointer=6, quoted packet = 40 bytes
    std::uint32_t pointer = 6;
    std::vector<std::uint8_t> body(4, 0);
    body[0] = static_cast<std::uint8_t>((pointer >> 24) & 0xFF);
    body[1] = static_cast<std::uint8_t>((pointer >> 16) & 0xFF);
    body[2] = static_cast<std::uint8_t>((pointer >> 8) & 0xFF);
    body[3] = static_cast<std::uint8_t>(pointer & 0xFF);
    std::vector<std::uint8_t> quoted(40, 0);
    body.insert(body.end(), quoted.begin(), quoted.end());
    auto msg = BuildIcmpv6(Icmpv6Type::ParameterProblem, 0, body);

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(Icmpv6Type::ParameterProblem, result.header.type);
    TCPIP2_EXPECT_EQ(std::uint32_t{6}, result.header.pointer);
    TCPIP2_EXPECT_EQ(std::size_t{40}, result.header.quoted_payload_len);
    TCPIP2_EXPECT_TRUE(result.header.quoted_payload == msg.data() + 8);
}

TCPIP2_TEST(ExactlyEightBytes) {
    // Exactly 8 bytes: echo request with no payload
    std::vector<std::uint8_t> body = {0x00, 0x01, 0x00, 0x01}; // id=1, seq=1
    auto msg = BuildIcmpv6(Icmpv6Type::EchoRequest, 0, body);
    TCPIP2_EXPECT_EQ(std::size_t{8}, msg.size());

    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_EQ(std::uint16_t{1}, result.header.id);
    TCPIP2_EXPECT_EQ(std::uint16_t{1}, result.header.sequence);
    TCPIP2_EXPECT_EQ(std::size_t{0}, result.payload_length);
}

TCPIP2_TEST(ChecksumOkPlaceholder) {
    // checksum_ok should default to true (placeholder)
    std::vector<std::uint8_t> body = {0, 0, 0, 0};
    auto msg = BuildIcmpv6(Icmpv6Type::EchoRequest, 0, body);
    auto result = ParseIcmpv6(msg.data(), msg.size());
    TCPIP2_EXPECT_TRUE(result.error == Icmpv6ParseResult::Error::None);
    TCPIP2_EXPECT_TRUE(result.checksum_ok);
}

TCPIP2_TEST(VerifyIcmpv6ChecksumValid) {
    // Build an Echo Request, compute correct ICMPv6 checksum, verify it.
    std::uint8_t src[16] = {};
    src[15] = 1;
    std::uint8_t dst[16] = {};
    dst[15] = 2;

    // 8-byte echo request: type=128, code=0, checksum=0, id=1, seq=1
    std::vector<std::uint8_t> msg = {128, 0, 0, 0, 0, 1, 0, 1};

    // Compute checksum
    std::uint32_t seed = Ipv6PseudoHeaderSeed(src, dst, 58, 8);
    std::uint16_t cs = InternetChecksum(msg.data(), 8, seed);
    msg[2] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(cs & 0xFF);

    TCPIP2_EXPECT_TRUE(VerifyIcmpv6Checksum(msg.data(), 8, src, dst));
}

TCPIP2_TEST(VerifyIcmpv6ChecksumInvalid) {
    // Same message but with wrong checksum — should fail
    std::uint8_t src[16] = {};
    src[15] = 1;
    std::uint8_t dst[16] = {};
    dst[15] = 2;

    std::vector<std::uint8_t> msg = {128, 0, 0xFF, 0xFF, 0, 1, 0, 1};
    TCPIP2_EXPECT_FALSE(VerifyIcmpv6Checksum(msg.data(), 8, src, dst));
}

TCPIP2_TEST_MAIN();
