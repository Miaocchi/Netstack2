#include <cstdint>
#include <cstring>

#include "Test.h"
#include <ip/checksum.h>

using namespace tcpip2;

TCPIP2_TEST(ChecksumZeroLength) {
    std::uint16_t cs = InternetChecksum(nullptr, 0, 0);
    // Sum of zero bytes = 0, ~0 = 0xFFFF
    TCPIP2_EXPECT_EQ(std::uint16_t{0xFFFF}, cs);
}

TCPIP2_TEST(ChecksumSingleByte) {
    const std::uint8_t data[] = {0xAB};
    // Treated as 0xAB00 (padded with zero on the right)
    // Sum = 0xAB00, fold = 0xAB00, ~0xAB00 = 0x54FF
    std::uint16_t cs = InternetChecksum(data, 1, 0);
    TCPIP2_EXPECT_EQ(std::uint16_t{0x54FF}, cs);
}

TCPIP2_TEST(ChecksumTwoBytes) {
    const std::uint8_t data[] = {0x00, 0x00};
    std::uint16_t cs = InternetChecksum(data, 2, 0);
    // Sum = 0, ~0 = 0xFFFF
    TCPIP2_EXPECT_EQ(std::uint16_t{0xFFFF}, cs);
}

TCPIP2_TEST(ChecksumSelfVerifying) {
    // Build a simple 20-byte IPv4-like header with a valid checksum.
    // First compute checksum, place it, then verify it reads as 0.
    std::uint8_t hdr[20] = {};
    hdr[0] = 0x45;  // version 4, IHL 5
    hdr[1] = 0x00;
    hdr[2] = 0x00;  // total length = 20
    hdr[3] = 0x14;
    hdr[4] = 0x00;  // identification
    hdr[5] = 0x01;
    hdr[6] = 0x00;  // flags/frag
    hdr[7] = 0x00;
    hdr[8] = 0x40;  // TTL = 64
    hdr[9] = 0x06;  // protocol = TCP
    // checksum at [10..11] = 0 for now
    hdr[12] = 0x0A;  // src 10.0.0.1
    hdr[13] = 0x00;
    hdr[14] = 0x00;
    hdr[15] = 0x01;
    hdr[16] = 0x0A;  // dst 10.0.0.2
    hdr[17] = 0x00;
    hdr[18] = 0x00;
    hdr[19] = 0x02;

    // Compute checksum over header (with checksum field = 0)
    std::uint16_t cs = InternetChecksum(hdr, 20, 0);
    // Place it
    hdr[10] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    hdr[11] = static_cast<std::uint8_t>(cs & 0xFF);

    // Verify: checksum over header with embedded checksum should be 0
    std::uint16_t verify = InternetChecksum(hdr, 20, 0);
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, verify);
}

TCPIP2_TEST(ChecksumSeedAccumulation) {
    // Verify that computing checksum in two parts (with seed) matches
    // computing it all at once.
    const std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    // All at once
    std::uint16_t all = InternetChecksum(data, 6, 0);

    // In two parts: first 2 bytes, then 4 bytes with seed
    std::uint32_t seed = 0;
    // Accumulate first 2 bytes as a word
    seed += static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
    std::uint16_t partial = InternetChecksum(data + 2, 4, seed);

    TCPIP2_EXPECT_EQ(all, partial);
}

TCPIP2_TEST(Ipv4PseudoHeaderSeedKnownValue) {
    // src = 10.0.0.1, dst = 10.0.0.2, protocol = TCP(6), transport_len = 20
    const std::uint8_t src[4] = {0x0A, 0x00, 0x00, 0x01};
    const std::uint8_t dst[4] = {0x0A, 0x00, 0x00, 0x02};

    std::uint32_t seed = Ipv4PseudoHeaderSeed(src, dst, 6, 20);

    // Manual computation:
    // word 0: 0x0A00 = 2560
    // word 1: 0x0001 = 1
    // word 2: 0x0A00 = 2560
    // word 3: 0x0002 = 2
    // word 4: 0x0006 = 6
    // word 5: 0x0014 = 20
    // Sum = 2560 + 1 + 2560 + 2 + 6 + 20 = 5149 = 0x141D
    TCPIP2_EXPECT_EQ(std::uint32_t{0x141D}, seed);
}

TCPIP2_TEST(Ipv4PseudoHeaderChecksumVerifies) {
    // Build a TCP segment with correct checksum using the pseudo-header seed,
    // then verify it with InternetChecksum.

    // Minimal TCP SYN: 20 bytes, src_port=1234, dst_port=80
    std::uint8_t tcp[20] = {};
    tcp[0] = 0x04;  // src port high
    tcp[1] = 0xD2;  // src port low (1234)
    tcp[2] = 0x00;  // dst port high
    tcp[3] = 0x50;  // dst port low (80)
    // seq = 0
    // ack = 0
    tcp[12] = 0x50; // data offset 5
    tcp[13] = 0x02; // SYN
    // window, checksum, urgent all 0

    const std::uint8_t src[4] = {0xC0, 0xA8, 0x01, 0x01}; // 192.168.1.1
    const std::uint8_t dst[4] = {0xC0, 0xA8, 0x01, 0x02}; // 192.168.1.2

    std::uint32_t seed = Ipv4PseudoHeaderSeed(src, dst, 6, 20);
    std::uint16_t cs = InternetChecksum(tcp, 20, seed);
    // Place checksum
    tcp[16] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    tcp[17] = static_cast<std::uint8_t>(cs & 0xFF);

    // Verify: should read as 0
    seed = Ipv4PseudoHeaderSeed(src, dst, 6, 20);
    std::uint16_t verify = InternetChecksum(tcp, 20, seed);
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, verify);
}

TCPIP2_TEST(Ipv6PseudoHeaderSeedKnownValue) {
    // src = ::1 (all zeros except last byte = 1)
    // dst = ::2 (all zeros except last byte = 2)
    std::uint8_t src[16] = {};
    src[15] = 1;
    std::uint8_t dst[16] = {};
    dst[15] = 2;

    // protocol = TCP(6), upper_len = 20
    std::uint32_t seed = Ipv6PseudoHeaderSeed(src, dst, 6, 20);

    // Manual computation (big-endian 16-bit words):
    // src: 15 words of 0x0000 + word at i=14: (src[14]<<8)|src[15] = (0<<8)|1 = 1
    // dst: 15 words of 0x0000 + word at i=14: (dst[14]<<8)|dst[15] = (0<<8)|2 = 2
    // upper_len = 20: high word 0x0000 + low word 0x0014 = 0 + 20 = 20
    // protocol: 0x0006 = 6
    // Sum = 1 + 2 + 0 + 20 + 6 = 29 = 0x001D
    TCPIP2_EXPECT_EQ(std::uint32_t{0x001D}, seed);
}

TCPIP2_TEST(Ipv6PseudoHeaderChecksumVerifies) {
    // Build a minimal TCP segment and verify checksum using IPv6 pseudo-header.
    std::uint8_t tcp[20] = {};
    tcp[0] = 0x04;  // src port 1234
    tcp[1] = 0xD2;
    tcp[2] = 0x00;  // dst port 80
    tcp[3] = 0x50;
    tcp[12] = 0x50; // data offset 5
    tcp[13] = 0x02; // SYN

    std::uint8_t src[16] = {};
    src[15] = 1;
    std::uint8_t dst[16] = {};
    dst[15] = 2;

    std::uint32_t seed = Ipv6PseudoHeaderSeed(src, dst, 6, 20);
    std::uint16_t cs = InternetChecksum(tcp, 20, seed);
    tcp[16] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
    tcp[17] = static_cast<std::uint8_t>(cs & 0xFF);

    // Verify
    seed = Ipv6PseudoHeaderSeed(src, dst, 6, 20);
    std::uint16_t verify = InternetChecksum(tcp, 20, seed);
    TCPIP2_EXPECT_EQ(std::uint16_t{0}, verify);
}

TCPIP2_TEST_MAIN();
