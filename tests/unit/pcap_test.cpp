#include <cstdint>
#include <vector>

#include "PacketBuilder.h"
#include "Pcap.h"
#include "Test.h"

using namespace tcpip2;
using namespace tcpip2::test;

TCPIP2_TEST(PcapHeaderFormat) {
    PcapWriter w;
    TCPIP2_EXPECT_EQ(std::size_t{0}, w.Bytes().size());
    TCPIP2_EXPECT_EQ(std::size_t{0}, w.RecordCount());

    const std::vector<std::uint8_t> pkt =
        PacketBuilder::BuildIpv4Tcp(1, 2, 3, 4, 5, 6, TcpFlags::Ack, {0xAA, 0xBB});
    w.Append(0, pkt);
    TCPIP2_EXPECT_EQ(std::size_t{1}, w.RecordCount());
    const std::vector<std::uint8_t>& bytes = w.Bytes();
    TCPIP2_EXPECT_EQ(std::size_t{24 + 16 + pkt.size()}, bytes.size());

    // magic 0xa1b2c3d4 little-endian
    TCPIP2_EXPECT_EQ(std::uint8_t{0xd4}, bytes[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xc3}, bytes[1]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xb2}, bytes[2]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xa1}, bytes[3]);
    // version 2.4
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, bytes[4]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, bytes[5]);
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, bytes[6]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, bytes[7]);
    // snaplen 65535 little-endian at offset 16
    TCPIP2_EXPECT_EQ(std::uint8_t{0xFF}, bytes[16]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xFF}, bytes[17]);
    // LINKTYPE_RAW (101) at offset 20
    TCPIP2_EXPECT_EQ(std::uint8_t{101}, bytes[20]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, bytes[21]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, bytes[22]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, bytes[23]);
    // record incl_len / orig_len = pkt.size() at offsets 32 and 36
    TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(pkt.size() & 0xFFu), bytes[32]);
    TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(pkt.size() & 0xFFu), bytes[36]);
    // packet data starts at offset 40 (IP header version/IHL byte)
    TCPIP2_EXPECT_EQ(std::uint8_t{0x45}, bytes[40]);
    // payload is the final two bytes of the captured packet
    TCPIP2_EXPECT_EQ(std::uint8_t{0xAA}, bytes[24 + 16 + pkt.size() - 2]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xBB}, bytes[24 + 16 + pkt.size() - 1]);
}

TCPIP2_TEST(PcapMultipleRecords) {
    PcapWriter w;
    w.Append(1'000'000, {1, 2, 3});
    w.Append(2'500'000, {4, 5, 6, 7});
    TCPIP2_EXPECT_EQ(std::size_t{2}, w.RecordCount());
    const std::vector<std::uint8_t>& b = w.Bytes();
    TCPIP2_EXPECT_EQ(std::size_t{24 + 16 + 3 + 16 + 4}, b.size());

    // record 1: ts_sec=1, ts_usec=0, incl_len=3
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, b[24]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0}, b[28]);
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, b[32]);
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, b[40]);
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, b[42]);

    // record 2 starts at 24 + 16 + 3 = 43
    const std::size_t r2 = 43;
    TCPIP2_EXPECT_EQ(std::uint8_t{2}, b[r2 + 0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x20}, b[r2 + 4]); // ts_usec low byte (500000)
    TCPIP2_EXPECT_EQ(std::uint8_t{0xA1}, b[r2 + 5]);
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, b[r2 + 8]);    // incl_len
    // record 2 data {4,5,6,7} begins after its 16-byte header
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, b[r2 + 16]);   // first data byte
    TCPIP2_EXPECT_EQ(std::uint8_t{7}, b[r2 + 19]);   // last data byte
}

TCPIP2_TEST(PcapClearResets) {
    PcapWriter w;
    w.Append(0, {1});
    TCPIP2_EXPECT_EQ(std::size_t{1}, w.RecordCount());
    w.Clear();
    TCPIP2_EXPECT_EQ(std::size_t{0}, w.Bytes().size());
    TCPIP2_EXPECT_EQ(std::size_t{0}, w.RecordCount());
}

TCPIP2_TEST_MAIN();
