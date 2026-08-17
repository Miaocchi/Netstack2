#include <cstdint>
#include <cstring>

#include "Test.h"
#include <ip/checked.h>

using namespace tcpip2;

// --- CheckedMul tests ---

TCPIP2_TEST(CheckedMulBasic) {
    std::size_t result;
    TCPIP2_EXPECT_TRUE(CheckedMul(std::size_t{3}, std::size_t{4}, result));
    TCPIP2_EXPECT_EQ(std::size_t{12}, result);
}

TCPIP2_TEST(CheckedMulZero) {
    std::size_t result = 999;
    TCPIP2_EXPECT_TRUE(CheckedMul(std::size_t{0}, std::size_t{5}, result));
    TCPIP2_EXPECT_EQ(std::size_t{0}, result);

    result = 999;
    TCPIP2_EXPECT_TRUE(CheckedMul(std::size_t{5}, std::size_t{0}, result));
    TCPIP2_EXPECT_EQ(std::size_t{0}, result);
}

TCPIP2_TEST(CheckedMulOverflow) {
    std::size_t result;
    // SIZE_MAX / 2 + 1 multiplied by 2 should overflow
    std::size_t big = SIZE_MAX / 2 + 1;
    TCPIP2_EXPECT_FALSE(CheckedMul(big, std::size_t{2}, result));
}

TCPIP2_TEST(CheckedMulUint32Overflow) {
    std::uint32_t result;
    TCPIP2_EXPECT_FALSE(CheckedMul(UINT32_MAX, std::uint32_t{2}, result));

    // 0x10000 * 0x8000 = 0x80000000 (fits in uint32_t)
    TCPIP2_EXPECT_TRUE(CheckedMul(std::uint32_t{0x10000}, std::uint32_t{0x8000}, result));
    TCPIP2_EXPECT_EQ(std::uint32_t{0x80000000}, result);
}

// --- CheckedAdd tests ---

TCPIP2_TEST(CheckedAddBasic) {
    std::size_t result;
    TCPIP2_EXPECT_TRUE(CheckedAdd(std::size_t{3}, std::size_t{4}, result));
    TCPIP2_EXPECT_EQ(std::size_t{7}, result);
}

TCPIP2_TEST(CheckedAddOverflow) {
    std::size_t result;
    TCPIP2_EXPECT_FALSE(CheckedAdd(SIZE_MAX, std::size_t{1}, result));
}

// --- ReadCursor tests ---

TCPIP2_TEST(CursorEmpty) {
    ReadCursor cur(nullptr, 0);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cur.Remaining());
    std::uint8_t v8;
    TCPIP2_EXPECT_FALSE(cur.ReadU8(v8));
}

TCPIP2_TEST(CursorReadU8) {
    const std::uint8_t data[] = {0x01, 0x02, 0x03};
    ReadCursor cur(data, 3);
    TCPIP2_EXPECT_EQ(std::size_t{3}, cur.Remaining());

    std::uint8_t v;
    TCPIP2_EXPECT_TRUE(cur.ReadU8(v));
    TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, v);
    TCPIP2_EXPECT_EQ(std::size_t{2}, cur.Remaining());
    TCPIP2_EXPECT_EQ(std::size_t{1}, cur.Position());

    TCPIP2_EXPECT_TRUE(cur.ReadU8(v));
    TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, v);

    TCPIP2_EXPECT_TRUE(cur.ReadU8(v));
    TCPIP2_EXPECT_EQ(std::uint8_t{0x03}, v);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cur.Remaining());

    TCPIP2_EXPECT_FALSE(cur.ReadU8(v));
}

TCPIP2_TEST(CursorReadU16BigEndian) {
    const std::uint8_t data[] = {0x12, 0x34, 0xAB, 0xCD};
    ReadCursor cur(data, 4);

    std::uint16_t v;
    TCPIP2_EXPECT_TRUE(cur.ReadU16(v));
    TCPIP2_EXPECT_EQ(std::uint16_t{0x1234}, v);

    TCPIP2_EXPECT_TRUE(cur.ReadU16(v));
    TCPIP2_EXPECT_EQ(std::uint16_t{0xABCD}, v);
}

TCPIP2_TEST(CursorReadU16Truncated) {
    const std::uint8_t data[] = {0x12};
    ReadCursor cur(data, 1);

    std::uint16_t v;
    TCPIP2_EXPECT_FALSE(cur.ReadU16(v));
    TCPIP2_EXPECT_EQ(std::size_t{1}, cur.Remaining()); // position unchanged
}

TCPIP2_TEST(CursorReadU32BigEndian) {
    const std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
    ReadCursor cur(data, 8);

    std::uint32_t v;
    TCPIP2_EXPECT_TRUE(cur.ReadU32(v));
    TCPIP2_EXPECT_EQ(std::uint32_t{0x01020304}, v);

    TCPIP2_EXPECT_TRUE(cur.ReadU32(v));
    TCPIP2_EXPECT_EQ(std::uint32_t{0xDEADBEEF}, v);
}

TCPIP2_TEST(CursorReadU32Truncated) {
    const std::uint8_t data[] = {0x01, 0x02, 0x03};
    ReadCursor cur(data, 3);

    std::uint32_t v;
    TCPIP2_EXPECT_FALSE(cur.ReadU32(v));
}

TCPIP2_TEST(CursorReadBytes) {
    const std::uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    ReadCursor cur(data, 5);

    std::uint8_t buf[3];
    TCPIP2_EXPECT_TRUE(cur.ReadBytes(buf, 3));
    TCPIP2_EXPECT_EQ(std::uint8_t{0xAA}, buf[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xBB}, buf[1]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xCC}, buf[2]);

    TCPIP2_EXPECT_EQ(std::size_t{2}, cur.Remaining());

    // Try to read 3 more — only 2 left
    TCPIP2_EXPECT_FALSE(cur.ReadBytes(buf, 3));
    TCPIP2_EXPECT_EQ(std::size_t{2}, cur.Remaining()); // unchanged
}

TCPIP2_TEST(CursorSkip) {
    const std::uint8_t data[] = {1, 2, 3, 4, 5};
    ReadCursor cur(data, 5);

    TCPIP2_EXPECT_TRUE(cur.Skip(2));
    TCPIP2_EXPECT_EQ(std::size_t{3}, cur.Remaining());
    TCPIP2_EXPECT_EQ(std::size_t{2}, cur.Position());

    std::uint8_t v;
    cur.ReadU8(v);
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, v);

    // Skip beyond end
    TCPIP2_EXPECT_FALSE(cur.Skip(10));
    TCPIP2_EXPECT_EQ(std::size_t{2}, cur.Remaining()); // unchanged
}

TCPIP2_TEST(CursorPeek) {
    const std::uint8_t data[] = {0x42, 0x99};
    ReadCursor cur(data, 2);

    const std::uint8_t *p = cur.Peek();
    TCPIP2_EXPECT_TRUE(p != nullptr);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x42}, *p);

    cur.Skip(1);
    p = cur.Peek();
    TCPIP2_EXPECT_TRUE(p != nullptr);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x99}, *p);

    cur.Skip(1);
    p = cur.Peek();
    TCPIP2_EXPECT_TRUE(p == nullptr);
}

TCPIP2_TEST(CursorReset) {
    const std::uint8_t data[] = {0x10, 0x20, 0x30, 0x40};
    ReadCursor cur(data, 4);

    cur.Skip(3);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cur.Remaining());

    TCPIP2_EXPECT_TRUE(cur.Reset(0));
    TCPIP2_EXPECT_EQ(std::size_t{4}, cur.Remaining());

    std::uint8_t v;
    cur.ReadU8(v);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x10}, v);

    // Reset beyond bounds
    TCPIP2_EXPECT_FALSE(cur.Reset(100));
    TCPIP2_EXPECT_EQ(std::size_t{3}, cur.Remaining()); // unchanged
}

TCPIP2_TEST_MAIN();
