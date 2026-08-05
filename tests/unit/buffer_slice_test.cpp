#include <cstdint>
#include <cstring>

#include <tcpip2/buffer.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(DefaultSliceIsEmpty) {
    BufferSlice s;
    TCPIP2_EXPECT_TRUE(s.Empty());
    TCPIP2_EXPECT_EQ(std::size_t{0}, s.Size());
    TCPIP2_EXPECT_TRUE(s.Data() == nullptr);
}

TCPIP2_TEST(ConstructFromRange) {
    const std::uint8_t raw[5] = {1, 2, 3, 4, 5};
    BufferSlice s(raw, 5);
    TCPIP2_EXPECT_FALSE(s.Empty());
    TCPIP2_EXPECT_EQ(std::size_t{5}, s.Size());
    TCPIP2_EXPECT_TRUE(s.Data() == raw);
    TCPIP2_EXPECT_EQ(std::uint8_t{3}, s.Data()[2]);
}

TCPIP2_TEST(SubsliceClipping) {
    const std::uint8_t raw[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    BufferSlice s(raw, 10);
    BufferSlice sub = s.Subslice(2, 4);
    TCPIP2_EXPECT_EQ(std::size_t{4}, sub.Size());
    TCPIP2_EXPECT_TRUE(sub.Data() == raw + 2);
    TCPIP2_EXPECT_EQ(std::uint8_t{4}, sub.Data()[2]);
    BufferSlice tail = s.Subslice(8, 100);
    TCPIP2_EXPECT_EQ(std::size_t{2}, tail.Size());
    BufferSlice beyond = s.Subslice(10, 1);
    TCPIP2_EXPECT_TRUE(beyond.Empty());
    BufferSlice past_end = s.Subslice(11, 1);
    TCPIP2_EXPECT_TRUE(past_end.Empty());
}

TCPIP2_TEST(TriviallyCopyable) {
    const std::uint8_t raw[4] = {9, 8, 7, 6};
    BufferSlice a(raw, 4);
    BufferSlice b;
    std::memcpy(&b, &a, sizeof(BufferSlice));
    TCPIP2_EXPECT_EQ(a.Data(), b.Data());
    TCPIP2_EXPECT_EQ(a.Size(), b.Size());
}

TCPIP2_TEST(SliceFromLease) {
    PktBufferPool pool(2, 256);
    BufferLease lease = pool.Allocate();
    lease.Data()[0] = 0x42;
    lease.Resize(1);
    BufferSlice s(lease.Data(), lease.Size());
    TCPIP2_EXPECT_EQ(std::size_t{1}, s.Size());
    TCPIP2_EXPECT_EQ(std::uint8_t{0x42}, s.Data()[0]);
    lease.Reset();
}

TCPIP2_TEST_MAIN();
