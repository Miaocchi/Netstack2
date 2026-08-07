#include <cstddef>
#include <cstdint>

#include <tcpip2/buffer.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(RetainKeepsPayload) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    std::uint8_t* d = lease.Data();
    for (std::size_t i = 0; i < 16; ++i) {
        d[i] = static_cast<std::uint8_t>(i * 2);
    }
    lease.Resize(16);
    BufferRef ref = pool.Retain(std::move(lease));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(ref));
    TCPIP2_EXPECT_EQ(std::size_t{16}, ref.Size());
    TCPIP2_EXPECT_EQ(std::uint8_t{10}, ref.Data()[5]);
    ref.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(RefCopiesAllowed) {
    PktBufferPool pool(4, 256);
    BufferLease lease = pool.Allocate();
    BufferRef a = pool.Retain(std::move(lease));
    BufferRef b = a;
    TCPIP2_EXPECT_TRUE(a.Get() == b.Get());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.RetainedCount());
    a.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    TCPIP2_EXPECT_TRUE(static_cast<bool>(b));
    b.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(EmptyRefNoOp) {
    PktBufferPool pool(4, 256);
    BufferRef empty;
    TCPIP2_EXPECT_FALSE(static_cast<bool>(empty));
    empty.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(RAIIReleasesOnLastReference) {
    PktBufferPool pool(4, 256);
    BufferLease lease = pool.Allocate();
    {
        BufferRef a = pool.Retain(std::move(lease));
        {
            BufferRef b = a;
            TCPIP2_EXPECT_EQ(std::size_t{1}, pool.RetainedCount());
            TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
        } // b destroyed: ref_count 2->1, buffer not returned
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.RetainedCount());
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    } // a destroyed: ref_count 1->0, buffer returned
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.RetainedCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, pool.FreeCount());
}

TCPIP2_TEST(ResizeExceedsCapacityAborts) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_DEATH(lease.Resize(513););
    lease.Reset();
}

TCPIP2_TEST(ResizeAtCapacitySucceeds) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    lease.Resize(512);
    TCPIP2_EXPECT_EQ(std::size_t{512}, lease.Size());
    lease.Reset();
}

TCPIP2_TEST(CrossPoolReturnAborts) {
    PktBufferPool poolA(4, 512);
    PktBufferPool poolB(4, 512);
    BufferLease a = poolA.Allocate();
    PktBuffer* pkt = a.Get();
    a.Reset();
    // Try to return poolA's buffer to poolB
    TCPIP2_EXPECT_DEATH(poolB.ReturnBuffer(pkt););
}

TCPIP2_TEST(ArenaFailureDegradesGracefully) {
    // Request an impossibly large arena; new(std::nothrow) returns nullptr.
    PktBufferPool pool(1, static_cast<std::size_t>(1) << 62);
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.SlotCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.FreeCount());
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_FALSE(static_cast<bool>(lease));
}

TCPIP2_TEST(ArithmeticOverflowDegradesGracefully) {
    // slot_count * slot_capacity overflows uint64_t: 2 * SIZE_MAX wraps.
    // The constructor must detect this and degrade to 0 usable slots.
    PktBufferPool pool(2, SIZE_MAX);
    TCPIP2_EXPECT_EQ(std::size_t{2}, pool.SlotCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.FreeCount());
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_FALSE(static_cast<bool>(lease));
}

TCPIP2_TEST_MAIN();
