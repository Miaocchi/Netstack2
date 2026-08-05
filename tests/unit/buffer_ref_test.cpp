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
    pool.Unpin(ref);
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(RefCopiesAllowed) {
    PktBufferPool pool(4, 256);
    BufferLease lease = pool.Allocate();
    BufferRef a = pool.Retain(std::move(lease));
    BufferRef b = a;
    TCPIP2_EXPECT_TRUE(a.Get() == b.Get());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.RetainedCount());
    pool.Unpin(a);
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    // b still references the buffer, but the slot is now free.
    TCPIP2_EXPECT_TRUE(static_cast<bool>(b));
}

TCPIP2_TEST(EmptyRefNoOp) {
    PktBufferPool pool(4, 256);
    BufferRef empty;
    TCPIP2_EXPECT_FALSE(static_cast<bool>(empty));
    pool.Unpin(empty);
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(DoubleUnpinAborts) {
    PktBufferPool pool(4, 256);
    BufferLease lease = pool.Allocate();
    BufferRef a = pool.Retain(std::move(lease));
    BufferRef b = a;
    pool.Unpin(a);
    TCPIP2_EXPECT_DEATH(pool.Unpin(b););
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
