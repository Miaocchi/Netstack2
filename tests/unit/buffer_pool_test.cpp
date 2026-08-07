#include <cstdint>
#include <thread>
#include <vector>

#include <tcpip2/buffer.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(AllocateReturnsLease) {
    PktBufferPool pool(8, 2048);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    TCPIP2_EXPECT_TRUE(lease.Get() != nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{7}, pool.FreeCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{2048}, lease.Capacity());
    TCPIP2_EXPECT_EQ(std::size_t{0}, lease.Size());
    TCPIP2_EXPECT_TRUE(lease.Data() != nullptr);
    lease.Reset();
    TCPIP2_EXPECT_FALSE(static_cast<bool>(lease));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{8}, pool.FreeCount());
}

TCPIP2_TEST(WriteAndResize) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    std::uint8_t* d = lease.Data();
    for (std::size_t i = 0; i < 128; ++i) {
        d[i] = static_cast<std::uint8_t>(i);
    }
    lease.Resize(128);
    TCPIP2_EXPECT_EQ(std::size_t{128}, lease.Size());
    const std::uint8_t* cd = lease.Data();
    for (std::size_t i = 0; i < 128; ++i) {
        TCPIP2_EXPECT_EQ(static_cast<std::uint8_t>(i), cd[i]);
    }
    TCPIP2_EXPECT_EQ(std::size_t{512}, lease.Capacity());
    lease.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ExhaustionReturnsEmpty) {
    PktBufferPool pool(2, 256);
    BufferLease a = pool.Allocate();
    BufferLease b = pool.Allocate();
    BufferLease c = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(a));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(b));
    TCPIP2_EXPECT_FALSE(static_cast<bool>(c));
    TCPIP2_EXPECT_EQ(std::size_t{2}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.FreeCount());
    a.Reset();
    BufferLease d = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(d));
    TCPIP2_EXPECT_EQ(std::size_t{2}, pool.OutstandingCount());
}

TCPIP2_TEST(MoveOnlyLease) {
    PktBufferPool pool(4, 256);
    BufferLease a = pool.Allocate();
    BufferLease b = std::move(a);
    TCPIP2_EXPECT_FALSE(static_cast<bool>(a));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(b));
    BufferLease& b_ref = b;
    b = std::move(b_ref);
    TCPIP2_EXPECT_TRUE(static_cast<bool>(b));
    b.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    a.Reset();
}

TCPIP2_TEST(CrossThreadRelease) {
    PktBufferPool pool(8, 1024);
    {
        BufferLease lease = pool.Allocate();
        TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
        std::thread t([lease = std::move(lease)]() mutable {
            lease.Reset();
        });
        t.join();
        // Released on a foreign thread: parked in the owner return queue.
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.ReturnQueueSize());
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.DrainReturnQueue());
    }
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{8}, pool.FreeCount());
}

TCPIP2_TEST(DoubleReleaseAborts) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    PktBuffer* pkt = lease.Get();
    TCPIP2_EXPECT_DEATH(pool.ReturnBuffer(pkt); pool.ReturnBuffer(pkt););
    lease.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(RetainConsumesLease) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    lease.Resize(32);
    BufferRef ref = pool.Retain(std::move(lease));
    TCPIP2_EXPECT_FALSE(static_cast<bool>(lease));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(ref));
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.RetainedCount());
    ref.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.RetainedCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, pool.FreeCount());
}

TCPIP2_TEST(RetainEmptyLeaseReturnsEmpty) {
    PktBufferPool pool(4, 256);
    BufferRef ref = pool.Retain(BufferLease{});
    TCPIP2_EXPECT_FALSE(static_cast<bool>(ref));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ReleaseRoutesToOwningPool) {
    PktBufferPool poolA(4, 256);
    PktBufferPool poolB(4, 256);
    BufferLease a = poolA.Allocate();
    BufferLease b = poolB.Allocate();
    a.Resize(8);
    b.Resize(16);
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolA.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolB.OutstandingCount());
    a.Reset();
    b.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, poolA.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, poolB.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, poolA.FreeCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, poolB.FreeCount());
}

TCPIP2_TEST(CrossThreadReleaseRoutesToOwningPool) {
    PktBufferPool poolA(4, 256);
    PktBufferPool poolB(4, 256);
    std::thread t([&] {
        BufferLease a = poolA.Allocate();
        BufferLease b = poolB.Allocate();
        a.Resize(1);
        b.Resize(1);
        // Release on a foreign thread; each buffer must route back to the
        // pool that created it, not to a global free list.
        a.Reset();
        b.Reset();
    });
    t.join();
    // Both pools park their buffer in their own owner return queue.
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolA.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolB.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolA.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolB.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolA.DrainReturnQueue());
    TCPIP2_EXPECT_EQ(std::size_t{1}, poolB.DrainReturnQueue());
    TCPIP2_EXPECT_EQ(std::size_t{0}, poolA.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, poolB.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, poolA.FreeCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, poolB.FreeCount());
}

TCPIP2_TEST(OwnerThreadReleaseTakesFastPath) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    // Released on the owner thread: straight back to the free list.
    lease.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, pool.FreeCount());
}

TCPIP2_TEST(AllocateLazilyDrainsReturnQueue) {
    PktBufferPool pool(1, 512);
    BufferLease lease = pool.Allocate();
    std::thread t([lease = std::move(lease)]() mutable { lease.Reset(); });
    t.join();
    // The only buffer is parked in the return queue: the pool looks exhausted.
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.FreeCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    // Allocate() lazily drains the queue and reuses the buffer.
    BufferLease again = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(again));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    again.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(DoubleReleaseWhileQueuedAborts) {
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    PktBuffer* pkt = lease.Get();
    TCPIP2_EXPECT_TRUE(pkt != nullptr);
    std::thread t([lease = std::move(lease)]() mutable { lease.Reset(); });
    t.join();
    // The buffer is queued (still outstanding); returning it again is a
    // double release and must abort even though it never hit the free list.
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.ReturnQueueSize());
    TCPIP2_EXPECT_DEATH(pool.ReturnBuffer(pkt););
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, pool.FreeCount());
}

TCPIP2_TEST_MAIN();
