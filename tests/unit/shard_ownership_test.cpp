#include <cstdint>
#include <thread>
#include <type_traits>

#include <tcpip2/buffer.h>

#include <core/shard.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(ShardMessageIsMoveOnly) {
    static_assert(std::is_move_constructible_v<ShardMessage>, "ShardMessage must be move constructible");
    static_assert(!std::is_copy_constructible_v<ShardMessage>, "ShardMessage must be move-only");
    static_assert(!std::is_copy_assignable_v<ShardMessage>, "ShardMessage must be move-only");
    static_assert(std::is_nothrow_move_constructible_v<ShardMessage>, "ShardMessage move construction must not throw");

    PktBufferPool pool(2, 256);
    ShardMessage a;
    a.type = ShardMessageType::kPacketIn;
    a.data = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(a.data));
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());

    ShardMessage b = std::move(a);
    TCPIP2_EXPECT_FALSE(static_cast<bool>(a.data));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(b.data));
    TCPIP2_EXPECT_TRUE(b.type == ShardMessageType::kPacketIn);
    b.data.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(FlowIdCompare) {
    const FlowId a{1};
    const FlowId b{1};
    const FlowId c{2};
    TCPIP2_EXPECT_TRUE(a == b);
    TCPIP2_EXPECT_TRUE(a != c);
    TCPIP2_EXPECT_FALSE(a == c);
}

TCPIP2_TEST(ShardMessageDefaults) {
    ShardMessage msg;
    TCPIP2_EXPECT_TRUE(msg.type == ShardMessageType::kControl);
    TCPIP2_EXPECT_FALSE(static_cast<bool>(msg.data));
    TCPIP2_EXPECT_TRUE(msg.error == SessionError::None);
}

TCPIP2_TEST(CrossThreadLeaseReleaseRoutesToPool) {
    PktBufferPool pool(4, 1024);
    BufferLease lease = pool.Allocate();
    lease.Resize(16);
    std::thread t([&pool, lease = std::move(lease)]() mutable {
        TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
        // Foreign-thread release parks the buffer in the owner return queue.
        lease.Reset();
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.ReturnQueueSize());
    });
    t.join();
    // Still outstanding until the owner thread drains the return queue.
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{3}, pool.FreeCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.DrainReturnQueue());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, pool.FreeCount());
}

TCPIP2_TEST(ShardMessageCarriesOwnershipAcrossThreads) {
    PktBufferPool pool(4, 512);
    ShardMessage msg;
    msg.type = ShardMessageType::kSessionData;
    msg.flow_id = FlowId{42};
    msg.data = pool.Allocate();
    std::thread t([&pool, msg = std::move(msg)]() mutable {
        TCPIP2_EXPECT_TRUE(static_cast<bool>(msg.data));
        TCPIP2_EXPECT_TRUE(msg.flow_id == FlowId{42});
        msg.data.Reset();
        TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    });
    t.join();
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
