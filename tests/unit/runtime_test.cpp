#include <cstddef>
#include <thread>

#include <tcpip2/buffer.h>
#include <tcpip2/config.h>
#include <tcpip2/packet_io.h>

#include <core/dispatcher.h>
#include <core/runtime.h>
#include <core/shard.h>
#include <core/dispatcher.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(RuntimeStartWithNullPacketIo) {
    NetstackConfig config;
    config.shard_count = 2;
    config.rx_queue_count = 2;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(2);

    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));
    TCPIP2_EXPECT_TRUE(rt.IsRunning());
    TCPIP2_EXPECT_EQ(std::size_t{2}, rt.ShardCount());
    TCPIP2_EXPECT_TRUE(rt.Dispatcher() != nullptr);
    // Per-shard pools created internally.
    TCPIP2_EXPECT_TRUE(rt.ShardPool(0) != nullptr);
    TCPIP2_EXPECT_TRUE(rt.ShardPool(1) != nullptr);

    rt.Stop();
    TCPIP2_EXPECT_FALSE(rt.IsRunning());
}

TCPIP2_TEST(RuntimeStopJoinsThreads) {
    NetstackConfig config;
    config.shard_count = 4;
    config.rx_queue_count = 4;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(4);

    Runtime rt;
    rt.Start(config, &io);
    TCPIP2_EXPECT_TRUE(rt.IsRunning());
    rt.Stop();
    TCPIP2_EXPECT_FALSE(rt.IsRunning());

    // All shards should be gone.
    TCPIP2_EXPECT_EQ(std::size_t{0}, rt.ShardCount());
}

TCPIP2_TEST(RuntimeInjectPacketReceived) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 1;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(1);

    Runtime rt;
    rt.Start(config, &io);

    // Inject a packet into queue 0, using shard 0's own pool.
    PktBufferPool* pool = rt.ShardPool(0);
    TCPIP2_EXPECT_TRUE(pool != nullptr);
    BufferLease lease = pool->Allocate();
    lease.Resize(64);
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    // Wait for the shard to receive it.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    StackShard* shard = rt.Shard(0);
    TCPIP2_EXPECT_TRUE(shard != nullptr);
    TCPIP2_EXPECT_TRUE(shard->PacketsReceived() > 0);

    // The shard released the buffer on its own thread (fast path), so
    // outstanding should be 0 without needing DrainReturnQueue.
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool->OutstandingCount());

    rt.Stop();
}

TCPIP2_TEST(RuntimeStartStopCycle) {
    NetstackConfig config;
    config.shard_count = 2;
    config.rx_queue_count = 2;
    config.pool_slot_count = 32;
    config.pool_slot_capacity = 256;

    NullPacketIo io(2);

    Runtime rt;
    for (int i = 0; i < 10; ++i) {
        TCPIP2_EXPECT_TRUE(rt.Start(config, &io));
        TCPIP2_EXPECT_TRUE(rt.IsRunning());
        rt.Stop();
        TCPIP2_EXPECT_FALSE(rt.IsRunning());
    }
}

TCPIP2_TEST(RuntimeCustomQueueShardMapping) {
    NetstackConfig config;
    config.shard_count = 4;
    config.rx_queue_count = 2;
    config.rx_queue_to_shard = {2, 3};
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(2);

    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));
    TCPIP2_EXPECT_TRUE(rt.Dispatcher() != nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{2}, rt.Dispatcher()->QueueShard(0));
    TCPIP2_EXPECT_EQ(std::size_t{3}, rt.Dispatcher()->QueueShard(1));

    rt.Stop();
}

TCPIP2_TEST(RuntimeInvalidConfigFails) {
    NetstackConfig config;
    config.shard_count = 0;  // invalid

    NullPacketIo io(1);

    Runtime rt;
    TCPIP2_EXPECT_FALSE(rt.Start(config, &io));
    TCPIP2_EXPECT_FALSE(rt.IsRunning());
}

TCPIP2_TEST(RuntimeNullPacketIoFails) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 1;
    Runtime rt;
    TCPIP2_EXPECT_FALSE(rt.Start(config, nullptr));
    TCPIP2_EXPECT_FALSE(rt.IsRunning());
}

TCPIP2_TEST(RuntimeStopIdempotent) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 1;
    config.pool_slot_count = 32;
    config.pool_slot_capacity = 256;

    NullPacketIo io(1);

    Runtime rt;
    rt.Start(config, &io);
    rt.Stop();
    rt.Stop();  // second stop should be a no-op
    TCPIP2_EXPECT_FALSE(rt.IsRunning());
}

TCPIP2_TEST_MAIN();
