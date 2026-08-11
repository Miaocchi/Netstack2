#include <cstddef>

#include <tcpip2/config.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(DefaultConfigValid) {
    NetstackConfig c;
    TCPIP2_EXPECT_TRUE(c.Validate());
}

TCPIP2_TEST(ZeroShardsInvalid) {
    NetstackConfig c;
    c.shard_count = 0;
    TCPIP2_EXPECT_FALSE(c.Validate());
}

TCPIP2_TEST(ZeroRxQueuesInvalid) {
    NetstackConfig c;
    c.rx_queue_count = 0;
    TCPIP2_EXPECT_FALSE(c.Validate());
}

TCPIP2_TEST(AffinityVectorRules) {
    NetstackConfig c;
    c.rx_queue_count = 2;
    c.shard_count = 2;
    c.rx_queue_to_shard = {0};
    TCPIP2_EXPECT_FALSE(c.Validate());

    c.rx_queue_to_shard = {0, 5};
    TCPIP2_EXPECT_FALSE(c.Validate());

    c.rx_queue_to_shard = {1, 0};
    TCPIP2_EXPECT_TRUE(c.Validate());

    c.rx_queue_to_shard = {};
    TCPIP2_EXPECT_TRUE(c.Validate());
}

TCPIP2_TEST(DefaultMappingCannotExceedShardCount) {
    NetstackConfig c;
    c.shard_count = 1;
    c.rx_queue_count = 2;
    TCPIP2_EXPECT_FALSE(c.Validate());

    c.rx_queue_to_shard = {0, 0};
    TCPIP2_EXPECT_TRUE(c.Validate());
}

TCPIP2_TEST(ZeroPoolInvalid) {
    NetstackConfig c;
    c.pool_slot_count = 0;
    TCPIP2_EXPECT_FALSE(c.Validate());

    NetstackConfig c2;
    c2.pool_slot_capacity = 0;
    TCPIP2_EXPECT_FALSE(c2.Validate());
}

TCPIP2_TEST(WindowAndMssRules) {
    NetstackConfig c;
    c.initial_tcp_window = 0;
    TCPIP2_EXPECT_FALSE(c.Validate());

    NetstackConfig c2;
    c2.tcp_mss = 0;
    TCPIP2_EXPECT_FALSE(c2.Validate());
    c2.tcp_mss = 511;
    TCPIP2_EXPECT_FALSE(c2.Validate());
    c2.tcp_mss = 512;
    TCPIP2_EXPECT_TRUE(c2.Validate());
}

TCPIP2_TEST(TimeoutZeroInvalid) {
    NetstackConfig c;
    c.rto_initial_ms = 0;
    TCPIP2_EXPECT_FALSE(c.Validate());

    NetstackConfig c2;
    c2.persist_timeout_ms = 0;
    TCPIP2_EXPECT_FALSE(c2.Validate());

    NetstackConfig c3;
    c3.keepalive_ms = 0;
    TCPIP2_EXPECT_FALSE(c3.Validate());

    NetstackConfig c4;
    c4.time_wait_ms = 0;
    TCPIP2_EXPECT_FALSE(c4.Validate());

    NetstackConfig c5;
    c5.rto_initial_ms = 199;
    TCPIP2_EXPECT_FALSE(c5.Validate());

    NetstackConfig c6;
    c6.time_wait_ms = static_cast<std::uint64_t>(UINT32_MAX) + 1;
    TCPIP2_EXPECT_FALSE(c6.Validate());
}

TCPIP2_TEST(PoolMemoryOverflowRejected) {
    // shard_count * pool_slot_count overflows uint64_t.
    // Pick values whose product wraps to a small number.
    NetstackConfig c;
    c.shard_count = 2;
    c.pool_slot_count = static_cast<std::size_t>(UINT64_MAX);
    c.pool_slot_capacity = 1;
    TCPIP2_EXPECT_FALSE(c.Validate());

    // shard_count * pool_slot_count is fine, but * pool_slot_capacity overflows.
    NetstackConfig c2;
    c2.shard_count = 2;
    c2.pool_slot_count = static_cast<std::size_t>(UINT64_MAX / 2);
    c2.pool_slot_capacity = 3;
    TCPIP2_EXPECT_FALSE(c2.Validate());
}

TCPIP2_TEST(PoolMemoryCapRejected) {
    // Under 4 GiB is OK, over 4 GiB is rejected.
    // 4 shards * 4096 slots * 256 bytes = 4 MiB (OK).
    NetstackConfig c;
    c.shard_count = 4;
    c.pool_slot_count = 4096;
    c.pool_slot_capacity = 256;
    TCPIP2_EXPECT_TRUE(c.Validate());

    // 4 shards * 4096 slots * 262144 bytes = 4 GiB (boundary, rejected as >).
    // Actually 4*4096*262144 = 4294967296 = 4 GiB exactly.
    // But 4 GiB == max_total_pool_bytes, so this is NOT > max — it's ==.
    // We need > 4 GiB to trigger rejection. Use 262145 bytes.
    NetstackConfig c2;
    c2.shard_count = 4;
    c2.pool_slot_count = 4096;
    c2.pool_slot_capacity = 262145;
    TCPIP2_EXPECT_FALSE(c2.Validate());
}

TCPIP2_TEST_MAIN();
