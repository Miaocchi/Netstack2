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
}

TCPIP2_TEST_MAIN();
