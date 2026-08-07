#include <atomic>
#include <cstddef>
#include <thread>
#include <vector>

#include <tcpip2/buffer.h>

#include <core/inbox_mpsc.h>
#include <core/inbox_spsc.h>
#include <core/shard.h>

#include "Test.h"

using namespace tcpip2;

// ---------------------------------------------------------------------------
// SPSC tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(SpscPushPopSingle) {
    PktBufferPool pool(4, 256);
    InboxSpsc inbox(8);

    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    TCPIP2_EXPECT_TRUE(inbox.Push(std::move(lease)));
    TCPIP2_EXPECT_FALSE(static_cast<bool>(lease));

    BufferLease out;
    TCPIP2_EXPECT_TRUE(inbox.Pop(out));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(out));
    out.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(SpscPushUntilFull) {
    PktBufferPool pool(32, 256);
    // Capacity 8 rounds up to 8 (power of 2).
    InboxSpsc inbox(8);
    const std::size_t cap = inbox.Capacity();
    TCPIP2_EXPECT_EQ(std::size_t{8}, cap);

    for (std::size_t i = 0; i < cap; ++i) {
        BufferLease lease = pool.Allocate();
        TCPIP2_EXPECT_TRUE(inbox.Push(std::move(lease)));
    }
    // Next push should fail (full).
    BufferLease extra = pool.Allocate();
    TCPIP2_EXPECT_FALSE(inbox.Push(std::move(extra)));
    extra.Reset();

    // Drain all.
    for (std::size_t i = 0; i < cap; ++i) {
        BufferLease out;
        TCPIP2_EXPECT_TRUE(inbox.Pop(out));
        out.Reset();
    }
    BufferLease out;
    TCPIP2_EXPECT_FALSE(inbox.Pop(out));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(SpscPopUntilEmpty) {
    PktBufferPool pool(4, 256);
    InboxSpsc inbox(4);

    BufferLease lease = pool.Allocate();
    inbox.Push(std::move(lease));

    BufferLease out;
    TCPIP2_EXPECT_TRUE(inbox.Pop(out));
    out.Reset();

    TCPIP2_EXPECT_FALSE(inbox.Pop(out));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(SpscEmptyAndSize) {
    PktBufferPool pool(4, 256);
    InboxSpsc inbox(4);

    TCPIP2_EXPECT_TRUE(inbox.Empty());
    TCPIP2_EXPECT_EQ(std::size_t{0}, inbox.Size());

    BufferLease lease = pool.Allocate();
    inbox.Push(std::move(lease));
    TCPIP2_EXPECT_FALSE(inbox.Empty());
    TCPIP2_EXPECT_EQ(std::size_t{1}, inbox.Size());

    BufferLease out;
    inbox.Pop(out);
    out.Reset();
    TCPIP2_EXPECT_TRUE(inbox.Empty());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(SpscMultithreaded) {
    PktBufferPool pool(2048, 256);
    InboxSpsc inbox(2048);
    const std::size_t N = 1000;

    std::thread producer([&]() {
        for (std::size_t i = 0; i < N; ++i) {
            BufferLease lease = pool.Allocate();
            while (!inbox.Push(std::move(lease))) {
                // Spin until space is available.
            }
        }
    });

    std::size_t received = 0;
    std::thread consumer([&]() {
        while (received < N) {
            BufferLease out;
            if (inbox.Pop(out)) {
                out.Reset();
                ++received;
            }
        }
    });

    producer.join();
    consumer.join();
    TCPIP2_EXPECT_EQ(N, received);
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

// ---------------------------------------------------------------------------
// MPSC tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(MpscPushPopSingle) {
    InboxMpsc inbox(8);
    ShardMessage msg;
    msg.type = ShardMessageType::kControl;
    msg.flow_id = FlowId{42};

    TCPIP2_EXPECT_TRUE(inbox.Push(std::move(msg)));
    TCPIP2_EXPECT_EQ(std::size_t{1}, inbox.Size());

    ShardMessage out;
    TCPIP2_EXPECT_TRUE(inbox.Pop(out));
    TCPIP2_EXPECT_TRUE(out.type == ShardMessageType::kControl);
    TCPIP2_EXPECT_TRUE(out.flow_id == FlowId{42});

    TCPIP2_EXPECT_FALSE(inbox.Pop(out));
    TCPIP2_EXPECT_EQ(std::size_t{0}, inbox.Size());
}

TCPIP2_TEST(MpscPushUntilFull) {
    InboxMpsc inbox(4);
    for (std::size_t i = 0; i < 4; ++i) {
        ShardMessage msg;
        msg.flow_id = FlowId{i};
        TCPIP2_EXPECT_TRUE(inbox.Push(std::move(msg)));
    }
    ShardMessage msg;
    msg.flow_id = FlowId{99};
    TCPIP2_EXPECT_FALSE(inbox.Push(std::move(msg)));
    TCPIP2_EXPECT_EQ(std::size_t{4}, inbox.Size());
    TCPIP2_EXPECT_EQ(std::size_t{4}, inbox.Capacity());
}

TCPIP2_TEST(MpscMultipleProducers) {
    InboxMpsc inbox(1024);
    const std::size_t num_producers = 4;
    const std::size_t per_producer = 100;

    std::vector<std::thread> producers;
    for (std::size_t p = 0; p < num_producers; ++p) {
        producers.emplace_back([&inbox, p]() {
            for (std::size_t i = 0; i < per_producer; ++i) {
                ShardMessage msg;
                msg.flow_id = FlowId{p * per_producer + i};
                while (!inbox.Push(std::move(msg))) {
                    // Spin until space is available.
                }
            }
        });
    }

    std::size_t received = 0;
    while (received < num_producers * per_producer) {
        ShardMessage out;
        if (inbox.Pop(out)) {
            ++received;
        }
    }

    for (auto& t : producers) t.join();
    TCPIP2_EXPECT_EQ(num_producers * per_producer, received);
}

TCPIP2_TEST(MpscWakeWait) {
    InboxMpsc inbox(8);

    // Wait with short timeout on empty inbox should return false.
    TCPIP2_EXPECT_FALSE(inbox.Wait(10));

    // Push a message, then Wait should return true.
    ShardMessage msg;
    msg.type = ShardMessageType::kControl;
    inbox.Push(std::move(msg));
    TCPIP2_EXPECT_TRUE(inbox.Wait(10));

    // Wake should not crash.
    inbox.Wake();
}

TCPIP2_TEST(MpscWakeFromAnotherThread) {
    InboxMpsc inbox(8);

    std::thread waker([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        inbox.Wake();
    });

    // Wait should return (false) after being woken.
    TCPIP2_EXPECT_FALSE(inbox.Wait(5000));

    waker.join();
}

TCPIP2_TEST_MAIN();
