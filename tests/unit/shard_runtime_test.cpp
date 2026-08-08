#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <thread>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/packet_io.h>

#include <core/shard.h>

#include "PacketBuilder.h"
#include "Test.h"

using namespace tcpip2;

namespace {

// A shard with no queue — packets arrive only via the SPSC inbox.
// Each shard gets its own pool (per-shard pool model, ADR-001).
std::unique_ptr<StackShard> MakeShard(std::size_t id, PktBufferPool& pool) {
    return std::unique_ptr<StackShard>(new StackShard(id, pool, nullptr, 128));
}

} // namespace

TCPIP2_TEST(ShardStartStop) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    TCPIP2_EXPECT_FALSE(shard->IsRunning());
    TCPIP2_EXPECT_TRUE(shard->Start());
    TCPIP2_EXPECT_TRUE(shard->IsRunning());
    shard->Stop();
    TCPIP2_EXPECT_FALSE(shard->IsRunning());
}

TCPIP2_TEST(ShardStopFallsBackWhenControlInboxHasZeroCapacity) {
    PktBufferPool pool(16, 256);
    StackShard shard(0, pool, nullptr, 0);
    TCPIP2_EXPECT_TRUE(shard.Start());
    shard.Stop();
    TCPIP2_EXPECT_FALSE(shard.IsRunning());
}

TCPIP2_TEST(ShardStartTwiceReturnsFalse) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    TCPIP2_EXPECT_TRUE(shard->Start());
    TCPIP2_EXPECT_FALSE(shard->Start());
    shard->Stop();
}

TCPIP2_TEST(ShardStopIdempotent) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();
    shard->Stop();
    // Second Stop should be a no-op (not crash, not hang).
    shard->Stop();
    TCPIP2_EXPECT_FALSE(shard->IsRunning());
}

TCPIP2_TEST(ShardStartStopCycle) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    for (int i = 0; i < 100; ++i) {
        TCPIP2_EXPECT_TRUE(shard->Start());
        TCPIP2_EXPECT_TRUE(shard->IsRunning());
        shard->Stop();
        TCPIP2_EXPECT_FALSE(shard->IsRunning());
    }
}

TCPIP2_TEST(ShardPostMessageProcessed) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();

    // Post a control message.
    ShardMessage msg;
    msg.type = ShardMessageType::kControl;
    msg.flow_id = FlowId{42};
    TCPIP2_EXPECT_TRUE(shard->PostMessage(std::move(msg)));

    // Wait for the shard to process it.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    TCPIP2_EXPECT_TRUE(shard->MessagesProcessed() > 0);

    shard->Stop();
}

TCPIP2_TEST(ShardPostPacketReceived) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();

    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    TCPIP2_EXPECT_TRUE(shard->PostPacket(std::move(lease)));

    // Wait for the shard to process it.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    TCPIP2_EXPECT_TRUE(shard->PacketsReceived() > 0);

    shard->Stop();
    // After stop, all buffers should be returned. The shard set
    // SetOwnerThread in Run(), so the buffer was returned on the owner
    // thread (fast path). DrainReturnQueue() is still called for safety.
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ShardMultipleShardsStartStop) {
    // Each shard gets its own pool (per-shard pool model).
    PktBufferPool pool0(32, 256);
    PktBufferPool pool1(32, 256);
    PktBufferPool pool2(32, 256);
    PktBufferPool pool3(32, 256);
    PktBufferPool* pools[] = {&pool0, &pool1, &pool2, &pool3};

    std::vector<std::unique_ptr<StackShard>> shards;
    for (std::size_t i = 0; i < 4; ++i) {
        shards.push_back(MakeShard(i, *pools[i]));
    }
    for (auto& s : shards) s->Start();
    for (auto& s : shards) TCPIP2_EXPECT_TRUE(s->IsRunning());
    for (auto& s : shards) s->Stop();
    for (auto& s : shards) TCPIP2_EXPECT_FALSE(s->IsRunning());
}

TCPIP2_TEST(ShardConcurrentMessages) {
    PktBufferPool pool(32, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();

    const std::size_t num_threads = 4;
    const std::size_t per_thread = 50;
    std::vector<std::thread> threads;
    for (std::size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([&shard, t]() {
            for (std::size_t i = 0; i < per_thread; ++i) {
                ShardMessage msg;
                msg.type = ShardMessageType::kControl;
                msg.flow_id = FlowId{t * per_thread + i};
                while (!shard->PostMessage(std::move(msg))) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });
    }
    for (auto& t : threads) t.join();

    // Wait for processing.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TCPIP2_EXPECT_TRUE(shard->MessagesProcessed() > 0);

    shard->Stop();
}

TCPIP2_TEST(ShardLateMessageAfterStop) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();
    shard->Stop();

    // Posting a message after Stop should not crash (it returns false since
    // the queue may still accept, but the shard is no longer running).
    // The key invariant: no crash.
    ShardMessage msg;
    msg.type = ShardMessageType::kControl;
    shard->PostMessage(std::move(msg));
    TCPIP2_EXPECT_FALSE(shard->IsRunning());
}

TCPIP2_TEST(ShardPoolOutstandingZeroAfterStop) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();

    // Post several packets.
    for (int i = 0; i < 10; ++i) {
        BufferLease lease = pool.Allocate();
        shard->PostPacket(std::move(lease));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    shard->Stop();
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ShardIsShardThreadFalseFromExternalThread) {
    PktBufferPool pool(16, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();

    // From the test thread, IsShardThread() must return false.
    TCPIP2_EXPECT_FALSE(shard->IsShardThread());

    // Stop() from a non-owner thread must work cleanly (no abort).
    shard->Stop();
    TCPIP2_EXPECT_FALSE(shard->IsRunning());
}

TCPIP2_TEST(ShardStressConcurrent) {
    PktBufferPool pool(256, 256);
    auto shard = MakeShard(0, pool);
    shard->Start();

    // PostPacket uses the SPSC inbox (single-producer), so concurrent
    // producers must go through PostMessage (MPSC inbox) instead.
    const std::size_t num_producers = 4;
    std::vector<std::thread> producers;
    std::atomic<std::size_t> sent{0};
    for (std::size_t p = 0; p < num_producers; ++p) {
        producers.emplace_back([&]() {
            for (std::size_t i = 0; i < 100; ++i) {
                ShardMessage msg;
                msg.type = ShardMessageType::kControl;
                msg.flow_id = FlowId{i};
                if (shard->PostMessage(std::move(msg))) {
                    ++sent;
                }
            }
        });
    }

    for (auto& t : producers) t.join();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    shard->Stop();
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(ShardProcessesSynAndRetainsWouldBlockTx) {
    NullPacketIo io(1);
    PktBufferPool pool(16, 256);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);
    StackShard shard(0, pool, queue.get(), 128);
    io.SetSendWouldBlock(true);
    TCPIP2_EXPECT_TRUE(shard.Start());

    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0,
        test::TcpFlags::Syn, {});
    BufferLease lease = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), syn.data(), syn.size());
    lease.Resize(syn.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    TCPIP2_EXPECT_EQ(std::size_t{1}, shard.TcpHalfOpenCount());
    io.SetSendWouldBlock(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    shard.Stop();

    const auto& egress = io.Egress(0);
    TCPIP2_EXPECT_EQ(std::size_t{1}, egress.size());
    if (!egress.empty()) {
        const test::ParsedPacket response = test::PacketParser::ParseIpv4Tcp(egress[0]);
        TCPIP2_EXPECT_TRUE(response.valid);
        TCPIP2_EXPECT_EQ(std::uint32_t{0x0a000002u}, response.src_ip);
        TCPIP2_EXPECT_EQ(std::uint32_t{0x0a000001u}, response.dst_ip);
        TCPIP2_EXPECT_EQ(std::uint16_t{443}, response.src_port);
        TCPIP2_EXPECT_EQ(std::uint16_t{40000}, response.dst_port);
        TCPIP2_EXPECT_EQ(std::uint32_t{1001}, response.ack);
        TCPIP2_EXPECT_EQ(
            static_cast<std::uint8_t>(test::TcpFlags::Syn | test::TcpFlags::Ack),
            response.flags);
    }
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
