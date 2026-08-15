#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/config.h>
#include <tcpip2/flow.h>
#include <tcpip2/netstack.h>
#include <tcpip2/packet_io.h>

#include <core/dispatcher.h>
#include <core/runtime.h>
#include <core/shard.h>

#include "PacketBuilder.h"
#include "Test.h"

using namespace tcpip2;

namespace {

bool WaitFor(const std::function<bool()>& predicate) {
    for (int i = 0; i < 200; ++i) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return predicate();
}

struct QueueOwnerState {
    explicit QueueOwnerState(std::size_t queue_count)
        : owners(queue_count), owner_set(queue_count, false) {}

    std::mutex mutex;
    std::vector<std::thread::id> owners;
    std::vector<bool> owner_set;
    bool foreign_send = false;
};

class OwnerCheckingQueue final : public IPacketQueue {
public:
    OwnerCheckingQueue(std::unique_ptr<IPacketQueue> inner,
                       std::shared_ptr<QueueOwnerState> state) noexcept
        : inner_(std::move(inner)), state_(std::move(state)) {}

    std::size_t RecvBatch(BufferLease out[], std::size_t capacity,
                          IoError& error) noexcept override {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            const std::size_t queue_id = inner_->QueueId();
            state_->owners[queue_id] = std::this_thread::get_id();
            state_->owner_set[queue_id] = true;
        }
        return inner_->RecvBatch(out, capacity, error);
    }

    std::size_t SendBatch(BufferLease packets[], std::size_t count,
                          IoError& error) noexcept override {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            const std::size_t queue_id = inner_->QueueId();
            if (!state_->owner_set[queue_id] ||
                state_->owners[queue_id] != std::this_thread::get_id()) {
                state_->foreign_send = true;
            }
        }
        return inner_->SendBatch(packets, count, error);
    }

    std::size_t QueueId() const noexcept override { return inner_->QueueId(); }
    void SetBufferPool(PktBufferPool* pool) noexcept override { inner_->SetBufferPool(pool); }
    void StopRx() noexcept override { inner_->StopRx(); }
    IoError DrainTx(std::uint64_t deadline_ms) noexcept override {
        return inner_->DrainTx(deadline_ms);
    }
    std::size_t OutstandingTx() const noexcept override { return inner_->OutstandingTx(); }
    void SetRecvHandler(std::function<void()> wake) override {
        inner_->SetRecvHandler(std::move(wake));
    }

private:
    std::unique_ptr<IPacketQueue> inner_;
    std::shared_ptr<QueueOwnerState> state_;
};

class OwnerCheckingPacketIo final : public IPacketIo {
public:
    explicit OwnerCheckingPacketIo(std::size_t queue_count)
        : inner_(queue_count), state_(std::make_shared<QueueOwnerState>(queue_count)) {}

    std::size_t QueueCount() const noexcept override { return inner_.QueueCount(); }

    std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) override {
        std::unique_ptr<IPacketQueue> queue = inner_.OpenQueue(queue_id);
        if (!queue) return nullptr;
        return std::unique_ptr<IPacketQueue>(new OwnerCheckingQueue(std::move(queue), state_));
    }

    bool Inject(std::size_t queue_id, BufferLease&& lease) {
        return inner_.Inject(queue_id, std::move(lease));
    }

    std::vector<std::vector<std::uint8_t>> EgressSnapshot(std::size_t queue_id) const {
        return inner_.EgressSnapshot(queue_id);
    }

    bool SentFromForeignThread() const {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->foreign_send;
    }

private:
    NullPacketIo inner_;
    std::shared_ptr<QueueOwnerState> state_;
};

} // namespace

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
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return rt.Shard(0)->PacketsReceived() > 0; }));
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
    for (int i = 0; i < 1000; ++i) {
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

    BufferLease queue_zero_lease = rt.ShardPool(2)->Allocate();
    queue_zero_lease.Resize(64);
    BufferLease queue_one_lease = rt.ShardPool(3)->Allocate();
    queue_one_lease.Resize(64);
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(queue_zero_lease)));
    TCPIP2_EXPECT_TRUE(io.Inject(1, std::move(queue_one_lease)));

    TCPIP2_EXPECT_TRUE(WaitFor([&] { return rt.Shard(2)->PacketsReceived() > 0; }));
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return rt.Shard(3)->PacketsReceived() > 0; }));

    rt.Stop();
}

TCPIP2_TEST(RuntimeMultipleQueuesOneShard) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 2;
    config.rx_queue_to_shard = {0, 0};
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(2);
    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    for (std::size_t queue_id = 0; queue_id < 2; ++queue_id) {
        BufferLease lease = rt.ShardPool(0)->Allocate();
        lease.Resize(64);
        TCPIP2_EXPECT_TRUE(io.Inject(queue_id, std::move(lease)));
    }

    TCPIP2_EXPECT_TRUE(WaitFor([&] { return rt.Shard(0)->PacketsReceived() >= 2; }));
    TCPIP2_EXPECT_EQ(std::size_t{2}, rt.Shard(0)->PacketsReceived());
    rt.Stop();
}

TCPIP2_TEST(RuntimeRedirectsConcurrentQueueOwnersToOneTcpOwner) {
    NetstackConfig config;
    config.shard_count = 5;
    config.rx_queue_count = 5;
    config.pool_slot_count = 128;
    config.pool_slot_capacity = 256;

    FlowKey flow;
    flow.source = IpAddress::Ipv4(10, 0, 0, 1);
    flow.destination = IpAddress::Ipv4(10, 0, 0, 2);
    flow.source_port = 40000;
    flow.destination_port = 443;
    flow.protocol = 6;
    const std::size_t owner = FlowToShard(flow, config.shard_count);
    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0, test::TcpFlags::Syn, {});

    NullPacketIo io(config.rx_queue_count);
    io.SetSendWouldBlock(true);
    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    std::atomic<bool> injected{true};
    std::vector<std::thread> producers;
    for (std::size_t source = 0; source < config.shard_count; ++source) {
        if (source == owner) continue;
        producers.emplace_back([&, source]() {
            for (std::size_t i = 0; i < 16; ++i) {
                BufferLease lease = rt.ShardPool(source)->Allocate();
                if (!lease) {
                    injected.store(false, std::memory_order_relaxed);
                    return;
                }
                std::memcpy(lease.Data(), syn.data(), syn.size());
                lease.Resize(syn.size());
                if (!io.Inject(source, std::move(lease))) {
                    injected.store(false, std::memory_order_relaxed);
                    return;
                }
            }
        });
    }
    for (auto& producer : producers) producer.join();

    TCPIP2_EXPECT_TRUE(injected.load(std::memory_order_relaxed));
    TCPIP2_EXPECT_TRUE(WaitFor([&] {
        return rt.Shard(owner)->TcpHalfOpenCount() == std::size_t{1};
    }));
    TCPIP2_EXPECT_TRUE(WaitFor([&] {
        for (std::size_t shard = 0; shard < config.shard_count; ++shard) {
            if (shard != owner && rt.Shard(shard)->RedirectedPackets() == 0) return false;
        }
        return true;
    }));
    TCPIP2_EXPECT_EQ(std::size_t{1}, rt.Shard(owner)->TcpHalfOpenCount());
    for (std::size_t shard = 0; shard < config.shard_count; ++shard) {
        if (shard == owner) continue;
        TCPIP2_EXPECT_EQ(std::size_t{0}, rt.Shard(shard)->TcpHalfOpenCount());
        TCPIP2_EXPECT_TRUE(rt.Shard(shard)->RedirectedPackets() > 0);
    }

    rt.Stop();
}

TCPIP2_TEST(RuntimeRoutesHashedTxThroughQueueOwner) {
    NetstackConfig config;
    config.shard_count = 2;
    config.rx_queue_count = 2;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    FlowKey selected;
    std::size_t tx_queue = 0;
    bool found = false;
    for (std::uint32_t port = 10000; port < 60000; ++port) {
        FlowKey flow;
        flow.source = IpAddress::Ipv4(10, 0, 0, 1);
        flow.destination = IpAddress::Ipv4(10, 0, 0, 2);
        flow.source_port = static_cast<std::uint16_t>(port);
        flow.destination_port = 443;
        flow.protocol = 6;
        const std::uint32_t fq_hash = static_cast<std::uint32_t>(FlowHash(flow) >> 32);
        if (FlowToShard(flow, config.shard_count) == 0 && fq_hash % config.rx_queue_count == 1) {
            selected = flow;
            tx_queue = 1;
            found = true;
            break;
        }
    }
    TCPIP2_EXPECT_TRUE(found);

    OwnerCheckingPacketIo io(config.rx_queue_count);
    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, selected.source_port, selected.destination_port,
        1000, 0, test::TcpFlags::Syn, {});
    BufferLease lease = rt.ShardPool(1)->Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), syn.data(), syn.size());
    lease.Resize(syn.size());
    TCPIP2_EXPECT_TRUE(io.Inject(1, std::move(lease)));

    TCPIP2_EXPECT_TRUE(WaitFor([&] {
        return rt.Shard(0)->TcpHalfOpenCount() == std::size_t{1};
    }));
    TCPIP2_EXPECT_TRUE(WaitFor([&] {
        return io.EgressSnapshot(tx_queue).size() == std::size_t{1};
    }));
    TCPIP2_EXPECT_EQ(std::size_t{0}, io.EgressSnapshot(0).size());
    TCPIP2_EXPECT_FALSE(io.SentFromForeignThread());

    rt.Stop();
}

TCPIP2_TEST(RuntimeRedirectsReassembledFragmentsToTcpFlowOwner) {
    NetstackConfig config;
    config.shard_count = 4;
    config.rx_queue_count = 4;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0, test::TcpFlags::Syn, {});
    const std::vector<std::uint8_t> first_segment(syn.begin() + 20, syn.begin() + 28);
    const std::vector<std::uint8_t> second_segment(syn.begin() + 28, syn.end());

    FlowKey flow;
    flow.source = IpAddress::Ipv4(10, 0, 0, 1);
    flow.destination = IpAddress::Ipv4(10, 0, 0, 2);
    flow.source_port = 40000;
    flow.destination_port = 443;
    flow.protocol = 6;
    const std::size_t flow_owner = FlowToShard(flow, config.shard_count);

    PacketDispatcher dispatcher(config.shard_count, config.rx_queue_count);
    std::uint16_t fragment_id = 0;
    std::size_t fragment_owner = flow_owner;
    std::vector<std::uint8_t> first_fragment;
    std::vector<std::uint8_t> second_fragment;
    for (std::uint32_t candidate = 1; candidate <= UINT16_MAX; ++candidate) {
        const std::uint16_t id = static_cast<std::uint16_t>(candidate);
        first_fragment = test::PacketBuilder::BuildIpv4TcpFragment(
            0x0a000001u, 0x0a000002u, id, 0, true, first_segment);
        const PacketClassification classified = dispatcher.ClassifyPacket(
            first_fragment.data(), first_fragment.size());
        if (classified.owner_shard == flow_owner) continue;
        fragment_id = id;
        fragment_owner = classified.owner_shard;
        second_fragment = test::PacketBuilder::BuildIpv4TcpFragment(
            0x0a000001u, 0x0a000002u, id, 1, false, second_segment);
        break;
    }
    TCPIP2_EXPECT_TRUE(fragment_id != 0);
    TCPIP2_EXPECT_TRUE(fragment_owner != flow_owner);

    NullPacketIo io(config.rx_queue_count);
    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    const std::size_t first_source = (fragment_owner + 1) % config.shard_count;
    const std::size_t second_source = (fragment_owner + 2) % config.shard_count;
    BufferLease first = rt.ShardPool(first_source)->Allocate();
    BufferLease second = rt.ShardPool(second_source)->Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(first));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(second));
    std::memcpy(first.Data(), first_fragment.data(), first_fragment.size());
    std::memcpy(second.Data(), second_fragment.data(), second_fragment.size());
    first.Resize(first_fragment.size());
    second.Resize(second_fragment.size());
    TCPIP2_EXPECT_TRUE(io.Inject(first_source, std::move(first)));
    TCPIP2_EXPECT_TRUE(io.Inject(second_source, std::move(second)));

    TCPIP2_EXPECT_TRUE(WaitFor([&] {
        return rt.Shard(flow_owner)->TcpHalfOpenCount() == std::size_t{1};
    }));
    TCPIP2_EXPECT_EQ(std::size_t{1}, rt.Shard(flow_owner)->TcpHalfOpenCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, rt.Shard(fragment_owner)->TcpHalfOpenCount());
    TCPIP2_EXPECT_TRUE(rt.Shard(fragment_owner)->RedirectedPackets() > 0);

    rt.Stop();
}

TCPIP2_TEST(RuntimeWiresPublicTcpConfiguration) {
    NetstackConfig config;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 2048;
    config.tcp_mss = 1200;
    config.initial_tcp_window = 32768;
    config.rto_initial_ms = 750;
    config.persist_timeout_ms = 300;
    config.time_wait_ms = 45000;
    config.keepalive_ms = 90000;

    NullPacketIo io(1);
    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    const TcpHandshakeConfig& tcp = rt.Shard(0)->TcpConfig();
    TCPIP2_EXPECT_EQ(std::uint16_t{1200}, tcp.local_mss);
    TCPIP2_EXPECT_EQ(std::uint32_t{32768}, tcp.receive_window);
    TCPIP2_EXPECT_EQ(std::uint64_t{750}, tcp.initial_rto_ms);
    TCPIP2_EXPECT_EQ(std::uint64_t{300}, tcp.persist_timer_max_ms);
    TCPIP2_EXPECT_EQ(std::uint64_t{300}, tcp.persist_timer_base_ms);
    TCPIP2_EXPECT_EQ(std::uint32_t{45000}, tcp.timewait_ms);
    TCPIP2_EXPECT_EQ(std::uint64_t{90000}, tcp.keepalive_ms);
    // pool_slot_capacity(2048) - kIpTcpMaxHeaderOverhead(100) = 1948
    TCPIP2_EXPECT_EQ(std::uint16_t{1948}, tcp.tx_payload_limit);
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

TCPIP2_TEST(RuntimeStopTimeoutRetainsPoolsAndAllowsRetry) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 1;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(1);
    io.SetAsyncTxCompletion(true);
    io.SetDrainTxWouldBlock(true);

    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0, test::TcpFlags::Syn, {});
    PktBufferPool* pool = rt.ShardPool(0);
    TCPIP2_EXPECT_TRUE(pool != nullptr);
    BufferLease lease = pool->Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    std::memcpy(lease.Data(), syn.data(), syn.size());
    lease.Resize(syn.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));
    TCPIP2_EXPECT_TRUE(WaitFor([&] {
        return io.PendingTxCompletions(0) != 0;
    }));

    StopOptions short_deadline;
    short_deadline.timeout_ms = 10;
    const StopResult timed_out = rt.Stop(short_deadline);
    TCPIP2_EXPECT_EQ(StopStatus::TimedOut, timed_out.status);
    TCPIP2_EXPECT_TRUE(timed_out.outstanding_tx != 0);
    TCPIP2_EXPECT_FALSE(rt.IsRunning());
    TCPIP2_EXPECT_TRUE(rt.IsStopping());
    TCPIP2_EXPECT_TRUE(rt.ShardPool(0) != nullptr);
    TCPIP2_EXPECT_FALSE(rt.Start(config, &io));

    // StopRx rejects external injection without taking ownership of the lease.
    BufferLease rejected = rt.ShardPool(0)->Allocate();
    rejected.Resize(1);
    TCPIP2_EXPECT_FALSE(io.Inject(0, std::move(rejected)));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(rejected));
    rejected.Reset();

    io.SetDrainTxWouldBlock(false);
    const StopResult stopped = rt.Stop(short_deadline);
    TCPIP2_EXPECT_TRUE(stopped.IsComplete());
    TCPIP2_EXPECT_EQ(StopStatus::Stopped, stopped.status);
    TCPIP2_EXPECT_EQ(std::size_t{0}, io.PendingTxCompletions(0));
    TCPIP2_EXPECT_TRUE(rt.ShardPool(0) == nullptr);
    TCPIP2_EXPECT_FALSE(rt.IsStopping());
}

TCPIP2_TEST(RuntimeConcurrentStopsObserveSameTimeout) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 1;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(1);
    io.SetAsyncTxCompletion(true);
    io.SetDrainTxWouldBlock(true);
    Runtime rt;
    TCPIP2_EXPECT_TRUE(rt.Start(config, &io));

    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0, test::TcpFlags::Syn, {});
    BufferLease lease = rt.ShardPool(0)->Allocate();
    std::memcpy(lease.Data(), syn.data(), syn.size());
    lease.Resize(syn.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return io.PendingTxCompletions(0) != 0; }));

    StopOptions short_deadline;
    short_deadline.timeout_ms = 25;
    StopResult first;
    StopResult second;
    std::thread first_stop([&] { first = rt.Stop(short_deadline); });
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    std::thread second_stop([&] { second = rt.Stop(short_deadline); });
    first_stop.join();
    second_stop.join();

    TCPIP2_EXPECT_EQ(StopStatus::TimedOut, first.status);
    TCPIP2_EXPECT_EQ(first.status, second.status);
    TCPIP2_EXPECT_EQ(first.outstanding_tx, second.outstanding_tx);

    io.SetDrainTxWouldBlock(false);
    StopOptions final_drain;
    final_drain.timeout_ms = 0;
    TCPIP2_EXPECT_TRUE(rt.Stop(final_drain).IsComplete());
}

TCPIP2_TEST(NetstackStopTimeoutRetainsFacadeRuntimeForRetry) {
    NetstackConfig config;
    config.shard_count = 1;
    config.rx_queue_count = 1;
    config.pool_slot_count = 64;
    config.pool_slot_capacity = 256;

    NullPacketIo io(1);
    io.SetAsyncTxCompletion(true);
    io.SetDrainTxWouldBlock(true);
    Netstack2 stack(config);
    TCPIP2_EXPECT_TRUE(stack.Start(&io));

    Runtime* runtime = stack.GetRuntime();
    TCPIP2_EXPECT_TRUE(runtime != nullptr);
    const std::vector<std::uint8_t> syn = test::PacketBuilder::BuildIpv4Tcp(
        0x0a000001u, 0x0a000002u, 40000, 443, 1000, 0, test::TcpFlags::Syn, {});
    BufferLease lease = runtime->ShardPool(0)->Allocate();
    std::memcpy(lease.Data(), syn.data(), syn.size());
    lease.Resize(syn.size());
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(lease)));
    TCPIP2_EXPECT_TRUE(WaitFor([&] { return io.PendingTxCompletions(0) != 0; }));

    StopOptions short_deadline;
    short_deadline.timeout_ms = 10;
    const StopResult timed_out = stack.Stop(short_deadline);
    TCPIP2_EXPECT_EQ(StopStatus::TimedOut, timed_out.status);
    TCPIP2_EXPECT_TRUE(stack.GetRuntime() != nullptr);
    TCPIP2_EXPECT_FALSE(stack.IsRunning());

    io.SetDrainTxWouldBlock(false);
    TCPIP2_EXPECT_TRUE(stack.Stop(short_deadline).IsComplete());
    TCPIP2_EXPECT_TRUE(stack.GetRuntime() == nullptr);
}

TCPIP2_TEST_MAIN();
