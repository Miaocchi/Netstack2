/**
 * @file openppp2_smoke_test.cpp
 * @brief End-to-end integration test simulating an OpenPPP2 adapter.
 * @license GPL-3.0
 *
 * This test uses only public headers and the test support library
 * (PacketBuilder/PacketParser). It exercises the full runtime path:
 *
 *   NullPacketIo (RX inject) → shard thread → IP parse → TCP engine
 *     → SYN-ACK (TX egress) → ACK → ESTABLISHED → data delivery to
 *     ITransportSession → FIN → ACK → Closed event
 *
 * The FakeSessionFactory returns a FakeSession that records delivered
 * bytes. A RecordingEventSink captures flow lifecycle events. This
 * validates the P4 acceptance criterion: a consumer can wire a packet
 * I/O backend and session factory into Netstack2 and complete a full
 * TCP connection lifecycle.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

#include <tcpip2/address.h>
#include <tcpip2/buffer.h>
#include <tcpip2/clock.h>
#include <tcpip2/config.h>
#include <tcpip2/events.h>
#include <tcpip2/netstack.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/runtime_deps.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/transport_session.h>

#include <core/runtime.h>

#include "PacketBuilder.h"
#include "Test.h"

using namespace tcpip2;

// ---------------------------------------------------------------------------
// FakeSession — ITransportSession that records delivered data
// ---------------------------------------------------------------------------

class FakeSession final : public ITransportSession {
public:
    SendResult TrySend(BufferView data) override {
        std::lock_guard<std::mutex> lock(mutex_);
        delivered_.insert(delivered_.end(), data.Data(), data.Data() + data.Size());
        return {data.Size(), SendStatus::Accepted};
    }

    void ShutdownWrite() override {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_write_called_ = true;
    }

    void Abort(SessionError) override {
        std::lock_guard<std::mutex> lock(mutex_);
        abort_called_ = true;
    }

    void SetWritableCallback(WritableCallback cb) override { writable_ = std::move(cb); }
    void SetDataCallback(DataCallback cb) override { data_ = std::move(cb); }
    void SetClosedCallback(ClosedCallback cb) override { closed_ = std::move(cb); }

    std::vector<std::uint8_t> Delivered() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return delivered_;
    }

    bool ShutdownWriteCalled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shutdown_write_called_;
    }

    bool AbortCalled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return abort_called_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::uint8_t> delivered_;
    bool shutdown_write_called_ = false;
    bool abort_called_ = false;
    WritableCallback writable_;
    DataCallback data_;
    ClosedCallback closed_;
};

// ---------------------------------------------------------------------------
// FakeSessionFactory — ISessionFactory that returns FakeSession
// ---------------------------------------------------------------------------

class FakeSessionFactory final : public ISessionFactory {
public:
    ~FakeSessionFactory() override {
        for (auto* s : created_) delete s;
    }

    SessionOpenResult OpenTcp(const TcpOpenRequest& request) override {
        std::lock_guard<std::mutex> lock(mutex_);
        ++open_tcp_count_;
        last_source_ = request.source;
        last_destination_ = request.original_destination;
        auto* session = new FakeSession();
        created_.push_back(session);
        SessionOpenResult result;
        result.session = session;
        return result;
    }

    DatagramOpenResult OpenUdp(const UdpOpenRequest&) override {
        return {};
    }

    int OpenTcpCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return open_tcp_count_;
    }

    IpEndpoint LastSource() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_source_;
    }

    IpEndpoint LastDestination() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_destination_;
    }

    FakeSession* LastSession() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return created_.empty() ? nullptr : created_.back();
    }

private:
    mutable std::mutex mutex_;
    int open_tcp_count_ = 0;
    IpEndpoint last_source_;
    IpEndpoint last_destination_;
    std::vector<FakeSession*> created_;
};

// ---------------------------------------------------------------------------
// RecordingEventSink — captures flow events and metric snapshots
// ---------------------------------------------------------------------------

class RecordingEventSink final : public IEventSink {
public:
    void OnFlowEvent(const FlowEvent& event) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        flow_events_.push_back({event.flow_id, event.type});
    }

    void OnMetricSnapshot(const MetricSnapshot& snapshot) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        ++metric_count_;
        last_snapshot_ = snapshot;
    }

    struct RecordedEvent {
        FlowId flow_id;
        FlowEventType type;
    };

    std::vector<RecordedEvent> FlowEvents() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flow_events_;
    }

    int MetricCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return metric_count_;
    }

    MetricSnapshot LastSnapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_snapshot_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<RecordedEvent> flow_events_;
    int metric_count_ = 0;
    MetricSnapshot last_snapshot_;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

/// Wait for at least `min_count` egress packets on queue 0.
/// Returns a snapshot of the egress vector, or an empty vector on timeout.
std::vector<std::vector<std::uint8_t>> WaitForEgress(NullPacketIo& io,
                                                      std::size_t min_count,
                                                      int max_attempts = 200) {
    for (int i = 0; i < max_attempts; ++i) {
        auto eg = io.EgressSnapshot(0);
        if (eg.size() >= min_count) return eg;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return {};
}

/// Inject a raw packet into queue 0 using the runtime's shard pool.
bool InjectPacket(NullPacketIo& io, PktBufferPool* pool,
                  const std::vector<std::uint8_t>& bytes) {
    BufferLease lease = pool->Allocate();
    if (!lease) return false;
    if (bytes.size() > lease.Capacity()) return false;
    std::copy(bytes.begin(), bytes.end(), lease.Data());
    lease.Resize(bytes.size());
    return io.Inject(0, std::move(lease));
}

} // namespace

// ---------------------------------------------------------------------------
// Test: full TCP connection lifecycle via public API
// ---------------------------------------------------------------------------

TCPIP2_TEST(OpenPpp2SmokeTestFullLifecycle) {
    // --- Setup ---
    NullPacketIo io(1);
    FakeSessionFactory factory;
    RecordingEventSink sink;
    SystemClock clock;

    NetstackConfig ns_config;
    ns_config.shard_count = 1;
    ns_config.rx_queue_count = 1;
    ns_config.pool_slot_count = 64;
    ns_config.pool_slot_capacity = 2048;

    Netstack2 stack(ns_config);
    RuntimeDependencies deps;
    deps.packet_io = &io;
    deps.session_factory = &factory;
    deps.clock = &clock;
    deps.event_sink = &sink;

    TCPIP2_EXPECT_TRUE(stack.Start(deps));
    TCPIP2_EXPECT_TRUE(stack.IsRunning());

    Runtime* rt = stack.GetRuntime();
    TCPIP2_EXPECT_TRUE(rt != nullptr);
    PktBufferPool* pool = rt->ShardPool(0);
    TCPIP2_EXPECT_TRUE(pool != nullptr);

    // Addresses: 10.0.0.1:40000 → 10.0.0.2:80
    const std::uint32_t client_ip = 0x0A000001;  // 10.0.0.1
    const std::uint32_t server_ip = 0x0A000002;  // 10.0.0.2
    const std::uint16_t client_port = 40000;
    const std::uint16_t server_port = 80;
    const std::uint32_t client_isn = 1000;

    // --- Step 1: SYN ---
    {
        auto syn = test::PacketBuilder::BuildIpv4Tcp(
            client_ip, server_ip, client_port, server_port,
            client_isn, 0, test::TcpFlags::Syn, {});
        TCPIP2_EXPECT_TRUE(InjectPacket(io, pool, syn));
    }

    // Wait for SYN-ACK
    auto egress1 = WaitForEgress(io, 1);
    TCPIP2_EXPECT_TRUE(!egress1.empty());

    // Parse SYN-ACK to extract server ISN
    auto synack = test::PacketParser::ParseIpv4Tcp(egress1.back());
    TCPIP2_EXPECT_TRUE(synack.valid);
    TCPIP2_EXPECT_TRUE(synack.tcp_checksum_ok);
    TCPIP2_EXPECT_TRUE(static_cast<bool>(synack.flags & test::TcpFlags::Syn));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(synack.flags & test::TcpFlags::Ack));
    TCPIP2_EXPECT_EQ(synack.ack, client_isn + 1);

    const std::uint32_t server_isn = synack.seq;

    // --- Step 2: ACK to complete handshake ---
    {
        auto ack = test::PacketBuilder::BuildIpv4Tcp(
            client_ip, server_ip, client_port, server_port,
            client_isn + 1, server_isn + 1, test::TcpFlags::Ack, {});
        TCPIP2_EXPECT_TRUE(InjectPacket(io, pool, ack));
    }

    // Wait a bit for the shard to process the ACK and enter ESTABLISHED.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Verify factory was called with correct endpoints.
    TCPIP2_EXPECT_EQ(1, factory.OpenTcpCount());
    TCPIP2_EXPECT_EQ(client_port, factory.LastSource().port);
    TCPIP2_EXPECT_EQ(server_port, factory.LastDestination().port);

    // Verify ESTABLISHED event was emitted.
    {
        auto events = sink.FlowEvents();
        bool found_established = false;
        for (const auto& e : events) {
            if (e.type == FlowEventType::Established) {
                found_established = true;
                break;
            }
        }
        TCPIP2_EXPECT_TRUE(found_established);
    }

    // --- Step 3: Data segment "hello" ---
    const std::vector<std::uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};
    {
        auto data = test::PacketBuilder::BuildIpv4Tcp(
            client_ip, server_ip, client_port, server_port,
            client_isn + 1, server_isn + 1,
            test::TcpFlags::Ack | test::TcpFlags::Psh, payload);
        TCPIP2_EXPECT_TRUE(InjectPacket(io, pool, data));
    }

    // Wait for data to be delivered to the session.
    {
        FakeSession* session = factory.LastSession();
        TCPIP2_EXPECT_TRUE(session != nullptr);
        std::vector<std::uint8_t> delivered;
        for (int i = 0; i < 100; ++i) {
            delivered = session->Delivered();
            if (delivered.size() >= payload.size()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        TCPIP2_EXPECT_EQ(payload.size(), delivered.size());
        if (delivered.size() >= payload.size()) {
            TCPIP2_EXPECT_TRUE(std::equal(payload.begin(), payload.end(),
                                          delivered.begin()));
        }
    }

    // --- Step 4: FIN from client ---
    {
        auto fin = test::PacketBuilder::BuildIpv4Tcp(
            client_ip, server_ip, client_port, server_port,
            client_isn + 1 + static_cast<std::uint32_t>(payload.size()), server_isn + 1,
            test::TcpFlags::Fin | test::TcpFlags::Ack, {});
        TCPIP2_EXPECT_TRUE(InjectPacket(io, pool, fin));
    }

    // Wait for the server's ACK to our FIN.
    auto egress_fin = WaitForEgress(io, egress1.size() + 1);
    TCPIP2_EXPECT_TRUE(egress_fin.size() > egress1.size());

    // Wait a bit more for any close event.
    // The server enters CLOSE-WAIT after receiving our FIN.  It stays there
    // until the application calls CloseFlow() (which sends the server's FIN
    // and moves to LAST-ACK).  Since the test never triggers a local close,
    // the PCB remains in CLOSE-WAIT and the Closed event is only emitted
    // during stack.Stop() → Shutdown().  Verify the FIN ACK was sent, then
    // check for Closed/Reset after Stop().
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Verify a Closed or Reset event was emitted before Stop().
    // In the current implementation the server stays in CLOSE-WAIT (no
    // application-triggered close), so the Closed event is emitted during
    // Shutdown() below.  This is a known limitation: a real consumer would
    // call CloseFlow() after receiving the peer's FIN.
    {
        auto events = sink.FlowEvents();
        bool found_close = false;
        for (const auto& e : events) {
            if (e.type == FlowEventType::Closed ||
                e.type == FlowEventType::Reset) {
                found_close = true;
                break;
            }
        }
        // Not asserted yet — the event may only arrive after Stop().
        (void)found_close;
    }

    // --- Cleanup ---
    stack.Stop();
    TCPIP2_EXPECT_FALSE(stack.IsRunning());

    // Verify a Closed or Reset event was emitted (now including Shutdown()).
    {
        auto events = sink.FlowEvents();
        bool found_close = false;
        for (const auto& e : events) {
            if (e.type == FlowEventType::Closed ||
                e.type == FlowEventType::Reset) {
                found_close = true;
                break;
            }
        }
        TCPIP2_EXPECT_TRUE(found_close);
    }
}

TCPIP2_TEST_MAIN()
