/**
 * @file openppp_adapter_spike_test.cpp
 * @brief Compile-only adapter spike proving public headers suffice for OpenPPP2.
 * @license GPL-3.0
 *
 * This translation unit implements an OpenPppPacketIo (IPacketIo +
 * IPacketQueue) and an OpenPppSessionFactory (ISessionFactory) using ONLY
 * public headers from include/tcpip2/. No OpenPPP2, Boost, or platform-specific
 * headers are required. The test validates that the public API is sufficient
 * for an external consumer to wire a packet I/O backend and session factory
 * into Netstack2.
 *
 * The implementations are stubs — they compile and link but do not send or
 * receive real packets. This is a spike, not a functional adapter.
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <tcpip2/address.h>
#include <tcpip2/buffer.h>
#include <tcpip2/capabilities.h>
#include <tcpip2/config.h>
#include <tcpip2/netstack.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/transport_session.h>

#include "Test.h"

using namespace tcpip2;

// ---------------------------------------------------------------------------
// OpenPppPacketIo — IPacketIo + IPacketQueue
// ---------------------------------------------------------------------------

class OpenPppPacketIo final : public IPacketIo {
  public:
    struct Config {
        /** Route mark applied to packets egressing the tunnel. */
        std::uint32_t route_mark = 0;
        /** Fake-IP subnet base for the tunnel's internal addressing. */
        std::uint32_t fake_ip_base = 0;
        /** DNS server addresses (as IPv4 uint32_t) pushed to tunnel clients. */
        std::vector<std::uint32_t> dns_servers;
        /** QUIC policy metadata (opaque to Netstack2 core). */
        std::uint8_t quic_policy = 0;
        /** Path MTU for the tunnel. */
        std::uint16_t pmtu = 1500;
        /** Number of hardware queues to expose. */
        std::size_t queue_count = 1;
    };

    OpenPppPacketIo() = default;

    ~OpenPppPacketIo() override = default;

    OpenPppPacketIo(const OpenPppPacketIo &) = delete;
    OpenPppPacketIo &operator=(const OpenPppPacketIo &) = delete;

    void SetConfig(const Config &config) noexcept {
        config_ = config;
        caps_.mtu = config.pmtu;
        caps_.queue_count = config.queue_count;
    }

    // IPacketIo overrides

    std::size_t QueueCount() const noexcept override { return config_.queue_count; }

    std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) override {
        if (queue_id >= config_.queue_count)
            return nullptr;
        return std::make_unique<OpenPppQueue>(queue_id);
    }

    PacketIoCapabilities Capabilities() const noexcept override { return caps_; }

  private:
    class OpenPppQueue final : public IPacketQueue {
      public:
        explicit OpenPppQueue(std::size_t queue_id) noexcept : queue_id_(queue_id) {}

        ~OpenPppQueue() override = default;

        std::size_t RecvBatch(BufferLease /*out*/[], std::size_t /*capacity*/, IoError &error) noexcept override {
            error = IoError::WouldBlock;
            return 0;
        }

        std::size_t SendBatch(BufferLease /*packets*/[], std::size_t count, IoError &error) noexcept override {
            error = IoError::None;
            return count;
        }

        std::size_t QueueId() const noexcept override { return queue_id_; }

        void SetBufferPool(PktBufferPool *pool) noexcept override { pool_ = pool; }

        void StopRx() noexcept override {}
        IoError DrainTx(std::uint64_t) noexcept override { return IoError::None; }
        std::size_t OutstandingTx() const noexcept override { return 0; }

        void SetRecvHandler(std::function<void()> wake) override { wake_ = std::move(wake); }

      private:
        std::size_t queue_id_;
        PktBufferPool *pool_ = nullptr;
        std::function<void()> wake_;
    };

    Config config_;
    PacketIoCapabilities caps_;
};

// ---------------------------------------------------------------------------
// OpenPppSessionFactory — ISessionFactory
// ---------------------------------------------------------------------------

class OpenPppSessionFactory final : public ISessionFactory {
  public:
    struct Config {
        std::uint32_t route_mark = 0;
        std::uint32_t fake_ip_base = 0;
        std::vector<std::uint32_t> dns_servers;
        std::uint8_t quic_policy = 0;
        std::uint16_t pmtu = 1500;
    };

    OpenPppSessionFactory() = default;

    explicit OpenPppSessionFactory(const Config &config) noexcept : config_(config) {}

    ~OpenPppSessionFactory() override = default;

    SessionOpenResult OpenTcp(const TcpOpenRequest & /*request*/) override {
        // Stub: real adapter creates a transport session here.
        return SessionOpenResult{};
    }

    DatagramOpenResult OpenUdp(const UdpOpenRequest & /*request*/) override {
        // Stub: real adapter creates a datagram channel here.
        return DatagramOpenResult{};
    }

  private:
    Config config_;
};

// ---------------------------------------------------------------------------
// Test: the adapter compiles and wires into Netstack2
// ---------------------------------------------------------------------------

TCPIP2_TEST(OpenPppAdapterCompiles) {
    // Configure the packet I/O backend with route/fake-IP/DNS/QUIC/PMTU metadata.
    OpenPppPacketIo::Config io_config;
    io_config.route_mark = 100;
    io_config.fake_ip_base = 0x0A000000;         // 10.0.0.0
    io_config.dns_servers.push_back(0x08080808); // 8.8.8.8
    io_config.quic_policy = 1;
    io_config.pmtu = 1400;
    io_config.queue_count = 2;

    OpenPppPacketIo io;
    io.SetConfig(io_config);

    // Verify capabilities propagate from config.
    const PacketIoCapabilities caps = io.Capabilities();
    TCPIP2_EXPECT_EQ(std::uint16_t{1400}, caps.mtu);
    TCPIP2_EXPECT_EQ(std::size_t{2}, caps.queue_count);
    TCPIP2_EXPECT_EQ(std::size_t{2}, io.QueueCount());

    // Open queues and verify basic wiring.
    auto q0 = io.OpenQueue(0);
    auto q1 = io.OpenQueue(1);
    auto q2 = io.OpenQueue(2); // out of range
    TCPIP2_EXPECT_TRUE(q0 != nullptr);
    TCPIP2_EXPECT_TRUE(q1 != nullptr);
    TCPIP2_EXPECT_TRUE(q2 == nullptr);

    TCPIP2_EXPECT_EQ(std::size_t{0}, q0->QueueId());
    TCPIP2_EXPECT_EQ(std::size_t{1}, q1->QueueId());

    // Queue accepts a pool pointer and a recv handler (event mode).
    PktBufferPool pool(4, 512);
    q0->SetBufferPool(&pool);
    int wake_count = 0;
    q0->SetRecvHandler([&wake_count] { ++wake_count; });

    // Stub RecvBatch returns 0 with WouldBlock (poll-style contract).
    BufferLease out[1];
    IoError err = IoError::None;
    TCPIP2_EXPECT_EQ(std::size_t{0}, q0->RecvBatch(out, 1, err));
    TCPIP2_EXPECT_TRUE(err == IoError::WouldBlock);

    // Stub SendBatch accepts all packets (returns count, None).
    BufferLease pkts[1];
    pkts[0] = pool.Allocate();
    pkts[0].Resize(4);
    IoError send_err = IoError::Internal;
    TCPIP2_EXPECT_EQ(std::size_t{1}, q0->SendBatch(pkts, 1, send_err));
    TCPIP2_EXPECT_TRUE(send_err == IoError::None);
    // The stub "accepted" the packet but does not release the lease — the
    // caller still owns it and must release it explicitly.
    TCPIP2_EXPECT_TRUE(static_cast<bool>(pkts[0]));
    pkts[0].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());

    // Configure the session factory with route/fake-IP/DNS/QUIC/PMTU metadata.
    OpenPppSessionFactory::Config sf_config;
    sf_config.route_mark = 100;
    sf_config.fake_ip_base = 0x0A000000;
    sf_config.dns_servers.push_back(0x08080808);
    sf_config.quic_policy = 1;
    sf_config.pmtu = 1400;

    OpenPppSessionFactory factory(sf_config);

    // Stub OpenTcp returns nullptr session with None (no real session created).
    TcpOpenRequest tcp_req;
    tcp_req.flow_id = FlowId{42};
    tcp_req.source.address = IpAddress::Ipv4(10, 0, 0, 1);
    tcp_req.source.port = 12345;
    tcp_req.original_destination.address = IpAddress::Ipv4(93, 184, 216, 34);
    tcp_req.original_destination.port = 80;
    tcp_req.resolved_destination = tcp_req.original_destination;
    tcp_req.route_mark = 100;
    tcp_req.dscp = 0;

    SessionOpenResult tcp_result = factory.OpenTcp(tcp_req);
    TCPIP2_EXPECT_TRUE(tcp_result.session == nullptr);
    TCPIP2_EXPECT_TRUE(tcp_result.error == SessionError::None);

    // Stub OpenUdp returns nullptr handle with None.
    UdpOpenRequest udp_req;
    udp_req.flow_id = FlowId{43};
    udp_req.source.address = IpAddress::Ipv4(10, 0, 0, 1);
    udp_req.source.port = 54321;
    udp_req.original_destination.address = IpAddress::Ipv4(8, 8, 8, 8);
    udp_req.original_destination.port = 53;
    udp_req.resolved_destination = udp_req.original_destination;
    udp_req.route_mark = 100;
    udp_req.dscp = 0;

    DatagramOpenResult udp_result = factory.OpenUdp(udp_req);
    TCPIP2_EXPECT_TRUE(udp_result.handle == nullptr);
    TCPIP2_EXPECT_TRUE(udp_result.error == SessionError::None);

    // Wire the packet I/O and session factory into Netstack2 via
    // RuntimeDependencies (ADR-005) — the structured injection path.
    NetstackConfig ns_config;
    ns_config.shard_count = 1;
    ns_config.rx_queue_count = 1;
    Netstack2 stack(ns_config);
    RuntimeDependencies deps;
    deps.packet_io = &io;
    deps.session_factory = &factory;
    TCPIP2_EXPECT_TRUE(stack.Start(deps));
    TCPIP2_EXPECT_TRUE(stack.IsRunning());
    stack.Stop();
    TCPIP2_EXPECT_FALSE(stack.IsRunning());
}

TCPIP2_TEST_MAIN();
