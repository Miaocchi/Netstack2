/**
 * @file compile_contract_test.cpp
 * @brief Consumer TU that exercises every public header — API-FREEZE-001 contract.
 * @license GPL-3.0
 *
 * This translation unit includes every public header in include/tcpip2/
 * exactly as an external consumer would, and touches the public API. It
 * proves the public headers are self-contained and usable together.
 *
 * After NETSTACK2-API-FREEZE-001 this TU also serves as the frozen-signature
 * guard: static_asserts below pin the move-only/copyable/trivially-copyable
 * properties of every public type. If a future change alters a frozen
 * signature this TU fails to compile, signaling a freeze violation that
 * requires an ADR.
 */

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <tcpip2/address.h>
#include <tcpip2/buffer.h>
#include <tcpip2/capabilities.h>
#include <tcpip2/config.h>
#include <tcpip2/flow.h>
#include <tcpip2/netstack.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/transport_session.h>

#include "Test.h"

using namespace tcpip2;

// ---------------------------------------------------------------------------
// Frozen-signature static asserts
// ---------------------------------------------------------------------------

// Buffer ownership
static_assert(std::is_move_constructible_v<BufferLease>,
              "BufferLease must be move constructible (frozen)");
static_assert(!std::is_copy_constructible_v<BufferLease>,
              "BufferLease must be move-only (frozen)");
static_assert(std::is_nothrow_move_constructible_v<BufferLease>,
              "BufferLease move must be noexcept (frozen)");
static_assert(std::is_trivially_copyable_v<BufferSlice>,
              "BufferSlice must be trivially copyable (frozen)");
static_assert(std::is_copy_constructible_v<BufferRef>,
              "BufferRef must be copyable (frozen)");
static_assert(std::is_move_constructible_v<BufferRef>,
              "BufferRef must be move constructible (frozen)");
static_assert(std::is_standard_layout_v<PktBuffer>,
              "PktBuffer must keep standard layout (frozen)");

// Transport session
static_assert(std::is_trivially_copyable_v<BufferView>,
              "BufferView must be trivially copyable (frozen)");

// Address / Flow
static_assert(std::is_copy_constructible_v<IpAddress>,
              "IpAddress must be copyable (frozen)");
static_assert(std::is_standard_layout_v<IpAddress>,
              "IpAddress must be standard layout (frozen)");
static_assert(std::is_copy_constructible_v<FlowKey>,
              "FlowKey must be copyable (frozen)");
static_assert(std::is_standard_layout_v<FlowKey>,
              "FlowKey must be standard layout (frozen)");

// Session factory
static_assert(std::is_trivially_copyable_v<FlowId>,
              "FlowId must be trivially copyable (frozen)");
static_assert(std::is_standard_layout_v<FlowId>,
              "FlowId must be standard layout (frozen)");
static_assert(std::is_copy_constructible_v<IpEndpoint>,
              "IpEndpoint must be copyable (frozen)");
static_assert(std::is_standard_layout_v<IpEndpoint>,
              "IpEndpoint must be standard layout (frozen)");
static_assert(std::is_copy_constructible_v<TcpOpenRequest>,
              "TcpOpenRequest must be copyable (frozen)");
static_assert(std::is_copy_constructible_v<UdpOpenRequest>,
              "UdpOpenRequest must be copyable (frozen)");
static_assert(std::is_copy_constructible_v<SessionOpenResult>,
              "SessionOpenResult must be copyable (frozen)");
static_assert(std::is_copy_constructible_v<DatagramOpenResult>,
              "DatagramOpenResult must be copyable (frozen)");

// Capabilities
static_assert(std::is_copy_constructible_v<PacketIoCapabilities>,
              "PacketIoCapabilities must be copyable (frozen)");
static_assert(std::is_standard_layout_v<PacketIoCapabilities>,
              "PacketIoCapabilities must be standard layout (frozen)");

// Config
static_assert(std::is_copy_constructible_v<NetstackConfig>,
              "NetstackConfig must be copyable (frozen)");

// ---------------------------------------------------------------------------
// Runtime contract exercise
// ---------------------------------------------------------------------------

TCPIP2_TEST(PublicHeadersConsumeCleanly) {
    // config + facade
    NetstackConfig config;
    config.shard_count = 2;
    config.rx_queue_count = 1;
    Netstack2 stack(config);
    TCPIP2_EXPECT_TRUE(stack.Start());
    TCPIP2_EXPECT_TRUE(stack.IsRunning());
    TCPIP2_EXPECT_TRUE(stack.Config().Validate());
    stack.Stop();
    TCPIP2_EXPECT_FALSE(stack.IsRunning());

    // buffer ownership types
    PktBufferPool pool(4, 512);
    BufferLease lease = pool.Allocate();
    lease.Resize(8);
    BufferSlice slice(lease.Data(), lease.Size());
    TCPIP2_EXPECT_EQ(std::size_t{8}, slice.Size());
    TCPIP2_EXPECT_FALSE(slice.Empty());
    BufferSlice sub = slice.Subslice(2, 4);
    TCPIP2_EXPECT_EQ(std::size_t{4}, sub.Size());
    BufferRef ref = pool.Retain(std::move(lease));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(ref));
    ref.Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.ReturnQueueSize());
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.DrainReturnQueue());

    // packet I/O
    NullPacketIo io(1);
    io.SetMaxSendPerBatch(1);
    io.SetRecvWouldBlock(false);
    io.SetSendWouldBlock(false);
    io.SetAsyncTxCompletion(true);
    TCPIP2_EXPECT_EQ(std::size_t{1}, io.QueueCount());
    std::unique_ptr<IPacketQueue> q = io.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);
    BufferLease out[1];
    IoError err = IoError::Internal;
    TCPIP2_EXPECT_EQ(std::size_t{0}, q->RecvBatch(out, 1, err));
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    q->SetRecvHandler([] {});
    TCPIP2_EXPECT_EQ(std::size_t{0}, io.PendingTxCompletions(0));
    io.DrainTxCompletions(0);

    // transport session types
    BufferView view(nullptr, 0);
    TCPIP2_EXPECT_TRUE(view.Empty());
    const std::uint8_t one = 1;
    BufferView view2(&one, 1);
    TCPIP2_EXPECT_FALSE(view2.Empty());
    SendResult r;
    TCPIP2_EXPECT_TRUE(r.status == SendStatus::Accepted);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.accepted_bytes);

    // session factory types
    FlowId fid{99};
    TCPIP2_EXPECT_EQ(std::uint64_t{99}, fid.value);
    IpEndpoint ep;
    ep.address = IpAddress::Ipv4(10, 0, 0, 1);
    ep.port = 8080;
    TCPIP2_EXPECT_EQ(std::uint16_t{8080}, ep.port);
    TcpOpenRequest tcp_req;
    tcp_req.flow_id = fid;
    tcp_req.source = ep;
    tcp_req.route_mark = 42;
    tcp_req.dscp = 46;
    TCPIP2_EXPECT_EQ(std::uint32_t{42}, tcp_req.route_mark);
    UdpOpenRequest udp_req;
    udp_req.flow_id = fid;
    udp_req.source = ep;
    SessionOpenResult sr;
    TCPIP2_EXPECT_TRUE(sr.session == nullptr);
    TCPIP2_EXPECT_TRUE(sr.error == SessionError::None);
    DatagramOpenResult dr;
    TCPIP2_EXPECT_TRUE(dr.handle == nullptr);
    TCPIP2_EXPECT_TRUE(dr.error == SessionError::None);

    // capabilities
    PacketIoCapabilities caps;
    TCPIP2_EXPECT_TRUE(caps.link_mode == LinkMode::L3);
    TCPIP2_EXPECT_EQ(std::uint16_t{1500}, caps.mtu);
    TCPIP2_EXPECT_TRUE(caps.poll_mode == PollMode::Event);
    TCPIP2_EXPECT_FALSE(caps.rx_checksum_offload);
    // IPacketIo::Capabilities() default override
    NullPacketIo cap_io(1);
    PacketIoCapabilities default_caps = cap_io.Capabilities();
    TCPIP2_EXPECT_EQ(std::uint16_t{1500}, default_caps.mtu);
}

TCPIP2_TEST_MAIN();
