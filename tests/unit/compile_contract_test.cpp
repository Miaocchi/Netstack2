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
#include <tcpip2/clock.h>
#include <tcpip2/config.h>
#include <tcpip2/events.h>
#include <tcpip2/flow.h>
#include <tcpip2/netstack.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/runtime_deps.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/tap_io.h>
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

// TapPacketIo (concrete backend)
static_assert(std::is_final_v<TapPacketIo>,
              "TapPacketIo must be final (frozen)");
static_assert(!std::is_copy_constructible_v<TapPacketIo>,
              "TapPacketIo must be non-copyable (frozen)");

// Clock / Events (P4-1)
static_assert(std::is_abstract_v<IClock>,
              "IClock must be abstract (frozen)");
static_assert(std::is_final_v<SystemClock>,
              "SystemClock must be final (frozen)");
static_assert(std::is_copy_constructible_v<FlowEvent>,
              "FlowEvent must be copyable (frozen)");
static_assert(std::is_standard_layout_v<FlowEvent>,
              "FlowEvent must be standard layout (frozen)");
static_assert(std::is_copy_constructible_v<MetricSnapshot>,
              "MetricSnapshot must be copyable (frozen)");
static_assert(std::is_standard_layout_v<MetricSnapshot>,
              "MetricSnapshot must be standard layout (frozen)");
static_assert(std::is_abstract_v<IEventSink>,
              "IEventSink must be abstract (frozen)");
static_assert(std::is_copy_constructible_v<RuntimeDependencies>,
              "RuntimeDependencies must be copyable (frozen)");
static_assert(std::is_standard_layout_v<RuntimeDependencies>,
              "RuntimeDependencies must be standard layout (frozen)");
static_assert(std::is_trivially_copyable_v<RuntimeDependencies>,
              "RuntimeDependencies must be trivially copyable (frozen)");

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

    // clock + events (P4-1)
    SystemClock sys_clock;
    TCPIP2_EXPECT_TRUE(sys_clock.NowMs() > 0);
    TCPIP2_EXPECT_TRUE(sys_clock.NowUs() > 0);
    IClock* default_clock = DefaultClock();
    TCPIP2_EXPECT_TRUE(default_clock != nullptr);
    TCPIP2_EXPECT_TRUE(default_clock->NowMs() > 0);

    // RuntimeDependencies validation
    RuntimeDependencies deps;
    TCPIP2_EXPECT_FALSE(deps.Validate());  // null packet_io + session_factory
    deps.packet_io = &io;
    TCPIP2_EXPECT_FALSE(deps.Validate());  // still missing session_factory
    deps.session_factory = nullptr;
    TCPIP2_EXPECT_FALSE(deps.Validate());
    deps.clock = &sys_clock;
    TCPIP2_EXPECT_FALSE(deps.Validate());  // still missing mandatory deps

    // FlowEvent / MetricSnapshot default-constructible and copyable
    FlowEvent fe;
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, fe.flow_id.value);
    TCPIP2_EXPECT_TRUE(fe.type == FlowEventType::Closed);
    MetricSnapshot ms;
    TCPIP2_EXPECT_EQ(std::size_t{0}, ms.shard_id);
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms.rx_packets);

    // FlowEventType enum values
    TCPIP2_EXPECT_TRUE(FlowEventType::Established != FlowEventType::Closed);
    TCPIP2_EXPECT_TRUE(FlowEventType::Reset != FlowEventType::Closed);

    // MetricSnapshot all fields default-constructible
    MetricSnapshot ms2;
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms2.rx_bytes);
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms2.tx_packets);
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms2.tx_bytes);
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms2.tcp_pcb_count);
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms2.tcp_half_open_count);
    TCPIP2_EXPECT_EQ(std::uint64_t{0}, ms2.udp_datagrams);

    // RuntimeDependencies with all deps set (including optional clock/event_sink)
    RuntimeDependencies full_deps;
    full_deps.packet_io = &io;
    // session_factory remains null — can't construct a real one here,
    // but Validate() requires both packet_io and session_factory
    TCPIP2_EXPECT_FALSE(full_deps.Validate());  // no session_factory
    full_deps.clock = &sys_clock;
    full_deps.event_sink = nullptr;  // optional, null is OK
    TCPIP2_EXPECT_FALSE(full_deps.Validate());  // still no session_factory

    // FlowKey canonicalization
    FlowKey fk;
    fk.source = IpAddress::Ipv4(10, 0, 0, 1);
    fk.destination = IpAddress::Ipv4(10, 0, 0, 2);
    fk.source_port = 1234;
    fk.destination_port = 80;
    fk.protocol = 6;
    FlowKey canon = fk.Canonical();
    // Canonical should swap so source <= destination
    TCPIP2_EXPECT_TRUE(canon.source == IpAddress::Ipv4(10, 0, 0, 1));

    // TapPacketIo default-constructible and non-open
    TapPacketIo tap;
    TCPIP2_EXPECT_FALSE(tap.IsOpen());
    TCPIP2_EXPECT_EQ(std::size_t{0}, tap.QueueCount());
    tap.Close();  // idempotent on unopened

    // Start(const RuntimeDependencies&) with invalid deps returns false
    Netstack2 stack2(config);
    TCPIP2_EXPECT_FALSE(stack2.Start(full_deps));  // Validate() fails
    TCPIP2_EXPECT_FALSE(stack2.IsRunning());

    // Start(const RuntimeDependencies&) with null packet_io returns false
    RuntimeDependencies null_deps;
    TCPIP2_EXPECT_FALSE(stack2.Start(null_deps));
    TCPIP2_EXPECT_FALSE(stack2.IsRunning());
}

TCPIP2_TEST_MAIN();
