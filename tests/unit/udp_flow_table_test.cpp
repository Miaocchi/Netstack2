/**
 * @file udp_flow_table_test.cpp
 * @brief Unit tests for the shard-local UDP flow table (R7).
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include "FakeUdpSession.h"
#include "Test.h"
#include <udp/flow_table.h>

using namespace tcpip2;

namespace {

FlowKey MakeUdpFlow(std::uint16_t src_port = 12345, std::uint16_t dst_port = 53) {
    FlowKey flow;
    flow.source = IpAddress::Ipv4(10, 0, 0, 1);
    flow.destination = IpAddress::Ipv4(10, 0, 0, 2);
    flow.source_port = src_port;
    flow.destination_port = dst_port;
    flow.protocol = 17;
    return flow;
}

/// PostMessageFn that records the last message so the test can feed it back
/// through OnRemoteData (simulating shard processing). State lives in a
/// shared_ptr because std::function stores a copy of the callable.
class PostRecorder {
  public:
    struct State {
        ShardMessageType last_type = ShardMessageType::kControl;
        std::uint64_t last_flow_id = 0;
    };
    std::shared_ptr<State> state = std::make_shared<State>();

    bool operator()(ShardMessage &&msg) noexcept {
        state->last_type = msg.type;
        state->last_flow_id = msg.flow_id.value;
        return true;
    }
};

std::vector<std::uint8_t> Payload(std::size_t n, std::uint8_t fill = 0xAB) {
    return std::vector<std::uint8_t>(n, fill);
}

} // namespace

TCPIP2_TEST(UdpFlowOpensSessionOnFirstDatagram) {
    UdpFlowConfig config;
    test::FakeSessionFactory factory;
    PostRecorder post;
    UdpFlowTable table(config, &factory, DefaultClock(), post);
    std::vector<std::uint8_t> lease_store;

    const FlowKey flow = MakeUdpFlow();
    const auto payload = Payload(4);
    const UdpFlowTable::Dispatch d = table.OnClientDatagram(flow, payload.data(), payload.size(), 1000);
    TCPIP2_EXPECT_EQ(UdpFlowTable::Dispatch::Accepted, d);
    TCPIP2_EXPECT_EQ(std::size_t{1}, factory.OpenCalls());
    TCPIP2_EXPECT_EQ(std::size_t{1}, factory.SessionCount());
    TCPIP2_EXPECT_EQ(payload, factory.Session(0)->Received());
    TCPIP2_EXPECT_EQ(std::size_t{1}, factory.Session(0)->SendCalls());
    TCPIP2_EXPECT_EQ(std::size_t{1}, table.Size());

    // Second datagram on the same flow reuses the session.
    const auto payload2 = Payload(3, 0xCD);
    table.OnClientDatagram(flow, payload2.data(), payload2.size(), 1010);
    TCPIP2_EXPECT_EQ(std::size_t{1}, factory.OpenCalls());
    TCPIP2_EXPECT_EQ(payload2, factory.Session(0)->Received());
    TCPIP2_EXPECT_EQ(std::size_t{2}, factory.Session(0)->SendCalls());

    UdpFlowSnapshot snap;
    TCPIP2_EXPECT_TRUE(table.Find(flow, snap));
    TCPIP2_EXPECT_TRUE(snap.session_bound);
    TCPIP2_EXPECT_EQ(std::size_t{2}, snap.client_datagrams);
}

TCPIP2_TEST(UdpFlowRejectsWithoutSession) {
    UdpFlowConfig config;
    PostRecorder post;
    // No factory: the flow is tracked but the datagram is rejected.
    UdpFlowTable table(config, nullptr, DefaultClock(), post);
    const FlowKey flow = MakeUdpFlow();
    const auto payload = Payload(4);
    const UdpFlowTable::Dispatch d = table.OnClientDatagram(flow, payload.data(), payload.size(), 1000);
    TCPIP2_EXPECT_EQ(UdpFlowTable::Dispatch::Rejected, d);

    // Factory refusal also rejects.
    test::FakeSessionFactory factory;
    factory.RejectNext();
    UdpFlowTable table2(config, &factory, DefaultClock(), post);
    const UdpFlowTable::Dispatch d2 = table2.OnClientDatagram(flow, payload.data(), payload.size(), 2000);
    TCPIP2_EXPECT_EQ(UdpFlowTable::Dispatch::Rejected, d2);
}

TCPIP2_TEST(UdpFlowRemoteDatagramEmitsViaEmitter) {
    UdpFlowConfig config;
    test::FakeSessionFactory factory;
    PostRecorder post;
    UdpFlowTable table(config, &factory, DefaultClock(), post);

    const FlowKey flow = MakeUdpFlow();
    const auto payload = Payload(6);
    table.OnClientDatagram(flow, payload.data(), payload.size(), 1000);

    // Remote datagram arrives via the session's data callback.
    PktBufferPool pool(8, 2048);
    const auto remote = Payload(5, 0x11);
    test::FakeDatagramSession &session = *factory.Session(0);
    const ReceiveStatus st = session.PushRemote(remote, pool);
    TCPIP2_EXPECT_EQ(ReceiveStatus::Accepted, st);
    TCPIP2_EXPECT_EQ(ShardMessageType::kUdpSessionData, post.state->last_type);

    // Simulate the shard processing the message: emitter receives the flow.
    bool emitted = false;
    FlowKey emitted_flow;
    table.SetEgressEmitter([&](const FlowKey &f, BufferLease &lease) {
        emitted = true;
        emitted_flow = f;
        TCPIP2_EXPECT_EQ(remote.size(), lease.Size());
        lease.Reset();
        return true;
    });
    BufferLease lease = pool.Allocate();
    std::memcpy(lease.Data(), remote.data(), remote.size());
    lease.Resize(remote.size());
    const ReceiveStatus emitted_st = table.OnRemoteData(post.state->last_flow_id, lease);
    TCPIP2_EXPECT_EQ(ReceiveStatus::Accepted, emitted_st);
    TCPIP2_EXPECT_TRUE(emitted);
    // The remote datagram is serialized back to the client: reversed flow.
    FlowKey reversed = flow;
    reversed.source = flow.destination;
    reversed.destination = flow.source;
    reversed.source_port = flow.destination_port;
    reversed.destination_port = flow.source_port;
    TCPIP2_EXPECT_TRUE(reversed == emitted_flow);

    UdpFlowSnapshot snap;
    TCPIP2_EXPECT_TRUE(table.Find(flow, snap));
    TCPIP2_EXPECT_EQ(std::size_t{1}, snap.remote_datagrams);
}

TCPIP2_TEST(UdpFlowIdleEviction) {
    UdpFlowConfig config;
    config.idle_timeout_ms = 1000;
    test::FakeSessionFactory factory;
    PostRecorder post;
    UdpFlowTable table(config, &factory, DefaultClock(), post);

    const auto payload = Payload(2);
    table.OnClientDatagram(MakeUdpFlow(1001), payload.data(), payload.size(), 0);
    table.OnClientDatagram(MakeUdpFlow(1002), payload.data(), payload.size(), 10);
    TCPIP2_EXPECT_EQ(std::size_t{2}, table.Size());

    // Both still fresh at t=500.
    table.PurgeExpired(500);
    TCPIP2_EXPECT_EQ(std::size_t{2}, table.Size());

    // Flow 1001 (active at 0) is idle past 1000ms; flow 1002 (active at 10)
    // is still fresh at t=1005.
    table.PurgeExpired(1005);
    TCPIP2_EXPECT_EQ(std::size_t{1}, table.Size());
    UdpFlowSnapshot snap;
    TCPIP2_EXPECT_FALSE(table.Find(MakeUdpFlow(1001), snap));
    TCPIP2_EXPECT_TRUE(table.Find(MakeUdpFlow(1002), snap));
}

TCPIP2_TEST(UdpFlowCapacityEvictsIdleEntry) {
    UdpFlowConfig config;
    config.max_flows = 2;
    config.idle_timeout_ms = 100;
    test::FakeSessionFactory factory;
    PostRecorder post;
    UdpFlowTable table(config, &factory, DefaultClock(), post);

    const auto payload = Payload(2);
    table.OnClientDatagram(MakeUdpFlow(1001), payload.data(), payload.size(), 0);
    table.OnClientDatagram(MakeUdpFlow(1002), payload.data(), payload.size(), 10);
    TCPIP2_EXPECT_EQ(std::size_t{2}, table.Size());

    // At t=1000 flow 1001 is idle; a third flow evicts it.
    table.OnClientDatagram(MakeUdpFlow(1003), payload.data(), payload.size(), 1000);
    TCPIP2_EXPECT_EQ(std::size_t{2}, table.Size());
    UdpFlowSnapshot snap;
    TCPIP2_EXPECT_FALSE(table.Find(MakeUdpFlow(1001), snap));
    TCPIP2_EXPECT_TRUE(table.Find(MakeUdpFlow(1003), snap));
}

TCPIP2_TEST(UdpFlowClosedCallbackEvicts) {
    UdpFlowConfig config;
    test::FakeSessionFactory factory;
    PostRecorder post;
    UdpFlowTable table(config, &factory, DefaultClock(), post);

    const FlowKey flow = MakeUdpFlow();
    const auto payload = Payload(2);
    table.OnClientDatagram(flow, payload.data(), payload.size(), 1000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, table.Size());

    // The session signals closure; the shard processes the closed message.
    factory.Session(0)->PushClosed(SessionError::RemoteClosed);
    TCPIP2_EXPECT_EQ(ShardMessageType::kUdpSessionClosed, post.state->last_type);
    table.OnFlowClosed(post.state->last_flow_id);
    TCPIP2_EXPECT_EQ(std::size_t{0}, table.Size());
    UdpFlowSnapshot snap;
    TCPIP2_EXPECT_FALSE(table.Find(flow, snap));
}

TCPIP2_TEST(UdpFlowIgnoresNonUdpOrMismatchedFamily) {
    UdpFlowConfig config;
    test::FakeSessionFactory factory;
    PostRecorder post;
    UdpFlowTable table(config, &factory, DefaultClock(), post);

    // Wrong protocol.
    FlowKey tcp = MakeUdpFlow();
    tcp.protocol = 6;
    const auto payload = Payload(2);
    TCPIP2_EXPECT_EQ(UdpFlowTable::Dispatch::Ignored, table.OnClientDatagram(tcp, payload.data(), payload.size(), 0));

    // IPv4 src with IPv6 dst.
    FlowKey mixed = MakeUdpFlow();
    std::uint8_t v6[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    mixed.destination = IpAddress::Ipv6(v6);
    TCPIP2_EXPECT_EQ(UdpFlowTable::Dispatch::Ignored, table.OnClientDatagram(mixed, payload.data(), payload.size(), 0));
    TCPIP2_EXPECT_EQ(std::size_t{0}, table.Size());
}

TCPIP2_TEST_MAIN()
