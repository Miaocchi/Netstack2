#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

#include "Test.h"
#include <tcp/delivery.h>
#include <tcp/receive.h>

using namespace tcpip2;

namespace {

class ScriptedSession final : public ITransportSession {
public:
    explicit ScriptedSession(std::vector<SendResult> script)
        : script_(std::move(script)) {}

    SendResult TrySend(BufferView data) override {
        calls_.push_back(std::vector<std::uint8_t>(data.Data(), data.Data() + data.Size()));
        if (next_ >= script_.size()) return {data.Size(), SendStatus::Accepted};
        return script_[next_++];
    }

    void ShutdownWrite() override {}
    void Abort(SessionError) override {}
    void SetWritableCallback(WritableCallback cb) override { writable_ = std::move(cb); }
    void SetDataCallback(DataCallback) override {}
    void SetClosedCallback(ClosedCallback) override {}

    const std::vector<std::vector<std::uint8_t>>& Calls() const noexcept { return calls_; }

private:
    std::vector<SendResult> script_;
    std::vector<std::vector<std::uint8_t>> calls_;
    std::size_t next_ = 0;
    WritableCallback writable_;
};

class ThrowingSession final : public ITransportSession {
public:
    SendResult TrySend(BufferView) override { throw std::runtime_error("send failure"); }
    void ShutdownWrite() override {}
    void Abort(SessionError) override {}
    void SetWritableCallback(WritableCallback) override {}
    void SetDataCallback(DataCallback) override {}
    void SetClosedCallback(ClosedCallback) override {}
};

template <std::size_t N>
void ExpectView(const TcpReadyView& view,
                const std::array<std::uint8_t, N>& expected) {
    TCPIP2_EXPECT_EQ(N, view.length);
    TCPIP2_EXPECT_TRUE(view.data != nullptr);
    if (view.data == nullptr) return;
    const std::size_t compared = view.length < N ? view.length : N;
    for (std::size_t i = 0; i < compared; ++i) {
        TCPIP2_EXPECT_EQ(expected[i], view.data[i]);
    }
}

} // namespace

TCPIP2_TEST(InOrderSegmentsDelayEveryOtherAck) {
    TcpReceiveBuffer receive(32, 1000);
    const std::array<std::uint8_t, 2> first{{1, 2}};
    const std::array<std::uint8_t, 2> second{{3, 4}};
    const std::array<std::uint8_t, 1> third{{5}};

    const auto a = receive.OnSegment(1000, first.data(), first.size(), false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Accepted, a.disposition);
    TCPIP2_EXPECT_EQ(AckDecision::Delayed, a.ack_decision);
    TCPIP2_EXPECT_EQ(std::size_t{2}, a.accepted_bytes);

    const auto b = receive.OnSegment(1002, second.data(), second.size(), false);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, b.ack_decision);
    const auto c = receive.OnSegment(1004, third.data(), third.size(), false);
    TCPIP2_EXPECT_EQ(AckDecision::Delayed, c.ack_decision);
    TCPIP2_EXPECT_EQ(std::uint32_t{1005}, receive.RcvNxt());
    TCPIP2_EXPECT_EQ(std::size_t{5}, receive.BytesHeld());
    TCPIP2_EXPECT_EQ(std::size_t{5}, receive.ReadyBytes());
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.OutOfOrderBytes());
    TCPIP2_EXPECT_EQ(std::size_t{27}, receive.AdvertisedWindow());
}

TCPIP2_TEST(DelayedAckSentResetsPairing) {
    TcpReceiveBuffer receive(16, 100);
    const std::array<std::uint8_t, 1> byte{{1}};
    TCPIP2_EXPECT_EQ(
        AckDecision::Delayed,
        receive.OnSegment(100, byte.data(), byte.size(), false).ack_decision);
    receive.AckSent();
    TCPIP2_EXPECT_EQ(
        AckDecision::Delayed,
        receive.OnSegment(101, byte.data(), byte.size(), false).ack_decision);
}

TCPIP2_TEST(OutOfOrderThenGapFillIsImmediatelyAcknowledged) {
    TcpReceiveBuffer receive(16, 100);
    const std::array<std::uint8_t, 2> tail{{5, 6}};
    const auto out_of_order =
        receive.OnSegment(104, tail.data(), tail.size(), false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Accepted, out_of_order.disposition);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, out_of_order.ack_decision);
    TCPIP2_EXPECT_EQ(std::uint32_t{100}, receive.RcvNxt());
    TCPIP2_EXPECT_EQ(std::size_t{2}, receive.OutOfOrderBytes());
    TCPIP2_EXPECT_EQ(std::size_t{14}, receive.AdvertisedWindow());

    const auto sacks = receive.SackBlocks();
    TCPIP2_EXPECT_EQ(std::size_t{1}, sacks.count);
    TCPIP2_EXPECT_EQ(std::uint32_t{104}, sacks.blocks[0].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{106}, sacks.blocks[0].right_edge);

    const std::array<std::uint8_t, 4> head{{1, 2, 3, 4}};
    const auto fill = receive.OnSegment(100, head.data(), head.size(), false);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, fill.ack_decision);
    TCPIP2_EXPECT_EQ(std::uint32_t{106}, receive.RcvNxt());
    TCPIP2_EXPECT_EQ(std::size_t{6}, receive.ReadyBytes());
    ExpectView(receive.ReadyView(),
               std::array<std::uint8_t, 6>{{1, 2, 3, 4, 5, 6}});
}

TCPIP2_TEST(SequenceWrapPreservesOrderingAndSackEdges) {
    const std::uint32_t initial = std::numeric_limits<std::uint32_t>::max() - 2;
    TcpReceiveBuffer receive(16, initial);
    const std::array<std::uint8_t, 2> tail{{4, 5}};
    receive.OnSegment(0, tail.data(), tail.size(), false);

    const auto sacks = receive.SackBlocks();
    TCPIP2_EXPECT_EQ(std::size_t{1}, sacks.count);
    TCPIP2_EXPECT_EQ(std::uint32_t{0}, sacks.blocks[0].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{2}, sacks.blocks[0].right_edge);

    const std::array<std::uint8_t, 3> head{{1, 2, 3}};
    const auto fill = receive.OnSegment(initial, head.data(), head.size(), false);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, fill.ack_decision);
    TCPIP2_EXPECT_EQ(std::uint32_t{2}, receive.RcvNxt());
    ExpectView(receive.ReadyView(),
               std::array<std::uint8_t, 5>{{1, 2, 3, 4, 5}});
}

TCPIP2_TEST(PartialOverlapKeepsFirstArrivalBytes) {
    TcpReceiveBuffer receive(16, 100);
    const std::array<std::uint8_t, 4> first{{10, 11, 12, 13}};
    receive.OnSegment(104, first.data(), first.size(), false);

    const std::array<std::uint8_t, 6> overlap{{3, 4, 90, 91, 92, 93}};
    const auto result =
        receive.OnSegment(102, overlap.data(), overlap.size(), false);
    TCPIP2_EXPECT_EQ(std::size_t{2}, result.accepted_bytes);
    TCPIP2_EXPECT_EQ(std::size_t{4}, result.duplicate_bytes);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, result.ack_decision);

    const std::array<std::uint8_t, 2> head{{1, 2}};
    receive.OnSegment(100, head.data(), head.size(), false);
    ExpectView(receive.ReadyView(),
               std::array<std::uint8_t, 8>{{1, 2, 3, 4, 10, 11, 12, 13}});

    const auto duplicate =
        receive.OnSegment(104, first.data(), first.size(), false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Duplicate, duplicate.disposition);
    TCPIP2_EXPECT_EQ(std::size_t{4}, duplicate.left_trimmed);
    TCPIP2_EXPECT_EQ(std::size_t{0}, duplicate.accepted_bytes);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, duplicate.ack_decision);
}

TCPIP2_TEST(AlreadyReceivedPrefixIsTrimmed) {
    TcpReceiveBuffer receive(12, 100);
    const std::array<std::uint8_t, 3> first{{1, 2, 3}};
    receive.OnSegment(100, first.data(), first.size(), false);

    const std::array<std::uint8_t, 7> crossing{{9, 9, 9, 9, 9, 4, 5}};
    const auto result =
        receive.OnSegment(98, crossing.data(), crossing.size(), false);
    TCPIP2_EXPECT_EQ(std::size_t{5}, result.left_trimmed);
    TCPIP2_EXPECT_EQ(std::size_t{2}, result.accepted_bytes);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, result.ack_decision);
    ExpectView(receive.ReadyView(),
               std::array<std::uint8_t, 5>{{1, 2, 3, 4, 5}});
}

TCPIP2_TEST(RightEdgeTrimAndOutOfWindowAreImmediate) {
    TcpReceiveBuffer receive(4, 100);
    const std::array<std::uint8_t, 6> bytes{{1, 2, 3, 4, 5, 6}};
    const auto trimmed =
        receive.OnSegment(100, bytes.data(), bytes.size(), false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Accepted, trimmed.disposition);
    TCPIP2_EXPECT_EQ(std::size_t{4}, trimmed.accepted_bytes);
    TCPIP2_EXPECT_EQ(std::size_t{2}, trimmed.right_trimmed);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, trimmed.ack_decision);
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.AdvertisedWindow());

    const auto rejected = receive.OnSegment(104, bytes.data(), 1, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::OutOfWindow, rejected.disposition);
    TCPIP2_EXPECT_EQ(std::size_t{1}, rejected.right_trimmed);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, rejected.ack_decision);
    TCPIP2_EXPECT_EQ(std::size_t{4}, receive.BytesHeld());
}

TCPIP2_TEST(SequenceAcceptabilityCoversZeroAndNonzeroWindows) {
    TcpReceiveBuffer receive(4, 100);
    TCPIP2_EXPECT_TRUE(receive.IsSequenceAcceptable(100, 0));
    TCPIP2_EXPECT_TRUE(receive.IsSequenceAcceptable(103, 0));
    TCPIP2_EXPECT_FALSE(receive.IsSequenceAcceptable(104, 0));
    TCPIP2_EXPECT_TRUE(receive.IsSequenceAcceptable(99, 2));
    TCPIP2_EXPECT_FALSE(receive.IsSequenceAcceptable(96, 2));

    const std::array<std::uint8_t, 4> bytes{{1, 2, 3, 4}};
    receive.OnSegment(100, bytes.data(), bytes.size(), false);
    TCPIP2_EXPECT_TRUE(receive.IsSequenceAcceptable(104, 0));
    TCPIP2_EXPECT_FALSE(receive.IsSequenceAcceptable(103, 0));
    TCPIP2_EXPECT_FALSE(receive.IsSequenceAcceptable(104, 1));
}

TCPIP2_TEST(SegmentEngulfingWindowWithoutAcceptableEndpointIsRejected) {
    TcpReceiveBuffer receive(4, 100);
    const std::array<std::uint8_t, 6> bytes{{1, 2, 3, 4, 5, 6}};
    const auto result = receive.OnSegment(99, bytes.data(), bytes.size(), false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::OutOfWindow, result.disposition);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, result.ack_decision);
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.BytesHeld());
    TCPIP2_EXPECT_EQ(std::uint32_t{100}, receive.RcvNxt());
}

TCPIP2_TEST(ReadyViewReturnsOnePhysicalRingChunk) {
    TcpReceiveBuffer receive(8, 100);
    const std::array<std::uint8_t, 6> first{{0, 1, 2, 3, 4, 5}};
    receive.OnSegment(100, first.data(), first.size(), false);
    TCPIP2_EXPECT_EQ(std::size_t{5}, receive.ConsumeReady(5));
    receive.RecordAdvertisedWindow(receive.AdvertisedWindow());

    const std::array<std::uint8_t, 5> second{{6, 7, 8, 9, 10}};
    receive.OnSegment(106, second.data(), second.size(), false);
    ExpectView(receive.ReadyView(),
               std::array<std::uint8_t, 3>{{5, 6, 7}});
    TCPIP2_EXPECT_EQ(std::size_t{3}, receive.ConsumeReady(3));
    ExpectView(receive.ReadyView(),
               std::array<std::uint8_t, 3>{{8, 9, 10}});
    TCPIP2_EXPECT_EQ(std::size_t{3}, receive.ConsumeReady(99));
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.ReadyView().length);
    TCPIP2_EXPECT_TRUE(receive.ReadyView().data == nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.BytesHeld());
    TCPIP2_EXPECT_EQ(std::uint32_t{111}, receive.RcvNxt());
}

TCPIP2_TEST(SackBlocksPutMostRecentTriggerFirstAndRemainBounded) {
    TcpReceiveBuffer receive(32, 100);
    const std::array<std::uint8_t, 3> three{{1, 2, 3}};
    const std::array<std::uint8_t, 2> two{{1, 2}};
    const std::array<std::uint8_t, 1> one{{1}};
    receive.OnSegment(110, two.data(), two.size(), false);
    receive.OnSegment(104, three.data(), three.size(), false);
    receive.OnSegment(116, one.data(), one.size(), false);
    receive.OnSegment(120, two.data(), two.size(), false);
    receive.OnSegment(124, one.data(), one.size(), false);

    const auto sacks = receive.SackBlocks();
    TCPIP2_EXPECT_EQ(std::size_t{4}, sacks.count);
    TCPIP2_EXPECT_EQ(std::uint32_t{124}, sacks.blocks[0].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{125}, sacks.blocks[0].right_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{104}, sacks.blocks[1].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{107}, sacks.blocks[1].right_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{110}, sacks.blocks[2].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{112}, sacks.blocks[2].right_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{116}, sacks.blocks[3].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{117}, sacks.blocks[3].right_edge);

    const auto limited = receive.SackBlocks(2);
    TCPIP2_EXPECT_EQ(std::size_t{2}, limited.count);
    const std::array<std::uint8_t, 4> gap{{1, 2, 3, 4}};
    receive.OnSegment(100, gap.data(), gap.size(), false);
    TCPIP2_EXPECT_EQ(std::uint32_t{107}, receive.RcvNxt());
    TCPIP2_EXPECT_EQ(std::uint32_t{124},
                     receive.SackBlocks().blocks[0].left_edge);
}

TCPIP2_TEST(DuplicateOutOfOrderSegmentBecomesFirstSackBlock) {
    TcpReceiveBuffer receive(32, 100);
    const std::array<std::uint8_t, 2> bytes{{1, 2}};
    receive.OnSegment(104, bytes.data(), bytes.size(), false);
    receive.OnSegment(110, bytes.data(), bytes.size(), false);
    TCPIP2_EXPECT_EQ(std::uint32_t{110},
                     receive.SackBlocks().blocks[0].left_edge);
    receive.OnSegment(104, bytes.data(), bytes.size(), false);
    const auto sacks = receive.SackBlocks();
    TCPIP2_EXPECT_EQ(std::uint32_t{104}, sacks.blocks[0].left_edge);
    TCPIP2_EXPECT_EQ(std::uint32_t{106}, sacks.blocks[0].right_edge);
}

TCPIP2_TEST(PshForcesImmediateAckAndResetsPairing) {
    TcpReceiveBuffer receive(8, 10);
    const std::array<std::uint8_t, 1> byte{{1}};
    const auto psh = receive.OnSegment(10, byte.data(), byte.size(), true);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, psh.ack_decision);
    const auto next = receive.OnSegment(11, byte.data(), byte.size(), false);
    TCPIP2_EXPECT_EQ(AckDecision::Delayed, next.ack_decision);
}

TCPIP2_TEST(BlockedWindowIsZeroButReadyDataCanDrain) {
    TcpReceiveBuffer receive(8, 100);
    const std::array<std::uint8_t, 2> bytes{{1, 2}};
    receive.OnSegment(100, bytes.data(), bytes.size(), false);
    receive.SetBlocked(true);
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.AdvertisedWindow());
    ExpectView(receive.ReadyView(), bytes);

    const auto blocked = receive.OnSegment(102, bytes.data(), 1, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Accepted, blocked.disposition);
    TCPIP2_EXPECT_EQ(std::size_t{1}, receive.ConsumeReady(1));
    ExpectView(receive.ReadyView(), std::array<std::uint8_t, 2>{{2, 1}});
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.AdvertisedWindow());

    receive.SetBlocked(false);
    TCPIP2_EXPECT_EQ(std::size_t{6}, receive.AdvertisedWindow());
    receive.RecordAdvertisedWindow(receive.AdvertisedWindow());
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Accepted,
                     receive.OnSegment(103, bytes.data(), 1, false).disposition);
}

TCPIP2_TEST(BlockedFlowHonorsOnlyPreviouslyAdvertisedRightEdge) {
    TcpReceiveBuffer receive(4, 100);
    const std::array<std::uint8_t, 4> bytes{{1, 2, 3, 4}};
    receive.SetBlocked(true);
    const auto in_flight = receive.OnSegment(
        100, bytes.data(), bytes.size(), false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Accepted, in_flight.disposition);
    TCPIP2_EXPECT_EQ(std::uint32_t{104}, receive.RcvNxt());
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.AcceptableWindow());

    const auto beyond = receive.OnSegment(104, bytes.data(), 1, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::OutOfWindow, beyond.disposition);
    TCPIP2_EXPECT_EQ(AckDecision::Immediate, beyond.ack_decision);
}

TCPIP2_TEST(NullZeroAndOversizedInputsAreInvalid) {
    TcpReceiveBuffer receive(8, 50);
    const std::array<std::uint8_t, 1> byte{{1}};
    const auto null_data = receive.OnSegment(50, nullptr, 1, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Invalid, null_data.disposition);
    TCPIP2_EXPECT_EQ(AckDecision::None, null_data.ack_decision);
    const auto zero = receive.OnSegment(50, byte.data(), 0, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Invalid, zero.disposition);
    const auto both = receive.OnSegment(50, nullptr, 0, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Invalid, both.disposition);
    const auto oversized = receive.OnSegment(
        50, byte.data(), std::size_t{0x80000000u}, false);
    TCPIP2_EXPECT_EQ(ReceiveDisposition::Invalid, oversized.disposition);
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.BytesHeld());
}

TCPIP2_TEST(CapacityValidationAndMemoryAccountingAreBounded) {
    bool rejected_zero = false;
    try {
        TcpReceiveBuffer invalid(0);
    } catch (const std::invalid_argument&) {
        rejected_zero = true;
    }
    TCPIP2_EXPECT_TRUE(rejected_zero);

    bool rejected_large = false;
    try {
        TcpReceiveBuffer invalid(std::size_t{0x80000000u});
    } catch (const std::invalid_argument&) {
        rejected_large = true;
    }
    TCPIP2_EXPECT_TRUE(rejected_large);

    TcpReceiveBuffer receive(65, 1);
    TCPIP2_EXPECT_EQ(std::size_t{65}, receive.Capacity());
    TCPIP2_EXPECT_EQ(std::size_t{81}, receive.MemoryBytes());
    TCPIP2_EXPECT_EQ(std::size_t{65}, receive.AdvertisedWindow());
}

TCPIP2_TEST(SessionDeliveryHandlesPartialAcceptedAcrossRingWrap) {
    TcpReceiveBuffer receive(8, 100);
    const std::array<std::uint8_t, 6> first{{0, 1, 2, 3, 4, 5}};
    receive.OnSegment(100, first.data(), first.size(), false);
    receive.ConsumeReady(5);
    receive.RecordAdvertisedWindow(receive.AdvertisedWindow());
    const std::array<std::uint8_t, 5> second{{6, 7, 8, 9, 10}};
    receive.OnSegment(106, second.data(), second.size(), false);

    ScriptedSession session({
        {2, SendStatus::Accepted},
        {1, SendStatus::Accepted},
        {3, SendStatus::Accepted},
    });
    DeliverFn deliver = [&session](BufferView data) -> SendResult {
        return session.TrySend(data);
    };
    const auto delivered = DrainTcpReceiveBuffer(receive, deliver, 8);
    TCPIP2_EXPECT_EQ(TcpDeliveryStatus::Drained, delivered.status);
    TCPIP2_EXPECT_EQ(std::size_t{6}, delivered.accepted_bytes);
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.BytesHeld());
    TCPIP2_EXPECT_EQ(std::size_t{3}, session.Calls().size());
}

TCPIP2_TEST(SessionDeliveryConsumesPartialWouldBlockBeforeBlocking) {
    TcpReceiveBuffer receive(8, 100);
    const std::array<std::uint8_t, 4> bytes{{1, 2, 3, 4}};
    receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ScriptedSession session({{2, SendStatus::WouldBlock}});
    DeliverFn deliver = [&session](BufferView data) -> SendResult {
        return session.TrySend(data);
    };

    const auto delivered = DrainTcpReceiveBuffer(receive, deliver);
    TCPIP2_EXPECT_EQ(TcpDeliveryStatus::WouldBlock, delivered.status);
    TCPIP2_EXPECT_EQ(std::size_t{2}, delivered.accepted_bytes);
    TCPIP2_EXPECT_EQ(std::size_t{2}, receive.ReadyBytes());
    TCPIP2_EXPECT_EQ(std::size_t{0}, receive.AdvertisedWindow());
}

TCPIP2_TEST(SessionDeliveryRejectsInvalidAndZeroProgressResults) {
    const std::array<std::uint8_t, 2> bytes{{1, 2}};
    TcpReceiveBuffer invalid_receive(8, 100);
    invalid_receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ScriptedSession invalid({{3, SendStatus::Accepted}});
    DeliverFn invalid_deliver = [&invalid](BufferView data) -> SendResult {
        return invalid.TrySend(data);
    };
    TCPIP2_EXPECT_EQ(
        TcpDeliveryStatus::InvalidResult,
        DrainTcpReceiveBuffer(invalid_receive, invalid_deliver).status);
    TCPIP2_EXPECT_EQ(std::size_t{2}, invalid_receive.ReadyBytes());

    TcpReceiveBuffer stalled_receive(8, 100);
    stalled_receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ScriptedSession stalled({{0, SendStatus::Accepted}});
    DeliverFn stalled_deliver = [&stalled](BufferView data) -> SendResult {
        return stalled.TrySend(data);
    };
    TCPIP2_EXPECT_EQ(
        TcpDeliveryStatus::NoProgress,
        DrainTcpReceiveBuffer(stalled_receive, stalled_deliver).status);
    TCPIP2_EXPECT_EQ(std::size_t{0}, stalled_receive.AdvertisedWindow());
}

TCPIP2_TEST(SessionDeliveryReportsTerminalStatusAfterAcceptedPrefix) {
    const std::array<std::uint8_t, 2> bytes{{1, 2}};
    TcpReceiveBuffer closed_receive(8, 100);
    closed_receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ScriptedSession closed({{1, SendStatus::Closed}});
    DeliverFn closed_deliver = [&closed](BufferView data) -> SendResult {
        return closed.TrySend(data);
    };
    const auto closed_result = DrainTcpReceiveBuffer(closed_receive, closed_deliver);
    TCPIP2_EXPECT_EQ(TcpDeliveryStatus::Closed, closed_result.status);
    TCPIP2_EXPECT_EQ(std::size_t{1}, closed_result.accepted_bytes);

    TcpReceiveBuffer error_receive(8, 100);
    error_receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ScriptedSession error({{1, SendStatus::Error}});
    DeliverFn error_deliver = [&error](BufferView data) -> SendResult {
        return error.TrySend(data);
    };
    TCPIP2_EXPECT_EQ(
        TcpDeliveryStatus::Error,
        DrainTcpReceiveBuffer(error_receive, error_deliver).status);
}

TCPIP2_TEST(SessionDeliveryCallBudgetPreventsUnboundedLoop) {
    TcpReceiveBuffer receive(8, 100);
    const std::array<std::uint8_t, 4> bytes{{1, 2, 3, 4}};
    receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ScriptedSession session({
        {1, SendStatus::Accepted},
        {1, SendStatus::Accepted},
        {1, SendStatus::Accepted},
        {1, SendStatus::Accepted},
    });
    DeliverFn deliver = [&session](BufferView data) -> SendResult {
        return session.TrySend(data);
    };
    const auto first = DrainTcpReceiveBuffer(receive, deliver, 2);
    TCPIP2_EXPECT_EQ(TcpDeliveryStatus::BudgetExhausted, first.status);
    TCPIP2_EXPECT_EQ(std::size_t{2}, receive.ReadyBytes());
    const auto second = DrainTcpReceiveBuffer(receive, deliver, 2);
    TCPIP2_EXPECT_EQ(TcpDeliveryStatus::Drained, second.status);
}

TCPIP2_TEST(SessionExceptionConvertsToDeliveryError) {
    TcpReceiveBuffer receive(8, 100);
    const std::array<std::uint8_t, 2> bytes{{1, 2}};
    receive.OnSegment(100, bytes.data(), bytes.size(), false);
    ThrowingSession session;
    DeliverFn deliver = [&session](BufferView data) -> SendResult {
        return session.TrySend(data);
    };
    const auto result = DrainTcpReceiveBuffer(receive, deliver);
    TCPIP2_EXPECT_EQ(TcpDeliveryStatus::Error, result.status);
    TCPIP2_EXPECT_EQ(std::size_t{2}, receive.ReadyBytes());
    TCPIP2_EXPECT_TRUE(receive.Blocked());
}

TCPIP2_TEST_MAIN()
