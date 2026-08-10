#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "Test.h"
#include <tcp/send.h>
#include <tcpip2/buffer.h>

using namespace tcpip2;

namespace {

/// Helper: create a TcpSendBuffer with small limits suitable for unit tests.
std::unique_ptr<TcpSendBuffer> MakeSendBuffer(
    std::uint32_t initial_seq = 1000,
    std::uint16_t mss = 1460,
    std::size_t queue_limit = 64 * 1024,
    std::size_t retransmit_limit = 64 * 1024) {
    return std::make_unique<TcpSendBuffer>(
        initial_seq, mss, 0, queue_limit, retransmit_limit,
        1000,   // initial_rto_ms
        200,    // min_rto_ms
        60000,  // max_rto_ms
        500,    // persist_base_ms
        60000,  // persist_max_ms
        3,      // max_retransmissions (small for test)
        3);     // max_persist_probes
}

/// Helper: simulate sending a segment by retaining a pool buffer and
/// copying the payload into it, then calling OnSent.
///
/// The pool is declared as the first member so that callers can write
/// `SendHelper sh; auto send = MakeSendBuffer(...);` — this guarantees
/// `send` is destroyed before `sh.pool`, avoiding use-after-free when
/// ~TcpSendBuffer releases retained BufferRefs back to the pool.
struct SendHelper {
    PktBufferPool pool;
    std::uint64_t now_ms = 100;

    explicit SendHelper(std::size_t slot_count = 8, std::size_t capacity = 2048)
        : pool(slot_count, capacity) {}

    /// Send a segment: allocate buffer, copy payload at given offset,
    /// retain, and call OnSent.  The time passed to OnSent is @p now_ms
    /// (defaults to sh.now_ms) so tests can advance the clock between
    /// NextSegment and OnSent without mutating sh.now_ms.
    void SendSegment(TcpSendBuffer& send, const TcpSendNextResult& seg,
                     std::size_t payload_offset, std::uint64_t now_ms_override = 0) {
        TCPIP2_EXPECT_TRUE(seg.has_segment);
        BufferLease lease = pool.Allocate();
        TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
        if (seg.payload_length > 0) {
            std::memcpy(lease.Data() + payload_offset, seg.payload,
                        seg.payload_length);
        }
        lease.Resize(payload_offset + seg.payload_length);
        BufferRef ref = pool.Retain(std::move(lease));
        send.OnSent(std::move(ref), payload_offset,
                    now_ms_override != 0 ? now_ms_override : now_ms);
    }

    /// Send a segment with payload at offset 20 (simulating IP+TCP headers).
    void SendSegment(TcpSendBuffer& send, const TcpSendNextResult& seg) {
        SendSegment(send, seg, 20, 0);
    }
};

/// Helper scope: declare sh before send so destruction order is correct.
/// Usage: `SendScope s; auto& send = s.send; auto& sh = s.sh;`
/// or simply use s.send and s.sh directly.
struct SendScope {
    SendHelper sh;
    std::unique_ptr<TcpSendBuffer> send;

    explicit SendScope(std::uint32_t initial_seq = 1000,
                       std::uint16_t mss = 1460,
                       std::size_t queue_limit = 64 * 1024,
                       std::size_t retransmit_limit = 64 * 1024)
        : sh(),
          send(MakeSendBuffer(initial_seq, mss, queue_limit, retransmit_limit)) {}
};

} // namespace

// ---------------------------------------------------------------------------
// Basic enqueue / send / ack cycle
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendEnqueueAndBasicCycle) {
    SendHelper sh;
    auto send = MakeSendBuffer(1000);

    std::uint8_t data[] = {1, 2, 3, 4, 5};
    TCPIP2_EXPECT_EQ(send->Enqueue(data, 5), std::size_t{5});

    auto seg = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg.has_segment);
    TCPIP2_EXPECT_FALSE(seg.is_retransmission);
    TCPIP2_EXPECT_FALSE(seg.is_zero_window_probe);
    TCPIP2_EXPECT_FALSE(seg.is_fin);
    TCPIP2_EXPECT_EQ(seg.payload_length, std::size_t{5});
    TCPIP2_EXPECT_EQ(seg.sequence, std::uint32_t{1000});
    TCPIP2_EXPECT_EQ(seg.payload[0], std::uint8_t{1});
    TCPIP2_EXPECT_EQ(seg.payload[4], std::uint8_t{5});

    sh.SendSegment(*send, seg);

    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{1005});
    TCPIP2_EXPECT_EQ(send->SndUna(), std::uint32_t{1000});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{5});
    TCPIP2_EXPECT_EQ(send->UnsntBytes(), std::size_t{0});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    // ACK the data.
    auto ack = send->OnAck(1005, 65535, sh.now_ms + 50);
    TCPIP2_EXPECT_EQ(ack.newly_acked, std::size_t{5});
    TCPIP2_EXPECT_TRUE(ack.fully_acked);
    TCPIP2_EXPECT_FALSE(ack.duplicate);

    TCPIP2_EXPECT_EQ(send->SndUna(), std::uint32_t{1005});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{0});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{0});
    TCPIP2_EXPECT_TRUE(send->AllAcked());

    send.reset();  // Destroy send before pool goes out of scope.
}

// ---------------------------------------------------------------------------
// Sequence number increment
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendSequenceIncrement) {
    SendHelper sh;
    auto send = MakeSendBuffer(2000);

    std::uint8_t data[10] = {};
    TCPIP2_EXPECT_EQ(send->Enqueue(data, 10), std::size_t{10});

    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{2010});
    TCPIP2_EXPECT_EQ(send->SndMax(), std::uint32_t{2010});

    send.reset();
}

// ---------------------------------------------------------------------------
// Multiple segments and partial ACK
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendMultipleSegmentsAndPartialAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(5000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {10, 20, 30, 40, 50, 60, 70, 80};
    TCPIP2_EXPECT_EQ(send->Enqueue(data, 8), std::size_t{8});

    // Send first segment (MSS=4).
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_EQ(seg1.payload_length, std::size_t{4});
    TCPIP2_EXPECT_EQ(seg1.sequence, std::uint32_t{5000});
    sh.SendSegment(*send, seg1);

    // Send second segment.
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_EQ(seg2.payload_length, std::size_t{4});
    TCPIP2_EXPECT_EQ(seg2.sequence, std::uint32_t{5004});
    sh.SendSegment(*send, seg2);

    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{5008});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{8});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{2});

    // Partial ACK: only first 4 bytes.
    auto ack = send->OnAck(5004, 65535, sh.now_ms + 30);
    TCPIP2_EXPECT_EQ(ack.newly_acked, std::size_t{4});
    TCPIP2_EXPECT_FALSE(ack.fully_acked);
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    // ACK the rest.
    auto ack2 = send->OnAck(5008, 65535, sh.now_ms + 60);
    TCPIP2_EXPECT_EQ(ack2.newly_acked, std::size_t{4});
    TCPIP2_EXPECT_TRUE(ack2.fully_acked);
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// RTO retransmission and backoff
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRtoRetransmission) {
    SendHelper sh;
    auto send = MakeSendBuffer(3000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);

    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    TCPIP2_EXPECT_TRUE(send->RetransmitDeadline() != 0);

    // Wait for RTO to expire.
    std::uint64_t deadline = send->RetransmitDeadline();
    auto rseg = send->NextSegment(65535, deadline);
    TCPIP2_EXPECT_TRUE(rseg.is_retransmission);
    TCPIP2_EXPECT_EQ(rseg.payload_length, std::size_t{5});
    TCPIP2_EXPECT_EQ(rseg.sequence, std::uint32_t{3000});
    // Retransmit doesn't need a new BufferRef — original is in retransmit queue.
    send->OnSent(BufferRef(), 0, deadline);

    TCPIP2_EXPECT_EQ(send->RetransmissionCount(), std::size_t{1});
    TCPIP2_EXPECT_FALSE(send->IsClosed());

    send.reset();
}

// ---------------------------------------------------------------------------
// Max retransmissions closes connection
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendMaxRetransmissionsClosesConnection) {
    SendHelper sh;
    auto send = MakeSendBuffer(3000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);

    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    // max_retransmissions = 3. Do 3 retransmits.
    for (int i = 0; i < 3; ++i) {
        std::uint64_t deadline = send->RetransmitDeadline();
        TCPIP2_EXPECT_TRUE(deadline != 0);
        auto rseg = send->NextSegment(65535, deadline);
        TCPIP2_EXPECT_TRUE(rseg.is_retransmission);
        send->OnSent(BufferRef(), 0, deadline);
    }

    TCPIP2_EXPECT_TRUE(send->IsClosed());

    send.reset();
}

// ---------------------------------------------------------------------------
// Duplicate ACK and fast retransmit
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendDuplicateAckAndFastRetransmit) {
    SendHelper sh;
    auto send = MakeSendBuffer(7000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);

    // Send 2 segments.
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // ACK first segment.
    send->OnAck(7004, 65535, sh.now_ms + 10);

    // 3 duplicate ACKs for 7004.
    for (int i = 0; i < 3; ++i) {
        auto ack = send->OnAck(7004, 65535, sh.now_ms + 20 + i);
        TCPIP2_EXPECT_TRUE(ack.duplicate);
    }

    // 3rd duplicate ACK should trigger fast retransmit.
    auto rseg = send->NextSegment(65535, sh.now_ms + 30);
    TCPIP2_EXPECT_TRUE(rseg.is_retransmission);
    TCPIP2_EXPECT_EQ(rseg.sequence, std::uint32_t{7004});
    send->OnSent(BufferRef(), 0, sh.now_ms + 30);

    // ACK everything.
    auto final_ack = send->OnAck(7008, 65535, sh.now_ms + 40);
    TCPIP2_EXPECT_TRUE(final_ack.fully_acked);

    send.reset();
}

// ---------------------------------------------------------------------------
// Zero-window persist probe (data)
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendZeroWindowPersistProbe) {
    SendHelper sh;
    auto send = MakeSendBuffer(8000);

    std::uint8_t data[3] = {};
    send->Enqueue(data, 3);

    // Peer window is 0 — can't send new data.
    auto seg1 = send->NextSegment(0, sh.now_ms);
    TCPIP2_EXPECT_FALSE(seg1.has_segment);

    // Arm persist timer.
    send->ArmPersistTimer(sh.now_ms);
    TCPIP2_EXPECT_TRUE(send->PersistActive());

    // Wait for persist to expire.
    std::uint64_t deadline = send->PersistDeadline();
    auto probe = send->NextSegment(0, deadline);
    TCPIP2_EXPECT_TRUE(probe.is_zero_window_probe);
    TCPIP2_EXPECT_EQ(probe.payload_length, std::size_t{1});
    sh.SendSegment(*send, probe, 20);

    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{8001});
    // A persist byte does not consume the advertised or congestion window,
    // but its payload remains retained until ACKed or promoted on reopen.
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{0});
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{1});
    TCPIP2_EXPECT_EQ(send->PersistProbeCount(), std::size_t{1});

    send.reset();
}

// ---------------------------------------------------------------------------
// Zero-window persist probe (FIN)
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendZeroWindowFinProbe) {
    SendHelper sh;
    auto send = MakeSendBuffer(9000);

    send->RequestFin();

    // Peer window is 0 — can't send FIN.
    auto seg1 = send->NextSegment(0, sh.now_ms);
    TCPIP2_EXPECT_FALSE(seg1.has_segment);

    send->ArmPersistTimer(sh.now_ms);

    std::uint64_t deadline = send->PersistDeadline();
    auto probe = send->NextSegment(0, deadline);
    TCPIP2_EXPECT_TRUE(probe.is_zero_window_probe);
    TCPIP2_EXPECT_TRUE(probe.is_fin);
    sh.SendSegment(*send, probe, 20);

    TCPIP2_EXPECT_TRUE(send->FinSent());
    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{9001});

    send.reset();
}

// ---------------------------------------------------------------------------
// FIN piggyback on data
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendFinPiggybackOnData) {
    SendHelper sh;
    auto send = MakeSendBuffer(6000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);
    send->RequestFin();

    auto seg = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg.has_segment);
    TCPIP2_EXPECT_TRUE(seg.is_fin);
    TCPIP2_EXPECT_EQ(seg.payload_length, std::size_t{5});
    sh.SendSegment(*send, seg);

    TCPIP2_EXPECT_TRUE(send->FinSent());
    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{6006});  // 5 data + 1 FIN

    send.reset();
}

// ---------------------------------------------------------------------------
// Queue full rejects enqueue
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendQueueFullRejectsEnqueue) {
    SendHelper sh;
    auto send = MakeSendBuffer(1000, 1460, 4, 64 * 1024);

    std::uint8_t data[10] = {};
    TCPIP2_EXPECT_EQ(send->Enqueue(data, 10), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->Enqueue(data, 1), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// Reject enqueue after FIN requested
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRejectEnqueueAfterFinRequested) {
    SendHelper sh;
    auto send = MakeSendBuffer(1000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);
    send->RequestFin();

    TCPIP2_EXPECT_EQ(send->Enqueue(data, 5), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// Congestion control: slow start
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendCongestionControlSlowStart) {
    SendHelper sh;
    auto send = MakeSendBuffer(10000, 100, 64 * 1024, 64 * 1024);

    // Initial cwnd = 2 * MSS = 200.
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), std::uint32_t{200});

    std::uint8_t data[500] = {};
    send->Enqueue(data, 500);

    // Send first segment (100 bytes, limited by MSS).
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_EQ(seg1.payload_length, std::size_t{100});
    sh.SendSegment(*send, seg1);

    // ACK it — slow start should increase cwnd by MSS.
    send->OnAck(10100, 65535, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), std::uint32_t{300});  // 200 + 100

    send.reset();
}

// ---------------------------------------------------------------------------
// RTT estimation updates RTO
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRttEstimationUpdatesRto) {
    SendHelper sh;
    auto send = MakeSendBuffer(11000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);

    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg, 20, sh.now_ms);

    // ACK after 50ms.
    send->OnAck(11005, 65535, sh.now_ms + 50);

    // First RTT measurement: SRTT = 50, RTTVAR = 25, RTO = 50 + 4*25 = 150.
    // Clamped to min_rto = 200.
    // Send another segment at now_ms + 60 and verify RTO is applied.
    send->Enqueue(data, 5);
    auto seg2 = send->NextSegment(65535, sh.now_ms + 60);
    sh.SendSegment(*send, seg2, 20, sh.now_ms + 60);

    // RTO should be at least min_rto_ms (200).
    std::uint64_t deadline = send->RetransmitDeadline();
    TCPIP2_EXPECT_TRUE(deadline >= sh.now_ms + 60 + 200);

    send.reset();
}

// ---------------------------------------------------------------------------
// Karn's rule: no RTT update after retransmit
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendKarnsRuleNoRttAfterRetransmit) {
    SendHelper sh;
    auto send = MakeSendBuffer(12000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);

    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg, 20, sh.now_ms);

    // RTO expires, retransmit.
    std::uint64_t deadline = send->RetransmitDeadline();
    auto rseg = send->NextSegment(65535, deadline);
    TCPIP2_EXPECT_TRUE(rseg.is_retransmission);
    send->OnSent(BufferRef(), 0, deadline);

    // ACK after retransmit — should NOT update RTT (Karn's rule).
    // rto_backed_off_ is true, so the RTT measurement in OnAck is skipped.
    send->OnAck(12005, 65535, deadline + 30);

    // After ACK, rto_backed_off_ is cleared for future segments.
    // The key check: the retransmit was counted and Karn's rule was honored.
    TCPIP2_EXPECT_TRUE(send->RetransmissionCount() >= 1);

    send.reset();
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendConfigValidation) {
    TcpSendConfig config;
    TCPIP2_EXPECT_TRUE(config.Validate());

    config.initial_mss = 0;
    TCPIP2_EXPECT_FALSE(config.Validate());

    config = TcpSendConfig{};
    config.min_rto_ms = 0;
    TCPIP2_EXPECT_FALSE(config.Validate());

    config = TcpSendConfig{};
    config.min_rto_ms = 500;
    config.max_rto_ms = 100;
    TCPIP2_EXPECT_FALSE(config.Validate());

    config = TcpSendConfig{};
    config.initial_rto_ms = 50;
    config.min_rto_ms = 100;
    TCPIP2_EXPECT_FALSE(config.Validate());

    config = TcpSendConfig{};
    config.persist_timer_base_ms = 0;
    TCPIP2_EXPECT_FALSE(config.Validate());

    config = TcpSendConfig{};
    config.max_retransmissions = 0;
    TCPIP2_EXPECT_FALSE(config.Validate());
}

// ---------------------------------------------------------------------------
// Retransmit queue data integrity
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRetransmitQueueDataIntegrity) {
    SendHelper sh;
    auto send = MakeSendBuffer(14000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    send->Enqueue(data, 8);

    // Send two segments: [0x10,0x20,0x30,0x40] and [0x50,0x60,0x70,0x80].
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // RTO retransmit first segment.
    std::uint64_t deadline = send->RetransmitDeadline();
    auto rseg = send->NextSegment(65535, deadline);
    TCPIP2_EXPECT_TRUE(rseg.is_retransmission);
    TCPIP2_EXPECT_EQ(rseg.payload_length, std::size_t{4});
    TCPIP2_EXPECT_EQ(rseg.payload[0], std::uint8_t{0x10});
    TCPIP2_EXPECT_EQ(rseg.payload[3], std::uint8_t{0x40});
    send->OnSent(BufferRef(), 0, deadline);

    // ACK first segment, partial ACK of second.
    send->OnAck(14004, 65535, deadline + 10);

    // RTO retransmit remaining segment — should be [0x50,0x60,0x70,0x80].
    // After partial ACK, the remaining segment's data starts at 0x50.
    // But the RTO timer was just armed, so we need to wait for it.
    std::uint64_t deadline2 = send->RetransmitDeadline();
    auto rseg2 = send->NextSegment(65535, deadline2);
    TCPIP2_EXPECT_TRUE(rseg2.is_retransmission);
    TCPIP2_EXPECT_EQ(rseg2.payload_length, std::size_t{4});
    TCPIP2_EXPECT_EQ(rseg2.payload[0], std::uint8_t{0x50});
    TCPIP2_EXPECT_EQ(rseg2.payload[3], std::uint8_t{0x80});
    send->OnSent(BufferRef(), 0, deadline2);

    send.reset();
}

// ---------------------------------------------------------------------------
// BufferRef released on ACK (no pool leak)
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendBufferRefReleasedOnAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(15000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);

    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    // One buffer should be retained.
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{1});

    // ACK should release it.
    send->OnAck(15005, 65535, sh.now_ms + 50);

    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// Persist timer backoff and max probes closes
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendPersistMaxProbesCloses) {
    SendHelper sh;
    auto send = MakeSendBuffer(16000);

    std::uint8_t data[3] = {};
    send->Enqueue(data, 3);

    send->ArmPersistTimer(sh.now_ms);

    // max_persist_probes = 3. The sender closes when the third unanswered
    // probe's response deadline expires, giving that final probe time to ACK.
    for (int i = 0; i < 3; ++i) {
        std::uint64_t deadline = send->PersistDeadline();
        TCPIP2_EXPECT_TRUE(deadline != 0);
        auto probe = send->NextSegment(0, deadline);
        TCPIP2_EXPECT_TRUE(probe.is_zero_window_probe);
        sh.SendSegment(*send, probe, 20, deadline);
    }

    TCPIP2_EXPECT_FALSE(send->IsClosed());
    auto none = send->NextSegment(0, send->PersistDeadline());
    TCPIP2_EXPECT_FALSE(none.has_segment);
    TCPIP2_EXPECT_TRUE(send->IsClosed());
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// CancelTimers clears all timers
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendCancelTimers) {
    SendHelper sh;
    auto send = MakeSendBuffer(17000);

    std::uint8_t data[5] = {};
    send->Enqueue(data, 5);
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    send->ArmPersistTimer(sh.now_ms);

    TCPIP2_EXPECT_TRUE(send->RetransmitDeadline() != 0);
    TCPIP2_EXPECT_TRUE(send->PersistActive());

    send->CancelTimers();

    TCPIP2_EXPECT_TRUE(send->RetransmitDeadline() == 0);
    TCPIP2_EXPECT_FALSE(send->PersistActive());

    send.reset();
}

// ---------------------------------------------------------------------------
// Zero-length enqueue rejected
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendZeroLengthEnqueueRejected) {
    SendHelper sh;
    auto send = MakeSendBuffer(18000);

    std::uint8_t data[5] = {};
    TCPIP2_EXPECT_EQ(send->Enqueue(data, 0), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// Null data rejected
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendNullDataRejected) {
    SendHelper sh;
    auto send = MakeSendBuffer(19000);

    TCPIP2_EXPECT_EQ(send->Enqueue(nullptr, 5), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// RequestFin twice rejected
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRequestFinTwiceRejected) {
    SendHelper sh;
    auto send = MakeSendBuffer(20000);

    TCPIP2_EXPECT_TRUE(send->RequestFin());
    TCPIP2_EXPECT_FALSE(send->RequestFin());

    send.reset();
}

// ---------------------------------------------------------------------------
// Multiple segments in flight (cwnd limits)
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendMultipleSegmentsInFlight) {
    SendHelper sh;
    auto send = MakeSendBuffer(21000, 100, 64 * 1024, 64 * 1024);

    // cwnd = 2 * MSS = 200.
    std::uint8_t data[500] = {};
    send->Enqueue(data, 500);

    // Should send 2 segments (200 bytes total, limited by cwnd).
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg1.has_segment);
    TCPIP2_EXPECT_EQ(seg1.payload_length, std::size_t{100});
    sh.SendSegment(*send, seg1);

    auto seg2 = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg2.has_segment);
    TCPIP2_EXPECT_EQ(seg2.payload_length, std::size_t{100});
    sh.SendSegment(*send, seg2);

    // cwnd exhausted — no more segments.
    auto seg3 = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_FALSE(seg3.has_segment);

    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{200});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{2});

    send.reset();
}

// ---------------------------------------------------------------------------
// Peer window limits segment
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendPeerWindowLimitsSegment) {
    SendHelper sh;
    auto send = MakeSendBuffer(22000, 1460, 64 * 1024, 64 * 1024);

    std::uint8_t data[100] = {};
    send->Enqueue(data, 100);

    // Peer window = 50, cwnd is large. Should only send 50 bytes.
    auto seg = send->NextSegment(50, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg.has_segment);
    TCPIP2_EXPECT_EQ(seg.payload_length, std::size_t{50});
    sh.SendSegment(*send, seg);

    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{50});
    TCPIP2_EXPECT_EQ(send->UnsntBytes(), std::size_t{50});

    send.reset();
}

// ---------------------------------------------------------------------------
// ACK validation and partial-record trimming
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRejectsFutureAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(23000);

    const std::uint8_t data[4] = {1, 2, 3, 4};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    auto ack = send->OnAck(23005, 65535, sh.now_ms + 10);
    TCPIP2_EXPECT_TRUE(ack.unacceptable);
    TCPIP2_EXPECT_EQ(ack.newly_acked, std::size_t{0});
    TCPIP2_EXPECT_EQ(send->SndUna(), std::uint32_t{23000});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{1});

    auto valid = send->OnAck(23004, 65535, sh.now_ms + 20);
    TCPIP2_EXPECT_FALSE(valid.unacceptable);
    TCPIP2_EXPECT_TRUE(valid.fully_acked);
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    send.reset();
}

TCPIP2_TEST(SendPartialAckTrimsRecord) {
    SendHelper sh;
    auto send = MakeSendBuffer(24000, 4);

    const std::uint8_t data[4] = {0x11, 0x22, 0x33, 0x44};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    auto ack = send->OnAck(24002, 65535, sh.now_ms + 20);
    TCPIP2_EXPECT_EQ(ack.newly_acked, std::size_t{2});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{2});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    const auto deadline = send->RetransmitDeadline();
    auto retry = send->NextSegment(65535, deadline);
    TCPIP2_EXPECT_TRUE(retry.is_retransmission);
    TCPIP2_EXPECT_EQ(retry.sequence, std::uint32_t{24002});
    TCPIP2_EXPECT_EQ(retry.payload_length, std::size_t{2});
    TCPIP2_EXPECT_EQ(retry.payload[0], std::uint8_t{0x33});
    TCPIP2_EXPECT_EQ(retry.payload[1], std::uint8_t{0x44});
    send->OnSent(BufferRef(), 0, deadline);

    auto final_ack = send->OnAck(24004, 65535, deadline + 10);
    TCPIP2_EXPECT_TRUE(final_ack.fully_acked);

    send.reset();
}

TCPIP2_TEST(SendPartialAckPreservesFinSequence) {
    SendHelper sh;
    auto send = MakeSendBuffer(25000, 4);

    const std::uint8_t data[4] = {0x10, 0x20, 0x30, 0x40};
    send->Enqueue(data, sizeof(data));
    send->RequestFin();
    auto seg = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg.is_fin);
    sh.SendSegment(*send, seg);

    send->OnAck(25002, 65535, sh.now_ms + 10);
    auto retry = send->NextSegment(65535, send->RetransmitDeadline());
    TCPIP2_EXPECT_EQ(retry.sequence, std::uint32_t{25002});
    TCPIP2_EXPECT_EQ(retry.payload_length, std::size_t{2});
    TCPIP2_EXPECT_TRUE(retry.is_fin);
    send->OnSent(BufferRef(), 0, send->RetransmitDeadline());

    send->OnAck(25004, 65535, sh.now_ms + 2200);
    TCPIP2_EXPECT_FALSE(send->FinAcked());
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{0});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    auto fin_retry = send->NextSegment(65535, send->RetransmitDeadline());
    TCPIP2_EXPECT_TRUE(fin_retry.is_retransmission);
    TCPIP2_EXPECT_TRUE(fin_retry.is_fin);
    TCPIP2_EXPECT_EQ(fin_retry.sequence, std::uint32_t{25004});
    TCPIP2_EXPECT_EQ(fin_retry.payload_length, std::size_t{0});
    send->OnSent(BufferRef(), 0, send->RetransmitDeadline());

    auto final_ack = send->OnAck(25005, 65535, sh.now_ms + 7000);
    TCPIP2_EXPECT_TRUE(final_ack.fully_acked);
    TCPIP2_EXPECT_TRUE(send->FinAcked());
    TCPIP2_EXPECT_TRUE(send->AllAcked());

    send.reset();
}

// ---------------------------------------------------------------------------
// Persist ownership and window reopening
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendPersistRetriesSameRetainedByte) {
    SendHelper sh;
    auto send = MakeSendBuffer(26000);

    const std::uint8_t data[3] = {0xaa, 0xbb, 0xcc};
    send->Enqueue(data, sizeof(data));

    auto none = send->NextSegment(0, sh.now_ms);
    TCPIP2_EXPECT_FALSE(none.has_segment);
    auto first = send->NextSegment(0, send->PersistDeadline());
    TCPIP2_EXPECT_EQ(first.sequence, std::uint32_t{26000});
    TCPIP2_EXPECT_EQ(first.payload[0], std::uint8_t{0xaa});
    sh.SendSegment(*send, first, 20, send->PersistDeadline());
    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{26001});
    TCPIP2_EXPECT_EQ(send->UnsntBytes(), std::size_t{2});
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{1});

    auto retry = send->NextSegment(0, send->PersistDeadline());
    TCPIP2_EXPECT_TRUE(retry.is_retransmission);
    TCPIP2_EXPECT_TRUE(retry.is_zero_window_probe);
    TCPIP2_EXPECT_EQ(retry.sequence, std::uint32_t{26000});
    TCPIP2_EXPECT_EQ(retry.payload[0], std::uint8_t{0xaa});
    sh.SendSegment(*send, retry, 20, send->PersistDeadline());
    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{26001});
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{1});

    send.reset();
}

TCPIP2_TEST(SendPersistPromotesWithoutSequenceHole) {
    SendHelper sh;
    auto send = MakeSendBuffer(27000);

    const std::uint8_t data[3] = {0x71, 0x72, 0x73};
    send->Enqueue(data, sizeof(data));
    send->NextSegment(0, sh.now_ms);
    auto probe = send->NextSegment(0, send->PersistDeadline());
    sh.SendSegment(*send, probe, 20, send->PersistDeadline());

    const std::uint64_t promote_time = send->PersistDeadline() + 1;
    auto promoted = send->NextSegment(10, promote_time);
    TCPIP2_EXPECT_TRUE(promoted.is_retransmission);
    TCPIP2_EXPECT_FALSE(promoted.is_zero_window_probe);
    TCPIP2_EXPECT_EQ(promoted.sequence, std::uint32_t{27000});
    TCPIP2_EXPECT_EQ(promoted.payload[0], std::uint8_t{0x71});
    sh.SendSegment(*send, promoted, 20, promote_time);
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{1});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    auto remainder = send->NextSegment(10, promote_time + 1);
    TCPIP2_EXPECT_FALSE(remainder.is_retransmission);
    TCPIP2_EXPECT_EQ(remainder.sequence, std::uint32_t{27001});
    TCPIP2_EXPECT_EQ(remainder.payload_length, std::size_t{2});
    TCPIP2_EXPECT_EQ(remainder.payload[0], std::uint8_t{0x72});
    sh.SendSegment(*send, remainder, 20, promote_time + 1);
    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{27003});

    auto ack = send->OnAck(27003, 10, promote_time + 10);
    TCPIP2_EXPECT_TRUE(ack.fully_acked);
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    send.reset();
}

TCPIP2_TEST(SendPersistWithOutstandingDataDoesNotAdvanceSequence) {
    SendHelper sh;
    auto send = MakeSendBuffer(28000, 4);

    const std::uint8_t data[4] = {9, 8, 7, 6};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);
    send->OnAck(28000, 0, sh.now_ms + 10);

    auto probe = send->NextSegment(0, send->PersistDeadline());
    TCPIP2_EXPECT_TRUE(probe.is_zero_window_probe);
    TCPIP2_EXPECT_TRUE(probe.is_retransmission);
    TCPIP2_EXPECT_EQ(probe.sequence, std::uint32_t{28000});
    TCPIP2_EXPECT_EQ(probe.payload_length, std::size_t{1});
    TCPIP2_EXPECT_EQ(probe.payload[0], std::uint8_t{9});
    sh.SendSegment(*send, probe, 20, send->PersistDeadline());

    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{28004});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    send.reset();
}

// ---------------------------------------------------------------------------
// Retransmit capacity and per-record Karn state
// ---------------------------------------------------------------------------

TCPIP2_TEST(SendRetransmitLimitAppliedBeforeSerialization) {
    SendHelper sh;
    auto send = MakeSendBuffer(29000, 4, 64 * 1024, 5);

    const std::uint8_t data[8] = {};
    send->Enqueue(data, sizeof(data));
    auto first = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_EQ(first.payload_length, std::size_t{4});
    sh.SendSegment(*send, first);

    auto second = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(second.has_segment);
    TCPIP2_EXPECT_EQ(second.payload_length, std::size_t{1});
    sh.SendSegment(*send, second);

    auto blocked = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_FALSE(blocked.has_segment);
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{5});
    TCPIP2_EXPECT_EQ(send->UnsntBytes(), std::size_t{3});

    send.reset();
}

TCPIP2_TEST(SendKarnStateIsPerRecord) {
    SendHelper sh;
    auto send = MakeSendBuffer(30000, 4);

    const std::uint8_t data[8] = {};
    send->Enqueue(data, sizeof(data));
    auto first = send->NextSegment(65535, 100);
    sh.SendSegment(*send, first, 20, 100);
    auto second = send->NextSegment(65535, 200);
    sh.SendSegment(*send, second, 20, 200);

    auto retry = send->NextSegment(65535, 1100);
    TCPIP2_EXPECT_TRUE(retry.is_retransmission);
    send->OnSent(BufferRef(), 0, 1100);
    TCPIP2_EXPECT_EQ(send->CurrentRto(), std::uint64_t{2000});

    send->OnAck(30004, 65535, 1110);
    TCPIP2_EXPECT_EQ(send->CurrentRto(), std::uint64_t{2000});
    send->OnAck(30008, 65535, 1200);
    TCPIP2_EXPECT_EQ(send->CurrentRto(), std::uint64_t{3000});

    send.reset();
}

TCPIP2_TEST(SendRetransmissionHonorsReducedMssAndWindow) {
    SendHelper sh;
    auto send = MakeSendBuffer(31000, 8);

    const std::uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    send->UpdateMss(4);
    auto retry = send->NextSegment(1, send->RetransmitDeadline());
    TCPIP2_EXPECT_TRUE(retry.is_retransmission);
    TCPIP2_EXPECT_EQ(retry.sequence, std::uint32_t{31000});
    TCPIP2_EXPECT_EQ(retry.payload_length, std::size_t{1});
    TCPIP2_EXPECT_EQ(retry.payload[0], std::uint8_t{1});
    send->OnSent(BufferRef(), 0, send->RetransmitDeadline());

    send.reset();
}

TCPIP2_TEST(SendZeroWindowAckUsesPersistNotFastRetransmit) {
    SendHelper sh;
    auto send = MakeSendBuffer(32000, 4);

    const std::uint8_t data[4] = {};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    for (int i = 0; i < 4; ++i) {
        auto ack = send->OnAck(32000, 0, sh.now_ms + 10 + i);
        TCPIP2_EXPECT_FALSE(ack.fast_retransmit);
        TCPIP2_EXPECT_EQ(send->DupAckCount(), std::size_t{0});
    }
    TCPIP2_EXPECT_TRUE(send->PersistActive());
    TCPIP2_EXPECT_EQ(send->RetransmitDeadline(), std::uint64_t{0});

    send.reset();
}

TCPIP2_TEST(SendFinalPersistAckCancelsTimer) {
    SendHelper sh;
    auto send = MakeSendBuffer(33000);

    const std::uint8_t data = 0x5a;
    send->Enqueue(&data, 1);
    send->NextSegment(0, sh.now_ms);
    auto probe = send->NextSegment(0, send->PersistDeadline());
    sh.SendSegment(*send, probe, 20, send->PersistDeadline());
    TCPIP2_EXPECT_TRUE(send->PersistActive());

    auto ack = send->OnAck(33001, 0, sh.now_ms + 1000);
    TCPIP2_EXPECT_TRUE(ack.fully_acked);
    TCPIP2_EXPECT_TRUE(send->AllAcked());
    TCPIP2_EXPECT_FALSE(send->PersistActive());
    TCPIP2_EXPECT_EQ(send->PersistDeadline(), std::uint64_t{0});
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    send.reset();
}

TCPIP2_TEST(SendCumulativeAckAcrossRetransmitSuppressesRttSample) {
    SendHelper sh;
    auto send = MakeSendBuffer(34000, 4);

    const std::uint8_t data[8] = {};
    send->Enqueue(data, sizeof(data));
    auto first = send->NextSegment(65535, 100);
    sh.SendSegment(*send, first, 20, 100);
    auto second = send->NextSegment(65535, 200);
    sh.SendSegment(*send, second, 20, 200);

    auto retry = send->NextSegment(65535, 1100);
    sh.SendSegment(*send, retry, 20, 1100);
    TCPIP2_EXPECT_EQ(send->CurrentRto(), std::uint64_t{2000});

    auto ack = send->OnAck(34008, 65535, 1200);
    TCPIP2_EXPECT_TRUE(ack.fully_acked);
    TCPIP2_EXPECT_EQ(send->CurrentRto(), std::uint64_t{2000});

    send.reset();
}

TCPIP2_TEST(SendFinAckDoesNotCountAsPayloadOrGrowCwnd) {
    SendHelper sh;
    auto send = MakeSendBuffer(35000);

    send->RequestFin();
    auto fin = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, fin);
    const std::uint32_t cwnd = send->CongestionWindow();

    auto ack = send->OnAck(35001, 65535, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(ack.newly_acked, std::size_t{0});
    TCPIP2_EXPECT_EQ(send->CongestionWindow(), cwnd);
    TCPIP2_EXPECT_TRUE(send->FinAcked());
    TCPIP2_EXPECT_TRUE(send->AllAcked());

    send.reset();
}

TCPIP2_TEST(SendResponsivePersistPeerDoesNotExhaustProbeBudget) {
    SendHelper sh;
    auto send = MakeSendBuffer(36000);

    const std::uint8_t data[3] = {1, 2, 3};
    send->Enqueue(data, sizeof(data));
    send->NextSegment(0, sh.now_ms);

    for (std::uint32_t i = 0; i < 3; ++i) {
        auto probe = send->NextSegment(0, send->PersistDeadline());
        TCPIP2_EXPECT_TRUE(probe.is_zero_window_probe);
        sh.SendSegment(*send, probe, 20, send->PersistDeadline());
        auto ack = send->OnAck(36001 + i, 0, sh.now_ms + 1000 + i);
        TCPIP2_EXPECT_FALSE(ack.unacceptable);
        TCPIP2_EXPECT_FALSE(send->IsClosed());
        TCPIP2_EXPECT_EQ(send->PersistProbeCount(), std::size_t{0});
    }

    TCPIP2_EXPECT_TRUE(send->AllAcked());
    TCPIP2_EXPECT_FALSE(send->PersistActive());

    send.reset();
}

TCPIP2_TEST(SendRtoRecoveryContinuesImmediatelyAfterPartialAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(37000, 4);

    const std::uint8_t data[4] = {1, 2, 3, 4};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, 100);
    sh.SendSegment(*send, seg, 20, 100);
    send->UpdateMss(1);

    std::uint64_t now = send->RetransmitDeadline();
    for (std::uint32_t i = 0; i < 4; ++i) {
        auto retry = send->NextSegment(65535, now);
        TCPIP2_EXPECT_TRUE(retry.is_retransmission);
        TCPIP2_EXPECT_EQ(retry.sequence, std::uint32_t{37000 + i});
        TCPIP2_EXPECT_EQ(retry.payload_length, std::size_t{1});
        sh.SendSegment(*send, retry, 20, now);
        ++now;
        auto ack = send->OnAck(37001 + i, 65535, now);
        TCPIP2_EXPECT_FALSE(send->IsClosed());
        if (i != 3) {
            TCPIP2_EXPECT_EQ(send->RetransmitDeadline(), now);
        } else {
            TCPIP2_EXPECT_TRUE(ack.fully_acked);
        }
    }

    TCPIP2_EXPECT_TRUE(send->AllAcked());
    send.reset();
}

TCPIP2_TEST(SendFirstThreeDuplicateAcksTriggerFastRetransmit) {
    SendHelper sh;
    auto send = MakeSendBuffer(38000, 4);

    const std::uint8_t data[4] = {};
    send->Enqueue(data, sizeof(data));
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);

    for (int i = 0; i < 2; ++i) {
        auto ack = send->OnAck(38000, 65535, sh.now_ms + 10 + i);
        TCPIP2_EXPECT_FALSE(ack.fast_retransmit);
    }
    auto third = send->OnAck(38000, 65535, sh.now_ms + 12);
    TCPIP2_EXPECT_TRUE(third.fast_retransmit);
    TCPIP2_EXPECT_EQ(send->DupAckCount(), std::size_t{3});

    send.reset();
}

TCPIP2_TEST(SendPayloadAckReleasesOwnerBeforeFinAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(39000, 4);

    const std::uint8_t data[4] = {};
    send->Enqueue(data, sizeof(data));
    send->RequestFin();
    auto seg = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg);
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{1});

    send->OnAck(39004, 65535, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});
    TCPIP2_EXPECT_EQ(send->InFlightBytes(), std::size_t{0});
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    send->OnAck(39005, 65535, sh.now_ms + 20);
    TCPIP2_EXPECT_TRUE(send->AllAcked());

    send.reset();
}

TCPIP2_TEST(SendSequenceWrapAckAndFin) {
    SendHelper sh;
    auto send = MakeSendBuffer(0xfffffffdU, 2);

    const std::uint8_t data[2] = {0xa1, 0xa2};
    send->Enqueue(data, sizeof(data));
    send->RequestFin();
    auto seg = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg.is_fin);
    sh.SendSegment(*send, seg);
    TCPIP2_EXPECT_EQ(send->SndNxt(), std::uint32_t{0});

    auto future = send->OnAck(1, 65535, sh.now_ms + 5);
    TCPIP2_EXPECT_TRUE(future.unacceptable);
    TCPIP2_EXPECT_EQ(send->SndUna(), std::uint32_t{0xfffffffdU});

    auto data_ack = send->OnAck(0xffffffffU, 65535, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(data_ack.newly_acked, std::size_t{2});
    TCPIP2_EXPECT_FALSE(send->FinAcked());
    TCPIP2_EXPECT_EQ(sh.pool.RetainedCount(), std::size_t{0});

    auto fin_ack = send->OnAck(0, 65535, sh.now_ms + 20);
    TCPIP2_EXPECT_TRUE(fin_ack.fully_acked);
    TCPIP2_EXPECT_TRUE(send->FinAcked());
    TCPIP2_EXPECT_TRUE(send->AllAcked());

    send.reset();
}

// ---------------------------------------------------------------------------
// SACK scoreboard tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(SackSingleBlockMarksRecord) {
    SendHelper sh;
    auto send = MakeSendBuffer(40000, 4, 64 * 1024, 64 * 1024);

    // Enqueue 8 bytes, send two segments of 4 bytes each.
    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // SACK the second segment [40004, 40008).
    TcpSackBlockList sacks;
    sacks.blocks[0] = {40004, 40008};
    sacks.count = 1;
    std::size_t newly = send->OnSack(sacks, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(newly, std::size_t{4});
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->SackedSequence(), std::uint32_t{4});
    TCPIP2_EXPECT_FALSE(send->InFastRecovery());

    send.reset();
}

TCPIP2_TEST(SackMultipleBlocksMarkMultipleRecords) {
    SendHelper sh;
    auto send = MakeSendBuffer(41000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    // Send 2 segments: [41000,41004), [41004,41008)  (cwnd = 2*MSS = 8)
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // SACK both segments.
    TcpSackBlockList sacks;
    sacks.blocks[0] = {41000, 41004};
    sacks.blocks[1] = {41004, 41008};
    sacks.count = 2;
    std::size_t newly = send->OnSack(sacks, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(newly, std::size_t{8});
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{8});
    TCPIP2_EXPECT_EQ(send->SackedSequence(), std::uint32_t{8});

    send.reset();
}

TCPIP2_TEST(SackAlreadySackedIsIdempotent) {
    SendHelper sh;
    auto send = MakeSendBuffer(42000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    TcpSackBlockList sacks;
    sacks.blocks[0] = {42004, 42008};
    sacks.count = 1;
    send->OnSack(sacks, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});

    // Second SACK with same block should not add bytes.
    std::size_t newly = send->OnSack(sacks, sh.now_ms + 20);
    TCPIP2_EXPECT_EQ(newly, std::size_t{0});
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});

    send.reset();
}

TCPIP2_TEST(SackTriggersFastRetransmit) {
    SendHelper sh;
    auto send = MakeSendBuffer(43000, 4, 64 * 1024, 64 * 1024);

    // cwnd starts at 2*MSS = 8, allowing 2 segments in flight.
    std::uint8_t data[16] = {};
    send->Enqueue(data, 16);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // ACK seg1 to open the window.  cwnd grows, allowing more sends.
    send->OnAck(43004, 65535, sh.now_ms + 5);

    // Now send seg3 and seg4.
    auto seg3 = send->NextSegment(65535, sh.now_ms + 5);
    sh.SendSegment(*send, seg3);
    auto seg4 = send->NextSegment(65535, sh.now_ms + 5);
    sh.SendSegment(*send, seg4);

    // SACK segments 2, 3, 4 (sequences 43004, 43008, 43012).
    // seg2 [43004,43008), seg3 [43008,43012), seg4 [43012,43016)
    TcpSackBlockList sacks;
    sacks.blocks[0] = {43004, 43008};
    sacks.blocks[1] = {43008, 43012};
    sacks.blocks[2] = {43012, 43016};
    sacks.count = 3;
    send->OnSack(sacks, sh.now_ms + 10);

    TCPIP2_EXPECT_TRUE(send->InFastRecovery());
    // Fast retransmit should be pending for the front segment.
    // After ACKing seg1, the front is seg2 [43004,43008).
    auto rseg = send->NextSegment(65535, sh.now_ms + 20);
    TCPIP2_EXPECT_TRUE(rseg.is_retransmission);
    TCPIP2_EXPECT_EQ(rseg.sequence, std::uint32_t{43004});

    send.reset();
}

TCPIP2_TEST(SackDoesNotAffectUnsackedRecords) {
    SendHelper sh;
    auto send = MakeSendBuffer(44000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // SACK only the second segment [44004, 44008).
    TcpSackBlockList sacks;
    sacks.blocks[0] = {44004, 44008};
    sacks.count = 1;
    send->OnSack(sacks, sh.now_ms + 10);

    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->SackedSequence(), std::uint32_t{4});
    TCPIP2_EXPECT_FALSE(send->InFastRecovery());

    send.reset();
}

TCPIP2_TEST(SackPartialOverlapDoesNotMarkRecord) {
    SendHelper sh;
    auto send = MakeSendBuffer(45000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // SACK block partially overlaps segment 2: [45002, 45006).
    // Segment 2 is [45004, 45008) — this does NOT fully cover it.
    TcpSackBlockList sacks;
    sacks.blocks[0] = {45002, 45006};
    sacks.count = 1;
    std::size_t newly = send->OnSack(sacks, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(newly, std::size_t{0});
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{0});

    send.reset();
}

TCPIP2_TEST(SackClearedOnFullAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(46000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // SACK segment 2.
    TcpSackBlockList sacks;
    sacks.blocks[0] = {46004, 46008};
    sacks.count = 1;
    send->OnSack(sacks, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});

    // Cumulative ACK of everything.
    auto ack = send->OnAck(46008, 65535, sh.now_ms + 20);
    TCPIP2_EXPECT_TRUE(ack.fully_acked);
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{0});
    TCPIP2_EXPECT_EQ(send->SackedSequence(), std::uint32_t{0});

    send.reset();
}

TCPIP2_TEST(SackUpdatesUsableWindow) {
    SendHelper sh;
    auto send = MakeSendBuffer(47000, 4, 64 * 1024, 64 * 1024);

    // cwnd = 2*MSS = 8. Send 2 segments (8 bytes in-flight).
    std::uint8_t data[12] = {};
    send->Enqueue(data, 12);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // cwnd exhausted — no new segment.
    auto none = send->NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_FALSE(none.has_segment);

    // SACK segment 2 → pipe shrinks by 4 bytes → usable window = 4.
    TcpSackBlockList sacks;
    sacks.blocks[0] = {47004, 47008};
    sacks.count = 1;
    send->OnSack(sacks, sh.now_ms + 10);

    // Now we should be able to send a new segment of up to 4 bytes.
    auto seg3 = send->NextSegment(65535, sh.now_ms + 10);
    TCPIP2_EXPECT_TRUE(seg3.has_segment);
    TCPIP2_EXPECT_EQ(seg3.payload_length, std::size_t{4});
    TCPIP2_EXPECT_EQ(seg3.sequence, std::uint32_t{47008});

    send.reset();
}

TCPIP2_TEST(SackClearedOnPartialAck) {
    SendHelper sh;
    auto send = MakeSendBuffer(48000, 4, 64 * 1024, 64 * 1024);

    std::uint8_t data[8] = {};
    send->Enqueue(data, 8);
    auto seg1 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg1);
    auto seg2 = send->NextSegment(65535, sh.now_ms);
    sh.SendSegment(*send, seg2);

    // SACK segment 2 [48004, 48008).
    TcpSackBlockList sacks;
    sacks.blocks[0] = {48004, 48008};
    sacks.count = 1;
    send->OnSack(sacks, sh.now_ms + 10);
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});

    // Partial ACK covering segment 1 — doesn't touch the SACKed segment 2.
    send->OnAck(48004, 65535, sh.now_ms + 20);
    // SACKed segment 2 is still in queue and still SACKed.
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{4});
    TCPIP2_EXPECT_EQ(send->RetransmitQueueSize(), std::size_t{1});

    // Full ACK of segment 2 should clear SACK state.
    send->OnAck(48008, 65535, sh.now_ms + 30);
    TCPIP2_EXPECT_EQ(send->SackedBytes(), std::size_t{0});

    send.reset();
}

// ---------------------------------------------------------------------------
// P3C-03: Per-flow pacing tests
// ---------------------------------------------------------------------------

TCPIP2_TEST(PacingAimdHasNoPacingGate) {
    SendScope s;
    auto& send = *s.send;
    auto& sh = s.sh;

    // AIMD pacing_rate is always 0 → no pacing gate.
    std::vector<std::uint8_t> data(5000, 0xAB);
    send.Enqueue(data.data(), data.size());
    auto seg = send.NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg.has_segment);
    sh.SendSegment(send, seg);
    TCPIP2_EXPECT_EQ(send.PacingDeadline(), std::uint64_t{0});
}

TCPIP2_TEST(PacingBbrDelaysSecondSegment) {
    SendScope s(1000, 1000, 64 * 1024, 64 * 1024);
    // Override with BBR controller.
    s.send = std::make_unique<TcpSendBuffer>(
        1000, 1000, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Bbr);
    auto& send = *s.send;
    auto& sh = s.sh;

    // Manually inject BtlBw and RTprop into the BBR controller by simulating
    // ACKs.  First, send data and ACK it to give BBR measurements.
    std::vector<std::uint8_t> data(2000, 0xAB);
    send.Enqueue(data.data(), data.size());

    // Send first segment.
    auto seg1 = send.NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg1.has_segment);
    sh.SendSegment(send, seg1);
    // First segment is not paced (gate was 0).
    TCPIP2_EXPECT_EQ(send.PacingDeadline(), std::uint64_t{0});

    // ACK the first segment to give BBR a rate sample.
    sh.now_ms += 10; // 10 ms RTT
    send.OnAck(seg1.sequence + static_cast<std::uint32_t>(seg1.payload_length), 65535, sh.now_ms, true);

    // BBR should now have BtlBw and RTprop.  Pacing rate should be nonzero.
    TCPIP2_EXPECT_TRUE(send.PacingRate() > 0);

    // Send second segment — should be paced.
    send.Enqueue(data.data(), 1000);
    auto seg2 = send.NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg2.has_segment);
    sh.SendSegment(send, seg2);

    // Pacing deadline should be in the future.
    TCPIP2_EXPECT_TRUE(send.PacingDeadline() > sh.now_ms);
}

TCPIP2_TEST(PacingDoesNotBlockRetransmission) {
    SendScope s(1000, 1000, 64 * 1024, 64 * 1024);
    s.send = std::make_unique<TcpSendBuffer>(
        1000, 1000, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Bbr);
    auto& send = *s.send;
    auto& sh = s.sh;

    // Establish BtlBw by sending and ACKing one segment.
    std::vector<std::uint8_t> data(1000, 0xAB);
    send.Enqueue(data.data(), data.size());
    auto seg1 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg1);
    sh.now_ms += 10;
    send.OnAck(seg1.sequence + static_cast<std::uint32_t>(seg1.payload_length), 65535, sh.now_ms, true);
    TCPIP2_EXPECT_TRUE(send.PacingRate() > 0);

    // Send second segment to arm pacing gate.
    send.Enqueue(data.data(), 1000);
    auto seg2 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg2);
    const std::uint64_t pacing_deadline = send.PacingDeadline();
    TCPIP2_EXPECT_TRUE(pacing_deadline > sh.now_ms);

    // Advance time past RTO.  Retransmit should fire even though pacing
    // gate hasn't expired.
    sh.now_ms += 2000; // well past RTO
    // Advance to exactly the RTO deadline.
    sh.now_ms = send.RetransmitDeadline() + 1;

    auto seg3 = send.NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg3.has_segment);
    TCPIP2_EXPECT_TRUE(seg3.is_retransmission);
}

TCPIP2_TEST(PacingDoesNotBlockZeroWindowProbe) {
    SendScope s(1000, 1000, 64 * 1024, 64 * 1024);
    s.send = std::make_unique<TcpSendBuffer>(
        1000, 1000, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Bbr);
    auto& send = *s.send;
    auto& sh = s.sh;

    // Establish BtlBw.
    std::vector<std::uint8_t> data(1000, 0xAB);
    send.Enqueue(data.data(), data.size());
    auto seg1 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg1);
    sh.now_ms += 10;
    send.OnAck(seg1.sequence + static_cast<std::uint32_t>(seg1.payload_length), 65535, sh.now_ms, true);
    TCPIP2_EXPECT_TRUE(send.PacingRate() > 0);

    // Queue more data, then peer closes window to 0.
    send.Enqueue(data.data(), 1000);
    send.OnAck(seg1.sequence + static_cast<std::uint32_t>(seg1.payload_length), 0, sh.now_ms, true);
    TCPIP2_EXPECT_TRUE(send.PersistActive());

    // Advance past persist timer.  Probe should fire despite pacing gate.
    sh.now_ms = send.PersistDeadline() + 1;
    auto seg2 = send.NextSegment(0, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg2.has_segment);
    TCPIP2_EXPECT_TRUE(seg2.is_zero_window_probe);
}

TCPIP2_TEST(PacingGateExpiresAfterDeadline) {
    SendScope s(1000, 1000, 64 * 1024, 64 * 1024);
    s.send = std::make_unique<TcpSendBuffer>(
        1000, 1000, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Bbr);
    auto& send = *s.send;
    auto& sh = s.sh;

    // Establish BtlBw.
    std::vector<std::uint8_t> data(1000, 0xAB);
    send.Enqueue(data.data(), data.size());
    auto seg1 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg1);
    sh.now_ms += 10;
    send.OnAck(seg1.sequence + static_cast<std::uint32_t>(seg1.payload_length), 65535, sh.now_ms, true);
    TCPIP2_EXPECT_TRUE(send.PacingRate() > 0);

    // Queue enough data for two more segments.
    std::vector<std::uint8_t> more(2000, 0xCD);
    send.Enqueue(more.data(), more.size());

    // Send second segment — arms pacing gate.
    auto seg2 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg2);
    const std::uint64_t deadline = send.PacingDeadline();
    TCPIP2_EXPECT_TRUE(deadline > sh.now_ms);

    // Before deadline: no new segment.
    auto seg3 = send.NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(!seg3.has_segment);

    // After deadline: new segment available.
    sh.now_ms = deadline + 1;
    auto seg4 = send.NextSegment(65535, sh.now_ms);
    TCPIP2_EXPECT_TRUE(seg4.has_segment);
    TCPIP2_EXPECT_TRUE(!seg4.is_retransmission);
}

TCPIP2_TEST(PacingResetOnClose) {
    SendScope s(1000, 1000, 64 * 1024, 64 * 1024);
    s.send = std::make_unique<TcpSendBuffer>(
        1000, 1000, 0, 64 * 1024, 64 * 1024,
        1000, 200, 60000, 500, 60000, 3, 3,
        CongestionAlgorithm::Bbr);
    auto& send = *s.send;
    auto& sh = s.sh;

    // Establish BtlBw and arm pacing gate.
    std::vector<std::uint8_t> data(1000, 0xAB);
    send.Enqueue(data.data(), data.size());
    auto seg1 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg1);
    sh.now_ms += 10;
    send.OnAck(seg1.sequence + static_cast<std::uint32_t>(seg1.payload_length), 65535, sh.now_ms, true);

    send.Enqueue(data.data(), 1000);
    auto seg2 = send.NextSegment(65535, sh.now_ms);
    sh.SendSegment(send, seg2);
    TCPIP2_EXPECT_TRUE(send.PacingDeadline() > sh.now_ms);

    // Exhaust retransmissions to trigger Close().
    for (int i = 0; i < 3 && !send.IsClosed(); ++i) {
        sh.now_ms = send.RetransmitDeadline() + 1;
        auto rt = send.NextSegment(65535, sh.now_ms);
        if (rt.has_segment) sh.SendSegment(send, rt);
    }
    TCPIP2_EXPECT_TRUE(send.IsClosed());
    TCPIP2_EXPECT_EQ(send.PacingDeadline(), std::uint64_t{0});
}

TCPIP2_TEST_MAIN()
