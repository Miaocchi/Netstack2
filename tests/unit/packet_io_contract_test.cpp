#include <cstdint>
#include <thread>

#include <tcpip2/buffer.h>
#include <tcpip2/packet_io.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(EmptyRecvReturnsZeroNone) {
    PktBufferPool pool(8, 1024);
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{0}, q->QueueId());
    BufferLease out[4];
    IoError err = IoError::Internal;
    std::size_t n = q->RecvBatch(out, 4, err);
    TCPIP2_EXPECT_EQ(std::size_t{0}, n);
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    TCPIP2_EXPECT_FALSE(static_cast<bool>(out[0]));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(InjectThenRecvTransfersLeases) {
    PktBufferPool pool(8, 1024);
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    BufferLease l1 = pool.Allocate();
    BufferLease l2 = pool.Allocate();
    l1.Resize(100);
    l2.Resize(200);
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(l1)));
    TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(l2)));
    TCPIP2_EXPECT_EQ(std::size_t{2}, pool.OutstandingCount());

    BufferLease out[4];
    IoError err = IoError::Internal;
    std::size_t n = q->RecvBatch(out, 4, err);
    TCPIP2_EXPECT_EQ(std::size_t{2}, n);
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    TCPIP2_EXPECT_TRUE(static_cast<bool>(out[0]));
    TCPIP2_EXPECT_TRUE(static_cast<bool>(out[1]));
    TCPIP2_EXPECT_EQ(std::size_t{100}, out[0].Size());
    TCPIP2_EXPECT_EQ(std::size_t{200}, out[1].Size());
    TCPIP2_EXPECT_EQ(std::size_t{2}, pool.OutstandingCount());
    TCPIP2_EXPECT_FALSE(static_cast<bool>(out[2]));

    out[0].Reset();
    out[1].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(RecvCapacityLimit) {
    PktBufferPool pool(8, 512);
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    for (int i = 0; i < 5; ++i) {
        BufferLease l = pool.Allocate();
        TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(l)));
    }
    TCPIP2_EXPECT_EQ(std::size_t{5}, pool.OutstandingCount());
    BufferLease out[2];
    IoError err = IoError::Internal;
    TCPIP2_EXPECT_EQ(std::size_t{2}, q->RecvBatch(out, 2, err));
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    out[0].Reset();
    out[1].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{3}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{2}, q->RecvBatch(out, 2, err));
    out[0].Reset();
    out[1].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, q->RecvBatch(out, 2, err));
    out[0].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, q->RecvBatch(out, 2, err));
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(SendBatchConsumesLeasesAndCapturesEgress) {
    PktBufferPool pool(4, 512);
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    BufferLease pkts[2];
    pkts[0] = pool.Allocate();
    pkts[1] = pool.Allocate();
    pkts[0].Data()[0] = 0xCA;
    pkts[0].Data()[1] = 0xFE;
    pkts[0].Resize(2);
    pkts[1].Data()[0] = 0x00;
    pkts[1].Resize(1);

    IoError err = IoError::Internal;
    std::size_t n = q->SendBatch(pkts, 2, err);
    TCPIP2_EXPECT_EQ(std::size_t{2}, n);
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());

    const std::vector<std::vector<std::uint8_t>>& eg = io.Egress(0);
    TCPIP2_EXPECT_EQ(std::size_t{2}, eg.size());
    TCPIP2_EXPECT_EQ(std::size_t{2}, eg[0].size());
    TCPIP2_EXPECT_EQ(std::uint8_t{0xCA}, eg[0][0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xFE}, eg[0][1]);
    TCPIP2_EXPECT_EQ(std::size_t{1}, eg[1].size());
}

TCPIP2_TEST(ZeroCountIsNone) {
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    BufferLease none[1];
    IoError err = IoError::Internal;
    TCPIP2_EXPECT_EQ(std::size_t{0}, q->SendBatch(none, 0, err));
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    TCPIP2_EXPECT_EQ(std::size_t{0}, q->RecvBatch(none, 0, err));
    TCPIP2_EXPECT_TRUE(err == IoError::None);
}

TCPIP2_TEST(OpenQueueBounds) {
    NullPacketIo io(3);
    TCPIP2_EXPECT_EQ(std::size_t{3}, io.QueueCount());
    TCPIP2_EXPECT_TRUE(io.OpenQueue(0) != nullptr);
    TCPIP2_EXPECT_TRUE(io.OpenQueue(2) != nullptr);
    TCPIP2_EXPECT_TRUE(io.OpenQueue(3) == nullptr);
    TCPIP2_EXPECT_TRUE(io.OpenQueue(99) == nullptr);

    PktBufferPool pool(4, 256);
    BufferLease l = pool.Allocate();
    TCPIP2_EXPECT_FALSE(io.Inject(3, std::move(l)));
    TCPIP2_EXPECT_EQ(std::size_t{1}, pool.OutstandingCount());
}

TCPIP2_TEST(InjectEmptyLeaseFails) {
    NullPacketIo io(1);
    TCPIP2_EXPECT_FALSE(io.Inject(0, BufferLease{}));
}

TCPIP2_TEST(QueueIsolation) {
    NullPacketIo io(2);
    PktBufferPool pool(4, 256);
    BufferLease l = pool.Allocate();
    l.Resize(4);
    TCPIP2_EXPECT_TRUE(io.Inject(1, std::move(l)));

    auto q0 = io.OpenQueue(0);
    BufferLease out[2];
    IoError err = IoError::Internal;
    TCPIP2_EXPECT_EQ(std::size_t{0}, q0->RecvBatch(out, 2, err));

    auto q1 = io.OpenQueue(1);
    TCPIP2_EXPECT_EQ(std::size_t{1}, q1->RecvBatch(out, 2, err));
    TCPIP2_EXPECT_EQ(std::size_t{4}, out[0].Size());
    out[0].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(RecvHandlerStored) {
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    int wake = 0;
    q->SetRecvHandler([&] { ++wake; });
    q->SetRecvHandler(nullptr);
    TCPIP2_EXPECT_EQ(0, wake);
}

TCPIP2_TEST(CrossThreadInjectRecv) {
    PktBufferPool pool(4, 512);
    NullPacketIo io(1);
    auto q = io.OpenQueue(0);
    std::thread t([&io, &pool] {
        BufferLease l = pool.Allocate();
        l.Resize(8);
        TCPIP2_EXPECT_TRUE(io.Inject(0, std::move(l)));
    });
    t.join();
    BufferLease out[1];
    IoError err = IoError::Internal;
    TCPIP2_EXPECT_EQ(std::size_t{1}, q->RecvBatch(out, 1, err));
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    TCPIP2_EXPECT_EQ(std::size_t{8}, out[0].Size());
    out[0].Reset();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST_MAIN();
