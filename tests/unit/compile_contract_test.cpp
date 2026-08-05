/**
 * @file compile_contract_test.cpp
 * @brief Consumer TU that exercises every public header.
 * @license GPL-3.0
 *
 * This translation unit includes every public header in include/tcpip2/
 * exactly as an external consumer would, and touches the public API. It
 * proves the public headers are self-contained and usable together.
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/buffer.h>
#include <tcpip2/config.h>
#include <tcpip2/netstack.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/transport_session.h>

#include "Test.h"

using namespace tcpip2;

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
    pool.Unpin(ref);
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
}

TCPIP2_TEST_MAIN();
