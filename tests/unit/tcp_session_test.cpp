/**
 * @file tcp_session_test.cpp
 * @brief Unit tests for TcpSession.
 * @license GPL-3.0
 */

#include "Test.h"

#include <tcpip2/buffer.h>
#include <tcpip2/transport_session.h>

#include <session/tcp_session.h>

#include <cstring>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace {

/// Allocate a BufferLease filled with @p fill, capacity @p size.
tcpip2::BufferLease MakeLease(tcpip2::PktBufferPool& pool,
                              std::uint8_t fill, std::size_t size) {
    auto lease = pool.Allocate();
    if (lease) {
        std::memset(lease.Data(), fill, size);
        lease.Resize(size);
    }
    return lease;
}

} // namespace

TCPIP2_TEST(TcpSessionTrySendAcceptsBytes) {
    tcpip2::TcpSession session;

    std::uint8_t data[] = {1, 2, 3, 4, 5};
    auto result = session.TrySend(tcpip2::BufferView(data, sizeof(data)));

    TCPIP2_EXPECT_EQ(result.accepted_bytes, static_cast<std::size_t>(5));
    TCPIP2_EXPECT_EQ(result.status, tcpip2::SendStatus::Accepted);
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(5));
    TCPIP2_EXPECT_TRUE(session.IsWritable());
    TCPIP2_EXPECT_FALSE(session.IsClosed());
}

TCPIP2_TEST(TcpSessionTrySendRespectsLimit) {
    tcpip2::TcpSession session(8); // 8-byte limit

    std::uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto result = session.TrySend(tcpip2::BufferView(data, sizeof(data)));

    // Only 8 bytes accepted.
    TCPIP2_EXPECT_EQ(result.accepted_bytes, static_cast<std::size_t>(8));
    TCPIP2_EXPECT_EQ(result.status, tcpip2::SendStatus::Accepted);
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(8));
    TCPIP2_EXPECT_FALSE(session.IsWritable()); // queue full
}

TCPIP2_TEST(TcpSessionTrySendWouldBlockWhenFull) {
    tcpip2::TcpSession session(4); // 4-byte limit

    std::uint8_t data1[] = {1, 2, 3, 4};
    auto r1 = session.TrySend(tcpip2::BufferView(data1, sizeof(data1)));
    TCPIP2_EXPECT_EQ(r1.accepted_bytes, static_cast<std::size_t>(4));
    TCPIP2_EXPECT_EQ(r1.status, tcpip2::SendStatus::Accepted);

    // Queue is now full — second send should WouldBlock.
    std::uint8_t data2[] = {5, 6};
    auto r2 = session.TrySend(tcpip2::BufferView(data2, sizeof(data2)));
    TCPIP2_EXPECT_EQ(r2.accepted_bytes, static_cast<std::size_t>(0));
    TCPIP2_EXPECT_EQ(r2.status, tcpip2::SendStatus::WouldBlock);
}

TCPIP2_TEST(TcpSessionTrySendOnClosedReturnsClosed) {
    tcpip2::TcpSession session;
    session.Abort(tcpip2::SessionError::Reset);

    std::uint8_t data[] = {1, 2, 3};
    auto result = session.TrySend(tcpip2::BufferView(data, sizeof(data)));
    TCPIP2_EXPECT_EQ(result.accepted_bytes, static_cast<std::size_t>(0));
    TCPIP2_EXPECT_EQ(result.status, tcpip2::SendStatus::Closed);
    TCPIP2_EXPECT_TRUE(session.IsClosed());
}

TCPIP2_TEST(TcpSessionShutdownWritePreventsFurtherSends) {
    tcpip2::TcpSession session;

    std::uint8_t data[] = {1, 2, 3};
    auto r1 = session.TrySend(tcpip2::BufferView(data, sizeof(data)));
    TCPIP2_EXPECT_EQ(r1.status, tcpip2::SendStatus::Accepted);

    session.ShutdownWrite();
    TCPIP2_EXPECT_TRUE(session.CloseRequested());

    auto r2 = session.TrySend(tcpip2::BufferView(data, sizeof(data)));
    TCPIP2_EXPECT_EQ(r2.status, tcpip2::SendStatus::Closed);
    TCPIP2_EXPECT_EQ(r2.accepted_bytes, static_cast<std::size_t>(0));
}

TCPIP2_TEST(TcpSessionAbortClearsSendQueue) {
    tcpip2::TcpSession session;

    std::uint8_t data[] = {1, 2, 3, 4, 5};
    session.TrySend(tcpip2::BufferView(data, sizeof(data)));
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(5));

    session.Abort(tcpip2::SessionError::Internal);
    TCPIP2_EXPECT_TRUE(session.IsClosed());
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(0));
}

TCPIP2_TEST(TcpSessionSetDataCallbackReceivesData) {
    tcpip2::PktBufferPool pool(4, 2048);
    tcpip2::TcpSession session;

    std::vector<std::uint8_t> received;
    tcpip2::BufferLease accepted;
    session.SetDataCallback([&received, &accepted](tcpip2::BufferLease& lease) {
        if (lease) {
            received.assign(lease.Data(), lease.Data() + lease.Size());
        }
        accepted = std::move(lease);
        return tcpip2::ReceiveStatus::Accepted;
    });

    auto lease = MakeLease(pool, 0xAB, 64);
    TCPIP2_EXPECT_TRUE(static_cast<bool>(lease));
    session.OnDataReceived(std::move(lease));

    TCPIP2_EXPECT_EQ(received.size(), static_cast<std::size_t>(64));
    TCPIP2_EXPECT_EQ(received[0], static_cast<std::uint8_t>(0xAB));
    TCPIP2_EXPECT_EQ(received[63], static_cast<std::uint8_t>(0xAB));
}

TCPIP2_TEST(TcpSessionRetainsWouldBlockLeaseUntilResume) {
    tcpip2::PktBufferPool pool(4, 2048);
    tcpip2::TcpSession session;
    bool accept = false;
    std::vector<std::uint8_t> received;
    tcpip2::BufferLease accepted;
    session.SetDataCallback([&](tcpip2::BufferLease& lease) {
        if (!accept) return tcpip2::ReceiveStatus::WouldBlock;
        received.assign(lease.Data(), lease.Data() + lease.Size());
        accepted = std::move(lease);
        return tcpip2::ReceiveStatus::Accepted;
    });

    auto lease = MakeLease(pool, 0xCD, 32);
    TCPIP2_EXPECT_EQ(tcpip2::ReceiveStatus::WouldBlock,
                     session.OnDataReceived(std::move(lease)));

    session.ResumeReceive();
    TCPIP2_EXPECT_EQ(std::size_t{0}, received.size());

    accept = true;
    session.ResumeReceive();
    TCPIP2_EXPECT_EQ(std::size_t{32}, received.size());
    TCPIP2_EXPECT_EQ(std::uint8_t{0xCD}, received[0]);
}

TCPIP2_TEST(TcpSessionSetWritableCallbackFiresOnDrain) {
    tcpip2::TcpSession session(8);
    int writable_count = 0;
    session.SetWritableCallback([&writable_count]() {
        ++writable_count;
    });

    // SetWritableCallback fires immediately when the session is already writable.
    TCPIP2_EXPECT_EQ(writable_count, 1);

    // Fill the queue.
    std::uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};
    auto r = session.TrySend(tcpip2::BufferView(data, sizeof(data)));
    TCPIP2_EXPECT_EQ(r.accepted_bytes, static_cast<std::size_t>(8));

    // Draining a full queue frees space, so the callback should fire again.
    std::uint8_t out[4];
    std::size_t drained = session.DrainSendQueue(out, 4);
    TCPIP2_EXPECT_EQ(drained, static_cast<std::size_t>(4));
    TCPIP2_EXPECT_EQ(writable_count, 2);

    // Manually call OnWritable (the shard would do this after draining).
    session.OnWritable();
    TCPIP2_EXPECT_EQ(writable_count, 3);
}

TCPIP2_TEST(TcpSessionSetClosedCallbackFiresOnAbort) {
    tcpip2::TcpSession session;

    tcpip2::SessionError received_error = tcpip2::SessionError::None;
    session.SetClosedCallback([&received_error](tcpip2::SessionError e) {
        received_error = e;
    });

    session.Abort(tcpip2::SessionError::Reset);
    TCPIP2_EXPECT_EQ(received_error, tcpip2::SessionError::Reset);
}

TCPIP2_TEST(TcpSessionSetClosedCallbackFiresOnOnClosed) {
    tcpip2::TcpSession session;

    tcpip2::SessionError received_error = tcpip2::SessionError::None;
    session.SetClosedCallback([&received_error](tcpip2::SessionError e) {
        received_error = e;
    });

    session.OnClosed(tcpip2::SessionError::RemoteClosed);
    TCPIP2_EXPECT_EQ(received_error, tcpip2::SessionError::RemoteClosed);
    TCPIP2_EXPECT_TRUE(session.IsClosed());
}

TCPIP2_TEST(TcpSessionDrainSendQueueReturnsQueuedBytes) {
    tcpip2::TcpSession session;

    std::uint8_t data[] = {10, 20, 30, 40, 50};
    auto r = session.TrySend(tcpip2::BufferView(data, sizeof(data)));
    TCPIP2_EXPECT_EQ(r.accepted_bytes, static_cast<std::size_t>(5));

    // Drain 3 bytes.
    std::uint8_t out[16] = {};
    std::size_t drained = session.DrainSendQueue(out, 3);
    TCPIP2_EXPECT_EQ(drained, static_cast<std::size_t>(3));
    TCPIP2_EXPECT_EQ(out[0], static_cast<std::uint8_t>(10));
    TCPIP2_EXPECT_EQ(out[1], static_cast<std::uint8_t>(20));
    TCPIP2_EXPECT_EQ(out[2], static_cast<std::uint8_t>(30));
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(2));

    // Drain the rest.
    drained = session.DrainSendQueue(out, 16);
    TCPIP2_EXPECT_EQ(drained, static_cast<std::size_t>(2));
    TCPIP2_EXPECT_EQ(out[0], static_cast<std::uint8_t>(40));
    TCPIP2_EXPECT_EQ(out[1], static_cast<std::uint8_t>(50));
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(0));
    TCPIP2_EXPECT_TRUE(session.IsWritable());
}

TCPIP2_TEST(TcpSessionDrainSendQueueOnEmptyReturnsZero) {
    tcpip2::TcpSession session;

    std::uint8_t out[16] = {};
    std::size_t drained = session.DrainSendQueue(out, 16);
    TCPIP2_EXPECT_EQ(drained, static_cast<std::size_t>(0));
}

TCPIP2_TEST(TcpSessionDrainSendQueueNullOutReturnsZero) {
    tcpip2::TcpSession session;

    std::uint8_t data[] = {1, 2, 3};
    session.TrySend(tcpip2::BufferView(data, sizeof(data)));

    std::size_t drained = session.DrainSendQueue(nullptr, 16);
    TCPIP2_EXPECT_EQ(drained, static_cast<std::size_t>(0));
}

TCPIP2_TEST(TcpSessionInitialState) {
    tcpip2::TcpSession session;
    TCPIP2_EXPECT_FALSE(session.IsClosed());
    TCPIP2_EXPECT_FALSE(session.CloseRequested());
    TCPIP2_EXPECT_TRUE(session.IsWritable());
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(0));
}

TCPIP2_TEST(TcpSessionOnWritableInvokesCallback) {
    tcpip2::TcpSession session;
    int count = 0;
    session.SetWritableCallback([&count]() { ++count; });

    // SetWritableCallback fires immediately because the session is writable.
    TCPIP2_EXPECT_EQ(count, 1);

    session.OnWritable();
    TCPIP2_EXPECT_EQ(count, 2);

    session.OnWritable();
    TCPIP2_EXPECT_EQ(count, 3);
}

TCPIP2_TEST(TcpSessionCallbacksNotSetAreSafe) {
    // Setting no callbacks should not crash when events fire.
    tcpip2::TcpSession session;
    session.OnWritable();
    session.OnClosed(tcpip2::SessionError::Timeout);

    tcpip2::PktBufferPool pool(2, 1024);
    auto lease = pool.Allocate();
    if (lease) {
        lease.Resize(8);
        session.OnDataReceived(std::move(lease));
    }
    // No crash = pass.
    TCPIP2_EXPECT_TRUE(true);
}

TCPIP2_TEST(TcpSessionClearDataCallbackWaitsForInFlightInvocation) {
    tcpip2::PktBufferPool pool(2, 1024);
    tcpip2::TcpSession session;
    std::mutex mutex;
    std::condition_variable callback_cv;
    bool entered = false;
    bool release = false;
    std::atomic<bool> clear_started{false};
    std::atomic<bool> cleared{false};
    std::atomic<tcpip2::ReceiveStatus> receive_status{tcpip2::ReceiveStatus::Closed};

    session.SetDataCallback([&](tcpip2::BufferLease& lease) {
        {
            std::unique_lock<std::mutex> lock(mutex);
            entered = true;
            callback_cv.notify_all();
            callback_cv.wait(lock, [&] { return release; });
        }
        lease.Reset();
        return tcpip2::ReceiveStatus::Accepted;
    });

    std::thread receiver([&] {
        receive_status.store(session.OnDataReceived(MakeLease(pool, 0xAB, 16)),
                             std::memory_order_relaxed);
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        callback_cv.wait(lock, [&] { return entered; });
    }

    std::thread clearer([&] {
        clear_started.store(true, std::memory_order_release);
        session.SetDataCallback(nullptr);
        cleared.store(true, std::memory_order_release);
    });
    while (!clear_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    TCPIP2_EXPECT_FALSE(cleared.load(std::memory_order_acquire));

    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    callback_cv.notify_all();
    receiver.join();
    clearer.join();

    TCPIP2_EXPECT_TRUE(cleared.load(std::memory_order_acquire));
    TCPIP2_EXPECT_EQ(tcpip2::ReceiveStatus::Accepted,
                     receive_status.load(std::memory_order_relaxed));
    pool.DrainReturnQueue();
    TCPIP2_EXPECT_EQ(std::size_t{0}, pool.OutstandingCount());
}

TCPIP2_TEST(TcpSessionTrySendEmptyView) {
    tcpip2::TcpSession session;
    auto result = session.TrySend(tcpip2::BufferView());
    TCPIP2_EXPECT_EQ(result.accepted_bytes, static_cast<std::size_t>(0));
    TCPIP2_EXPECT_EQ(result.status, tcpip2::SendStatus::Accepted);
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(0));
}

TCPIP2_TEST(TcpSessionPartialSendThenDrainThenSendAgain) {
    tcpip2::TcpSession session(4);

    // Fill queue.
    std::uint8_t d1[] = {1, 2, 3, 4};
    auto r1 = session.TrySend(tcpip2::BufferView(d1, sizeof(d1)));
    TCPIP2_EXPECT_EQ(r1.accepted_bytes, static_cast<std::size_t>(4));
    TCPIP2_EXPECT_FALSE(session.IsWritable());

    // Drain 2 bytes.
    std::uint8_t out[8];
    session.DrainSendQueue(out, 2);
    TCPIP2_EXPECT_TRUE(session.IsWritable());

    // Send 2 more — should succeed now.
    std::uint8_t d2[] = {5, 6};
    auto r2 = session.TrySend(tcpip2::BufferView(d2, sizeof(d2)));
    TCPIP2_EXPECT_EQ(r2.accepted_bytes, static_cast<std::size_t>(2));
    TCPIP2_EXPECT_EQ(session.SendQueueBytes(), static_cast<std::size_t>(4));
}

TCPIP2_TEST_MAIN()
