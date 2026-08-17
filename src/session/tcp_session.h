#pragma once

/**
 * @file tcp_session.h
 * @brief TcpSession — userspace TCP transport session.
 * @license GPL-3.0
 *
 * Implements the frozen ITransportSession interface (public API) for
 * in-process TCP connections.  The session bridges the application
 * thread (TrySend / callbacks) and the shard thread (data delivery,
 * writable notification, close events).
 *
 * Thread-safety: all public ITransportSession methods and shard-facing
 * methods are protected by an internal mutex.  Callbacks are invoked
 * outside the lock to avoid deadlocks.
 *
 * This is a private header used only by src/session/ — not part of the
 * frozen public API.
 */

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/transport_session.h>

namespace tcpip2 {

/**
 * Concrete ITransportSession for TCP connections managed by the
 * Netstack2 userspace stack.
 *
 * Data flow:
 *   App → TrySend() → send_queue_ → shard drains via DrainSendQueue()
 *   Shard → OnDataReceived() → data_callback_ → App
 *   Shard → OnWritable() → writable_callback_ → App
 *   Shard → OnClosed() → closed_callback_ → App
 */
class TcpSession : public ITransportSession {
  public:
    /// Default send queue capacity before WouldBlock (256 KiB).
    static constexpr std::size_t kDefaultSendQueueLimit = 256 * 1024;

    explicit TcpSession(std::size_t send_queue_limit = kDefaultSendQueueLimit);

    ~TcpSession() override = default;

    TcpSession(const TcpSession &) = delete;
    TcpSession &operator=(const TcpSession &) = delete;

    // ---- ITransportSession (application-facing) ----

    SendResult TrySend(BufferView data) override;
    void ResumeReceive() override;
    void ShutdownWrite() override;
    void Abort(SessionError error) override;
    void SetWritableCallback(WritableCallback cb) override;
    void SetDataCallback(DataCallback cb) override;
    void SetClosedCallback(ClosedCallback cb) override;

    // ---- Shard-facing methods (non-virtual) ----

    /**
     * Offer remote data to the stack. WouldBlock retains the lease until a
     * later ResumeReceive() retry; callers must not submit another lease while
     * the session is paused.
     */
    ReceiveStatus OnDataReceived(BufferLease lease);

    /// Notify the application that the session can accept more data.
    void OnWritable();

    /// Notify the application that the session has been closed.
    void OnClosed(SessionError error);

    /// Pull pending send data into @p out (up to @p max bytes).
    /// Returns the number of bytes copied.  Clears those bytes from the queue.
    std::size_t DrainSendQueue(std::uint8_t *out, std::size_t max) noexcept;

    /// True when ShutdownWrite() has been called.
    bool CloseRequested() const noexcept;

    /// Bytes currently buffered in the send queue.
    std::size_t SendQueueBytes() const noexcept;

    /// True when the session can accept more data (not closed, not full).
    bool IsWritable() const noexcept;

    /// True when the session is closed (Abort or OnClosed was called).
    bool IsClosed() const noexcept;

  private:
    mutable std::mutex mutex_;
    std::vector<std::uint8_t> send_queue_;
    std::size_t send_queue_limit_;
    bool write_shutdown_ = false;
    bool closed_ = false;
    SessionError close_error_ = SessionError::None;

    WritableCallback writable_callback_;
    DataCallback data_callback_;
    ClosedCallback closed_callback_;
    BufferLease pending_receive_;
    std::condition_variable callback_cv_;
    std::size_t callbacks_in_flight_ = 0;

    void CallbackFinished() noexcept;
};

} // namespace tcpip2
