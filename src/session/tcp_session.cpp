/**
 * @file tcp_session.cpp
 * @brief TcpSession — userspace TCP transport session implementation.
 * @license GPL-3.0
 */

#include "session/tcp_session.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace tcpip2 {

TcpSession::TcpSession(std::size_t send_queue_limit)
    : send_queue_limit_(send_queue_limit) {
    send_queue_.reserve(4096);
}

SendResult TcpSession::TrySend(BufferView data) {
    WritableCallback writable_cb;
    SendResult result{0, SendStatus::Accepted};

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (closed_ || write_shutdown_) {
            return {0, SendStatus::Closed};
        }

        const std::size_t available = (send_queue_.size() >= send_queue_limit_)
            ? 0 : (send_queue_limit_ - send_queue_.size());

        if (available == 0) {
            // Queue is full — capture callback for deferred notification.
            writable_cb = writable_callback_;
            result = {0, SendStatus::WouldBlock};
        } else {
            const std::size_t to_copy = std::min(available, data.Size());
            if (to_copy > 0) {
                send_queue_.insert(send_queue_.end(), data.Data(),
                                   data.Data() + to_copy);
            }
            result = {to_copy, SendStatus::Accepted};

            // If we could not accept everything, notify the writable callback
            // later when the shard drains the queue.
            if (to_copy < data.Size()) {
                writable_cb = writable_callback_;
            }
        }
    }

    // Invoke callback outside the lock to avoid deadlocks.
    if (writable_cb) {
        writable_cb();
    }

    return result;
}

void TcpSession::ShutdownWrite() {
    std::lock_guard<std::mutex> lock(mutex_);
    write_shutdown_ = true;
}

void TcpSession::Abort(SessionError error) {
    ClosedCallback cb;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        close_error_ = error;
        send_queue_.clear();
        cb = closed_callback_;
    }

    if (cb) {
        cb(error);
    }
}

void TcpSession::SetWritableCallback(WritableCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    writable_callback_ = std::move(cb);
}

void TcpSession::SetDataCallback(DataCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    data_callback_ = std::move(cb);
}

void TcpSession::SetClosedCallback(ClosedCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_callback_ = std::move(cb);
}

void TcpSession::OnDataReceived(BufferLease lease) {
    DataCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = data_callback_;
    }

    if (cb) {
        cb(std::move(lease));
    }
}

void TcpSession::OnWritable() {
    WritableCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = writable_callback_;
    }

    if (cb) {
        cb();
    }
}

void TcpSession::OnClosed(SessionError error) {
    ClosedCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        close_error_ = error;
        cb = closed_callback_;
    }

    if (cb) {
        cb(error);
    }
}

std::size_t TcpSession::DrainSendQueue(std::uint8_t* out,
                                        std::size_t max) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);

    if (out == nullptr) {
        return 0;
    }

    const std::size_t to_copy = std::min(max, send_queue_.size());
    if (to_copy > 0) {
        std::memcpy(out, send_queue_.data(), to_copy);
        send_queue_.erase(send_queue_.begin(),
                          send_queue_.begin() + static_cast<std::ptrdiff_t>(to_copy));
    }
    return to_copy;
}

bool TcpSession::CloseRequested() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return write_shutdown_;
}

std::size_t TcpSession::SendQueueBytes() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return send_queue_.size();
}

bool TcpSession::IsWritable() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return !closed_ && !write_shutdown_ && send_queue_.size() < send_queue_limit_;
}

bool TcpSession::IsClosed() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

} // namespace tcpip2
