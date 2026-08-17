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

TcpSession::TcpSession(std::size_t send_queue_limit) : send_queue_limit_(send_queue_limit) {
    send_queue_.reserve(4096);
}

SendResult TcpSession::TrySend(BufferView data) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (closed_ || write_shutdown_) {
        return {0, SendStatus::Closed};
    }

    const std::size_t available =
        (send_queue_.size() >= send_queue_limit_) ? 0 : (send_queue_limit_ - send_queue_.size());

    if (available == 0) {
        return {0, SendStatus::WouldBlock};
    }

    const std::size_t to_copy = std::min(available, data.Size());
    if (to_copy > 0) {
        send_queue_.insert(send_queue_.end(), data.Data(), data.Data() + to_copy);
    }
    return {to_copy, SendStatus::Accepted};
}

void TcpSession::ResumeReceive() {
    BufferLease pending;
    DataCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || !pending_receive_ || !data_callback_)
            return;
        pending = std::move(pending_receive_);
        cb = data_callback_;
        ++callbacks_in_flight_;
    }

    ReceiveStatus status = ReceiveStatus::Closed;
    try {
        status = cb(pending);
    } catch (...) {
        status = ReceiveStatus::Closed;
    }

    if (status == ReceiveStatus::WouldBlock && pending) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!closed_ && !pending_receive_) {
            pending_receive_ = std::move(pending);
        }
    }
    CallbackFinished();
}

void TcpSession::ShutdownWrite() {
    WritableCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        write_shutdown_ = true;
        cb = writable_callback_;
        if (cb)
            ++callbacks_in_flight_;
    }

    if (cb) {
        try {
            cb();
        } catch (...) {
            CallbackFinished();
            throw;
        }
        CallbackFinished();
    }
}

void TcpSession::Abort(SessionError error) {
    ClosedCallback cb;
    BufferLease pending;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        close_error_ = error;
        send_queue_.clear();
        pending = std::move(pending_receive_);
        cb = closed_callback_;
        if (cb)
            ++callbacks_in_flight_;
    }

    if (cb) {
        try {
            cb(error);
        } catch (...) {
            CallbackFinished();
            throw;
        }
        CallbackFinished();
    }
}

void TcpSession::SetWritableCallback(WritableCallback cb) {
    WritableCallback immediate;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        writable_callback_ = std::move(cb);
        if (writable_callback_ && !closed_ && !write_shutdown_ && send_queue_.size() < send_queue_limit_) {
            immediate = writable_callback_;
            ++callbacks_in_flight_;
        }
        if (!writable_callback_) {
            callback_cv_.wait(lock, [this] { return callbacks_in_flight_ == 0; });
        }
    }

    if (immediate) {
        try {
            immediate();
        } catch (...) {
            CallbackFinished();
            throw;
        }
        CallbackFinished();
    }
}

void TcpSession::SetDataCallback(DataCallback cb) {
    BufferLease pending;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        data_callback_ = std::move(cb);
        if (!data_callback_) {
            callback_cv_.wait(lock, [this] { return callbacks_in_flight_ == 0; });
            pending = std::move(pending_receive_);
        }
    }
    pending.Reset();
}

void TcpSession::SetClosedCallback(ClosedCallback cb) {
    std::unique_lock<std::mutex> lock(mutex_);
    closed_callback_ = std::move(cb);
    if (!closed_callback_) {
        callback_cv_.wait(lock, [this] { return callbacks_in_flight_ == 0; });
    }
}

ReceiveStatus TcpSession::OnDataReceived(BufferLease lease) {
    DataCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || pending_receive_)
            return ReceiveStatus::Closed;
        cb = data_callback_;
        if (cb)
            ++callbacks_in_flight_;
    }

    if (!cb)
        return ReceiveStatus::Closed;

    ReceiveStatus status = ReceiveStatus::Closed;
    try {
        status = cb(lease);
    } catch (...) {
        status = ReceiveStatus::Closed;
    }

    ReceiveStatus result = ReceiveStatus::Closed;
    if (status == ReceiveStatus::Accepted && !lease) {
        result = ReceiveStatus::Accepted;
    } else if (status == ReceiveStatus::WouldBlock && lease) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!closed_ && !pending_receive_) {
            pending_receive_ = std::move(lease);
            result = ReceiveStatus::WouldBlock;
        }
    }
    CallbackFinished();
    return result;
}

void TcpSession::OnWritable() {
    WritableCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = writable_callback_;
        if (cb)
            ++callbacks_in_flight_;
    }

    if (cb) {
        try {
            cb();
        } catch (...) {
            CallbackFinished();
            throw;
        }
        CallbackFinished();
    }
}

void TcpSession::OnClosed(SessionError error) {
    ClosedCallback cb;
    BufferLease pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        close_error_ = error;
        pending = std::move(pending_receive_);
        cb = closed_callback_;
        if (cb)
            ++callbacks_in_flight_;
    }

    if (cb) {
        try {
            cb(error);
        } catch (...) {
            CallbackFinished();
            throw;
        }
        CallbackFinished();
    }
}

std::size_t TcpSession::DrainSendQueue(std::uint8_t *out, std::size_t max) noexcept {
    WritableCallback cb;
    std::size_t copied = 0;
    bool was_full = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (out == nullptr) {
            return 0;
        }

        was_full = send_queue_.size() >= send_queue_limit_;
        const std::size_t to_copy = std::min(max, send_queue_.size());
        if (to_copy > 0) {
            std::memcpy(out, send_queue_.data(), to_copy);
            send_queue_.erase(send_queue_.begin(), send_queue_.begin() + static_cast<std::ptrdiff_t>(to_copy));
        }
        copied = to_copy;

        if (was_full && send_queue_.size() < send_queue_limit_) {
            cb = writable_callback_;
            if (cb)
                ++callbacks_in_flight_;
        }
    }

    if (cb) {
        try {
            cb();
        } catch (...) {
            CallbackFinished();
            return copied;
        }
        CallbackFinished();
    }

    return copied;
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

void TcpSession::CallbackFinished() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbacks_in_flight_ > 0)
        --callbacks_in_flight_;
    if (callbacks_in_flight_ == 0)
        callback_cv_.notify_all();
}

} // namespace tcpip2
