#pragma once

/**
 * @file inbox_mpsc.h
 * @brief Bounded MPSC queue for shard control messages.
 * @license GPL-3.0
 *
 * Multi-producer single-consumer queue for ShardMessage values. The control
 * inbox is not on the hot packet path (a few hundred messages per loop
 * iteration at most), so a simple mutex + condition variable is used. The
 * key invariant is bounded capacity: Push() returns false when full so
 * callers can apply backpressure instead of unbounded queuing.
 *
 * The consumer (the owning shard thread) can Wait() with a timeout to park
 * when the inbox is empty, and Wake() is available to interrupt the wait.
 */

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <utility>

#include <core/shard_message.h>

namespace tcpip2 {

class InboxMpsc {
public:
    explicit InboxMpsc(std::size_t capacity) noexcept
        : capacity_(capacity) {}

    bool Push(ShardMessage&& msg) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= capacity_) return false;
        queue_.push_back(std::move(msg));
        cv_.notify_one();
        return true;
    }

    bool Pop(ShardMessage& out) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }

    void Wake() noexcept {
        cv_.notify_all();
    }

    bool Wait(std::uint64_t timeout_ms) noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!queue_.empty()) return true;
        cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms));
        return !queue_.empty();
    }

    std::size_t Size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    std::size_t Capacity() const noexcept {
        return capacity_;
    }

private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<ShardMessage> queue_;
};

} // namespace tcpip2
