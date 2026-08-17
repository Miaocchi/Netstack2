#pragma once

/**
 * @file inbox_spsc.h
 * @brief Bounded lock-free SPSC ring buffer for packet inboxes.
 * @license GPL-3.0
 *
 * Single-producer single-consumer queue backed by a power-of-two ring.
 * The producer (a dispatch path or another shard) writes via Push(); the
 * consumer (the owning shard thread) drains via Pop(). Capacity is rounded
 * up to the next power of two so the index can be masked instead of modulo.
 *
 * head_ is written by the producer and read by the consumer (acquire/release).
 * tail_ is written by the consumer and read by the producer.
 * Push() returns false when the ring is full so the caller can drop the
 * packet (and account it).
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <utility>

#include <tcpip2/buffer.h>

namespace tcpip2 {

template <typename T> class SpscRing {
  public:
    explicit SpscRing(std::size_t capacity) noexcept
        : mask_(NextPow2Mask(capacity)),
          slots_(static_cast<T *>(::operator new((mask_ + 1) * sizeof(T), std::nothrow))), head_(0), tail_(0) {
        if (slots_ == nullptr) {
            // Allocation failure: degrade to 0 usable capacity.
            mask_ = 0;
            slots_ = nullptr;
            return;
        }
        // Construct empty leases in every slot (all are default-constructed
        // null leases; they will be move-assigned on Push).
        for (std::size_t i = 0; i <= mask_; ++i) {
            ::new (slots_ + i) T();
        }
    }

    ~SpscRing() {
        if (slots_ != nullptr) {
            for (std::size_t i = 0; i <= mask_; ++i) {
                slots_[i].~T();
            }
            ::operator delete(slots_);
        }
    }

    bool Push(T &&item) noexcept {
        if (slots_ == nullptr)
            return false;
        const std::size_t head = head_.load(std::memory_order_relaxed);
        const std::size_t tail = tail_.load(std::memory_order_acquire);
        if (head - tail > mask_)
            return false; // full
        slots_[head & mask_] = std::move(item);
        head_.store(head + 1, std::memory_order_release);
        return true;
    }

    bool Pop(T &out) noexcept {
        if (slots_ == nullptr)
            return false;
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        const std::size_t head = head_.load(std::memory_order_acquire);
        if (tail == head)
            return false; // empty
        out = std::move(slots_[tail & mask_]);
        tail_.store(tail + 1, std::memory_order_release);
        return true;
    }

    std::size_t Capacity() const noexcept { return slots_ ? mask_ + 1 : 0; }

    std::size_t Size() const noexcept {
        const std::size_t head = head_.load(std::memory_order_relaxed);
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        return head - tail;
    }

    bool Empty() const noexcept {
        const std::size_t head = head_.load(std::memory_order_relaxed);
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        return head == tail;
    }

    SpscRing(const SpscRing &) = delete;
    SpscRing &operator=(const SpscRing &) = delete;

  private:
    static std::size_t NextPow2Mask(std::size_t capacity) noexcept {
        if (capacity == 0)
            return 0;
        --capacity;
        capacity |= capacity >> 1;
        capacity |= capacity >> 2;
        capacity |= capacity >> 4;
        capacity |= capacity >> 8;
        capacity |= capacity >> 16;
        capacity |= capacity >> 32;
        return capacity;
    }

    std::size_t mask_;
    T *slots_;
    std::atomic<std::size_t> head_{0}; // producer writes
    std::atomic<std::size_t> tail_{0}; // consumer writes
};

using InboxSpsc = SpscRing<BufferLease>;

} // namespace tcpip2
