/**
 * @file buffer_pool.cpp
 * @brief PktBufferPool implementation.
 * @license GPL-3.0
 *
 * Fixed-size pool with internally synchronized allocation/release. Slot
 * states are tracked so double release and invalid transitions abort
 * (death-tested). Release may occur on any thread; the buffer is routed back
 * to the pool that owns it. Buffers returned on a foreign thread are parked
 * in an owner return queue (still counted as outstanding) and freed by
 * DrainReturnQueue() on the owner thread; Allocate() drains lazily when the
 * free list runs empty.
 */

#include <tcpip2/buffer.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <new>
#include <thread>
#include <vector>

namespace tcpip2 {

namespace {
[[noreturn]] void Die(const char *what) noexcept {
    std::fprintf(stderr, "tcpip2: buffer ownership violation: %s\n", what);
    std::abort();
}
} // namespace

PktBufferPool::PktBufferPool(std::size_t slot_count, std::size_t slot_capacity)
    : slot_count_(slot_count), slots_(slot_count), states_(slot_count, SlotState::Free), arena_(nullptr),
      owner_thread_id_(std::this_thread::get_id()) {
    // Guard against slot_count * slot_capacity overflow. PktBufferPool is a
    // public type constructible independently of NetstackConfig::Validate(),
    // so the constructor must validate its own arithmetic. On overflow or
    // allocation failure, degrade to 0 usable slots (Allocate() returns empty).
    const std::uint64_t slot_count_u = slot_count;
    const std::uint64_t slot_cap_u = slot_capacity;
    if (slot_count_u != 0 && slot_cap_u > UINT64_MAX / slot_count_u) {
        free_head_.store(slot_count, std::memory_order_relaxed); // empty free list
        return;                                                  // arithmetic overflow — degrade to 0 usable slots
    }
    const std::uint64_t total_bytes_u = slot_count_u * slot_cap_u;
    if (total_bytes_u > static_cast<std::uint64_t>(SIZE_MAX)) {
        free_head_.store(slot_count, std::memory_order_relaxed); // empty free list
        return;                                                  // exceeds address space — degrade to 0 usable slots
    }
    arena_.reset(new (std::nothrow) std::uint8_t[total_bytes_u]);
    if (arena_ == nullptr) {
        // Arena allocation failed: degrade to 0 usable slots.
        // slots_ and states_ exist but no buffer has valid data_.
        // The free list stays empty, so Allocate() always returns empty.
        free_head_.store(slot_count, std::memory_order_relaxed); // empty free list
        return;
    }
    free_next_.resize(slot_count + 1, 0);
    for (std::size_t i = 0; i < slot_count; ++i) {
        PktBuffer &b = slots_[i];
        b.pool_ = this;
        b.slot_ = i;
        b.capacity_ = slot_capacity;
        b.data_ = arena_.get() + i * slot_capacity;
        free_next_[i] = static_cast<std::uint32_t>(i + 1);
    }
    // Sentinel slot_count_ terminates the LIFO; the stack starts at slot 0.
    free_next_[slot_count] = static_cast<std::uint32_t>(slot_count);
    free_head_.store(0, std::memory_order_relaxed);
    free_count_.store(slot_count, std::memory_order_relaxed);
}

PktBufferPool::~PktBufferPool() = default;

std::size_t PktBufferPool::PopFree() noexcept {
    std::uint64_t head = free_head_.load(std::memory_order_acquire);
    for (;;) {
        const std::uint32_t idx = static_cast<std::uint32_t>(head & 0xFFFFFFFFu);
        if (idx >= slot_count_)
            return slot_count_; // empty
        const std::uint32_t next = free_next_[idx];
        const std::uint64_t new_head = (((head >> 32) + 1) << 32) | static_cast<std::uint64_t>(next);
        if (free_head_.compare_exchange_weak(head, new_head, std::memory_order_acq_rel, std::memory_order_relaxed)) {
            free_count_.fetch_sub(1, std::memory_order_relaxed);
            return idx;
        }
    }
}

void PktBufferPool::PushFree(std::size_t idx) noexcept {
    std::uint64_t head = free_head_.load(std::memory_order_relaxed);
    for (;;) {
        free_next_[idx] = static_cast<std::uint32_t>(head & 0xFFFFFFFFu);
        const std::uint64_t new_head = (((head >> 32) + 1) << 32) | static_cast<std::uint64_t>(idx);
        if (free_head_.compare_exchange_weak(head, new_head, std::memory_order_acq_rel, std::memory_order_relaxed)) {
            free_count_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
}

BufferLease PktBufferPool::Allocate() {
    std::size_t idx = PopFree();
    if (idx == slot_count_) {
        // Free list empty — recycle foreign-thread returns before giving up.
        std::lock_guard<std::mutex> lock(mutex_);
        DrainLocked();
        idx = PopFree();
        if (idx == slot_count_)
            return {};
    }
    if (states_[idx] != SlotState::Free)
        Die("allocate on non-free slot");
    states_[idx] = SlotState::Leased;
    outstanding_.fetch_add(1, std::memory_order_relaxed);
    PktBuffer &b = slots_[idx];
    b.size_ = 0;
    return BufferLease(&b);
}

BufferRef PktBufferPool::Retain(BufferLease &&lease) {
    PktBuffer *p = lease.Get();
    if (p == nullptr)
        return {};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t idx = p->slot_;
        if (states_[idx] != SlotState::Leased)
            Die("retain on non-leased slot");
        states_[idx] = SlotState::Retained;
        retained_.fetch_add(1, std::memory_order_relaxed);
        p->ref_count_ = 1;
    }
    lease.pkt_ = nullptr;
    return BufferRef(p);
}

void PktBufferPool::ReleaseRetained(PktBuffer *pkt) {
    if (pkt == nullptr)
        return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pkt->pool_ != this)
        Die("buffer returned to wrong pool");
    const std::size_t idx = pkt->slot_;
    if (&slots_[idx] != pkt)
        Die("buffer pointer/slot mismatch");
    if (states_[idx] != SlotState::Retained)
        Die("release on non-retained slot");
    retained_.fetch_sub(1, std::memory_order_relaxed);
    if (std::this_thread::get_id() == owner_thread_id_) {
        states_[idx] = SlotState::Free;
        pkt->size_ = 0;
        outstanding_.fetch_sub(1, std::memory_order_relaxed);
        PushFree(idx);
    } else {
        states_[idx] = SlotState::Queued;
        return_queue_.push_back(idx);
    }
}

void PktBufferPool::ReturnBuffer(PktBuffer *pkt) {
    if (pkt == nullptr)
        return;
    if (pkt->pool_ != this)
        Die("buffer returned to wrong pool");
    const std::size_t idx = pkt->slot_;
    if (&slots_[idx] != pkt)
        Die("buffer pointer/slot mismatch");
    if (std::this_thread::get_id() == owner_thread_id_) {
        // Owner-thread fast path: lock-free LIFO push.
        if (states_[idx] != SlotState::Leased)
            Die("double release / invalid return");
        states_[idx] = SlotState::Free;
        pkt->size_ = 0;
        outstanding_.fetch_sub(1, std::memory_order_relaxed);
        PushFree(idx);
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        if (states_[idx] != SlotState::Leased)
            Die("double release / invalid return");
        states_[idx] = SlotState::Queued;
        return_queue_.push_back(idx);
    }
}

void PktBufferPool::DrainLocked() noexcept {
    while (!return_queue_.empty()) {
        const std::size_t idx = return_queue_.front();
        return_queue_.pop_front();
        if (states_[idx] != SlotState::Queued)
            Die("drain on non-queued slot");
        states_[idx] = SlotState::Free;
        slots_[idx].size_ = 0;
        outstanding_.fetch_sub(1, std::memory_order_relaxed);
        PushFree(idx);
    }
}

std::size_t PktBufferPool::DrainReturnQueue() {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t drained = return_queue_.size();
    DrainLocked();
    return drained;
}

std::size_t PktBufferPool::ReturnQueueSize() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return return_queue_.size();
}

BufferLease::~BufferLease() { Release(); }

BufferLease &BufferLease::operator=(BufferLease &&other) noexcept {
    if (this != &other) {
        Release();
        pkt_ = other.pkt_;
        other.pkt_ = nullptr;
    }
    return *this;
}

void BufferLease::Release() noexcept {
    PktBuffer *p = pkt_;
    pkt_ = nullptr;
    if (p != nullptr)
        p->pool_->ReturnBuffer(p);
}

BufferRef::~BufferRef() { Release(); }

BufferRef &BufferRef::operator=(const BufferRef &other) noexcept {
    if (this != &other) {
        Release();
        pkt_ = other.pkt_;
        if (pkt_)
            ++pkt_->ref_count_;
    }
    return *this;
}

BufferRef &BufferRef::operator=(BufferRef &&other) noexcept {
    if (this != &other) {
        Release();
        pkt_ = other.pkt_;
        other.pkt_ = nullptr;
    }
    return *this;
}

void BufferRef::Reset() noexcept { Release(); }

void BufferRef::Release() noexcept {
    PktBuffer *p = pkt_;
    pkt_ = nullptr;
    if (p != nullptr) {
        if (--p->ref_count_ == 0) {
            p->pool_->ReleaseRetained(p);
        }
    }
}

std::size_t PktBufferPool::SlotCount() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return slot_count_;
}

std::size_t PktBufferPool::FreeCount() const noexcept { return free_count_.load(std::memory_order_relaxed); }

std::size_t PktBufferPool::OutstandingCount() const noexcept { return outstanding_.load(std::memory_order_relaxed); }

std::size_t PktBufferPool::RetainedCount() const noexcept { return retained_.load(std::memory_order_relaxed); }

} // namespace tcpip2
