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
[[noreturn]] void Die(const char* what) noexcept {
    std::fprintf(stderr, "tcpip2: buffer ownership violation: %s\n", what);
    std::abort();
}
} // namespace

PktBufferPool::PktBufferPool(std::size_t slot_count, std::size_t slot_capacity)
    : slot_count_(slot_count),
      slots_(slot_count),
      states_(slot_count, SlotState::Free),
      arena_(new (std::nothrow) std::uint8_t[slot_count * slot_capacity]),
      owner_thread_id_(std::this_thread::get_id()) {
    free_slots_.reserve(slot_count);
    if (arena_ != nullptr) {
        for (std::size_t i = 0; i < slot_count; ++i) {
            PktBuffer& b = slots_[i];
            b.pool_ = this;
            b.slot_ = i;
            b.capacity_ = slot_capacity;
            b.data_ = arena_.get() + i * slot_capacity;
            free_slots_.push_back(i);
        }
    }
}

PktBufferPool::~PktBufferPool() = default;

BufferLease PktBufferPool::Allocate() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (free_slots_.empty() && !return_queue_.empty()) {
        DrainLocked();
    }
    if (free_slots_.empty()) return {};
    const std::size_t idx = free_slots_.back();
    free_slots_.pop_back();
    if (states_[idx] != SlotState::Free) Die("allocate on non-free slot");
    states_[idx] = SlotState::Leased;
    ++outstanding_;
    PktBuffer& b = slots_[idx];
    b.size_ = 0;
    return BufferLease(&b);
}

BufferRef PktBufferPool::Retain(BufferLease&& lease) {
    PktBuffer* p = lease.Get();
    if (p == nullptr) return {};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t idx = p->slot_;
        if (states_[idx] != SlotState::Leased) Die("retain on non-leased slot");
        states_[idx] = SlotState::Retained;
        ++retained_;
    }
    lease.pkt_ = nullptr;
    return BufferRef(p);
}

void PktBufferPool::Unpin(BufferRef ref) {
    PktBuffer* p = ref.Get();
    if (p == nullptr) return;
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t idx = p->slot_;
    if (states_[idx] != SlotState::Retained) Die("unpin on non-retained slot");
    --retained_;
    if (std::this_thread::get_id() == owner_thread_id_) {
        states_[idx] = SlotState::Free;
        p->size_ = 0;
        --outstanding_;
        free_slots_.push_back(idx);
    } else {
        states_[idx] = SlotState::Queued;
        return_queue_.push_back(idx);
    }
}

void PktBufferPool::ReturnBuffer(PktBuffer* pkt) {
    if (pkt == nullptr) return;
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t idx = pkt->slot_;
    if (states_[idx] != SlotState::Leased) Die("double release / invalid return");
    if (std::this_thread::get_id() == owner_thread_id_) {
        states_[idx] = SlotState::Free;
        pkt->size_ = 0;
        --outstanding_;
        free_slots_.push_back(idx);
    } else {
        states_[idx] = SlotState::Queued;
        return_queue_.push_back(idx);
    }
}

void PktBufferPool::DrainLocked() noexcept {
    while (!return_queue_.empty()) {
        const std::size_t idx = return_queue_.front();
        return_queue_.pop_front();
        if (states_[idx] != SlotState::Queued) Die("drain on non-queued slot");
        states_[idx] = SlotState::Free;
        slots_[idx].size_ = 0;
        --outstanding_;
        free_slots_.push_back(idx);
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

BufferLease& BufferLease::operator=(BufferLease&& other) noexcept {
    if (this != &other) {
        Release();
        pkt_ = other.pkt_;
        other.pkt_ = nullptr;
    }
    return *this;
}

void BufferLease::Release() noexcept {
    PktBuffer* p = pkt_;
    pkt_ = nullptr;
    if (p != nullptr) p->pool_->ReturnBuffer(p);
}

std::size_t PktBufferPool::SlotCount() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return slot_count_;
}

std::size_t PktBufferPool::FreeCount() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return free_slots_.size();
}

std::size_t PktBufferPool::OutstandingCount() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return outstanding_;
}

std::size_t PktBufferPool::RetainedCount() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return retained_;
}

} // namespace tcpip2
