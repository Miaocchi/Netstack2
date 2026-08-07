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
      arena_(nullptr),
      owner_thread_id_(std::this_thread::get_id()) {
    // Guard against slot_count * slot_capacity overflow. PktBufferPool is a
    // public type constructible independently of NetstackConfig::Validate(),
    // so the constructor must validate its own arithmetic. On overflow or
    // allocation failure, degrade to 0 usable slots (Allocate() returns empty).
    const std::uint64_t slot_count_u = slot_count;
    const std::uint64_t slot_cap_u = slot_capacity;
    if (slot_count_u != 0 && slot_cap_u > UINT64_MAX / slot_count_u) {
        return; // arithmetic overflow — degrade to 0 usable slots
    }
    const std::uint64_t total_bytes_u = slot_count_u * slot_cap_u;
    if (total_bytes_u > static_cast<std::uint64_t>(SIZE_MAX)) {
        return; // exceeds address space — degrade to 0 usable slots
    }
    arena_.reset(new (std::nothrow) std::uint8_t[total_bytes_u]);
    if (arena_ == nullptr) {
        // Arena allocation failed: degrade to 0 usable slots.
        // slots_ and states_ exist but no buffer has valid data_.
        // free_slots_ remains empty, so Allocate() always returns empty.
        return;
    }
    free_slots_.reserve(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i) {
        PktBuffer& b = slots_[i];
        b.pool_ = this;
        b.slot_ = i;
        b.capacity_ = slot_capacity;
        b.data_ = arena_.get() + i * slot_capacity;
        free_slots_.push_back(i);
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
        p->ref_count_ = 1;
    }
    lease.pkt_ = nullptr;
    return BufferRef(p);
}

void PktBufferPool::ReleaseRetained(PktBuffer* pkt) {
    if (pkt == nullptr) return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pkt->pool_ != this) Die("buffer returned to wrong pool");
    const std::size_t idx = pkt->slot_;
    if (&slots_[idx] != pkt) Die("buffer pointer/slot mismatch");
    if (states_[idx] != SlotState::Retained) Die("release on non-retained slot");
    --retained_;
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

void PktBufferPool::ReturnBuffer(PktBuffer* pkt) {
    if (pkt == nullptr) return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pkt->pool_ != this) Die("buffer returned to wrong pool");
    const std::size_t idx = pkt->slot_;
    if (&slots_[idx] != pkt) Die("buffer pointer/slot mismatch");
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

BufferRef::~BufferRef() { Release(); }

BufferRef& BufferRef::operator=(const BufferRef& other) noexcept {
    if (this != &other) {
        Release();
        pkt_ = other.pkt_;
        if (pkt_) ++pkt_->ref_count_;
    }
    return *this;
}

BufferRef& BufferRef::operator=(BufferRef&& other) noexcept {
    if (this != &other) {
        Release();
        pkt_ = other.pkt_;
        other.pkt_ = nullptr;
    }
    return *this;
}

void BufferRef::Reset() noexcept { Release(); }

void BufferRef::Release() noexcept {
    PktBuffer* p = pkt_;
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
