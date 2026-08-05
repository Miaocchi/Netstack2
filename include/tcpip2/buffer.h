#pragma once

/**
 * @file buffer.h
 * @brief Buffer ownership model for the Netstack2 packet path.
 * @license GPL-3.0
 *
 * Experimental API (NETSTACK2-000). Ownership is validated by
 * NETSTACK2-002; signatures may change until NETSTACK2-API-FREEZE-001.
 *
 * Ownership taxonomy (see docs/architecture/ownership.adr):
 *
 *   PktBuffer    pool-internal object. No public ownership operations, no
 *                atomic reference count, fixed standard layout.
 *
 *   BufferLease  unique ownership. Move-only; may be moved across threads,
 *                but release always routes back to the owning pool. When a
 *                lease is destroyed the buffer returns to the pool. Releases
 *                on a foreign thread park the buffer in the pool's owner
 *                return queue until the owner thread drains it.
 *
 *   BufferSlice  non-owning, trivially copyable read-only view. Lifetime
 *                must not exceed the lease/ref it was derived from.
 *
 *   BufferRef    shard-local retained handle. Used only where a payload must
 *                outlive its originating lease (retransmission, reassembly).
 *                Multiple BufferRef copies are allowed; the retaining flow
 *                owns the buffer and must Unpin() it exactly once.
 */

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace tcpip2 {

class PktBufferPool;
class BufferLease;
class BufferRef;

/**
 * Pool-internal buffer object. Not owning, not thread-safe by itself;
 * all transitions are performed by PktBufferPool under its lock.
 * No atomic reference count by design.
 */
class PktBuffer final {
public:
    PktBuffer() noexcept = default;

    std::uint8_t* Data() noexcept { return data_; }
    const std::uint8_t* Data() const noexcept { return data_; }
    std::size_t Capacity() const noexcept { return capacity_; }
    std::size_t Size() const noexcept { return size_; }
    void Resize(std::size_t n) noexcept { size_ = n; }

private:
    friend class PktBufferPool;
    friend class BufferLease;
    friend class BufferRef;

    PktBufferPool* pool_ = nullptr;
    std::uint8_t* data_ = nullptr;
    std::size_t capacity_ = 0;
    std::size_t size_ = 0;
    std::size_t slot_ = 0;
};

/**
 * Unique ownership of a pooled packet buffer. Move-only. Releasing routes
 * the buffer back to the pool that created it.
 */
class BufferLease final {
public:
    BufferLease() noexcept = default;
    ~BufferLease();

    BufferLease(BufferLease&& other) noexcept : pkt_(other.pkt_) { other.pkt_ = nullptr; }
    BufferLease& operator=(BufferLease&& other) noexcept;
    BufferLease(const BufferLease&) = delete;
    BufferLease& operator=(const BufferLease&) = delete;

    explicit operator bool() const noexcept { return pkt_ != nullptr; }
    PktBuffer* Get() const noexcept { return pkt_; }

    std::uint8_t* Data() noexcept { return pkt_ ? pkt_->Data() : nullptr; }
    const std::uint8_t* Data() const noexcept { return pkt_ ? pkt_->Data() : nullptr; }
    std::size_t Size() const noexcept { return pkt_ ? pkt_->Size() : 0; }
    std::size_t Capacity() const noexcept { return pkt_ ? pkt_->Capacity() : 0; }
    void Resize(std::size_t n) noexcept {
        if (pkt_) pkt_->Resize(n);
    }

    /** Return the buffer to its pool immediately (no-op if already released). */
    void Reset() noexcept { Release(); }

private:
    friend class PktBufferPool;
    explicit BufferLease(PktBuffer* pkt) noexcept : pkt_(pkt) {}

    void Release() noexcept;

    PktBuffer* pkt_ = nullptr;
};

/**
 * Non-owning, trivially copyable read-only view of packet payload.
 * Must not outlive the lease/ref it was taken from.
 */
class BufferSlice final {
public:
    BufferSlice() noexcept = default;
    BufferSlice(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

    const std::uint8_t* Data() const noexcept { return data_; }
    std::size_t Size() const noexcept { return size_; }
    bool Empty() const noexcept { return size_ == 0; }

    BufferSlice Subslice(std::size_t offset, std::size_t length) const noexcept {
        if (offset > size_) return {};
        const std::size_t take = (length > size_ - offset) ? (size_ - offset) : length;
        return BufferSlice(data_ + offset, take);
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

/**
 * Shard-local retained handle to a pool buffer. Copies are allowed; the
 * retaining flow owns the underlying buffer and releases it via Unpin().
 */
class BufferRef final {
public:
    BufferRef() noexcept = default;

    PktBuffer* Get() const noexcept { return pkt_; }
    const std::uint8_t* Data() const noexcept { return pkt_ ? pkt_->Data() : nullptr; }
    std::size_t Size() const noexcept { return pkt_ ? pkt_->Size() : 0; }
    explicit operator bool() const noexcept { return pkt_ != nullptr; }

private:
    friend class PktBufferPool;
    explicit BufferRef(PktBuffer* pkt) noexcept : pkt_(pkt) {}

    PktBuffer* pkt_ = nullptr;
};

/** Metadata for one TCP segment held in the retransmission queue. */
struct TxSegment {
    std::uint32_t seq = 0;
    std::uint32_t len = 0;
    BufferRef owner;
    BufferSlice data;
};

/**
 * Fixed-size pool of packet buffers. Allocate()/ReturnBuffer()/Retain()/
 * Unpin() are internally synchronized, so release may happen on any thread
 * and is routed back to the owning pool.
 *
 * The pool records the owner thread id at construction. Buffers returned on
 * the owner thread take the fast path straight back to the free list;
 * buffers returned on any other thread are parked in an owner return queue
 * (SlotState::Queued, still counted as outstanding) and only become free
 * after DrainReturnQueue(). Allocate() lazily drains the queue when the free
 * list is empty.
 *
 * The pool tracks slot states and aborts (death test) on double release or
 * invalid transitions; use OutstandingCount()/FreeCount()/ReturnQueueSize()
 * to assert against leaks in tests.
 */
class PktBufferPool final {
public:
    PktBufferPool(std::size_t slot_count, std::size_t slot_capacity);
    ~PktBufferPool();

    PktBufferPool(const PktBufferPool&) = delete;
    PktBufferPool& operator=(const PktBufferPool&) = delete;

    /** Allocate a lease, or an empty lease if the pool is exhausted. */
    BufferLease Allocate();

    /**
     * Move a leased buffer into the retained state (flow ownership).
     * Consumes @p lease; the returned BufferRef keeps the payload alive.
     */
    BufferRef Retain(BufferLease&& lease);

    /** Release a retained buffer back to the pool. Must be called exactly once. */
    void Unpin(BufferRef ref);

    /**
     * Internal: return a buffer to the free list. Used by BufferLease;
     * calling directly is a contract violation and the second return of the
     * same buffer aborts (double-release detection).
     */
    void ReturnBuffer(PktBuffer* pkt);

    /**
     * Move buffers parked by foreign-thread releases onto the free list.
     * Returns the number of buffers freed. No-op when nothing is queued.
     */
    std::size_t DrainReturnQueue();

    /** Number of buffers awaiting DrainReturnQueue() (for test assertions). */
    std::size_t ReturnQueueSize() const noexcept;

    std::size_t SlotCount() const noexcept;
    std::size_t FreeCount() const noexcept;
    /** Buffers currently leased, retained, or queued (not available for allocation). */
    std::size_t OutstandingCount() const noexcept;
    std::size_t RetainedCount() const noexcept;

private:
    enum class SlotState : std::uint8_t { Free, Leased, Retained, Queued };

    void DrainLocked() noexcept;

    std::size_t slot_count_;
    std::vector<PktBuffer> slots_;
    std::vector<SlotState> states_;
    std::vector<std::size_t> free_slots_;
    std::deque<std::size_t> return_queue_;
    std::unique_ptr<std::uint8_t[]> arena_;
    mutable std::mutex mutex_;
    std::thread::id owner_thread_id_;
    std::size_t outstanding_ = 0;
    std::size_t retained_ = 0;
};

} // namespace tcpip2
