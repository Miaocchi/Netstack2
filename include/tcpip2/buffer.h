#pragma once

/**
 * @file buffer.h
 * @brief Buffer ownership model for the Netstack2 packet path.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * Ownership taxonomy (see docs/architecture/ownership.md):
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
 *                Multiple BufferRef copies are allowed; the buffer is returned
 *                to the pool when the last copy is destroyed or reset.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

    std::uint8_t *Data() noexcept { return data_; }
    const std::uint8_t *Data() const noexcept { return data_; }
    std::size_t Capacity() const noexcept { return capacity_; }
    std::size_t Size() const noexcept { return size_; }
    void Resize(std::size_t n) noexcept {
        if (n > capacity_) {
            std::fprintf(stderr, "tcpip2: resize exceeds capacity (%zu > %zu)\n", n, capacity_);
            std::abort();
        }
        size_ = n;
    }

  private:
    friend class PktBufferPool;
    friend class BufferLease;
    friend class BufferRef;

    PktBufferPool *pool_ = nullptr;
    std::uint8_t *data_ = nullptr;
    std::size_t capacity_ = 0;
    std::size_t size_ = 0;
    std::size_t slot_ = 0;
    std::uint32_t ref_count_ = 0;
};

/**
 * Unique ownership of a pooled packet buffer. Move-only. Releasing routes
 * the buffer back to the pool that created it.
 */
class BufferLease final {
  public:
    BufferLease() noexcept = default;
    ~BufferLease();

    BufferLease(BufferLease &&other) noexcept : pkt_(other.pkt_) { other.pkt_ = nullptr; }
    BufferLease &operator=(BufferLease &&other) noexcept;
    BufferLease(const BufferLease &) = delete;
    BufferLease &operator=(const BufferLease &) = delete;

    explicit operator bool() const noexcept { return pkt_ != nullptr; }
    PktBuffer *Get() const noexcept { return pkt_; }

    std::uint8_t *Data() noexcept { return pkt_ ? pkt_->Data() : nullptr; }
    const std::uint8_t *Data() const noexcept { return pkt_ ? pkt_->Data() : nullptr; }
    std::size_t Size() const noexcept { return pkt_ ? pkt_->Size() : 0; }
    std::size_t Capacity() const noexcept { return pkt_ ? pkt_->Capacity() : 0; }
    void Resize(std::size_t n) noexcept {
        if (pkt_)
            pkt_->Resize(n);
    }

    /** Return the buffer to its pool immediately (no-op if already released). */
    void Reset() noexcept { Release(); }

  private:
    friend class PktBufferPool;
    explicit BufferLease(PktBuffer *pkt) noexcept : pkt_(pkt) {}

    void Release() noexcept;

    PktBuffer *pkt_ = nullptr;
};

/**
 * Non-owning, trivially copyable read-only view of packet payload.
 * Must not outlive the lease/ref it was taken from.
 */
class BufferSlice final {
  public:
    BufferSlice() noexcept = default;
    BufferSlice(const std::uint8_t *data, std::size_t size) noexcept : data_(data), size_(size) {}

    const std::uint8_t *Data() const noexcept { return data_; }
    std::size_t Size() const noexcept { return size_; }
    bool Empty() const noexcept { return size_ == 0; }

    BufferSlice Subslice(std::size_t offset, std::size_t length) const noexcept {
        if (offset > size_)
            return {};
        const std::size_t take = (length > size_ - offset) ? (size_ - offset) : length;
        return BufferSlice(data_ + offset, take);
    }

  private:
    const std::uint8_t *data_ = nullptr;
    std::size_t size_ = 0;
};

/**
 * Shard-local retained handle to a pool buffer. Copies are allowed; the
 * underlying buffer is returned to the pool when the last BufferRef is
 * destroyed or reset (non-atomic retain count, shard-local).
 */
class BufferRef final {
  public:
    BufferRef() noexcept = default;
    ~BufferRef();

    BufferRef(const BufferRef &other) noexcept : pkt_(other.pkt_) {
        if (pkt_)
            ++pkt_->ref_count_;
    }
    BufferRef &operator=(const BufferRef &other) noexcept;
    BufferRef(BufferRef &&other) noexcept : pkt_(other.pkt_) { other.pkt_ = nullptr; }
    BufferRef &operator=(BufferRef &&other) noexcept;

    PktBuffer *Get() const noexcept { return pkt_; }
    const std::uint8_t *Data() const noexcept { return pkt_ ? pkt_->Data() : nullptr; }
    std::size_t Size() const noexcept { return pkt_ ? pkt_->Size() : 0; }
    explicit operator bool() const noexcept { return pkt_ != nullptr; }

    /** Release this reference. If it was the last reference, return the buffer to its pool. */
    void Reset() noexcept;

  private:
    friend class PktBufferPool;
    explicit BufferRef(PktBuffer *pkt) noexcept : pkt_(pkt) {}

    void Release() noexcept;

    PktBuffer *pkt_ = nullptr;
};

/** Metadata for one TCP segment held in the retransmission queue. */
struct TxSegment {
    std::uint32_t seq = 0;
    std::uint32_t len = 0;
    BufferRef owner;
    BufferSlice data;
};

/**
 * Fixed-size pool of packet buffers. Allocate()/ReturnBuffer()/Retain() are
 * internally synchronized, so release may happen on any thread and is routed
 * back to the owning pool.
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

    PktBufferPool(const PktBufferPool &) = delete;
    PktBufferPool &operator=(const PktBufferPool &) = delete;

    /** Allocate a lease, or an empty lease if the pool is exhausted. */
    BufferLease Allocate();

    /**
     * Move a leased buffer into the retained state (flow ownership).
     * Consumes @p lease; the returned BufferRef keeps the payload alive.
     */
    BufferRef Retain(BufferLease &&lease);

    /**
     * Internal: return a buffer to the free list. Used by BufferLease;
     * calling directly is a contract violation and the second return of the
     * same buffer aborts (double-release detection).
     */
    void ReturnBuffer(PktBuffer *pkt);

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

    /**
     * Reassign the owner thread to @p id. Called once from the shard's Run()
     * before the first allocation so that Allocate()/ReturnBuffer() take the
     * owner-local uncontended fast path on the shard thread: the mutex is
     * still acquired, but only the owner shard thread contends for it on the
     * hot path (per-shard pool model, ADR-001). Safe to call before the pool
     * is in use; racing with an in-flight Allocate()/ReturnBuffer() is a
     * contract violation.
     */
    void SetOwnerThread(std::thread::id id) noexcept { owner_thread_id_ = id; }

  private:
    enum class SlotState : std::uint8_t { Free, Leased, Retained, Queued };

    friend class BufferRef;

    void DrainLocked() noexcept;

    /** Lock-free LIFO pop of a free slot index; returns slot_count_ when empty. */
    std::size_t PopFree() noexcept;

    /** Lock-free LIFO push of a freed slot index. */
    void PushFree(std::size_t idx) noexcept;

    /** Return a retained buffer to the pool (called by BufferRef on last reference). */
    void ReleaseRetained(PktBuffer *pkt);

    std::size_t slot_count_;
    std::vector<PktBuffer> slots_;
    std::vector<SlotState> states_;
    // Lock-free free list: free_head_ packs (tag << 32 | next index); the
    // sentinel index == slot_count_ marks an empty stack. free_next_[i] is
    // the successor of slot i while i is on the stack. Tagged 64-bit CAS
    // defeats ABA on the index reuse.
    std::vector<std::uint32_t> free_next_;
    std::atomic<std::uint64_t> free_head_{0};
    std::atomic<std::size_t> free_count_{0}; // number of slots on the free list
    std::deque<std::size_t> return_queue_;
    std::unique_ptr<std::uint8_t[]> arena_;
    // Isolated on its own cache line: the shard thread takes this mutex on
    // every iteration (DrainReturnQueue) while producers hammer free_head_;
    // sharing a line would bounce the free-list CAS on every shard wakeup.
    alignas(64) mutable std::mutex mutex_; // return_queue_ + retained bookkeeping only
    std::thread::id owner_thread_id_;
    std::atomic<std::size_t> outstanding_{0};
    std::atomic<std::size_t> retained_{0};
};

} // namespace tcpip2
