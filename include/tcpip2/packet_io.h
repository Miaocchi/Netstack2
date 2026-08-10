#pragma once

/**
 * @file packet_io.h
 * @brief Pluggable packet I/O (kernel-bypass backends and virtio-style taps).
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * Each hardware queue is modeled as exactly one IPacketQueue, opened by a
 * single owner thread (RX queue -> owner shard). Polling backends call
 * RecvBatch() repeatedly; event backends wake the owner via SetRecvHandler().
 *
 * Ownership rules (success-prefix transfer; written down, enforced by tests):
 *   * RecvBatch(): a return of n transfers out[0..n-1] to the caller. Any
 *     leases already present in out beyond the returned n are untouched.
 *   * SendBatch(): a return of n transfers packets[0..n-1] to the backend;
 *     the remaining (n..count-1) leases stay with the caller. n < count is a
 *     legal partial send, not an error: the caller keeps the tail and may
 *     resubmit it later. n == count is the full-send success case.
 *   * On error the batch makes no partial transfer: ownership of every lease
 *     stays with the caller (a returned n is always the success prefix).
 *   * Async TX backends return buffers to the owner pool at completion, not
 *     inside SendBatch(); until completion the backend holds the leases.
 *   * count == 0 returns 0 with IoError::None (not an error).
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/capabilities.h>

namespace tcpip2 {

enum class IoError {
    None = 0,
    WouldBlock,
    NoBuffer,
    Invalid,
    Closed,
    Internal,
};

class IPacketQueue {
public:
    virtual ~IPacketQueue() = default;

    /**
     * Receive up to @p capacity packets into @p out.
     *
     * Returns n <= capacity. Ownership of out[0..n-1] transfers to the
     * caller; out[n..capacity-1] are untouched. When no packets are currently
     * available the backend reports 0 with either IoError::None or
     * IoError::WouldBlock (poll-based backends report WouldBlock).
     */
    virtual std::size_t RecvBatch(BufferLease out[], std::size_t capacity, IoError& error) noexcept = 0;

    /**
     * Transmit up to @p count packets from @p packets.
     *
     * Returns n <= count. Ownership of packets[0..n-1] transfers to the
     * backend; packets[n..count-1] stay with the caller. A partial send
     * (n < count with IoError::None) is legal: the caller keeps the tail and
     * may resubmit it later. On error no leases are transferred.
     */
    virtual std::size_t SendBatch(BufferLease packets[], std::size_t count, IoError& error) noexcept = 0;

    virtual std::size_t QueueId() const noexcept = 0;

    /**
     * Inject the buffer pool used for RX allocation.
     *
     * Called by the runtime after OpenQueue() and before the shard starts
     * polling. Every concrete IPacketQueue must override this: backends that
     * allocate RX leases (TapQueue, future AF_XDP/DPDK) store and use the
     * pool pointer; backends that source leases via other means
     * (NullPacketIo) still must accept and store the pool for interface
     * conformance.
     *
     * Making this pure virtual forces every backend to acknowledge the pool
     * dependency at compile time — a backend that forgets to inject the pool
     * would silently compile but fail at runtime.
     *
     * This breaks the global-pool anti-pattern: leases allocated in RecvBatch()
     * must belong to the same pool the shard drains via DrainReturnQueue(),
     * otherwise foreign-thread returns accumulate in an undrained pool.
     */
    virtual void SetBufferPool(PktBufferPool* pool) noexcept = 0;

    /** Event backends wake the owner thread by invoking @p wake. */
    virtual void SetRecvHandler(std::function<void()> wake) = 0;
};

class IPacketIo {
public:
    virtual ~IPacketIo() = default;

    virtual std::size_t QueueCount() const noexcept = 0;

    /** Open a queue for exclusive use by one thread; nullptr if invalid. */
    virtual std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) = 0;

    /**
     * Declare backend capabilities. Non-pure: existing backends get default
     * capabilities (L3, 1500 MTU, single queue, event mode, no offloads).
     * Backends that need to advertise different capabilities override this.
     */
    virtual PacketIoCapabilities Capabilities() const noexcept { return {}; }
};

/**
 * Trivially conforming IPacketIo for contract tests and dry runs.
 * Buffers are injected via Inject(); egress bytes are captured for tests.
 *
 * Test knobs emulate backends that the contract must tolerate:
 *   * SetMaxSendPerBatch() exercises the partial-send ownership rule.
 *   * SetRecvWouldBlock()/SetSendWouldBlock() emulate poll-based backends
 *     that report WouldBlock.
 *   * SetAsyncTxCompletion() emulates async TX backends that return buffers
 *     to the owner pool at completion instead of inside SendBatch().
 */
class NullPacketIo final : public IPacketIo {
public:
    explicit NullPacketIo(std::size_t queue_count = 1);
    ~NullPacketIo() override;

    std::size_t QueueCount() const noexcept override;
    std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) override;

    /**
     * Inject a packet into @p queue_id's receive backlog.
     * The backend becomes the owner of @p lease on success.
     */
    bool Inject(std::size_t queue_id, BufferLease&& lease);

    /**
     * Test knob: cap the number of leases SendBatch() accepts per call
     * (default unlimited). Exercises the partial-send ownership rule: the
     * first n leases are transferred to the backend, the rest stay with the
     * caller. Ignored when @p n == 0 (means unlimited).
     */
    void SetMaxSendPerBatch(std::size_t n);

    /**
     * Test knob: when true, RecvBatch() on an empty backlog returns
     * 0 with IoError::WouldBlock instead of IoError::None.
     */
    void SetRecvWouldBlock(bool on);

    /**
     * Test knob: when true, SendBatch() accepts 0 leases and returns
     * IoError::WouldBlock; every lease stays with the caller.
     */
    void SetSendWouldBlock(bool on);

    /**
     * Test knob: when true, SendBatch() keeps the accepted leases pending
     * instead of resetting them inline. DrainTxCompletions() must be called
     * (emulating the async backend's completion path) to return those leases
     * to their owner pool.
     */
    void SetAsyncTxCompletion(bool on);

    /** Emulate TX completion for @p queue_id: release pending leases to their pools. */
    void DrainTxCompletions(std::size_t queue_id);

    /** Number of leases awaiting TX completion for @p queue_id (for assertions). */
    std::size_t PendingTxCompletions(std::size_t queue_id) const;

    /**
     * Egress records captured by SendBatch() for @p queue_id.
     *
     * @warning This returns a const reference to internal state. It is only
     * safe to call when no shard thread is writing to the same queue (e.g.,
     * after `Stop()`). For concurrent access while the runtime is running,
     * use `EgressSnapshot()` instead.
     */
    const std::vector<std::vector<std::uint8_t>>& Egress(std::size_t queue_id) const;

    /**
     * Thread-safe snapshot of egress records for @p queue_id.
     *
     * Copies the egress vector under the internal lock. Safe to call from any
     * thread, including while the runtime is running.
     *
     * Added post-freeze per ADR-007.
     */
    std::vector<std::vector<std::uint8_t>> EgressSnapshot(std::size_t queue_id) const;

    /** Backend state; definition lives in src/packetio/null_io.cpp. */
    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

} // namespace tcpip2
