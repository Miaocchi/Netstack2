#pragma once

/**
 * @file packet_io.h
 * @brief Pluggable packet I/O (kernel-bypass backends and virtio-style taps).
 * @license GPL-3.0
 *
 * Experimental API (NETSTACK2-000). Semantics are validated by
 * NETSTACK2-002; signatures may change until NETSTACK2-API-FREEZE-001.
 *
 * Each hardware queue is modeled as exactly one IPacketQueue, opened by a
 * single owner thread (RX queue -> owner shard). Polling backends call
 * RecvBatch() repeatedly; event backends wake the owner via SetRecvHandler().
 *
 * Ownership rules (written down, enforced by tests):
 *   * RecvBatch(): the first n returned leases are transferred to the caller.
 *   * SendBatch(): when n is returned, the first n leases are transferred to
 *     the backend; the remaining (n..count-1) leases stay with the caller.
 *   * Async TX backends return buffers to the owner pool at completion.
 *   * count == 0 returns 0 with IoError::None (not an error).
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <tcpip2/buffer.h>

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

    /** Receive up to @p capacity packets into @p out. */
    virtual std::size_t RecvBatch(BufferLease out[], std::size_t capacity, IoError& error) noexcept = 0;

    /** Transmit up to @p count packets from @p packets. */
    virtual std::size_t SendBatch(BufferLease packets[], std::size_t count, IoError& error) noexcept = 0;

    virtual std::size_t QueueId() const noexcept = 0;

    /** Event backends wake the owner thread by invoking @p wake. */
    virtual void SetRecvHandler(std::function<void()> wake) = 0;
};

class IPacketIo {
public:
    virtual ~IPacketIo() = default;

    virtual std::size_t QueueCount() const noexcept = 0;

    /** Open a queue for exclusive use by one thread; nullptr if invalid. */
    virtual std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) = 0;
};

/**
 * Trivially conforming IPacketIo for contract tests and dry runs.
 * Buffers are injected via Inject(); egress bytes are captured for tests.
 */
class NullPacketIo final : public IPacketIo {
public:
    explicit NullPacketIo(std::size_t queue_count = 1);
    ~NullPacketIo() override;

    std::size_t QueueCount() const noexcept override;
    std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) override;

    /** Inject a packet into @p queue_id's receive backlog. */
    bool Inject(std::size_t queue_id, BufferLease&& lease);

    /** Egress records captured by SendBatch() for @p queue_id. */
    const std::vector<std::vector<std::uint8_t>>& Egress(std::size_t queue_id) const;

    /** Backend state; definition lives in src/packetio/null_io.cpp. */
    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

} // namespace tcpip2
