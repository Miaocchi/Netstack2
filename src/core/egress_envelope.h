#pragma once

/**
 * @file egress_envelope.h
 * @brief Move-only TX payload used by cross-shard egress lanes.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/buffer.h>

namespace tcpip2 {

/**
 * Owns a packet after its protocol-owner FQ-CoDel scheduler has selected it
 * for a TX queue owned by another shard. The original enqueue timestamp is
 * retained so the queue owner's scheduler accounts for lane delay as well.
 */
struct EgressEnvelope {
    BufferLease lease;
    std::size_t queue_id = 0;
    std::uint32_t flow_hash = 0;
    std::uint64_t enqueue_time_ms = 0;

    std::size_t ByteSize() const noexcept { return lease.Size(); }
};

} // namespace tcpip2
