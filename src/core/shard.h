#pragma once

/**
 * @file shard.h
 * @brief Typed inter-thread message for StackShard ownership transfer.
 * @license GPL-3.0
 *
 * Internal header (not public API). Cross-thread communication is limited to
 * ShardMessage values: no arbitrary closures, no flow pointers escape, so the
 * single-ownership invariant cannot be bypassed. The full Shard/SPSC wiring
 * lands in NETSTACK2-004.
 */

#include <cstdint>

#include <tcpip2/buffer.h>
#include <tcpip2/transport_session.h>

namespace tcpip2 {

struct FlowId {
    std::uint64_t value = 0;
    bool operator==(const FlowId& o) const noexcept { return value == o.value; }
    bool operator!=(const FlowId& o) const noexcept { return value != o.value; }
};

enum class ShardMessageType {
    kPacketIn,
    kSessionData,
    kControl,
    kSessionClosed,
};

/** Typed message posted to a shard; move-only (carries a BufferLease). */
struct ShardMessage {
    ShardMessageType type = ShardMessageType::kControl;
    FlowId flow_id;
    BufferLease data;
    SessionError error = SessionError::None;
};

} // namespace tcpip2
