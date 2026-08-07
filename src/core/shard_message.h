#pragma once

/**
 * @file shard_message.h
 * @brief Typed inter-thread message types for shard communication.
 * @license GPL-3.0
 *
 * Extracted from shard.h to break a circular include between shard.h and
 * inbox_mpsc.h. Both headers include this file to get FlowId, ShardMessageType,
 * and ShardMessage. The message carries a BufferLease (unique ownership) and
 * a SessionError, so this header depends on the buffer and transport_session
 * public headers.
 */

#include <cstdint>

#include <tcpip2/buffer.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/transport_session.h>

namespace tcpip2 {

// FlowId is defined in the public header session_factory.h; we re-export it
// here via the include above so that shard_message.h consumers get it without
// having to include session_factory.h directly.

enum class ShardMessageType {
    kPacketIn,
    kSessionData,
    kControl,
    kSessionClosed,
    kStop,
};

/** Typed message posted to a shard; move-only (carries a BufferLease). */
struct ShardMessage {
    ShardMessageType type = ShardMessageType::kControl;
    FlowId flow_id;
    BufferLease data;
    SessionError error = SessionError::None;
};

} // namespace tcpip2
