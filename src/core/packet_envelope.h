#pragma once

/**
 * @file packet_envelope.h
 * @brief Move-only packet payload used by cross-shard RX lanes.
 * @license GPL-3.0
 */

#include <cstddef>

#include <tcpip2/address.h>
#include <tcpip2/buffer.h>

namespace tcpip2 {

enum class PacketEnvelopeType {
    kRawIp,
    kReassembledTcp,
    kReassembledUdp,
};

/**
 * Owns all packet data that crosses a shard boundary. Reassembled packets
 * carry their already-validated IP endpoints because their lease contains
 * only the transport segment.
 */
struct PacketEnvelope {
    PacketEnvelopeType type = PacketEnvelopeType::kRawIp;
    BufferLease lease;
    IpAddress source;
    IpAddress destination;

    std::size_t ByteSize() const noexcept { return lease.Size(); }
};

} // namespace tcpip2
