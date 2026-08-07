#pragma once

/**
 * @file capabilities.h
 * @brief Packet I/O capability declaration for backend-agnostic negotiation.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * Backends declare their capabilities via PacketIoCapabilities so the
 * protocol core can adapt (e.g. checksum offload, GSO/GRO, poll vs event
 * mode) without branching on backend names.
 */

#include <cstddef>
#include <cstdint>

namespace tcpip2 {

/** L2 (Ethernet) or L3 (IP) link mode. */
enum class LinkMode {
    L2,
    L3,
};

/** Polling (busy-poll RecvBatch) or event (woken via SetRecvHandler) mode. */
enum class PollMode {
    Polling,
    Event,
};

/**
 * Declares what a packet I/O backend supports. The core must not branch on
 * backend identity; it queries capabilities instead.
 */
struct PacketIoCapabilities {
    LinkMode link_mode = LinkMode::L3;
    std::uint16_t mtu = 1500;
    std::uint16_t headroom = 0;
    std::size_t queue_count = 1;
    PollMode poll_mode = PollMode::Event;
    bool rx_checksum_offload = false;
    bool tx_checksum_offload = false;
    bool scatter_gather = false;
    bool gso = false;
    bool gro = false;
    bool tso = false;
    bool async_tx = false;
    bool zero_copy = false;
};

} // namespace tcpip2
