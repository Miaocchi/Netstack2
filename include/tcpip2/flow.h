#pragma once

/**
 * @file flow.h
 * @brief FlowKey: bidirectional flow identifier with canonical hashing.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * FlowKey identifies a network flow by (source, source_port, destination,
 * destination_port, protocol). Canonical() reorders the endpoints so that
 * A->B and B->A produce the same canonical key, guaranteeing bidirectional
 * flows always map to the same shard via FlowToShard().
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/address.h>

namespace tcpip2 {

struct FlowKey {
    IpAddress source;
    IpAddress destination;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint8_t protocol = 0;

    bool operator==(const FlowKey &o) const noexcept {
        return source == o.source && destination == o.destination && source_port == o.source_port &&
               destination_port == o.destination_port && protocol == o.protocol;
    }

    bool operator!=(const FlowKey &o) const noexcept { return !(*this == o); }

    /**
     * Canonical form: ensures bidirectional flows hash to the same value.
     * Sorts endpoints so that (source,source_port) <= (destination,destination_port).
     */
    FlowKey Canonical() const noexcept;
};

/**
 * Fixed hash function — deterministic, NOT std::hash.
 * Uses FNV-1a variant over canonical bytes. Returns shard index via modulo.
 */
std::uint64_t FlowHash(const FlowKey &key) noexcept;

/** Map a flow to a shard in [0, shard_count). */
std::size_t FlowToShard(const FlowKey &key, std::size_t shard_count) noexcept;

} // namespace tcpip2
