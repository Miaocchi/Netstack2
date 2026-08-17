/**
 * @file flow_hash.cpp
 * @brief Canonical flow key ordering and FNV-1a hashing.
 * @license GPL-3.0
 *
 * Canonical ordering reorders the (source,source_port) and
 * (destination,destination_port) pairs so the "smaller" endpoint becomes
 * the source. This guarantees A->B and B->A produce identical canonical
 * keys, so FlowToShard() maps both directions to the same shard.
 *
 * The hash serializes the canonical FlowKey to a deterministic byte array
 * (family byte + address bytes + port bytes big-endian + protocol byte)
 * and applies FNV-1a (64-bit). The result is platform-independent.
 */

#include <tcpip2/flow.h>

#include <cstdint>
#include <cstring>

namespace tcpip2 {

namespace {

struct Endpoint {
    IpAddress addr;
    std::uint16_t port;

    bool operator<(const Endpoint &o) const noexcept {
        if (addr < o.addr)
            return true;
        if (o.addr < addr)
            return false;
        return port < o.port;
    }
};

} // namespace

FlowKey FlowKey::Canonical() const noexcept {
    const Endpoint a{source, source_port};
    const Endpoint b{destination, destination_port};

    FlowKey result;
    if (b < a) {
        result.source = b.addr;
        result.source_port = b.port;
        result.destination = a.addr;
        result.destination_port = a.port;
    } else {
        result.source = a.addr;
        result.source_port = a.port;
        result.destination = b.addr;
        result.destination_port = b.port;
    }
    result.protocol = protocol;
    return result;
}

std::uint64_t FlowHash(const FlowKey &key) noexcept {
    const FlowKey canon = key.Canonical();

    // Serialize to a deterministic byte buffer.
    std::uint8_t buf[1 + 16 + 16 + 2 + 2 + 1];
    std::size_t pos = 0;

    buf[pos++] = static_cast<std::uint8_t>(canon.source.family());

    std::memcpy(buf + pos, canon.source.Bytes(), canon.source.ByteCount());
    pos += canon.source.ByteCount();

    // Pad IPv4 to 16 bytes so both families have the same layout width.
    if (canon.source.IsIpv4()) {
        for (std::size_t i = 4; i < 16; ++i)
            buf[pos++] = 0;
    }

    std::memcpy(buf + pos, canon.destination.Bytes(), canon.destination.ByteCount());
    pos += canon.destination.ByteCount();

    if (canon.destination.IsIpv4()) {
        for (std::size_t i = 4; i < 16; ++i)
            buf[pos++] = 0;
    }

    buf[pos++] = static_cast<std::uint8_t>((canon.source_port >> 8) & 0xFF);
    buf[pos++] = static_cast<std::uint8_t>(canon.source_port & 0xFF);
    buf[pos++] = static_cast<std::uint8_t>((canon.destination_port >> 8) & 0xFF);
    buf[pos++] = static_cast<std::uint8_t>(canon.destination_port & 0xFF);
    buf[pos++] = canon.protocol;

    // FNV-1a 64-bit.
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    const std::uint64_t prime = 0x100000001b3ULL;
    for (std::size_t i = 0; i < pos; ++i) {
        hash ^= buf[i];
        hash *= prime;
    }
    return hash;
}

std::size_t FlowToShard(const FlowKey &key, std::size_t shard_count) noexcept {
    if (shard_count == 0)
        return 0;
    const std::uint64_t h = FlowHash(key);
    return static_cast<std::size_t>(h % shard_count);
}

} // namespace tcpip2
