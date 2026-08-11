/**
 * @file dispatcher.cpp
 * @brief PacketDispatcher routing logic.
 * @license GPL-3.0
 *
 * Dispatch() classifies only the bounded L3/L4 headers needed for ownership.
 * It intentionally performs no protocol state mutation or packet handoff.
 */

#include <core/dispatcher.h>
#include <cstring>

#include <ip/ipv4.h>
#include <ip/ipv6.h>

namespace tcpip2 {

namespace {

std::uint16_t ReadU16(const std::uint8_t* data) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
}

void CopyIpv4Mapped(const std::uint8_t input[4], std::uint8_t output[16]) noexcept {
    std::memset(output, 0, 10);
    output[10] = 0xff;
    output[11] = 0xff;
    std::memcpy(output + 12, input, 4);
}

std::size_t FragmentHash(const FragmentKey& key) noexcept {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    const std::uint64_t prime = 0x100000001b3ULL;
    const auto add = [&hash](std::uint8_t byte) noexcept {
        hash ^= byte;
        hash *= prime;
    };
    add(key.ip_version);
    add(key.protocol);
    for (std::size_t i = 0; i < sizeof(key.identification); ++i) {
        const std::size_t shift = (sizeof(key.identification) - 1 - i) * 8;
        add(static_cast<std::uint8_t>(key.identification >> shift));
    }
    for (std::uint8_t byte : key.src_ip) add(byte);
    for (std::uint8_t byte : key.dst_ip) add(byte);
    return static_cast<std::size_t>(hash);
}

PacketClassification ClassifyTransport(std::uint8_t protocol, const IpAddress& source,
                                       const IpAddress& destination,
                                       const std::uint8_t* transport,
                                       std::size_t transport_length,
                                       const PacketDispatcher& dispatcher) noexcept {
    PacketClassification result;
    if (protocol != 6 && protocol != 17) return result;
    if (transport == nullptr || transport_length < 4) {
        result.error = PacketClassificationError::TruncatedTransport;
        return result;
    }
    result.packet_class = protocol == 6 ? PacketClass::kTcp : PacketClass::kUdp;
    result.flow.source = source;
    result.flow.destination = destination;
    result.flow.source_port = ReadU16(transport);
    result.flow.destination_port = ReadU16(transport + 2);
    result.flow.protocol = protocol;
    result.flow = result.flow.Canonical();
    result.owner_shard = dispatcher.FlowShard(result.flow);
    return result;
}

} // namespace

PacketClassification PacketDispatcher::ClassifyPacket(const std::uint8_t* packet,
                                                       std::size_t length) const noexcept {
    PacketClassification result;
    if (packet == nullptr || length == 0) {
        result.error = PacketClassificationError::Empty;
        return result;
    }

    const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);
    if (version == 4) {
        const Ipv4ParseResult ip = ParseIpv4(packet, length);
        if (ip.error != Ipv4ParseError::None) {
            result.error = PacketClassificationError::MalformedIp;
            return result;
        }
        if (ip.header.fragment_offset != 0 || (ip.header.flags & 0x01u) != 0) {
            if (ip.header.protocol != 6 && ip.header.protocol != 17) return result;
            result.packet_class = PacketClass::kFragment;
            result.fragment.ip_version = 4;
            result.fragment.protocol = ip.header.protocol;
            result.fragment.identification = ip.header.identification;
            CopyIpv4Mapped(ip.header.src_ip, result.fragment.src_ip);
            CopyIpv4Mapped(ip.header.dst_ip, result.fragment.dst_ip);
            result.owner_shard = FragmentShard(result.fragment);
            return result;
        }
        return ClassifyTransport(ip.header.protocol,
                                 IpAddress::Ipv4(ip.header.src_ip[0], ip.header.src_ip[1],
                                                 ip.header.src_ip[2], ip.header.src_ip[3]),
                                 IpAddress::Ipv4(ip.header.dst_ip[0], ip.header.dst_ip[1],
                                                 ip.header.dst_ip[2], ip.header.dst_ip[3]),
                                 ip.payload, ip.header.payload_length, *this);
    }
    if (version == 6) {
        const Ipv6ParseResult ip = ParseIpv6(packet, length);
        if (ip.error != Ipv6ParseResult::Error::None) {
            result.error = PacketClassificationError::MalformedIp;
            return result;
        }
        if (ip.fragment_header_present) {
            if (ip.final_next_header != 6 && ip.final_next_header != 17) return result;
            result.packet_class = PacketClass::kFragment;
            result.fragment.ip_version = 6;
            result.fragment.protocol = ip.final_next_header;
            result.fragment.identification = ip.fragment_identification;
            std::memcpy(result.fragment.src_ip, ip.header.src_ip, 16);
            std::memcpy(result.fragment.dst_ip, ip.header.dst_ip, 16);
            result.owner_shard = FragmentShard(result.fragment);
            return result;
        }
        return ClassifyTransport(ip.final_next_header, IpAddress::Ipv6(ip.header.src_ip),
                                 IpAddress::Ipv6(ip.header.dst_ip), ip.payload,
                                 ip.payload_length, *this);
    }

    result.error = PacketClassificationError::UnsupportedIpVersion;
    return result;
}

DispatchDecision PacketDispatcher::Dispatch(std::size_t source_shard,
                                            const std::uint8_t* packet,
                                            std::size_t length) const noexcept {
    DispatchDecision decision;
    decision.classification = ClassifyPacket(packet, length);
    if (decision.classification.IsRoutable() &&
        source_shard < shard_count_ &&
        decision.classification.owner_shard != source_shard) {
        decision.action = DispatchAction::kRedirect;
    }
    return decision;
}

std::size_t PacketDispatcher::FragmentShard(const FragmentKey& key) const noexcept {
    if (shard_count_ == 0) return 0;
    return FragmentHash(key) % shard_count_;
}

} // namespace tcpip2
