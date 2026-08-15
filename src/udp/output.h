#pragma once

/**
 * @file output.h
 * @brief Bounded IPv4/IPv6 UDP packet serialization.
 * @license GPL-3.0
 *
 * Builds a complete IP+UDP packet (20-byte IPv4 or 40-byte IPv6 header, 8-byte
 * UDP header, payload) with correct IP and UDP checksums. UDP checksums are
 * always computed: mandatory for IPv6 (RFC 8200 §8.1) and interoperable for
 * IPv4 (RFC 768). RFC 768's "checksum 0 means not computed" applies only on
 * the receive path (see udp.h / ParseUdpDatagram).
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/flow.h>

namespace tcpip2 {

enum class UdpOutputError {
    None,
    InvalidFlow,       ///< mismatched or non-UDP flow, null output.
    BufferTooSmall,    ///< capacity < IPv4/IPv6 header + UDP header + payload.
    PayloadTooLarge,   ///< payload would overflow the UDP length field.
};

struct UdpOutputResult {
    UdpOutputError error = UdpOutputError::None;
    std::size_t packet_length = 0;
};

/**
 * Serialize one UDP datagram (flow.source:src_port -> flow.destination:dst_port)
 * into @p output. The flow must be protocol 17 with matching address families.
 *
 * @param flow         source/destination endpoints (flow.protocol must be 17).
 * @param payload      datagram payload (may be empty).
 * @param payload_length number of payload bytes.
 * @param output       destination buffer.
 * @param capacity     bytes available at @p output.
 * @param ipv4_id      IPv4 identification field (for DF=0 fragment interop).
 * @param hop_limit    IPv4 TTL / IPv6 hop limit.
 */
UdpOutputResult BuildUdpPacket(const FlowKey& flow,
                               const std::uint8_t* payload,
                               std::size_t payload_length,
                               std::uint8_t* output,
                               std::size_t capacity,
                               std::uint16_t ipv4_id = 0,
                               std::uint8_t hop_limit = 64) noexcept;

} // namespace tcpip2
