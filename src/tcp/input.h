#pragma once

/**
 * @file input.h
 * @brief IPv4/IPv6 packet validation and TCP input normalization.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>

#include <tcp/segment.h>

namespace tcpip2 {

enum class TcpInputError {
    None,
    NullData,
    UnsupportedIpVersion,
    MalformedIp,
    BadIpv4Checksum,
    NotTcp,
    FragmentRequiresReassembly,
    MalformedTcp,
};

struct TcpInputResult {
    TcpInputError error = TcpInputError::None;
    TcpParseError tcp_error = TcpParseError::None;
    TcpSegmentView segment;
};

TcpInputResult ParseIpTcpPacket(const std::uint8_t* packet,
                                std::size_t length) noexcept;

/// Fragment metadata extracted from a raw IP packet.
/// Used when ParseIpTcpPacket returns FragmentRequiresReassembly to feed
/// the fragment into FragmentReassembler without re-parsing the IP header.
struct FragmentInfo {
    bool valid = false;
    std::uint8_t ip_version = 0;         // 4 or 6
    std::uint8_t src_ip[16] = {};
    std::uint8_t dst_ip[16] = {};
    std::uint8_t protocol = 0;            ///< Upper-layer protocol (IPv4 protocol / IPv6 final next-header).
    std::uint32_t identification = 0;
    std::uint16_t fragment_offset = 0;    // 8-byte units
    bool more_fragments = false;
    const std::uint8_t* payload = nullptr;
    std::size_t payload_length = 0;
    /// IP header ECN codepoint of this fragment (0 Not-ECT .. 3 CE).
    std::uint8_t ecn = 0;
};

/// Extract fragment metadata from a raw IP packet.
/// Returns FragmentInfo with valid=false on any parse error.
FragmentInfo ExtractFragmentInfo(const std::uint8_t* packet,
                                 std::size_t length) noexcept;

} // namespace tcpip2
