#include <ip/ipv4.h>
#include <ip/checksum.h>

namespace tcpip2 {

Ipv4ParseResult ParseIpv4(const std::uint8_t* data, std::size_t len) noexcept {
    Ipv4ParseResult result;

    // Need at least 20 bytes for the fixed IPv4 header.
    if (len < 20) {
        result.error = Ipv4ParseError::TooShort;
        return result;
    }

    ReadCursor cur(data, len);

    std::uint8_t version_ihl;
    if (!cur.ReadU8(version_ihl)) {
        result.error = Ipv4ParseError::TooShort;
        return result;
    }

    result.header.version = static_cast<std::uint8_t>(version_ihl >> 4);
    result.header.ihl = static_cast<std::uint8_t>(version_ihl & 0x0F);

    if (result.header.version != 4) {
        result.error = Ipv4ParseError::BadVersion;
        return result;
    }
    if (result.header.ihl < 5) {
        result.error = Ipv4ParseError::BadIhl;
        return result;
    }

    // header_length = IHL * 4 — use checked arithmetic
    std::size_t header_len;
    if (!CheckedMul<std::size_t>(result.header.ihl, std::size_t{4}, header_len)) {
        result.error = Ipv4ParseError::BadIhl;
        return result;
    }
    result.header.header_length = header_len;

    // DSCP/ECN
    std::uint8_t dscp_ecn;
    cur.ReadU8(dscp_ecn);
    result.header.dscp = static_cast<std::uint8_t>(dscp_ecn >> 2);
    result.header.ecn = static_cast<std::uint8_t>(dscp_ecn & 0x03);

    // Total length
    cur.ReadU16(result.header.total_length);

    // Identification
    cur.ReadU16(result.header.identification);

    // Flags + fragment offset (2 bytes)
    std::uint16_t flags_frag;
    cur.ReadU16(flags_frag);
    result.header.flags = static_cast<std::uint8_t>((flags_frag >> 13) & 0x07);
    result.header.fragment_offset = static_cast<std::uint16_t>(flags_frag & 0x1FFF);

    // TTL
    cur.ReadU8(result.header.ttl);

    // Protocol
    cur.ReadU8(result.header.protocol);

    // Header checksum
    cur.ReadU16(result.header.header_checksum);

    // Source IP (4 bytes)
    cur.ReadBytes(result.header.src_ip, 4);

    // Destination IP (4 bytes)
    cur.ReadBytes(result.header.dst_ip, 4);

    // Verify we have the full header (including options)
    if (len < header_len) {
        result.error = Ipv4ParseError::TruncatedHeader;
        return result;
    }

    // Verify total_length is at least header_len
    if (result.header.total_length < header_len) {
        result.error = Ipv4ParseError::TruncatedTotal;
        return result;
    }

    // Verify buffer has at least total_length bytes
    if (len < result.header.total_length) {
        result.error = Ipv4ParseError::TruncatedTotal;
        return result;
    }

    // Compute payload offset and length
    result.header.payload_offset = header_len;
    // payload_length = total_length - header_length (both are size_t/uint16_t)
    result.header.payload_length = static_cast<std::size_t>(result.header.total_length) - header_len;
    result.payload = data + header_len;

    // Verify header checksum (over the entire header including options)
    result.checksum_ok = (InternetChecksum(data, header_len, 0) == 0);

    return result;
}

} // namespace tcpip2
