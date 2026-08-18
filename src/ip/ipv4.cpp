#include <ip/ipv4.h>
#include <ip/checksum.h>
#include <cstring>

namespace tcpip2 {

Ipv4ParseResult ParseIpv4(const std::uint8_t *data, std::size_t len) noexcept {
    Ipv4ParseResult result;

    // Need at least 20 bytes for the fixed IPv4 header.
    if (len < 20) {
        result.error = Ipv4ParseError::TooShort;
        return result;
    }

    // Direct byte-offset extraction (no per-field bounds-checked cursor):
    // for a 64-byte packet the whole header is one or two cache lines and
    // the compiler merges these loads into wide reads. Every validation the
    // cursor version performed is preserved below.
    const std::uint8_t version_ihl = data[0];
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

    // header_length = IHL * 4 — IHL <= 15 so no overflow is possible.
    const std::size_t header_len = static_cast<std::size_t>(result.header.ihl) * 4u;
    result.header.header_length = header_len;

    const std::uint8_t dscp_ecn = data[1];
    result.header.dscp = static_cast<std::uint8_t>(dscp_ecn >> 2);
    result.header.ecn = static_cast<std::uint8_t>(dscp_ecn & 0x03);

    result.header.total_length = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[2]) << 8) | data[3]);
    result.header.identification = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[4]) << 8) | data[5]);

    const std::uint16_t flags_frag = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[6]) << 8) | data[7]);
    result.header.flags = static_cast<std::uint8_t>((flags_frag >> 13) & 0x07);
    result.header.fragment_offset = static_cast<std::uint16_t>(flags_frag & 0x1FFF);

    result.header.ttl = data[8];
    result.header.protocol = data[9];
    result.header.header_checksum = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[10]) << 8) | data[11]);

    std::memcpy(result.header.src_ip, data + 12, 4);
    std::memcpy(result.header.dst_ip, data + 16, 4);

    // Verify we have the full header (including options).
    if (len < header_len) {
        result.error = Ipv4ParseError::TruncatedHeader;
        return result;
    }

    // Verify total_length is at least header_len.
    if (result.header.total_length < header_len) {
        result.error = Ipv4ParseError::TruncatedTotal;
        return result;
    }

    // Verify buffer has at least total_length bytes.
    if (len < result.header.total_length) {
        result.error = Ipv4ParseError::TruncatedTotal;
        return result;
    }

    // Compute payload offset and length.
    result.header.payload_offset = header_len;
    result.header.payload_length = static_cast<std::size_t>(result.header.total_length) - header_len;
    result.payload = data + header_len;

    // Verify header checksum (over the entire header including options).
    result.checksum_ok = (InternetChecksum(data, header_len, 0) == 0);

    return result;
}

} // namespace tcpip2
