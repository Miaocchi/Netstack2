#include <ip/ipv6.h>

namespace tcpip2 {

namespace {

/// Returns true if the given next-header value is an extension header
/// that should be walked (as opposed to a terminal upper-layer protocol).
bool IsExtensionHeader(std::uint8_t nh) noexcept {
    return nh == Ipv6ExtHeaderType::HopByHop ||
           nh == Ipv6ExtHeaderType::Routing ||
           nh == Ipv6ExtHeaderType::Fragment ||
           nh == Ipv6ExtHeaderType::DestinationOptions;
}

} // namespace

Ipv6ParseResult ParseIpv6(const std::uint8_t* data, std::size_t len) noexcept {
    Ipv6ParseResult result;

    // Need at least 40 bytes for the fixed IPv6 header.
    if (len < 40) {
        result.error = Ipv6ParseResult::Error::TooShort;
        return result;
    }

    ReadCursor cur(data, len);

    // Version (4 bits) + traffic class (8 bits) + flow label (20 bits) = 4 bytes
    std::uint8_t vtf[4];
    cur.ReadBytes(vtf, 4);

    result.header.version = static_cast<std::uint8_t>(vtf[0] >> 4);
    if (result.header.version != 6) {
        result.error = Ipv6ParseResult::Error::BadVersion;
        return result;
    }

    result.header.traffic_class = static_cast<std::uint8_t>(
        ((static_cast<std::uint16_t>(vtf[0]) & 0x0F) << 4) | (vtf[1] >> 4));
    result.header.flow_label =
        ((static_cast<std::uint32_t>(vtf[1]) & 0x0F) << 16) |
        (static_cast<std::uint32_t>(vtf[2]) << 8) |
        static_cast<std::uint32_t>(vtf[3]);

    // Payload length (2 bytes) — may be 0 for jumbograms (not handled here)
    cur.ReadU16(result.header.payload_length);

    // Next header
    cur.ReadU8(result.header.next_header);

    // Hop limit
    cur.ReadU8(result.header.hop_limit);

    // Source address (16 bytes)
    cur.ReadBytes(result.header.src_ip, 16);

    // Destination address (16 bytes)
    cur.ReadBytes(result.header.dst_ip, 16);

    // Now cur is at position 40 (end of fixed header).
    // Check that we have the full payload.
    std::size_t available_payload = len - 40; // bytes after fixed header

    // If payload_length is set (non-zero), it specifies the length of everything
    // after the fixed header (extension headers + upper-layer payload).
    // For jumbograms (payload_length == 0), we don't handle hop-by-hop jumbo
    // option — treat 0 as "use available buffer length" for robustness.
    std::size_t total_after_fixed;
    if (result.header.payload_length == 0) {
        // Jumbogram or truncated — use available bytes. This is acceptable
        // for a parser: the caller may know the real length from the L2 frame.
        total_after_fixed = available_payload;
    } else {
        total_after_fixed = result.header.payload_length;
    }

    // Verify buffer has enough data
    if (available_payload < total_after_fixed) {
        result.error = Ipv6ParseResult::Error::TruncatedPayload;
        return result;
    }

    // Walk extension headers starting at position 40.
    std::uint8_t current_nh = result.header.next_header;
    std::size_t offset = 40;
    std::size_t ext_total_bytes = 0;

    // Track visited extension header types for loop detection (8 slots).
    std::uint8_t visited[8] = {};
    std::size_t visited_count = 0;

    while (IsExtensionHeader(current_nh)) {
        if (current_nh == Ipv6ExtHeaderType::Fragment) {
            result.fragment_header_present = true;
        }
        // Loop detection: check if we've seen this next-header value before.
        bool loop = false;
        for (std::size_t i = 0; i < visited_count; ++i) {
            if (visited[i] == current_nh) {
                loop = true;
                break;
            }
        }
        if (loop) {
            result.error = Ipv6ParseResult::Error::ExtHeaderLoop;
            return result;
        }
        if (visited_count >= kIpv6MaxExtHeaders) {
            result.error = Ipv6ParseResult::Error::ExtHeaderTooMany;
            return result;
        }
        visited[visited_count++] = current_nh;

        // Need at least 2 bytes for the extension header (next_header + hdr_ext_len).
        if (offset + 2 > len) {
            result.error = Ipv6ParseResult::Error::TruncatedExtHeader;
            return result;
        }

        std::uint8_t ext_nh = data[offset];
        std::uint8_t ext_len = data[offset + 1];

        // Compute extension header size.
        std::size_t ext_size;
        if (current_nh == Ipv6ExtHeaderType::Fragment) {
            // Fragment header is always 8 bytes.
            ext_size = 8;
        } else {
            // Other extension headers: (ext_len + 1) * 8 bytes.
            std::size_t mul;
            if (!CheckedMul<std::size_t>(
                    static_cast<std::size_t>(ext_len) + 1, std::size_t{8}, mul)) {
                result.error = Ipv6ParseResult::Error::TruncatedExtHeader;
                return result;
            }
            ext_size = mul;
        }

        // Check total extension header bytes limit.
        std::size_t new_ext_total;
        if (!CheckedAdd<std::size_t>(ext_total_bytes, ext_size, new_ext_total)) {
            result.error = Ipv6ParseResult::Error::ExtHeaderTooLong;
            return result;
        }
        if (new_ext_total > kIpv6MaxExtHeaderBytes) {
            result.error = Ipv6ParseResult::Error::ExtHeaderTooLong;
            return result;
        }
        ext_total_bytes = new_ext_total;

        // Check bounds: offset + ext_size must not exceed len or 40 + total_after_fixed.
        std::size_t ext_end;
        if (!CheckedAdd<std::size_t>(offset, ext_size, ext_end)) {
            result.error = Ipv6ParseResult::Error::TruncatedExtHeader;
            return result;
        }
        if (ext_end > len || ext_end > 40 + total_after_fixed) {
            result.error = Ipv6ParseResult::Error::TruncatedExtHeader;
            return result;
        }

        offset = ext_end;
        current_nh = ext_nh;
        result.ext_header_count++;
    }

    // current_nh is now the terminal upper-layer protocol.
    result.final_next_header = current_nh;
    result.payload_offset = offset;
    result.payload_length = (40 + total_after_fixed) - offset;
    result.payload = data + offset;

    return result;
}

} // namespace tcpip2
