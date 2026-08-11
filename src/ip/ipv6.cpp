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

/// Search parsed HopByHop options for a Jumbo Payload option (RFC 2675).
/// If found, decode the 4-byte big-endian length into @p jumbo_len.
/// @return true if the Jumbo option was found and decoded.
bool FindJumboPayload(const Ipv6Option* opts, std::size_t count,
                      std::uint32_t& jumbo_len) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        if (opts[i].type == Ipv6OptionType::JumboPayload) {
            if (opts[i].length != 4 || opts[i].data == nullptr) {
                return false; // malformed jumbo option
            }
            jumbo_len = (static_cast<std::uint32_t>(opts[i].data[0]) << 24) |
                        (static_cast<std::uint32_t>(opts[i].data[1]) << 16) |
                        (static_cast<std::uint32_t>(opts[i].data[2]) << 8) |
                        static_cast<std::uint32_t>(opts[i].data[3]);
            return true;
        }
    }
    return false;
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

    // Payload length (2 bytes) — 0 for jumbograms.
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

    // If payload_length is non-zero, it specifies the length of everything
    // after the fixed header (extension headers + upper-layer payload).
    // For jumbograms (payload_length == 0), the HopByHop JumboPayload option
    // (RFC 2675) carries the real length. If the first extension header is
    // HopByHop we parse it early to find the Jumbo option. If no Jumbo option
    // is found we fall back to using the available buffer length.
    std::size_t total_after_fixed;
    if (result.header.payload_length == 0) {
        // Check if the first extension header is HopByHop — then peek at its
        // options to find a JumboPayload option.
        std::uint32_t jumbo_len = 0;
        bool jumbo_found = false;

        if (result.header.next_header == Ipv6ExtHeaderType::HopByHop &&
            available_payload >= 2) {
            // Read the HopByHop header: next_header(1) + hdr_ext_len(1) + options.
            std::uint8_t hbh_nh = data[40];
            std::uint8_t hbh_ext_len = data[41];
            std::size_t hbh_size;
            if (CheckedMul<std::size_t>(
                    static_cast<std::size_t>(hbh_ext_len) + 1, std::size_t{8}, hbh_size) &&
                hbh_size >= 2 && hbh_size <= available_payload) {
                // Parse options within the HopByHop body.
                Ipv6Option tmp_opts[kIpv6MaxOptions];
                std::size_t tmp_count = 0;
                if (ParseIpv6Options(data + 40 + 2, hbh_size - 2,
                                     tmp_opts, tmp_count)) {
                    if (FindJumboPayload(tmp_opts, tmp_count, jumbo_len)) {
                        jumbo_found = true;
                    }
                }
            }
            (void)hbh_nh; // consumed during the walk below
        }

        if (jumbo_found) {
            result.jumbo_payload_present = true;
            result.jumbo_payload_length = jumbo_len;
            total_after_fixed = jumbo_len;
        } else {
            // No jumbo option — use available bytes.
            total_after_fixed = available_payload;
        }
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
            // Parse the 8-byte Fragment header.
            // data[offset]     = next header
            // data[offset+1]   = reserved
            // data[offset+2..3] = fragment_offset(13) | res(2) | MF(1)
            // data[offset+4..7] = identification (32-bit)
            if (offset + 8 > len) {
                result.error = Ipv6ParseResult::Error::TruncatedExtHeader;
                return result;
            }
            const std::uint16_t ff =
                static_cast<std::uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
            result.fragment_offset = static_cast<std::uint16_t>(ff >> 3);
            result.fragment_more = (ff & 0x01u) != 0;
            result.fragment_identification =
                (static_cast<std::uint32_t>(data[offset + 4]) << 24) |
                (static_cast<std::uint32_t>(data[offset + 5]) << 16) |
                (static_cast<std::uint32_t>(data[offset + 6]) << 8) |
                static_cast<std::uint32_t>(data[offset + 7]);
            // The fragmentable payload is everything after the Fragment header
            // (i.e. from ext_end to the end of the packet's declared payload).
            const std::size_t frag_payload_end = 40 + total_after_fixed;
            std::size_t frag_start;
            if (!CheckedAdd<std::size_t>(offset, std::size_t{8}, frag_start)) {
                result.error = Ipv6ParseResult::Error::TruncatedExtHeader;
                return result;
            }
            if (frag_start <= frag_payload_end) {
                result.fragment_payload = data + frag_start;
                result.fragment_payload_length = frag_payload_end - frag_start;
            }
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

        // Structured parsing for non-Fragment extension headers.
        // The option/routing data starts at offset+2 (after next_header + hdr_ext_len)
        // and extends for ext_size-2 bytes.
        if (current_nh == Ipv6ExtHeaderType::HopByHop) {
            if (!ParseIpv6Options(data + offset + 2, ext_size - 2,
                                  result.hopbyhop_options,
                                  result.hopbyhop_option_count)) {
                result.error = Ipv6ParseResult::Error::BadExtHeaderOption;
                return result;
            }
            // Validate JumboPayload consistency (RFC 2675): the option is only
            // valid when the fixed-header payload_length is 0.
            std::uint32_t jlen = 0;
            if (FindJumboPayload(result.hopbyhop_options,
                                 result.hopbyhop_option_count, jlen)) {
                if (result.header.payload_length != 0) {
                    result.error = Ipv6ParseResult::Error::BadJumboPayload;
                    return result;
                }
                // Jumbo was already detected during the pre-scan; values match.
                result.jumbo_payload_present = true;
                result.jumbo_payload_length = jlen;
            }
        } else if (current_nh == Ipv6ExtHeaderType::Routing) {
            result.routing_header_present = true;
            result.routing_header =
                ParseIpv6RoutingHeader(data + offset + 2, ext_size - 2);
        } else if (current_nh == Ipv6ExtHeaderType::DestinationOptions) {
            if (!ParseIpv6Options(data + offset + 2, ext_size - 2,
                                  result.dest_options,
                                  result.dest_option_count)) {
                result.error = Ipv6ParseResult::Error::BadExtHeaderOption;
                return result;
            }
        }

        offset = ext_end;
        current_nh = ext_nh;
        result.ext_header_count++;
    }

    // current_nh is now the terminal upper-layer protocol.
    result.final_next_header = current_nh;

    // NoNextHeader (59) means there is no payload after the extension headers.
    if (current_nh == Ipv6ExtHeaderType::NoNextHeader) {
        result.payload_offset = offset;
        result.payload_length = 0;
        result.payload = nullptr;
    } else {
        result.payload_offset = offset;
        result.payload_length = (40 + total_after_fixed) - offset;
        result.payload = data + offset;
    }

    return result;
}

} // namespace tcpip2
