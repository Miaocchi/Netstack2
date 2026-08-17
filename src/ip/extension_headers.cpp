#include <ip/extension_headers.h>

namespace tcpip2 {

bool ParseIpv6Options(const std::uint8_t *data, std::size_t len, Ipv6Option *out, std::size_t &out_count) noexcept {
    ReadCursor cur(data, len);
    std::size_t count = 0;

    while (cur.Remaining() > 0) {
        if (count >= kIpv6MaxOptions) {
            // Too many options — refuse to continue.
            return false;
        }

        std::uint8_t type;
        if (!cur.ReadU8(type)) {
            return false;
        }

        if (type == Ipv6OptionType::Pad1) {
            // Pad1: single byte, no length, no data.
            out[count].type = Ipv6OptionType::Pad1;
            out[count].length = 0;
            out[count].data = nullptr;
            ++count;
            continue;
        }

        // All other options: type(1) + length(1) + data(length).
        std::uint8_t opt_len;
        if (!cur.ReadU8(opt_len)) {
            return false;
        }

        const std::uint8_t *opt_data = cur.Peek();
        if (!cur.Skip(static_cast<std::size_t>(opt_len))) {
            return false;
        }

        out[count].type = type;
        out[count].length = opt_len;
        out[count].data = opt_data;
        ++count;
    }

    out_count = count;
    return true;
}

Ipv6RoutingHeader ParseIpv6RoutingHeader(const std::uint8_t *data, std::size_t len) noexcept {
    Ipv6RoutingHeader rh;
    if (len < 2) {
        return rh;
    }

    ReadCursor cur(data, len);

    std::uint8_t routing_type;
    if (!cur.ReadU8(routing_type)) {
        return rh;
    }
    std::uint8_t segments_left;
    if (!cur.ReadU8(segments_left)) {
        return rh;
    }

    rh.routing_type = routing_type;
    rh.segments_left = segments_left;
    rh.type_specific_data = cur.Peek();
    rh.type_specific_length = cur.Remaining();
    return rh;
}

} // namespace tcpip2
