#include <ip/icmpv6.h>
#include <ip/checksum.h>

namespace tcpip2 {

Icmpv6ParseResult ParseIcmpv6(const std::uint8_t* data, std::size_t len) noexcept {
    Icmpv6ParseResult result;

    // Minimum ICMPv6 message is 8 bytes: 4-byte header + 4 bytes type-specific data.
    if (len < 8) {
        result.error = Icmpv6ParseResult::Error::TooShort;
        return result;
    }

    ReadCursor cur(data, len);

    // Fixed 4-byte header: type(1) + code(1) + checksum(2)
    cur.ReadU8(result.header.type);
    cur.ReadU8(result.header.code);
    cur.ReadU16(result.header.checksum);

    // Type-specific bytes [4..7] and body.
    switch (result.header.type) {
        case Icmpv6Type::DestinationUnreachable:
        case Icmpv6Type::TimeExceeded:
            // Bytes [4..7] are unused. Quoted packet starts at offset 8.
            cur.Skip(4);
            result.header.quoted_payload = data + 8;
            result.header.quoted_payload_len = len - 8;
            break;

        case Icmpv6Type::PacketTooBig:
            // Bytes [4..7] are MTU (u32 big-endian). Quoted packet at offset 8.
            cur.ReadU32(result.header.mtu);
            result.header.quoted_payload = data + 8;
            result.header.quoted_payload_len = len - 8;
            break;

        case Icmpv6Type::ParameterProblem:
            // Bytes [4..7] are pointer (u32 big-endian). Quoted packet at offset 8.
            cur.ReadU32(result.header.pointer);
            result.header.quoted_payload = data + 8;
            result.header.quoted_payload_len = len - 8;
            break;

        case Icmpv6Type::EchoRequest:
        case Icmpv6Type::EchoReply:
            // Bytes [4..5] are id (u16), bytes [6..7] are sequence (u16).
            // Payload data starts at offset 8.
            cur.ReadU16(result.header.id);
            cur.ReadU16(result.header.sequence);
            result.payload = data + 8;
            result.payload_length = len - 8;
            break;

        default:
            // Unknown type: skip the 4 type-specific bytes. No body pointers set.
            cur.Skip(4);
            break;
    }

    return result;
}

bool VerifyIcmpv6Checksum(const std::uint8_t* data, std::size_t len,
                          const std::uint8_t src_ip[16],
                          const std::uint8_t dst_ip[16]) noexcept {
    const std::uint32_t seed = Ipv6PseudoHeaderSeed(src_ip, dst_ip, 58,
                                                    static_cast<std::uint32_t>(len));
    return InternetChecksum(data, len, seed) == 0;
}

} // namespace tcpip2
