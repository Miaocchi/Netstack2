#include <ip/icmpv4.h>
#include <ip/checksum.h>

namespace tcpip2 {

Icmpv4ParseResult ParseIcmpv4(const std::uint8_t *data, std::size_t len) noexcept {
    Icmpv4ParseResult result;

    // Minimum ICMP header is 8 bytes: type + code + checksum + 4 type-specific bytes.
    if (len < 8) {
        result.error = Icmpv4ParseError::TooShort;
        return result;
    }

    ReadCursor cur(data, len);

    // Type
    cur.ReadU8(result.header.type);

    // Code
    cur.ReadU8(result.header.code);

    // Checksum
    cur.ReadU16(result.header.checksum);

    // The remaining 4 bytes of the fixed header depend on the type.
    switch (result.header.type) {
    case Icmpv4Type::Echo:
    case Icmpv4Type::EchoReply: {
        // id (u16) + sequence (u16)
        cur.ReadU16(result.header.id);
        cur.ReadU16(result.header.sequence);

        // Payload starts at offset 8.
        result.payload = data + 8;
        result.payload_length = len - 8;
        break;
    }
    case Icmpv4Type::DestinationUnreachable: {
        if (result.header.code == Icmpv4DestUnreachableCode::FragmentationNeeded) {
            // bytes [4..5] unused (0), bytes [6..7] = next-hop MTU (u16, big-endian)
            cur.Skip(2);
            cur.ReadU16(result.header.mtu);
        } else {
            // bytes [4..7] unused (0)
            cur.Skip(4);
        }

        // Quoted payload starts at offset 8.
        result.header.quoted_payload = data + 8;
        result.header.quoted_payload_len = len - 8;
        break;
    }
    case Icmpv4Type::TimeExceeded: {
        // bytes [4..7] unused (0)
        cur.Skip(4);

        // Quoted payload starts at offset 8.
        result.header.quoted_payload = data + 8;
        result.header.quoted_payload_len = len - 8;
        break;
    }
    case Icmpv4Type::ParameterProblem: {
        // byte [4] = pointer, bytes [5..7] unused
        // (pointer is not exposed in the header struct; skip over it)
        cur.Skip(4);

        // Quoted payload starts at offset 8.
        result.header.quoted_payload = data + 8;
        result.header.quoted_payload_len = len - 8;
        break;
    }
    default:
        // Unknown type: skip the remaining 4 fixed bytes.
        cur.Skip(4);
        break;
    }

    // Compute checksum over the entire ICMP message (header + payload).
    result.checksum_ok = (InternetChecksum(data, len, 0) == 0);

    return result;
}

} // namespace tcpip2
