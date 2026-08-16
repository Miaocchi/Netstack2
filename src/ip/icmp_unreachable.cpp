#include <ip/icmp_unreachable.h>

#include <algorithm>
#include <cstring>
#include <limits>

#include <ip/checksum.h>
#include <ip/icmpv4.h>
#include <ip/ipv4.h>
#include <ip/ipv6.h>

namespace tcpip2 {
namespace {

constexpr std::size_t kMaxQuoteBytes = 8;  // RFC 792/4443: header + 8 transport bytes

void Write16(std::uint8_t* output, std::uint16_t value) noexcept {
    output[0] = static_cast<std::uint8_t>(value >> 8);
    output[1] = static_cast<std::uint8_t>(value & 0xffu);
}

void Write32(std::uint8_t* output, std::uint32_t value) noexcept {
    output[0] = static_cast<std::uint8_t>(value >> 24);
    output[1] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
    output[2] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    output[3] = static_cast<std::uint8_t>(value & 0xffu);
}

} // namespace

IcmpUnreachableResult BuildIcmpv4Unreachable(const std::uint8_t* original,
                                             std::size_t original_len,
                                             std::uint8_t code,
                                             std::uint16_t mtu,
                                             std::uint8_t* output,
                                             std::size_t capacity,
                                             std::uint8_t hop_limit) noexcept {
    IcmpUnreachableResult result;
    if (original == nullptr || output == nullptr || original_len < 20) {
        result.error = IcmpUnreachableError::InvalidOriginal;
        return result;
    }
    if ((original[0] >> 4) != 4) {
        result.error = IcmpUnreachableError::InvalidOriginal;
        return result;
    }

    const std::size_t header_length = static_cast<std::size_t>(original[0] & 0x0Fu) * 4;
    if (header_length < 20 || header_length > original_len) {
        result.error = IcmpUnreachableError::InvalidOriginal;
        return result;
    }
    const std::size_t quoted = header_length + std::min(kMaxQuoteBytes, original_len - header_length);

    // ICMP message: type(1) code(1) checksum(2) + 4 bytes (unused or mtu) + quoted.
    const std::size_t icmp_length = 8 + quoted;
    const std::size_t packet_length = 20 + icmp_length;
    if (capacity < packet_length) {
        result.error = IcmpUnreachableError::BufferTooSmall;
        return result;
    }

    std::uint8_t* const icmp = output + 20;
    icmp[0] = 3;  // Destination Unreachable
    icmp[1] = code;
    Write16(icmp + 2, 0);  // checksum placeholder
    if (code == Icmpv4DestUnreachableCode::FragmentationNeeded) {
        Write16(icmp + 4, 0);
        Write16(icmp + 6, mtu);
    } else {
        Write32(icmp + 4, 0);  // unused
    }
    std::memcpy(icmp + 8, original, quoted);
    Write16(icmp + 2, InternetChecksum(icmp, icmp_length));

    // IPv4 header with source/destination swapped, protocol ICMP.
    output[0] = 0x45;
    output[1] = 0;
    Write16(output + 2, static_cast<std::uint16_t>(packet_length));
    Write16(output + 4, 0);  // identification
    Write16(output + 6, 0);  // flags + fragment offset
    output[8] = hop_limit;
    output[9] = 1;  // ICMP
    Write16(output + 10, 0);  // checksum field must be zero for the fold
    std::memcpy(output + 12, original + 16, 4);   // src = original dst
    std::memcpy(output + 16, original + 12, 4);   // dst = original src
    Write16(output + 10, InternetChecksum(output, 20));

    result.packet_length = packet_length;
    return result;
}

IcmpUnreachableResult BuildIcmpv6Unreachable(const std::uint8_t* original,
                                             std::size_t original_len,
                                             std::uint8_t code,
                                             std::uint8_t* output,
                                             std::size_t capacity,
                                             std::uint8_t hop_limit) noexcept {
    IcmpUnreachableResult result;
    if (original == nullptr || output == nullptr || original_len < 40) {
        result.error = IcmpUnreachableError::InvalidOriginal;
        return result;
    }
    if ((original[0] >> 4) != 6) {
        result.error = IcmpUnreachableError::InvalidOriginal;
        return result;
    }

    const std::size_t quoted = 40 + std::min(kMaxQuoteBytes, original_len - 40);

    const std::size_t icmp_length = 8 + quoted;
    const std::size_t packet_length = 40 + icmp_length;
    if (capacity < packet_length) {
        result.error = IcmpUnreachableError::BufferTooSmall;
        return result;
    }

    std::uint8_t* const icmp = output + 40;
    icmp[0] = 1;  // Destination Unreachable
    icmp[1] = code;
    Write16(icmp + 2, 0);  // checksum placeholder
    Write32(icmp + 4, 0);  // unused
    std::memcpy(icmp + 8, original, quoted);

    // ICMPv6 checksum includes the (swapped) pseudo-header.
    const std::uint32_t seed = Ipv6PseudoHeaderSeed(
        original + 24, original + 8, 58, static_cast<std::uint32_t>(icmp_length));
    Write16(icmp + 2, InternetChecksum(icmp, icmp_length, seed));

    // IPv6 header with source/destination swapped, next header ICMPv6.
    output[0] = 0x60;
    Write16(output + 4, static_cast<std::uint16_t>(icmp_length));
    output[6] = 58;  // ICMPv6
    output[7] = hop_limit;
    std::memcpy(output + 8, original + 24, 16);  // src = original dst
    std::memcpy(output + 24, original + 8, 16);  // dst = original src

    result.packet_length = packet_length;
    return result;
}

} // namespace tcpip2
