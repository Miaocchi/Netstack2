#include <ip/checksum.h>

namespace tcpip2 {

std::uint16_t InternetChecksum(const std::uint8_t* data, std::size_t len,
                                std::uint32_t seed) noexcept {
    std::uint32_t acc = seed;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        const std::uint16_t word =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1]);
        acc += word;
    }
    if (i < len) {
        acc += static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[i]) << 8);
    }
    while ((acc >> 16) != 0) {
        acc = (acc & 0xFFFFu) + (acc >> 16);
    }
    return static_cast<std::uint16_t>(~acc & 0xFFFFu);
}

std::uint32_t Ipv4PseudoHeaderSeed(const std::uint8_t src_ip[4],
                                    const std::uint8_t dst_ip[4],
                                    std::uint8_t protocol,
                                    std::uint16_t transport_len) noexcept {
    std::uint32_t seed = 0;
    // Source IP (4 bytes = 2 words)
    seed += static_cast<std::uint16_t>((static_cast<std::uint16_t>(src_ip[0]) << 8) | src_ip[1]);
    seed += static_cast<std::uint16_t>((static_cast<std::uint16_t>(src_ip[2]) << 8) | src_ip[3]);
    // Destination IP (4 bytes = 2 words)
    seed += static_cast<std::uint16_t>((static_cast<std::uint16_t>(dst_ip[0]) << 8) | dst_ip[1]);
    seed += static_cast<std::uint16_t>((static_cast<std::uint16_t>(dst_ip[2]) << 8) | dst_ip[3]);
    // Zero + protocol (1 word)
    seed += protocol;
    // Transport length (1 word, big-endian)
    seed += transport_len;
    return seed;
}

std::uint32_t Ipv6PseudoHeaderSeed(const std::uint8_t src_ip[16],
                                    const std::uint8_t dst_ip[16],
                                    std::uint8_t protocol,
                                    std::uint32_t upper_len) noexcept {
    std::uint32_t seed = 0;
    // Source address (16 bytes = 8 words)
    for (int i = 0; i < 16; i += 2) {
        seed += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(src_ip[i]) << 8) | src_ip[i + 1]);
    }
    // Destination address (16 bytes = 8 words)
    for (int i = 0; i < 16; i += 2) {
        seed += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(dst_ip[i]) << 8) | dst_ip[i + 1]);
    }
    // Upper-layer length (4 bytes = 2 words, big-endian)
    seed += static_cast<std::uint16_t>((upper_len >> 16) & 0xFFFF);
    seed += static_cast<std::uint16_t>(upper_len & 0xFFFF);
    // Zero(3) + protocol(1) = 1 word
    seed += protocol;
    return seed;
}

} // namespace tcpip2
