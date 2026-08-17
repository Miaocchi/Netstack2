#include <tcp/output.h>

#include <algorithm>
#include <array>
#include <cstring>

#include <ip/checksum.h>

namespace tcpip2 {
namespace {

void Write16(std::uint8_t *output, std::uint16_t value) noexcept {
    output[0] = static_cast<std::uint8_t>(value >> 8);
    output[1] = static_cast<std::uint8_t>(value & 0xffu);
}

void Write32(std::uint8_t *output, std::uint32_t value) noexcept {
    output[0] = static_cast<std::uint8_t>(value >> 24);
    output[1] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
    output[2] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    output[3] = static_cast<std::uint8_t>(value & 0xffu);
}

bool AppendByte(std::array<std::uint8_t, 40> &options, std::size_t &length, std::uint8_t value) noexcept {
    if (length >= options.size())
        return false;
    options[length++] = value;
    return true;
}

bool SerializeSynOptions(const TcpSynOptions &source, std::array<std::uint8_t, 40> &options,
                         std::size_t &length) noexcept {
    length = 0;
    if (source.mss_present) {
        if (!AppendByte(options, length, 2) || !AppendByte(options, length, 4) ||
            !AppendByte(options, length, static_cast<std::uint8_t>(source.mss >> 8)) ||
            !AppendByte(options, length, static_cast<std::uint8_t>(source.mss & 0xffu))) {
            return false;
        }
    }
    if (source.sack_permitted) {
        if (!AppendByte(options, length, 4) || !AppendByte(options, length, 2)) {
            return false;
        }
    }
    if (source.timestamp_present) {
        if (!AppendByte(options, length, 1) || !AppendByte(options, length, 1) || !AppendByte(options, length, 8) ||
            !AppendByte(options, length, 10)) {
            return false;
        }
        for (int shift = 24; shift >= 0; shift -= 8) {
            if (!AppendByte(options, length, static_cast<std::uint8_t>((source.timestamp_value >> shift) & 0xffu))) {
                return false;
            }
        }
        for (int shift = 24; shift >= 0; shift -= 8) {
            if (!AppendByte(options, length, static_cast<std::uint8_t>((source.timestamp_echo >> shift) & 0xffu))) {
                return false;
            }
        }
    }
    if (source.window_scale_present) {
        if (!AppendByte(options, length, 1) || !AppendByte(options, length, 3) || !AppendByte(options, length, 3) ||
            !AppendByte(options, length, std::min<std::uint8_t>(source.window_scale, 14))) {
            return false;
        }
    }
    while ((length % 4) != 0) {
        if (!AppendByte(options, length, 0))
            return false;
    }
    return true;
}

bool SerializeAckOptions(const TcpResponse &response, std::array<std::uint8_t, 40> &options,
                         std::size_t &length) noexcept {
    length = 0;
    if (response.timestamp_present) {
        if (!AppendByte(options, length, 1) || !AppendByte(options, length, 1) || !AppendByte(options, length, 8) ||
            !AppendByte(options, length, 10)) {
            return false;
        }
        for (int shift = 24; shift >= 0; shift -= 8) {
            if (!AppendByte(options, length, static_cast<std::uint8_t>((response.timestamp_value >> shift) & 0xffu)))
                return false;
        }
        for (int shift = 24; shift >= 0; shift -= 8) {
            if (!AppendByte(options, length, static_cast<std::uint8_t>((response.timestamp_echo >> shift) & 0xffu)))
                return false;
        }
    }

    const std::size_t max_sack_blocks = response.timestamp_present ? 3 : 4;
    const std::size_t sack_count = std::min(response.sack_blocks.count, max_sack_blocks);
    if (sack_count != 0) {
        if (!AppendByte(options, length, 5) ||
            !AppendByte(options, length, static_cast<std::uint8_t>(2 + sack_count * 8))) {
            return false;
        }
        for (std::size_t i = 0; i < sack_count; ++i) {
            const TcpSackBlock &block = response.sack_blocks.blocks[i];
            for (int shift = 24; shift >= 0; shift -= 8) {
                if (!AppendByte(options, length, static_cast<std::uint8_t>((block.left_edge >> shift) & 0xffu)))
                    return false;
            }
            for (int shift = 24; shift >= 0; shift -= 8) {
                if (!AppendByte(options, length, static_cast<std::uint8_t>((block.right_edge >> shift) & 0xffu)))
                    return false;
            }
        }
    }
    while ((length % 4) != 0) {
        if (!AppendByte(options, length, 0))
            return false;
    }
    return true;
}

} // namespace

TcpOutputResult BuildTcpControlPacket(const TcpResponse &response, std::uint8_t *output, std::size_t capacity,
                                      std::uint16_t ipv4_id, std::uint8_t hop_limit) noexcept {
    TcpOutputResult result;
    if (!response.valid || output == nullptr || response.flow.protocol != 6) {
        result.error = TcpOutputError::InvalidResponse;
        return result;
    }
    if (response.flow.source.family() != response.flow.destination.family()) {
        result.error = TcpOutputError::AddressFamilyMismatch;
        return result;
    }

    std::array<std::uint8_t, 40> options{};
    std::size_t options_length = 0;
    if ((response.flags & TcpFlag::Syn) != 0) {
        if (!SerializeSynOptions(response.syn_options, options, options_length)) {
            result.error = TcpOutputError::OptionsTooLong;
            return result;
        }
    } else if ((response.flags & TcpFlag::Ack) != 0) {
        if (!SerializeAckOptions(response, options, options_length)) {
            result.error = TcpOutputError::OptionsTooLong;
            return result;
        }
    }

    const std::size_t ip_header_length = response.flow.source.IsIpv4() ? 20 : 40;
    const std::size_t tcp_total = 20 + options_length + response.payload_length;
    const std::size_t packet_length = ip_header_length + tcp_total;
    if (capacity < packet_length) {
        result.error = TcpOutputError::BufferTooSmall;
        return result;
    }

    // Clear header region only — payload area will be memcpy'd below.
    std::memset(output, 0, ip_header_length + 20 + options_length);
    std::uint8_t *tcp = output + ip_header_length;
    Write16(tcp, response.flow.source_port);
    Write16(tcp + 2, response.flow.destination_port);
    Write32(tcp + 4, response.sequence);
    Write32(tcp + 8, response.acknowledgment);
    tcp[12] = static_cast<std::uint8_t>(((20 + options_length) / 4) << 4);
    tcp[13] = response.flags;
    Write16(tcp + 14, response.window);
    if (options_length > 0) {
        std::memcpy(tcp + 20, options.data(), options_length);
    }
    if (response.payload_length > 0 && response.payload != nullptr) {
        std::memcpy(tcp + 20 + options_length, response.payload, response.payload_length);
    }

    std::uint32_t pseudo_seed = 0;
    if (response.flow.source.IsIpv4()) {
        output[0] = 0x45;
        output[1] = static_cast<std::uint8_t>(response.ip_ecn & 0x03u);
        Write16(output + 2, static_cast<std::uint16_t>(packet_length));
        Write16(output + 4, ipv4_id);
        output[8] = hop_limit;
        output[9] = 6;
        std::memcpy(output + 12, response.flow.source.Bytes(), 4);
        std::memcpy(output + 16, response.flow.destination.Bytes(), 4);
        Write16(output + 10, InternetChecksum(output, 20));
        pseudo_seed = Ipv4PseudoHeaderSeed(response.flow.source.Bytes(), response.flow.destination.Bytes(), 6,
                                           static_cast<std::uint16_t>(tcp_total));
    } else {
        output[0] = 0x60;
        // ECN codepoint occupies the low two bits of the traffic-class octet,
        // i.e. bits 5:4 of byte 1 (DSCP stays 0).
        output[1] = static_cast<std::uint8_t>((response.ip_ecn & 0x03u) << 4);
        Write16(output + 4, static_cast<std::uint16_t>(tcp_total));
        output[6] = 6;
        output[7] = hop_limit;
        std::memcpy(output + 8, response.flow.source.Bytes(), 16);
        std::memcpy(output + 24, response.flow.destination.Bytes(), 16);
        pseudo_seed = Ipv6PseudoHeaderSeed(response.flow.source.Bytes(), response.flow.destination.Bytes(), 6,
                                           static_cast<std::uint32_t>(tcp_total));
    }
    Write16(tcp + 16, InternetChecksum(tcp, tcp_total, pseudo_seed));

    result.packet_length = packet_length;
    return result;
}

} // namespace tcpip2
