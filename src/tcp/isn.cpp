#include <tcp/isn.h>

#include <cstddef>
#include <cstring>
#include <limits>

#if defined(__linux__)
#include <cerrno>
#include <sys/random.h>
#endif

namespace tcpip2 {
namespace {

std::uint64_t RotateLeft(std::uint64_t value, unsigned bits) noexcept {
    return (value << bits) | (value >> (64U - bits));
}

std::uint64_t ReadLittle64(const std::uint8_t* data) noexcept {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (i * 8U);
    }
    return value;
}

void SipRound(std::uint64_t& v0, std::uint64_t& v1,
              std::uint64_t& v2, std::uint64_t& v3) noexcept {
    v0 += v1;
    v1 = RotateLeft(v1, 13);
    v1 ^= v0;
    v0 = RotateLeft(v0, 32);
    v2 += v3;
    v3 = RotateLeft(v3, 16);
    v3 ^= v2;
    v0 += v3;
    v3 = RotateLeft(v3, 21);
    v3 ^= v0;
    v2 += v1;
    v1 = RotateLeft(v1, 17);
    v1 ^= v2;
    v2 = RotateLeft(v2, 32);
}

std::uint64_t SipHash24(const std::uint8_t* data, std::size_t length,
                        const std::array<std::uint64_t, 2>& key) noexcept {
    std::uint64_t v0 = 0x736f6d6570736575ULL ^ key[0];
    std::uint64_t v1 = 0x646f72616e646f6dULL ^ key[1];
    std::uint64_t v2 = 0x6c7967656e657261ULL ^ key[0];
    std::uint64_t v3 = 0x7465646279746573ULL ^ key[1];

    const std::size_t blocks = length / 8;
    for (std::size_t i = 0; i < blocks; ++i) {
        const std::uint64_t message = ReadLittle64(data + i * 8);
        v3 ^= message;
        SipRound(v0, v1, v2, v3);
        SipRound(v0, v1, v2, v3);
        v0 ^= message;
    }

    std::uint64_t last = static_cast<std::uint64_t>(length) << 56;
    const std::size_t remaining_offset = blocks * 8;
    for (std::size_t i = 0; i < length - remaining_offset; ++i) {
        last |= static_cast<std::uint64_t>(data[remaining_offset + i]) << (i * 8);
    }

    v3 ^= last;
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);
    v0 ^= last;
    v2 ^= 0xff;
    for (int i = 0; i < 4; ++i) SipRound(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

} // namespace

std::uint32_t TcpIsnGenerator::Generate(const FlowKey& flow,
                                        std::uint64_t now_ms) const noexcept {
    std::uint8_t input[38] = {};
    std::size_t offset = 0;
    input[offset++] = static_cast<std::uint8_t>(flow.source.family());
    std::memcpy(input + offset, flow.source.Bytes(), flow.source.ByteCount());
    offset += 16;
    std::memcpy(input + offset, flow.destination.Bytes(), flow.destination.ByteCount());
    offset += 16;
    input[offset++] = static_cast<std::uint8_t>(flow.source_port >> 8);
    input[offset++] = static_cast<std::uint8_t>(flow.source_port & 0xffu);
    input[offset++] = static_cast<std::uint8_t>(flow.destination_port >> 8);
    input[offset++] = static_cast<std::uint8_t>(flow.destination_port & 0xffu);
    input[offset++] = flow.protocol;

    const std::uint32_t keyed = static_cast<std::uint32_t>(
        SipHash24(input, offset, secret_));
    std::uint64_t clock_tick = now_ms > std::numeric_limits<std::uint64_t>::max() / 250
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms * std::uint64_t{250};
    if (clock_tick <= last_clock_tick_ &&
        last_clock_tick_ != std::numeric_limits<std::uint64_t>::max()) {
        clock_tick = last_clock_tick_ + 1;
    }
    last_clock_tick_ = clock_tick;
    const std::uint32_t clock_component = static_cast<std::uint32_t>(clock_tick);
    return keyed + clock_component;
}

bool LoadTcpIsnSecret(std::array<std::uint64_t, 2>& secret) noexcept {
#if defined(__linux__)
    std::uint8_t* output = reinterpret_cast<std::uint8_t*>(secret.data());
    std::size_t remaining = sizeof(secret);
    while (remaining > 0) {
        const ssize_t count = ::getrandom(output, remaining, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) return false;
        output += static_cast<std::size_t>(count);
        remaining -= static_cast<std::size_t>(count);
    }
    return true;
#else
    (void)secret;
    return false;
#endif
}

} // namespace tcpip2
