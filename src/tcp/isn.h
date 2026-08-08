#pragma once

/**
 * @file isn.h
 * @brief Keyed RFC 6528-style TCP initial sequence number generation.
 * @license GPL-3.0
 */

#include <array>
#include <cstdint>

#include <tcpip2/flow.h>

namespace tcpip2 {

class TcpIsnGenerator final {
public:
    explicit TcpIsnGenerator(const std::array<std::uint64_t, 2>& secret) noexcept
        : secret_(secret) {}

    std::uint32_t Generate(const FlowKey& directional_flow,
                           std::uint64_t now_ms) const noexcept;

private:
    std::array<std::uint64_t, 2> secret_;
    mutable std::uint64_t last_clock_tick_ = 0;
};

/** Load a fresh 128-bit ISN secret from the operating system CSPRNG. */
bool LoadTcpIsnSecret(std::array<std::uint64_t, 2>& secret) noexcept;

} // namespace tcpip2
