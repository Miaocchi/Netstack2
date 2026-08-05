#pragma once

/**
 * @file FakeClock.h
 * @brief Deterministic millisecond clock for timer tests.
 * @license GPL-3.0
 *
 * The TimerWheel has no real clock; time is advanced explicitly by the test
 * harness. FakeClock provides the Now() value that tests pass to
 * TimerWheel::AdvanceTo().
 */

#include <cstdint>

namespace tcpip2 {
namespace test {

class FakeClock final {
public:
    explicit FakeClock(std::uint64_t now_ms = 0) noexcept : now_(now_ms) {}

    std::uint64_t Now() const noexcept { return now_; }

    void Advance(std::uint64_t ms) noexcept { now_ += ms; }
    void Set(std::uint64_t ms) noexcept { now_ = ms; }

private:
    std::uint64_t now_;
};

} // namespace test
} // namespace tcpip2
