/**
 * @file clock.cpp
 * @brief SystemClock implementation backed by steady_clock.
 * @license GPL-3.0
 */

#include <chrono>

#include <tcpip2/clock.h>

namespace tcpip2 {

namespace {

std::uint64_t SteadyNowMs() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::uint64_t SteadyNowUs() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace

std::uint64_t SystemClock::NowMs() const noexcept {
    return SteadyNowMs();
}

std::uint64_t SystemClock::NowUs() const noexcept {
    return SteadyNowUs();
}

IClock* DefaultClock() noexcept {
    static SystemClock instance;
    return &instance;
}

} // namespace tcpip2
