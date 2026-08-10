#pragma once

/**
 * @file clock.h
 * @brief Monotonic clock abstraction for the Netstack2 runtime.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001 after ADR-005. Signature
 * changes require an ADR and a consumer compile-contract test update.
 *
 * IClock allows tests to inject a deterministic clock. Production code uses
 * SystemClock, which wraps std::chrono::steady_clock.
 *
 * All time values are in milliseconds since an unspecified monotonic epoch.
 * The epoch is not related to wall-clock time; only differences are meaningful.
 */

#include <cstdint>

namespace tcpip2 {

/**
 * Abstract monotonic clock.
 *
 * Implementations must guarantee:
 *   - NowMs() is non-decreasing across calls from a single thread.
 *   - NowMs() and NowUs() share the same epoch.
 *   - Both methods are safe to call from any thread (no internal locking
 *     required for SystemClock, but implementations may add their own).
 */
class IClock {
public:
    virtual ~IClock() = default;

    /** Monotonic time in milliseconds. */
    virtual std::uint64_t NowMs() const noexcept = 0;

    /** Monotonic time in microseconds. */
    virtual std::uint64_t NowUs() const noexcept = 0;
};

/**
 * Default IClock backed by std::chrono::steady_clock.
 *
 * This class has no mutable state and is safe to share across threads.
 */
class SystemClock final : public IClock {
public:
    std::uint64_t NowMs() const noexcept override;
    std::uint64_t NowUs() const noexcept override;
};

/**
 * Return a pointer to a process-wide SystemClock singleton.
 *
 * This is the default clock used when RuntimeDependencies::clock is nullptr.
 * The pointer is valid for the lifetime of the process.
 */
IClock* DefaultClock() noexcept;

} // namespace tcpip2
