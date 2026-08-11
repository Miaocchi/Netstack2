#pragma once

/**
 * @file shutdown.h
 * @brief Public deadline-aware shutdown result contract.
 * @license GPL-3.0
 */

#include <cstddef>
#include <cstdint>
#include <limits>

#include <tcpip2/packet_io.h>

namespace tcpip2 {

/** Outcome of a Netstack2 shutdown attempt. */
enum class StopStatus {
    Stopped = 0,
    TimedOut,
    DrainFailed,
};

/**
 * Shutdown budget. A zero timeout requests an unbounded final drain/cancel.
 * Normal callers should use the finite default; destructors use zero so pools
 * are never released while a queue still owns a lease.
 */
struct StopOptions {
    std::uint64_t timeout_ms = 5000;
};

/**
 * Result of one shutdown attempt. TimedOut and DrainFailed leave the runtime
 * in Stopping with its queues and pools intact; call Stop again to retry.
 */
struct StopResult {
    StopStatus status = StopStatus::Stopped;
    IoError drain_error = IoError::None;
    std::size_t queue_id = std::numeric_limits<std::size_t>::max();
    std::size_t outstanding_tx = 0;
    std::size_t outstanding_buffers = 0;

    bool IsComplete() const noexcept { return status == StopStatus::Stopped; }
};

} // namespace tcpip2
