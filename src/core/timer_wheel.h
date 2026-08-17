#pragma once

/**
 * @file timer_wheel.h
 * @brief Deterministic timer wheel for the Netstack2 core.
 * @license GPL-3.0
 *
 * Absolute-deadline wheel with 1 ms granularity, driven explicitly by
 * AdvanceTo(). No real clock, no sleeping: the test harness controls time via
 * FakeClock. Newly scheduled callbacks fire on the next AdvanceTo() call that
 * reaches their deadline.
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <unordered_map>
#include <vector>

namespace tcpip2 {

struct TimerId {
    std::uint64_t value = 0;
    bool operator==(const TimerId &o) const noexcept { return value == o.value; }
    bool operator!=(const TimerId &o) const noexcept { return value != o.value; }
};

using TimerCallback = std::function<void()>;

class TimerWheel final {
  public:
    explicit TimerWheel(std::size_t slot_count = 256) noexcept;
    ~TimerWheel();

    TimerWheel(const TimerWheel &) = delete;
    TimerWheel &operator=(const TimerWheel &) = delete;

    /** Schedule @p cb at absolute @p deadline_ms (clamped to now+1). */
    TimerId Schedule(std::uint64_t deadline_ms, TimerCallback cb);

    /** Cancel a pending timer; returns false if already fired/cancelled. */
    bool Cancel(TimerId id);

    /**
     * Fire every callback whose deadline has been reached by @p now_ms.
     * Returns the number of callbacks fired. No-ops if now <= current time.
     */
    std::size_t AdvanceTo(std::uint64_t now_ms);

    std::uint64_t Now() const noexcept { return cursor_ms_; }
    std::size_t PendingCount() const noexcept { return pending_; }

  private:
    struct Entry {
        TimerId id;
        std::uint64_t deadline_ms;
        TimerCallback cb;
    };
    struct SlotPos {
        std::size_t slot;
        std::list<Entry>::iterator it;
    };

    std::size_t slot_count_;
    std::vector<std::list<Entry>> slots_;
    std::unordered_map<std::uint64_t, SlotPos> by_id_;
    std::uint64_t next_id_ = 1;
    std::uint64_t cursor_ms_ = 0;
    std::size_t pending_ = 0;
};

} // namespace tcpip2
