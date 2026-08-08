/**
 * @file timer_wheel.cpp
 * @brief Deterministic absolute-deadline timer wheel.
 * @license GPL-3.0
 *
 * Callbacks are keyed by absolute deadline, hashed to wheel slots via
 * deadline % slot_count. AdvanceTo() scans the wheel, collects every entry
 * whose deadline has passed, fires the collected set, and only then advances
 * the cursor. Scheduling/cancelling from inside a callback therefore cannot
 * invalidate the fire loop. No real clock, no sleeping: time is driven
 * explicitly by the harness (FakeClock).
 */

#include <core/timer_wheel.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace tcpip2 {

TimerWheel::TimerWheel(std::size_t slot_count) noexcept
    : slot_count_(slot_count == 0 ? 1 : slot_count),
      slots_(slot_count_) {}

TimerWheel::~TimerWheel() = default;

TimerId TimerWheel::Schedule(std::uint64_t deadline_ms, TimerCallback cb) {
    if (deadline_ms <= cursor_ms_) {
        // Deadlines in the past (or "now") are clamped to the next tick so a
        // timer scheduled from inside AdvanceTo() fires on the next advance.
        if (cursor_ms_ == std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error("timer wheel cursor exhausted");
        }
        deadline_ms = cursor_ms_ + 1;
    }
    TimerId id{next_id_++};
    if (next_id_ == 0) next_id_ = 1;
    while (id.value == 0 || by_id_.find(id.value) != by_id_.end()) {
        id.value = next_id_++;
        if (next_id_ == 0) next_id_ = 1;
    }
    const std::size_t slot = static_cast<std::size_t>(deadline_ms % slot_count_);
    slots_[slot].push_back(Entry{id, deadline_ms, std::move(cb)});
    std::list<Entry>::iterator it = slots_[slot].end();
    --it;
    try {
        const auto inserted = by_id_.emplace(id.value, SlotPos{slot, it});
        if (!inserted.second) {
            throw std::overflow_error("timer id space exhausted");
        }
    } catch (...) {
        slots_[slot].erase(it);
        throw;
    }
    ++pending_;
    return id;
}

bool TimerWheel::Cancel(TimerId id) {
    auto found = by_id_.find(id.value);
    if (found == by_id_.end()) return false;
    SlotPos& pos = found->second;
    slots_[pos.slot].erase(pos.it);
    by_id_.erase(found);
    --pending_;
    return true;
}

std::size_t TimerWheel::AdvanceTo(std::uint64_t now_ms) {
    if (now_ms <= cursor_ms_) return 0;
    cursor_ms_ = now_ms;

    std::vector<Entry> due;
    due.reserve(pending_);
    for (auto& list : slots_) {
        for (auto it = list.begin(); it != list.end();) {
            if (it->deadline_ms <= now_ms) {
                by_id_.erase(it->id.value);
                due.push_back(std::move(*it));
                it = list.erase(it);
                --pending_;
            } else {
                ++it;
            }
        }
    }

    for (auto& e : due) {
        if (e.cb) e.cb();
    }
    return due.size();
}

} // namespace tcpip2
