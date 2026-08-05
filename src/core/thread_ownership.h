#pragma once

/**
 * @file thread_ownership.h
 * @brief Single-ownership invariant enforcement (code-level invariant).
 * @license GPL-3.0
 *
 * A guarded object may be read/written by exactly one thread at a time.
 * AssertOwner() aborts on any access from a non-owner thread. Used by the
 * StackShard (NETSTACK2-004) and exercised by thread_ownership_test.
 */

#include <atomic>
#include <thread>

namespace tcpip2 {

class ThreadOwnershipGuard final {
public:
    ThreadOwnershipGuard() noexcept = default;

    void SetOwner(std::thread::id owner = std::this_thread::get_id()) noexcept {
        owner_.store(owner, std::memory_order_relaxed);
    }
    void ClearOwner() noexcept { owner_.store(std::thread::id{}, std::memory_order_relaxed); }

    std::thread::id OwnerId() const noexcept { return owner_.load(std::memory_order_relaxed); }
    bool IsOwner() const noexcept {
        return owner_.load(std::memory_order_relaxed) == std::this_thread::get_id();
    }

    /** Returns true on the owner thread; aborts the process otherwise. */
    bool AssertOwner(const char* file, int line) noexcept;

private:
    std::atomic<std::thread::id> owner_{};
};

#define TCPIP2_ASSERT_OWNER(guard) (guard).AssertOwner(__FILE__, __LINE__)

} // namespace tcpip2
