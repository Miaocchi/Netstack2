/**
 * @file thread_ownership.cpp
 * @brief Single-ownership invariant enforcement.
 * @license GPL-3.0
 *
 * AssertOwner() is the enforcement point for the code-level invariant that a
 * guarded object is touched by exactly one thread at a time. Access from a
 * non-owner thread aborts the process (death-tested); the diagnostic prints
 * the owning thread and the offending thread.
 */

#include <core/thread_ownership.h>

#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace tcpip2 {

bool ThreadOwnershipGuard::AssertOwner(const char *file, int line) noexcept {
    if (IsOwner())
        return true;
    std::ostringstream os;
    os << "tcpip2: ownership violation at " << file << ':' << line << ": object owned by thread "
       << owner_.load(std::memory_order_relaxed) << " but accessed from thread " << std::this_thread::get_id() << '\n';
    std::fprintf(stderr, "%s", os.str().c_str());
    std::fflush(stderr);
    std::abort();
}

} // namespace tcpip2
