#pragma once

/**
 * @file LeakTracker.h
 * @brief RAII leak assertion for PktBufferPool.
 * @license GPL-3.0
 *
 * A PoolLeakCheck observes a pool and reports a test failure if the pool ends
 * its scope with outstanding (leased or retained) buffers. This turns an
 * accidental lease leak into a hard test failure instead of a silent leak.
 */

#include <cstddef>

#include <tcpip2/buffer.h>

#include "Test.h"

namespace tcpip2 {
namespace test {

class PoolLeakCheck final {
public:
    explicit PoolLeakCheck(const PktBufferPool& pool) noexcept : pool_(pool) {}

    PoolLeakCheck(const PoolLeakCheck&) = delete;
    PoolLeakCheck& operator=(const PoolLeakCheck&) = delete;

    ~PoolLeakCheck() {
        if (pool_.OutstandingCount() != 0) {
            RecordFailure("LeakTracker.h", __LINE__, "pool leak: outstanding != 0");
        }
    }

    std::size_t Outstanding() const { return pool_.OutstandingCount(); }
    std::size_t Free() const { return pool_.FreeCount(); }

private:
    const PktBufferPool& pool_;
};

} // namespace test
} // namespace tcpip2
