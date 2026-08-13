/**
 * @file hotpath_alloc_test.cpp
 * @brief Hot-path heap-allocation accounting via a global operator new hook.
 * @license GPL-3.0
 *
 * R6 requirement: the per-TX-queue scheduler hot path must not perform
 * general heap allocation per packet. This file overrides the global
 * new/delete operators with counting versions and drives the FQ-CoDel
 * scheduler at a steady queue depth, asserting the enqueue/dequeue cycle
 * allocates nothing once warm.
 *
 * The overrides are confined to this translation unit / test binary so the
 * other (sanitizer-instrumented) test targets are unaffected. The tests
 * measure a *delta* of the cumulative counter around the measured loop, so
 * static-init and harness allocations are not counted.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <vector>

#include "Test.h"
#include <qos/fq_codel.h>
#include <tcpip2/buffer.h>

// ---------------------------------------------------------------------------
// Counting global operator new/delete.
// ---------------------------------------------------------------------------

namespace {
std::atomic<std::size_t> g_allocation_count{0};

std::size_t AllocCount() noexcept {
    return g_allocation_count.load(std::memory_order_relaxed);
}
} // namespace

void* operator new(std::size_t size) {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::malloc(size)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::malloc(size)) return p;
    throw std::bad_alloc();
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size);
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size);
}
void* operator new(std::size_t size, std::align_val_t align) {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::aligned_alloc(static_cast<std::size_t>(align), size)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size, std::align_val_t align) {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::aligned_alloc(static_cast<std::size_t>(align), size)) return p;
    throw std::bad_alloc();
}
void* operator new(std::size_t size, std::align_val_t align, const std::nothrow_t&) noexcept {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    return std::aligned_alloc(static_cast<std::size_t>(align), size);
}
void* operator new[](std::size_t size, std::align_val_t align, const std::nothrow_t&) noexcept {
    g_allocation_count.fetch_add(1, std::memory_order_relaxed);
    return std::aligned_alloc(static_cast<std::size_t>(align), size);
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

// ---------------------------------------------------------------------------
// Test fixture.
// ---------------------------------------------------------------------------

namespace {

using namespace tcpip2;

/// Pre-allocated lease ring so the pool itself never allocates during the
/// measured loop (the pool only reuses slots once warm). Capacity must exceed
/// the peak number of leases held in the scheduler at once.
class LeaseRing {
public:
    explicit LeaseRing(std::size_t capacity = 1024)
        : pool_(capacity, 2048) {
        free_.reserve(capacity);
        for (std::size_t i = 0; i < capacity; ++i) {
            BufferLease lease = pool_.Allocate();
            std::memset(lease.Data(), 0x55, 128);
            lease.Resize(128);
            free_.push_back(std::move(lease));
        }
    }

    BufferLease Take() noexcept {
        BufferLease lease = std::move(free_.back());
        free_.pop_back();
        return lease;
    }

    void Give(BufferLease&& lease) noexcept { free_.push_back(std::move(lease)); }

private:
    PktBufferPool pool_;
    std::vector<BufferLease> free_;
};

} // namespace

TCPIP2_TEST(FqCoDelSteadyStateHotPathNoHeapAllocation) {
    FqCoDelConfig config;
    // quantum == packet size so one flow is served once per dequeue. CoDel
    // is disabled by a huge target/interval: the test measures allocation,
    // not the AQM.
    config.quantum = 128;
    config.target_ms = 100000;
    config.interval_ms = 100000;
    LeaseRing leases;  // pool must outlive the scheduler (held leases)
    FqCoDelScheduler sched(config);

    // Warm up a single flow to a depth below the ring's next power-of-two
    // capacity: push_back grows the backing vector at 8,16,32,64,128, so
    // filling 100 leaves capacity 128. The steady loop then enqueues at most
    // 101 packets at once, never triggering another Grow.
    constexpr std::uint32_t kFlow = 7;
    constexpr std::uint32_t kWarmDepth = 100;
    for (std::uint32_t d = 0; d < kWarmDepth; ++d) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(leases.Take(), kFlow, 0));
    }
    TCPIP2_EXPECT_EQ(sched.QueueLength(), std::size_t{kWarmDepth});

    // Steady state: one enqueue + one dequeue per iteration keeps the queue
    // depth constant (~100). The flow is never drained and never exceeds its
    // warmed capacity, so no heap allocation occurs.
    const std::size_t before = AllocCount();
    std::uint64_t now = 2;
    constexpr std::uint32_t kIterations = 20000;
    for (std::uint32_t i = 0; i < kIterations; ++i) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(leases.Take(), kFlow, now));
        auto pkt = sched.Dequeue(now + 1);
        TCPIP2_EXPECT_TRUE(pkt.has_value());
        if (pkt) leases.Give(std::move(pkt->lease));
        now += 2;
    }
    TCPIP2_EXPECT_EQ(AllocCount() - before, std::size_t{0});
}

TCPIP2_TEST(FlowReactivationReusesCapacity) {
    FqCoDelConfig config;
    config.quantum = 128;
    config.target_ms = 100000;
    config.interval_ms = 100000;
    LeaseRing leases;  // pool must outlive the scheduler (held leases)
    FqCoDelScheduler sched(config);

    // Warm a single flow to depth 100 (capacity 128).
    constexpr std::uint32_t kFlow = 3;
    constexpr std::uint32_t kWarmDepth = 100;
    for (std::uint32_t d = 0; d < kWarmDepth; ++d) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(leases.Take(), kFlow, 0));
    }
    // Drain it completely (frees nothing — capacity is retained).
    for (std::uint32_t d = 0; d < kWarmDepth; ++d) {
        auto pkt = sched.Dequeue(1);
        TCPIP2_EXPECT_TRUE(pkt.has_value());
        if (pkt) leases.Give(std::move(pkt->lease));
    }
    TCPIP2_EXPECT_TRUE(sched.Empty());

    // Re-fill the same flow: the retained ring must absorb the same depth
    // without allocating (a std::deque would have re-allocated its blocks).
    const std::size_t before = AllocCount();
    for (std::uint32_t d = 0; d < kWarmDepth; ++d) {
        TCPIP2_EXPECT_TRUE(sched.Enqueue(leases.Take(), kFlow, 1000));
    }
    TCPIP2_EXPECT_EQ(AllocCount() - before, std::size_t{0});
}

TCPIP2_TEST_MAIN()
