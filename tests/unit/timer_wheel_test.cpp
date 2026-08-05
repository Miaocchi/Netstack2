#include <cstdint>
#include <vector>

#include <core/timer_wheel.h>

#include "FakeClock.h"
#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(ScheduleAndFire) {
    tcpip2::test::FakeClock clock;
    TimerWheel wheel(16);
    std::vector<std::uint64_t> fired;
    wheel.Schedule(100, [&] { fired.push_back(clock.Now()); });
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.PendingCount());
    clock.Advance(50);
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.AdvanceTo(clock.Now()));
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.PendingCount());
    clock.Advance(50);
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.AdvanceTo(clock.Now()));
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.PendingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, fired.size());
    TCPIP2_EXPECT_EQ(std::uint64_t{100}, fired[0]);
    TCPIP2_EXPECT_EQ(std::uint64_t{100}, wheel.Now());
}

TCPIP2_TEST(ClampsPastDeadline) {
    TimerWheel wheel;
    wheel.Schedule(0, [] {});
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.PendingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.AdvanceTo(1));
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.PendingCount());
    TCPIP2_EXPECT_EQ(std::uint64_t{1}, wheel.Now());
}

TCPIP2_TEST(FiresAllDueInSingleAdvance) {
    TimerWheel wheel(4);
    std::vector<std::uint64_t> order;
    wheel.Schedule(10, [&] { order.push_back(10); });
    wheel.Schedule(5, [&] { order.push_back(5); });
    wheel.Schedule(7, [&] { order.push_back(7); });
    TCPIP2_EXPECT_EQ(std::size_t{3}, wheel.AdvanceTo(10));
    TCPIP2_EXPECT_EQ(std::size_t{3}, order.size());
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.PendingCount());
    bool has5 = false;
    bool has7 = false;
    bool has10 = false;
    for (std::uint64_t v : order) {
        if (v == 5) has5 = true;
        if (v == 7) has7 = true;
        if (v == 10) has10 = true;
    }
    TCPIP2_EXPECT_TRUE(has5 && has7 && has10);
}

TCPIP2_TEST(SameDeadlineFiresInInsertionOrder) {
    TimerWheel wheel(8);
    std::vector<int> order;
    wheel.Schedule(42, [&] { order.push_back(1); });
    wheel.Schedule(42, [&] { order.push_back(2); });
    wheel.Schedule(42, [&] { order.push_back(3); });
    TCPIP2_EXPECT_EQ(std::size_t{3}, wheel.AdvanceTo(42));
    TCPIP2_EXPECT_EQ(std::size_t{3}, order.size());
    TCPIP2_EXPECT_EQ(1, order[0]);
    TCPIP2_EXPECT_EQ(2, order[1]);
    TCPIP2_EXPECT_EQ(3, order[2]);
}

TCPIP2_TEST(CancelPending) {
    TimerWheel wheel;
    TimerId id = wheel.Schedule(50, [] {});
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.PendingCount());
    TCPIP2_EXPECT_TRUE(wheel.Cancel(id));
    TCPIP2_EXPECT_FALSE(wheel.Cancel(id));
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.PendingCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.AdvanceTo(100));
}

TCPIP2_TEST(ScheduleDuringFireFiresNextAdvance) {
    TimerWheel wheel;
    std::vector<std::uint64_t> fired;
    wheel.Schedule(10, [&] {
        fired.push_back(10);
        wheel.Schedule(10, [&] { fired.push_back(11); });
    });
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.AdvanceTo(10));
    TCPIP2_EXPECT_EQ(std::size_t{1}, fired.size());
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.PendingCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.AdvanceTo(11));
    TCPIP2_EXPECT_EQ(std::size_t{2}, fired.size());
    TCPIP2_EXPECT_EQ(std::uint64_t{11}, fired[1]);
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.PendingCount());
}

TCPIP2_TEST(AdvanceBackwardsIsNoOp) {
    TimerWheel wheel;
    wheel.Schedule(100, [] {});
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.AdvanceTo(50));
    TCPIP2_EXPECT_EQ(std::size_t{0}, wheel.AdvanceTo(50));
    TCPIP2_EXPECT_EQ(std::uint64_t{50}, wheel.Now());
    TCPIP2_EXPECT_EQ(std::size_t{1}, wheel.PendingCount());
}

TCPIP2_TEST(DefaultSlotCountAcceptsFarDeadlines) {
    TimerWheel wheel;
    std::vector<std::uint64_t> fired;
    wheel.Schedule(1'000'000'000, [&] { fired.push_back(1); });
    wheel.Schedule(2'000'000'000, [&] { fired.push_back(2); });
    TCPIP2_EXPECT_EQ(std::size_t{2}, wheel.AdvanceTo(2'000'000'000));
    TCPIP2_EXPECT_EQ(std::size_t{2}, fired.size());
}

TCPIP2_TEST_MAIN();
