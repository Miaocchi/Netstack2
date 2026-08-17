#include <thread>

#include <core/thread_ownership.h>

#include "Test.h"

using namespace tcpip2;

TCPIP2_TEST(OwnerThreadPasses) {
    ThreadOwnershipGuard g;
    TCPIP2_EXPECT_FALSE(g.IsOwner());
    g.SetOwner();
    TCPIP2_EXPECT_TRUE(g.IsOwner());
    TCPIP2_EXPECT_TRUE(g.AssertOwner(__FILE__, __LINE__));
    TCPIP2_EXPECT_TRUE(std::this_thread::get_id() == g.OwnerId());
    g.ClearOwner();
    TCPIP2_EXPECT_FALSE(g.IsOwner());
}

TCPIP2_TEST(OtherThreadNotOwner) {
    ThreadOwnershipGuard g;
    g.SetOwner();
    std::thread t([&g] {
        TCPIP2_EXPECT_FALSE(g.IsOwner());
        TCPIP2_EXPECT_FALSE(std::this_thread::get_id() == g.OwnerId());
    });
    t.join();
}

TCPIP2_TEST(OwnershipCanBeTransferred) {
    ThreadOwnershipGuard g;
    g.SetOwner();
    std::thread t([&g] {
        g.SetOwner();
        TCPIP2_EXPECT_TRUE(g.IsOwner());
        TCPIP2_EXPECT_TRUE(g.AssertOwner(__FILE__, __LINE__));
        g.ClearOwner();
    });
    t.join();
    TCPIP2_EXPECT_FALSE(g.IsOwner());
}

TCPIP2_TEST(NonOwnerAccessAborts) {
    // A forked child spawns a thread that is not the owner; AssertOwner must
    // abort the child process (death test).
    TCPIP2_EXPECT_DEATH({
        ThreadOwnershipGuard g;
        g.SetOwner();
        std::thread worker([&g] { g.AssertOwner(__FILE__, __LINE__); });
        worker.join();
    });
}

TCPIP2_TEST_MAIN();
