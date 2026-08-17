#pragma once

/**
 * @file Test.h
 * @brief Minimal dependency-free test harness for libtcpip2 unit tests.
 * @license GPL-3.0
 *
 * The library has zero external dependencies, so unit tests cannot rely on
 * a test framework. This header provides:
 *
 *   * a test registry (TCPIP2_TEST) driven by a per-binary main()
 *   * value/condition expectations that record failures without aborting
 *   * a fork-based death-test helper (TCPIP2_EXPECT_DEATH) used for the
 *     double-release and ownership-violation contract tests
 */

#include <cstdio>
#include <functional>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace tcpip2 {
namespace test {

class TestRegistry {
  public:
    using Fn = void (*)();

    static TestRegistry &Instance() {
        static TestRegistry registry;
        return registry;
    }

    void Add(const char *name, Fn fn) { tests_.push_back({name, fn}); }

    int RunAll() {
        int total_failures = 0;
        for (const auto &t : tests_) {
            const int before = failures_;
            t.fn();
            const int test_failures = failures_ - before;
            total_failures += test_failures;
            if (test_failures == 0) {
                std::printf("[PASS] %s\n", t.name);
            } else {
                std::printf("[FAIL] %s (%d assertion failures)\n", t.name, test_failures);
            }
        }
        std::printf("netstack2 test: %d failure(s) across %zu test(s)\n", total_failures, tests_.size());
        return total_failures;
    }

    void RecordFailure(const char *file, int line, const char *expr) {
        ++failures_;
        std::printf("    FAILED %s:%d: %s\n", file, line, expr);
        std::fflush(stdout);
    }

  private:
    struct Test {
        const char *name;
        Fn fn;
    };
    std::vector<Test> tests_;
    int failures_ = 0;
};

inline void RecordFailure(const char *file, int line, const char *expr) {
    TestRegistry::Instance().RecordFailure(file, line, expr);
}

struct Registrar {
    Registrar(const char *name, TestRegistry::Fn fn) { TestRegistry::Instance().Add(name, fn); }
};

/**
 * Run @p fn in a forked child process. The child is expected to abort (or
 * exit non-zero); the parent verifies that it did not exit cleanly with 0.
 */
inline bool ExpectDeath(const std::function<void()> &fn, const char *what) {
    std::fflush(nullptr);
    const pid_t pid = fork();
    if (pid == 0) {
        fn();
        std::printf("DEATH-TEST-FAIL: child did not die: %s\n", what);
        std::fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0);
}

} // namespace test
} // namespace tcpip2

#define TCPIP2_TEST(NAME)                                                                                              \
    static void NAME();                                                                                                \
    static ::tcpip2::test::Registrar NAME##_registrar(#NAME, &NAME);                                                   \
    static void NAME()

#define TCPIP2_TEST_MAIN()                                                                                             \
    int main() { return ::tcpip2::test::TestRegistry::Instance().RunAll() == 0 ? 0 : 1; }

#define TCPIP2_EXPECT_TRUE(cond)                                                                                       \
    do {                                                                                                               \
        if (!(cond))                                                                                                   \
            ::tcpip2::test::RecordFailure(__FILE__, __LINE__, #cond);                                                  \
    } while (0)

#define TCPIP2_EXPECT_FALSE(cond)                                                                                      \
    do {                                                                                                               \
        if (cond)                                                                                                      \
            ::tcpip2::test::RecordFailure(__FILE__, __LINE__, "!(" #cond ")");                                         \
    } while (0)

#define TCPIP2_EXPECT_EQ(a, b)                                                                                         \
    do {                                                                                                               \
        const auto tcpip2_va = (a);                                                                                    \
        const auto tcpip2_vb = (b);                                                                                    \
        if (!(tcpip2_va == tcpip2_vb)) {                                                                               \
            ::tcpip2::test::RecordFailure(__FILE__, __LINE__, #a " == " #b " (" #a " = " #b ")");                      \
        }                                                                                                              \
    } while (0)

#define TCPIP2_EXPECT_NE(a, b)                                                                                         \
    do {                                                                                                               \
        const auto tcpip2_va = (a);                                                                                    \
        const auto tcpip2_vb = (b);                                                                                    \
        if (!(tcpip2_va != tcpip2_vb)) {                                                                               \
            ::tcpip2::test::RecordFailure(__FILE__, __LINE__, #a " != " #b " (" #a " = " #b ")");                      \
        }                                                                                                              \
    } while (0)

#define TCPIP2_EXPECT_DEATH(stmt)                                                                                      \
    do {                                                                                                               \
        if (!::tcpip2::test::ExpectDeath([&] { stmt; }, #stmt)) {                                                      \
            ::tcpip2::test::RecordFailure(__FILE__, __LINE__, "expected death: " #stmt);                               \
        }                                                                                                              \
    } while (0)
