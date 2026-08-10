# Integration tests. Each test is a standalone executable that exercises
# the full runtime (shard threads, packet I/O, TCP engine) end-to-end.

include(../../cmake/compiler_flags.cmake)

function(tcpip2_add_integration_test target)
    add_executable(${target} ${ARGN})
    tcpip2_apply_common(${target})
    target_link_libraries(${target} PRIVATE unit_support)
    add_test(NAME ${target} COMMAND ${target})
    # Watchdog: deadlocks must fail the test instead of hanging CI forever.
    set_tests_properties(${target} PROPERTIES TIMEOUT 120)
    # Allow new(std::nothrow) to return nullptr under sanitizers (arena failure test).
    set_tests_properties(${target} PROPERTIES ENVIRONMENT "ASAN_OPTIONS=allocator_may_return_null=1;TSAN_OPTIONS=allocator_may_return_null=1")
endfunction()

tcpip2_add_integration_test(openppp2_smoke_test openppp2_smoke_test.cpp)
