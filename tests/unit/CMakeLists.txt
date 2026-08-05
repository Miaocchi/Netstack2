# Unit tests. Each test is a standalone executable; death tests (double
# release, ownership violations) fork a child process internally.

include(../../cmake/compiler_flags.cmake)

# Shared unit-test harness: registry, death tests, packet builder/parser, pcap.
add_library(unit_support STATIC
    support/PacketBuilder.cpp
    support/Pcap.cpp
)
tcpip2_apply_common(unit_support)
target_include_directories(unit_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/support)
target_link_libraries(unit_support PUBLIC tcpip2::tcpip2)

function(tcpip2_add_unit_test target)
    add_executable(${target} ${ARGN})
    tcpip2_apply_common(${target})
    target_link_libraries(${target} PRIVATE unit_support)
    add_test(NAME ${target} COMMAND ${target})
    # Watchdog: deadlocks must fail the test instead of hanging CI forever.
    set_tests_properties(${target} PROPERTIES TIMEOUT 120)
endfunction()

tcpip2_add_unit_test(buffer_pool_test buffer_pool_test.cpp)
tcpip2_add_unit_test(buffer_slice_test buffer_slice_test.cpp)
tcpip2_add_unit_test(buffer_ref_test buffer_ref_test.cpp)
tcpip2_add_unit_test(timer_wheel_test timer_wheel_test.cpp)
tcpip2_add_unit_test(packet_builder_parser_test packet_builder_parser_test.cpp)
tcpip2_add_unit_test(pcap_test pcap_test.cpp)
tcpip2_add_unit_test(packet_io_contract_test packet_io_contract_test.cpp)
tcpip2_add_unit_test(shard_ownership_test shard_ownership_test.cpp)
tcpip2_add_unit_test(config_test config_test.cpp)
tcpip2_add_unit_test(compile_contract_test compile_contract_test.cpp)
tcpip2_add_unit_test(static_assert_test static_assert_test.cpp)
tcpip2_add_unit_test(thread_ownership_test thread_ownership_test.cpp)
