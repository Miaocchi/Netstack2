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
    # Allow new(std::nothrow) to return nullptr under sanitizers (arena failure test).
    set_tests_properties(${target} PROPERTIES ENVIRONMENT "ASAN_OPTIONS=allocator_may_return_null=1;TSAN_OPTIONS=allocator_may_return_null=1")
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
tcpip2_add_unit_test(tap_io_test tap_io_test.cpp)
tcpip2_add_unit_test(flow_hash_test flow_hash_test.cpp)
tcpip2_add_unit_test(inbox_test inbox_test.cpp)
tcpip2_add_unit_test(dispatcher_test dispatcher_test.cpp)
tcpip2_add_unit_test(shard_runtime_test shard_runtime_test.cpp)
tcpip2_add_unit_test(runtime_test runtime_test.cpp)
tcpip2_add_unit_test(openppp_adapter_spike_test openppp_adapter_spike_test.cpp)
tcpip2_add_unit_test(checked_test ip/checked_test.cpp)
tcpip2_add_unit_test(checksum_test ip/checksum_test.cpp)
tcpip2_add_unit_test(ipv4_parser_test ip/ipv4_parser_test.cpp)
tcpip2_add_unit_test(ipv6_parser_test ip/ipv6_parser_test.cpp)
tcpip2_add_unit_test(icmpv6_test ip/icmpv6_test.cpp)
tcpip2_add_unit_test(pmtu_test ip/pmtu_test.cpp)
tcpip2_add_unit_test(icmpv4_parser_test ip/icmpv4_parser_test.cpp)
tcpip2_add_unit_test(fragment_test ip/fragment_test.cpp)
tcpip2_add_unit_test(tcp_handshake_test tcp/handshake_test.cpp)
