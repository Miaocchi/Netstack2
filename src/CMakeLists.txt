# The libtcpip2 core. Sources are listed explicitly — no glob. The library
# depends only on the C++ standard library (plus pthreads via Threads).

include(../cmake/compiler_flags.cmake)

add_library(tcpip2 STATIC
    core/buffer.cpp
    core/buffer_pool.cpp
    core/flow_hash.cpp
    core/dispatcher.cpp
    core/shard.cpp
    core/runtime.cpp
    core/netstack.cpp
    core/thread_ownership.cpp
    core/timer_wheel.cpp
    packetio/null_io.cpp
    packetio/tap_io.cpp
    ip/checksum.cpp
    ip/ipv4.cpp
    ip/ipv6.cpp
    ip/icmpv4.cpp
    ip/icmpv6.cpp
    ip/pmtu.cpp
    ip/fragment.cpp
)

add_library(tcpip2::tcpip2 ALIAS tcpip2)
tcpip2_apply_common(tcpip2)

target_include_directories(tcpip2 PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include>"
)

find_package(Threads REQUIRED)
target_link_libraries(tcpip2 PUBLIC Threads::Threads)
