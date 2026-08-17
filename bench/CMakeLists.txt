# P0 baseline benchmark (bench/README.md). Built only when
# NETSTACK2_BUILD_BENCHMARKS=ON so the default build stays lean.
include(../cmake/compiler_flags.cmake)

add_executable(bench_p0 bench_p0.cpp)
tcpip2_apply_common(bench_p0)
target_link_libraries(bench_p0 PRIVATE tcpip2::tcpip2)
