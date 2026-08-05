#!/bin/sh
# NETSTACK2-000 build + test entry point (plain).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CXX=${CXX:-}
if [ -z "$CXX" ] && command -v clang++ >/dev/null 2>&1; then
    CXX=clang++
fi
CMAKE_ARGS="-G Ninja"
if [ -n "$CXX" ]; then
    CMAKE_ARGS="$CMAKE_ARGS -DCMAKE_CXX_COMPILER=$CXX"
fi
cmake -S "$ROOT" -B "$ROOT/build" $CMAKE_ARGS
cmake --build "$ROOT/build"
ctest --test-dir "$ROOT/build" --output-on-failure
