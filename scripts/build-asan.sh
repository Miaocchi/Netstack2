#!/bin/sh
# ASan + UBSan build/test (mutually exclusive with TSan).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CXX=${CXX:-}
if [ -z "$CXX" ] && command -v clang++ >/dev/null 2>&1; then
    CXX=clang++
fi
CMAKE_ARGS="-G Ninja -DENABLE_SANITIZERS=ON"
if [ -n "$CXX" ]; then
    CMAKE_ARGS="$CMAKE_ARGS -DCMAKE_CXX_COMPILER=$CXX"
fi
cmake -S "$ROOT" -B "$ROOT/build-asan" $CMAKE_ARGS
cmake --build "$ROOT/build-asan"
ctest --test-dir "$ROOT/build-asan" --output-on-failure
