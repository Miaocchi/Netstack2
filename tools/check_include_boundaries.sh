#!/bin/sh
# Enforce include boundaries for the libtcpip2 core.
#
# Rules:
#   * Public headers (include/tcpip2/*.h) and core sources (src/**/*.cpp)
#     may only include:
#       - other project headers via  <tcpip2/...>  or  "src-relative"   (src/...)
#       - C++ standard library headers  <...>
#   * They must NOT include quoted relative headers (hides dependencies),
#     nor any third-party header (boost/, openssl/, asio/, ppp/, lwip/, ...).
#
# Exit code 0 = clean, 1 = violations found.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
status=0

# Third-party include prefixes that are forbidden in the core.
FORBIDDEN='boost/ openssl/ asio/ ppp/ lwip/ zlib.h jemalloc/'

check_file() {
    file=$1
    # shellcheck disable=SC2013
    for inc in $(grep -E '^[[:space:]]*#include[[:space:]]+' "$file" | sed -E 's/^[[:space:]]*#include[[:space:]]+//'); do
        for f in $FORBIDDEN; do
            case "$inc" in
                "<$f"*) echo "FAIL $file: forbidden include $inc" ; status=1 ;;
            esac
        done
        case "$inc" in
            '"'*)
                echo "FAIL $file: quoted relative include $inc"
                status=1
                ;;
        esac
    done
}

for f in "$ROOT"/include/tcpip2/*.h; do
    check_file "$f"
done
for f in "$ROOT"/src/core/*.cpp "$ROOT"/src/packetio/*.cpp "$ROOT"/src/ip/*.cpp; do
    check_file "$f"
done

if [ "$status" -eq 0 ]; then
    echo "include boundary check: OK"
fi
exit "$status"
