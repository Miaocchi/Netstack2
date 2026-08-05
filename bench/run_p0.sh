#!/bin/sh
# P0 benchmark skeleton. Wires the concrete benchmark binary once it lands;
# today it only validates the result schema against an example record.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# Validate JSON against the schema if a validator is available.
VALIDATE() {
    if command -v jq >/dev/null 2>&1; then
        # Minimal structural check; a full schema validator may be added later.
        jq -e '.schema_version == 1 and (.scenario | type == "string") and .metrics' "$1" >/dev/null
    fi
}

EXAMPLE="$ROOT/bench/example-record.json"
if [ ! -f "$EXAMPLE" ]; then
    echo "bench: no benchmark binary yet; example record absent, skipping." >&2
    exit 0
fi

if ! VALIDATE "$EXAMPLE"; then
    echo "bench: example record failed schema validation" >&2
    exit 1
fi
echo "bench: example record OK (skeleton; benchmark binary lands in P0)"
