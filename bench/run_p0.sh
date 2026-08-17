#!/bin/sh
# P0 baseline benchmark orchestrator (bench/README.md).
#
# Builds are expected to have been configured with -DNETSTACK2_BUILD_BENCHMARKS=ON.
# Usage:
#   BUILD_DIR=<cmake build dir> ./bench/run_p0.sh
# Emits bench/runs/<timestamp>/record-<scenario>.json for every P0 scenario and
# validates each record against bench/record.json.schema (structural subset).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
BENCH_BIN="$BUILD_DIR/bench/bench_p0"

if [ ! -x "$BENCH_BIN" ]; then
    echo "bench: $BENCH_BIN not found; configure with -DNETSTACK2_BUILD_BENCHMARKS=ON and build" >&2
    exit 1
fi

RUN_DIR="$ROOT/bench/runs/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN_DIR"

GIT_REV=$(cd "$ROOT" && git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
export GIT_REV

echo "bench: run dir $RUN_DIR (git $GIT_REV)"
"$BENCH_BIN" --scenario all --out-dir "$RUN_DIR"

# Structural validation: every record must carry the schema's required fields
# and a positive ops_per_sec. A full JSON Schema validator is not required;
# this mirrors the checks run_p0.sh historically did with jq.
python3 - "$RUN_DIR" <<'EOF'
import json
import os
import sys

run_dir = sys.argv[1]
required = {"schema_version", "scenario", "git_rev", "date_utc", "params", "metrics"}
scenarios = {
    "null-rx", "null-tx", "pool-alloc-release", "timer-wheel-advance",
    "shard-dispatch",
}
failures = 0
for name in sorted(os.listdir(run_dir)):
    if not name.endswith(".json"):
        continue
    path = os.path.join(run_dir, name)
    with open(path, encoding="utf-8") as f:
        rec = json.load(f)
    problems = []
    if not required.issubset(rec.keys()):
        problems.append("missing fields: %s" % (required - set(rec.keys())))
    if rec.get("schema_version") != 1:
        problems.append("schema_version != 1")
    if rec.get("scenario") not in scenarios:
        problems.append("unknown scenario %r" % rec.get("scenario"))
    metrics = rec.get("metrics") or {}
    if "ops_per_sec" not in metrics or metrics["ops_per_sec"] <= 0:
        problems.append("ops_per_sec missing or <= 0")
    if problems:
        failures += 1
        print("bench: FAIL %s: %s" % (name, "; ".join(problems)))
    else:
        print("bench: OK   %s (%s)" % (name, rec["scenario"]))
if failures:
    print("bench: %d record(s) failed validation" % failures)
    sys.exit(1)
print("bench: all records OK")
EOF

echo "bench: done -> $RUN_DIR"
