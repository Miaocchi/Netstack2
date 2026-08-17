# Netstack2 Bench — P0 Baseline Protocol

> Status: implemented (P0). `bench/bench_p0.cpp` implements all five scenarios;
> `bench/run_p0.sh` runs them and validates the records.

## Goal

Establish a repeatable baseline for the multithreaded engine before protocol
milestones (IP layer, TCP state machine, interop) land. Baseline numbers are
not an SLA; they exist to catch gross regressions and to size the packet I/O
backends (see `docs/architecture/packet_io_backends.md`).

## What is measured

- RX/TX throughput for `IPacketIo` backends (null first; BPF/XDP in
  NETSTACK2-003).
- Buffer pool allocate/release rate (single-thread and cross-thread release).
- Timer wheel insert/advance/cancel rate.
- Per-shard CPU utilisation when dispatching synthetic RX batches.

All measurements are single-queue first; multi-queue scaling is a P3 concern.

## Result format

Every run emits one JSON record per scenario, conforming to `record.json.schema`
(`bench/runs/<timestamp>/record-<scenario>.json`). Runs are immutable: never
edit a committed run, add a new one.

## Running

```sh
cmake -S . -B build -G Ninja -DNETSTACK2_BUILD_BENCHMARKS=ON
cmake --build build --target bench_p0
BUILD_DIR=build ./bench/run_p0.sh
```

The orchestrator stamps each record with the git revision, runs every scenario,
and structurally validates the records. In CI this is the `bench` job in
`.github/workflows/ci.yml`; its records are uploaded as artifacts. No
pass/fail threshold is enforced yet — CI runners are too noisy for absolute
numbers — so the gate catches broken builds and invalid records, and the
artifacts accumulate the baseline.
