# Netstack2 Bench — P0 Baseline Protocol

> Status: skeleton (NETSTACK2-000). The executable benchmark tooling lands with
> the P0 milestone; this directory defines the measurement protocol and result
> format now so later milestones can be compared against a fixed baseline.

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

Every run emits one JSON record per test, conforming to `record.json.schema`.
A run is a directory (`runs/<timestamp>/`) containing `record.json` plus any
captures. Runs are immutable: never edit a committed run, add a new one.

## Reference command

`./bench/run_p0.sh` is the skeleton orchestrator; it is wired to the concrete
benchmark binary in the P0 milestone. Today it only validates the result
schema against an example record.
