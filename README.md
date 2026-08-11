# Netstack2

Multithreaded userspace IPv4/IPv6 TCP/IP engine.

> **API status: v0.3.0.** ADR-008 supersedes the v0.2.0 signatures that could
> not express callback ownership or deadline-aware shutdown. `Stop()` now
> returns `StopResult`; statement-style v0.2.0 calls remain source compatible.

## Design invariants

- A `TcpFlow` (and, in general, any per-connection state) is owned and
  written by exactly one `StackShard` thread for its whole lifetime.
  Other threads may only post typed messages; they never get a writable
  flow pointer.
- Packet I/O is pluggable through `IPacketIo` / `IPacketQueue`
  (TUN/Wintun/utun/VpnService/AF_XDP/netmap/DPDK). Each hardware queue is
  bound to exactly one owner thread. TX queue selection is deterministic from
  the canonical flow hash; protocol shards hand packets for foreign-owned
  queues through bounded egress lanes and never call those queues directly.
  The primary kernel-bypass backend for TCP is a BPF (XDP/AF_XDP) driver; see
  `docs/architecture/packet_io_backends.md`.
- Remote transport is pluggable through `ITransportSession`
  (kernel socket, Onload socket, userspace DPDK/EfVi backends).
- The core library depends on nothing but the C++ standard library.
- Shutdown enters `Stopping` before RX is closed. A failed or timed-out drain
  retains queues and pools for a later `Stop()` retry; no pool is destroyed
  while a backend or callback can retain a lease.

## Layout

```
include/tcpip2/     public API (v0.3.0)
src/core/           dispatcher, shard, timer wheel, buffer pool
src/ip/             IPv4/IPv6/ICMP/checksum
src/tcp/            TCP state machine, input, output, recovery, congestion (AIMD/BBR/KCC), FQ-CoDel
src/session/        transport session adapters (TcpSession)
src/packetio/       null / TAP / AF_XDP / netmap / DPDK backends
tests/unit/         unit tests (+ support harness)
bench/              P0 measurement protocol and result format
```

## Build

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Sanitizer variants (mutually exclusive):

```sh
bash scripts/build-asan.sh
bash scripts/build-tsan.sh
```

## Milestones

| Milestone | Status |
|-----------|--------|
| NETSTACK2-000 repository + test base | done |
| NETSTACK2-002 Buffer / Packet I/O contracts | done |
| NETSTACK2-002H Buffer / Packet I/O hardening | done |
| NETSTACK2-003 Linux TUN/TAP packet I/O backend | done |
| NETSTACK2-004 Dispatcher / StackShard | done |
| NETSTACK2-ADAPTER-SPIKE OpenPPP2 compile-only adapter | done |
| NETSTACK2-API-FREEZE-001 public API freeze (v0.2.0) | done |
| ADR-008 v0.3 API correctness reset | in progress |
| P3A IP layer (IPv4/IPv6/ICMP/fragment reassembly) | done |
| P3B TCP state machine (handshake/send/receive/close) | done |
| P3C congestion control (AIMD/BBR/KCC/pacer/FQ-CoDel/TcpSession) | in progress |
| P3U UDP flow and datagram session | done |
| P3I ICMP shard RX wiring + PMTU | done |
| P4 OpenPPP2 integration | in progress |
| P5–P7 high-perf I/O, platform spread, tuning | planned |

See `docs/IMPLEMENTATION_GUIDE.md` for the file-level implementation plan and
`bench/README.md` for the P0 baseline measurement protocol.
