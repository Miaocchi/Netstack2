# Netstack2

Multithreaded userspace IPv4/IPv6 TCP/IP engine.

> **API status: experimental.** Public signatures in `include/tcpip2/` are
> intentionally not frozen yet. They are validated by NETSTACK2-002
> (Buffer / Packet I/O), NETSTACK2-003 (Linux TapPacketIo) and NETSTACK2-004
> (Dispatcher / StackShard). After all three land and sanitizer/TSan gates
> pass, `NETSTACK2-API-FREEZE-001` freezes the public API; any signature
> change from that point on requires an ADR and a compatibility migration.

## Design invariants

- A `TcpFlow` (and, in general, any per-connection state) is owned and
  written by exactly one `StackShard` thread for its whole lifetime.
  Other threads may only post typed messages; they never get a writable
  flow pointer.
- Packet I/O is pluggable through `IPacketIo` / `IPacketQueue`
  (TUN/Wintun/utun/VpnService/AF_XDP/netmap/DPDK). Each hardware queue is
  bound to exactly one owner thread. The primary kernel-bypass backend for TCP
  is a BPF (XDP/AF_XDP) driver; see `docs/architecture/packet_io_backends.md`.
- Remote transport is pluggable through `ITransportSession`
  (kernel socket, Onload socket, userspace DPDK/EfVi backends).
- The core library depends on nothing but the C++ standard library.

## Layout

```
include/tcpip2/     public API (experimental)
src/core/           dispatcher, shard, timer wheel, buffer pool
src/ip/             IPv4/IPv6/ICMP/checksum
src/tcp/            TCP state machine, input, output, recovery
src/session/        transport session adapters
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
| NETSTACK2-002H Buffer / Packet I/O hardening | ready |
| NETSTACK2-003 Linux TUN/TAP packet I/O backend | ready after 002H |
| NETSTACK2-004 Dispatcher / StackShard | ready after 002H |
| NETSTACK2-API-FREEZE-001 | blocked by 002H / 003 / 004 / adapter spike |
| P3A / P3B / P3C (IP layer, TCP state machine, interop) | planned |

See `docs/IMPLEMENTATION_GUIDE.md` for the file-level implementation plan and
`bench/README.md` for the P0 baseline measurement protocol.
