# Packet I/O Backends — Design Direction

> **Status:** direction (recorded for NETSTACK2-000; ratified by the packet I/O
> contract in NETSTACK2-002 and the AF_XDP backend in NETSTACK2-003).
> Not an ADR yet; an ADR is required before `NETSTACK2-API-FREEZE-001`.

## Decision

For TCP traffic the primary kernel-bypass packet I/O backend is a **BPF
driver** — an XDP/AF_XDP-based eBPF path — rather than a pure TAP device.

Consequences:

- `IPacketIo` / `IPacketQueue` (see `include/tcpip2/packet_io.h`) stay the only
  seam between the engine and the NIC; the BPF backend is one more
  `IPacketIo` implementation, not a fork in the ownership rules.
- RX queues are still bound to exactly one owner shard thread; the BPF driver
  does not change the thread-ownership invariant.
- AF_XDP zero-copy buffers must be adapted into `PktBufferPool` leases (or a
  dedicated zero-copy pool later). The lease/ref ownership model in
  `include/tcpip2/buffer.h` must not be bypassed.
- TAP/Wintun/utun/VpnService/netmap/DPDK remain supported alternatives; BPF is
  the default kernel-bypass path on Linux.

## Kernel hairpin NAT

Traffic that hairpins — a client and a server behind the same NAT gateway
reaching each other through the public address — must loop back through the
same host. The direction is:

- **Rely on kernel hairpin NAT** to rewrite the hairpinned flow, rather than
  implementing NAT inside the userspace engine.
- The engine must therefore be able to see packets that re-enter through the
  same interface/queue that they left (RX after TX on the same queue) without
  deadlock or ownership confusion: a lease that leaves via `SendBatch()` may
  legitimately come back via `RecvBatch()` on the same `IPacketQueue`.
- NETSTACK2-003 must add a contract test for the hairpin path (echo a packet
  into the same queue it was sent from and verify the engine treats it as a
  fresh RX packet with a fresh lease).

## Scope

This note captures direction only. Backend-specific design (XDP program layout,
UMEM/pool wiring, hairpin test vectors) is deferred to NETSTACK2-003.
