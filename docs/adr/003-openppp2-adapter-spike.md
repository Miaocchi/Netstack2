# ADR-003: OpenPPP2 Adapter Spike — Public API Validation

**Status:** Accepted
**Date:** 2026-08-07

## Context

The `NETSTACK2-API-FREEZE-001` gate requires a compile-only OpenPPP2 adapter
spike to prove that the public headers in `include/tcpip2/` are sufficient for
an external consumer (OpenPPP2) to wire a packet I/O backend and session
factory into Netstack2 — without depending on OpenPPP2, Boost, or
platform-specific types.

Before the spike, the public API was missing:

- Session creation interface (`ISessionFactory`, `TcpOpenRequest`,
  `UdpOpenRequest`, `IpEndpoint`, `FlowId`).
- Packet I/O capabilities negotiation (`PacketIoCapabilities`,
  `IPacketIo::Capabilities()`).
- IP address abstraction (`IpAddress`) and flow key (`FlowKey`) needed by the
  dispatcher and shard layers.

The spike was implemented in `tests/unit/openppp_adapter_spike_test.cpp` as a
compile-only `OpenPppPacketIo` (implementing `IPacketIo` + `IPacketQueue`) and
`OpenPppSessionFactory` (implementing `ISessionFactory`), using only public
headers.

## Decision

### 1. New public headers

The following headers are added to `include/tcpip2/` and become part of the
frozen public API:

| Header | Key types | Purpose |
|--------|-----------|---------|
| `address.h` | `IpAddress` (IPv4/IPv6 union, network-byte-order storage) | IP address abstraction for flow model and session requests |
| `flow.h` | `FlowKey`, `FlowHash()`, `FlowToShard()` | Bidirectional flow identifier with canonical hashing |
| `capabilities.h` | `PacketIoCapabilities`, `LinkMode`, `PollMode` | Backend capability declaration; core queries capabilities instead of branching on backend identity |
| `session_factory.h` | `FlowId`, `IpEndpoint`, `TcpOpenRequest`, `UdpOpenRequest`, `SessionOpenResult`, `DatagramOpenResult`, `ISessionFactory` | Session creation interface; external adapter implements routing policy |

### 2. IPacketIo interface change

`IPacketIo` gains a non-pure virtual `Capabilities()` returning
`PacketIoCapabilities` with sensible defaults (L3, 1500 MTU, single queue,
event mode, no offloads). Existing backends (`NullPacketIo`, `TapPacketIo`)
inherit the default; backends with different capabilities override.

### 3. FlowId unification

`FlowId` was previously defined in the private header `src/core/shard_message.h`.
The spike introduced a duplicate definition in the public `session_factory.h`.
To avoid ODR violations and duplication, `shard_message.h` now includes
`session_factory.h` and uses the public `FlowId`. The two definitions were
identical (`struct FlowId { uint64_t value; }` with `==`/`!=`), so the merge
is behavior-preserving.

### 4. Adapter spike scope

The spike validates that the public API is sufficient for:

- Implementing a multiqueue packet I/O backend (`OpenPppPacketIo` with
  configurable `queue_count`, `route_mark`, `fake_ip_base`, `dns_servers`,
  `quic_policy`, `pmtu`).
- Propagating backend configuration to `PacketIoCapabilities` (MTU,
  queue_count).
- Implementing a session factory with TCP/UDP open requests carrying full
  routing metadata (source, original/resolved destination, route_mark, DSCP).
- Wiring into `Netstack2::Start(IPacketIo*)` and `Stop()` lifecycle.

The spike does **not**:

- Send or receive real packets (stubs return WouldBlock / accept-all).
- Implement fake-IP resolution, Direct/Proxy routing, DNS, QUIC, or PMTU
  logic (these remain in the adapter, not in Netstack2 core).
- Validate platform-specific lifecycle (Wintun, iOS Data framework) — these
  are deferred to P4/P6.

## Consequences

- The public API is now sufficient for an external consumer to implement a
  packet I/O backend and session factory without private headers.
- `FlowId` has a single definition in `session_factory.h`; `shard_message.h`
  depends on the public header (no circular dependency — `session_factory.h`
  does not include `shard_message.h`).
- `IPacketIo::Capabilities()` is non-pure virtual; backends are not forced to
  override unless they need non-default capabilities.
- The `NETSTACK2-API-FREEZE-001` gate's adapter spike prerequisite is
  satisfied.

## Verification

- `openppp_adapter_spike_test` compiles and passes in all three build
  configurations (default, ASan, TSan): 19/19 tests green.
- `check_include_boundaries.sh` passes (no public header includes a private
  header).
- `compile_contract_test` passes (all public headers are self-contained and
  usable from a consumer TU).
- `git diff --check` clean (no whitespace issues).

## Future work

- P4: Real OpenPPP2 integration — replace stubs with functional
  `OpenPppPacketIo` that reads from `VEthernet` and writes via `ITap::Output`.
- P6: Platform adapter compile contracts (Android/iOS/Windows).
- Consider whether `RuntimeDependencies` (packing `IPacketIo*` +
  `ISessionFactory*` + `IClock*` + `IEventSink*` into a struct) should
  replace the current `Start(IPacketIo*)` signature at freeze time.
