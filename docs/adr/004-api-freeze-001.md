# ADR-004: NETSTACK2-API-FREEZE-001 — Public API Freeze

**Status:** Accepted
**Date:** 2026-08-07
**Supersedes:** — (finalizes the "Experimental API" phase referenced by all public headers)

## Context

`NETSTACK2-API-FREEZE-001` is the gate that transitions the public API from
experimental to frozen. After this point, any signature change to a public
header requires a new ADR, a compatibility analysis, a migration path, and an
update to the consumer compile-contract test.

All prerequisites are satisfied:

- **NETSTACK2-002 / 002H** (Buffer + Packet I/O) — Completed.
- **NETSTACK2-003** (Linux TapPacketIo) — Completed.
- **NETSTACK2-004** (Dispatcher + StackShard) — Completed.
- **NETSTACK2-ADAPTER-SPIKE** (OpenPPP2 compile-only adapter) — Completed (ADR-003).
- **TUN multiqueue Tier 2** — Satisfied (ADR-002: `TapMultiqueueTier2RootTest`
  passes as root, 4-queue TUN, UDP-to-self, all three build configurations).
- **Buffer pool ownership** — Satisfied (ADR-001 v2: per-shard pool,
  `SetBufferPool` pure virtual, `SetOwnerThread` called in `Shard::Run()`).
- **Config overflow guards** — `NetstackConfig::Validate()` and
  `PktBufferPool` constructor both check `slot_count * slot_capacity` and
  `total_slots * pool_slot_capacity` against `UINT64_MAX` and a 4 GiB cap.

## Decision

### 1. Frozen public header inventory (10 headers)

All headers reside in `include/tcpip2/`. No header outside this directory is
part of the public API.

| # | Header | Key frozen types | Frozen semantics |
|---|--------|-----------------|-------------------|
| 1 | `address.h` | `IpAddress` | IPv4/IPv6 union; network byte order; `Family` enum; `Ipv4()`/`Ipv6()` factories; `==`/`!=`/`<` |
| 2 | `buffer.h` | `PktBuffer`, `BufferLease`, `BufferSlice`, `BufferRef`, `TxSegment`, `PktBufferPool` | Move-only `BufferLease` (noexcept); trivially copyable `BufferSlice`; copyable RAII `BufferRef`; `PktBufferPool` with `Allocate`/`Retain`/`ReturnBuffer`/`DrainReturnQueue`/`SetOwnerThread` |
| 3 | `capabilities.h` | `LinkMode`, `PollMode`, `PacketIoCapabilities` | L2/L3, Polling/Event; mtu/headroom/queue_count/poll_mode/offload flags/scatter_gather/gso/gro/tso/async_tx/zero_copy |
| 4 | `config.h` | `NetstackConfig` | shard_count, rx_queue_count, rx_queue_to_shard, pool_slot_count/capacity, TCP params; `Validate()` with uint64_t overflow guards + 4 GiB cap |
| 5 | `flow.h` | `FlowKey`, `FlowHash()`, `FlowToShard()` | FNV-1a canonical hashing; bidirectional flow identity |
| 6 | `netstack.h` | `Netstack2` | ctor(`NetstackConfig`); `Start(IPacketIo*)`; `Stop()`; `IsRunning()`; `GetRuntime()`; `Config()` |
| 7 | `packet_io.h` | `IoError`, `IPacketQueue`, `IPacketIo`, `NullPacketIo` | Pure virtual `RecvBatch`/`SendBatch`/`QueueId`/`SetBufferPool`/`SetRecvHandler`; non-pure `Capabilities()` default; `NullPacketIo` test backend |
| 8 | `session_factory.h` | `FlowId`, `IpEndpoint`, `TcpOpenRequest`, `UdpOpenRequest`, `SessionOpenResult`, `DatagramOpenResult`, `ISessionFactory` | `FlowId` trivially copyable; pure virtual `OpenTcp`/`OpenUdp` |
| 9 | `tap_io.h` | `TapPacketIo` | final; `Config` struct; `Open()`/`Close()`/`IsOpen()`; multi-queue via `IFF_MULTI_QUEUE` |
| 10 | `transport_session.h` | `SessionError`, `SendStatus`, `SendResult`, `BufferView`, callback typedefs, `ITransportSession` | Trivially copyable `BufferView`; pure virtual `TrySend`/`ShutdownWrite`/`Abort`/`SetWritableCallback`/`SetDataCallback`/`SetClosedCallback` |

### 2. Frozen type properties (enforced by `compile_contract_test.cpp`)

The consumer compile-contract test pins the following `static_assert`
properties. Any change that violates them is a freeze violation:

- `BufferLease`: move-only, `noexcept` move.
- `BufferSlice`: trivially copyable.
- `BufferRef`: copyable, moveable.
- `PktBuffer`: standard layout.
- `BufferView`: trivially copyable.
- `IpAddress`: copyable, standard layout.
- `FlowKey`: copyable, standard layout.
- `FlowId`: trivially copyable, standard layout.
- `IpEndpoint`: copyable, standard layout.
- `TcpOpenRequest`, `UdpOpenRequest`, `SessionOpenResult`,
  `DatagramOpenResult`: copyable.
- `PacketIoCapabilities`: copyable, standard layout.
- `NetstackConfig`: copyable.

### 3. Frozen behavioral semantics

Beyond type signatures, the following behavioral contracts are frozen:

1. **Buffer ownership transfer**: `RecvBatch` returns `n` → transfers
   `out[0..n-1]` to caller. `SendBatch` returns `n` → transfers
   `packets[0..n-1]` to backend; `n < count` is a legal partial send, not an
   error.
2. **`SetBufferPool` is pure virtual**: every `IPacketQueue` implementation
   must override. A backend that forgets pool injection will not compile.
3. **Per-shard pool model**: `Runtime` creates `shard_count` independent
   `PktBufferPool` instances, each with `pool_slot_count` slots. Each queue
   is injected with the pool of the shard that owns it
   (`config.rx_queue_to_shard[queue_id]`).
4. **`SetOwnerThread`**: called at the start of `StackShard::Run()`,
   designating the shard thread as the pool's owner. `Allocate()` and
   `DrainReturnQueue()` on the owner thread are uncontended (mutex acquired,
   but no cross-shard contention).
5. **`DrainReturnQueue`**: every shard calls this at the top of each event
   loop iteration to recycle buffers returned by foreign threads.
6. **`Netstack2::Start(nullptr)`**: validates config only, does not create a
   runtime. `Start(IPacketIo*)` creates the runtime and per-shard pools.
7. **`Stop()` is idempotent**: safe to call from any thread; joins all shard
   threads; never joins on the shard's own thread.
8. **`NullPacketIo`**: test backend with `Inject`/`SetMaxSendPerBatch`/
   `SetRecvWouldBlock`/`SetSendWouldBlock`/`SetAsyncTxCompletion`/
   `DrainTxCompletions`/`PendingTxCompletions`/`Egress`.
9. **Config overflow**: `NetstackConfig::Validate()` and `PktBufferPool`
   constructor both guard against arithmetic overflow in
   `slot_count * slot_capacity` and `total_slots * pool_slot_capacity`,
   with a hard 4 GiB cap on total buffer memory.
10. **Flow hashing**: FNV-1a over canonical bytes (family byte + address
    bytes + big-endian port bytes + protocol byte). Canonical ordering
    ensures bidirectional flows map to the same shard.

### 4. Header comment convention

All 10 public headers now carry the comment:

```
Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
require an ADR and a consumer compile-contract test update.
```

The previous "Experimental API (NETSTACK2-XXX) ... signatures may change
until NETSTACK2-API-FREEZE-001" comments have been removed.

## Test evidence

**Base commit**: see git tag `v0.2.0`

**Compiler**: Clang 19.1.7, C++17
**Flags**: `-Werror=return-type -Wall -Wextra -Wpedantic -Wshadow -Wconversion`

### Default build

```
cmake --build build
cd build && ctest --output-on-failure
```

Result: **19/19 PASS** (0.60s)

| # | Test | Result |
|---|------|--------|
| 1 | buffer_pool_test | Passed |
| 2 | buffer_slice_test | Passed |
| 3 | buffer_ref_test | Passed |
| 4 | timer_wheel_test | Passed |
| 5 | packet_builder_parser_test | Passed |
| 6 | pcap_test | Passed |
| 7 | packet_io_contract_test | Passed |
| 8 | shard_ownership_test | Passed |
| 9 | config_test | Passed |
| 10 | compile_contract_test | Passed |
| 11 | static_assert_test | Passed |
| 12 | thread_ownership_test | Passed |
| 13 | tap_io_test | Passed (incl. root TUN Tier 2) |
| 14 | flow_hash_test | Passed |
| 15 | inbox_test | Passed |
| 16 | dispatcher_test | Passed |
| 17 | shard_runtime_test | Passed |
| 18 | runtime_test | Passed |
| 19 | openppp_adapter_spike_test | Passed |

### ASan + UBSan build

```
cmake --build build-asan
cd build-asan && ctest --output-on-failure
```

Result: **19/19 PASS** (1.72s)

### TSan build

```
cmake --build build-tsan
cd build-tsan && ctest --output-on-failure
```

Result: **19/19 PASS** (1.60s)

### Root TUN Tier 2 (ADR-002)

`TapMultiqueueTier2RootTest` runs as root in all three build configurations:

- Opens a 4-queue TUN device (`IFF_MULTI_QUEUE`).
- Opens all 4 queues.
- Arms each queue with a per-shard buffer pool and recv handler.
- Configures interface `10.222.0.1/24`.
- Injects a UDP datagram to the interface's own address.
- Polls all 4 queue fds for reception.
- Verifies clean close.

In non-root environments the test skips gracefully (never fails).

### Static checks

- `tools/check_include_boundaries.sh` — **OK** (no public header includes a
  private header).
- `git diff --check` — **CLEAN** (no whitespace issues).

## Not in freeze scope

The following items are explicitly **not** part of the frozen API and may
change in P3A or later without a freeze-violation ADR:

1. **`stats.h`**: listed in the file layout but not yet implemented. Not
   part of the frozen API.
2. **QoS/AQM config structs**: `FqCoDelConfig`, `AqmConfig`, etc. are not
   yet defined. They will be added as new public headers in P3Q.
3. **Private headers** (`src/core/*.h`): not frozen. The `static_assert_test`
   uses `#include <core/shard.h>` to pin private type properties; this is a
   supplementary check, not part of the public freeze.

**`Netstack2::Start(IPacketIo*)` is frozen.** If P3A requires replacing it
with `Start(RuntimeDependencies)` (packing `IPacketIo*` + `ISessionFactory*`
+ `IClock*` + `IEventSink*`), the change must follow the post-freeze change
procedure below: a new ADR, a compatibility analysis, a migration path, and
an update to the consumer compile-contract test. There is no blanket
exemption.

## Post-freeze change procedure

Any change to a frozen public header must:

1. **File an ADR** describing the change, rationale, and compatibility impact.
2. **Provide a migration path** for existing consumers (including
   `compile_contract_test.cpp` and `openppp_adapter_spike_test.cpp`).
3. **Update the consumer compile-contract test** to reflect the new
   signatures/properties.
4. **Run all three build configurations** (default, ASan, TSan) to verify
   no regressions.
5. **Record the change in `docs/roadmap.md`** §2 commit/tag table.

## Consequences

- The public API is stable. P3A protocol implementation can proceed without
  drifting public interfaces.
- `compile_contract_test.cpp` serves as the freeze guard: any signature
  change that violates a frozen `static_assert` will fail compilation.
- The "Experimental API" era is over. Consumers can depend on the headers
  with confidence that changes require an ADR.
- The next version tag `v0.2.0` will be placed on the freeze commit.
