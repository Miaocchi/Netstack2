# ADR-008: API Correctness Reset for R0-R3

**Status:** Accepted
**Date:** 2026-08-12
**Supersedes:** ADR-004 API signatures where they prevent R0-R3 correctness

## Context

ADR-004 froze v0.2.0 before the TCP Session data direction, multi-queue
ownership, and asynchronous TX shutdown semantics were proven in production.
The frozen `DataCallback`, untyped UDP result, and `void Stop()` cannot express
the ownership, backpressure, and teardown results required by R0-R3.

The repository contains no released consumer or compatibility target for
v0.2.0. The OpenPPP2 test is an in-repository spike, not a shipped adapter.

## Decision

Netstack2 moves to a source-breaking v0.3.0 contract. There is one internal
implementation; no v0.2 compatibility wrappers are retained.

1. `DataCallback` returns `ReceiveStatus` (`Accepted`, `WouldBlock`, or
   `Closed`) and receives `BufferLease&`. `Accepted` requires moving the lease
   out; `WouldBlock` leaves ownership with the session; `Closed` rejects it.
2. `ITransportSession` adds `ResumeReceive()`. The stack invokes it only after
   remote-data backlog falls below the documented low watermark.
3. `SessionOpenResult::session` becomes `std::shared_ptr<ITransportSession>`.
   The factory and stack may retain references until callback quiescence.
4. `DatagramOpenResult` is replaced by a typed `IDatagramSession`; UDP flow
   work may not use `void*` handles.
5. `Netstack2::Stop()` gains a result-bearing v0.3 entry point. A timeout
   leaves the instance in `Stopping`, retains its Runtime/pools, and permits a
   later drain. Destruction performs a final unbounded cancel/drain.
6. `IPacketQueue::StopRx`, `DrainTx`, and `OutstandingTx` are part of the
   public shutdown contract. `DrainTx` must either release every accepted lease
   or report why resources remain owned.
7. Queue ownership and protocol ownership are distinct. RX packets are
   classified by canonical flow or fragment key before a protocol PCB is
   touched; cross-shard packets move through bounded typed lanes.

### Shutdown contract

`StopResult Stop(const StopOptions&)` is the v0.3 entry point; no-argument
`Stop()` returns the same result with a finite 5000 ms default. Ignoring that
return value preserves normal statement-style source callers. `timeout_ms` is
the total shutdown budget; zero requests the destructor-only unbounded final
completion/cancel path. `TimedOut` and `DrainFailed` retain queues and pools in
`Stopping`, with the first backend error, queue id, and remaining TX/buffer
counts for diagnosis. Only `Stopped` permits resource destruction.

Shutdown order is fixed: mark `Stopping`; clear handlers and `StopRx`;
deactivate and clear Session callbacks after in-flight callback posts quiesce;
stop and join shards; release shard/lane work; drain every queue TX; drain pool
return queues; verify all outstanding buffers are zero; then destroy queues and
pools.

## Migration

All in-repository `ITransportSession`, `ISessionFactory`, and `IPacketQueue`
implementations must be updated in the same change as their contract tests.
`compile_contract_test.cpp` is the consumer compatibility gate for v0.3. The
OpenPPP2 spike must compile against v0.3 before it can claim any integration.

## Consequences

R1 cannot be considered complete until callback backpressure and remainder
ownership are implemented. R2 cannot be considered complete until production
RX invokes the classifier and bounded lanes. R3 cannot be considered complete
until timeout/failure results are observable by callers.
