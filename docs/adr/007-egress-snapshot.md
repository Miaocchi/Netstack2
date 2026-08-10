# ADR-007: Add NullPacketIo::EgressSnapshot() for thread-safe egress access

**Status:** Accepted
**Date:** 2026-08-10
**Related:** ADR-004 (NETSTACK2-API-FREEZE-001)

## Context

`NullPacketIo::Egress(queue_id)` returns a `const std::vector<std::vector<std::uint8_t>>&`
reference to the internal egress capture. The implementation acquires the internal
mutex to return the reference, but the caller then reads the vector outside the lock.
Meanwhile, the shard thread (via `NullQueue::SendBatch()`) acquires the same mutex and
mutates the egress vector. This produces a TSan data race:

- **Thread T1 (shard):** `SendBatch()` → `egress.emplace_back(...)` (holds mutex)
- **Thread T2 (test main):** `Egress(0).size()` / iteration (no mutex held)

The existing `Egress()` method is frozen at NETSTACK2-API-FREEZE-001. Its signature
and semantics cannot change without this ADR.

## Decision

1. **Add a new method** `EgressSnapshot(std::size_t queue_id) const` returning
   `std::vector<std::vector<std::uint8_t>>` by value. The implementation acquires the
   internal mutex, copies the egress vector, and returns the copy. This is safe to call
   from any thread.

2. **Keep `Egress()` unchanged** for backward compatibility. Existing callers that
   access `Egress()` from a single thread (e.g., contract tests that stop the shard
   before inspecting egress) continue to work.

3. **Update all multi-threaded callers** (integration tests, any code that inspects
   egress while the runtime is running) to use `EgressSnapshot()` instead of `Egress()`.

### Rationale

Adding a new method is an additive change to a frozen header. It does not break any
existing consumer or change frozen type properties. The `compile_contract_test` does
not need modification (no existing `static_assert` is affected). This follows the
post-freeze change procedure: ADR filed, compatibility analysis (additive only),
migration path (use `EgressSnapshot()` in multi-threaded contexts).

## Compatibility Analysis

| Aspect | Impact |
|--------|--------|
| ABI | Additive — new virtual not added (NullPacketIo is `final`, not virtual). New non-virtual method. No vtable change. |
| Source | Additive — existing code that calls `Egress()` still compiles and works. |
| Frozen properties | No change — `NullPacketIo` is `final`; no new `static_assert` needed. |
| Consumer contract test | No change needed. |

## Migration Path

- Multi-threaded callers: replace `io.Egress(q)` with `io.EgressSnapshot(q)`.
- Single-threaded callers (post-`Stop()`): can keep using `Egress()` or migrate;
  both are safe when no shard thread is running.

## Test Plan

All existing tests continue to pass. The new `openppp2_smoke_test` uses
`EgressSnapshot()` and passes under TSan.
