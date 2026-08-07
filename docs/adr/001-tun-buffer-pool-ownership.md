# ADR-001: TUN Packet I/O Buffer Pool Ownership

**Status:** Accepted
**Date:** 2026-08-07
**Updated:** 2026-08-07 (per-shard pool model)
**Supersedes:** `GlobalTapPool()` pattern in NS2-003

## Context

NS2-003 introduced `TapQueue::RecvBatch()` which allocates `BufferLease`
objects for incoming TUN packets. The original implementation used a
process-global static pool:

```cpp
PktBufferPool& GlobalTapPool() {
    static PktBufferPool pool(256, 2048);
    return pool;
}
```

This created a **pool ownership mismatch**:

1. `Runtime::Start()` creates one `PktBufferPool` (the "runtime pool") and
   passes it to each `StackShard`. The shard calls `pool_.DrainReturnQueue()`
   every event-loop iteration to recycle buffers returned on foreign threads.

2. `TapQueue::RecvBatch()` allocated leases from `GlobalTapPool()`, **not** the
   runtime pool. These leases' `owner_pool` pointer points to `GlobalTapPool`.

3. When a lease is `Reset()` on the shard thread (a non-owner thread for
   `GlobalTapPool`), the buffer is pushed into `GlobalTapPool`'s
   `return_queue_`.

4. **Nobody drains `GlobalTapPool`'s `return_queue_`.** The shard only drains
   the runtime pool. Over time, returned buffers accumulate in
   `GlobalTapPool`'s return queue, effectively leaking all pool slots.

5. Additionally, `GlobalTapPool()` introduced a global mutex (`PktBufferPool`
   has a `std::mutex mutex_`), creating lock contention that conflicts with
   the per-shard owner-pool model where each shard owns its pool
   independently.

This is a real design defect, not a theoretical concern: in any production
deployment where TUN receives packets and the shard processes and releases
them, the pool exhausts within seconds.

## Decision (original: ADR-001 v1)

**Remove `GlobalTapPool()` entirely. Inject the runtime pool into
`TapQueue` via a new `IPacketQueue::SetBufferPool()` virtual method.**

### Interface change

```cpp
// packet_io.h — IPacketQueue
virtual void SetBufferPool(PktBufferPool* pool) noexcept = 0;
```

`SetBufferPool` is **pure virtual**: every concrete `IPacketQueue` must
override it. This prevents a backend from silently compiling without pool
injection, which would reintroduce the leak. Backends that do not allocate
from a pool (e.g. `NullQueue`) store the pointer but are not obligated to use
it.

### Runtime wiring (original)

`Runtime::Start()` calls `q->SetBufferPool(pool)` immediately after
`OpenQueue()` and before the shard thread starts:

```cpp
auto q = packet_io->OpenQueue(i);
q->SetBufferPool(pool);  // inject runtime pool
queues_.push_back(std::move(q));
```

## Decision (update: ADR-001 v2 — per-shard pool)

### Problem with the single runtime pool

ADR-001 v1 injected a **single shared runtime pool** into every shard's
queues. While this fixed the `GlobalTapPool` leak, it introduced a different
problem: all shard threads compete for the same `PktBufferPool::mutex_` on
every `Allocate()` and `DrainReturnQueue()`. With a single shared pool,
`SetOwnerThread()` can only designate one owner thread, so all other
shards contend on the mutex — the owner-local uncontended fast path only
benefits one shard.

### Per-shard pool model

**Each shard now owns its own `PktBufferPool`.** `Runtime::Start()` creates
`shard_count` pools, each with `config.pool_slot_count` slots (no division).
Each queue is injected with the pool of the shard that owns it:

```cpp
// runtime.cpp — Start()
shard_pools_.reserve(config.shard_count);
for (std::size_t i = 0; i < config.shard_count; ++i) {
    shard_pools_.push_back(
        std::make_unique<PktBufferPool>(config.pool_slot_count,
                                        config.pool_slot_capacity));
}

// For each queue, inject the owner shard's pool
auto shard_idx = config.rx_queue_to_shard[queue_id];
queues_[queue_id]->SetBufferPool(shard_pools_[shard_idx].get());
```

### SetOwnerThread

Each shard calls `pool_.SetOwnerThread(std::this_thread::get_id())` at the
start of `StackShard::Run()`, right after `ownership_.SetOwner()`. This
activates the owner-local uncontended fast path: `Allocate()` and
`DrainReturnQueue()` on the shard's own thread still acquire the mutex,
but only the owner shard thread contends for it — there is no cross-shard
lock contention because each shard has its own pool with its own mutex.

### Cross-shard buffer transfer

When a buffer allocated from shard A's pool is passed to shard B (e.g. via
packet redirect), shard B calls `Reset()` on a non-owner thread. The buffer is
pushed into shard A's `return_queue_` (the `pkt_->pool_` pointer still points
to A's pool). Shard A drains its own `return_queue_` every event-loop
iteration. This is correct as long as every shard drains its own pool — which
all shards do in step 1 of the event loop.

### Runtime::Stop

After joining all shard threads, `Runtime::Stop()` calls
`DrainReturnQueue()` on each pool to collect any final returns, then verifies
outstanding counts and clears the pool vector.

### API simplification

- `Runtime::Start()` signature changed from
  `Start(config, packet_io, PktBufferPool* pool)` to
  `Start(config, packet_io)`. The pool is now internal to Runtime.
- `Netstack2::Pool()` method removed. Callers no longer have direct access to
  the pool.
- `Netstack2` no longer holds a `pool_` member or includes `buffer.h`.

### Why this approach

- **No global state**: eliminates `GlobalTapPool` and its global mutex.
- **No cross-shard lock contention**: each shard's hot path
  (`Allocate`/`DrainReturnQueue`) is owner-local uncontended — the mutex
  is still acquired, but only the owner shard thread contends for it.
- **Correct ownership**: leases allocated by `TapQueue` belong to the owner
  shard's pool, so `Reset()` routes to that pool's return queue, which the
  owner shard drains every iteration.
- **`SetBufferPool` pure virtual**: forces every backend to explicitly handle
  pool injection. A backend that forgets to override will fail to compile,
  not silently leak.
- **No breaking changes to existing tests**: `NullPacketIo`-based tests
  (`packet_io_contract_test`) are unaffected because `NullQueue` overrides
  `SetBufferPool` (stores the pointer) but `RecvBatch` injects leases via
  `Inject()`, not pool allocation. `tap_io_test` already calls
  `SetBufferPool(&pool)`.

## Consequences

- `TapQueue::RecvBatch()` before `SetBufferPool()` returns 0 with
  `IoError::Closed` (defensive guard).
- `tap_io_test.cpp` tests that call `RecvBatch` must call
  `q->SetBufferPool(&pool)` after `OpenQueue`.
- `IPacketQueue::SetBufferPool` is pure virtual. Every concrete
  `IPacketQueue` must override it. This is part of the API-FREEZE contract.
- `Runtime::Start()` no longer accepts an external pool. Pools are created
  internally and are per-shard.
- `Runtime::ShardPool(i)` exposes the i-th shard's pool for testing purposes
  (allocate, check outstanding count).
- Future backends (AF_XDP, DPDK) that allocate RX buffers from a pool will
  also override `SetBufferPool`.

## Verification

- All 18 tests pass across plain, ASan+UBSan, and TSan builds.
- `shard_runtime_test` and `runtime_test` exercise the full
  `Runtime::Start → OpenQueue → SetBufferPool(per-shard pool) →
  SetOwnerThread → shard poll → RecvBatch → Reset → DrainReturnQueue` cycle
  without leaks (outstanding count returns to zero on Stop).
- `ShardMultipleShardsStartStop` uses 4 independent pools (one per shard),
  verifying no cross-shard pool contention.
