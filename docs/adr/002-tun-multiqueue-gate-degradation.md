# ADR-002: TUN Multiqueue Gate Degradation Strategy

**Status:** Accepted
**Date:** 2026-08-07
**Updated:** 2026-08-07 (Tier 2 test implemented; passes as root)

## Context

The `NETSTACK2-API-FREEZE-001` gate requires:

> 至少一个真实 Linux TUN multiqueue 测试通过

The current TUN test suite (`tap_io_test.cpp`, 10 tests) calls
`TapPacketIo::Open()` which requires root or `CAP_NET_ADMIN`. In non-root CI
environments (the common case), every test exercises the **graceful skip**
path: `Open()` returns `false`, and the test verifies closed-state invariants
instead of performing real TUN I/O.

This means:

- **No real TUN multiqueue test has been observed passing** in the current
  development environment.
- The graceful-skip path validates error handling, not the actual
  `IFF_MULTI_QUEUE` open/send/recv/close lifecycle.
- The API-FREEZE gate as written cannot be satisfied without root access.

## Decision

**Adopt a two-tier gate for the TUN multiqueue requirement:**

### Tier 1 — Code review gate (always required, always satisfied)

Before API-FREEZE, the following must be verified by code review:

1. `TapPacketIo::Open()` correctly sets `IFF_MULTI_QUEUE` when
   `config.multi_queue == true`.
2. Each `OpenQueue(i)` returns a `TapQueue` backed by a distinct fd from
   `fds_[i]`.
3. `OpenQueue()` for `queue_id >= fds_.size()` returns `nullptr`.
4. `TapQueue::RecvBatch()` and `SendBatch()` operate on their own fd
   independently (no cross-queue coupling).
5. Buffer pool ownership is correct per ADR-001 (per-shard pool injected via
   `SetBufferPool`, no `GlobalTapPool`).
6. The `TapOpenMultiQueue` test exercises the `queue_count=2,
   multi_queue=true` path when root is available.

### Tier 2 — Runtime gate (HARD REQUIREMENT — NOT YET SATISFIED)

When root or `CAP_NET_ADMIN` is available (locally or in a privileged CI
runner), the `TapOpenMultiQueue` test must pass end-to-end:

- Open a 2-queue TUN device.
- Open both queues.
- Verify distinct queue IDs.
- Close cleanly.

**Tier 2 is a hard requirement for API-FREEZE.** The degradation below does
NOT exempt the project from eventually passing Tier 2. It only allows the
freeze to proceed when no root environment is available at freeze time,
provided the gap is explicitly recorded and tracked.

### Degradation (conditional, with explicit tracking)

If a privileged environment is **not available** at API-FREEZE time, the gate
may temporarily degrade to:

1. Tier 1 (code review) completed and documented.
2. An explicit note in the API-FREEZE record stating that real TUN multiqueue
   was **not exercised**.
3. A follow-up action item to run the suite in a privileged environment before
   any post-freeze release.

This degradation must be approved by an ADR or explicit stakeholder sign-off.
It does NOT represent "Tier 2 passed."

### What does NOT satisfy the gate

- Graceful skip alone (all tests skip without root) does **not** satisfy even
  the degraded gate. The code review tier must be explicitly completed and
  documented.
- A degradation approval is not equivalent to Tier 2. It is a recorded
  exception with a follow-up obligation.

## Future work

- Add a CI job that runs `tap_io_test` with `CAP_NET_ADMIN` in a container
  or VM, so the real TUN multiqueue path is exercised automatically.
- Consider a `veth`-pair based integration test that doesn't require TUN
  privileges but still exercises the packet I/O path end-to-end.

## Verification status at time of writing

- **Tier 1**: Satisfied. Code review completed during ADR-001 work. The
  multiqueue path is straightforward: `OpenOneQueue` is called in a loop,
  each fd is stored in `fds_`, `OpenQueue(i)` wraps `fds_[i]`.
- **Tier 2**: **SATISFIED.** The `TapMultiqueueTier2RootTest` test was
  implemented in `tap_io_test.cpp` and passes as root with all three build
  configurations (default, ASan, TSan). The test opens a 4-queue TUN device
  (`IFF_MULTI_QUEUE`), opens all 4 queues, arms each with a buffer pool and
  recv handler, injects a UDP datagram to the interface's own address, and
  verifies reception on one of the queue fds. In non-root environments the
  test skips gracefully (never fails). The degradation clause below is no
  longer needed for API-FREEZE, but is retained for environments without
  root access.
