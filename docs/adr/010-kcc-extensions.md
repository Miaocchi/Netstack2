# ADR-010: KCC v2.0 Port — Extensions (KF, ECN EWMA, Tunables, Observability)

**Status:** Accepted
**Date:** 2026-08-16
**Supersedes:** —

## Context

ADR-009 ported the KCC v2.0 algorithm core (`KccController`). Four kernel-only
subsystems were left out: the global cross-connection Kalman filter (KF), TSO/GSO
burst control, `/proc`/sysctl interfaces, and ECN EWMA backoff. This ADR records
the decisions for bringing each of them into Netstack2.

## Decision

### 1. Cross-connection KF — per-shard instance, default off

Port `kcc_kf_compute_R` / `kcc_kf_update` / `kcc_kf_get_init_bw` as
`KccKalmanFilter`. Deviation from upstream architecture:

- Upstream keeps one **global** filter (atomic64 + spinlock shared across all
  sockets). Netstack2's design invariant is *flow-fixed shard, no writable
  cross-shard shared state*, so the filter is instantiated **per shard** and
  only accessed on the shard thread. The spinlock/atomics collapse to plain
  members; determinism per shard is preserved.
- New flows bootstrap their sliding-window max-BW filter, pacing rate, and
  initial cwnd from `GetInitBw()` (discounted 50%, gain-compensated) — the
  upstream KF-injection block in `kcc_init()`, adapted to run on the first data
  ACK once SRTT is known (the controller has no handshake RTT).
- Master switch `enabled` mirrors upstream `kcc_kf_enable = 0` default.
  Exposed as `NetstackConfig::kcc_kf_enable`.
- The chi-squared innovation gate and peak-tracking steady mode are retained.

### 2. TSO/GSO — not ported; burst headroom adapted

Netstack2 transmits per-packet with no GSO skb. `kcc_min_tso_segs` /
`kcc_tso_segs_goal` have no equivalent object. The `3 * tso_segs_goal` burst
term in `kcc_quantization_budget` is replaced by a pacing-interval estimate
(`pacing_rate / 1000 / MSS`, capped at the upstream 64-segment TSO ceiling),
which preserves the burst headroom semantics without a TSO stack.

### 3. sysctl/module params — folded into config

- `kcc_turbo` → `NetstackConfig::kcc_turbo` (default true).
- `kcc_ai_num` → `NetstackConfig::kcc_ai_num` (default 25).
- KF sysctls → `KccKalmanFilter` members + `NetstackConfig::kcc_kf_enable`.
- `/proc/kcc/status` has no user-space counterpart; KCC per-flow state is
  observable through the existing `KccController` accessors
  (mode/x_est/min_rtt/gains/qdelay/jitter) and the `MetricSnapshot` path.

### 4. ECN EWMA backoff — ported and enabled

Port `kcc_update_ecn_ewma` and `kcc_ecn_backoff`. Two deliberate deviations:

- Upstream gates the backoff on `p_est < KCC_CONVERGED_MIN(=1)` which can never
  fire (the p_est floor is 10), making it dead code. Netstack2 drops that gate
  and relies on `sample_cnt >= KCC_MIN_SAMPLES`, `ecn_ewma > 0`, and
  `qdelay_avg > cong_thresh`, so the backoff is actually functional.
- Upstream disables ECN via `KCC_ECN_ENABLE=0`. Netstack2 enables it
  (`NetstackConfig::kcc_ecn`, default true) because the RFC 3168 data path
  (ECT/CE/ECE/CWR) is verified. `KccController::OnEcnCe()` stays a no-op: KCC
  reacts through the proactive EWMA cwnd_gain backoff, not a reactive per-ECE
  window halving — avoiding double reduction with the send buffer's ECE/CWR loop.
- `RateSample::delivered_ce` carries the cumulative CE-marked segment count
  (`tp->delivered_ce`); `TcpSendBuffer` increments it on ECE-bearing ACKs.

## Consequences

- `KccConfig` carries turbo/ai_num/ecn + a `KccKalmanFilter*`; plumbed via
  `TcpHandshakeConfig` (`kcc_turbo`/`kcc_ai_num`/`kcc_ecn`/`kcc_kf_enable`/
  `kcc_kf`) into `TcpSendBuffer` and `KccController`.
- `StackShard` owns one `KccKalmanFilter`; wired to `tcp_config_.kcc_kf` and
  `enabled` in `Start()` when the CC algorithm is KCC.
- New public config fields: `kcc_turbo`, `kcc_ai_num`, `kcc_ecn`,
  `kcc_kf_enable` (all additive, defaults preserve upstream behaviour except
  ECN which is enabled by default per this ADR).

## Migration

Additive config; existing `NetstackConfig` defaults remain valid. KCC remains
opt-in via `tcp_cc = Kcc`. The KF stays off unless `kcc_kf_enable = true`.

## Verification

- `KccKalmanFilter`: disabled-by-default, first-sample seeding, chi-squared
  gate, discount/floor in `GetInitBw`, reset.
- `KccConfig`: turbo off -> neutral cwnd_gain floor; small `ai_num` -> slower
  PROBE_BW gain climb; `ecn=false` -> no gain change on CE; `ecn=true` ->
  bounded cwnd_gain under queue buildup.
- `TcpSendBuffer::DeliveredCeCount()` increments on ECE ACKs.
- Full suite: default 42/42, ASan/UBSan 42/42, TSan 41/41; congestion test
  97/97. (shard_udp flake is a pre-existing intermittent timing issue, also
  present on the clean tree.)
