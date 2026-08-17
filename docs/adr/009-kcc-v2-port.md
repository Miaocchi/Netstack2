# ADR-009: KCC v2.0 Geodesic Congestion Control Port

**Status:** Accepted
**Date:** 2026-08-16
**Supersedes:** ADR-006 §3/§4.1 to the extent it ruled out a real KCC port
(see below)

## Context

ADR-006 (2026-08-11) concluded that OpenPPP2's local source tree contained no
KCC/KCP implementation and therefore designed `HybridBdpAimdController` as a
purpose-built hybrid instead of porting upstream code.

The upstream KCC project (`https://github.com/liulilittle/kcc`, TCP congestion
control module `tcp_kcc.c`, KCC v2.0 "Network Spacetime Geodesic") is a
separate Linux kernel module with a dual BSD/GPL license. A local copy is
available at `/root/kcc-latest-227a20b` (commit `227a20b`, kernel 6.17
compat). This ADR records the decision to port KCC v2.0's algorithm core into
Netstack2 as a real, faithful congestion controller.

`HybridBdpAimdController` remains a distinct algorithm (BBR-style bandwidth
estimation + AIMD loss response, telemetry `hybrid_bdp_aimd_v1`) and is
retained unchanged. KCC v2.0 is added as a fourth selectable algorithm
(telemetry `kcc`).

## Decision

Port the algorithm core of `tcp_kcc.c` (commit `227a20b`) into Netstack2 as
`KccController` (`src/tcp/congestion.h`/`.cpp`), selectable via
`CongestionAlgorithm::Kcc` and the new public `TcpCongestionAlgorithm::Kcc`
config enum.

### Ported mechanisms (faithful)

- Three-component RTT model: `T_prop` (geodesic `x_est`), `T_queue`
  (`qdelay_avg` EWMA), `T_noise` (`jitter_ewma` EWMA).
- Geodesic estimator: G1 (instant downward min), G2 (12.2%/RTT capped upward
  growth), G3 (dual-threshold path-increase confirmation: 1.10x × 3 / 1.05x × 4),
  G4 (BDP floor `min(x_est>>10, min_rtt_us)`), plus the 128-round staleness
  reset and the p_est convergence proxy.
- Three-state FSM: `STARTUP -> DRAIN -> PROBE_BW` with the physical
  queue-driven closed-loop AI/MD PI controller (`pg ∈ [0.75x, 1.25x]`,
  periodic 0.75x drain every 128 rounds, turbo 1.88x BDP cwnd floor).
- Windowed min RTT update: sticky fall (75%), fast fall (1/4), SRTT guard
  (90%), geodesic pull-down with 5-sample confirmation.
- LT-BW policer detection (loss-triggered sampling, EMA smoothing, queue
  guard, periodic re-probe every 48 rounds).
- Confidence-gated ACK-aggregation compensation (dual-window sliding max,
  4-factor confidence score, CONFIRMED/TRUSTED gating, watchdog).
- Alone-on-path single-flow bypass.
- `win_minmax` sliding-window max filter (Linux `include/linux/win_minmax.h`).

### Not ported (kernel-only subsystems) — superseded by ADR-010

- ~~Global cross-connection Kalman filter (KF)~~ — **ported per-shard** by
  ADR-010 (`KccKalmanFilter`, default off).
- ~~TSO/GSO burst control~~ — adapted by ADR-010 (pacing-interval headroom).
- ~~`/proc/kcc/status` diagnostics, sysctl/module params~~ — folded into
  `NetstackConfig`/`KccConfig` by ADR-010.
- ~~ECN EWMA backoff~~ — **ported and enabled** by ADR-010
  (`NetstackConfig::kcc_ecn`, default true); `OnEcnCe()` stays a no-op.
- Recovery cwnd transitions are driven by the existing send-buffer fast
  recovery path (`OnFastRecoveryEntry/Exit`) instead of the kernel's
  `icsk_ca_state` transitions.

### Precision mapping

KCC works in the segment domain (`BW_UNIT = 1<<24` segments/usec) and requires
microsecond RTT/interval inputs. Netstack2's clock is millisecond-granular; the
port feeds `rtt_us = rtt_ms * 1000` and `interval_us = interval_ms * 1000`
(populated by `DeliveryRateSampler`). Sub-ms precision is therefore bounded by
the injected `IClock`; this is a documented limitation, not a behavioural
deviation, and matches the deterministic test harness.

## Consequences

- `RateSample`/`PacketDeliveryState` gain us-scale fields and delivered
  counters (backward compatible; BBR/Hybrid/AIMD still consume the ms fields).
- `KccController` is a value member of `TcpSendBuffer`'s controller variant
  (no heap allocation, no per-ACK virtual dispatch).
- Loss handling: KCC preserves pipe capacity through loss (no cwnd collapse on
  RTO), seeds LT-BW on loss events, and uses packet conservation during
  recovery — matching upstream `kcc_ssthresh`/`kcc_set_state`.
- KCC does not react to ECN (upstream `KCC_ECN_ENABLE=0`); flows that
  negotiated ECN keep the RFC 3168 ECE/CWR loop but KCC's own controller does
  not reduce cwnd on CE.
- License: `tcp_kcc.c` is BSD/GPL dual-licensed; the port is derived work under
  GPL-3.0 (project license) with upstream copyright preserved in comments.

## Migration

- Public: `NetstackConfig::tcp_cc` accepts `TcpCongestionAlgorithm::Kcc`
  (additive; existing configs default to `Aimd`).
- Internal: `CongestionAlgorithm::Kcc` selects `KccController` in
  `TcpSendBuffer`.
- Existing `HybridBdpAimd` configs and telemetry are unchanged.

## Verification

- 14 new unit tests in `tests/unit/tcp/congestion_test.cpp` covering initial
  state, geodesic G1/G2/G3, STARTUP->PROBE_BW transition, bounded cwnd,
  pacing activation, RTO/LT-BW seeding, fast-recovery conservation, MSS
  scaling, Reset, and send-buffer integration.
- Default + ASan/UBSan + TSan builds green (42/42, 42/42, 41/41).
- Deterministic golden values derived by hand from the fixed-point arithmetic
  (e.g. G2 growth 18000us -> 20196us; G3 commit + SRTT guard -> 23300us).
