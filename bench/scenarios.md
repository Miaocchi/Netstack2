# P0 Benchmark Scenarios

> Status: skeleton. Scenario definitions are refined when the P0 benchmark
> binary lands.

## null-rx

Single `NullPacketIo` queue, N injected packets, `RecvBatch()` drains the
backlog. Measures `IPacketQueue::RecvBatch()` transfer rate with a fixed pool.

## null-tx

N leases sent through `SendBatch()` into the null backend's egress capture.
Measures lease consumption + release rate.

## pool-alloc-release

Ping-pong `Allocate()`/`Reset()` on one pool: single-threaded throughput and
cross-thread release rate (release from a different thread than allocation).

## timer-wheel-advance

Insert M timers at varied deadlines, advance the wheel in fixed steps, count
callbacks fired. Measures insert/advance/cancel throughput.

## shard-dispatch

Synthetic RX batch distributed across shards; measures queue-to-shard
routing cost without a real NIC (affinity vector from `NetstackConfig`).

Scenario IDs are stable: once `scenarios.md` lists an ID, its name and metric
set must not change without an ADR.
