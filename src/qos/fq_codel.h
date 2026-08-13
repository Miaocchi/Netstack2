#pragma once

/**
 * @file fq_codel.h
 * @brief FQ-CoDel shard-local egress scheduler (generic, not TCP-specific).
 * @license GPL-3.0
 *
 * Private internal component: fair queuing with the CoDel controlled-delay
 * AQM algorithm following RFC 8290 (FQ-CoDel) and RFC 8289 (CoDel).
 *
 * Structure (RFC 8290 §3):
 *   * A fixed-size hash table of flows, probed linearly by flow hash.
 *   * @c new_flows_ — FIFO of flows that have not yet been drained; they are
 *     serviced with strict priority over old flows, one packet at a time.
 *   * @c old_flows_ — DRR list for flows whose queue drained at least once.
 *
 * CoDel (RFC 8289): a packet is dropped when its sojourn time stays above
 * @c target_ms for at least @c interval_ms. While dropping, subsequent drops
 * follow the interval/sqrt(count) control law with the phase-shift heuristic
 * for returning flows. Packets marked ECT(0)/ECT(1) are CE-marked instead of
 * dropped when ECN marking is enabled (the IPv4 header checksum is refreshed
 * after the mark); Not-ECT packets are dropped.
 *
 * The scheduler is NOT thread-safe. It is intended to be used from a single
 * shard thread only, matching the shard-local execution model.
 *
 * The scheduler owns BufferLease objects directly — no per-packet heap
 * allocation or memcpy on the hot path. Callers move a BufferLease in on
 * Enqueue and receive it back on Dequeue.
 *
 * Deviation from RFC 8290: a flow slot is released when its queue drains, so
 * a returning flow re-enters as a new flow. This keeps the fixed probe table
 * reusable; the kernel keeps drained flows in old_flows until eviction.
 *
 * This is a private header used only by src/qos/ — not part of the frozen
 * public API.
 */

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

#include <tcpip2/buffer.h>

namespace tcpip2 {

/// Configuration for the FQ-CoDel scheduler.
struct FqCoDelConfig {
    /// CoDel interval — window over which persistent sojourn above target
    /// leads to dropping (ms).
    std::uint32_t interval_ms = 100;
    /// CoDel target — acceptable maximum sojourn time (ms).
    std::uint32_t target_ms = 5;
    /// Quantum — deficit round-robin credits per flow per round (bytes).
    std::uint32_t quantum = 1514;
    /// Maximum number of distinct flows tracked.
    std::uint32_t max_flows = 64;
    /// Maximum packets queued per flow before Enqueue returns false.
    std::uint32_t max_queue_length = 1024;
    /// Maximum bytes queued per flow before Enqueue returns false.
    std::size_t max_flow_queue_bytes = 256 * 1024;
    /// Hard byte limit across all flows; Enqueue beyond it returns false.
    std::size_t max_total_bytes = 4 * 1024 * 1024;
    /// Hard packet limit across all flows.
    std::size_t max_total_packets = 8 * 1024;
    /// Mark ECT(0)/ECT(1) packets with CE instead of dropping them.
    bool ecn_ce_marking = true;
};

/**
 * A packet dequeued from the scheduler. Owns its BufferLease so the caller
 * can safely use the data until the packet is destroyed or the lease is
 * moved out.
 */
struct FqCoDelPacket {
    BufferLease lease;
    std::uint64_t enqueue_time_ms = 0;
    std::uint32_t flow_hash = 0;
    /// True when this packet was CE-marked by the scheduler instead of the
    /// drop CoDel otherwise demanded.
    bool ce_marked = false;

    const std::uint8_t* Data() const noexcept { return lease.Data(); }
    std::size_t Size() const noexcept { return lease.Size(); }
    bool Empty() const noexcept { return !lease; }
};

/**
 * FQ-CoDel scheduler: RFC 8290 new/old flow lists with deficit round-robin
 * and RFC 8289 CoDel AQM.
 *
 * Usage: call Enqueue() to add a packet tagged with a flow hash, and
 * Dequeue() to pull the next scheduled packet.
 */
class FqCoDelScheduler final {
public:
    FqCoDelScheduler() noexcept : FqCoDelScheduler(FqCoDelConfig{}) {}
    explicit FqCoDelScheduler(const FqCoDelConfig& config) noexcept;

    FqCoDelScheduler(const FqCoDelScheduler&) = delete;
    FqCoDelScheduler& operator=(const FqCoDelScheduler&) = delete;

    /**
     * Enqueue @p lease on the flow identified by @p flow_hash. The scheduler
     * takes ownership of the lease on success. Returns false if the flow
     * table is full, the per-flow queue (packets or bytes) is full, the
     * scheduler-wide limits are exceeded, or the lease is empty; on failure
     * the lease is released (buffer returned to pool).
     */
    bool Enqueue(BufferLease lease, std::uint32_t flow_hash,
                 std::uint64_t now_ms) noexcept;

    /**
     * Dequeue the next packet according to the RFC 8290 new/old flow
     * structure, applying CoDel AQM. Packets CoDel drops are skipped (their
     * leases released); ECN-capable packets may be CE-marked and delivered
     * instead. Returns std::nullopt when the scheduler is empty.
     */
    std::optional<FqCoDelPacket> Dequeue(std::uint64_t now_ms) noexcept;

    /// True when no packets are queued.
    bool Empty() const noexcept;

    /// Total packets across all flow queues.
    std::size_t QueueLength() const noexcept { return total_packets_; }

    /// Total bytes across all flow queues.
    std::size_t QueueBytes() const noexcept { return total_bytes_; }

    /// Clear all queues and reset all CoDel / deficit state.
    void Reset() noexcept;

    /// Number of currently tracked (non-empty) flows.
    std::size_t ActiveFlowCount() const noexcept;

private:
    enum class FlowList : std::uint8_t { None, New, Old };

    struct QueuedPacket {
        BufferLease lease;
        std::uint64_t enqueue_time_ms = 0;
    };

    struct Flow {
        std::deque<QueuedPacket> queue;
        std::size_t queue_bytes = 0;
        std::int64_t deficit = 0;
        FlowList list = FlowList::None;
        std::uint32_t flow_hash = 0; // 0 = slot unused

        // CoDel state (RFC 8289).
        std::uint64_t first_above_time = 0; // 0 = not above target
        std::uint64_t drop_next = 0;        // time of the next scheduled drop
        std::uint64_t last_drop_time = 0;   // 0 = never dropped
        bool in_dropping = false;
        std::uint32_t drop_count = 0;

        Flow() noexcept = default;
        Flow(const Flow&) = delete;
        Flow& operator=(const Flow&) = delete;
        Flow(Flow&&) noexcept = default;
        Flow& operator=(Flow&&) noexcept = default;
        ~Flow() = default;
    };

    FqCoDelConfig config_;
    std::vector<Flow> flows_;                 // hash table with linear probing
    std::deque<std::uint32_t> new_flows_;     // indices into flows_
    std::deque<std::uint32_t> old_flows_;
    std::size_t total_packets_ = 0;
    std::size_t total_bytes_ = 0;

    Flow* FindOrCreateFlow(std::uint32_t flow_hash) noexcept;
    void ReleaseFlowSlot(std::uint32_t idx) noexcept;

    /// Serve the flow at @p idx (which must sit at the front of @p list).
    /// Returns a packet when one survived CoDel, std::nullopt when the flow
    /// contributed nothing this round. Updates deficit/list placement.
    std::optional<FqCoDelPacket> ServeFlow(std::uint32_t idx, FlowList list,
                                           std::uint64_t now_ms) noexcept;

    /// CoDel verdict for the head packet: false = deliver (possibly after
    /// CE-marking), true = drop. May transition the dropping state machine.
    bool CodelShouldDrop(Flow& flow, std::uint64_t sojourn_ms,
                         std::uint64_t now_ms) noexcept;

    /// Mark CE on an ECT(0)/ECT(1) packet in place (refreshing the IPv4
    /// header checksum); returns false when the packet is Not-ECT or
    /// unparseable.
    static bool MarkCe(QueuedPacket& pkt) noexcept;
};

} // namespace tcpip2
