#pragma once

/**
 * @file fq_codel.h
 * @brief FQ-CoDel shard-local egress scheduler.
 * @license GPL-3.0
 *
 * Private internal component: provides per-flow fair queuing with the
 * CoDel controlled-delay AQM algorithm (RFC 8290 / RFC 8289).  This is
 * used by the TCP egress path to schedule packets across active flows
 * on a shard, preventing slow/bursty flows from starving others.
 *
 * The scheduler is NOT thread-safe.  It is intended to be used from a
 * single shard thread only, matching the shard-local execution model.
 *
 * This is a private header used only by src/tcp/ — not part of the
 * frozen public API.
 */

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

namespace tcpip2 {

/// Configuration for the FQ-CoDel scheduler.
struct FqCoDelConfig {
    /// CoDel interval — minimum time between drops for the same flow (ms).
    std::uint32_t interval_ms = 100;
    /// CoDel target — acceptable maximum sojourn time (ms).
    std::uint32_t target_ms = 5;
    /// Quantum — bytes each flow may send per round-robin turn.
    std::uint32_t quantum = 1514;
    /// Maximum number of distinct flows tracked.
    std::uint32_t max_flows = 64;
    /// Maximum packets queued per flow before Enqueue returns false.
    std::uint32_t max_queue_length = 1024;
};

/**
 * A packet dequeued from the scheduler.  Owns its byte buffer so the
 * caller can safely read the data until the packet is destroyed.
 */
struct FqCoDelPacket {
    std::vector<std::uint8_t> data;
    std::uint64_t enqueue_time_ms = 0;
    std::uint32_t flow_hash = 0;

    const std::uint8_t* Data() const noexcept { return data.data(); }
    std::size_t Size() const noexcept { return data.size(); }
    bool Empty() const noexcept { return data.empty(); }
};

/**
 * FQ-CoDel scheduler: per-flow deficit round-robin with CoDel AQM.
 *
 * Usage: call Enqueue() to add packets tagged with a flow hash, and
 * Dequeue() to pull the next scheduled packet.  CoDel drops packets
 * whose sojourn time (time spent in the queue) exceeds @p target_ms
 * for longer than @p interval_ms.
 */
class FqCoDelScheduler final {
public:
    FqCoDelScheduler() noexcept : FqCoDelScheduler(FqCoDelConfig{}) {}
    explicit FqCoDelScheduler(const FqCoDelConfig& config) noexcept;

    FqCoDelScheduler(const FqCoDelScheduler&) = delete;
    FqCoDelScheduler& operator=(const FqCoDelScheduler&) = delete;

    /**
     * Enqueue @p length bytes from @p data on the flow identified by
     * @p flow_hash.  Returns false if the flow table is full, the per-flow
     * queue is full, or the input is invalid.
     */
    bool Enqueue(const std::uint8_t* data, std::size_t length,
                 std::uint32_t flow_hash, std::uint64_t now_ms) noexcept;

    /**
     * Dequeue the next packet according to deficit round-robin order,
     * applying CoDel AQM.  Packets dropped by CoDel are skipped silently.
     * Returns std::nullopt when the scheduler is empty.
     */
    std::optional<FqCoDelPacket> Dequeue(std::uint64_t now_ms) noexcept;

    /// True when no packets are queued.
    bool Empty() const noexcept;

    /// Total packets across all flow queues.
    std::size_t QueueLength() const noexcept;

    /// Clear all queues and reset all CoDel / deficit state.
    void Reset() noexcept;

    /// Number of currently active (non-empty) flows.
    std::size_t ActiveFlowCount() const noexcept;

private:
    struct QueuedPacket {
        std::vector<std::uint8_t> data;
        std::uint64_t enqueue_time_ms = 0;
    };

    struct Flow {
        std::deque<QueuedPacket> queue;
        std::int64_t deficit = 0;
        bool active = false;
        std::uint32_t flow_hash = 0; // 0 = slot unused

        // CoDel state
        std::uint64_t first_above_time = 0; // 0 = not above target
        std::uint64_t last_drop_time = 0;  // 0 = never dropped
        bool dropping = false;
        std::uint32_t drop_count = 0;
    };

    FqCoDelConfig config_;
    std::vector<Flow> flows_;                // indexed by flow_hash % max_flows with linear probing
    std::vector<std::uint32_t> active_list_; // indices into flows_
    std::size_t total_packets_ = 0;

    Flow* FindOrCreateFlow(std::uint32_t flow_hash) noexcept;
    void ActivateFlow(std::size_t idx) noexcept;
    bool CodelShouldDrop(Flow& flow, std::uint64_t sojourn_ms,
                         std::uint64_t now_ms) noexcept;
};

} // namespace tcpip2
