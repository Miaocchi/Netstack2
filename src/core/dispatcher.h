#pragma once

/**
 * @file dispatcher.h
 * @brief PacketDispatcher: maps RX queues and flows to owning shards.
 * @license GPL-3.0
 *
 * The dispatcher is the single arbitration point between the RX path and the
 * shard layer. Each RX queue has a home shard (identity mapping by default,
 * or an explicit queue->shard table). When a packet's flow maps to the same
 * shard that owns the queue, the packet stays direct; otherwise it is
 * redirected via the target shard's SPSC packet inbox.
 *
 * Dispatch() itself is a pure routing decision — it does not perform I/O.
 * The caller passes the shard array so the dispatcher can hand off the
 * redirect to the correct StackShard::PostPacket().
 */

#include <cstddef>
#include <vector>

#include <tcpip2/flow.h>

namespace tcpip2 {

class StackShard;  // forward

class PacketDispatcher {
public:
    PacketDispatcher(std::size_t shard_count, std::size_t queue_count) noexcept
        : shard_count_(shard_count),
          queue_count_(queue_count),
          queue_to_shard_() {}

    /** Set queue -> shard mapping. queue_id < queue_count, shard_id < shard_count. */
    void SetQueueShard(std::size_t queue_id, std::size_t shard_id) noexcept {
        if (queue_id >= queue_count_ || shard_id >= shard_count_) return;
        if (queue_to_shard_.empty()) {
            queue_to_shard_.resize(queue_count_);
            for (std::size_t i = 0; i < queue_count_; ++i) queue_to_shard_[i] = i;
        }
        queue_to_shard_[queue_id] = shard_id;
    }

    /** Get the owning shard for a queue. */
    std::size_t QueueShard(std::size_t queue_id) const noexcept {
        if (queue_id >= queue_count_) return 0;
        if (queue_to_shard_.empty()) return queue_id;
        return queue_to_shard_[queue_id];
    }

    /** Get the owning shard for a flow (via canonical hash). */
    std::size_t FlowShard(const FlowKey& key) const noexcept {
        return FlowToShard(key, shard_count_);
    }

    /**
     * Redirect a packet to the correct shard. Returns true if the flow's
     * shard matches the queue's shard (direct, caller keeps the packet),
     * false if the packet was redirected via the target shard's inbox.
     *
     * On redirect, ownership of the BufferLease inside @p key's accompanying
     * packet transfers to the target shard via PostPacket(). The caller is
     * responsible for passing the lease separately; Dispatch() only routes.
     *
     * This overload is for the routing decision without an actual packet.
     */
    bool Dispatch(std::size_t rx_queue_id, FlowKey key, StackShard* shards[]) noexcept;

    std::size_t ShardCount() const noexcept { return shard_count_; }
    std::size_t QueueCount() const noexcept { return queue_count_; }

private:
    std::size_t shard_count_;
    std::size_t queue_count_;
    std::vector<std::size_t> queue_to_shard_;  // identity if empty
};

} // namespace tcpip2
