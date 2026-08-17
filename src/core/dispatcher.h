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
 * redirected through that source shard's dedicated target lane.
 *
 * Dispatch() is a pure routing decision. It never owns a queue, lease, or
 * shard pointer; the caller performs the corresponding direct delivery or
 * lane handoff.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <tcpip2/flow.h>

#include <ip/fragment.h>

namespace tcpip2 {

enum class PacketClass {
    kOther,
    kTcp,
    kUdp,
    kFragment,
};

enum class PacketClassificationError {
    None,
    Empty,
    UnsupportedIpVersion,
    MalformedIp,
    TruncatedTransport,
};

struct PacketClassification {
    PacketClass packet_class = PacketClass::kOther;
    PacketClassificationError error = PacketClassificationError::None;
    FlowKey flow;
    FragmentKey fragment;
    std::size_t owner_shard = 0;

    bool IsRoutable() const noexcept {
        return error == PacketClassificationError::None &&
               (packet_class == PacketClass::kTcp || packet_class == PacketClass::kUdp ||
                packet_class == PacketClass::kFragment);
    }
};

enum class DispatchAction {
    kLocal,
    kRedirect,
};

struct DispatchDecision {
    DispatchAction action = DispatchAction::kLocal;
    PacketClassification classification;
};

class PacketDispatcher {
  public:
    PacketDispatcher(std::size_t shard_count, std::size_t queue_count) noexcept
        : shard_count_(shard_count), queue_count_(queue_count), queue_to_shard_() {}

    /** Set queue -> shard mapping. queue_id < queue_count, shard_id < shard_count. */
    void SetQueueShard(std::size_t queue_id, std::size_t shard_id) noexcept {
        if (queue_id >= queue_count_ || shard_id >= shard_count_)
            return;
        if (queue_to_shard_.empty()) {
            queue_to_shard_.resize(queue_count_);
            for (std::size_t i = 0; i < queue_count_; ++i)
                queue_to_shard_[i] = i;
        }
        queue_to_shard_[queue_id] = shard_id;
    }

    /** Get the owning shard for a queue. */
    std::size_t QueueShard(std::size_t queue_id) const noexcept {
        if (queue_id >= queue_count_)
            return 0;
        if (queue_to_shard_.empty())
            return queue_id;
        return queue_to_shard_[queue_id];
    }

    /** Get the owning shard for a flow (via canonical hash). */
    std::size_t FlowShard(const FlowKey &key) const noexcept { return FlowToShard(key, shard_count_); }

    /** Read only the IP and transport headers needed to select an RX owner. */
    PacketClassification ClassifyPacket(const std::uint8_t *packet, std::size_t length) const noexcept;

    /** Return a local/redirect decision for an already-known source shard. */
    DispatchDecision Dispatch(std::size_t source_shard, const std::uint8_t *packet, std::size_t length) const noexcept;

    /** Stable fragment-group ownership before a transport FlowKey exists. */
    std::size_t FragmentShard(const FragmentKey &key) const noexcept;

    std::size_t ShardCount() const noexcept { return shard_count_; }
    std::size_t QueueCount() const noexcept { return queue_count_; }

  private:
    std::size_t shard_count_;
    std::size_t queue_count_;
    std::vector<std::size_t> queue_to_shard_; // identity if empty
};

} // namespace tcpip2
