#pragma once

/**
 * @file shard_lanes.h
 * @brief Bounded source-shard to target-shard SPSC packet and egress lanes.
 * @license GPL-3.0
 */

#include <atomic>
#include <cstddef>
#include <limits>
#include <memory>
#include <new>
#include <utility>
#include <vector>

#include <core/egress_envelope.h>
#include <core/inbox_spsc.h>
#include <core/packet_envelope.h>

namespace tcpip2 {

/**
 * A lane has exactly one producer (its source shard) and one consumer (its
 * target shard). Message and byte limits are independent, so a few oversized
 * leases cannot consume unbounded memory while the ring remains non-full.
 */
template <typename Envelope>
class ShardBoundedLane final {
public:
    ShardBoundedLane(std::size_t message_capacity, std::size_t byte_capacity) noexcept
        : queue_(message_capacity), byte_capacity_(byte_capacity) {}

    bool Push(Envelope&& envelope) noexcept {
        const std::size_t bytes = envelope.ByteSize();
        if (bytes > byte_capacity_) return false;

        std::size_t used = bytes_.load(std::memory_order_relaxed);
        for (;;) {
            if (used > byte_capacity_ - bytes) return false;
            if (bytes_.compare_exchange_weak(used, used + bytes,
                                             std::memory_order_acq_rel,
                                             std::memory_order_relaxed)) {
                break;
            }
        }

        if (!queue_.Push(std::move(envelope))) {
            bytes_.fetch_sub(bytes, std::memory_order_release);
            return false;
        }

        std::size_t high = high_watermark_.load(std::memory_order_relaxed);
        const std::size_t after = used + bytes;
        while (after > high &&
               !high_watermark_.compare_exchange_weak(high, after,
                                                       std::memory_order_relaxed,
                                                       std::memory_order_relaxed)) {
        }
        return true;
    }

    bool Pop(Envelope& envelope) noexcept {
        if (!queue_.Pop(envelope)) return false;
        bytes_.fetch_sub(envelope.ByteSize(), std::memory_order_release);
        return true;
    }

    std::size_t MessageCapacity() const noexcept { return queue_.Capacity(); }
    std::size_t ByteCapacity() const noexcept { return byte_capacity_; }
    std::size_t MessageCount() const noexcept { return queue_.Size(); }
    std::size_t ByteCount() const noexcept { return bytes_.load(std::memory_order_acquire); }
    std::size_t HighWatermark() const noexcept {
        return high_watermark_.load(std::memory_order_relaxed);
    }

private:
    SpscRing<Envelope> queue_;
    std::size_t byte_capacity_;
    std::atomic<std::size_t> bytes_{0};
    std::atomic<std::size_t> high_watermark_{0};
};

using ShardPacketLane = ShardBoundedLane<PacketEnvelope>;
using ShardEgressLane = ShardBoundedLane<EgressEnvelope>;

/** Owns the full directed source-shard to target-shard lane matrix. */
template <typename LaneType>
class DirectedShardLanes final {
public:
    DirectedShardLanes(std::size_t shard_count, std::size_t message_capacity,
                       std::size_t byte_capacity)
        : shard_count_(shard_count) {
        if (shard_count_ != 0 &&
            shard_count_ > std::numeric_limits<std::size_t>::max() / shard_count_) {
            throw std::bad_array_new_length();
        }
        lanes_.resize(shard_count_ * shard_count_);
        for (std::size_t source = 0; source < shard_count_; ++source) {
            for (std::size_t target = 0; target < shard_count_; ++target) {
                if (source == target) continue;
                lanes_[Index(source, target)] =
                    std::make_unique<LaneType>(message_capacity, byte_capacity);
            }
        }
    }

    LaneType* Lane(std::size_t source, std::size_t target) const noexcept {
        if (source >= shard_count_ || target >= shard_count_ || source == target) return nullptr;
        return lanes_[Index(source, target)].get();
    }

private:
    std::size_t Index(std::size_t source, std::size_t target) const noexcept {
        return source * shard_count_ + target;
    }

    std::size_t shard_count_;
    std::vector<std::unique_ptr<LaneType>> lanes_;
};

using ShardLanes = DirectedShardLanes<ShardPacketLane>;
using ShardEgressLanes = DirectedShardLanes<ShardEgressLane>;

} // namespace tcpip2
