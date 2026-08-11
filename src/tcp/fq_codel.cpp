/**
 * @file fq_codel.cpp
 * @brief FQ-CoDel shard-local egress scheduler implementation.
 * @license GPL-3.0
 */

#include "tcp/fq_codel.h"

#include <algorithm>
#include <cstring>

namespace tcpip2 {

FqCoDelScheduler::FqCoDelScheduler(const FqCoDelConfig& config) noexcept
    : config_(config) {
    flows_.resize(config_.max_flows);
}

FqCoDelScheduler::Flow* FqCoDelScheduler::FindOrCreateFlow(
    std::uint32_t flow_hash) noexcept {
    if (flows_.empty()) {
        return nullptr;
    }

    const std::uint32_t start_slot = flow_hash % flows_.size();
    std::uint32_t slot = start_slot;

    // Linear probing to find an existing flow or an empty slot.
    for (std::uint32_t i = 0; i < flows_.size(); ++i) {
        Flow& flow = flows_[slot];
        if (flow.queue.empty() && flow.flow_hash == 0) {
            // Empty slot — claim it for this flow.
            flow.flow_hash = flow_hash;
            return &flow;
        }
        if (flow.flow_hash == flow_hash) {
            return &flow;
        }
        slot = (slot + 1) % flows_.size();
    }

    // Flow table is full.
    return nullptr;
}

void FqCoDelScheduler::ActivateFlow(std::size_t idx) noexcept {
    flows_[idx].active = true;
    flows_[idx].deficit = static_cast<std::int64_t>(config_.quantum);
    active_list_.push_back(static_cast<std::uint32_t>(idx));
}

bool FqCoDelScheduler::Enqueue(const std::uint8_t* data, std::size_t length,
                                std::uint32_t flow_hash,
                                std::uint64_t now_ms) noexcept {
    if (data == nullptr || length == 0) {
        return false;
    }

    Flow* flow = FindOrCreateFlow(flow_hash);
    if (flow == nullptr) {
        return false;
    }
    if (flow->queue.size() >= config_.max_queue_length) {
        return false;
    }

    QueuedPacket pkt;
    pkt.data.resize(length);
    std::memcpy(pkt.data.data(), data, length);
    pkt.enqueue_time_ms = now_ms;

    flow->queue.push_back(std::move(pkt));
    ++total_packets_;

    if (!flow->active) {
        ActivateFlow(static_cast<std::size_t>(flow - flows_.data()));
    }

    return true;
}

bool FqCoDelScheduler::CodelShouldDrop(Flow& flow, std::uint64_t sojourn_ms,
                                        std::uint64_t now_ms) noexcept {
    const std::uint32_t target = config_.target_ms;
    const std::uint32_t interval = config_.interval_ms;

    if (sojourn_ms <= target) {
        // Sojourn is at or below target — exit dropping state.
        flow.first_above_time = 0;
        flow.dropping = false;
        return false;
    }

    // Sojourn is above target.
    if (flow.first_above_time == 0) {
        // First time above target — record when we noticed.
        flow.first_above_time = now_ms;
    }

    // Check if we've been above target for longer than the interval.
    const std::uint64_t above_duration = (now_ms >= flow.first_above_time)
        ? (now_ms - flow.first_above_time) : 0;

    if (above_duration < interval) {
        return false;
    }

    // We've been above target for longer than the interval — drop.
    flow.dropping = true;
    flow.drop_count++;
    flow.last_drop_time = now_ms;
    // Reset the interval timer so the next drop check waits another interval.
    flow.first_above_time = now_ms;
    return true;
}

std::optional<FqCoDelPacket> FqCoDelScheduler::Dequeue(
    std::uint64_t now_ms) noexcept {
    while (!active_list_.empty()) {
        const std::uint32_t idx = active_list_.front();
        Flow& flow = flows_[idx];

        if (flow.queue.empty()) {
            // Stale entry — deactivate.
            flow.active = false;
            flow.deficit = 0;
            active_list_.erase(active_list_.begin());
            continue;
        }

        // Credit deficit for this round.
        flow.deficit += static_cast<std::int64_t>(config_.quantum);

        const std::size_t pkt_size = flow.queue.front().data.size();

        if (static_cast<std::size_t>(flow.deficit) < pkt_size) {
            // Not enough deficit — move to back of round-robin list.
            // With a single active flow, deficit accumulates each iteration
            // of this loop until it exceeds the packet size, so no livelock.
            active_list_.erase(active_list_.begin());
            active_list_.push_back(idx);
            continue;
        }

        // Dequeue the head packet.
        QueuedPacket pkt = std::move(flow.queue.front());
        flow.queue.pop_front();
        --total_packets_;
        flow.deficit -= static_cast<std::int64_t>(pkt.data.size());

        const std::uint64_t sojourn = (now_ms >= pkt.enqueue_time_ms)
            ? (now_ms - pkt.enqueue_time_ms) : 0;

        if (CodelShouldDrop(flow, sojourn, now_ms)) {
            // Drop the packet — continue to the next.
            continue;
        }

        // If the flow is now empty, deactivate; otherwise rotate to back.
        if (flow.queue.empty()) {
            flow.active = false;
            flow.deficit = 0;
            flow.flow_hash = 0;
            active_list_.erase(active_list_.begin());
        } else {
            active_list_.erase(active_list_.begin());
            active_list_.push_back(idx);
        }

        FqCoDelPacket result;
        result.data = std::move(pkt.data);
        result.enqueue_time_ms = pkt.enqueue_time_ms;
        result.flow_hash = flow.flow_hash;
        return result;
    }

    return std::nullopt;
}

bool FqCoDelScheduler::Empty() const noexcept {
    return total_packets_ == 0;
}

std::size_t FqCoDelScheduler::QueueLength() const noexcept {
    return total_packets_;
}

void FqCoDelScheduler::Reset() noexcept {
    for (auto& flow : flows_) {
        flow.queue.clear();
        flow.deficit = 0;
        flow.active = false;
        flow.flow_hash = 0;
        flow.first_above_time = 0;
        flow.last_drop_time = 0;
        flow.dropping = false;
        flow.drop_count = 0;
    }
    active_list_.clear();
    total_packets_ = 0;
}

std::size_t FqCoDelScheduler::ActiveFlowCount() const noexcept {
    std::size_t count = 0;
    for (const auto& flow : flows_) {
        if (!flow.queue.empty()) {
            ++count;
        }
    }
    return count;
}

} // namespace tcpip2
