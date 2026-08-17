/**
 * @file fq_codel.cpp
 * @brief FQ-CoDel shard-local egress scheduler implementation.
 * @license GPL-3.0
 */

#include "qos/fq_codel.h"

#include <algorithm>

#include <ip/checksum.h>

namespace tcpip2 {

namespace {

/// Integer square root (Newton-free loop; CoDel counts stay small).
std::uint32_t Isqrt32(std::uint32_t x) noexcept {
    if (x == 0)
        return 0;
    std::uint32_t r = 1;
    while ((r + 1) <= x / (r + 1))
        ++r;
    return r;
}

} // namespace

FqCoDelScheduler::FqCoDelScheduler(const FqCoDelConfig &config) noexcept : config_(config) {
    // reserve + emplace_back avoids vector reallocation (which would require
    // Flow to be nothrow_move_constructible — undesirable given Flow holds a
    // deque of move-only QueuedPacket/BufferLease objects).
    flows_.reserve(config_.max_flows);
    for (std::uint32_t i = 0; i < config_.max_flows; ++i) {
        flows_.emplace_back();
    }
}

FqCoDelScheduler::Flow *FqCoDelScheduler::FindOrCreateFlow(std::uint32_t flow_hash) noexcept {
    if (flows_.empty()) {
        return nullptr;
    }

    const std::uint32_t start_slot = flow_hash % flows_.size();
    std::uint32_t slot = start_slot;

    // Linear probing to find an existing flow or an empty slot.
    for (std::uint32_t i = 0; i < flows_.size(); ++i) {
        Flow &flow = flows_[slot];
        if (flow.queue.empty() && flow.flow_hash == 0) {
            flow.flow_hash = flow_hash;
            return &flow;
        }
        if (flow.flow_hash == flow_hash) {
            return &flow;
        }
        slot = (slot + 1) % flows_.size();
    }
    return nullptr; // flow table full
}

void FqCoDelScheduler::ReleaseFlowSlot(std::uint32_t idx) noexcept {
    Flow &flow = flows_[idx];
    flow.queue.clear();
    flow.queue_bytes = 0;
    flow.deficit = 0;
    flow.list = FlowList::None;
    flow.flow_hash = 0;
    flow.first_above_time = 0;
    flow.drop_next = 0;
    flow.last_drop_time = 0;
    flow.in_dropping = false;
    flow.drop_count = 0;
}

bool FqCoDelScheduler::Enqueue(BufferLease lease, std::uint32_t flow_hash, std::uint64_t now_ms) noexcept {
    if (!lease) {
        return false;
    }
    const std::size_t bytes = lease.Size();

    // Scheduler-wide hard limits (R6: packet AND byte bounds).
    if (total_packets_ + 1 > config_.max_total_packets || total_bytes_ + bytes > config_.max_total_bytes) {
        return false;
    }

    Flow *flow = FindOrCreateFlow(flow_hash);
    if (flow == nullptr) {
        return false;
    }
    if (flow->queue.size() >= config_.max_queue_length || flow->queue_bytes + bytes > config_.max_flow_queue_bytes) {
        return false;
    }

    QueuedPacket pkt;
    pkt.lease = std::move(lease);
    pkt.enqueue_time_ms = now_ms;

    const bool was_inactive = flow->list == FlowList::None;
    flow->queue.push_back(std::move(pkt));
    flow->queue_bytes += bytes;
    total_packets_++;
    total_bytes_ += bytes;

    if (was_inactive) {
        // New flow (RFC 8290 §3.3): priority service starts at zero deficit.
        flow->deficit = 0;
        flow->list = FlowList::New;
        new_flows_.push_back(static_cast<std::uint32_t>(flow - flows_.data()));
    }
    return true;
}

bool FqCoDelScheduler::CodelShouldDrop(Flow &flow, std::uint64_t sojourn_ms, std::uint64_t now_ms) noexcept {
    const std::uint32_t target = config_.target_ms;
    const std::uint32_t interval = config_.interval_ms;

    if (sojourn_ms <= target) {
        // Sojourn at or below target: reset the over-target window and exit
        // the dropping state (RFC 8289 §4.2).
        flow.first_above_time = 0;
        flow.in_dropping = false;
        return false;
    }

    if (flow.first_above_time == 0) {
        flow.first_above_time = now_ms;
    }
    if (now_ms - flow.first_above_time < interval) {
        return false;
    }

    // Persistent sojourn above target for at least one interval.
    auto next_drop_delay = [&](std::uint32_t count) -> std::uint64_t {
        const std::uint32_t r = Isqrt32(count);
        const std::uint64_t inc = interval / (r == 0 ? 1 : r);
        return inc == 0 ? 1 : inc;
    };

    if (flow.in_dropping) {
        if (now_ms >= flow.drop_next) {
            flow.last_drop_time = now_ms;
            flow.drop_count++;
            flow.drop_next = now_ms + next_drop_delay(flow.drop_count);
            return true;
        }
        return false;
    }

    // Enter the dropping state; drop the current packet.
    flow.in_dropping = true;
    if (flow.last_drop_time != 0 && flow.drop_count > 1 && now_ms - flow.last_drop_time < interval) {
        // Phase shift (RFC 8289 §4.2): resume the previous cycle's count and
        // replay the control law forwards until the next drop is in the
        // future, rather than restarting at count = 1.
        std::uint32_t count = flow.drop_count;
        std::uint64_t next = flow.last_drop_time;
        while (count > 1) {
            const std::uint64_t step = next_drop_delay(count);
            if (next + step > now_ms)
                break;
            next += step;
            --count;
        }
        flow.drop_count = count;
        flow.drop_next = now_ms + next_drop_delay(count);
    } else {
        flow.drop_count = 1;
        flow.drop_next = now_ms + next_drop_delay(1);
    }
    flow.last_drop_time = now_ms;
    return true;
}

bool FqCoDelScheduler::MarkCe(QueuedPacket &pkt) noexcept {
    const std::size_t length = pkt.lease.Size();
    std::uint8_t *const data = pkt.lease.Data();
    if (data == nullptr || length < 20) {
        return false;
    }

    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    if (version == 4) {
        // IPv4: ECN occupies the low two bits of the TOS byte.
        const std::uint8_t ecn = static_cast<std::uint8_t>(data[1] & 0x03u);
        if (ecn != 0x01u && ecn != 0x02u) {
            return false; // Not-ECT or already CE
        }
        data[1] = static_cast<std::uint8_t>((data[1] & 0xFCu) | 0x03u);
        // CE marking changed the header — refresh the IPv4 header checksum.
        const std::size_t header_length = static_cast<std::size_t>(data[0] & 0x0Fu) * 4;
        if (header_length >= 20 && header_length <= length) {
            data[10] = 0;
            data[11] = 0;
            const std::uint16_t cksum = InternetChecksum(data, header_length, 0);
            data[10] = static_cast<std::uint8_t>(cksum >> 8);
            data[11] = static_cast<std::uint8_t>(cksum & 0xFFu);
        }
        return true;
    }

    if (version == 6) {
        if (length < 40) {
            return false;
        }
        // IPv6: ECN occupies bits 4-5 of the second byte (low bits of the
        // traffic class). IPv6 has no header checksum to refresh.
        const std::uint8_t ecn = static_cast<std::uint8_t>((data[1] >> 4) & 0x03u);
        if (ecn != 0x01u && ecn != 0x02u) {
            return false; // Not-ECT or already CE
        }
        data[1] = static_cast<std::uint8_t>((data[1] & 0xCFu) | 0x30u);
        return true;
    }

    return false;
}

std::optional<FqCoDelPacket> FqCoDelScheduler::ServeFlow(std::uint32_t idx, FlowList list,
                                                         std::uint64_t now_ms) noexcept {
    Flow &flow = flows_[idx];
    const std::uint32_t flow_hash = flow.flow_hash;

    while (!flow.queue.empty()) {
        // Take the head packet out of the queue before any CoDel verdict.
        QueuedPacket pkt = std::move(flow.queue.front());
        flow.queue.pop_front();
        const std::size_t size = pkt.lease.Size();
        flow.queue_bytes -= size;
        total_packets_--;
        total_bytes_ -= size;
        flow.deficit -= static_cast<std::int64_t>(size);

        const std::uint64_t sojourn = (now_ms >= pkt.enqueue_time_ms) ? (now_ms - pkt.enqueue_time_ms) : 0;

        if (!CodelShouldDrop(flow, sojourn, now_ms)) {
            FqCoDelPacket out;
            out.lease = std::move(pkt.lease);
            out.enqueue_time_ms = pkt.enqueue_time_ms;
            out.flow_hash = flow_hash; // saved before any slot release
            return out;
        }

        // CoDel demanded a drop; ECN-capable packets are CE-marked and
        // delivered instead (RFC 8290 §3.4 / RFC 8311).
        if (config_.ecn_ce_marking && MarkCe(pkt)) {
            FqCoDelPacket out;
            out.lease = std::move(pkt.lease);
            out.enqueue_time_ms = pkt.enqueue_time_ms;
            out.flow_hash = flow_hash;
            out.ce_marked = true;
            return out;
        }
        // Drop: pkt's destructor returns the lease to its pool.
    }

    // Queue drained (delivered nothing or everything dropped).
    (void)list;
    return std::nullopt;
}

std::optional<FqCoDelPacket> FqCoDelScheduler::Dequeue(std::uint64_t now_ms) noexcept {
    // New flows first (RFC 8290): serviced with priority, one packet per
    // call, until they drain and move to the old-flow list.
    while (!new_flows_.empty()) {
        const std::uint32_t idx = new_flows_.front();
        Flow &flow = flows_[idx];
        if (flow.queue.empty()) {
            new_flows_.pop_front();
            ReleaseFlowSlot(idx);
            continue;
        }

        if (flow.deficit <= 0) {
            flow.deficit += static_cast<std::int64_t>(config_.quantum);
        }
        if (flow.deficit < static_cast<std::int64_t>(flow.queue.front().lease.Size())) {
            // Not enough credit yet — mature into the old-flow DRR list.
            new_flows_.pop_front();
            flow.list = FlowList::Old;
            old_flows_.push_back(idx);
            continue;
        }

        auto pkt = ServeFlow(idx, FlowList::New, now_ms);
        if (pkt) {
            if (flow.queue.empty()) {
                new_flows_.pop_front();
                ReleaseFlowSlot(idx);
            }
            return pkt;
        }
        // Drained (possibly all drops): release the slot.
        new_flows_.pop_front();
        ReleaseFlowSlot(idx);
    }

    // Old flows: deficit round-robin with CoDel gating.
    while (!old_flows_.empty()) {
        const std::uint32_t idx = old_flows_.front();
        Flow &flow = flows_[idx];
        if (flow.queue.empty()) {
            old_flows_.pop_front();
            ReleaseFlowSlot(idx);
            continue;
        }

        if (flow.deficit < static_cast<std::int64_t>(flow.queue.front().lease.Size())) {
            flow.deficit += static_cast<std::int64_t>(config_.quantum);
            old_flows_.pop_front();
            old_flows_.push_back(idx);
            continue;
        }

        auto pkt = ServeFlow(idx, FlowList::Old, now_ms);
        if (pkt) {
            // Flow keeps its place at the head while it has credit.
            return pkt;
        }
        // Drained — release the slot.
        old_flows_.pop_front();
        ReleaseFlowSlot(idx);
    }

    return std::nullopt;
}

bool FqCoDelScheduler::Empty() const noexcept { return total_packets_ == 0; }

void FqCoDelScheduler::Reset() noexcept {
    for (std::uint32_t i = 0; i < flows_.size(); ++i) {
        ReleaseFlowSlot(i);
    }
    new_flows_.clear();
    old_flows_.clear();
    total_packets_ = 0;
    total_bytes_ = 0;
}

std::size_t FqCoDelScheduler::ActiveFlowCount() const noexcept {
    std::size_t count = 0;
    for (const auto &flow : flows_) {
        if (!flow.queue.empty()) {
            ++count;
        }
    }
    return count;
}

} // namespace tcpip2
