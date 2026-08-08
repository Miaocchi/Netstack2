#include <tcp/receive.h>

#include <algorithm>
#include <stdexcept>

namespace tcpip2 {
namespace {

constexpr std::size_t kMaximumCapacity = 0x7fffffffu;
constexpr std::uint32_t kHalfSequenceSpace = 0x80000000u;

std::size_t ValidateCapacity(std::size_t capacity) {
    if (capacity == 0 || capacity > kMaximumCapacity) {
        throw std::invalid_argument("TCP receive capacity must be in [1, 2^31-1]");
    }
    return capacity;
}

bool SequenceOffset(std::uint32_t sequence, std::uint32_t base,
                    std::int64_t& offset) noexcept {
    const std::uint32_t forward = sequence - base;
    if (forward == kHalfSequenceSpace) return false;
    if (forward < kHalfSequenceSpace) {
        offset = static_cast<std::int64_t>(forward);
    } else {
        offset = -static_cast<std::int64_t>(base - sequence);
    }
    return true;
}

} // namespace

TcpReceiveBuffer::TcpReceiveBuffer(std::size_t capacity,
                                   std::uint32_t initial_sequence,
                                   std::size_t initial_advertised_window)
    : capacity_(ValidateCapacity(capacity)),
      storage_(capacity_),
      occupancy_((capacity_ + 63) / 64, 0),
      first_undelivered_(initial_sequence),
      rcv_nxt_(initial_sequence),
      rcv_adv_(initial_sequence + static_cast<std::uint32_t>(
          initial_advertised_window == 0
              ? capacity_
              : std::min(initial_advertised_window, capacity_))) {}

std::size_t TcpReceiveBuffer::PhysicalIndex(
    std::size_t logical_offset) const noexcept {
    const std::size_t until_end = capacity_ - first_index_;
    return logical_offset < until_end
        ? first_index_ + logical_offset
        : logical_offset - until_end;
}

bool TcpReceiveBuffer::Occupied(std::size_t physical_index) const noexcept {
    const std::uint64_t mask = std::uint64_t{1} << (physical_index % 64);
    return (occupancy_[physical_index / 64] & mask) != 0;
}

void TcpReceiveBuffer::SetOccupied(std::size_t physical_index,
                                   bool occupied) noexcept {
    const std::uint64_t mask = std::uint64_t{1} << (physical_index % 64);
    std::uint64_t& word = occupancy_[physical_index / 64];
    if (occupied) {
        word |= mask;
    } else {
        word &= ~mask;
    }
}

std::size_t TcpReceiveBuffer::AcceptableWindow() const noexcept {
    const std::uint32_t forward = rcv_adv_ - rcv_nxt_;
    return forward < kHalfSequenceSpace
        ? std::min<std::size_t>(forward, capacity_ - ready_bytes_)
        : 0;
}

void TcpReceiveBuffer::RecordAdvertisedWindow(std::size_t window) noexcept {
    const std::size_t bounded = std::min(window, capacity_ - ready_bytes_);
    const std::uint32_t candidate =
        rcv_nxt_ + static_cast<std::uint32_t>(bounded);
    std::int64_t advance = 0;
    if (SequenceOffset(candidate, rcv_adv_, advance) && advance > 0) {
        rcv_adv_ = candidate;
    }
}

bool TcpReceiveBuffer::IsSequenceAcceptable(
    std::uint32_t sequence, std::size_t segment_length) const noexcept {
    if (segment_length > kMaximumCapacity) return false;
    std::int64_t begin = 0;
    if (!SequenceOffset(sequence, rcv_nxt_, begin)) return false;
    const std::size_t window = AcceptableWindow();
    if (window == 0) return segment_length == 0 && begin == 0;
    if (segment_length == 0) {
        return begin >= 0 && static_cast<std::size_t>(begin) < window;
    }
    const std::int64_t end = begin + static_cast<std::int64_t>(segment_length) - 1;
    return (begin >= 0 && static_cast<std::size_t>(begin) < window) ||
           (end >= 0 && static_cast<std::size_t>(end) < window);
}

TcpReceiveResult TcpReceiveBuffer::OnSegment(std::uint32_t sequence,
                                              const std::uint8_t* data,
                                              std::size_t length,
                                              bool psh) noexcept {
    TcpReceiveResult result;
    if (data == nullptr || length == 0 || length > kMaximumCapacity) {
        return result;
    }

    std::int64_t segment_begin = 0;
    if (!SequenceOffset(sequence, rcv_nxt_, segment_begin)) {
        result.disposition = ReceiveDisposition::OutOfWindow;
        result.ack_decision = AckDecision::Immediate;
        result.right_trimmed = length;
        delayed_ack_pending_ = false;
        return result;
    }

    if (!IsSequenceAcceptable(sequence, length)) {
        const std::int64_t segment_end_for_disposition =
            segment_begin + static_cast<std::int64_t>(length);
        result.disposition = segment_end_for_disposition <= 0
            ? ReceiveDisposition::Duplicate
            : ReceiveDisposition::OutOfWindow;
        result.ack_decision = AckDecision::Immediate;
        if (result.disposition == ReceiveDisposition::Duplicate) {
            result.left_trimmed = length;
        } else {
            result.right_trimmed = length;
        }
        delayed_ack_pending_ = false;
        return result;
    }

    const std::int64_t segment_end =
        segment_begin + static_cast<std::int64_t>(length);
    const std::int64_t window_end =
        static_cast<std::int64_t>(AcceptableWindow());

    if (segment_begin < 0) {
        const std::size_t before_rcv_nxt =
            static_cast<std::size_t>(-segment_begin);
        result.left_trimmed = std::min(length, before_rcv_nxt);
    }

    const std::int64_t accepted_begin = std::max<std::int64_t>(0, segment_begin);
    const std::int64_t accepted_end = std::min(segment_end, window_end);
    std::size_t candidate_bytes = 0;
    if (accepted_end > accepted_begin) {
        candidate_bytes = static_cast<std::size_t>(accepted_end - accepted_begin);
    }
    result.right_trimmed = length - result.left_trimmed - candidate_bytes;

    if (candidate_bytes == 0) {
        result.disposition = segment_end <= 0
            ? ReceiveDisposition::Duplicate
            : ReceiveDisposition::OutOfWindow;
        result.ack_decision = AckDecision::Immediate;
        delayed_ack_pending_ = false;
        return result;
    }

    const std::size_t window_offset =
        static_cast<std::size_t>(accepted_begin);
    const std::size_t logical_offset = ready_bytes_ + window_offset;
    std::uint32_t first_new_sequence = 0;
    bool first_new_sequence_set = false;
    for (std::size_t i = 0; i < candidate_bytes; ++i) {
        const std::size_t physical = PhysicalIndex(logical_offset + i);
        if (Occupied(physical)) {
            ++result.duplicate_bytes;
            continue;
        }
        storage_[physical] = data[result.left_trimmed + i];
        SetOccupied(physical, true);
        if (!first_new_sequence_set) {
            first_new_sequence = sequence + static_cast<std::uint32_t>(
                result.left_trimmed + i);
            first_new_sequence_set = true;
        }
        ++result.accepted_bytes;
        ++bytes_held_;
    }

    const std::size_t old_ready_bytes = ready_bytes_;
    while (ready_bytes_ < capacity_ &&
           Occupied(PhysicalIndex(ready_bytes_))) {
        ++ready_bytes_;
    }
    const std::size_t advanced = ready_bytes_ - old_ready_bytes;
    rcv_nxt_ += static_cast<std::uint32_t>(advanced);

    result.disposition = result.accepted_bytes == 0
        ? ReceiveDisposition::Duplicate
        : ReceiveDisposition::Accepted;

    if (accepted_begin > 0) {
        const std::uint32_t trigger_sequence = first_new_sequence_set
            ? first_new_sequence
            : sequence + static_cast<std::uint32_t>(result.left_trimmed);
        const std::uint32_t trigger_offset = trigger_sequence - rcv_nxt_;
        if (trigger_offset != 0 && trigger_offset < kHalfSequenceSpace) {
            std::size_t block_begin = ready_bytes_ + trigger_offset;
            std::size_t block_end = block_begin + 1;
            while (block_begin > ready_bytes_ &&
                   Occupied(PhysicalIndex(block_begin - 1))) {
                --block_begin;
            }
            while (block_end < capacity_ && Occupied(PhysicalIndex(block_end))) {
                ++block_end;
            }
            recent_sack_.left_edge = rcv_nxt_ + static_cast<std::uint32_t>(
                block_begin - ready_bytes_);
            recent_sack_.right_edge = rcv_nxt_ + static_cast<std::uint32_t>(
                block_end - ready_bytes_);
            recent_sack_valid_ = true;
        }
    }

    const bool out_of_order = accepted_begin > 0;
    const bool overlap = result.left_trimmed != 0 ||
                         result.duplicate_bytes != 0;
    const bool gap_fill = advanced > result.accepted_bytes;
    const bool immediate = blocked_ || out_of_order || overlap ||
                            result.right_trimmed != 0 || gap_fill || psh ||
                           result.accepted_bytes == 0;
    if (immediate) {
        result.ack_decision = AckDecision::Immediate;
        delayed_ack_pending_ = false;
    } else if (delayed_ack_pending_) {
        result.ack_decision = AckDecision::Immediate;
        delayed_ack_pending_ = false;
    } else {
        result.ack_decision = AckDecision::Delayed;
        delayed_ack_pending_ = true;
    }
    return result;
}

TcpReadyView TcpReceiveBuffer::ReadyView() const noexcept {
    if (ready_bytes_ == 0) return {};
    return {
        storage_.data() + first_index_,
        std::min(ready_bytes_, capacity_ - first_index_),
    };
}

std::size_t TcpReceiveBuffer::ConsumeReady(std::size_t length) noexcept {
    const std::size_t consumed = std::min(length, ready_bytes_);
    for (std::size_t i = 0; i < consumed; ++i) {
        SetOccupied(PhysicalIndex(i), false);
    }
    first_undelivered_ += static_cast<std::uint32_t>(consumed);
    first_index_ = PhysicalIndex(consumed);
    bytes_held_ -= consumed;
    ready_bytes_ -= consumed;
    return consumed;
}

TcpSackBlockList TcpReceiveBuffer::SackBlocks(
    std::size_t max_blocks) const noexcept {
    TcpSackBlockList result;
    const std::size_t limit = std::min(max_blocks, result.blocks.size());
    if (limit == 0) return result;

    if (recent_sack_valid_) {
        const std::uint32_t width = recent_sack_.right_edge - recent_sack_.left_edge;
        const std::uint32_t offset = recent_sack_.left_edge - rcv_nxt_;
        if (offset < kHalfSequenceSpace && width != 0) {
            bool complete = true;
            const std::size_t logical_begin = ready_bytes_ + offset;
            for (std::uint32_t i = 0; i < width; ++i) {
                if (logical_begin + i >= capacity_ ||
                    !Occupied(PhysicalIndex(logical_begin + i))) {
                    complete = false;
                    break;
                }
            }
            if (complete) result.blocks[result.count++] = recent_sack_;
        }
    }

    std::size_t remaining = OutOfOrderBytes();
    std::size_t logical = ready_bytes_;
    while (logical < capacity_ && result.count < limit && remaining != 0) {
        while (logical < capacity_ && !Occupied(PhysicalIndex(logical))) {
            ++logical;
        }
        if (logical == capacity_) break;

        const std::size_t block_begin = logical;
        while (logical < capacity_ && Occupied(PhysicalIndex(logical))) {
            ++logical;
            --remaining;
        }
        TcpSackBlock block;
        block.left_edge = rcv_nxt_ + static_cast<std::uint32_t>(
            block_begin - ready_bytes_);
        block.right_edge = rcv_nxt_ + static_cast<std::uint32_t>(
            logical - ready_bytes_);
        if (result.count != 0 &&
            block.left_edge == result.blocks[0].left_edge &&
            block.right_edge == result.blocks[0].right_edge) {
            continue;
        }
        result.blocks[result.count++] = block;
    }
    return result;
}

} // namespace tcpip2
