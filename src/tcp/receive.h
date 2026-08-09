#pragma once

/**
 * @file receive.h
 * @brief Fixed-capacity TCP receive sequencing and reassembly.
 * @license GPL-3.0
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcpip2 {

enum class ReceiveDisposition {
    Accepted,
    Duplicate,
    OutOfWindow,
    Invalid,
};

enum class AckDecision {
    None,
    Delayed,
    Immediate,
};

struct TcpReceiveResult {
    ReceiveDisposition disposition = ReceiveDisposition::Invalid;
    AckDecision ack_decision = AckDecision::None;
    std::size_t accepted_bytes = 0;
    std::size_t left_trimmed = 0;
    std::size_t right_trimmed = 0;
    std::size_t duplicate_bytes = 0;
};

struct TcpReadyView {
    const std::uint8_t* data = nullptr;
    std::size_t length = 0;
};

struct TcpSackBlock {
    std::uint32_t left_edge = 0;
    std::uint32_t right_edge = 0;
};

struct TcpSackBlockList {
    std::array<TcpSackBlock, 4> blocks{};
    std::size_t count = 0;
};

/**
 * Single-owner receive ring. Construction allocates all backing storage;
 * segment processing, delivery, and SACK inspection do not allocate.
 */
class TcpReceiveBuffer final {
public:
    explicit TcpReceiveBuffer(std::size_t capacity,
                               std::uint32_t initial_sequence = 0,
                               std::size_t initial_advertised_window = 0);

    TcpReceiveBuffer(const TcpReceiveBuffer&) = delete;
    TcpReceiveBuffer& operator=(const TcpReceiveBuffer&) = delete;

    TcpReceiveResult OnSegment(std::uint32_t sequence,
                               const std::uint8_t* data,
                               std::size_t length,
                               bool psh) noexcept;
    bool IsSequenceAcceptable(std::uint32_t sequence,
                              std::size_t segment_length) const noexcept;

    TcpReadyView ReadyView() const noexcept;
    std::size_t ConsumeReady(std::size_t length) noexcept;
    void SetBlocked(bool blocked) noexcept { blocked_ = blocked; }
    void AckSent() noexcept { delayed_ack_pending_ = false; }
    void RecordAdvertisedWindow(std::size_t window) noexcept;
    TcpSackBlockList SackBlocks(std::size_t max_blocks = 4) const noexcept;

    std::size_t AdvertisedWindow() const noexcept {
        return blocked_ ? 0 : capacity_ - bytes_held_;
    }
    std::size_t AcceptableWindow() const noexcept;
    std::size_t BytesHeld() const noexcept { return bytes_held_; }
    std::size_t ReadyBytes() const noexcept { return ready_bytes_; }
    std::size_t OutOfOrderBytes() const noexcept {
        return bytes_held_ - ready_bytes_;
    }
    std::uint32_t RcvNxt() const noexcept { return rcv_nxt_; }
    void ConsumeFin() noexcept;
    bool FinReceived() const noexcept { return fin_received_; }
    std::size_t Capacity() const noexcept { return capacity_; }
    bool Blocked() const noexcept { return blocked_; }
    std::size_t MemoryBytes() const noexcept {
        return storage_.size() + occupancy_.size() * sizeof(std::uint64_t);
    }

private:
    std::size_t PhysicalIndex(std::size_t logical_offset) const noexcept;
    bool Occupied(std::size_t physical_index) const noexcept;
    void SetOccupied(std::size_t physical_index, bool occupied) noexcept;

    std::size_t capacity_;
    std::vector<std::uint8_t> storage_;
    std::vector<std::uint64_t> occupancy_;
    std::uint32_t first_undelivered_;
    std::uint32_t rcv_nxt_;
    std::uint32_t rcv_adv_;
    std::size_t first_index_ = 0;
    std::size_t bytes_held_ = 0;
    std::size_t ready_bytes_ = 0;
    bool blocked_ = false;
    bool delayed_ack_pending_ = false;
    TcpSackBlock recent_sack_{};
    bool recent_sack_valid_ = false;
    bool fin_received_ = false;
};

} // namespace tcpip2
