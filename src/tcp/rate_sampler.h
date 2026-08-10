#pragma once

/**
 * @file rate_sampler.h
 * @brief Delivery-rate sampler for BBR/KCC congestion controllers.
 * @license GPL-3.0
 *
 * Tracks per-packet delivery information so that ACKs can produce
 * RateSample values consumable by BBR or KCC controllers.  The model
 * follows the Linux TCP delivery-rate estimator: every in-flight
 * segment is stamped with the total-delivered counter and timestamp at
 * send time; when a cumulative ACK covers a segment, the difference in
 * delivered bytes divided by the interval gives a delivery rate.
 *
 * This is a private header used only by src/tcp/ — not part of the
 * frozen public API.
 */

#include <cstddef>
#include <cstdint>

namespace tcpip2 {

/// Information passed to the congestion controller on every ACK.
struct RateSample {
    std::uint64_t now_ms = 0;
    /// Delivery rate in bytes per second (0 until first RTT-complete sample).
    std::uint64_t delivery_rate_bytes_per_sec = 0;
    /// Time between send and ACK for the sample (ms).
    std::uint64_t interval_ms = 0;
    /// RTT of the sampled packet (ms).
    std::uint64_t rtt_ms = 0;
    /// Bytes newly acknowledged by this ACK.
    std::uint64_t acked_bytes = 0;
    /// Bytes lost since the last sample (detected via RTO or SACK).
    std::uint64_t lost_bytes = 0;
    /// Estimated bytes currently in flight.
    std::uint64_t inflight_bytes = 0;
    /// True if the application is not filling the congestion window.
    bool app_limited = false;
    /// True if ECN CE was observed on the ACK path.
    bool ecn_ce = false;
};

/// Per-packet information recorded at send time and consumed at ACK time.
/// Stored inside SendRecord by TcpSendBuffer.
struct PacketDeliveryState {
    /// Total bytes delivered (ACKed) at the moment this packet was sent.
    std::uint64_t delivered_bytes = 0;
    /// Timestamp (ms) when delivered_bytes was last updated at send time.
    std::uint64_t delivered_time_ms = 0;
    /// Timestamp (ms) when this packet was first transmitted.
    std::uint64_t first_sent_time_ms = 0;
    /// True if the connection was app-limited when this packet was sent.
    bool app_limited = false;
    /// True if this packet has been retransmitted (invalidates rate sample).
    bool retransmitted = false;
};

/// Tracks connection-level delivery counters for rate sampling.
///
/// The TcpSendBuffer owns one instance and calls:
///   - OnPacketSent() when a new segment is transmitted
///   - OnAck() when a cumulative ACK covers a segment
///   - MarkAppLimited() when the send queue is drained below cwnd
class DeliveryRateSampler {
public:
    DeliveryRateSampler() = default;

    /// Stamp a PacketDeliveryState for a newly-sent segment.
    /// Called by TcpSendBuffer::StoreNewRecord.
    void OnPacketSent(PacketDeliveryState& pkt, std::uint64_t now_ms) noexcept;

    /// Generate a RateSample when a segment is ACKed.
    /// @param pkt   The PacketDeliveryState of the ACKed segment.
    /// @param acked_bytes Bytes newly acknowledged in this ACK event.
    /// @param now_ms Current monotonic time.
    /// @param inflight_bytes Current in-flight bytes after this ACK.
    RateSample OnAck(const PacketDeliveryState& pkt,
                     std::uint64_t acked_bytes,
                     std::uint64_t now_ms,
                     std::uint64_t inflight_bytes) noexcept;

    /// Mark the connection as app-limited at @p now_ms.
    void MarkAppLimited(std::uint64_t now_ms) noexcept;

    /// Clear app-limited state (called when new data is enqueued).
    void ClearAppLimited() noexcept { app_limited_ = false; }

    /// @return True if currently app-limited.
    bool IsAppLimited() const noexcept { return app_limited_; }

    /// @return Total bytes delivered so far.
    std::uint64_t DeliveredBytes() const noexcept { return delivered_bytes_; }

    /// @return Timestamp of the last delivery update.
    std::uint64_t DeliveredTime() const noexcept { return delivered_time_ms_; }

    /// @return The most recent RateSample (or a default-constructed one).
    const RateSample& LastSample() const noexcept { return last_sample_; }

    /// Reset all state (called on close/reset).
    void Reset() noexcept;

private:
    std::uint64_t delivered_bytes_ = 0;
    std::uint64_t delivered_time_ms_ = 0;
    bool app_limited_ = false;
    RateSample last_sample_{};
};

} // namespace tcpip2
