#include "rate_sampler.h"

#include <algorithm>
#include <cstdint>
#include <limits>

namespace tcpip2 {

namespace {

std::uint64_t SaturatingSub(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? a - b : 0;
}

std::uint64_t SaturatingMulDiv(std::uint64_t bytes,
                                std::uint64_t multiplier,
                                std::uint64_t divisor) noexcept {
    if (divisor == 0) return 0;
    if (bytes == 0 || multiplier == 0) return 0;
    // Guard against overflow: bytes * multiplier
    if (bytes > std::numeric_limits<std::uint64_t>::max() / multiplier) {
        // Saturate
        return std::numeric_limits<std::uint64_t>::max() / divisor;
    }
    return (bytes * multiplier) / divisor;
}

} // namespace

void DeliveryRateSampler::OnPacketSent(PacketDeliveryState& pkt,
                                        std::uint64_t now_ms) noexcept {
    pkt.delivered_bytes = delivered_bytes_;
    pkt.delivered_time_ms = delivered_time_ms_;
    if (pkt.first_sent_time_ms == 0) {
        pkt.first_sent_time_ms = now_ms;
    }
    pkt.app_limited = app_limited_;
    pkt.retransmitted = false;
}

RateSample DeliveryRateSampler::OnAck(const PacketDeliveryState& pkt,
                                       std::uint64_t acked_bytes,
                                       std::uint64_t now_ms,
                                       std::uint64_t inflight_bytes) noexcept {
    RateSample sample;
    sample.now_ms = now_ms;
    sample.acked_bytes = acked_bytes;
    sample.inflight_bytes = inflight_bytes;
    sample.app_limited = pkt.app_limited;

    // Update delivered counters.
    delivered_bytes_ += acked_bytes;
    delivered_time_ms_ = now_ms;

    // Compute RTT for this packet.
    // If the packet was retransmitted, the rate sample is not trustworthy
    // (we cannot know which transmission the ACK refers to).  In that case
    // we still report acked_bytes but leave delivery_rate at 0.
    if (!pkt.retransmitted && now_ms >= pkt.first_sent_time_ms) {
        sample.rtt_ms = now_ms - pkt.first_sent_time_ms;

        // Delivery rate = delivered增量 / interval
        // Interval = delivered_time_ms (now) - pkt.delivered_time_ms
        const std::uint64_t interval_ms =
            SaturatingSub(delivered_time_ms_, pkt.delivered_time_ms);

        if (interval_ms > 0) {
            const std::uint64_t delivered_delta =
                SaturatingSub(delivered_bytes_, pkt.delivered_bytes);

            sample.interval_ms = interval_ms;
            sample.delivery_rate_bytes_per_sec =
                SaturatingMulDiv(delivered_delta, 1000, interval_ms);
        }
    }

    last_sample_ = sample;
    return sample;
}

void DeliveryRateSampler::MarkAppLimited(std::uint64_t now_ms) noexcept {
    (void)now_ms;
    app_limited_ = true;
}

void DeliveryRateSampler::Reset() noexcept {
    delivered_bytes_ = 0;
    delivered_time_ms_ = 0;
    app_limited_ = false;
    last_sample_ = {};
}

} // namespace tcpip2
