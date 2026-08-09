#include "send.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

namespace tcpip2 {
namespace {

bool SequenceBefore(std::uint32_t left, std::uint32_t right) noexcept {
    return static_cast<std::int32_t>(left - right) < 0;
}

bool SequenceAfter(std::uint32_t left, std::uint32_t right) noexcept {
    return static_cast<std::int32_t>(left - right) > 0;
}

std::uint32_t SaturatingUint32(std::size_t value) noexcept {
    return value > std::numeric_limits<std::uint32_t>::max()
               ? std::numeric_limits<std::uint32_t>::max()
               : static_cast<std::uint32_t>(value);
}

std::uint64_t SaturatingAdd(std::uint64_t left, std::uint64_t right) noexcept {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return left + right;
}

} // namespace

bool TcpSendConfig::Validate() const noexcept {
    return initial_mss != 0 && window_scale <= 14 && send_queue_limit != 0 &&
           retransmit_queue_limit != 0 && min_rto_ms != 0 &&
           min_rto_ms <= initial_rto_ms && initial_rto_ms <= max_rto_ms &&
           persist_timer_base_ms != 0 &&
           persist_timer_base_ms <= persist_timer_max_ms &&
           max_retransmissions != 0 && max_persist_probes != 0;
}

TcpSendBuffer::TcpSendBuffer(std::uint32_t initial_sequence,
                             std::uint16_t mss,
                             std::uint8_t window_scale,
                             std::size_t queue_limit,
                             std::size_t retransmit_limit,
                             std::uint64_t initial_rto_ms,
                             std::uint64_t min_rto_ms,
                             std::uint64_t max_rto_ms,
                             std::uint64_t persist_base_ms,
                             std::uint64_t persist_max_ms,
                             std::size_t max_retransmissions,
                             std::size_t max_persist_probes)
    : send_queue_limit_(queue_limit),
      retransmit_limit_(retransmit_limit),
      snd_una_(initial_sequence),
      snd_nxt_(initial_sequence),
      snd_max_(initial_sequence),
      cwnd_(static_cast<std::uint32_t>(mss) * 2U),
      ssthresh_(std::numeric_limits<std::uint32_t>::max()),
      mss_(mss),
      rto_ms_(initial_rto_ms),
      rto_deadline_ms_(0),
      min_rto_ms_(min_rto_ms),
      max_rto_ms_(max_rto_ms),
      max_retransmissions_(max_retransmissions),
      persist_base_ms_(persist_base_ms),
      persist_max_ms_(persist_max_ms),
      persist_current_ms_(persist_base_ms),
      max_persist_probes_(max_persist_probes) {
    (void)window_scale;
    send_queue_.reserve(queue_limit);
}

std::size_t TcpSendBuffer::Enqueue(const std::uint8_t* data,
                                   std::size_t length) noexcept {
    if (data == nullptr || length == 0 || fin_requested_ || closed_ ||
        send_queue_.size() >= send_queue_limit_) {
        return 0;
    }

    const std::size_t accepted =
        std::min(length, send_queue_limit_ - send_queue_.size());
    send_queue_.insert(send_queue_.end(), data, data + accepted);
    return accepted;
}

bool TcpSendBuffer::RequestFin() noexcept {
    if (fin_requested_ || closed_) {
        return false;
    }
    fin_requested_ = true;
    return true;
}

std::size_t TcpSendBuffer::UsableWindow(std::uint32_t peer_window) const noexcept {
    const std::size_t allowed = std::min<std::size_t>(peer_window, cwnd_);
    // RFC 6675 pipe: in-flight minus SACKed bytes.
    const std::size_t pipe =
        in_flight_sequence_ > sacked_sequence_
            ? in_flight_sequence_ - sacked_sequence_
            : 0;
    return allowed > pipe ? allowed - pipe : 0;
}

bool TcpSendBuffer::CanSendNew(std::uint32_t peer_window) const noexcept {
    if (peer_window == 0 || UsableWindow(peer_window) == 0 ||
        retransmit_bytes_ >= retransmit_limit_) {
        return false;
    }
    return !send_queue_.empty() || (fin_requested_ && !fin_sent_);
}

TcpSendNextResult TcpSendBuffer::NextSegment(std::uint32_t peer_window,
                                             std::uint64_t now_ms) noexcept {
    TcpSendNextResult result;
    if (closed_ || pending_kind_ != PendingKind::None) {
        return result;
    }
    if (!peer_window_valid_) {
        last_peer_window_ = peer_window;
        peer_window_valid_ = true;
    }

    if (peer_window == 0) {
        // A persist timer, rather than the retransmission timer, governs a
        // connection whose peer has explicitly closed its receive window.
        rto_running_ = false;
        rto_deadline_ms_ = 0;
        ArmPersistTimer(now_ms);
        if (!PersistExpired(now_ms)) {
            return result;
        }
        if (persist_probe_count_ >= max_persist_probes_) {
            Close();
            return result;
        }

        if (persist_probe_.has_value()) {
            const SendRecord& probe = *persist_probe_;
            result.has_segment = true;
            result.is_retransmission = true;
            result.is_zero_window_probe = true;
            result.is_fin = probe.logical_length > probe.data.Size();
            result.payload = probe.data.Data();
            result.payload_length = probe.data.Size();
            result.sequence = probe.seq;
            pending_kind_ = PendingKind::PersistRetry;
            pending_seq_ = probe.seq;
            pending_len_ = probe.logical_length;
            pending_is_fin_ = result.is_fin;
            return result;
        }

        if (!retransmit_queue_.empty()) {
            const SendRecord& record = retransmit_queue_.front();
            const std::size_t payload_length = record.data.Empty() ? 0 : 1;
            result.has_segment = true;
            result.is_retransmission = true;
            result.is_zero_window_probe = true;
            result.is_fin = payload_length == 0 &&
                            record.logical_length > record.data.Size();
            result.payload = record.data.Data();
            result.payload_length = payload_length;
            result.sequence = record.seq;
            pending_kind_ = PendingKind::PersistExisting;
            pending_seq_ = record.seq;
            pending_len_ = payload_length + (result.is_fin ? 1U : 0U);
            pending_is_fin_ = result.is_fin;
            return result;
        }

        if (retransmit_bytes_ >= retransmit_limit_) {
            return result;
        }
        if (!send_queue_.empty()) {
            result.has_segment = true;
            result.is_zero_window_probe = true;
            result.payload = send_queue_.data();
            result.payload_length = 1;
            result.sequence = snd_nxt_;
            pending_kind_ = PendingKind::PersistNew;
            pending_seq_ = snd_nxt_;
            pending_len_ = 1;
            return result;
        }
        if (fin_requested_ && !fin_sent_) {
            result.has_segment = true;
            result.is_zero_window_probe = true;
            result.is_fin = true;
            result.sequence = snd_nxt_;
            pending_kind_ = PendingKind::PersistNew;
            pending_is_fin_ = true;
            pending_seq_ = snd_nxt_;
            pending_len_ = 1;
        }
        return result;
    }

    CancelPersist();

    if (persist_probe_.has_value()) {
        const SendRecord& probe = *persist_probe_;
        if (UsableWindow(peer_window) < probe.logical_length) {
            return result;
        }
        result.has_segment = true;
        result.is_retransmission = true;
        result.is_fin = probe.logical_length > probe.data.Size();
        result.payload = probe.data.Data();
        result.payload_length = probe.data.Size();
        result.sequence = probe.seq;
        pending_kind_ = PendingKind::PersistPromote;
        pending_seq_ = probe.seq;
        pending_len_ = probe.logical_length;
        pending_is_fin_ = result.is_fin;
        return result;
    }

    if (!retransmit_queue_.empty() && !rto_running_) {
        ArmRto(now_ms);
    }

    const auto prepare_retransmission =
        [&](const SendRecord& record, PendingKind kind) noexcept {
            const std::size_t payload_length =
                std::min({record.data.Size(), static_cast<std::size_t>(mss_),
                          static_cast<std::size_t>(peer_window)});
            const bool include_fin =
                record.logical_length > record.data.Size() &&
                payload_length == record.data.Size() &&
                payload_length < peer_window;
            if (payload_length == 0 && !include_fin) {
                return false;
            }

            result.has_segment = true;
            result.is_retransmission = true;
            result.is_fin = include_fin;
            result.payload = payload_length == 0 ? nullptr : record.data.Data();
            result.payload_length = payload_length;
            result.sequence = record.seq;
            pending_kind_ = kind;
            pending_seq_ = record.seq;
            pending_len_ = payload_length + (include_fin ? 1U : 0U);
            pending_is_fin_ = include_fin;
            return true;
        };

    if (fast_retransmit_pending_ && !retransmit_queue_.empty()) {
        prepare_retransmission(retransmit_queue_.front(),
                               PendingKind::FastRetransmit);
        return result;
    }

    if (RetransmitExpired(now_ms) && !retransmit_queue_.empty()) {
        prepare_retransmission(retransmit_queue_.front(),
                               PendingKind::RtoRetransmit);
        return result;
    }

    if (!CanSendNew(peer_window)) {
        return result;
    }

    const std::size_t usable = UsableWindow(peer_window);
    const std::size_t available = retransmit_limit_ - retransmit_bytes_;
    std::size_t payload_length =
        std::min({send_queue_.size(), static_cast<std::size_t>(mss_), usable,
                  available});
    bool include_fin = false;

    if (payload_length != 0) {
        include_fin = fin_requested_ && !fin_sent_ &&
                      payload_length == send_queue_.size() &&
                      payload_length < usable && payload_length < available;
    } else if (fin_requested_ && !fin_sent_ && usable != 0 && available != 0) {
        include_fin = true;
    } else {
        return result;
    }

    result.has_segment = true;
    result.is_fin = include_fin;
    result.payload = payload_length == 0 ? nullptr : send_queue_.data();
    result.payload_length = payload_length;
    result.sequence = snd_nxt_;
    pending_kind_ = PendingKind::NewData;
    pending_is_fin_ = include_fin;
    pending_seq_ = snd_nxt_;
    pending_len_ = payload_length + (include_fin ? 1U : 0U);
    return result;
}

bool TcpSendBuffer::StoreNewRecord(BufferRef owner,
                                   std::size_t payload_offset,
                                   std::uint64_t now_ms) noexcept {
    const std::size_t payload_length =
        pending_len_ - (pending_is_fin_ ? 1U : 0U);
    if (payload_length > send_queue_.size() ||
        pending_len_ > retransmit_limit_ - retransmit_bytes_) {
        return false;
    }
    if (payload_length != 0 &&
        (!owner || payload_offset > owner.Size() ||
         payload_length > owner.Size() - payload_offset)) {
        return false;
    }

    SendRecord record;
    record.seq = pending_seq_;
    record.logical_length = SaturatingUint32(pending_len_);
    record.owner = std::move(owner);
    if (payload_length != 0) {
        record.data = BufferSlice(record.owner.Data() + payload_offset,
                                  payload_length);
    }
    record.sent_time_ms = now_ms;
    retransmit_queue_.push_back(std::move(record));

    send_queue_.erase(send_queue_.begin(),
                      send_queue_.begin() +
                          static_cast<std::ptrdiff_t>(payload_length));
    retransmit_bytes_ += pending_len_;
    in_flight_bytes_ += payload_length;
    in_flight_sequence_ += pending_len_;
    snd_nxt_ += static_cast<std::uint32_t>(pending_len_);
    if (SequenceAfter(snd_nxt_, snd_max_)) {
        snd_max_ = snd_nxt_;
    }
    if (pending_is_fin_) {
        fin_sent_ = true;
    }
    if (!rto_running_) {
        ArmRto(now_ms);
    }
    return true;
}

void TcpSendBuffer::OnSent(BufferRef owner, std::size_t payload_offset,
                           std::uint64_t now_ms) noexcept {
    const PendingKind kind = pending_kind_;
    if (kind == PendingKind::None) {
        return;
    }

    bool accepted = true;
    if (kind == PendingKind::NewData) {
        accepted = StoreNewRecord(std::move(owner), payload_offset, now_ms);
    } else if (kind == PendingKind::PersistNew) {
        const std::size_t payload_length =
            pending_len_ - (pending_is_fin_ ? 1U : 0U);
        if (payload_length > send_queue_.size() ||
            pending_len_ > retransmit_limit_ - retransmit_bytes_ ||
            (payload_length != 0 &&
             (!owner || payload_offset > owner.Size() ||
              payload_length > owner.Size() - payload_offset))) {
            accepted = false;
        } else {
            SendRecord probe;
            probe.seq = pending_seq_;
            probe.logical_length = SaturatingUint32(pending_len_);
            probe.owner = std::move(owner);
            if (payload_length != 0) {
                probe.data = BufferSlice(probe.owner.Data() + payload_offset,
                                         payload_length);
            }
            probe.sent_time_ms = now_ms;
            probe.retransmitted = true;
            persist_probe_.emplace(std::move(probe));
            send_queue_.erase(send_queue_.begin(),
                              send_queue_.begin() +
                                  static_cast<std::ptrdiff_t>(payload_length));
            retransmit_bytes_ += pending_len_;
            snd_nxt_ += static_cast<std::uint32_t>(pending_len_);
            if (SequenceAfter(snd_nxt_, snd_max_)) {
                snd_max_ = snd_nxt_;
            }
            if (pending_is_fin_) {
                fin_sent_ = true;
            }
        }
    } else if (kind == PendingKind::PersistPromote) {
        if (!persist_probe_.has_value()) {
            accepted = false;
        } else {
            SendRecord record = std::move(*persist_probe_);
            persist_probe_.reset();
            record.sent_time_ms = now_ms;
            record.retransmitted = true;
            in_flight_bytes_ += record.data.Size();
            in_flight_sequence_ += record.logical_length;
            retransmit_queue_.push_back(std::move(record));
            ArmRto(now_ms);
        }
    } else if (kind == PendingKind::RtoRetransmit) {
        if (retransmit_queue_.empty()) {
            accepted = false;
        } else {
            SendRecord& record = retransmit_queue_.front();
            record.retransmitted = true;
            record.sent_time_ms = now_ms;
            const bool first_timeout = record.rto_attempts == 0;
            ++record.rto_attempts;
            ++retransmission_count_;
            if (first_timeout) {
                const std::uint32_t flight = SaturatingUint32(in_flight_sequence_);
                ssthresh_ = std::max<std::uint32_t>(
                    flight / 2U, static_cast<std::uint32_t>(mss_) * 2U);
            }
            cwnd_ = mss_;
            fast_recovery_ = false;
            fast_retransmit_pending_ = false;
            BackoffRto();
            ArmRto(now_ms);
            if (record.rto_attempts >= max_retransmissions_) {
                Close();
            }
        }
    } else if (kind == PendingKind::FastRetransmit) {
        if (retransmit_queue_.empty()) {
            accepted = false;
        } else {
            SendRecord& record = retransmit_queue_.front();
            record.retransmitted = true;
            record.sent_time_ms = now_ms;
            ++retransmission_count_;
            fast_retransmit_pending_ = false;
            ArmRto(now_ms);
        }
    } else if (kind == PendingKind::PersistRetry) {
        accepted = persist_probe_.has_value();
        if (accepted) {
            persist_probe_->retransmitted = true;
        }
    } else if (kind == PendingKind::PersistExisting) {
        accepted = !retransmit_queue_.empty();
        if (accepted) {
            retransmit_queue_.front().retransmitted = true;
        }
    }

    if (accepted && (kind == PendingKind::PersistNew ||
                     kind == PendingKind::PersistRetry ||
                     kind == PendingKind::PersistExisting)) {
        ++persist_probe_count_;
        ScheduleNextPersist(now_ms);
    }

    pending_kind_ = PendingKind::None;
    pending_is_fin_ = false;
    pending_seq_ = 0;
    pending_len_ = 0;
}

TcpSendAckResult TcpSendBuffer::OnAck(std::uint32_t acknowledgment,
                                      std::uint32_t peer_window,
                                      std::uint64_t now_ms,
                                      bool ack_only) noexcept {
    TcpSendAckResult result;

    if (SequenceAfter(acknowledgment, snd_max_)) {
        result.unacceptable = true;
        result.retransmit_queue_bytes = in_flight_bytes_;
        return result;
    }
    if (SequenceBefore(acknowledgment, snd_una_)) {
        result.retransmit_queue_bytes = in_flight_bytes_;
        return result;
    }

    if (acknowledgment == snd_una_) {
        result.duplicate = true;
        const bool has_outstanding =
            !retransmit_queue_.empty() || persist_probe_.has_value();
        const bool qualifying_duplicate =
            ack_only && has_outstanding && peer_window != 0 &&
            peer_window_valid_ &&
            peer_window == last_peer_window_;

        if (qualifying_duplicate) {
            ++dup_ack_count_;
            if (fast_recovery_) {
                // Inflate cwnd by 1 MSS per dup ACK during recovery (RFC 5681).
                const std::uint64_t inflated =
                    static_cast<std::uint64_t>(cwnd_) + mss_;
                cwnd_ = inflated > std::numeric_limits<std::uint32_t>::max()
                            ? std::numeric_limits<std::uint32_t>::max()
                            : static_cast<std::uint32_t>(inflated);
            }
            if (dup_ack_count_ == 3 && !retransmit_queue_.empty() &&
                !fast_recovery_) {
                const std::uint32_t flight = SaturatingUint32(in_flight_sequence_);
                ssthresh_ = std::max<std::uint32_t>(
                    flight / 2U, static_cast<std::uint32_t>(mss_) * 2U);
                const std::uint64_t recovery_window =
                    static_cast<std::uint64_t>(ssthresh_) +
                    static_cast<std::uint64_t>(mss_) * 3U;
                cwnd_ = recovery_window >
                                std::numeric_limits<std::uint32_t>::max()
                            ? std::numeric_limits<std::uint32_t>::max()
                            : static_cast<std::uint32_t>(recovery_window);
                fast_retransmit_pending_ = true;
                fast_recovery_ = true;
                result.fast_retransmit = true;
            }
        } else {
            dup_ack_count_ = 0;
        }

        last_peer_window_ = peer_window;
        peer_window_valid_ = true;
        if (peer_window == 0) {
            rto_running_ = false;
            rto_deadline_ms_ = 0;
            persist_probe_count_ = 0;
            persist_current_ms_ = persist_base_ms_;
            persist_deadline_ms_ = 0;
            ArmPersistTimer(now_ms);
        } else {
            CancelPersist();
            if (!retransmit_queue_.empty() && !rto_running_) {
                ArmRto(now_ms);
            }
        }
        result.fully_acked = retransmit_queue_.empty() &&
                             !persist_probe_.has_value();
        result.retransmit_queue_bytes = in_flight_bytes_;
        return result;
    }

    const std::size_t acknowledged_sequence =
        static_cast<std::uint32_t>(acknowledgment - snd_una_);
    std::size_t remaining = acknowledged_sequence;
    std::size_t acknowledged_payload = 0;
    std::optional<std::uint64_t> rtt_sample;
    bool ack_covers_retransmission = false;
    bool partial_rto_recovery = false;

    while (remaining != 0 && !retransmit_queue_.empty()) {
        SendRecord& record = retransmit_queue_.front();
        const std::size_t logical_length = record.logical_length;
        const std::size_t take = std::min(remaining, logical_length);
        const std::size_t payload_take = std::min(take, record.data.Size());
        const bool carries_fin = logical_length > record.data.Size();

        retransmit_bytes_ -= take;
        in_flight_sequence_ -= take;
        in_flight_bytes_ -= payload_take;
        acknowledged_payload += payload_take;
        remaining -= take;

        if (record.retransmitted) {
            ack_covers_retransmission = true;
        }

        if (take == logical_length) {
            if (!rtt_sample.has_value() && !record.retransmitted &&
                now_ms >= record.sent_time_ms) {
                rtt_sample = now_ms - record.sent_time_ms;
            }
            if (carries_fin) {
                fin_acked_ = true;
            }
            if (record.sacked) {
                if (sacked_bytes_ >= record.data.Size()) {
                    sacked_bytes_ -= record.data.Size();
                } else {
                    sacked_bytes_ = 0;
                }
                if (sacked_sequence_ >= logical_length) {
                    sacked_sequence_ -= static_cast<std::uint32_t>(logical_length);
                } else {
                    sacked_sequence_ = 0;
                }
            }
            retransmit_queue_.pop_front();
            continue;
        }

        record.seq += static_cast<std::uint32_t>(take);
        record.logical_length -= static_cast<std::uint32_t>(take);
        record.data = record.data.Subslice(payload_take,
                                           record.data.Size() - payload_take);
        if (record.data.Empty()) {
            record.data = {};
            record.owner.Reset();
        }
        if (record.sacked) {
            record.sacked = false;
            if (sacked_bytes_ >= payload_take) {
                sacked_bytes_ -= payload_take;
            } else {
                sacked_bytes_ = 0;
            }
            if (sacked_sequence_ >= static_cast<std::uint32_t>(take)) {
                sacked_sequence_ -= static_cast<std::uint32_t>(take);
            } else {
                sacked_sequence_ = 0;
            }
        }
        partial_rto_recovery = record.rto_attempts != 0;
        break;
    }

    if (remaining != 0 && persist_probe_.has_value()) {
        SendRecord& probe = *persist_probe_;
        const std::size_t logical_length = probe.logical_length;
        const std::size_t take = std::min(remaining, logical_length);
        const std::size_t payload_take = std::min(take, probe.data.Size());
        const bool carries_fin = logical_length > probe.data.Size();

        retransmit_bytes_ -= take;
        acknowledged_payload += payload_take;
        remaining -= take;
        if (take == logical_length) {
            if (carries_fin) {
                fin_acked_ = true;
            }
            persist_probe_.reset();
        } else {
            probe.seq += static_cast<std::uint32_t>(take);
            probe.logical_length -= static_cast<std::uint32_t>(take);
            probe.data = probe.data.Subslice(payload_take,
                                             probe.data.Size() - payload_take);
        }
    }

    snd_una_ = acknowledgment;
    result.newly_acked = acknowledged_payload;
    dup_ack_count_ = 0;
    last_peer_window_ = peer_window;
    peer_window_valid_ = true;

    if (rtt_sample.has_value() && !ack_covers_retransmission) {
        RecomputeRto(*rtt_sample);
    }

    if (fast_recovery_) {
        cwnd_ = ssthresh_;
        fast_recovery_ = false;
        fast_retransmit_pending_ = false;
    } else if (acknowledged_payload != 0 && cwnd_ < ssthresh_) {
        const std::uint32_t increase = static_cast<std::uint32_t>(
            std::min<std::size_t>(acknowledged_payload, mss_));
        cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                    ? std::numeric_limits<std::uint32_t>::max()
                    : cwnd_ + increase;
    } else if (acknowledged_payload != 0 && cwnd_ != 0) {
        const std::uint32_t increase = std::max<std::uint32_t>(
            1U, static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(mss_) * mss_) / cwnd_));
        cwnd_ = std::numeric_limits<std::uint32_t>::max() - cwnd_ < increase
                    ? std::numeric_limits<std::uint32_t>::max()
                    : cwnd_ + increase;
    }

    if (retransmit_queue_.empty()) {
        rto_running_ = false;
        rto_deadline_ms_ = 0;
    } else if (peer_window != 0) {
        ArmRto(now_ms);
    }
    if (partial_rto_recovery && peer_window != 0 &&
        !retransmit_queue_.empty()) {
        fast_retransmit_pending_ = true;
        rto_running_ = true;
        rto_deadline_ms_ = now_ms;
    }

    if (peer_window == 0) {
        rto_running_ = false;
        rto_deadline_ms_ = 0;
        persist_probe_count_ = 0;
        persist_current_ms_ = persist_base_ms_;
        persist_deadline_ms_ = 0;
        const bool has_work = !send_queue_.empty() ||
                              !retransmit_queue_.empty() ||
                              persist_probe_.has_value() ||
                              (fin_requested_ && !fin_sent_);
        if (has_work) {
            ArmPersistTimer(now_ms);
        } else {
            CancelPersist();
        }
    } else {
        CancelPersist();
    }

    result.fully_acked = retransmit_queue_.empty() &&
                         !persist_probe_.has_value();
    result.retransmit_queue_bytes = in_flight_bytes_;
    return result;
}

void TcpSendBuffer::RecomputeRto(std::uint64_t rtt_ms) noexcept {
    if (!srtt_valid_) {
        srtt_ms_ = rtt_ms;
        rttvar_ms_ = rtt_ms / 2U;
        srtt_valid_ = true;
    } else {
        const std::uint64_t difference =
            srtt_ms_ > rtt_ms ? srtt_ms_ - rtt_ms : rtt_ms - srtt_ms_;
        rttvar_ms_ = (3U * rttvar_ms_ + difference) / 4U;
        srtt_ms_ = (7U * srtt_ms_ + rtt_ms) / 8U;
    }

    const std::uint64_t variation =
        rttvar_ms_ > std::numeric_limits<std::uint64_t>::max() / 4U
            ? std::numeric_limits<std::uint64_t>::max()
            : std::max<std::uint64_t>(1U, rttvar_ms_ * 4U);
    const std::uint64_t computed = SaturatingAdd(srtt_ms_, variation);
    rto_ms_ = std::clamp(computed, min_rto_ms_, max_rto_ms_);
}

void TcpSendBuffer::BackoffRto() noexcept {
    if (rto_ms_ >= max_rto_ms_ || rto_ms_ > max_rto_ms_ / 2U) {
        rto_ms_ = max_rto_ms_;
    } else {
        rto_ms_ *= 2U;
    }
}

void TcpSendBuffer::ArmRto(std::uint64_t now_ms) noexcept {
    if (retransmit_queue_.empty()) {
        rto_running_ = false;
        rto_deadline_ms_ = 0;
        return;
    }
    rto_running_ = true;
    rto_deadline_ms_ = SaturatingAdd(now_ms, rto_ms_);
}

bool TcpSendBuffer::RetransmitExpired(std::uint64_t now_ms) const noexcept {
    return !closed_ && rto_running_ && rto_deadline_ms_ != 0 &&
           now_ms >= rto_deadline_ms_;
}

void TcpSendBuffer::ArmPersistTimer(std::uint64_t now_ms) noexcept {
    const bool has_work = !send_queue_.empty() || !retransmit_queue_.empty() ||
                          persist_probe_.has_value() ||
                          (fin_requested_ && !fin_sent_);
    if (closed_ || !has_work || persist_deadline_ms_ != 0) {
        return;
    }
    persist_current_ms_ = persist_base_ms_;
    persist_deadline_ms_ = SaturatingAdd(now_ms, persist_current_ms_);
}

bool TcpSendBuffer::PersistExpired(std::uint64_t now_ms) const noexcept {
    return !closed_ && persist_deadline_ms_ != 0 &&
           now_ms >= persist_deadline_ms_;
}

void TcpSendBuffer::ScheduleNextPersist(std::uint64_t now_ms) noexcept {
    if (persist_current_ms_ >= persist_max_ms_ ||
        persist_current_ms_ > persist_max_ms_ / 2U) {
        persist_current_ms_ = persist_max_ms_;
    } else {
        persist_current_ms_ *= 2U;
    }
    persist_deadline_ms_ = SaturatingAdd(now_ms, persist_current_ms_);
}

void TcpSendBuffer::CancelPersist() noexcept {
    persist_deadline_ms_ = 0;
    persist_current_ms_ = persist_base_ms_;
    persist_probe_count_ = 0;
}

void TcpSendBuffer::Close() noexcept {
    closed_ = true;
    CancelTimers();
    send_queue_.clear();
    retransmit_queue_.clear();
    persist_probe_.reset();
    retransmit_bytes_ = 0;
    in_flight_bytes_ = 0;
    in_flight_sequence_ = 0;
    sacked_bytes_ = 0;
    sacked_sequence_ = 0;
    fast_retransmit_pending_ = false;
    pending_kind_ = PendingKind::None;
}

void TcpSendBuffer::UpdateMss(std::uint16_t mss) noexcept {
    if (mss == 0 || mss == mss_) {
        return;
    }
    const bool pristine = snd_una_ == snd_max_ && retransmit_queue_.empty() &&
                          !persist_probe_.has_value();
    const std::uint16_t old_mss = mss_;
    mss_ = mss;
    if (pristine) {
        cwnd_ = static_cast<std::uint32_t>(mss_) * 2U;
    } else if (mss_ < old_mss) {
        const std::uint64_t scaled =
            static_cast<std::uint64_t>(cwnd_) * mss_ / old_mss;
        cwnd_ = std::max<std::uint32_t>(
            mss_, static_cast<std::uint32_t>(scaled));
    }
}

bool TcpSendBuffer::AllAcked() const noexcept {
    const bool fin_complete = !fin_requested_ || fin_acked_;
    return send_queue_.empty() && retransmit_queue_.empty() &&
           !persist_probe_.has_value() && snd_una_ == snd_max_ && fin_complete;
}

void TcpSendBuffer::CancelTimers() noexcept {
    rto_running_ = false;
    rto_deadline_ms_ = 0;
    persist_deadline_ms_ = 0;
}

void TcpSendBuffer::ResetPending() noexcept {
    pending_kind_ = PendingKind::None;
    pending_is_fin_ = false;
    pending_seq_ = 0;
    pending_len_ = 0;
}

std::size_t TcpSendBuffer::OnSack(const TcpSackBlockList& sack_blocks,
                                   std::uint64_t now_ms) noexcept {
    (void)now_ms;
    if (sack_blocks.count == 0 || retransmit_queue_.empty() || closed_) {
        return 0;
    }

    std::size_t newly_sacked = 0;
    std::size_t sacked_count = 0;

    for (SendRecord& record : retransmit_queue_) {
        if (record.sacked) {
            ++sacked_count;
            continue;
        }
        // A record is SACKed only when a SACK block fully covers its
        // [seq, seq + logical_length) range.
        const std::uint32_t record_end =
            record.seq + static_cast<std::uint32_t>(record.logical_length);
        bool covered = false;
        for (std::size_t i = 0; i < sack_blocks.count; ++i) {
            const auto& block = sack_blocks.blocks[i];
            if (block.left_edge == block.right_edge) {
                continue;
            }
            // Check block covers [record.seq, record_end).
            const bool left_ok =
                !SequenceBefore(record.seq, block.left_edge);
            const bool right_ok =
                !SequenceAfter(record_end, block.right_edge);
            if (left_ok && right_ok) {
                covered = true;
                break;
            }
        }
        if (covered) {
            record.sacked = true;
            sacked_bytes_ += record.data.Size();
            sacked_sequence_ += static_cast<std::uint32_t>(record.logical_length);
            newly_sacked += record.data.Size();
            ++sacked_count;
        }
    }

    // Trigger fast retransmit if 3+ distinct records are SACKed and
    // we are not already in fast recovery.
    if (sacked_count >= 3 && !fast_recovery_ && !retransmit_queue_.empty()) {
        const std::uint32_t flight = SaturatingUint32(in_flight_sequence_);
        ssthresh_ = std::max<std::uint32_t>(
            flight / 2U, static_cast<std::uint32_t>(mss_) * 2U);
        const std::uint64_t recovery_window =
            static_cast<std::uint64_t>(ssthresh_) +
            static_cast<std::uint64_t>(mss_) * 3U;
        cwnd_ = recovery_window > std::numeric_limits<std::uint32_t>::max()
                    ? std::numeric_limits<std::uint32_t>::max()
                    : static_cast<std::uint32_t>(recovery_window);
        fast_retransmit_pending_ = true;
        fast_recovery_ = true;
    }

    return newly_sacked;
}

} // namespace tcpip2
