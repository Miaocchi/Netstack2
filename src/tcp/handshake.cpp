#include <tcp/handshake.h>

#include <core/shard_message.h>
#include <tcp/output.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace tcpip2 {
namespace {

constexpr std::size_t kNotFound = std::numeric_limits<std::size_t>::max();

FlowKey ReverseFlow(const FlowKey& flow) noexcept {
    FlowKey reversed;
    reversed.source = flow.destination;
    reversed.destination = flow.source;
    reversed.source_port = flow.destination_port;
    reversed.destination_port = flow.source_port;
    reversed.protocol = flow.protocol;
    return reversed;
}

std::uint64_t SaturatingAdd(std::uint64_t left, std::uint64_t right) noexcept {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return left + right;
}

std::uint8_t ReceiveWindowScale(std::uint32_t window) noexcept {
    std::uint8_t scale = 0;
    while (window > 65535 && scale < 14) {
        window >>= 1;
        ++scale;
    }
    return scale;
}

std::uint16_t WireWindow(std::uint32_t window, std::uint8_t scale) noexcept {
    const std::uint32_t scaled = window >> scale;
    return static_cast<std::uint16_t>(std::min<std::uint32_t>(scaled, 65535));
}

bool SameListener(const FlowKey& left, const FlowKey& right) noexcept {
    return left.destination == right.destination &&
           left.destination_port == right.destination_port;
}

bool SequenceAcceptable(const TcpSegmentView& segment,
                        std::uint32_t rcv_nxt,
                        std::uint32_t receive_window) noexcept {
    std::uint32_t segment_length = static_cast<std::uint32_t>(segment.payload_length);
    if (segment.HasFlag(TcpFlag::Syn)) ++segment_length;
    if (segment.HasFlag(TcpFlag::Fin)) ++segment_length;
    if (receive_window == 0) return segment_length == 0 && segment.sequence == rcv_nxt;
    const std::uint32_t first_offset = segment.sequence - rcv_nxt;
    if (segment_length == 0) return first_offset < receive_window;
    const std::uint32_t last_offset = segment.sequence + segment_length - 1 - rcv_nxt;
    return first_offset < receive_window || last_offset < receive_window;
}

bool TimestampBefore(std::uint32_t left, std::uint32_t right) noexcept {
    return left != right && ((left - right) & 0x80000000u) != 0;
}

bool SequenceAfter(std::uint32_t left, std::uint32_t right) noexcept {
    return left != right && ((left - right) & 0x80000000u) == 0;
}

} // namespace

bool TcpHandshakeConfig::Validate() const noexcept {
    if (backlog_limit == 0 || half_open_limit == 0 || pcb_limit == 0 ||
        pending_response_limit == 0 || receive_memory_budget == 0 ||
        delivery_call_budget == 0 || delayed_ack_ms == 0) {
        return false;
    }
    if (backlog_limit > pcb_limit || half_open_limit > pcb_limit) return false;
    constexpr std::uint32_t kMaxScaledWindow = std::uint32_t{65535} << 14;
    if (local_mss == 0 || path_mtu < 1280 ||
        receive_window == 0 || receive_window > kMaxScaledWindow) {
        return false;
    }
    for (std::uint64_t interval : syn_ack_retry_intervals_ms) {
        if (interval == 0) return false;
    }
    if (send_queue_limit == 0 || retransmit_queue_limit == 0 ||
        min_rto_ms == 0 || max_rto_ms == 0 ||
        min_rto_ms > initial_rto_ms || initial_rto_ms > max_rto_ms ||
        persist_timer_base_ms == 0 ||
        persist_timer_base_ms > persist_timer_max_ms ||
        max_retransmissions == 0 || max_persist_probes == 0) {
        return false;
    }
    if (max_timewait_entries == 0 || timewait_ms == 0) return false;
    return true;
}

TcpHandshakeEngine::TcpHandshakeEngine(const TcpHandshakeConfig& config,
                                       const TcpIsnGenerator& isn,
                                       TimerWheel& timers,
                                       std::uint64_t generation_epoch,
                                       ISessionFactory* session_factory,
                                       PostMessageFn post_message,
                                       IEventSink* event_sink)
    : config_(config), isn_(isn), timers_(timers),
      callback_gate_(std::make_shared<CallbackGate>()),
      generation_epoch_(generation_epoch == 0 ? 1 : generation_epoch),
      session_factory_(session_factory),
      post_message_fn_(std::move(post_message)),
      event_sink_(event_sink) {
    if (!config_.Validate()) {
        throw std::invalid_argument("invalid TCP handshake configuration");
    }
    pcbs_.reserve(config_.pcb_limit);
    pending_responses_.reserve(config_.pending_response_limit);
    callback_gate_->post_message = post_message_fn_;
}

TcpHandshakeEngine::~TcpHandshakeEngine() {
    Shutdown();
}

std::size_t TcpHandshakeEngine::FindIndex(const FlowKey& incoming_flow) const noexcept {
    for (std::size_t i = 0; i < pcbs_.size(); ++i) {
        if (pcbs_[i].incoming_flow == incoming_flow) return i;
    }
    return kNotFound;
}

std::size_t TcpHandshakeEngine::ListenerHalfOpenCount(
    const FlowKey& incoming_flow) const noexcept {
    std::size_t count = 0;
    for (const Pcb& pcb : pcbs_) {
        if (pcb.state == TcpState::SynReceived &&
            SameListener(pcb.incoming_flow, incoming_flow)) {
            ++count;
        }
    }
    return count;
}

TcpResponse TcpHandshakeEngine::BuildSynAck(Pcb& pcb,
                                            std::uint64_t now_ms) noexcept {
    TcpResponse response;
    response.valid = true;
    response.flow = ReverseFlow(pcb.incoming_flow);
    response.sequence = pcb.iss;
    response.acknowledgment = pcb.rcv_nxt;
    response.flags = static_cast<std::uint8_t>(TcpFlag::Syn | TcpFlag::Ack);
    response.window = pcb.response_window;
    response.syn_options = pcb.response_options;
    if (response.syn_options.timestamp_present) {
        response.syn_options.timestamp_value = static_cast<std::uint32_t>(now_ms);
        pcb.response_options.timestamp_value = response.syn_options.timestamp_value;
    }
    return response;
}

TcpResponse TcpHandshakeEngine::BuildAck(Pcb& pcb,
                                         std::uint64_t now_ms) noexcept {
    TcpResponse response;
    if (!pcb.receive) return response;
    if (pcb.delayed_ack_timer.value != 0) {
        timers_.Cancel(pcb.delayed_ack_timer);
        pcb.delayed_ack_timer = TimerId{};
    }
    response.valid = true;
    response.flow = ReverseFlow(pcb.incoming_flow);
    response.sequence = pcb.send ? pcb.send->SndNxt() : pcb.snd_nxt;
    response.acknowledgment = pcb.receive->RcvNxt();
    response.flags = TcpFlag::Ack;

    const std::uint8_t scale = pcb.options.window_scale
        ? pcb.options.receive_window_scale : 0;
    const std::size_t available = pcb.receive->AdvertisedWindow();
    response.window = WireWindow(
        static_cast<std::uint32_t>(std::min<std::size_t>(
            available, std::numeric_limits<std::uint32_t>::max())), scale);
    const std::size_t represented = static_cast<std::size_t>(response.window) << scale;
    pcb.receive->RecordAdvertisedWindow(represented);

    response.timestamp_present = pcb.options.timestamps;
    response.timestamp_value = static_cast<std::uint32_t>(now_ms);
    response.timestamp_echo = pcb.options.peer_timestamp;
    if (pcb.options.sack_permitted) {
        response.sack_blocks = pcb.receive->SackBlocks(
            pcb.options.timestamps ? 3 : 4);
    }
    pcb.receive->AckSent();
    return response;
}

TcpResponse TcpHandshakeEngine::BuildReset(const TcpSegmentView& segment) noexcept {
    TcpResponse response;
    response.valid = true;
    response.flow = ReverseFlow(segment.flow);
    response.window = 0;
    if (segment.HasFlag(TcpFlag::Ack)) {
        response.sequence = segment.acknowledgment;
        response.flags = TcpFlag::Rst;
        return response;
    }

    std::uint32_t segment_length = static_cast<std::uint32_t>(segment.payload_length);
    if (segment.HasFlag(TcpFlag::Syn)) ++segment_length;
    if (segment.HasFlag(TcpFlag::Fin)) ++segment_length;
    response.acknowledgment = segment.sequence + segment_length;
    response.flags = static_cast<std::uint8_t>(TcpFlag::Rst | TcpFlag::Ack);
    return response;
}

bool TcpHandshakeEngine::ScheduleRetry(Pcb& pcb,
                                       std::uint64_t deadline_ms) noexcept {
    const FlowKey flow = pcb.incoming_flow;
    const std::uint64_t generation = pcb.generation;
    const std::weak_ptr<CallbackGate> weak_gate = callback_gate_;
    try {
        pcb.retry_timer = timers_.Schedule(deadline_ms, [weak_gate, this, flow, generation] {
            const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
            if (!gate) return;
            gate->TryRun([this, flow, generation] {
                if (!shutdown_) OnRetry(flow, generation);
            });
        });
        return true;
    } catch (...) {
        pcb.retry_timer = TimerId{};
        return false;
    }
}

void TcpHandshakeEngine::EmitFlowEvent(FlowId flow_id, FlowEventType type) noexcept {
    if (event_sink_ != nullptr) {
        FlowEvent event;
        event.flow_id = flow_id;
        event.type = type;
        event_sink_->OnFlowEvent(event);
    }
}

void TcpHandshakeEngine::QueueResponse(const TcpResponse& response) noexcept {
    const bool replaceable_ack = response.valid && response.flags == TcpFlag::Ack;
    if (replaceable_ack) {
        for (Pcb& pcb : pcbs_) {
            if (ReverseFlow(pcb.incoming_flow) == response.flow) {
                pcb.pending_ack = response;
                pcb.pending_ack_valid = true;
                return;
            }
        }
        for (TcpResponse& pending : pending_responses_) {
            if (pending.valid && pending.flags == TcpFlag::Ack &&
                pending.flow == response.flow) {
                pending = response;
                return;
            }
        }
    }
    if (pending_responses_.size() >= config_.pending_response_limit) {
        ++dropped_responses_;
        return;
    }
    try {
        pending_responses_.push_back(response);
    } catch (...) {
        ++dropped_responses_;
    }
}

void TcpHandshakeEngine::OnRetry(const FlowKey& incoming_flow,
                                 std::uint64_t generation) noexcept {
    const std::size_t index = FindIndex(incoming_flow);
    if (index == kNotFound) return;
    Pcb& pcb = pcbs_[index];
    if (pcb.generation != generation || pcb.state != TcpState::SynReceived) return;

    if (pcb.retry_index >= config_.syn_ack_retry_intervals_ms.size()) {
        RemoveAt(index);
        return;
    }

    QueueResponse(BuildSynAck(pcb, timers_.Now()));
    ++pcb.retry_index;
    const std::uint64_t interval = pcb.retry_index < config_.syn_ack_retry_intervals_ms.size()
        ? config_.syn_ack_retry_intervals_ms[pcb.retry_index]
        : config_.syn_ack_retry_intervals_ms.back();
    if (!ScheduleRetry(pcb, SaturatingAdd(timers_.Now(), interval))) {
        RemoveAt(index);
    }
}

bool TcpHandshakeEngine::ScheduleDelayedAck(Pcb& pcb,
                                            std::uint64_t now_ms) noexcept {
    if (pcb.delayed_ack_timer.value != 0) return true;
    const FlowKey flow = pcb.incoming_flow;
    const std::uint64_t generation = pcb.generation;
    const std::weak_ptr<CallbackGate> weak_gate = callback_gate_;
    try {
        pcb.delayed_ack_timer = timers_.Schedule(
            SaturatingAdd(now_ms, config_.delayed_ack_ms),
            [weak_gate, this, flow, generation] {
                const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
                if (!gate) return;
                gate->TryRun([this, flow, generation] {
                    if (!shutdown_) OnDelayedAck(flow, generation);
                });
            });
        return true;
    } catch (...) {
        pcb.delayed_ack_timer = TimerId{};
        return false;
    }
}

void TcpHandshakeEngine::OnDelayedAck(const FlowKey& incoming_flow,
                                      std::uint64_t generation) noexcept {
    const std::size_t index = FindIndex(incoming_flow);
    if (index == kNotFound) return;
    Pcb& pcb = pcbs_[index];
    if (pcb.generation != generation ||
        (pcb.state == TcpState::SynReceived ||
         pcb.state == TcpState::TimeWait) ||
        !pcb.receive) {
        return;
    }
    pcb.delayed_ack_timer = TimerId{};
    QueueResponse(BuildAck(pcb, timers_.Now()));
}

TcpDeliveryResult TcpHandshakeEngine::DrainSession(Pcb& pcb) noexcept {
    TcpDeliveryResult result;
    if (!pcb.receive || pcb.session == nullptr || pcb.receive->ReadyBytes() == 0) {
        return result;
    }
    if (pcb.receive->Blocked()) {
        result.status = TcpDeliveryStatus::WouldBlock;
        return result;
    }
    // Client TCP payload always enters the externally owned transport session
    // through TrySend(). Remote payload travels in the other direction via
    // the DataCallback registered in BindSessionCallbacks().
    const std::shared_ptr<ITransportSession> session = pcb.session;
    DeliverFn deliver = [session](BufferView data) -> SendResult {
        return session->TrySend(data);
    };
    result = DrainTcpReceiveBuffer(
        *pcb.receive, deliver, config_.delivery_call_budget);
    pcb.delivery_pending = result.status == TcpDeliveryStatus::BudgetExhausted;
    if (result.status == TcpDeliveryStatus::Closed ||
        result.status == TcpDeliveryStatus::Error ||
        result.status == TcpDeliveryStatus::InvalidResult ||
        result.status == TcpDeliveryStatus::NoProgress) {
        pcb.session = nullptr;
        pcb.session_bound = false;
        pcb.delivery_pending = false;
    }
    return result;
}

TcpHandshakeResult TcpHandshakeEngine::ProcessEstablished(
    Pcb& pcb, const TcpSegmentView& segment, std::uint64_t now_ms) noexcept {
    TcpHandshakeResult result;
    if (pcb.state == TcpState::TimeWait) {
        // Fix 7: retransmitted FIN in TIME-WAIT restarts the 2MSL timer.
        if (segment.HasFlag(TcpFlag::Fin)) {
            const std::size_t index = &pcb - pcbs_.data();
            if (pcb.timewait_timer.value != 0) {
                timers_.Cancel(pcb.timewait_timer);
                pcb.timewait_timer = TimerId{};
            }
            ScheduleTimeWait(index, now_ms);
        }
        result.response = BuildAck(pcb, now_ms);
        return result;
    }
    if (!pcb.receive) {
        result.error = TcpHandshakeError::ReceiveBudget;
        return result;
    }

    if (segment.HasFlag(TcpFlag::Syn)) {
        result.response = BuildAck(pcb, now_ms);
        return result;
    }
    if (!segment.HasFlag(TcpFlag::Ack)) {
        result.error = TcpHandshakeError::InvalidFlags;
        return result;
    }
    const std::uint32_t effective_snd_nxt =
        pcb.send ? pcb.send->SndNxt() : pcb.snd_nxt;
    if (SequenceAfter(segment.acknowledgment, effective_snd_nxt)) {
        result.response = BuildAck(pcb, now_ms);
        return result;
    }

    std::uint32_t incoming_timestamp = 0;
    bool timestamp_present = false;
    if (pcb.options.timestamps) {
        const TcpOptionParseResult parsed =
            ParseTcpSynOptions(segment.options, segment.options_length);
        if (parsed.error != TcpOptionError::None ||
            !parsed.options.timestamp_present) {
            result.error = TcpHandshakeError::InvalidOptions;
            return result;
        }
        if (TimestampBefore(parsed.options.timestamp_value,
                            pcb.options.peer_timestamp)) {
            result.response = BuildAck(pcb, now_ms);
            return result;
        }
        incoming_timestamp = parsed.options.timestamp_value;
        timestamp_present = true;
    }

    // Fix 3: Validate segment sequence *before* processing ACK or FIN.
    // This prevents out-of-window segments from acknowledging our FIN.
    // Use IsSequenceAcceptable (backed by AcceptableWindow / rcv_adv_) rather
    // than AdvertisedWindow(), so zero-window sessions still accept in-flight
    // data that was within the previously advertised window.
    {
        std::uint32_t seg_len = static_cast<std::uint32_t>(segment.payload_length);
        if (segment.HasFlag(TcpFlag::Fin)) ++seg_len;
        if (!pcb.receive->IsSequenceAcceptable(segment.sequence, seg_len)) {
            result.response = BuildAck(pcb, now_ms);
            return result;
        }
    }

    // Update peer window and feed ACK to send buffer.
    pcb.peer_window = segment.window;
    if (pcb.send) {
        const std::uint32_t scaled_pw = pcb.options.window_scale
            ? static_cast<std::uint32_t>(segment.window)
                << pcb.options.send_window_scale
            : static_cast<std::uint32_t>(segment.window);
        const TcpSendAckResult ar = pcb.send->OnAck(
            segment.acknowledgment, scaled_pw, now_ms,
            segment.payload_length == 0);
        if (ar.duplicate && pcb.options.sack_permitted) {
            const TcpSackBlockList sacks =
                ParseTcpSackBlocks(segment.options, segment.options_length);
            if (sacks.count > 0) pcb.send->OnSack(sacks, now_ms);
        }
    }

    // After ACK processing, check if our FIN was acknowledged.
    if (pcb.send && pcb.send->FinAcked()) {
        const std::size_t index = &pcb - pcbs_.data();
        if (pcb.state == TcpState::FinWait1) {
            pcb.state = TcpState::FinWait2;
            result.state_changed = true;
        } else if (pcb.state == TcpState::Closing) {
            if (!ScheduleTimeWait(index, now_ms)) {
                RemoveAt(index);
                return result;
            }
            result.state_changed = true;
        } else if (pcb.state == TcpState::LastAck) {
            const FlowId fid = pcb.flow_id;
            RemoveAt(index);
            result.state_changed = true;
            EmitFlowEvent(fid, FlowEventType::Closed);
            return result;
        }
    }

    // Helper lambda for FIN processing with state transitions.
    // Fix 2: FIN is only consumed when its sequence number equals RCV.NXT
    //         (after any payload in this segment has been accepted).
    // Fix 4: Call ShutdownWrite() on the session when FIN is consumed.
    // Fix 8: Set state_changed on all state transitions.
    auto handle_fin = [&](Pcb& p, std::uint32_t fin_seq) -> bool {
        if (fin_seq != p.receive->RcvNxt()) return false;
        const std::size_t index = &p - pcbs_.data();
        p.receive->ConsumeFin();
        p.fin_received = true;
        if (p.session != nullptr && !p.close_notified) {
            p.session->ShutdownWrite();
        }
        p.close_notified = true;
        if (p.state == TcpState::Established) {
            p.state = TcpState::CloseWait;
            result.state_changed = true;
            return false;  // PCB still alive; caller should send ACK
        } else if (p.state == TcpState::FinWait1) {
            p.state = TcpState::Closing;
            result.state_changed = true;
            return false;
        } else if (p.state == TcpState::FinWait2) {
            if (!ScheduleTimeWait(index, now_ms)) {
                RemoveAt(index);
                return true;  // PCB removed; caller must not touch pcb
            }
            result.state_changed = true;
            return false;
        } else if (p.state == TcpState::Closing) {
            if (!ScheduleTimeWait(index, now_ms)) {
                RemoveAt(index);
                return true;
            }
            result.state_changed = true;
            return false;
        }
        return false;
    };

    if (segment.payload_length == 0) {
        if (timestamp_present && segment.sequence == pcb.receive->RcvNxt()) {
            pcb.options.peer_timestamp = incoming_timestamp;
        }
        if (segment.HasFlag(TcpFlag::Fin)) {
            // Fix 2: zero-payload FIN must have SEQ == RCV.NXT.
            if (segment.sequence == pcb.receive->RcvNxt()) {
                const bool removed = handle_fin(pcb, segment.sequence);
                if (removed) return result;
                if (pcb.delayed_ack_timer.value != 0) {
                    timers_.Cancel(pcb.delayed_ack_timer);
                    pcb.delayed_ack_timer = TimerId{};
                }
                result.response = BuildAck(pcb, now_ms);
            } else {
                // FIN in window but not at RCV.NXT — ACK but don't consume.
                result.response = BuildAck(pcb, now_ms);
            }
        }
        return result;
    }

    // Fix 4: Reject peer data in CloseWait and later states (half-close).
    if (pcb.state == TcpState::CloseWait ||
        pcb.state == TcpState::Closing ||
        pcb.state == TcpState::LastAck ||
        pcb.state == TcpState::TimeWait) {
        result.response = BuildAck(pcb, now_ms);
        return result;
    }

    const bool was_blocked = pcb.receive->Blocked();
    const std::uint32_t old_rcv_nxt = pcb.receive->RcvNxt();
    const TcpReceiveResult received = pcb.receive->OnSegment(
        segment.sequence, segment.payload, segment.payload_length,
        segment.HasFlag(TcpFlag::Psh));
    if (received.disposition == ReceiveDisposition::Invalid) {
        result.error = TcpHandshakeError::InvalidFlags;
        return result;
    }
    if (timestamp_present && pcb.receive->RcvNxt() != old_rcv_nxt) {
        pcb.options.peer_timestamp = incoming_timestamp;
    }
    const TcpDeliveryResult delivered = DrainSession(pcb);
    if (delivered.status == TcpDeliveryStatus::InvalidResult ||
        delivered.status == TcpDeliveryStatus::Closed ||
        delivered.status == TcpDeliveryStatus::Error ||
        delivered.status == TcpDeliveryStatus::NoProgress) {
        result.error = TcpHandshakeError::InvalidSession;
    }

    const bool became_blocked = !was_blocked && pcb.receive->Blocked();
    if (received.ack_decision == AckDecision::Immediate || became_blocked) {
        if (pcb.delayed_ack_timer.value != 0) {
            timers_.Cancel(pcb.delayed_ack_timer);
            pcb.delayed_ack_timer = TimerId{};
        }
        result.response = BuildAck(pcb, now_ms);
    } else if (received.ack_decision == AckDecision::Delayed) {
        if (!ScheduleDelayedAck(pcb, now_ms)) {
            result.response = BuildAck(pcb, now_ms);
        }
    }

    // Fix 2: data+FIN — only consume FIN if data was accepted (not duplicate/OOO)
    //         and FIN sequence == new RCV.NXT.
    if (segment.HasFlag(TcpFlag::Fin)) {
        const std::uint32_t fin_seq =
            segment.sequence + static_cast<std::uint32_t>(segment.payload_length);
        if (fin_seq == pcb.receive->RcvNxt() &&
            received.disposition != ReceiveDisposition::Duplicate &&
            received.disposition != ReceiveDisposition::OutOfWindow) {
            const bool removed = handle_fin(pcb, fin_seq);
            result.state_changed = true;
            if (removed) return result;
            if (pcb.delayed_ack_timer.value != 0) {
                timers_.Cancel(pcb.delayed_ack_timer);
                pcb.delayed_ack_timer = TimerId{};
            }
            result.response = BuildAck(pcb, now_ms);
        } else {
            // FIN not at RCV.NXT or data wasn't accepted — just ACK.
            if (!result.response.valid) {
                result.response = BuildAck(pcb, now_ms);
            }
        }
    }
    return result;
}

void TcpHandshakeEngine::RemoveAt(std::size_t index) noexcept {
    if (index >= pcbs_.size()) return;
    Pcb& pcb = pcbs_[index];
    if (pcb.retry_timer.value != 0) {
        timers_.Cancel(pcb.retry_timer);
    }
    if (pcb.delayed_ack_timer.value != 0) {
        timers_.Cancel(pcb.delayed_ack_timer);
    }
    if (pcb.timewait_timer.value != 0) {
        timers_.Cancel(pcb.timewait_timer);
    }
    if (pcb.session) {
        try {
            pcb.session->SetWritableCallback(nullptr);
            pcb.session->SetDataCallback(nullptr);
            pcb.session->SetClosedCallback(nullptr);
        } catch (...) {
            // An external session may not prevent shutdown of shard-owned state.
        }
    }
    if (pcb.receive) {
        const std::size_t memory = pcb.receive->MemoryBytes();
        receive_memory_bytes_ = memory > receive_memory_bytes_
            ? 0 : receive_memory_bytes_ - memory;
    }
    if (pcb.send) {
        pcb.send->CancelTimers();
    }
    if (pcb.state == TcpState::SynReceived && half_open_count_ > 0) {
        --half_open_count_;
    }
    if (index + 1 != pcbs_.size()) {
        pcbs_[index] = std::move(pcbs_.back());
    }
    pcbs_.pop_back();
}

TcpHandshakeResult TcpHandshakeEngine::OnSegment(const TcpSegmentView& segment,
                                                 std::uint64_t now_ms) noexcept {
    TcpHandshakeResult result;
    if (shutdown_) {
        result.error = TcpHandshakeError::Shutdown;
        return result;
    }
    const std::size_t existing_index = FindIndex(segment.flow);
    if (existing_index != kNotFound) {
        Pcb& pcb = pcbs_[existing_index];
        if (pcb.state == TcpState::SynReceived) {
            if (segment.HasFlag(TcpFlag::Rst)) {
                if (segment.sequence == pcb.rcv_nxt) {
                    const FlowId fid = pcb.flow_id;
                    RemoveAt(existing_index);
                    result.state_changed = true;
                    EmitFlowEvent(fid, FlowEventType::Reset);
                }
                return result;
            }
            if (segment.HasFlag(TcpFlag::Syn)) {
                if (!segment.HasFlag(TcpFlag::Ack) &&
                    !segment.HasFlag(TcpFlag::Fin) &&
                    segment.sequence == pcb.irs) {
                    const TcpOptionParseResult duplicate_options =
                        ParseTcpSynOptions(segment.options, segment.options_length);
                    if (duplicate_options.error == TcpOptionError::None &&
                        pcb.options.timestamps &&
                        duplicate_options.options.timestamp_present) {
                        pcb.response_options.timestamp_echo =
                            duplicate_options.options.timestamp_value;
                    }
                    result.response = BuildSynAck(pcb, now_ms);
                    return result;
                }
                result.error = TcpHandshakeError::InvalidFlags;
                return result;
            }
            if (!SequenceAcceptable(segment, pcb.rcv_nxt, pcb.response_window)) {
                result.response = BuildSynAck(pcb, now_ms);
                return result;
            }
            if (segment.HasFlag(TcpFlag::Ack)) {
                if (segment.acknowledgment == pcb.snd_nxt &&
                    SequenceAcceptable(segment, pcb.rcv_nxt, pcb.response_window)) {
                    if (pcb.options.timestamps) {
                        const TcpOptionParseResult ack_options =
                            ParseTcpSynOptions(segment.options, segment.options_length);
                        if (ack_options.error != TcpOptionError::None ||
                            !ack_options.options.timestamp_present ||
                            ack_options.options.timestamp_echo !=
                                pcb.response_options.timestamp_value) {
                            result.error = TcpHandshakeError::InvalidOptions;
                            return result;
                        }
                        pcb.options.peer_timestamp =
                            ack_options.options.timestamp_value;
                    }

                    const std::size_t capacity = pcb.receive_window;
                    const std::size_t bitmap_bytes = ((capacity + 63) / 64) * 8;
                    const std::size_t memory = capacity + bitmap_bytes;
                    if (memory > config_.receive_memory_budget ||
                        receive_memory_bytes_ > config_.receive_memory_budget - memory) {
                        result.response = BuildReset(segment);
                        result.error = TcpHandshakeError::ReceiveBudget;
                        RemoveAt(existing_index);
                        return result;
                    }
                    try {
                        pcb.receive = std::make_unique<TcpReceiveBuffer>(
                            capacity, pcb.rcv_nxt, pcb.response_window);
                    } catch (...) {
                        result.response = BuildReset(segment);
                        result.error = TcpHandshakeError::ReceiveBudget;
                        RemoveAt(existing_index);
                        return result;
                    }
                    receive_memory_bytes_ += pcb.receive->MemoryBytes();
                    if (pcb.retry_timer.value != 0) timers_.Cancel(pcb.retry_timer);
                    pcb.retry_timer = TimerId{};
                    pcb.snd_una = segment.acknowledgment;
                    pcb.state = TcpState::Established;
                    try {
                        pcb.send = std::make_unique<TcpSendBuffer>(
                            pcb.snd_nxt, pcb.options.peer_mss,
                            pcb.options.send_window_scale,
                            config_.send_queue_limit,
                            config_.retransmit_queue_limit,
                            config_.initial_rto_ms, config_.min_rto_ms,
                            config_.max_rto_ms, config_.persist_timer_base_ms,
                            config_.persist_timer_max_ms,
                            config_.max_retransmissions,
                            config_.max_persist_probes,
                            config_.cc_algorithm);
                    } catch (...) {
                        result.response = BuildReset(segment);
                        result.error = TcpHandshakeError::ReceiveBudget;
                        RemoveAt(existing_index);
                        return result;
                    }
                    if (half_open_count_ > 0) --half_open_count_;
                    result.state_changed = true;
                    EmitFlowEvent(pcb.flow_id, FlowEventType::Established);

                    // P4-2: Notify the session factory that a TCP flow has
                    // been established.  When a factory is present it may
                    // accept or reject the flow.  On acceptance the session
                    // is bound immediately so that payload data in the same
                    // segment (if any) is delivered through it.  On rejection
                    // a RST is emitted and the PCB is removed.
                    if (session_factory_ != nullptr) {
                        TcpOpenRequest req;
                        req.flow_id = pcb.flow_id;
                        req.source = IpEndpoint{pcb.incoming_flow.source,
                                                 pcb.incoming_flow.source_port};
                        req.original_destination = IpEndpoint{
                            pcb.incoming_flow.destination,
                            pcb.incoming_flow.destination_port};
                        // The factory is implemented by the consumer and is not
                        // required to be noexcept; OnSegment is noexcept, so a
                        // throwing factory would terminate. Treat any exception
                        // as a rejection.
                        SessionOpenResult open_result;
                        try {
                            open_result = session_factory_->OpenTcp(req);
                        } catch (...) {
                            open_result = SessionOpenResult{};
                        }
                        if (open_result.session != nullptr &&
                            open_result.error == SessionError::None) {
                            pcb.session = open_result.session;
                            pcb.session_bound = true;
                            pcb.receive->SetBlocked(false);
                            BindSessionCallbacks(pcb);
                            DrainSession(pcb);
                        } else {
                            result.state_changed = false;
                            result.response = BuildReset(segment);
                            RemoveAt(existing_index);
                            return result;
                        }
                    }

                    if (segment.payload_length != 0 || segment.HasFlag(TcpFlag::Fin)) {
                        TcpHandshakeResult established =
                            ProcessEstablished(pcb, segment, now_ms);
                        established.state_changed = true;
                        return established;
                    }
                    return result;
                }
                result.response = BuildReset(segment);
                return result;
            }
            return result;
        }

        const std::uint32_t current_rcv_nxt = pcb.receive
            ? pcb.receive->RcvNxt() : pcb.rcv_nxt;
        if (segment.HasFlag(TcpFlag::Rst)) {
            if (segment.sequence == current_rcv_nxt) {
                const FlowId fid = pcb.flow_id;
                RemoveAt(existing_index);
                result.state_changed = true;
                EmitFlowEvent(fid, FlowEventType::Reset);
            } else {
                result.response = BuildAck(pcb, now_ms);
            }
            return result;
        }
        return ProcessEstablished(pcb, segment, now_ms);
    }

    if (segment.HasFlag(TcpFlag::Rst)) return result;
    if (segment.HasFlag(TcpFlag::Ack)) {
        result.response = BuildReset(segment);
        return result;
    }
    if (!segment.HasFlag(TcpFlag::Syn)) return result;
    if (segment.HasFlag(TcpFlag::Fin)) {
        result.error = TcpHandshakeError::InvalidFlags;
        return result;
    }
    if (half_open_count_ >= config_.half_open_limit) {
        result.error = TcpHandshakeError::HalfOpenLimit;
        return result;
    }
    if (ListenerHalfOpenCount(segment.flow) >= config_.backlog_limit) {
        result.error = TcpHandshakeError::BacklogFull;
        return result;
    }
    if (pcbs_.size() >= config_.pcb_limit) {
        result.error = TcpHandshakeError::PcbLimit;
        return result;
    }

    const TcpOptionParseResult parsed_options =
        ParseTcpSynOptions(segment.options, segment.options_length);
    if (parsed_options.error != TcpOptionError::None) {
        result.error = TcpHandshakeError::InvalidOptions;
        return result;
    }

    Pcb pcb;
    pcb.incoming_flow = segment.flow;
    pcb.iss = isn_.Generate(ReverseFlow(segment.flow), now_ms);
    pcb.irs = segment.sequence;
    pcb.snd_una = pcb.iss;
    pcb.snd_nxt = pcb.iss + 1;
    pcb.rcv_nxt = pcb.irs + 1;
    pcb.peer_window = segment.window;
    pcb.receive_window = config_.receive_window;
    pcb.generation = generation_epoch_;
    pcb.flow_id = FlowId{next_flow_id_++};

    const TcpSynOptions& offered = parsed_options.options;
    pcb.options.peer_mss = offered.mss_present
        ? offered.mss
        : (segment.flow.source.IsIpv4() ? std::uint16_t{536} : std::uint16_t{1220});
    pcb.options.window_scale = config_.enable_window_scale && offered.window_scale_present;
    if (pcb.options.window_scale) {
        pcb.options.send_window_scale = offered.window_scale;
        pcb.options.receive_window_scale = ReceiveWindowScale(config_.receive_window);
    }
    pcb.options.sack_permitted = config_.enable_sack && offered.sack_permitted;
    pcb.options.timestamps = config_.enable_timestamps && offered.timestamp_present;
    pcb.options.peer_timestamp = offered.timestamp_value;

    pcb.response_options.mss_present = true;
    const std::uint16_t fixed_header_bytes = segment.flow.source.IsIpv4() ? 40 : 60;
    pcb.response_options.mss = std::min<std::uint16_t>(
        config_.local_mss,
        static_cast<std::uint16_t>(config_.path_mtu - fixed_header_bytes));
    pcb.response_options.window_scale_present = pcb.options.window_scale;
    pcb.response_options.window_scale = pcb.options.receive_window_scale;
    pcb.response_options.sack_permitted = pcb.options.sack_permitted;
    pcb.response_options.timestamp_present = pcb.options.timestamps;
    pcb.response_options.timestamp_echo = offered.timestamp_value;
    pcb.response_window = WireWindow(config_.receive_window, 0);

    try {
        pcbs_.push_back(std::move(pcb));
    } catch (...) {
        result.error = TcpHandshakeError::PcbLimit;
        return result;
    }
    ++half_open_count_;
    Pcb& stored = pcbs_.back();
    if (!ScheduleRetry(stored, SaturatingAdd(
            now_ms, config_.syn_ack_retry_intervals_ms[0]))) {
        RemoveAt(pcbs_.size() - 1);
        result.error = TcpHandshakeError::TimerFailure;
        return result;
    }

    result.state_changed = true;
    result.response = BuildSynAck(stored, now_ms);
    return result;
}

bool TcpHandshakeEngine::Find(const FlowKey& incoming_flow,
                              TcpPcbSnapshot& out) const noexcept {
    const std::size_t index = FindIndex(incoming_flow);
    if (index == kNotFound) return false;
    const Pcb& pcb = pcbs_[index];
    out.state = pcb.state;
    out.iss = pcb.iss;
    out.irs = pcb.irs;
    out.snd_una = pcb.send ? pcb.send->SndUna() : pcb.snd_una;
    out.snd_nxt = pcb.send ? pcb.send->SndNxt() : pcb.snd_nxt;
    out.rcv_nxt = pcb.rcv_nxt;
    out.flow_id = pcb.flow_id;
    out.generation = pcb.generation;
    if (pcb.receive) {
        out.rcv_nxt = pcb.receive->RcvNxt();
        out.receive_bytes = pcb.receive->BytesHeld();
        out.ready_bytes = pcb.receive->ReadyBytes();
        out.out_of_order_bytes = pcb.receive->OutOfOrderBytes();
        out.advertised_window = pcb.receive->AdvertisedWindow();
        out.session_blocked = pcb.receive->Blocked();
    }
    out.options = pcb.options;
    return true;
}

void TcpHandshakeEngine::BindSessionCallbacks(Pcb& pcb) noexcept {
    if (pcb.session == nullptr || !post_message_fn_) return;

    const FlowId flow_id = pcb.flow_id;
    const std::uint64_t generation = pcb.generation;
    const std::weak_ptr<CallbackGate> weak_gate = callback_gate_;

    // WritableCallback — posted back to the shard as kSessionWritable.
    pcb.session->SetWritableCallback([weak_gate, flow_id, generation] {
        const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
        if (!gate) return;
        ShardMessage msg;
        msg.type = ShardMessageType::kSessionWritable;
        msg.flow_id = flow_id;
        msg.generation = generation;
        gate->TryPost(std::move(msg));
    });

    // ClosedCallback — posted back as kSessionClosed.
    pcb.session->SetClosedCallback([weak_gate, flow_id, generation](SessionError error) {
        const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
        if (!gate) return;
        ShardMessage msg;
        msg.type = ShardMessageType::kSessionClosed;
        msg.flow_id = flow_id;
        msg.generation = generation;
        msg.error = error;
        gate->TryPost(std::move(msg));
    });

    // Remote payload returns to the shard, which owns the TCP send buffer.
    pcb.session->SetDataCallback([weak_gate, flow_id, generation](BufferLease& lease) {
        if (!lease) return ReceiveStatus::Accepted;
        const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
        if (!gate) return ReceiveStatus::Closed;
        ShardMessage msg;
        msg.type = ShardMessageType::kSessionData;
        msg.flow_id = flow_id;
        msg.generation = generation;
        msg.data = std::move(lease);
        if (gate->TryPost(std::move(msg))) {
            return ReceiveStatus::Accepted;
        }
        lease = std::move(msg.data);
        return gate->IsActive() && lease ? ReceiveStatus::WouldBlock
                                          : ReceiveStatus::Closed;
    });
}

TcpHandshakeResult TcpHandshakeEngine::AttachSession(
    const FlowKey& incoming_flow, std::shared_ptr<ITransportSession> session,
    std::uint64_t now_ms) noexcept {
    TcpHandshakeResult result;
    if (!session) {
        result.error = TcpHandshakeError::InvalidSession;
        return result;
    }
    const std::size_t index = FindIndex(incoming_flow);
    if (index == kNotFound || pcbs_[index].state != TcpState::Established ||
        !pcbs_[index].receive || pcbs_[index].session_bound) {
        result.error = TcpHandshakeError::InvalidSession;
        return result;
    }
    Pcb& pcb = pcbs_[index];
    pcb.session = std::move(session);
    pcb.session_bound = true;
    pcb.receive->SetBlocked(false);
    BindSessionCallbacks(pcb);
    const TcpDeliveryResult delivered = DrainSession(pcb);
    if (delivered.status == TcpDeliveryStatus::InvalidResult ||
        delivered.status == TcpDeliveryStatus::Closed ||
        delivered.status == TcpDeliveryStatus::Error ||
        delivered.status == TcpDeliveryStatus::NoProgress) {
        result.error = TcpHandshakeError::InvalidSession;
    }
    result.response = BuildAck(pcb, now_ms);
    return result;
}

TcpHandshakeResult TcpHandshakeEngine::OnSessionWritable(
    FlowId flow_id, std::uint64_t generation, std::uint64_t now_ms) noexcept {
    TcpHandshakeResult result;
    for (Pcb& pcb : pcbs_) {
        if (pcb.flow_id != flow_id || pcb.generation != generation ||
            pcb.state == TcpState::SynReceived ||
            pcb.state == TcpState::TimeWait ||
            !pcb.receive || pcb.session == nullptr) {
            continue;
        }
        pcb.receive->SetBlocked(false);
        const TcpDeliveryResult delivered = DrainSession(pcb);
        if (delivered.status == TcpDeliveryStatus::InvalidResult ||
            delivered.status == TcpDeliveryStatus::Closed ||
            delivered.status == TcpDeliveryStatus::Error ||
            delivered.status == TcpDeliveryStatus::NoProgress) {
            result.error = TcpHandshakeError::InvalidSession;
        }
        result.response = BuildAck(pcb, now_ms);
        return result;
    }
    result.error = TcpHandshakeError::InvalidSession;
    return result;
}

bool TcpHandshakeEngine::OnSessionClosed(
    FlowId flow_id, std::uint64_t generation, SessionError error) noexcept {
    for (std::size_t i = 0; i < pcbs_.size(); ++i) {
        if (pcbs_[i].flow_id == flow_id && pcbs_[i].generation == generation) {
            // Fix 5: In closing/TIME-WAIT states, only clear session binding.
            // The PCB lifetime is managed by retransmission/timer logic.
            // Removing a TIME-WAIT PCB would cancel the 2MSL timer prematurely.
            const TcpState state = pcbs_[i].state;
            pcbs_[i].session = nullptr;
            pcbs_[i].session_bound = false;
            if (state == TcpState::TimeWait ||
                state == TcpState::FinWait1 ||
                state == TcpState::FinWait2 ||
                state == TcpState::Closing ||
                state == TcpState::LastAck) {
                return true;
            }
            if (error == SessionError::None || error == SessionError::RemoteClosed) {
                CloseFlow(flow_id, generation);
            } else {
                AbortFlow(flow_id, generation);
            }
            return true;
        }
    }
    return false;
}

void TcpHandshakeEngine::PumpSessionDeliveries(
    std::uint64_t now_ms, std::size_t pcb_budget) noexcept {
    std::size_t visited = 0;
    for (Pcb& pcb : pcbs_) {
        if (visited >= pcb_budget) break;
        if (!pcb.delivery_pending ||
            pcb.state == TcpState::SynReceived ||
            pcb.state == TcpState::TimeWait ||
            pcb.session == nullptr || !pcb.receive || pcb.receive->Blocked()) {
            continue;
        }
        ++visited;
        const TcpDeliveryResult delivered = DrainSession(pcb);
        if (delivered.accepted_bytes != 0) {
            QueueResponse(BuildAck(pcb, now_ms));
        }
    }
}

bool TcpHandshakeEngine::PopPendingResponse(TcpResponse& out) noexcept {
    for (Pcb& pcb : pcbs_) {
        if (pcb.pending_ack_valid) {
            out = pcb.pending_ack;
            pcb.pending_ack = TcpResponse{};
            pcb.pending_ack_valid = false;
            return true;
        }
    }
    if (pending_responses_.empty()) return false;
    out = pending_responses_.front();
    if (pending_responses_.size() > 1) {
        std::move(pending_responses_.begin() + 1,
                  pending_responses_.end(), pending_responses_.begin());
    }
    pending_responses_.pop_back();
    return true;
}

std::size_t TcpHandshakeEngine::PendingResponseCount() const noexcept {
    std::size_t count = pending_responses_.size();
    for (const Pcb& pcb : pcbs_) {
        if (pcb.pending_ack_valid) ++count;
    }
    return count;
}

std::size_t TcpHandshakeEngine::EstablishedCount() const noexcept {
    std::size_t count = 0;
    for (const Pcb& pcb : pcbs_) {
        if (pcb.state == TcpState::Established) ++count;
    }
    return count;
}

void TcpHandshakeEngine::Shutdown() noexcept {
    if (shutdown_) return;
    shutdown_ = true;
    if (callback_gate_) callback_gate_->Deactivate();
    // Emit Closed for any connection that is still alive (ESTABLISHED,
    // CLOSE-WAIT, etc.) so consumers are notified before the PCB is
    // destroyed.  TIME-WAIT entries are evicted silently.
    for (const Pcb& pcb : pcbs_) {
        if (pcb.state != TcpState::TimeWait) {
            EmitFlowEvent(pcb.flow_id, FlowEventType::Closed);
        }
    }
    while (!pcbs_.empty()) RemoveAt(pcbs_.size() - 1);
    pending_responses_.clear();
}

std::size_t TcpHandshakeEngine::EnqueueSendData(FlowId flow_id,
    const std::uint8_t* data, std::size_t length) noexcept {
    if (data == nullptr || length == 0) return 0;
    for (Pcb& pcb : pcbs_) {
        if (pcb.flow_id == flow_id &&
            (pcb.state == TcpState::Established ||
             pcb.state == TcpState::CloseWait) && pcb.send) {
            return pcb.send->Enqueue(data, length);
        }
    }
    return 0;
}

bool TcpHandshakeEngine::EnqueueRemoteData(FlowId flow_id,
    std::uint64_t generation, BufferLease& lease) noexcept {
    if (!lease) return true;
    for (Pcb& pcb : pcbs_) {
        if (pcb.flow_id != flow_id || pcb.generation != generation) continue;
        if ((pcb.state != TcpState::Established && pcb.state != TcpState::CloseWait) ||
            !pcb.send) {
            lease.Reset();
            return true;
        }
        const std::size_t accepted = pcb.send->Enqueue(lease.Data(), lease.Size());
        if (accepted == lease.Size()) {
            lease.Reset();
            return true;
        }
        if (accepted != 0) {
            const std::size_t remaining = lease.Size() - accepted;
            std::memmove(lease.Data(), lease.Data() + accepted, remaining);
            lease.Resize(remaining);
        }
        return false;
    }
    lease.Reset();
    return true;
}

void TcpHandshakeEngine::ResumeSessionReceives(
    std::size_t remote_backlog, std::size_t remote_low_watermark) noexcept {
    if (remote_low_watermark == 0 || remote_backlog >= remote_low_watermark) {
        return;
    }
    const std::size_t send_low_watermark =
        std::max<std::size_t>(1, config_.send_queue_limit / 2);
    for (Pcb& pcb : pcbs_) {
        if (!pcb.session || !pcb.send ||
            pcb.send->UnsntBytes() >= send_low_watermark) {
            continue;
        }
        try {
            pcb.session->ResumeReceive();
        } catch (...) {
            // A faulty external session must not terminate the owner shard.
        }
    }
}

void TcpHandshakeEngine::PumpSendPaths(std::uint64_t now_ms,
    std::size_t pcb_budget, PktBufferPool& pool,
    std::vector<BufferLease>& tx_leases, std::size_t max_segments) noexcept {
    std::size_t visited = 0, built = 0;
    // Fix 6: Use index-based iteration so we can RemoveAt stranded PCBs
    //         whose send buffer is closed (FIN retransmission exhausted).
    std::size_t i = 0;
    while (i < pcbs_.size() && visited < pcb_budget && built < max_segments) {
        Pcb& pcb = pcbs_[i];
        if (pcb.state == TcpState::SynReceived ||
            pcb.state == TcpState::TimeWait || !pcb.send) {
            ++i;
            continue;
        }
        // Fix 6: If send buffer is exhausted in a closing state, the
        //         connection is dead — remove the PCB.
        if (pcb.send->IsClosed()) {
            if (pcb.state == TcpState::FinWait1 ||
                pcb.state == TcpState::FinWait2 ||
                pcb.state == TcpState::Closing ||
                pcb.state == TcpState::LastAck) {
                const FlowId fid = pcb.flow_id;
                RemoveAt(i);
                EmitFlowEvent(fid, FlowEventType::Closed);
                // Don't advance i — swap-pop moved a new PCB here.
                continue;
            }
            ++i;
            continue;
        }
        ++visited;
        const std::uint32_t spw = pcb.options.window_scale
            ? static_cast<std::uint32_t>(pcb.peer_window)
                << pcb.options.send_window_scale
            : static_cast<std::uint32_t>(pcb.peer_window);
        TcpSendNextResult next = pcb.send->NextSegment(spw, now_ms);
        if (!next.has_segment) { ++i; continue; }
        BufferLease tx = pool.Allocate();
        if (!tx) { pcb.send->ResetPending(); ++i; continue; }
        TcpResponse resp;
        resp.valid = true;
        resp.flow = ReverseFlow(pcb.incoming_flow);
        resp.sequence = next.sequence;
        resp.acknowledgment = pcb.receive ? pcb.receive->RcvNxt() : pcb.rcv_nxt;
        resp.flags = TcpFlag::Ack | (next.is_fin ? TcpFlag::Fin : 0);
        resp.timestamp_present = pcb.options.timestamps;
        resp.timestamp_value = static_cast<std::uint32_t>(now_ms);
        resp.timestamp_echo = pcb.options.peer_timestamp;
        resp.payload = next.payload;
        resp.payload_length = next.payload_length;
        if (pcb.options.sack_permitted && pcb.receive)
            resp.sack_blocks = pcb.receive->SackBlocks(
                pcb.options.timestamps ? 3 : 4);
        const std::uint8_t rcv_scale = pcb.options.window_scale
            ? pcb.options.receive_window_scale : 0;
        const std::size_t avail = pcb.receive ? pcb.receive->AdvertisedWindow() : 0;
        resp.window = WireWindow(static_cast<std::uint32_t>(
            std::min<std::size_t>(avail, UINT32_MAX)), rcv_scale);
        const TcpOutputResult out = BuildTcpControlPacket(
            resp, tx.Data(), tx.Capacity());
        if (out.error != TcpOutputError::None) {
            pcb.send->ResetPending(); ++i; continue;
        }
        tx.Resize(out.packet_length);
        // Owner lease must be created before OnSent, because OnSent
        // erases the send_queue_ front, invalidating next.payload.
        BufferRef owner;
        if (!next.is_retransmission && next.payload_length > 0) {
            BufferLease ol = pool.Allocate();
            if (!ol) { pcb.send->ResetPending(); ++i; continue; }
            std::memcpy(ol.Data(), next.payload, next.payload_length);
            ol.Resize(next.payload_length);
            owner = pool.Retain(std::move(ol));
        }
        pcb.send->OnSent(std::move(owner), 0, now_ms);
        try { tx_leases.push_back(std::move(tx)); ++built; }
        catch (...) { break; }
        ++i;
    }
}

void TcpHandshakeEngine::CloseFlow(FlowId flow_id,
                                    std::uint64_t generation) noexcept {
    for (std::size_t i = 0; i < pcbs_.size(); ++i) {
        Pcb& pcb = pcbs_[i];
        if (pcb.flow_id != flow_id || pcb.generation != generation) continue;
        if (pcb.state == TcpState::Established) {
            pcb.state = TcpState::FinWait1;
            if (pcb.send) pcb.send->RequestFin();
        } else if (pcb.state == TcpState::CloseWait) {
            pcb.state = TcpState::LastAck;
            if (pcb.send) pcb.send->RequestFin();
        }
        return;
    }
}

void TcpHandshakeEngine::AbortFlow(FlowId flow_id,
                                    std::uint64_t generation) noexcept {
    for (std::size_t i = 0; i < pcbs_.size(); ++i) {
        Pcb& pcb = pcbs_[i];
        if (pcb.flow_id != flow_id || pcb.generation != generation) continue;
        TcpResponse rst;
        rst.valid = true;
        rst.flow = ReverseFlow(pcb.incoming_flow);
        rst.sequence = pcb.send ? pcb.send->SndNxt() : pcb.snd_nxt;
        rst.acknowledgment = pcb.receive ? pcb.receive->RcvNxt() : pcb.rcv_nxt;
        rst.flags = static_cast<std::uint8_t>(TcpFlag::Rst | TcpFlag::Ack);
        rst.window = 0;
        QueueResponse(rst);
        const FlowId fid = pcb.flow_id;
        RemoveAt(i);
        EmitFlowEvent(fid, FlowEventType::Reset);
        return;
    }
}

bool TcpHandshakeEngine::ScheduleTimeWait(std::size_t index,
                                           std::uint64_t now_ms) noexcept {
    if (index >= pcbs_.size()) return false;
    // Capture identity before any eviction; RemoveAt uses swap-pop so the
    // PCB at @p index may be relocated.
    const FlowKey target_flow = pcbs_[index].incoming_flow;
    const std::uint64_t target_generation = pcbs_[index].generation;

    // Enforce TIME-WAIT capacity via oldest-deadline eviction.
    std::size_t tw_count = 0;
    for (const Pcb& p : pcbs_) {
        if (p.state == TcpState::TimeWait) ++tw_count;
    }
    if (tw_count >= config_.max_timewait_entries) {
        // Find the oldest TIME-WAIT entry.
        std::size_t oldest = kNotFound;
        std::uint64_t oldest_deadline = std::numeric_limits<std::uint64_t>::max();
        for (std::size_t i = 0; i < pcbs_.size(); ++i) {
            if (pcbs_[i].state == TcpState::TimeWait &&
                pcbs_[i].timewait_deadline_ms < oldest_deadline) {
                oldest_deadline = pcbs_[i].timewait_deadline_ms;
                oldest = i;
            }
        }
        if (oldest != kNotFound) {
            const FlowId evicted_fid = pcbs_[oldest].flow_id;
            RemoveAt(oldest);
            EmitFlowEvent(evicted_fid, FlowEventType::Closed);
            // Re-find by identity; swap-pop may have moved our target.
            index = FindIndex(target_flow);
            if (index == kNotFound) return false;
            if (pcbs_[index].generation != target_generation) return false;
        }
    }
    Pcb& pcb = pcbs_[index];
    pcb.state = TcpState::TimeWait;
    pcb.timewait_deadline_ms =
        SaturatingAdd(now_ms, static_cast<std::uint64_t>(config_.timewait_ms));
    const FlowKey flow = pcb.incoming_flow;
    const std::uint64_t generation = pcb.generation;
    const std::weak_ptr<CallbackGate> weak_gate = callback_gate_;
    try {
        pcb.timewait_timer = timers_.Schedule(
            pcb.timewait_deadline_ms,
            [weak_gate, this, flow, generation] {
                const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
                if (!gate) return;
                gate->TryRun([this, flow, generation] {
                    if (!shutdown_) OnTimeWaitExpired(flow, generation);
                });
            });
        return true;
    } catch (...) {
        pcb.timewait_timer = TimerId{};
        return false;
    }
}

void TcpHandshakeEngine::OnTimeWaitExpired(
    const FlowKey& incoming_flow, std::uint64_t generation) noexcept {
    const std::size_t index = FindIndex(incoming_flow);
    if (index == kNotFound) return;
    Pcb& pcb = pcbs_[index];
    if (pcb.generation != generation || pcb.state != TcpState::TimeWait) return;
    const FlowId fid = pcb.flow_id;
    RemoveAt(index);
    EmitFlowEvent(fid, FlowEventType::Closed);
}

} // namespace tcpip2
