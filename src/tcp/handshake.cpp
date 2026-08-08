#include <tcp/handshake.h>

#include <algorithm>
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

} // namespace

bool TcpHandshakeConfig::Validate() const noexcept {
    if (backlog_limit == 0 || half_open_limit == 0 || pcb_limit == 0 ||
        pending_response_limit == 0) {
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
    return true;
}

TcpHandshakeEngine::TcpHandshakeEngine(const TcpHandshakeConfig& config,
                                       const TcpIsnGenerator& isn,
                                       TimerWheel& timers)
    : config_(config), isn_(isn), timers_(timers),
      callback_gate_(std::make_shared<CallbackGate>()) {
    if (!config_.Validate()) {
        throw std::invalid_argument("invalid TCP handshake configuration");
    }
    pcbs_.reserve(config_.pcb_limit);
    pending_responses_.reserve(config_.pending_response_limit);
    callback_gate_->owner = this;
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
        pcb.retry_timer = timers_.Schedule(deadline_ms, [weak_gate, flow, generation] {
            const std::shared_ptr<CallbackGate> gate = weak_gate.lock();
            if (gate && gate->owner != nullptr) gate->owner->OnRetry(flow, generation);
        });
        return true;
    } catch (...) {
        pcb.retry_timer = TimerId{};
        return false;
    }
}

void TcpHandshakeEngine::QueueResponse(const TcpResponse& response) noexcept {
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

void TcpHandshakeEngine::RemoveAt(std::size_t index) noexcept {
    if (index >= pcbs_.size()) return;
    Pcb& pcb = pcbs_[index];
    if (pcb.retry_timer.value != 0) {
        timers_.Cancel(pcb.retry_timer);
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
                    RemoveAt(existing_index);
                    result.state_changed = true;
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
            if (!SequenceAcceptable(segment, pcb.rcv_nxt, pcb.receive_window)) {
                result.response = BuildSynAck(pcb, now_ms);
                return result;
            }
            if (segment.HasFlag(TcpFlag::Ack)) {
                if (segment.acknowledgment == pcb.snd_nxt &&
                    SequenceAcceptable(segment, pcb.rcv_nxt, pcb.receive_window)) {
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
                    }
                    if (pcb.retry_timer.value != 0) timers_.Cancel(pcb.retry_timer);
                    pcb.retry_timer = TimerId{};
                    pcb.snd_una = segment.acknowledgment;
                    pcb.state = TcpState::Established;
                    if (half_open_count_ > 0) --half_open_count_;
                    result.state_changed = true;
                    return result;
                }
                result.response = BuildReset(segment);
                return result;
            }
            return result;
        }

        if (segment.HasFlag(TcpFlag::Rst) && segment.sequence == pcb.rcv_nxt) {
            RemoveAt(existing_index);
            result.state_changed = true;
        }
        return result;
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
    pcb.generation = next_generation_++;

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
        pcbs_.push_back(pcb);
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
    out.snd_una = pcb.snd_una;
    out.snd_nxt = pcb.snd_nxt;
    out.rcv_nxt = pcb.rcv_nxt;
    out.options = pcb.options;
    return true;
}

bool TcpHandshakeEngine::PopPendingResponse(TcpResponse& out) noexcept {
    if (pending_responses_.empty()) return false;
    out = pending_responses_.front();
    if (pending_responses_.size() > 1) {
        std::move(pending_responses_.begin() + 1,
                  pending_responses_.end(), pending_responses_.begin());
    }
    pending_responses_.pop_back();
    return true;
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
    if (callback_gate_) callback_gate_->owner = nullptr;
    while (!pcbs_.empty()) RemoveAt(pcbs_.size() - 1);
    pending_responses_.clear();
}

} // namespace tcpip2
