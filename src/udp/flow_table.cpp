#include <udp/flow_table.h>

namespace tcpip2 {
namespace {

/// The remote datagram arrives on the reverse of the client's flow: it must be
/// serialized back to the client with source/destination swapped.
FlowKey ReverseFlow(const FlowKey &flow) noexcept {
    FlowKey reversed;
    reversed.source = flow.destination;
    reversed.destination = flow.source;
    reversed.source_port = flow.destination_port;
    reversed.destination_port = flow.source_port;
    reversed.protocol = flow.protocol;
    return reversed;
}

} // namespace

UdpFlowTable::UdpFlowTable(const UdpFlowConfig &config, ISessionFactory *session_factory, IClock *clock,
                           PostMessageFn post_message) noexcept
    : config_(config), session_factory_(session_factory), clock_(clock != nullptr ? clock : DefaultClock()),
      post_message_fn_(std::move(post_message)) {
    flows_.reserve(config_.max_flows);
}

UdpFlowTable::Dispatch UdpFlowTable::OnClientDatagram(const FlowKey &flow, const std::uint8_t *payload,
                                                      std::size_t payload_length, std::uint64_t now_ms) noexcept {
    if (flow.protocol != 17 || flow.source.family() != flow.destination.family()) {
        return Dispatch::Ignored;
    }
    Flow *const f = FindOrCreate(flow, now_ms);
    if (f == nullptr) {
        return Dispatch::NoCapacity;
    }
    if (!f->session_bound || f->session == nullptr) {
        return Dispatch::Rejected;
    }

    f->last_activity_ms = now_ms;
    ++f->client_datagrams;

    SendResult result;
    BufferView view(payload, payload_length);
    try {
        result = f->session->Send(view);
    } catch (...) {
        return Dispatch::Rejected;
    }
    if (result.status == SendStatus::Accepted) {
        // A datagram session must accept the whole datagram or none of it.
        return result.accepted_bytes == payload_length ? Dispatch::Accepted : Dispatch::Rejected;
    }
    if (result.status == SendStatus::WouldBlock) {
        return Dispatch::WouldBlock;
    }
    // Closed / Error: the remote channel is gone — drop the flow.
    Evict(static_cast<std::size_t>(f - flows_.data()));
    return Dispatch::Rejected;
}

UdpFlowTable::Flow *UdpFlowTable::FindOrCreate(const FlowKey &flow, std::uint64_t now_ms) {
    for (std::size_t i = 0; i < flows_.size(); ++i) {
        if (flows_[i].flow == flow) {
            return &flows_[i];
        }
    }

    if (flows_.size() >= config_.max_flows) {
        // Evict the oldest idle entry to make room, if any.
        for (std::size_t i = 0; i < flows_.size(); ++i) {
            if (now_ms - flows_[i].last_activity_ms >= config_.idle_timeout_ms) {
                Evict(i);
                break;
            }
        }
        if (flows_.size() >= config_.max_flows) {
            return nullptr;
        }
    }

    Flow f;
    f.flow = flow;
    f.flow_id = next_flow_id_++;
    f.last_activity_ms = now_ms;

    if (!shutdown_ && session_factory_ != nullptr) {
        UdpOpenRequest req;
        req.flow_id = FlowId{f.flow_id};
        req.source = IpEndpoint{flow.source, flow.source_port};
        req.original_destination = IpEndpoint{flow.destination, flow.destination_port};
        req.resolved_destination = req.original_destination;

        DatagramOpenResult opened;
        try {
            opened = session_factory_->OpenUdp(req);
        } catch (...) {
            opened = DatagramOpenResult{};
        }
        if (opened.handle != nullptr && opened.error == SessionError::None) {
            f.session = static_cast<IDatagramSession *>(opened.handle);
            f.session_bound = true;

            const std::uint64_t flow_id = f.flow_id;
            f.session->SetDataCallback([this, flow_id](BufferLease &lease) {
                if (!lease || shutdown_)
                    return ReceiveStatus::Closed;
                ShardMessage msg;
                msg.type = ShardMessageType::kUdpSessionData;
                msg.flow_id = FlowId{flow_id};
                msg.data = std::move(lease);
                if (post_message_fn_(std::move(msg))) {
                    return ReceiveStatus::Accepted;
                }
                // Post failed — restore the lease so the adapter can retry.
                lease = std::move(msg.data);
                return shutdown_ ? ReceiveStatus::Closed : ReceiveStatus::WouldBlock;
            });
            f.session->SetClosedCallback([this, flow_id](SessionError) {
                if (shutdown_)
                    return;
                ShardMessage msg;
                msg.type = ShardMessageType::kUdpSessionClosed;
                msg.flow_id = FlowId{flow_id};
                post_message_fn_(std::move(msg));
            });
        }
    }

    flows_.push_back(std::move(f));
    flow_count_.fetch_add(1, std::memory_order_relaxed);
    return &flows_.back();
}

void UdpFlowTable::Evict(std::size_t index) {
    if (index >= flows_.size()) {
        return;
    }
    UnbindSession(flows_[index]);
    flows_.erase(flows_.begin() + static_cast<std::ptrdiff_t>(index));
    flow_count_.fetch_sub(1, std::memory_order_relaxed);
}

void UdpFlowTable::UnbindSession(Flow &flow) noexcept {
    if (flow.session_bound && flow.session != nullptr) {
        // SetDataCallback(nullptr) must quiesce any in-flight invocation.
        flow.session->SetDataCallback(nullptr);
        flow.session->SetClosedCallback(nullptr);
        flow.session_bound = false;
    }
}

ReceiveStatus UdpFlowTable::OnRemoteData(std::uint64_t flow_id, BufferLease &lease) noexcept {
    for (std::size_t i = 0; i < flows_.size(); ++i) {
        if (flows_[i].flow_id != flow_id) {
            continue;
        }
        Flow &flow = flows_[i];
        flow.last_activity_ms = clock_->NowMs();
        ++flow.remote_datagrams;
        if (!lease || !emitter_) {
            return ReceiveStatus::Accepted;
        }
        return emitter_(ReverseFlow(flow.flow), lease) ? ReceiveStatus::Accepted : ReceiveStatus::WouldBlock;
    }
    // Flow was evicted between the adapter posting and shard processing.
    return ReceiveStatus::Closed;
}

void UdpFlowTable::OnFlowClosed(std::uint64_t flow_id) noexcept {
    for (std::size_t i = 0; i < flows_.size(); ++i) {
        if (flows_[i].flow_id == flow_id) {
            Evict(i);
            return;
        }
    }
}

void UdpFlowTable::PurgeExpired(std::uint64_t now_ms) noexcept {
    std::size_t i = 0;
    while (i < flows_.size()) {
        if (now_ms - flows_[i].last_activity_ms >= config_.idle_timeout_ms) {
            Evict(i);
        } else {
            ++i;
        }
    }
}

bool UdpFlowTable::Find(const FlowKey &flow, UdpFlowSnapshot &out) const noexcept {
    for (const Flow &f : flows_) {
        if (f.flow == flow) {
            out.flow = f.flow;
            out.flow_id = f.flow_id;
            out.session_bound = f.session_bound;
            out.last_activity_ms = f.last_activity_ms;
            out.client_datagrams = f.client_datagrams;
            out.remote_datagrams = f.remote_datagrams;
            return true;
        }
    }
    return false;
}

bool UdpFlowTable::FindById(std::uint64_t flow_id, UdpFlowSnapshot &out) const noexcept {
    for (const Flow &f : flows_) {
        if (f.flow_id == flow_id) {
            out.flow = f.flow;
            out.flow_id = f.flow_id;
            out.session_bound = f.session_bound;
            out.last_activity_ms = f.last_activity_ms;
            out.client_datagrams = f.client_datagrams;
            out.remote_datagrams = f.remote_datagrams;
            return true;
        }
    }
    return false;
}

void UdpFlowTable::Shutdown() noexcept {
    shutdown_ = true;
    for (Flow &f : flows_) {
        UnbindSession(f);
    }
    flows_.clear();
    flow_count_.store(0, std::memory_order_relaxed);
}

} // namespace tcpip2
