/**
 * @file shard.cpp
 * @brief StackShard event loop implementation.
 * @license GPL-3.0
 *
 * The shard thread runs the 10-step event loop from IMPLEMENTATION_GUIDE §5.2:
 *   1. DrainReturnQueue — return foreign-thread buffer releases to the free list
 *   2. RX batch — poll the local queue (if any)
 *   3. Drain packet inbox (SPSC) — redirected packets from other shards
 *   4. Drain control inbox (MPSC) — check for StopMessage first
 *   5. Advance timers
 *   6. Protocol work
 *   7. Pacing/FQ
 *   8. Route FQ output to the selected queue owner and send TX
 *   9. Publish counters (noop)
 *  10. Wait — sleep 1ms or block on the control inbox with timeout
 *
 * Stop() is idempotent and must not be called from the shard thread itself
 * (that would deadlock on join). A kStop message posted to the control inbox
 * causes the loop to exit cleanly.
 */

#include <core/shard.h>

#include <chrono>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include <core/dispatcher.h>

#include <tcp/handshake.h>
#include <tcp/input.h>
#include <tcp/isn.h>
#include <tcp/output.h>
#include <tcp/segment.h>

#include <ip/icmpv4.h>
#include <ip/icmpv6.h>
#include <ip/ipv4.h>
#include <ip/ipv6.h>
#include <tcpip2/flow.h>
#include <udp/input.h>

namespace tcpip2 {

namespace {

std::uint32_t HashTxLease(const std::uint8_t* data, std::size_t size) noexcept {
    // Derive a flow hash from source/dest IP and ports in the serialized
    // IPv4/IPv6 + TCP packet. Falls back to FNV-1a of the whole packet if
    // the packet is too short or not IP/TCP.
    if (data == nullptr || size < 20) {
        std::uint32_t hash = 2166136261u;
        const std::uint32_t kPrime = 16777619u;
        for (std::size_t i = 0; i < size; ++i) {
            hash ^= data[i];
            hash *= kPrime;
        }
        return hash;
    }

    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    if (version == 4 && size >= 20) {
        const std::uint8_t* tcp = data + 20;
        FlowKey key;
        key.source = IpAddress::Ipv4(
            (static_cast<std::uint32_t>(data[12]) << 24) |
            (static_cast<std::uint32_t>(data[13]) << 16) |
            (static_cast<std::uint32_t>(data[14]) << 8) |
            static_cast<std::uint32_t>(data[15]));
        key.destination = IpAddress::Ipv4(
            (static_cast<std::uint32_t>(data[16]) << 24) |
            (static_cast<std::uint32_t>(data[17]) << 16) |
            (static_cast<std::uint32_t>(data[18]) << 8) |
            static_cast<std::uint32_t>(data[19]));
        key.source_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(tcp[0]) << 8) | tcp[1]);
        key.destination_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(tcp[2]) << 8) | tcp[3]);
        key.protocol = 6;
        return static_cast<std::uint32_t>(FlowHash(key) >> 32);
    }

    if (version == 6 && size >= 40) {
        const std::uint8_t* tcp = data + 40;
        FlowKey key;
        key.source = IpAddress::Ipv6(data + 8);
        key.destination = IpAddress::Ipv6(data + 24);
        key.source_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(tcp[0]) << 8) | tcp[1]);
        key.destination_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(tcp[2]) << 8) | tcp[3]);
        key.protocol = 6;
        return static_cast<std::uint32_t>(FlowHash(key) >> 32);
    }

    // Fallback: FNV-1a of the whole packet.
    std::uint32_t hash = 2166136261u;
    const std::uint32_t kPrime = 16777619u;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= kPrime;
    }
    return hash;
}

} // namespace

StackShard::StackShard(std::size_t shard_id, PktBufferPool& pool, IPacketQueue* queue,
                        std::size_t inbox_capacity,
                        ISessionFactory* session_factory,
                        IClock* clock,
                        IEventSink* event_sink,
                        TcpHandshakeConfig tcp_config) noexcept
    : shard_id_(shard_id),
      pool_(pool),
      queue_(queue),
       session_factory_(session_factory),
       clock_(clock ? clock : DefaultClock()),
       event_sink_(event_sink),
       tcp_config_(std::move(tcp_config)),
      packet_inbox_(inbox_capacity),
      control_inbox_(inbox_capacity),
      timer_(256) {}

StackShard::~StackShard() {
    Stop();
}

bool StackShard::Start() noexcept {
    if (running_.load(std::memory_order_relaxed)) return false;
    std::array<std::uint64_t, 2> isn_secret{};
    if (!LoadTcpIsnSecret(isn_secret)) return false;
    ++tcp_engine_epoch_;
    if (tcp_engine_epoch_ == 0) ++tcp_engine_epoch_;
    try {
        tcp_ = std::make_unique<TcpHandshakeEngine>(
            tcp_config_, TcpIsnGenerator(isn_secret), timer_,
            tcp_engine_epoch_, session_factory_,
            [this](ShardMessage&& msg) noexcept {
                return control_inbox_.Push(std::move(msg));
            },
            event_sink_);
    } catch (...) {
        tcp_.reset();
        return false;
    }
    stop_requested_.store(false, std::memory_order_relaxed);
    running_.store(true, std::memory_order_relaxed);
    try {
        thread_ = std::thread([this] { Run(); });
    } catch (...) {
        running_.store(false, std::memory_order_relaxed);
        tcp_.reset();
        return false;
    }
    return true;
}

void StackShard::Stop() noexcept {
    // Must not be called from the shard thread — that would deadlock on join.
    if (ownership_.IsOwner()) {
        std::fprintf(stderr, "tcpip2: Stop() called from shard thread (would deadlock)\n");
        std::abort();
    }
    if (!running_.load(std::memory_order_relaxed)) return;

    // Post a stop message to the control inbox.
    ShardMessage msg;
    msg.type = ShardMessageType::kStop;
    if (!control_inbox_.Push(std::move(msg))) {
        stop_requested_.store(true, std::memory_order_relaxed);
    }
    control_inbox_.Wake();

    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false, std::memory_order_release);
    tcp_.reset();
}

bool StackShard::PostMessage(ShardMessage&& msg) noexcept {
    if (!running_.load(std::memory_order_relaxed)) return false;
    return control_inbox_.Push(std::move(msg));
}

bool StackShard::PostPacket(BufferLease&& lease) noexcept {
    if (!running_.load(std::memory_order_relaxed)) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (packet_inbox_.Push(std::move(lease))) return true;
    packets_dropped_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

bool StackShard::SetRxQueues(const std::vector<IPacketQueue*>& queues) noexcept {
    if (running_.load(std::memory_order_relaxed)) return false;
    try {
        rx_queues_ = queues;
        next_rx_queue_ = 0;
        return true;
    } catch (...) {
        return false;
    }
}

bool StackShard::SetPacketLanes(PacketDispatcher* dispatcher,
                                 const std::vector<ShardPacketLane*>& inbound,
                                 const std::vector<ShardPacketLane*>& outbound,
                                const std::vector<StackShard*>& targets) noexcept {
    if (running_.load(std::memory_order_relaxed) || dispatcher == nullptr ||
        inbound.size() != outbound.size() || outbound.size() != targets.size()) {
        return false;
    }
    try {
        dispatcher_ = dispatcher;
        inbound_lanes_ = inbound;
        outbound_lanes_ = outbound;
        redirect_targets_ = targets;
        next_inbound_lane_ = 0;
        return true;
    } catch (...) {
        dispatcher_ = nullptr;
        inbound_lanes_.clear();
        outbound_lanes_.clear();
        redirect_targets_.clear();
        return false;
    }
}

bool StackShard::SetTxQueues(const std::vector<IPacketQueue*>& queues) noexcept {
    if (running_.load(std::memory_order_relaxed)) return false;
    try {
        tx_queues_ = queues;
        return true;
    } catch (...) {
        tx_queues_.clear();
        return false;
    }
}

bool StackShard::SetEgressLanes(const std::vector<ShardEgressLane*>& inbound,
                                 const std::vector<ShardEgressLane*>& outbound) noexcept {
    if (running_.load(std::memory_order_relaxed) ||
        inbound.size() != outbound.size() ||
        outbound.size() != redirect_targets_.size()) {
        return false;
    }
    try {
        inbound_egress_lanes_ = inbound;
        outbound_egress_lanes_ = outbound;
        next_inbound_egress_lane_ = 0;
        return true;
    } catch (...) {
        inbound_egress_lanes_.clear();
        outbound_egress_lanes_.clear();
        return false;
    }
}

void StackShard::Run() noexcept {
    ownership_.SetOwner();
    // Reassign the pool's owner thread to this shard thread so that
    // Allocate()/ReturnBuffer() take the owner-local uncontended fast
    // path (ADR-001): the mutex is still acquired, but only this shard
    // thread contends for it on the hot path.
    pool_.SetOwnerThread(std::this_thread::get_id());
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        EventLoopIteration();
    }
    if (tcp_) tcp_->Shutdown();
    fq_codel_.Reset();
    tcp_tx_.clear();
    deferred_session_data_ = ShardMessage{};

    // A stop message can overtake owning packet/control messages. Release all
    // remaining leases on the owner thread before Runtime considers pool
    // teardown; cross-shard lanes are released by Runtime after every join.
    for (;;) {
        BufferLease lease;
        if (!packet_inbox_.Pop(lease)) break;
        lease.Reset();
    }
    for (;;) {
        ShardMessage msg;
        if (!control_inbox_.Pop(msg)) break;
        msg.data.Reset();
    }
    tcp_pcb_count_.store(0, std::memory_order_relaxed);
    tcp_half_open_count_.store(0, std::memory_order_relaxed);
    // Final drain so foreign-thread buffer releases are cleaned up.
    pool_.DrainReturnQueue();
    ownership_.ClearOwner();
}

void StackShard::EventLoopIteration() noexcept {
    const std::uint64_t now_ms = clock_->NowMs();

    // Step 1: DrainReturnQueue — recycle foreign-thread releases.
    pool_.DrainReturnQueue();

    // Step 2: RX batches from queues owned by this shard. Rotate the first
    // queue each iteration so a busy queue cannot starve another owner queue.
    const std::size_t queue_count = rx_queues_.empty()
        ? (queue_ == nullptr ? 0 : 1)
        : rx_queues_.size();
    const std::size_t queue_visits = std::min(queue_count, kRxBudget);
    const std::size_t per_queue_budget = queue_visits == 0 ? 0 : kRxBudget / queue_visits;
    for (std::size_t visit = 0; visit < queue_visits; ++visit) {
        IPacketQueue* rx_queue = queue_;
        if (!rx_queues_.empty()) {
            rx_queue = rx_queues_[(next_rx_queue_ + visit) % queue_count];
        }
        if (rx_queue == nullptr) continue;

        BufferLease rx[kRxBudget];
        IoError error = IoError::None;
        const std::size_t n = rx_queue->RecvBatch(rx, per_queue_budget, error);
        for (std::size_t i = 0; i < n; ++i) {
            packets_received_.fetch_add(1, std::memory_order_relaxed);
            RouteRxPacket(std::move(rx[i]), now_ms);
        }
    }
    if (!rx_queues_.empty() && queue_visits != 0) {
        next_rx_queue_ = (next_rx_queue_ + queue_visits) % queue_count;
    }

    // Step 3: Drain dedicated inbound source->target lanes round-robin. Each
    // lane has one producer, avoiding an unsafe MPSC use of InboxSpsc.
    if (!inbound_lanes_.empty()) {
        for (std::size_t i = 0; i < kPacketInboxBudget; ++i) {
            ShardPacketLane* lane = inbound_lanes_[next_inbound_lane_];
            next_inbound_lane_ = (next_inbound_lane_ + 1) % inbound_lanes_.size();
            if (lane == nullptr) continue;
            PacketEnvelope envelope;
            if (!lane->Pop(envelope)) continue;
            packets_received_.fetch_add(1, std::memory_order_relaxed);
            ProcessEnvelope(std::move(envelope), now_ms);
        }
    }

    // Legacy SPSC inbox is retained for single-producer unit tests only.
    for (std::size_t i = 0; i < kPacketInboxBudget; ++i) {
        BufferLease lease;
        if (!packet_inbox_.Pop(lease)) break;
        packets_received_.fetch_add(1, std::memory_order_relaxed);
        ProcessPacket(std::move(lease), now_ms);
    }

    // Step 4: Drain control inbox (MPSC). Check for StopMessage first.
    bool session_data_blocked = false;
    if (deferred_session_data_.data && tcp_) {
        session_data_blocked = !tcp_->EnqueueRemoteData(
            deferred_session_data_.flow_id, deferred_session_data_.generation,
            deferred_session_data_.data);
        if (!session_data_blocked) {
            deferred_session_data_ = ShardMessage{};
        }
    }
    for (std::size_t i = 0; i < kControlInboxBudget; ++i) {
        if (session_data_blocked) break;
        ShardMessage msg;
        if (!control_inbox_.Pop(msg)) break;
        if (msg.type == ShardMessageType::kStop) {
            stop_requested_.store(true, std::memory_order_relaxed);
            // Release any carried data.
            msg.data.Reset();
            break;
        }
        if (msg.type == ShardMessageType::kSessionWritable && tcp_) {
            const TcpHandshakeResult writable = tcp_->OnSessionWritable(
                msg.flow_id, msg.generation, now_ms);
            if (writable.response.valid && !EnqueueTcpResponse(writable.response)) {
                tcp_->DeferResponse(writable.response);
            }
        }
        if (msg.type == ShardMessageType::kSessionClosed && tcp_) {
            tcp_->OnSessionClosed(msg.flow_id, msg.generation, msg.error);
        }
        if (msg.type == ShardMessageType::kSessionData && tcp_) {
            if (!tcp_->EnqueueRemoteData(msg.flow_id, msg.generation, msg.data)) {
                deferred_session_data_ = std::move(msg);
                session_data_blocked = true;
                break;
            }
        }
        if (msg.type == ShardMessageType::kFlowClose && tcp_) {
            tcp_->CloseFlow(msg.flow_id, msg.generation);
        }
        if (msg.type == ShardMessageType::kFlowAbort && tcp_) {
            tcp_->AbortFlow(msg.flow_id, msg.generation);
        }
        messages_processed_.fetch_add(1, std::memory_order_relaxed);
        // Release any carried data.
        msg.data.Reset();
    }

    if (stop_requested_.load(std::memory_order_relaxed)) return;

    // Step 5: advance timers, then drain bounded retry/control output.
    timer_.AdvanceTo(now_ms);
    reassembler_.Purge(now_ms);
    pmtu_cache_.Purge(now_ms);
    if (tcp_) {
        tcp_->PumpSessionDeliveries(now_ms, kControlInboxBudget);
        TcpResponse response;
        while (fq_codel_.QueueLength() < kTcpTxBudget &&
               tcp_->PopPendingResponse(response)) {
            if (!EnqueueTcpResponse(response)) {
                tcp_->DeferResponse(response);
                break;
            }
        }
        tcp_pcb_count_.store(tcp_->PcbCount(), std::memory_order_relaxed);
        tcp_half_open_count_.store(tcp_->HalfOpenCount(), std::memory_order_relaxed);
    }

    // Step 7: pump TCP send paths (new data, retransmissions, persist probes).
    if (tcp_) {
        PumpTcpSendPaths(now_ms);
        const std::size_t remote_low_watermark = std::max<std::size_t>(
            1, control_inbox_.Capacity() / kRemoteReceiveLowWatermarkDivisor);
        const std::size_t remote_backlog = control_inbox_.Count(
            ShardMessageType::kSessionData) +
            (deferred_session_data_.data ? 1U : 0U);
        tcp_->ResumeSessionReceives(remote_backlog, remote_low_watermark);
    }

    // Step 8: admit cross-shard egress into its queue-owner scheduler, then
    // route the bounded local FQ-CoDel output to the selected TX queue owner.
    DrainEgressLanes();
    FlushTcpTx();

    // Step 9: Publish periodic metric snapshot to the event sink (if any).
    // Throttled to once per second to avoid overhead on the hot path.
    if (event_sink_ != nullptr) {
        constexpr std::uint64_t kMetricIntervalMs = 1000;
        if (now_ms - last_metric_snapshot_ms_ >= kMetricIntervalMs ||
            last_metric_snapshot_ms_ == 0) {
            last_metric_snapshot_ms_ = now_ms;
            MetricSnapshot snapshot;
            snapshot.shard_id = shard_id_;
            snapshot.rx_packets = packets_received_.load(std::memory_order_relaxed);
            snapshot.rx_bytes = 0;  // Byte counter not yet tracked per-shard.
            snapshot.dropped_packets = packets_dropped_.load(std::memory_order_relaxed);
            snapshot.tx_packets = 0;  // TX counter not yet tracked per-shard.
            snapshot.tx_bytes = 0;
            snapshot.tcp_pcb_count = tcp_pcb_count_.load(std::memory_order_relaxed);
            snapshot.tcp_half_open_count = tcp_half_open_count_.load(std::memory_order_relaxed);
            snapshot.udp_datagrams = udp_datagrams_received_.load(std::memory_order_relaxed);
            event_sink_->OnMetricSnapshot(snapshot);
        }
    }

    // Step 10: Wait — block on the control inbox with a short timeout.
    // This keeps the shard responsive to control messages while avoiding
    // a busy spin when there is no RX work.
    if (!stop_requested_.load(std::memory_order_relaxed)) {
        control_inbox_.Wait(1);
    }
}

void StackShard::RouteRxPacket(BufferLease&& lease, std::uint64_t now_ms) noexcept {
    if (!lease) return;
    if (dispatcher_ == nullptr) {
        ProcessPacket(std::move(lease), now_ms);
        return;
    }

    const DispatchDecision decision = dispatcher_->Dispatch(
        shard_id_, lease.Data(), lease.Size());
    if (decision.action != DispatchAction::kRedirect) {
        ProcessPacket(std::move(lease), now_ms);
        return;
    }

    PacketEnvelope envelope;
    envelope.lease = std::move(lease);
    RedirectPacket(decision.classification.owner_shard, std::move(envelope));
}

void StackShard::ProcessPacket(BufferLease&& lease, std::uint64_t now_ms) noexcept {
    if (!lease || !tcp_) return;
    const TcpInputResult input = ParseIpTcpPacket(lease.Data(), lease.Size());
    if (input.error == TcpInputError::FragmentRequiresReassembly) {
        HandleFragment(lease.Data(), lease.Size(), now_ms);
        return;
    }
    if (input.error != TcpInputError::None) {
        if (input.error == TcpInputError::NotTcp) {
            const std::uint8_t version = static_cast<std::uint8_t>(lease.Data()[0] >> 4);
            const std::uint8_t protocol = (version == 4)
                ? [&] {
                    const Ipv4ParseResult ip = ParseIpv4(lease.Data(), lease.Size());
                    return (ip.error == Ipv4ParseError::None) ? ip.header.protocol
                                                              : static_cast<std::uint8_t>(0);
                }()
                : (version == 6)
                ? [&] {
                    const Ipv6ParseResult ip = ParseIpv6(lease.Data(), lease.Size());
                    return (ip.error == Ipv6ParseResult::Error::None)
                        ? ip.final_next_header
                        : static_cast<std::uint8_t>(0);
                }()
                : static_cast<std::uint8_t>(0);

            if (protocol == 1 || protocol == 58) {
                HandleIcmp(lease.Data(), lease.Size(), now_ms);
                return;
            }
            if (protocol == 17) {
                const FragmentInfo fragment = ExtractFragmentInfo(lease.Data(), lease.Size());
                if (fragment.valid && fragment.protocol == 17) {
                    HandleFragment(lease.Data(), lease.Size(), now_ms);
                    return;
                }
                const UdpInputResult udp = ParseIpUdpPacket(lease.Data(), lease.Size());
                if (udp.error == UdpInputResult::Error::None) {
                    if (dispatcher_ != nullptr &&
                        dispatcher_->FlowShard(udp.datagram.flow) != shard_id_) {
                        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
                        return;
                    }
                    HandleUdp(std::move(lease), now_ms);
                    return;
                }
            }
        }
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    ProcessTcpSegment(input.segment, now_ms);
}

void StackShard::ProcessEnvelope(PacketEnvelope&& envelope, std::uint64_t now_ms) noexcept {
    if (!envelope.lease) return;
    if (envelope.type == PacketEnvelopeType::kRawIp) {
        ProcessPacket(std::move(envelope.lease), now_ms);
        return;
    }
    if (envelope.type == PacketEnvelopeType::kReassembledTcp) {
        const TcpParseResult tcp = ParseTcpSegment(
            envelope.source, envelope.destination,
            envelope.lease.Data(), envelope.lease.Size());
        if (tcp.error != TcpParseError::None) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        ProcessTcpSegment(tcp.segment, now_ms);
        return;
    }
    HandleReassembledUdp(envelope.source, envelope.destination, std::move(envelope.lease));
}

void StackShard::ProcessTcpSegment(const TcpSegmentView& segment,
                                   std::uint64_t now_ms) noexcept {
    TCPIP2_ASSERT_OWNER(ownership_);
    if (dispatcher_ != nullptr && dispatcher_->FlowShard(segment.flow) != shard_id_) {
        // No caller may mutate a PCB after a misrouted segment. The runtime
        // routes every raw and reassembled TCP packet before this point.
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const TcpHandshakeResult result = tcp_->OnSegment(segment, now_ms);
    if (result.error != TcpHandshakeError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.response.valid && !EnqueueTcpResponse(result.response)) {
        tcp_->DeferResponse(result.response);
    }
}

void StackShard::HandleFragment(const std::uint8_t* packet, std::size_t length,
                                std::uint64_t now_ms) noexcept {
    const FragmentInfo fi = ExtractFragmentInfo(packet, length);
    if (!fi.valid) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    FragmentAddResult result;
    if (fi.ip_version == 4) {
        result = reassembler_.AddIpv4Fragment(
            fi.src_ip, fi.dst_ip, fi.protocol,
            static_cast<std::uint16_t>(fi.identification),
            fi.fragment_offset, fi.more_fragments,
            fi.payload, fi.payload_length, now_ms);
    } else {
        result = reassembler_.AddIpv6Fragment(
            fi.src_ip, fi.dst_ip, fi.identification,
            fi.fragment_offset, fi.more_fragments,
            fi.payload, fi.payload_length, now_ms, 0, 0, fi.protocol);
    }
    if (result.error != FragmentError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!result.complete) return;

    // Reassembly complete — its fragment shard may differ from the canonical
    // flow owner, so classify the transport segment before mutating a PCB.
    IpAddress src, dst;
    if (fi.ip_version == 4) {
        src = IpAddress::Ipv4(fi.src_ip[0], fi.src_ip[1], fi.src_ip[2], fi.src_ip[3]);
        dst = IpAddress::Ipv4(fi.dst_ip[0], fi.dst_ip[1], fi.dst_ip[2], fi.dst_ip[3]);
    } else {
        src = IpAddress::Ipv6(fi.src_ip);
        dst = IpAddress::Ipv6(fi.dst_ip);
    }
    if (fi.protocol == 6) {
        const TcpParseResult tcp = ParseTcpSegment(
            src, dst, result.payload.data(), result.total_length);
        if (tcp.error != TcpParseError::None) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const std::size_t owner = dispatcher_ == nullptr
            ? shard_id_
            : dispatcher_->FlowShard(tcp.segment.flow);
        if (owner == shard_id_) {
            ProcessTcpSegment(tcp.segment, now_ms);
            return;
        }

        BufferLease transport = pool_.Allocate();
        if (!transport || result.total_length > transport.Capacity()) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        std::memcpy(transport.Data(), result.payload.data(), result.total_length);
        transport.Resize(result.total_length);
        PacketEnvelope envelope;
        envelope.type = PacketEnvelopeType::kReassembledTcp;
        envelope.lease = std::move(transport);
        envelope.source = src;
        envelope.destination = dst;
        RedirectPacket(owner, std::move(envelope));
        return;
    }

    if (fi.protocol == 17) {
        const bool validate_checksum = src.IsIpv6() ||
            (result.total_length >= 8 &&
             (result.payload[6] != 0 || result.payload[7] != 0));
        const UdpParseResult udp = ParseUdpDatagram(
            src, dst, result.payload.data(), result.total_length, validate_checksum);
        if (udp.error != UdpParseError::None) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const std::size_t owner = dispatcher_ == nullptr
            ? shard_id_
            : dispatcher_->FlowShard(udp.flow);
        if (owner == shard_id_) {
            udp_datagrams_received_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        BufferLease transport = pool_.Allocate();
        if (!transport || result.total_length > transport.Capacity()) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        std::memcpy(transport.Data(), result.payload.data(), result.total_length);
        transport.Resize(result.total_length);
        PacketEnvelope envelope;
        envelope.type = PacketEnvelopeType::kReassembledUdp;
        envelope.lease = std::move(transport);
        envelope.source = src;
        envelope.destination = dst;
        RedirectPacket(owner, std::move(envelope));
        return;
    }

    packets_dropped_.fetch_add(1, std::memory_order_relaxed);
}

void StackShard::HandleUdp(BufferLease&& lease, std::uint64_t /*now_ms*/) noexcept {
    (void)lease;
    udp_datagrams_received_.fetch_add(1, std::memory_order_relaxed);
    // Full UDP flow tracking is future work. The lease is consumed (dropped).
}

void StackShard::HandleReassembledUdp(const IpAddress& source, const IpAddress& destination,
                                      BufferLease&& lease) noexcept {
    if (!lease) return;
    const bool validate_checksum = source.IsIpv6() ||
        (lease.Size() >= 8 && (lease.Data()[6] != 0 || lease.Data()[7] != 0));
    const UdpParseResult udp = ParseUdpDatagram(
        source, destination, lease.Data(), lease.Size(), validate_checksum);
    if (udp.error != UdpParseError::None ||
        (dispatcher_ != nullptr && dispatcher_->FlowShard(udp.flow) != shard_id_)) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    udp_datagrams_received_.fetch_add(1, std::memory_order_relaxed);
}

bool StackShard::RedirectPacket(std::size_t target_shard, PacketEnvelope&& envelope) noexcept {
    if (target_shard >= outbound_lanes_.size() || target_shard >= redirect_targets_.size() ||
        outbound_lanes_[target_shard] == nullptr || redirect_targets_[target_shard] == nullptr) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        redirect_drops_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (!outbound_lanes_[target_shard]->Push(std::move(envelope))) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        redirect_drops_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    redirected_packets_.fetch_add(1, std::memory_order_relaxed);
    redirect_targets_[target_shard]->Wake();
    return true;
}

bool StackShard::QuotedPacketMatchesFlow(const std::uint8_t* quoted,
                                         std::size_t quoted_len,
                                         std::uint8_t family) const noexcept {
    // RFC 1191 §6 / RFC 4443 §2.4 attribution: the ICMP-quoted packet is one
    // WE sent, so its reversed 5-tuple must match a tracked TCP PCB before the
    // error may influence PMTU state. A forged ICMP for a path we are not
    // sending on must not poison the PMTU cache.
    if (!tcp_) return false;

    FlowKey incoming;
    std::size_t l4_offset;
    if (family == 4) {
        if (quoted_len < 20) return false;
        const std::uint8_t ihl_words = static_cast<std::uint8_t>(quoted[0] & 0x0Fu);
        if (ihl_words < 5) return false;
        l4_offset = static_cast<std::size_t>(ihl_words) * 4;
        if (quoted_len < l4_offset + 4) return false; // need both ports
        if (quoted[9] != 6) return false;             // attribute TCP only
        incoming.source = IpAddress::Ipv4(quoted[16], quoted[17], quoted[18], quoted[19]);
        incoming.destination = IpAddress::Ipv4(quoted[12], quoted[13], quoted[14], quoted[15]);
        // Quoted packet's dst_port is the peer's port (incoming source_port);
        // its src_port is our port (incoming destination_port).
        incoming.source_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(quoted[l4_offset + 2]) << 8) | quoted[l4_offset + 3]);
        incoming.destination_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(quoted[l4_offset]) << 8) | quoted[l4_offset + 1]);
        incoming.protocol = 6;
    } else {
        if (quoted_len < 40 + 4) return false;
        if (quoted[6] != 6) return false; // next header must be TCP
        incoming.source = IpAddress::Ipv6(quoted + 24);
        incoming.destination = IpAddress::Ipv6(quoted + 8);
        incoming.source_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(quoted[42]) << 8) | quoted[43]);
        incoming.destination_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(quoted[40]) << 8) | quoted[41]);
        incoming.protocol = 6;
    }
    return tcp_->HasFlow(incoming);
}

void StackShard::HandleIcmp(const std::uint8_t* packet, std::size_t length,
                            std::uint64_t now_ms) noexcept {
    if (packet == nullptr || length == 0) return;

    const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);

    if (version == 4) {
        const Ipv4ParseResult ip = ParseIpv4(packet, length);
        if (ip.error != Ipv4ParseError::None) return;
        if (ip.header.protocol != 1) return;  // ICMPv4

        const Icmpv4ParseResult icmp = ParseIcmpv4(ip.payload, ip.header.payload_length);
        if (icmp.error != Icmpv4ParseError::None) return;

        // Verify ICMPv4 checksum before acting. ICMPv4 does not use a
        // pseudo-header (seed == 0). A corrupted message must not lower PMTU.
        if (!icmp.checksum_ok) return;

        if (icmp.header.type == Icmpv4Type::DestinationUnreachable &&
            icmp.header.code == Icmpv4DestUnreachableCode::FragmentationNeeded) {
            // Extract original dst_ip from the quoted IPv4 header (bytes 16-19).
            if (icmp.header.quoted_payload == nullptr ||
                icmp.header.quoted_payload_len < 20) {
                return;  // quoted payload too short
            }
            // Attribution: ignore errors whose quoted packet does not belong
            // to an existing TCP flow (prevents PMTU-cache poisoning).
            if (!QuotedPacketMatchesFlow(icmp.header.quoted_payload,
                                         icmp.header.quoted_payload_len, 4)) {
                return;
            }
            const std::uint8_t* orig_dst = icmp.header.quoted_payload + 16;
            pmtu_cache_.LowerFromIcmp(orig_dst, 4, icmp.header.mtu, now_ms);
            NotifyTcpPmtuLowered(
                IpAddress::Ipv4(orig_dst[0], orig_dst[1], orig_dst[2], orig_dst[3]),
                now_ms);
        }
        // TimeExceeded and ParameterProblem: no PMTU action for now.
    } else if (version == 6) {
        const Ipv6ParseResult ip = ParseIpv6(packet, length);
        if (ip.error != Ipv6ParseResult::Error::None) return;
        if (ip.final_next_header != 58) return;  // ICMPv6

        // Verify ICMPv6 checksum (includes IPv6 pseudo-header).
        if (!VerifyIcmpv6Checksum(ip.payload, ip.payload_length,
                                  ip.header.src_ip, ip.header.dst_ip)) {
            return;
        }

        const Icmpv6ParseResult icmp = ParseIcmpv6(ip.payload, ip.payload_length);
        if (icmp.error != Icmpv6ParseResult::Error::None) return;

        if (icmp.header.type == Icmpv6Type::PacketTooBig) {
            // Extract original dst_ip from the quoted IPv6 fixed header (bytes 24-39).
            if (icmp.header.quoted_payload == nullptr ||
                icmp.header.quoted_payload_len < 40) {
                return;  // quoted payload too short
            }
            // Attribution: ignore errors whose quoted packet does not belong
            // to an existing TCP flow (prevents PMTU-cache poisoning).
            if (!QuotedPacketMatchesFlow(icmp.header.quoted_payload,
                                         icmp.header.quoted_payload_len, 6)) {
                return;
            }
            const std::uint8_t* orig_dst = icmp.header.quoted_payload + 24;
            pmtu_cache_.LowerFromIcmp(orig_dst, 6, icmp.header.mtu, now_ms);
            NotifyTcpPmtuLowered(IpAddress::Ipv6(orig_dst), now_ms);
        }
    }
}

void StackShard::NotifyTcpPmtuLowered(const IpAddress& peer,
                                      std::uint64_t now_ms) noexcept {
    if (!tcp_) return;
    const PmtuLookupResult r = pmtu_cache_.Lookup(peer.Bytes(),
                                                  peer.IsIpv4() ? 4 : 6, now_ms);
    if (!r.found) return;
    tcp_->OnPathMtuLowered(peer, r.pmtu);
}

bool StackShard::EnqueueTcpResponse(const TcpResponse& response) noexcept {
    if (queue_ == nullptr && tx_queues_.empty()) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (fq_codel_.QueueLength() >= kTcpTxBudget) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    BufferLease lease = pool_.Allocate();
    if (!lease) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    const TcpOutputResult output = BuildTcpControlPacket(
        response, lease.Data(), lease.Capacity());
    if (output.error != TcpOutputError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    lease.Resize(output.packet_length);
    if (!fq_codel_.Enqueue(std::move(lease),
                            static_cast<std::uint32_t>(FlowHash(response.flow) >> 32),
                            clock_->NowMs())) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

void StackShard::PumpTcpSendPaths(std::uint64_t now_ms) noexcept {
    if (!tcp_) return;
    if (fq_codel_.QueueLength() >= kTcpTxBudget) return;
    const std::size_t remaining = kTcpTxBudget - fq_codel_.QueueLength();
    tcp_tx_.clear();
    tcp_->PumpSendPaths(now_ms, kControlInboxBudget, pool_, tcp_tx_, remaining);
    for (auto& lease : tcp_tx_) {
        if (!lease) continue;
        const std::uint32_t flow_hash = HashTxLease(lease.Data(), lease.Size());
        if (!fq_codel_.Enqueue(std::move(lease), flow_hash, now_ms)) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    tcp_tx_.clear();
}

void StackShard::DrainEgressLanes() noexcept {
    if (inbound_egress_lanes_.empty()) return;

    for (std::size_t i = 0;
         i < kTcpTxBudget && fq_codel_.QueueLength() < kTcpTxBudget;
         ++i) {
        ShardEgressLane* lane = inbound_egress_lanes_[next_inbound_egress_lane_];
        next_inbound_egress_lane_ =
            (next_inbound_egress_lane_ + 1) % inbound_egress_lanes_.size();
        if (lane == nullptr) continue;

        EgressEnvelope envelope;
        if (!lane->Pop(envelope)) continue;

        const bool valid_queue = envelope.queue_id < tx_queues_.size() &&
            tx_queues_[envelope.queue_id] != nullptr && dispatcher_ != nullptr &&
            dispatcher_->QueueShard(envelope.queue_id) == shard_id_ &&
            (static_cast<std::size_t>(envelope.flow_hash) % tx_queues_.size()) ==
                envelope.queue_id;
        if (!valid_queue || !envelope.lease ||
            !fq_codel_.Enqueue(std::move(envelope.lease),
                                envelope.flow_hash, envelope.enqueue_time_ms)) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        envelope.lease.Reset();
    }
}

bool StackShard::RouteEgressPacket(FqCoDelPacket& packet) noexcept {
    if (packet.Empty()) return false;

    // Legacy standalone shards have one directly owned queue. Runtime-configured
    // shards have an index for every queue but only retain local queue pointers.
    std::size_t queue_id = 0;
    std::size_t target_shard = shard_id_;
    IPacketQueue* queue = queue_;
    if (!tx_queues_.empty()) {
        queue_id = static_cast<std::size_t>(packet.flow_hash) % tx_queues_.size();
        if (dispatcher_ == nullptr) return false;
        target_shard = dispatcher_->QueueShard(queue_id);
        if (target_shard == shard_id_) {
            queue = tx_queues_[queue_id];
        } else {
            queue = nullptr;
        }
    }

    BufferLease lease = std::move(packet.lease);

    if (target_shard != shard_id_) {
        if (target_shard >= outbound_egress_lanes_.size() ||
            target_shard >= redirect_targets_.size() ||
            outbound_egress_lanes_[target_shard] == nullptr ||
            redirect_targets_[target_shard] == nullptr) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }

        EgressEnvelope envelope;
        envelope.lease = std::move(lease);
        envelope.queue_id = queue_id;
        envelope.flow_hash = packet.flow_hash;
        envelope.enqueue_time_ms = packet.enqueue_time_ms;
        if (!outbound_egress_lanes_[target_shard]->Push(std::move(envelope))) {
            // Lane full — reclaim the lease so the caller can re-enqueue.
            packet.lease = std::move(envelope.lease);
            return false;
        }
        redirect_targets_[target_shard]->Wake();
        return true;
    }

    if (queue == nullptr) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    IoError error = IoError::None;
    std::size_t sent = queue->SendBatch(&lease, 1, error);
    if (sent > 1) sent = 1;
    if (sent == 1) return true;
    // SendBatch would block — the lease was not consumed. Restore it so the
    // caller can re-enqueue the packet with its original timestamp.
    packet.lease = std::move(lease);
    return false;
}

void StackShard::FlushTcpTx() noexcept {
    if (fq_codel_.Empty()) return;

    // CoDel makes the drop decision on the protocol-owner shard. A surviving
    // packet is then either submitted locally or moved to one bounded egress
    // lane. A blocked queue/lane is re-admitted with its original timestamp.
    for (std::size_t i = 0; i < kTcpTxBudget; ++i) {
        auto pkt = fq_codel_.Dequeue(clock_->NowMs());
        if (!pkt) break;
        if (!RouteEgressPacket(*pkt)) {
            if (!fq_codel_.Enqueue(std::move(pkt->lease), pkt->flow_hash,
                                   pkt->enqueue_time_ms)) {
                packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            }
            // A full egress lane or a queue that would block applies bounded
            // backpressure to this shard instead of spinning on one flow.
            break;
        }
    }
}

} // namespace tcpip2
