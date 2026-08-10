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
 *   6. Protocol work (noop — future TCP engine)
 *   7. Pacing/FQ (noop)
 *   8. Send TX batch (noop — future TX path)
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
#include <memory>
#include <utility>

#include <tcp/handshake.h>
#include <tcp/input.h>
#include <tcp/isn.h>
#include <tcp/output.h>
#include <tcp/segment.h>

#include <ip/icmpv4.h>
#include <ip/icmpv6.h>
#include <ip/ipv4.h>
#include <ip/ipv6.h>
#include <udp/input.h>

namespace tcpip2 {
StackShard::StackShard(std::size_t shard_id, PktBufferPool& pool, IPacketQueue* queue,
                       std::size_t inbox_capacity,
                       ISessionFactory* session_factory,
                       IClock* clock,
                       IEventSink* event_sink) noexcept
    : shard_id_(shard_id),
      pool_(pool),
      queue_(queue),
      session_factory_(session_factory),
      clock_(clock ? clock : DefaultClock()),
      event_sink_(event_sink),
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
            TcpHandshakeConfig{}, TcpIsnGenerator(isn_secret), timer_,
            tcp_engine_epoch_, session_factory_,
            [this](ShardMessage&& msg) noexcept {
                return control_inbox_.Push(std::move(msg));
            },
            event_sink_);
        tcp_tx_.reserve(kTcpTxBudget);
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
    tcp_tx_.clear();
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

    // Step 2: RX batch from the local queue (if any).
    if (queue_ != nullptr) {
        BufferLease rx[kRxBudget];
        IoError error = IoError::None;
        const std::size_t n = queue_->RecvBatch(rx, kRxBudget, error);
        for (std::size_t i = 0; i < n; ++i) {
            packets_received_.fetch_add(1, std::memory_order_relaxed);
            ProcessPacket(std::move(rx[i]), now_ms);
        }
    }

    // Step 3: Drain packet inbox (SPSC) — redirected packets.
    for (std::size_t i = 0; i < kPacketInboxBudget; ++i) {
        BufferLease lease;
        if (!packet_inbox_.Pop(lease)) break;
        packets_received_.fetch_add(1, std::memory_order_relaxed);
        ProcessPacket(std::move(lease), now_ms);
    }

    // Step 4: Drain control inbox (MPSC). Check for StopMessage first.
    for (std::size_t i = 0; i < kControlInboxBudget; ++i) {
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
            tcp_->OnSessionClosed(msg.flow_id, msg.generation);
        }
        if (msg.type == ShardMessageType::kSessionData && tcp_) {
            // EnqueueSendData copies bytes into the TCP send buffer; the lease
            // is still owned by msg and will be Reset() below.
            tcp_->EnqueueSendData(msg.flow_id, msg.data);
            // Prevent double-release: msg.data still holds the lease, and the
            // unified Reset() at the end of the loop will release it. Do NOT
            // reset it here.
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
        while (tcp_tx_.size() < kTcpTxBudget &&
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
    }

    // Step 8: submit the bounded TCP control batch. Partial-send tails remain owned.
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
                const UdpInputResult udp = ParseIpUdpPacket(lease.Data(), lease.Size());
                if (udp.error == UdpInputResult::Error::None) {
                    HandleUdp(std::move(lease), now_ms);
                    return;
                }
            }
        }
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const TcpHandshakeResult result = tcp_->OnSegment(input.segment, now_ms);
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
            fi.payload, fi.payload_length, now_ms);
    }
    if (result.error != FragmentError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!result.complete) return;

    // Reassembly complete — re-parse as TCP segment and deliver.
    IpAddress src, dst;
    if (fi.ip_version == 4) {
        src = IpAddress::Ipv4(fi.src_ip[0], fi.src_ip[1], fi.src_ip[2], fi.src_ip[3]);
        dst = IpAddress::Ipv4(fi.dst_ip[0], fi.dst_ip[1], fi.dst_ip[2], fi.dst_ip[3]);
    } else {
        src = IpAddress::Ipv6(fi.src_ip);
        dst = IpAddress::Ipv6(fi.dst_ip);
    }
    const TcpParseResult tcp = ParseTcpSegment(
        src, dst, result.payload.data(), result.total_length);
    if (tcp.error != TcpParseError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const TcpHandshakeResult hr = tcp_->OnSegment(tcp.segment, now_ms);
    if (hr.error != TcpHandshakeError::None) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
    }
    if (hr.response.valid && !EnqueueTcpResponse(hr.response)) {
        tcp_->DeferResponse(hr.response);
    }
}

void StackShard::HandleUdp(BufferLease&& lease, std::uint64_t /*now_ms*/) noexcept {
    udp_datagrams_received_.fetch_add(1, std::memory_order_relaxed);
    // Full UDP flow tracking is future work. The lease is consumed (dropped).
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

        if (icmp.header.type == Icmpv4Type::DestinationUnreachable &&
            icmp.header.code == Icmpv4DestUnreachableCode::FragmentationNeeded) {
            // Extract original dst_ip from the quoted IPv4 header (bytes 16-19).
            if (icmp.header.quoted_payload == nullptr ||
                icmp.header.quoted_payload_len < 20) {
                return;  // quoted payload too short
            }
            const std::uint8_t* orig_dst = icmp.header.quoted_payload + 16;
            pmtu_cache_.LowerFromIcmp(orig_dst, 4, icmp.header.mtu, now_ms);
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
            const std::uint8_t* orig_dst = icmp.header.quoted_payload + 24;
            pmtu_cache_.LowerFromIcmp(orig_dst, 6, icmp.header.mtu, now_ms);
        }
    }
}

bool StackShard::EnqueueTcpResponse(const TcpResponse& response) noexcept {
    if (queue_ == nullptr || tcp_tx_.size() >= kTcpTxBudget) {
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
    try {
        tcp_tx_.push_back(std::move(lease));
    } catch (...) {
        packets_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

void StackShard::PumpTcpSendPaths(std::uint64_t now_ms) noexcept {
    if (!tcp_ || tcp_tx_.size() >= kTcpTxBudget) return;
    const std::size_t remaining = kTcpTxBudget - tcp_tx_.size();
    tcp_->PumpSendPaths(now_ms, kControlInboxBudget, pool_, tcp_tx_, remaining);
}

void StackShard::FlushTcpTx() noexcept {
    if (queue_ == nullptr || tcp_tx_.empty()) return;
    IoError error = IoError::None;
    std::size_t sent = queue_->SendBatch(tcp_tx_.data(), tcp_tx_.size(), error);
    if (sent > tcp_tx_.size()) sent = tcp_tx_.size();
    if (sent > 0) {
        for (std::size_t i = sent; i < tcp_tx_.size(); ++i) {
            tcp_tx_[i - sent] = std::move(tcp_tx_[i]);
        }
        tcp_tx_.resize(tcp_tx_.size() - sent);
    }
    if (error != IoError::None && error != IoError::WouldBlock) {
        packets_dropped_.fetch_add(tcp_tx_.size(), std::memory_order_relaxed);
        tcp_tx_.clear();
    }
}

} // namespace tcpip2
