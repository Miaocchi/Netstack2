#pragma once

/**
 * @file events.h
 * @brief Flow event and metrics observation for the Netstack2 runtime.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001 after ADR-005. Signature
 * changes require an ADR and a consumer compile-contract test update.
 *
 * IEventSink allows an external consumer (e.g. an OpenPPP2 adapter) to
 * observe flow lifecycle events and periodic metric snapshots without
 * gaining access to internal flow state.
 *
 * All callbacks are invoked on the owning shard thread. Implementations
 * must not block, must not call back into the Netstack2 API, and must not
 * throw exceptions (methods are noexcept).
 */

#include <cstddef>
#include <cstdint>

#include <tcpip2/flow.h>
#include <tcpip2/session_factory.h>

namespace tcpip2 {

/** Type of flow lifecycle event. */
enum class FlowEventType : std::uint8_t {
    /// A flow entered the ESTABLISHED state (handshake completed).
    Established = 0,
    /// A flow was closed cleanly (FIN/RST exchange or local close).
    Closed = 1,
    /// A flow was reset by the remote peer or due to a local error.
    Reset = 2,
};

/** A single flow lifecycle event. */
struct FlowEvent {
    FlowId flow_id;
    FlowEventType type = FlowEventType::Closed;
};

/**
 * Point-in-time metric snapshot for a single shard.
 *
 * All counters are cumulative since the shard started unless noted.
 */
struct MetricSnapshot {
    /// Shard index (0-based).
    std::size_t shard_id = 0;
    /// Total packets received (RX queue + cross-shard redirect).
    std::uint64_t rx_packets = 0;
    /// Total bytes received.
    std::uint64_t rx_bytes = 0;
    /// Total packets dropped (malformed, pool exhaustion, queue full).
    std::uint64_t dropped_packets = 0;
    /// Total packets transmitted.
    std::uint64_t tx_packets = 0;
    /// Total bytes transmitted.
    std::uint64_t tx_bytes = 0;
    /// Current active TCP PCB count on this shard.
    std::uint64_t tcp_pcb_count = 0;
    /// Current half-open (SYN-RECEIVED) TCP count.
    std::uint64_t tcp_half_open_count = 0;
    /// Total UDP datagrams received.
    std::uint64_t udp_datagrams = 0;
};

/**
 * Abstract event/metrics sink.
 *
 * Methods are called on shard threads. Implementations must be thread-safe
 * (different shards may call concurrently) and must not block.
 */
class IEventSink {
public:
    virtual ~IEventSink() = default;

    /** Called when a flow transitions state (established/closed/reset). */
    virtual void OnFlowEvent(const FlowEvent& event) noexcept = 0;

    /** Called periodically with a shard metric snapshot. */
    virtual void OnMetricSnapshot(const MetricSnapshot& snapshot) noexcept = 0;
};

} // namespace tcpip2
