#pragma once

/**
 * @file config.h
 * @brief Netstack2 runtime configuration.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcpip2 {

/// TCP congestion-control algorithm selection (fixed at flow creation).
enum class TcpCongestionAlgorithm {
    Aimd,           ///< RFC 5681 (default, no pacing).
    Bbr,            ///< BBRv1 (with pacing).
    HybridBdpAimd,  ///< BDP-based cwnd with AIMD loss response.
    Kcc,            ///< KCC v2.0 geodesic congestion control.
};

struct NetstackConfig {
    std::size_t shard_count = 1;

    /** Number of hardware RX queues the packet I/O exposes. */
    std::size_t rx_queue_count = 1;

    /**
     * RX queue -> shard affinity. Empty means identity (queue i -> shard i),
     * which is valid only when rx_queue_count <= shard_count. When non-empty
     * it must have exactly rx_queue_count entries, each < shard_count.
     */
    std::vector<std::size_t> rx_queue_to_shard;

    /** Per-shard buffer pool slot count. Total slots across all shards =
     * shard_count × pool_slot_count; total pool arena =
     * shard_count × pool_slot_count × pool_slot_capacity. */
    std::size_t pool_slot_count = 4096;

    /** Per-slot capacity in bytes. */
    std::size_t pool_slot_capacity = 2048;

    std::uint32_t initial_tcp_window = 65536;
    std::uint16_t tcp_mss = 1460;

    /// Per-flow congestion-control algorithm for new TCP connections.
    TcpCongestionAlgorithm tcp_cc = TcpCongestionAlgorithm::Aimd;

    /// KCC v2.0 tunables (ADR-010). Ignored unless tcp_cc == Kcc.
    /// 1.88x BDP cwnd floor in PROBE_BW (upstream kcc_turbo, default 1).
    bool kcc_turbo = true;
    /// PROBE_BW additive-increase numerator over 800 (upstream kcc_ai_num,
    /// default 25 = 3.125%/round).
    std::uint32_t kcc_ai_num = 25;
    /// Enable KCC's ECN-CE EWMA cwnd_gain backoff (upstream KCC_ECN_ENABLE is
    /// 0; Netstack2 enables it because the RFC 3168 data path is verified).
    bool kcc_ecn = true;
    /// Enable the per-shard cross-connection bandwidth filter (KCC Forwarding,
    /// upstream kcc_kf_enable default 0). New KCC flows on a shard bootstrap
    /// their window from a fair-share estimate learned from the shard's other
    /// flows.
    bool kcc_kf_enable = false;

    std::uint64_t rto_initial_ms = 1000;
    std::uint64_t persist_timeout_ms = 30000;
    std::uint64_t keepalive_ms = 7200000;
    std::uint64_t time_wait_ms = 60000;

    bool Validate() const noexcept {
        if (shard_count == 0) return false;
        if (rx_queue_count == 0) return false;
        if (rx_queue_to_shard.empty() && rx_queue_count > shard_count) return false;
        if (!rx_queue_to_shard.empty()) {
            if (rx_queue_to_shard.size() != rx_queue_count) return false;
            for (std::size_t s : rx_queue_to_shard) {
                if (s >= shard_count) return false;
            }
        }
        if (pool_slot_count == 0) return false;
        if (pool_slot_capacity == 0) return false;

        // Per-shard pool: total slots = shard_count * pool_slot_count, then
        // total bytes = total_slots * pool_slot_capacity. Guard each
        // multiplication against uint64_t wraparound (on 64-bit targets
        // size_t == uint64_t, so the cast alone does not prevent overflow).
        const std::uint64_t shard_count_u = shard_count;
        const std::uint64_t slot_count_u = pool_slot_count;
        const std::uint64_t slot_cap_u = pool_slot_capacity;
        if (shard_count_u != 0 && slot_count_u > UINT64_MAX / shard_count_u) return false;
        const std::uint64_t total_slots_u = shard_count_u * slot_count_u;
        if (total_slots_u != 0 && slot_cap_u > UINT64_MAX / total_slots_u) return false;
        const std::uint64_t total_bytes_u = total_slots_u * slot_cap_u;
        // Reject if total exceeds SIZE_MAX (would overflow allocation).
        if (total_bytes_u > static_cast<std::uint64_t>(SIZE_MAX)) return false;
        // Reasonable process-level memory cap (4 GiB total pool arena).
        static constexpr std::uint64_t max_total_pool_bytes =
            std::uint64_t{4} * 1024 * 1024 * 1024;
        if (total_bytes_u > max_total_pool_bytes) return false;

        if (initial_tcp_window == 0) return false;
        if (tcp_mss < 512) return false;
        // TcpSendBuffer enforces RFC 6298's 200 ms minimum RTO.
        if (rto_initial_ms < 200) return false;
        if (persist_timeout_ms == 0) return false;
        if (keepalive_ms == 0) return false;
        if (time_wait_ms == 0 || time_wait_ms > UINT32_MAX) return false;
        return true;
    }
};

} // namespace tcpip2
