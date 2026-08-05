#pragma once

/**
 * @file config.h
 * @brief Netstack2 runtime configuration.
 * @license GPL-3.0
 *
 * Experimental API (NETSTACK2-000). Validated by config_test; may change
 * until NETSTACK2-API-FREEZE-001.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcpip2 {

struct NetstackConfig {
    std::size_t shard_count = 1;

    /** Number of hardware RX queues the packet I/O exposes. */
    std::size_t rx_queue_count = 1;

    /**
     * RX queue -> shard affinity. Empty means identity (queue i -> shard i).
     * When non-empty it must have exactly rx_queue_count entries, each
     * < shard_count.
     */
    std::vector<std::size_t> rx_queue_to_shard;

    std::size_t pool_slot_count = 4096;
    std::size_t pool_slot_capacity = 2048;

    std::uint32_t initial_tcp_window = 65536;
    std::uint16_t tcp_mss = 1460;

    std::uint64_t rto_initial_ms = 1000;
    std::uint64_t persist_timeout_ms = 30000;
    std::uint64_t keepalive_ms = 7200000;
    std::uint64_t time_wait_ms = 60000;

    bool Validate() const noexcept {
        if (shard_count == 0) return false;
        if (rx_queue_count == 0) return false;
        if (!rx_queue_to_shard.empty()) {
            if (rx_queue_to_shard.size() != rx_queue_count) return false;
            for (std::size_t s : rx_queue_to_shard) {
                if (s >= shard_count) return false;
            }
        }
        if (pool_slot_count == 0) return false;
        if (pool_slot_capacity == 0) return false;
        if (initial_tcp_window == 0) return false;
        if (tcp_mss < 512) return false;
        if (rto_initial_ms == 0) return false;
        if (persist_timeout_ms == 0) return false;
        if (keepalive_ms == 0) return false;
        if (time_wait_ms == 0) return false;
        return true;
    }
};

} // namespace tcpip2
