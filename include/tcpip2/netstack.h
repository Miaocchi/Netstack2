#pragma once

/**
 * @file netstack.h
 * @brief Top-level Netstack2 facade.
 * @license GPL-3.0
 *
 * Experimental API (NETSTACK2-000). The facade is a placeholder until
 * NETSTACK2-004 wires the Dispatcher and StackShard; Start() currently only
 * validates configuration. Signatures may change until
 * NETSTACK2-API-FREEZE-001.
 *
 * Single-ownership invariant (enforced as a code-level invariant):
 *
 *   A TcpFlow — and in general any per-connection state — is created on and
 *   owned by exactly one StackShard thread, which is the only thread allowed
 *   to read/write it until the flow is destroyed. Other threads communicate
 *   exclusively via typed ShardMessage values posted to the owning shard;
 *   they never obtain a writable flow pointer.
 */

#include <tcpip2/config.h>

namespace tcpip2 {

class Netstack2 final {
public:
    explicit Netstack2(NetstackConfig config) noexcept : config_(config) {}

    /** Validate configuration; returns false without starting on error. */
    bool Start() {
        if (started_) return true;
        if (!config_.Validate()) return false;
        started_ = true;
        return true;
    }

    void Stop() noexcept { started_ = false; }

    const NetstackConfig& Config() const noexcept { return config_; }
    bool IsRunning() const noexcept { return started_; }

private:
    NetstackConfig config_;
    bool started_ = false;
};

} // namespace tcpip2
