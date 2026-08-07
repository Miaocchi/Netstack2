#pragma once

/**
 * @file netstack.h
 * @brief Top-level Netstack2 facade.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * The facade optionally owns a Runtime. Start() with a non-null packet I/O
 * creates the Runtime (which in turn creates per-shard buffer pools, ADR-001);
 * Start() with nullptr validates config only.
 *
 * Single-ownership invariant (enforced as a code-level invariant):
 *
 *   A TcpFlow — and in general any per-connection state — is created on and
 *   owned by exactly one StackShard thread, which is the only thread allowed
 *   to read/write it until the flow is destroyed. Other threads communicate
 *   exclusively via typed ShardMessage values posted to the owning shard;
 *   they never obtain a writable flow pointer.
 */

#include <memory>

#include <tcpip2/config.h>
#include <tcpip2/packet_io.h>

namespace tcpip2 {

class Runtime;

class Netstack2 final {
public:
    explicit Netstack2(NetstackConfig config) noexcept;
    ~Netstack2();

    Netstack2(const Netstack2&) = delete;
    Netstack2& operator=(const Netstack2&) = delete;

    /**
     * Start with an external packet I/O. nullptr = no I/O (validate config
     * only). When a packet I/O is provided, the Runtime creates per-shard
     * buffer pools internally (ADR-001).
     */
    bool Start(IPacketIo* packet_io = nullptr) noexcept;

    void Stop() noexcept;

    const NetstackConfig& Config() const noexcept { return config_; }
    bool IsRunning() const noexcept { return started_; }

    Runtime* GetRuntime() const noexcept { return runtime_.get(); }

private:
    NetstackConfig config_;
    std::unique_ptr<Runtime> runtime_;
    bool started_ = false;
};

} // namespace tcpip2
