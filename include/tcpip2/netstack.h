#pragma once

/**
 * @file netstack.h
 * @brief Top-level Netstack2 facade.
 * @license GPL-3.0
 *
 * Public API — v0.3.0 contract from ADR-008. Signature changes require an ADR
 * and a consumer compile-contract test update.
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
#include <mutex>

#include <tcpip2/config.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/runtime_deps.h>
#include <tcpip2/shutdown.h>

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
     *
     * This overload exists for backward compatibility. It does not inject a
     * session factory, clock, or event sink. Prefer Start(const
     * RuntimeDependencies&).
     */
    bool Start(IPacketIo* packet_io = nullptr) noexcept;

    /**
     * Start with structured runtime dependencies (ADR-005).
     *
     * The Runtime creates per-shard buffer pools internally (ADR-001) and
     * wires the session factory, clock, and event sink into every shard.
     * Returns false if deps.Validate() fails or the Runtime fails to start.
     */
    bool Start(const RuntimeDependencies& deps) noexcept;

    /**
     * Stop with the default finite deadline. Existing statement-style
     * `stack.Stop();` callers remain source compatible and may now inspect the
     * returned result.
     */
    StopResult Stop() noexcept;

    /**
     * Stop in the fixed R3 order. A timeout or drain failure retains the
     * Runtime and its pools in Stopping; call Stop again after the backend can
     * complete/cancel outstanding TX.
     */
    StopResult Stop(const StopOptions& options) noexcept;

    const NetstackConfig& Config() const noexcept { return config_; }
    bool IsRunning() const noexcept;

    Runtime* GetRuntime() const noexcept;

private:
    NetstackConfig config_;
    std::unique_ptr<Runtime> runtime_;
    bool started_ = false;
    mutable std::mutex mutex_;
};

} // namespace tcpip2
