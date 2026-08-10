#pragma once

/**
 * @file runtime_deps.h
 * @brief RuntimeDependencies: structured dependency injection bundle.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001 after ADR-005. Signature
 * changes require an ADR and a consumer compile-contract test update.
 *
 * RuntimeDependencies bundles the external objects the Netstack2 runtime
 * needs at start time (ADR-005). It replaces the loose Start(IPacketIo*)
 * entry point with a structured dependency set.
 */

#include <tcpip2/clock.h>
#include <tcpip2/events.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/session_factory.h>

namespace tcpip2 {

/**
 * External dependencies injected into the Netstack2 runtime at start time.
 *
 * Ownership: all pointers are non-owning. The caller must keep the objects
 * alive until after Netstack2::Stop() returns.
 */
struct RuntimeDependencies {
    /// Packet I/O backend (TUN, AF_XDP, etc.). Must not be null.
    IPacketIo* packet_io = nullptr;

    /// Session factory for creating transport sessions. Must not be null.
    ISessionFactory* session_factory = nullptr;

    /// Monotonic clock. If null, a process-wide SystemClock is used.
    IClock* clock = nullptr;

    /// Event/metrics sink. If null, events are silently dropped.
    IEventSink* event_sink = nullptr;

    /**
     * Validate that mandatory dependencies are present.
     * packet_io and session_factory must be non-null.
     */
    bool Validate() const noexcept {
        return packet_io != nullptr && session_factory != nullptr;
    }
};

} // namespace tcpip2
