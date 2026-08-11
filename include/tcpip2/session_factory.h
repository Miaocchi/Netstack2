#pragma once

/**
 * @file session_factory.h
 * @brief Session creation interface for the Netstack2 TCP/UDP engine.
 * @license GPL-3.0
 *
 * Public API — v0.3.0 contract from ADR-008. Signature changes require an ADR
 * and a consumer compile-contract test update.
 *
 * Allows an external consumer (e.g. an OpenPPP2 adapter) to create
 * transport sessions by implementing ISessionFactory. The factory owns all
 * routing policy: fake-IP resolution, Direct/Proxy route selection, DNS,
 * QUIC policy, and PMTU — none of this enters the Netstack2 core.
 */

#include <cstdint>
#include <memory>

#include <tcpip2/address.h>
#include <tcpip2/transport_session.h>

namespace tcpip2 {

/**
 * Opaque flow identifier. This mirrors the internal FlowId (a 64-bit value
 * used in shard messages) but is defined here independently so that external
 * consumers never depend on a private header.
 */
struct FlowId {
    std::uint64_t value = 0;

    bool operator==(const FlowId& o) const noexcept { return value == o.value; }
    bool operator!=(const FlowId& o) const noexcept { return value != o.value; }
};

/** IP address + port — a network endpoint. */
struct IpEndpoint {
    IpAddress address;
    std::uint16_t port = 0;

    bool operator==(const IpEndpoint& o) const noexcept {
        return address == o.address && port == o.port;
    }
    bool operator!=(const IpEndpoint& o) const noexcept { return !(*this == o); }
};

/** Parameters for opening a TCP session. */
struct TcpOpenRequest {
    FlowId flow_id;
    IpEndpoint source;
    IpEndpoint original_destination;
    IpEndpoint resolved_destination;
    std::uint32_t route_mark = 0;
    std::uint8_t dscp = 0;
};

/** Parameters for opening a UDP datagram channel. */
struct UdpOpenRequest {
    FlowId flow_id;
    IpEndpoint source;
    IpEndpoint original_destination;
    IpEndpoint resolved_destination;
    std::uint32_t route_mark = 0;
    std::uint8_t dscp = 0;
};

/** Result of a TCP session open attempt. */
struct SessionOpenResult {
    std::shared_ptr<ITransportSession> session;
    SessionError error = SessionError::None;
};

/** Result of a UDP datagram channel open attempt. */
struct DatagramOpenResult {
    void* handle = nullptr;
    SessionError error = SessionError::None;
};

/**
 * Abstract factory for creating transport sessions.
 *
 * The external adapter implements this to bridge Netstack2's TCP/UDP engine
 * with the consumer's routing and session management. All policy decisions
 * (fake-IP, Direct/Proxy routing, DNS, QUIC, PMTU) live in the adapter, not
 * in the Netstack2 core.
 */
class ISessionFactory {
public:
    virtual ~ISessionFactory() = default;

    virtual SessionOpenResult OpenTcp(const TcpOpenRequest& request) = 0;
    virtual DatagramOpenResult OpenUdp(const UdpOpenRequest& request) = 0;
};

} // namespace tcpip2
