#pragma once

/**
 * @file datagram_session.h
 * @brief Remote datagram transport abstraction for the Netstack2 UDP engine.
 * @license GPL-3.0
 *
 * The UDP engine routes client datagrams through a datagram session owned by
 * the external adapter. ISessionFactory::OpenUdp() returns the session as an
 * opaque void* handle (frozen DatagramOpenResult contract); the UDP engine
 * interprets that handle as an IDatagramSession* — the adapter returns a
 * pointer to an object implementing this interface. The core never owns or
 * frees the session; the adapter keeps it alive for as long as the flow is
 * tracked (or until the closed callback evicts the flow).
 *
 * Datagram semantics: every Send() call carries exactly one application
 * datagram. Boundaries must be preserved — the session MUST NOT split or
 * coalesce datagrams into a stream.
 */

#include <tcpip2/transport_session.h>

namespace tcpip2 {

/**
 * A remote UDP channel. The adapter implements this and returns it from
 * OpenUdp(); the core binds the data/closed callbacks and forwards client
 * datagrams to the remote.
 */
class IDatagramSession {
  public:
    virtual ~IDatagramSession() = default;

    /**
     * Send one datagram to the remote. On WouldBlock the session must later
     * invoke the writable callback (routed back to the owning shard) before
     * the flow retries. Datagram boundaries are preserved.
     */
    virtual SendResult Send(BufferView data) = 0;

    /**
     * Remote datagram callback. The adapter fills @p lease with the payload
     * of one inbound remote datagram and invokes the callback. On Accepted
     * the callback moves the lease out; on WouldBlock it must leave it intact
     * and pause remote reads until ResumeReceive() / the writable callback.
     */
    virtual void SetDataCallback(DataCallback cb) = 0;

    /** Install or synchronously quiesce the closed callback. */
    virtual void SetClosedCallback(ClosedCallback cb) = 0;
};

} // namespace tcpip2
