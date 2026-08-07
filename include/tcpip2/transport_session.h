#pragma once

/**
 * @file transport_session.h
 * @brief Remote transport abstraction for the Netstack2 TCP engine.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * Hierarchy (see docs/architecture/transport_session.adr):
 *
 *   ITransportSession
 *   |-- SocketSession
 *   |    |-- KernelSocketSession
 *   |    `-- OnloadSocketSession
 *   `-- UserspaceSession
 *        |-- DpdkSession
 *        `-- EfViSession
 *
 * Backpressure contract: a session that returns SendStatus::WouldBlock must
 * invoke SetWritableCallback() (posted back to the owning shard) when it can
 * accept data again. The TCP flow shrinks or stops growing its advertised
 * window while the session is blocked — this is TCP correctness and memory
 * safety, not tuning.
 */

#include <cstddef>
#include <cstdint>
#include <functional>

#include <tcpip2/buffer.h>

namespace tcpip2 {

enum class SessionError {
    None = 0,
    RemoteClosed,
    Reset,
    Timeout,
    WouldBlock,
    Internal,
};

enum class SendStatus {
    Accepted = 0,
    WouldBlock,
    Closed,
    Error,
};

/** Result of a partial or full send attempt. */
struct SendResult {
    std::size_t accepted_bytes = 0;
    SendStatus status = SendStatus::Accepted;
};

/**
 * Non-owning, trivially copyable view of user data.
 *
 * BufferView lifetime contract (fixed at NETSTACK2-000):
 * after TrySend() returns, the session MUST NOT reference the view.
 * The caller retains ownership of the underlying bytes.
 */
class BufferView final {
public:
    BufferView() noexcept = default;
    BufferView(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

    const std::uint8_t* Data() const noexcept { return data_; }
    std::size_t Size() const noexcept { return size_; }
    bool Empty() const noexcept { return size_ == 0; }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

using WritableCallback = std::function<void()>;
using DataCallback = std::function<void(BufferLease)>;
using ClosedCallback = std::function<void(SessionError)>;

class ITransportSession {
public:
    virtual ~ITransportSession() = default;

    /**
     * Accept up to @p data.size() bytes. Returns the number accepted and a
     * status. On WouldBlock, the session must later invoke the writable
     * callback (routed back to the owning shard).
     */
    virtual SendResult TrySend(BufferView data) = 0;

    virtual void ShutdownWrite() = 0;
    virtual void Abort(SessionError error) = 0;

    virtual void SetWritableCallback(WritableCallback cb) = 0;

    /** Remote data is delivered as an owning BufferLease. */
    virtual void SetDataCallback(DataCallback cb) = 0;

    virtual void SetClosedCallback(ClosedCallback cb) = 0;
};

} // namespace tcpip2
