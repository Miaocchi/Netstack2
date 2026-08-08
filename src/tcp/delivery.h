#pragma once

/**
 * @file delivery.h
 * @brief Bounded delivery of contiguous TCP receive data to a Session.
 * @license GPL-3.0
 */

#include <cstddef>

#include <tcpip2/transport_session.h>

#include <tcp/receive.h>

namespace tcpip2 {

enum class TcpDeliveryStatus {
    Idle,
    Drained,
    WouldBlock,
    NoProgress,
    Closed,
    Error,
    InvalidResult,
    BudgetExhausted,
};

struct TcpDeliveryResult {
    TcpDeliveryStatus status = TcpDeliveryStatus::Idle;
    std::size_t accepted_bytes = 0;
    std::size_t calls = 0;
};

TcpDeliveryResult DrainTcpReceiveBuffer(TcpReceiveBuffer& receive,
                                        ITransportSession& session,
                                        std::size_t call_budget = 16) noexcept;

} // namespace tcpip2
