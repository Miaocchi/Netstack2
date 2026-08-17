#pragma once

/**
 * @file delivery.h
 * @brief Bounded delivery of contiguous TCP receive data to a Session.
 * @license GPL-3.0
 */

#include <cstddef>
#include <functional>

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

/// Function type called for each contiguous chunk of received TCP data.
/// The callee must return how many bytes it accepted (0..data.Size())
/// and a SendStatus indicating whether to continue, block, or stop.
using DeliverFn = std::function<SendResult(BufferView)>;

TcpDeliveryResult DrainTcpReceiveBuffer(TcpReceiveBuffer &receive, const DeliverFn &deliver,
                                        std::size_t call_budget = 16) noexcept;

} // namespace tcpip2
