#include <tcp/delivery.h>

namespace tcpip2 {

TcpDeliveryResult DrainTcpReceiveBuffer(TcpReceiveBuffer &receive, const DeliverFn &deliver,
                                        std::size_t call_budget) noexcept {
    TcpDeliveryResult result;
    if (receive.ReadyBytes() == 0)
        return result;
    if (call_budget == 0) {
        result.status = TcpDeliveryStatus::BudgetExhausted;
        return result;
    }

    while (receive.ReadyBytes() != 0 && result.calls < call_budget) {
        const TcpReadyView ready = receive.ReadyView();
        if (ready.data == nullptr || ready.length == 0) {
            result.status = TcpDeliveryStatus::InvalidResult;
            receive.SetBlocked(true);
            return result;
        }

        SendResult sent;
        try {
            sent = deliver(BufferView(ready.data, ready.length));
        } catch (...) {
            result.status = TcpDeliveryStatus::Error;
            receive.SetBlocked(true);
            return result;
        }
        ++result.calls;
        if (sent.accepted_bytes > ready.length) {
            result.status = TcpDeliveryStatus::InvalidResult;
            receive.SetBlocked(true);
            return result;
        }
        if (sent.accepted_bytes != 0) {
            receive.ConsumeReady(sent.accepted_bytes);
            result.accepted_bytes += sent.accepted_bytes;
        }

        switch (sent.status) {
        case SendStatus::Accepted:
            if (sent.accepted_bytes == 0) {
                result.status = TcpDeliveryStatus::NoProgress;
                receive.SetBlocked(true);
                return result;
            }
            break;
        case SendStatus::WouldBlock:
            result.status = TcpDeliveryStatus::WouldBlock;
            receive.SetBlocked(true);
            return result;
        case SendStatus::Closed:
            result.status = TcpDeliveryStatus::Closed;
            receive.SetBlocked(true);
            return result;
        case SendStatus::Error:
            result.status = TcpDeliveryStatus::Error;
            receive.SetBlocked(true);
            return result;
        }
    }

    if (receive.ReadyBytes() == 0) {
        result.status = TcpDeliveryStatus::Drained;
        receive.SetBlocked(false);
    } else {
        result.status = TcpDeliveryStatus::BudgetExhausted;
    }
    return result;
}

} // namespace tcpip2
