/**
 * @file null_io.cpp
 * @brief Trivially conforming IPacketIo for contract tests and dry runs.
 * @license GPL-3.0
 *
 * The Null backend is the reference implementation that the packet I/O
 * contract tests in NETSTACK2-002 are written against:
 *
 *   * RecvBatch() drains the injectable RX backlog; when the backlog is empty
 *     it returns 0 with IoError::None (never WouldBlock — there is no device).
 *   * SendBatch() accepts every lease (n == count), copies the bytes into the
 *     egress capture, and releases the leases back to their owning pools.
 *   * Inject() may be called from any thread; the queue mutex makes the
 *     backend thread-safe as a contract baseline.
 *
 * All transfers follow the ownership rules documented in packet_io.h: the
 * first n leases go to the receiver (Recv) or the backend (Send); everything
 * else stays with the caller.
 */

#include <tcpip2/packet_io.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

namespace tcpip2 {

struct NullPacketIo::Impl {
    std::size_t queue_count = 0;
    mutable std::mutex mutex;
    std::vector<std::deque<BufferLease>> rx_backlog;
    std::vector<std::vector<std::vector<std::uint8_t>>> egress;
    std::vector<std::function<void()>> recv_handler;
};

namespace {

class NullQueue final : public IPacketQueue {
public:
    NullQueue(std::size_t queue_id, std::shared_ptr<NullPacketIo::Impl> impl) noexcept
        : queue_id_(queue_id), impl_(std::move(impl)) {}

    std::size_t RecvBatch(BufferLease out[], std::size_t capacity, IoError& error) noexcept override {
        if (capacity == 0) {
            error = IoError::None;
            return 0;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        error = IoError::None;
        std::size_t taken = 0;
        while (taken < capacity && !impl_->rx_backlog[queue_id_].empty()) {
            BufferLease lease = std::move(impl_->rx_backlog[queue_id_].front());
            impl_->rx_backlog[queue_id_].pop_front();
            if (!lease) continue;
            out[taken++] = std::move(lease);
        }
        return taken;
    }

    std::size_t SendBatch(BufferLease packets[], std::size_t count, IoError& error) noexcept override {
        if (count == 0) {
            error = IoError::None;
            return 0;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        error = IoError::None;
        auto& egress = impl_->egress[queue_id_];
        for (std::size_t i = 0; i < count; ++i) {
            // Copy egress bytes first; then release the lease (transfer to the
            // backend, i.e. return the buffer to its owning pool).
            egress.emplace_back(packets[i].Data(), packets[i].Data() + packets[i].Size());
            packets[i].Reset();
        }
        return count;
    }

    std::size_t QueueId() const noexcept override { return queue_id_; }

    void SetRecvHandler(std::function<void()> wake) override {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->recv_handler[queue_id_] = std::move(wake);
    }

private:
    std::size_t queue_id_;
    std::shared_ptr<NullPacketIo::Impl> impl_;
};

} // namespace

NullPacketIo::NullPacketIo(std::size_t queue_count)
    : impl_(std::make_shared<Impl>()) {
    impl_->queue_count = queue_count;
    impl_->rx_backlog.resize(queue_count);
    impl_->egress.resize(queue_count);
    impl_->recv_handler.resize(queue_count);
}

NullPacketIo::~NullPacketIo() = default;

std::size_t NullPacketIo::QueueCount() const noexcept { return impl_->queue_count; }

std::unique_ptr<IPacketQueue> NullPacketIo::OpenQueue(std::size_t queue_id) {
    if (queue_id >= impl_->queue_count) return nullptr;
    return std::unique_ptr<IPacketQueue>(new NullQueue(queue_id, impl_));
}

bool NullPacketIo::Inject(std::size_t queue_id, BufferLease&& lease) {
    if (!lease || queue_id >= impl_->queue_count) return false;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->rx_backlog[queue_id].push_back(std::move(lease));
    return true;
}

const std::vector<std::vector<std::uint8_t>>& NullPacketIo::Egress(std::size_t queue_id) const {
    static const std::vector<std::vector<std::uint8_t>> kEmpty;
    if (queue_id >= impl_->queue_count) return kEmpty;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->egress[queue_id];
}

} // namespace tcpip2
