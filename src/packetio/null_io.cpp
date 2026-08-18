/**
 * @file null_io.cpp
 * @brief Trivially conforming IPacketIo for contract tests and dry runs.
 * @license GPL-3.0
 *
 * The Null backend is the reference implementation that the packet I/O
 * contract tests in NETSTACK2-002 are written against:
 *
 *  * RecvBatch() drains the injectable RX backlog; when the backlog is empty
 *     it returns 0 with IoError::None (never WouldBlock — there is no device).
 *     SetRecvWouldBlock() emulates a poll-based backend: an empty backlog is
 *     then reported as 0 with IoError::WouldBlock.
 *   * SendBatch() accepts every lease (n == count), copies the bytes into the
 *     egress capture, and releases the leases back to their owning pools.
 *     SetMaxSendPerBatch() caps the per-call budget so contract tests can
 *     exercise the partial-send ownership rule (first n to the backend, the
 *     rest stay with the caller). SetSendWouldBlock() emulates a full backend:
 *     no lease is accepted and IoError::WouldBlock is returned.
 *   * SetAsyncTxCompletion() emulates an async TX backend: accepted leases are
 *     held pending instead of being reset inline; DrainTxCompletions() returns
 *     them to their owning pools (the backend's completion path).
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
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <core/inbox_spsc.h>

namespace tcpip2 {

struct NullPacketIo::Impl {
    std::size_t queue_count = 0;
    std::size_t max_send_per_batch = 0;
    bool recv_would_block = false;
    bool send_would_block = false;
    bool async_tx_completion = false;
    bool drain_tx_would_block = false;
    mutable std::mutex mutex;
    std::vector<std::deque<BufferLease>> rx_backlog;
    std::vector<std::deque<BufferLease>> pending_tx;
    std::vector<std::vector<std::vector<std::uint8_t>>> egress;
    std::vector<std::function<void()>> recv_handler;
    std::vector<bool> rx_stopped;
    // Optional lock-free SPSC fast path for benchmark backends: a queue
    // switched to fast mode must be injected from exactly one thread while
    // the shard drains it. Eliminates the mutex + deque node allocation per
    // packet on the RX hot path.
    std::vector<bool> fast;
    std::vector<std::unique_ptr<SpscRing<BufferLease>>> fast_backlog;
};

namespace {

class NullQueue final : public IPacketQueue {
  public:
    NullQueue(std::size_t queue_id, std::shared_ptr<NullPacketIo::Impl> impl) noexcept
        : queue_id_(queue_id), impl_(std::move(impl)) {}

    std::size_t RecvBatch(BufferLease out[], std::size_t capacity, IoError &error) noexcept override {
        if (capacity == 0) {
            error = IoError::None;
            return 0;
        }
        if (impl_->fast[queue_id_]) {
            SpscRing<BufferLease> &ring = *impl_->fast_backlog[queue_id_];
            error = IoError::None;
            std::size_t taken = 0;
            while (taken < capacity) {
                BufferLease lease;
                if (!ring.Pop(lease))
                    break;
                if (!lease)
                    continue;
                out[taken++] = std::move(lease);
            }
            return taken;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->rx_stopped[queue_id_]) {
            error = IoError::Closed;
            return 0;
        }
        error = IoError::None;
        std::size_t taken = 0;
        while (taken < capacity && !impl_->rx_backlog[queue_id_].empty()) {
            BufferLease lease = std::move(impl_->rx_backlog[queue_id_].front());
            impl_->rx_backlog[queue_id_].pop_front();
            if (!lease)
                continue;
            out[taken++] = std::move(lease);
        }
        if (taken == 0 && impl_->recv_would_block) {
            error = IoError::WouldBlock;
        }
        return taken;
    }

    bool Empty() const noexcept override {
        if (impl_->fast[queue_id_]) {
            return impl_->fast_backlog[queue_id_]->Empty();
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        return impl_->rx_backlog[queue_id_].empty();
    }

    std::size_t SendBatch(BufferLease packets[], std::size_t count, IoError &error) noexcept override {
        if (count == 0) {
            error = IoError::None;
            return 0;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->send_would_block) {
            error = IoError::WouldBlock;
            return 0;
        }
        error = IoError::None;
        std::size_t budget = count;
        if (impl_->max_send_per_batch != 0 && impl_->max_send_per_batch < budget) {
            budget = impl_->max_send_per_batch;
        }
        auto &egress = impl_->egress[queue_id_];
        for (std::size_t i = 0; i < budget; ++i) {
            if (!packets[i])
                continue;
            // Copy egress bytes first; then transfer the lease to the backend.
            egress.emplace_back(packets[i].Data(), packets[i].Data() + packets[i].Size());
            if (impl_->async_tx_completion) {
                // Async backend: hold the lease until DrainTxCompletions().
                impl_->pending_tx[queue_id_].push_back(std::move(packets[i]));
            } else {
                // Sync backend: return the buffer to its owning pool now.
                packets[i].Reset();
            }
        }
        return budget;
    }

    std::size_t QueueId() const noexcept override { return queue_id_; }

    void SetBufferPool(PktBufferPool *pool) noexcept override { pool_ = pool; }

    void StopRx() noexcept override {
        if (impl_->fast[queue_id_]) {
            impl_->recv_handler[queue_id_] = nullptr;
            impl_->rx_stopped[queue_id_] = true;
            BufferLease lease;
            while (impl_->fast_backlog[queue_id_]->Pop(lease)) {
                lease.Reset();
            }
            return;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->recv_handler[queue_id_] = nullptr;
        impl_->rx_stopped[queue_id_] = true;
        auto &backlog = impl_->rx_backlog[queue_id_];
        while (!backlog.empty()) {
            backlog.front().Reset();
            backlog.pop_front();
        }
    }

    IoError DrainTx(std::uint64_t deadline_ms) noexcept override {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        auto &pending = impl_->pending_tx[queue_id_];
        if (impl_->drain_tx_would_block && deadline_ms != 0 && !pending.empty()) {
            return IoError::WouldBlock;
        }
        while (!pending.empty()) {
            pending.front().Reset();
            pending.pop_front();
        }
        return IoError::None;
    }

    std::size_t OutstandingTx() const noexcept override {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        return impl_->pending_tx[queue_id_].size();
    }

    void SetRecvHandler(std::function<void()> wake) override {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->recv_handler[queue_id_] = std::move(wake);
    }

  private:
    std::size_t queue_id_;
    std::shared_ptr<NullPacketIo::Impl> impl_;
    PktBufferPool *pool_ = nullptr; // stored for interface conformance; NullQueue does not allocate from it
};

} // namespace

NullPacketIo::NullPacketIo(std::size_t queue_count) : impl_(std::make_shared<Impl>()) {
    impl_->queue_count = queue_count;
    impl_->rx_backlog.resize(queue_count);
    impl_->pending_tx.resize(queue_count);
    impl_->egress.resize(queue_count);
    impl_->recv_handler.resize(queue_count);
    impl_->rx_stopped.resize(queue_count, false);
    impl_->fast.resize(queue_count, false);
    impl_->fast_backlog.resize(queue_count);
}

NullPacketIo::~NullPacketIo() = default;

std::size_t NullPacketIo::QueueCount() const noexcept { return impl_->queue_count; }

std::unique_ptr<IPacketQueue> NullPacketIo::OpenQueue(std::size_t queue_id) {
    if (queue_id >= impl_->queue_count)
        return nullptr;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->rx_stopped[queue_id] = false;
    }
    return std::unique_ptr<IPacketQueue>(new NullQueue(queue_id, impl_));
}

bool NullPacketIo::Inject(std::size_t queue_id, BufferLease &&lease) {
    if (!lease || queue_id >= impl_->queue_count)
        return false;
    if (impl_->fast[queue_id]) {
        // Lock-free single-producer path. The receiver drains the ring; a
        // full ring rejects the injection like a busy device would.
        if (impl_->rx_stopped[queue_id])
            return false;
        return impl_->fast_backlog[queue_id]->Push(std::move(lease));
    }
    std::function<void()> wake;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->rx_stopped[queue_id])
            return false;
        const bool was_empty = impl_->rx_backlog[queue_id].empty();
        impl_->rx_backlog[queue_id].push_back(std::move(lease));
        if (was_empty) {
            // Copy the handler under the lock; invoke it outside to avoid
            // deadlock if the handler calls back into the queue (e.g. RecvBatch).
            wake = impl_->recv_handler[queue_id];
        }
    }
    if (wake)
        wake();
    return true;
}

void NullPacketIo::SetFastQueue(std::size_t queue_id, std::size_t capacity) {
    if (queue_id >= impl_->queue_count)
        return;
    impl_->fast[queue_id] = true;
    impl_->fast_backlog[queue_id] = std::make_unique<SpscRing<BufferLease>>(capacity);
}

void NullPacketIo::SetMaxSendPerBatch(std::size_t n) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->max_send_per_batch = n;
}

void NullPacketIo::SetRecvWouldBlock(bool on) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->recv_would_block = on;
}

void NullPacketIo::SetSendWouldBlock(bool on) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->send_would_block = on;
}

void NullPacketIo::SetAsyncTxCompletion(bool on) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->async_tx_completion = on;
}

void NullPacketIo::SetDrainTxWouldBlock(bool on) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->drain_tx_would_block = on;
}

void NullPacketIo::DrainTxCompletions(std::size_t queue_id) {
    if (queue_id >= impl_->queue_count)
        return;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto &pending = impl_->pending_tx[queue_id];
    while (!pending.empty()) {
        pending.front().Reset();
        pending.pop_front();
    }
}

std::size_t NullPacketIo::PendingTxCompletions(std::size_t queue_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (queue_id >= impl_->queue_count)
        return 0;
    return impl_->pending_tx[queue_id].size();
}

const std::vector<std::vector<std::uint8_t>> &NullPacketIo::Egress(std::size_t queue_id) const {
    static const std::vector<std::vector<std::uint8_t>> kEmpty;
    if (queue_id >= impl_->queue_count)
        return kEmpty;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->egress[queue_id];
}

std::vector<std::vector<std::uint8_t>> NullPacketIo::EgressSnapshot(std::size_t queue_id) const {
    if (queue_id >= impl_->queue_count)
        return {};
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->egress[queue_id];
}

} // namespace tcpip2
