#pragma once

/**
 * @file FakeUdpSession.h
 * @brief Thread-safe test double ISessionFactory + IDatagramSession for UDP.
 * @license GPL-3.0
 *
 * The StackShard calls OpenUdp() and session->Send() on the shard thread while
 * the test thread polls state from these doubles, so all mutable members are
 * mutex-guarded.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/datagram_session.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/transport_session.h>

namespace tcpip2 {
namespace test {

class FakeDatagramSession final : public IDatagramSession {
public:
    SendResult Send(BufferView data) override {
        std::lock_guard<std::mutex> lock(mutex_);
        received_.assign(data.Data(), data.Data() + data.Size());
        ++send_calls_;
        return {data.Size(), SendStatus::Accepted};
    }
    void SetDataCallback(DataCallback cb) override {
        std::lock_guard<std::mutex> lock(mutex_);
        data_cb_ = std::move(cb);
    }
    void SetClosedCallback(ClosedCallback cb) override {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_cb_ = std::move(cb);
    }

    /// Invoke the data callback with a lease holding @p payload.
    ReceiveStatus PushRemote(const std::vector<std::uint8_t>& payload,
                             PktBufferPool& pool) {
        BufferLease lease = pool.Allocate();
        if (!lease) return ReceiveStatus::Closed;
        std::memcpy(lease.Data(), payload.data(), payload.size());
        lease.Resize(payload.size());
        DataCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = data_cb_;
        }
        if (!cb) return ReceiveStatus::Closed;
        return cb(lease);
    }

    void PushClosed(SessionError error) {
        ClosedCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = closed_cb_;
        }
        if (cb) cb(error);
    }

    std::size_t SendCalls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return send_calls_;
    }
    std::vector<std::uint8_t> Received() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return received_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::uint8_t> received_;
    std::size_t send_calls_ = 0;
    DataCallback data_cb_;
    ClosedCallback closed_cb_;
};

class FakeSessionFactory final : public ISessionFactory {
public:
    SessionOpenResult OpenTcp(const TcpOpenRequest&) override { return {}; }

    DatagramOpenResult OpenUdp(const UdpOpenRequest& request) override {
        std::lock_guard<std::mutex> lock(mutex_);
        ++open_calls_;
        last_request = request;
        if (reject_next_) {
            reject_next_ = false;
            return {};
        }
        auto session = std::make_shared<FakeDatagramSession>();
        sessions_.push_back(session);
        DatagramOpenResult result;
        result.handle = session.get();
        return result;
    }

    std::size_t OpenCalls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return open_calls_;
    }
    void RejectNext() {
        std::lock_guard<std::mutex> lock(mutex_);
        reject_next_ = true;
    }
    std::size_t SessionCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.size();
    }
    std::shared_ptr<FakeDatagramSession> Session(std::size_t i) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.at(i);
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<FakeDatagramSession>> sessions_;
    std::size_t open_calls_ = 0;
    bool reject_next_ = false;
    UdpOpenRequest last_request;
};

} // namespace test
} // namespace tcpip2
