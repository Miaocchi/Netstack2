/**
 * @file tap_io.cpp
 * @brief Linux TUN/TAP packet I/O backend implementation.
 * @license GPL-3.0
 *
 * Implements TapPacketIo (IPacketIo) and TapQueue (IPacketQueue) using
 * /dev/net/tun. Each queue is one fd opened with TUNSETIFF; in multi-queue
 * mode each fd is a separate queue of the same interface.
 *
 * RecvBatch allocates a fresh BufferLease per packet via the runtime-injected
 * pool (SetBufferPool), reads into it with a per-packet read() syscall, and
 * resizes to the actual byte count. SendBatch writes each packet to the fd
 * with a per-packet write() syscall and releases the lease on success
 * (synchronous TX). Both paths are simple per-packet syscall loops — no
 * readv/writev batching in this version.
 *
 * All transfers follow the ownership rules documented in packet_io.h:
 *   * RecvBatch returns n; out[0..n-1] transferred to caller.
 *   * SendBatch returns n; packets[0..n-1] transferred to backend (released
 *     to pool on write completion), rest stay with caller.
 *   * On error no partial transfer: every lease stays with caller.
 *   * count == 0 returns 0 with IoError::None.
 */

#include <tcpip2/tap_io.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace tcpip2 {

namespace {

class TapQueue final : public IPacketQueue {
public:
    TapQueue(int fd, std::size_t queue_id) noexcept
        : fd_(fd), queue_id_(queue_id) {}

    std::size_t RecvBatch(BufferLease out[], std::size_t capacity, IoError& error) noexcept override {
        if (capacity == 0) {
            error = IoError::None;
            return 0;
        }
        // Pool must be injected before first RecvBatch. If not, report Closed.
        if (pool_ == nullptr) {
            error = IoError::Closed;
            return 0;
        }
        error = IoError::None;
        std::size_t taken = 0;
        while (taken < capacity) {
            BufferLease lease = pool_->Allocate();
            if (!lease) {
                error = IoError::NoBuffer;
                return taken;
            }
            int retries = 0;
            ssize_t n = 0;
            for (;;) {
                n = ::read(fd_, lease.Data(), lease.Capacity());
                if (n >= 0) break;
                if (errno == EINTR) {
                    if (++retries > 3) break;
                    continue;
                }
                break;
            }
            if (n < 0) {
                const int err = errno;
                if (err == EAGAIN || err == EWOULDBLOCK) {
                    error = (taken == 0) ? IoError::WouldBlock : IoError::None;
                    return taken;
                }
                // EBADF, EIO, or other permanent errors.
                error = (taken == 0) ? IoError::Closed : IoError::None;
                return taken;
            }
            lease.Resize(static_cast<std::size_t>(n));
            out[taken++] = std::move(lease);
        }
        return taken;
    }

    std::size_t SendBatch(BufferLease packets[], std::size_t count, IoError& error) noexcept override {
        if (count == 0) {
            error = IoError::None;
            return 0;
        }
        error = IoError::None;
        std::size_t sent = 0;
        for (std::size_t i = 0; i < count; ++i) {
            if (!packets[i]) {
                // Skip empty leases; they count as transferred (no-op).
                ++sent;
                continue;
            }
            const std::size_t size = packets[i].Size();
            if (size == 0) {
                // Zero-length packet: transfer (release) without writing.
                packets[i].Reset();
                ++sent;
                continue;
            }
            int retries = 0;
            ssize_t n = 0;
            for (;;) {
                n = ::write(fd_, packets[i].Data(), size);
                if (n >= 0) break;
                if (errno == EINTR) {
                    if (++retries > 3) break;
                    continue;
                }
                break;
            }
            if (n < 0) {
                const int err = errno;
                if (err == EAGAIN || err == EWOULDBLOCK) {
                    error = (sent == 0) ? IoError::WouldBlock : IoError::None;
                    return sent;
                }
                // Permanent write error: no transfer for this packet.
                error = (sent == 0) ? IoError::Closed : IoError::None;
                return sent;
            }
            if (static_cast<std::size_t>(n) != size) {
                // Partial write is not valid for TUN packets.
                error = (sent == 0) ? IoError::Internal : IoError::None;
                return sent;
            }
            // Success: transfer the lease back to its pool (synchronous TX).
            packets[i].Reset();
            ++sent;
        }
        return sent;
    }

    std::size_t QueueId() const noexcept override { return queue_id_; }

    void SetBufferPool(PktBufferPool* pool) noexcept override {
        pool_ = pool;
    }

    void SetRecvHandler(std::function<void()> wake) override {
        // The TUN backend is poll-based in this version; the wake callback
        // is stored but not proactively invoked (no epoll). The caller
        // polls via RecvBatch().
        recv_handler_ = std::move(wake);
    }

private:
    int fd_;
    std::size_t queue_id_;
    PktBufferPool* pool_ = nullptr;
    std::function<void()> recv_handler_;
};

} // namespace

int TapPacketIo::OpenOneQueue(std::size_t /*queue_id*/, const Config& config) noexcept {
    const int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));

    short flags = 0;
    if (config.tap_mode) {
        flags = IFF_TAP;
    } else {
        flags = IFF_TUN;
    }
    if (config.no_pi) {
        flags |= static_cast<short>(IFF_NO_PI);
    }
    if (config.multi_queue) {
        flags |= static_cast<short>(IFF_MULTI_QUEUE);
    }
    ifr.ifr_flags = flags;

    if (!config.dev_name.empty()) {
        std::strncpy(ifr.ifr_name, config.dev_name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        ::close(fd);
        return -1;
    }

    // Set nonblocking.
    const int fl = ::fcntl(fd, F_GETFL);
    if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        ::close(fd);
        return -1;
    }

    return fd;
}

bool TapPacketIo::Open(const Config& config) noexcept {
    if (opened_) {
        return false;
    }
    if (config.queue_count == 0) {
        return false;
    }

    config_ = config;
    fds_.clear();
    fds_.reserve(config.queue_count);

    for (std::size_t i = 0; i < config.queue_count; ++i) {
        int fd = OpenOneQueue(i, config);
        if (fd < 0) {
            // Clean up any fds already opened.
            for (int prev_fd : fds_) {
                ::close(prev_fd);
            }
            fds_.clear();
            return false;
        }
        fds_.push_back(fd);
    }

    opened_ = true;
    return true;
}

std::size_t TapPacketIo::QueueCount() const noexcept {
    if (!opened_) {
        return 0;
    }
    return fds_.size();
}

std::unique_ptr<IPacketQueue> TapPacketIo::OpenQueue(std::size_t queue_id) {
    if (!opened_ || queue_id >= fds_.size()) {
        return nullptr;
    }
    return std::unique_ptr<IPacketQueue>(new TapQueue(fds_[queue_id], queue_id));
}

bool TapPacketIo::IsOpen() const noexcept {
    return opened_;
}

void TapPacketIo::Close() noexcept {
    if (!opened_) {
        return;
    }
    for (int fd : fds_) {
        ::close(fd);
    }
    fds_.clear();
    opened_ = false;
}

TapPacketIo::~TapPacketIo() {
    Close();
}

} // namespace tcpip2
