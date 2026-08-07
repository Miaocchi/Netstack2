#pragma once

/**
 * @file tap_io.h
 * @brief Linux TUN/TAP packet I/O backend.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * Provides a concrete IPacketIo implementation backed by Linux TUN/TAP
 *
 * Each hardware queue is backed by one file descriptor obtained via
 * TUNSETIFF. In multi-queue mode (IFF_MULTI_QUEUE) each TUNSETIFF call
 * on a new fd returns a separate queue of the same device.
 *
 * Non-root environments: Open() returns false when /dev/net/tun is not
 * accessible (ENOENT or EACCES). Tests call Open() and skip gracefully
 * when it fails.
 *
 * All transfers follow the ownership rules documented in packet_io.h.
 */

#include <cstddef>
#include <string>
#include <vector>

#include <tcpip2/packet_io.h>

namespace tcpip2 {

/**
 * IPacketIo backed by Linux TUN/TAP devices.
 *
 * The backend is synchronous and poll-based: RecvBatch() reads from the
 * TUN fd using per-packet read() syscalls and reports IoError::WouldBlock
 * when the fd would block; SendBatch() writes each packet with per-packet
 * write() syscalls and returns leases to their pool on successful
 * completion (no async TX queue in this version). Neither path uses
 * readv/writev; batching is achieved by looping over individual syscalls.
 */
class TapPacketIo final : public IPacketIo {
public:
    struct Config {
        /** Device name (e.g. "tun0"), or empty for auto-assign by the kernel. */
        std::string dev_name;
        /** true = TAP (Ethernet L2), false = TUN (L3 IP packets). */
        bool tap_mode = false;
        /** true = IFF_MULTI_QUEUE (one fd per queue). */
        bool multi_queue = false;
        /** Number of queues to open (>= 1). */
        std::size_t queue_count = 1;
        /** true = IFF_NO_PI (no packet info prefix, default for L3). */
        bool no_pi = true;
    };

    TapPacketIo() = default;
    ~TapPacketIo() override;

    TapPacketIo(const TapPacketIo&) = delete;
    TapPacketIo& operator=(const TapPacketIo&) = delete;

    /**
     * Open the TUN device and configure all queues per @p config.
     * Returns false on failure (no root, no /dev/net/tun, ioctl error).
     * On failure the object is in the closed state and safe to destruct.
     */
    bool Open(const Config& config) noexcept;

    // IPacketIo overrides
    std::size_t QueueCount() const noexcept override;
    std::unique_ptr<IPacketQueue> OpenQueue(std::size_t queue_id) override;

    /** True if the TUN device is open and usable. */
    bool IsOpen() const noexcept;

    /** Close all fds and reset state. Idempotent. */
    void Close() noexcept;

private:
    int OpenOneQueue(std::size_t queue_id, const Config& config) noexcept;

    Config config_;
    std::vector<int> fds_;
    bool opened_ = false;
};

} // namespace tcpip2
