/**
 * @file tap_io_test.cpp
 * @brief Unit tests for the Linux TUN/TAP packet I/O backend.
 * @license GPL-3.0
 *
 * These tests exercise TapPacketIo. TUN requires root (or CAP_NET_ADMIN);
 * when Open() fails (typical in CI without privileges) every test skips
 * gracefully by verifying the closed-state invariants. When Open() succeeds
 * the tests exercise queue opening, send/recv, and close idempotency.
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>

#include <tcpip2/buffer.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/tap_io.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "Test.h"

using namespace tcpip2;

// Helper: open a single-queue TUN with a deterministic name.
static bool OpenTestTap(TapPacketIo& tap) {
    TapPacketIo::Config cfg;
    cfg.dev_name = "tun-ns2-test";
    cfg.queue_count = 1;
    cfg.tap_mode = false;
    cfg.no_pi = true;
    return tap.Open(cfg);
}

TCPIP2_TEST(TapOpenFailsGracefully) {
    TapPacketIo tap;
    const bool opened = OpenTestTap(tap);
    if (!opened) {
        // Expected in non-root CI: verify graceful degradation.
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        TCPIP2_EXPECT_EQ(std::size_t{0}, tap.QueueCount());
        TCPIP2_EXPECT_TRUE(tap.OpenQueue(0) == nullptr);
        return;
    }
    // We have root: verify it opened.
    TCPIP2_EXPECT_TRUE(tap.IsOpen());
    TCPIP2_EXPECT_EQ(std::size_t{1}, tap.QueueCount());
    tap.Close();
}

TCPIP2_TEST(TapQueueIdMatches) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    TCPIP2_EXPECT_EQ(std::size_t{1}, tap.QueueCount());
    auto q = tap.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{0}, q->QueueId());
    // Out-of-range queue returns nullptr.
    TCPIP2_EXPECT_TRUE(tap.OpenQueue(1) == nullptr);
    TCPIP2_EXPECT_TRUE(tap.OpenQueue(99) == nullptr);
    tap.Close();
}

TCPIP2_TEST(TapSendEmptyBatchReturnsZero) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    auto q = tap.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);
    BufferLease pkts[1];
    IoError err = IoError::Internal;
    std::size_t n = q->SendBatch(pkts, 0, err);
    TCPIP2_EXPECT_EQ(std::size_t{0}, n);
    TCPIP2_EXPECT_TRUE(err == IoError::None);
    tap.Close();
}

TCPIP2_TEST(TapRecvEmptyReturnsWouldBlock) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    auto q = tap.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);
    // Inject a pool for RX allocation (see ADR-001).
    PktBufferPool pool(4, 2048);
    q->SetBufferPool(&pool);
    BufferLease out[2];
    IoError err = IoError::Internal;
    std::size_t n = q->RecvBatch(out, 2, err);
    // No data on the TUN: should get 0 with WouldBlock.
    TCPIP2_EXPECT_EQ(std::size_t{0}, n);
    TCPIP2_EXPECT_TRUE(err == IoError::WouldBlock || err == IoError::None);
    tap.Close();
}

TCPIP2_TEST(TapSendAndRecvEcho) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    auto q = tap.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);

    // Build a minimal IPv4 packet (no payload, just a 20-byte header).
    PktBufferPool pool(4, 2048);
    q->SetBufferPool(&pool);
    BufferLease pkt = pool.Allocate();
    TCPIP2_EXPECT_TRUE(static_cast<bool>(pkt));
    if (!pkt) {
        tap.Close();
        return;
    }
    // Minimal IPv4 header: version/IHL=0x45, tot_len=20, proto=255 (reserved),
    // src=10.0.0.1, dst=10.0.0.2. Checksum left zero (TUN won't validate).
    std::memset(pkt.Data(), 0, 20);
    pkt.Data()[0] = 0x45;      // version 4, IHL 5
    pkt.Data()[1] = 0x00;      // DSCP/ECN
    pkt.Data()[2] = 0x00;      // total length hi
    pkt.Data()[3] = 0x14;      // total length lo = 20
    pkt.Data()[8] = 64;        // TTL
    pkt.Data()[9] = 255;       // protocol (reserved)
    pkt.Data()[12] = 10;       // src IP
    pkt.Data()[16] = 10;       // dst IP
    pkt.Data()[17] = 2;
    pkt.Resize(20);

    IoError err = IoError::Internal;
    std::size_t sent = q->SendBatch(&pkt, 1, err);
    // The TUN interface may not be up/configured in the test environment,
    // causing EIO on write. Accept both success and error here: the contract
    // is that on error the lease stays with the caller, on success it's
    // transferred to the backend.
    if (sent == 1 && err == IoError::None) {
        // Lease was transferred to the backend (released on write success).
        TCPIP2_EXPECT_FALSE(static_cast<bool>(pkt));
    } else {
        // Write failed: lease must stay with the caller (no transfer on error).
        TCPIP2_EXPECT_TRUE(err == IoError::Closed || err == IoError::Internal ||
                           err == IoError::WouldBlock);
        TCPIP2_EXPECT_TRUE(static_cast<bool>(pkt));
        pkt.Reset();
    }

    // Try to read back. With no data on the TUN, expect WouldBlock or None.
    BufferLease out[2];
    err = IoError::Internal;
    std::size_t n = q->RecvBatch(out, 2, err);
    if (n > 0) {
        TCPIP2_EXPECT_TRUE(static_cast<bool>(out[0]));
        TCPIP2_EXPECT_TRUE(err == IoError::None);
        TCPIP2_EXPECT_EQ(std::size_t{20}, out[0].Size());
        TCPIP2_EXPECT_EQ(std::uint8_t{0x45}, out[0].Data()[0]);
        out[0].Reset();
    } else {
        TCPIP2_EXPECT_TRUE(err == IoError::WouldBlock || err == IoError::None ||
                           err == IoError::Closed);
    }
    tap.Close();
}

TCPIP2_TEST(TapCloseIsIdempotent) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        // Close on a never-opened TAP should be a no-op.
        tap.Close();
        tap.Close();
        return;
    }
    TCPIP2_EXPECT_TRUE(tap.IsOpen());
    tap.Close();
    TCPIP2_EXPECT_FALSE(tap.IsOpen());
    // Second close must not crash.
    tap.Close();
    TCPIP2_EXPECT_FALSE(tap.IsOpen());
}

TCPIP2_TEST(TapRecvOnClosedFd) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    auto q = tap.OpenQueue(0);
    TCPIP2_EXPECT_TRUE(q != nullptr);
    PktBufferPool pool(4, 2048);
    q->SetBufferPool(&pool);
    // Close the underlying device while the queue handle exists.
    tap.Close();
    TCPIP2_EXPECT_FALSE(tap.IsOpen());
    // RecvBatch on a closed fd: should get 0 with an error (Closed or WouldBlock).
    BufferLease out[2];
    IoError err = IoError::None;
    std::size_t n = q->RecvBatch(out, 2, err);
    TCPIP2_EXPECT_EQ(std::size_t{0}, n);
    TCPIP2_EXPECT_TRUE(err == IoError::Closed || err == IoError::WouldBlock);
}

TCPIP2_TEST(TapOpenMultiQueue) {
    TapPacketIo tap;
    TapPacketIo::Config cfg;
    cfg.dev_name = "tun-ns2-mq";
    cfg.queue_count = 2;
    cfg.multi_queue = true;
    cfg.no_pi = true;
    const bool opened = tap.Open(cfg);
    if (!opened) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    TCPIP2_EXPECT_EQ(std::size_t{2}, tap.QueueCount());
    auto q0 = tap.OpenQueue(0);
    auto q1 = tap.OpenQueue(1);
    TCPIP2_EXPECT_TRUE(q0 != nullptr);
    TCPIP2_EXPECT_TRUE(q1 != nullptr);
    TCPIP2_EXPECT_EQ(std::size_t{0}, q0->QueueId());
    TCPIP2_EXPECT_EQ(std::size_t{1}, q1->QueueId());
    tap.Close();
}

TCPIP2_TEST(TapDoubleOpenFails) {
    TapPacketIo tap;
    if (!OpenTestTap(tap)) {
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    TCPIP2_EXPECT_TRUE(tap.IsOpen());
    // Second Open should fail (already opened).
    TapPacketIo::Config cfg2;
    cfg2.dev_name = "tun-ns2-test2";
    cfg2.queue_count = 1;
    TCPIP2_EXPECT_FALSE(tap.Open(cfg2));
    tap.Close();
}

TCPIP2_TEST(TapZeroQueueCountFails) {
    TapPacketIo tap;
    TapPacketIo::Config cfg;
    cfg.queue_count = 0;
    TCPIP2_EXPECT_FALSE(tap.Open(cfg));
    TCPIP2_EXPECT_FALSE(tap.IsOpen());
    tap.Close();
}

TCPIP2_TEST(TapMultiqueueTier2RootTest) {
    // Tier 2 gate (ADR-002): real multiqueue TUN I/O lifecycle. This test
    // only runs as root; otherwise it skips (never fails). Even as root it
    // skips if /dev/net/tun is unavailable or Open() fails for any reason.
    if (geteuid() != 0) {
        std::fprintf(stderr, "SKIP: TapMultiqueueTier2RootTest requires root\n");
        return;
    }
    std::fprintf(stderr, "TapMultiqueueTier2RootTest: running as root\n");

    TapPacketIo tap;
    TapPacketIo::Config cfg;
    cfg.dev_name = "nsmqtest";
    cfg.tap_mode = false;
    cfg.multi_queue = true;
    cfg.queue_count = 4;
    cfg.no_pi = true;
    if (!tap.Open(cfg)) {
        std::fprintf(stderr,
                     "SKIP: TapMultiqueueTier2RootTest Open() failed (no TUN?)\n");
        TCPIP2_EXPECT_FALSE(tap.IsOpen());
        return;
    }
    TCPIP2_EXPECT_TRUE(tap.IsOpen());
    TCPIP2_EXPECT_EQ(std::size_t{4}, tap.QueueCount());

    // Bring the interface UP and assign an address. Without IFF_UP the kernel
    // rejects writes with EIO; without an address the kernel has no route to
    // deliver packets back to the TUN's RX path. Assigning a /24 and sending
    // a UDP datagram to the TUN's own address makes the kernel route the
    // packet through the TUN device, delivering it to one of the queue fds.
    {
        const int ctl_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        TCPIP2_EXPECT_TRUE(ctl_fd >= 0);
        if (ctl_fd >= 0) {
            struct ifreq ifr;
            std::memset(&ifr, 0, sizeof(ifr));
            std::strncpy(ifr.ifr_name, "nsmqtest", IFNAMSIZ - 1);
            // Set address 10.222.0.1.
            ifr.ifr_addr.sa_family = AF_INET;
            std::memcpy(ifr.ifr_addr.sa_data, "\x0a\xde\x00\x01", 4);
            ::ioctl(ctl_fd, SIOCSIFADDR, &ifr);
            // Set netmask 255.255.255.0.
            std::memcpy(ifr.ifr_addr.sa_data, "\xff\xff\xff\x00", 4);
            ::ioctl(ctl_fd, SIOCSIFNETMASK, &ifr);
            // Bring up.
            std::memset(&ifr, 0, sizeof(ifr));
            std::strncpy(ifr.ifr_name, "nsmqtest", IFNAMSIZ - 1);
            if (::ioctl(ctl_fd, SIOCGIFFLAGS, &ifr) == 0) {
                ifr.ifr_flags |= static_cast<short>(IFF_UP);
                ::ioctl(ctl_fd, SIOCSIFFLAGS, &ifr);
            }
            ::close(ctl_fd);
        }
    }

    // Open all 4 queues and arm each with a local pool + recv handler.
    PktBufferPool pool(16, 2048);
    std::unique_ptr<IPacketQueue> queues[4];
    for (std::size_t i = 0; i < 4; ++i) {
        queues[i] = tap.OpenQueue(i);
        TCPIP2_EXPECT_TRUE(queues[i] != nullptr);
        if (!queues[i]) {
            tap.Close();
            return;
        }
        TCPIP2_EXPECT_EQ(i, queues[i]->QueueId());
        queues[i]->SetBufferPool(&pool);
        queues[i]->SetRecvHandler([] {});
        // Basic RecvBatch on each queue: may get 0 (empty) or >0 if the
        // kernel already queued traffic. Either is acceptable here; the
        // real RX verification happens after the explicit injection below.
        BufferLease drain[1];
        IoError err = IoError::Internal;
        std::size_t n = queues[i]->RecvBatch(drain, 1, err);
        if (n > 0) {
            drain[0].Reset();
        } else {
            TCPIP2_EXPECT_TRUE(err == IoError::WouldBlock || err == IoError::None);
        }
    }

    // Inject traffic into the TUN's RX path by sending a UDP datagram to the
    // interface's own address (10.222.0.1:9999). The kernel routes the packet
    // through the TUN device, making it appear on one of the queue fds. This
    // is the standard way to test TUN RX without a peer interface or veth pair.
    int udp_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    TCPIP2_EXPECT_TRUE(udp_fd >= 0);
    if (udp_fd < 0) {
        tap.Close();
        return;
    }
    {
        struct sockaddr_in dst;
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(9999);
        dst.sin_addr.s_addr = htonl(0x0ADE0001U); // 10.222.0.1
        const ssize_t nsent = ::sendto(udp_fd, "mq", 2, 0,
                                       reinterpret_cast<struct sockaddr*>(&dst),
                                       sizeof(dst));
        TCPIP2_EXPECT_TRUE(nsent == 2);
    }
    ::close(udp_fd);

    // Receive on any queue (multiqueue TUN delivers to one of the fds).
    // Retry with small sleeps: under ASan/TSan the kernel may take longer to
    // route the injected datagram to the TUN's RX path.
    bool got = false;
    for (std::size_t attempt = 0; attempt < 20; ++attempt) {
        for (std::size_t qi = 0; qi < 4; ++qi) {
            BufferLease out[1];
            IoError recv_err = IoError::Internal;
            std::size_t n = queues[qi]->RecvBatch(out, 1, recv_err);
            if (n > 0) {
                TCPIP2_EXPECT_TRUE(static_cast<bool>(out[0]));
                TCPIP2_EXPECT_TRUE(recv_err == IoError::None);
                TCPIP2_EXPECT_TRUE(out[0].Size() >= std::size_t{20});
                // Kernel may deliver IPv4 (0x4_) or IPv6 (0x6_) depending on
                // stack behavior; just verify a valid IP version nibble.
                const std::uint8_t ver = static_cast<std::uint8_t>(out[0].Data()[0] >> 4);
                TCPIP2_EXPECT_TRUE(ver == 4 || ver == 6);
                out[0].Reset();
                got = true;
                break;
            }
        }
        if (got) break;
        // 1 ms sleep between polling rounds.
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 1000000;
        ::nanosleep(&ts, nullptr);
    }
    TCPIP2_EXPECT_TRUE(got);

    // Clean up queues before closing the device.
    for (std::size_t i = 0; i < 4; ++i) {
        queues[i].reset();
    }
    tap.Close();
    TCPIP2_EXPECT_FALSE(tap.IsOpen());
}

TCPIP2_TEST_MAIN();
