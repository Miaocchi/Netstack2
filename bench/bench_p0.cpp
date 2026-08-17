// bench/bench_p0.cpp
// P0 baseline benchmark binary (NETSTACK2-000, bench/README.md).
//
// Implements the five stable P0 scenarios defined in bench/scenarios.md:
//   null-rx              IPacketQueue::RecvBatch() transfer rate (null backend)
//   null-tx              SendBatch() lease consumption + egress capture rate
//   pool-alloc-release   PktBufferPool allocate/release (single + cross thread)
//   timer-wheel-advance  TimerWheel insert/advance/cancel throughput
//   shard-dispatch       synthetic RX batch queue->shard routing cost
//
// Every scenario emits one JSON record conforming to bench/record.json.schema.
// Scenario IDs and metric sets are stable (see scenarios.md): do not rename a
// scenario or change its metrics without an ADR.
//
// Numbers here are not an SLA; they exist to catch gross regressions and to
// size the packet I/O backends (see docs/architecture/packet_io_backends.md).

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/clock.h>
#include <tcpip2/config.h>
#include <tcpip2/datagram_session.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/runtime_deps.h>
#include <tcpip2/session_factory.h>
#include <tcpip2/shutdown.h>
#include <tcpip2/transport_session.h>

#include <core/runtime.h>
#include <core/shard.h>
#include <core/timer_wheel.h>
#include <ip/checksum.h>

namespace {

using tcpip2::BufferLease;
using tcpip2::BufferView;
using tcpip2::ClosedCallback;
using tcpip2::DataCallback;
using tcpip2::DefaultClock;
using tcpip2::IDatagramSession;
using tcpip2::IoError;
using tcpip2::IPacketQueue;
using tcpip2::ISessionFactory;
using tcpip2::NetstackConfig;
using tcpip2::NullPacketIo;
using tcpip2::PktBufferPool;
using tcpip2::Runtime;
using tcpip2::RuntimeDependencies;
using tcpip2::SendResult;
using tcpip2::SendStatus;
using tcpip2::SessionError;
using tcpip2::SessionOpenResult;
using tcpip2::StackShard;
using tcpip2::TimerId;
using tcpip2::TimerWheel;
using tcpip2::UdpOpenRequest;

using Clock = std::chrono::steady_clock;
using Seconds = std::chrono::duration<double>;

// ---------------------------------------------------------------------------
// JSON helpers. The record schema is fixed (record.json.schema), so a
// hand-rolled writer suffices; numbers are formatted with %g.
// ---------------------------------------------------------------------------

std::string JsonEscape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::string FormatDouble(double v) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%g", v);
    return buf;
}

std::string NowIsoUtc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string GitRev() {
    const char *rev = std::getenv("GIT_REV");
    if (rev != nullptr && rev[0] != '\0')
        return rev;
    std::FILE *pipe = ::popen("git rev-parse --short=12 HEAD 2>/dev/null", "r");
    if (pipe == nullptr)
        return "unknown";
    char buf[64] = {0};
    if (std::fgets(buf, sizeof(buf), pipe) == nullptr) {
        ::pclose(pipe);
        return "unknown";
    }
    ::pclose(pipe);
    std::string s(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    return s.empty() ? "unknown" : s;
}

struct ScenarioResult {
    std::string scenario;
    std::string params_json;  // object body, e.g. "\"slot_count\": 4096"
    std::string metrics_json; // object body, e.g. "\"ops_per_sec\": 1.2e6"
    double ops_per_sec = 0.0; // for the human-readable summary line
};

bool WriteRecord(const ScenarioResult &r, const std::string &out_dir) {
    const std::string record = "{\n"
                               "  \"schema_version\": 1,\n"
                               "  \"scenario\": \"" +
                               r.scenario +
                               "\",\n"
                               "  \"git_rev\": \"" +
                               JsonEscape(GitRev()) +
                               "\",\n"
                               "  \"date_utc\": \"" +
                               NowIsoUtc() +
                               "\",\n"
                               "  \"params\": { " +
                               r.params_json +
                               " },\n"
                               "  \"metrics\": { " +
                               r.metrics_json +
                               " }\n"
                               "}\n";

    std::printf("bench: %-20s %14s ops/s\n", r.scenario.c_str(), FormatDouble(r.ops_per_sec).c_str());

    if (out_dir.empty())
        return true;
    const std::string path = out_dir + "/record-" + r.scenario + ".json";
    std::FILE *f = std::fopen(path.c_str(), "w");
    if (f == nullptr) {
        std::fprintf(stderr, "bench: cannot write %s\n", path.c_str());
        return false;
    }
    const std::size_t written = std::fwrite(record.data(), 1, record.size(), f);
    std::fclose(f);
    if (written != record.size()) {
        std::fprintf(stderr, "bench: short write to %s\n", path.c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Scenario: pool-alloc-release
// ---------------------------------------------------------------------------

ScenarioResult BenchPoolAllocRelease() {
    constexpr std::size_t kSlotCount = 4096;
    constexpr std::size_t kSlotCapacity = 2048;
    constexpr std::size_t kSingleIterations = 2000000;
    constexpr std::size_t kCrossBatch = 256;
    constexpr std::size_t kCrossRounds = 4096; // ~1M cross-thread releases

    // --- single-threaded allocate + release ---
    PktBufferPool single(kSlotCount, kSlotCapacity);
    for (std::size_t i = 0; i < 4096; ++i) {
        BufferLease l = single.Allocate();
        if (!l)
            return {"pool-alloc-release", "\"error\": \"warmup alloc failed\"", "{}", 0.0};
        l.Reset();
    }
    const auto t0 = Clock::now();
    for (std::size_t i = 0; i < kSingleIterations; ++i) {
        BufferLease l = single.Allocate();
        if (!l)
            return {"pool-alloc-release", "\"error\": \"alloc failed\"", "{}", 0.0};
        l.Reset();
    }
    const double single_elapsed = std::chrono::duration_cast<Seconds>(Clock::now() - t0).count();
    const double single_ops = static_cast<double>(kSingleIterations) * 2.0 / single_elapsed;

    // --- cross-thread release: worker thread resets leases allocated on the
    //     main thread; the main thread drains the owner return queue. ---
    PktBufferPool cross(kSlotCount, kSlotCapacity);
    std::mutex mtx;
    std::condition_variable cv_worker;
    std::condition_variable cv_main;
    std::vector<BufferLease> batch;
    batch.reserve(kCrossBatch);
    bool worker_done = true; // true while the worker may wait for work
    bool stop = false;

    std::thread worker([&] {
        std::unique_lock<std::mutex> lock(mtx);
        for (;;) {
            cv_worker.wait(lock, [&] { return !worker_done || stop; });
            if (stop)
                break;
            worker_done = true;
            // Destructing the leases runs Reset() on this (foreign) thread,
            // parking the buffers in the pool's owner return queue.
            batch.clear();
            cv_main.notify_one();
        }
    });

    const auto t1 = Clock::now();
    std::size_t released = 0;
    for (std::size_t round = 0; round < kCrossRounds; ++round) {
        {
            std::unique_lock<std::mutex> lock(mtx);
            for (std::size_t i = 0; i < kCrossBatch; ++i) {
                BufferLease l = cross.Allocate();
                if (!l) {
                    std::fprintf(stderr, "bench: cross-thread alloc failed\n");
                    std::exit(2);
                }
                batch.push_back(std::move(l));
            }
            worker_done = false;
        }
        cv_worker.notify_one();
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv_main.wait(lock, [&] { return worker_done; });
        }
        released += cross.DrainReturnQueue();
    }
    {
        std::lock_guard<std::mutex> lock(mtx);
        stop = true;
    }
    cv_worker.notify_one();
    worker.join();
    const double cross_elapsed = std::chrono::duration_cast<Seconds>(Clock::now() - t1).count();
    const double cross_ops = static_cast<double>(kCrossRounds) * static_cast<double>(kCrossBatch) / cross_elapsed;

    const std::string params = "\"slot_count\": " + std::to_string(kSlotCount) +
                               ", \"slot_capacity\": " + std::to_string(kSlotCapacity) +
                               ", \"single_iterations\": " + std::to_string(kSingleIterations) +
                               ", \"cross_releases\": " + std::to_string(kCrossRounds * kCrossBatch) +
                               ", \"cross_thread_releases_per_sec\": " + FormatDouble(cross_ops);
    // The schema forbids extra metrics fields (additionalProperties: false)
    // and requires every metric to be > 0, so the record carries only
    // ops_per_sec; the cross-thread figure lives in params.
    ScenarioResult r;
    r.scenario = "pool-alloc-release";
    r.params_json = params;
    r.metrics_json = "\"ops_per_sec\": " + FormatDouble(single_ops);
    r.ops_per_sec = single_ops;
    return r;
}

// ---------------------------------------------------------------------------
// Scenario: timer-wheel-advance
// ---------------------------------------------------------------------------

ScenarioResult BenchTimerWheel() {
    constexpr std::size_t kSlotCount = 256;
    constexpr std::size_t kTimers = 100000;
    constexpr std::uint64_t kHorizonMs = 10000;

    TimerWheel wheel(kSlotCount);
    std::vector<TimerId> ids;
    ids.reserve(kTimers);

    const auto t0 = Clock::now();
    for (std::size_t i = 0; i < kTimers; ++i) {
        const std::uint64_t deadline = 1 + static_cast<std::uint64_t>(i % kHorizonMs);
        ids.push_back(wheel.Schedule(deadline, [] {}));
    }
    std::size_t cancelled = 0;
    for (std::size_t i = 0; i < kTimers; i += 2) {
        if (wheel.Cancel(ids[i]))
            ++cancelled;
    }
    std::size_t fired = 0;
    for (std::uint64_t now = 1; now <= kHorizonMs + 1; ++now) {
        fired += wheel.AdvanceTo(now);
    }
    const double elapsed = std::chrono::duration_cast<Seconds>(Clock::now() - t0).count();
    const double ops = (static_cast<double>(kTimers) + static_cast<double>(fired)) / elapsed;

    ScenarioResult r;
    r.scenario = "timer-wheel-advance";
    r.params_json = "\"slot_count\": " + std::to_string(kSlotCount) + ", \"timers\": " + std::to_string(kTimers) +
                    ", \"horizon_ms\": " + std::to_string(kHorizonMs) +
                    ", \"cancelled\": " + std::to_string(cancelled) + ", \"fired\": " + std::to_string(fired);
    r.metrics_json = "\"ops_per_sec\": " + FormatDouble(ops);
    r.ops_per_sec = ops;
    return r;
}

// ---------------------------------------------------------------------------
// Scenario: null-rx
// ---------------------------------------------------------------------------

ScenarioResult BenchNullRx() {
    constexpr std::size_t kSlotCount = 4096;
    constexpr std::size_t kSlotCapacity = 2048;
    constexpr std::size_t kPacketBytes = 64;
    constexpr std::size_t kBatch = 4096; // equals pool slot count
    constexpr std::size_t kRounds = 256; // 1M packets total
    constexpr std::size_t kDrain = 64;   // RecvBatch() capacity per call

    PktBufferPool pool(kSlotCount, kSlotCapacity);
    NullPacketIo io(1);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);

    // Warmup: one inject+drain cycle to touch the fast paths.
    for (std::size_t i = 0; i < kBatch; ++i) {
        BufferLease l = pool.Allocate();
        l.Resize(kPacketBytes);
        io.Inject(0, std::move(l));
    }
    {
        BufferLease out[kDrain];
        IoError err = IoError::None;
        while (queue->RecvBatch(out, kDrain, err) != 0) {
        }
    }

    const auto t0 = Clock::now();
    for (std::size_t round = 0; round < kRounds; ++round) {
        for (std::size_t i = 0; i < kBatch; ++i) {
            BufferLease l = pool.Allocate();
            if (!l) {
                std::fprintf(stderr, "bench: null-rx alloc failed\n");
                std::exit(2);
            }
            l.Resize(kPacketBytes);
            io.Inject(0, std::move(l));
        }
        BufferLease out[kDrain];
        IoError err = IoError::None;
        for (;;) {
            const std::size_t n = queue->RecvBatch(out, kDrain, err);
            if (n == 0)
                break;
            for (std::size_t i = 0; i < n; ++i)
                out[i].Reset();
        }
    }
    const double elapsed = std::chrono::duration_cast<Seconds>(Clock::now() - t0).count();
    const double packets = static_cast<double>(kRounds * kBatch);
    const double ops = packets / elapsed;

    ScenarioResult r;
    r.scenario = "null-rx";
    r.params_json = "\"packet_bytes\": " + std::to_string(kPacketBytes) +
                    ", \"packets\": " + std::to_string(kRounds * kBatch) +
                    ", \"slot_count\": " + std::to_string(kSlotCount);
    r.metrics_json = "\"ops_per_sec\": " + FormatDouble(ops) +
                     ", \"bytes_per_sec\": " + FormatDouble(packets * static_cast<double>(kPacketBytes) / elapsed);
    r.ops_per_sec = ops;
    return r;
}

// ---------------------------------------------------------------------------
// Scenario: null-tx
// ---------------------------------------------------------------------------

ScenarioResult BenchNullTx() {
    constexpr std::size_t kSlotCount = 4096;
    constexpr std::size_t kSlotCapacity = 2048;
    constexpr std::size_t kPacketBytes = 1500;
    constexpr std::size_t kBatch = 256;
    constexpr std::size_t kRounds = 3907; // ~1M packets

    PktBufferPool pool(kSlotCount, kSlotCapacity);
    NullPacketIo io(1);
    std::unique_ptr<IPacketQueue> queue = io.OpenQueue(0);
    queue->SetBufferPool(&pool);

    std::vector<BufferLease> batch;
    batch.reserve(kBatch);
    // Warmup round.
    for (std::size_t i = 0; i < kBatch; ++i) {
        BufferLease l = pool.Allocate();
        l.Resize(kPacketBytes);
        batch.push_back(std::move(l));
    }
    {
        IoError err = IoError::None;
        const std::size_t n = queue->SendBatch(batch.data(), kBatch, err);
        if (n != kBatch) {
            std::fprintf(stderr, "bench: null-tx warmup send failed\n");
            std::exit(2);
        }
        batch.clear();
    }

    const auto t0 = Clock::now();
    for (std::size_t round = 0; round < kRounds; ++round) {
        for (std::size_t i = 0; i < kBatch; ++i) {
            BufferLease l = pool.Allocate();
            if (!l) {
                std::fprintf(stderr, "bench: null-tx alloc failed\n");
                std::exit(2);
            }
            l.Resize(kPacketBytes);
            batch.push_back(std::move(l));
        }
        IoError err = IoError::None;
        const std::size_t n = queue->SendBatch(batch.data(), kBatch, err);
        if (n != kBatch) {
            std::fprintf(stderr, "bench: null-tx send failed\n");
            std::exit(2);
        }
        batch.clear();
    }
    const double elapsed = std::chrono::duration_cast<Seconds>(Clock::now() - t0).count();
    const double packets = static_cast<double>(kRounds * kBatch);
    const double ops = packets / elapsed;

    ScenarioResult r;
    r.scenario = "null-tx";
    r.params_json = "\"packet_bytes\": " + std::to_string(kPacketBytes) +
                    ", \"packets\": " + std::to_string(kRounds * kBatch) +
                    ", \"slot_count\": " + std::to_string(kSlotCount);
    r.metrics_json = "\"ops_per_sec\": " + FormatDouble(ops) +
                     ", \"bytes_per_sec\": " + FormatDouble(packets * static_cast<double>(kPacketBytes) / elapsed);
    r.ops_per_sec = ops;
    return r;
}

// ---------------------------------------------------------------------------
// Scenario: shard-dispatch
//
// Synthetic RX batch injected into a NullPacketIo queue owned by a running
// StackShard; measures queue->shard routing plus the parse path without a real
// NIC. Packets are minimal valid IPv4+UDP datagrams (correct checksums) so the
// packet is accepted and counted as received.
// ---------------------------------------------------------------------------

class BenchDatagramSession final : public IDatagramSession {
  public:
    // Accept the whole datagram so the flow table reports Accepted and no
    // ICMP port-unreachable storm is generated (the benchmark measures the
    // dispatch path, not the rejection path).
    SendResult Send(BufferView data) override { return {data.Size(), SendStatus::Accepted}; }
    void SetDataCallback(DataCallback) override {}
    void SetClosedCallback(ClosedCallback) override {}
};

class BenchSessionFactory final : public ISessionFactory {
  public:
    SessionOpenResult OpenTcp(const tcpip2::TcpOpenRequest &) override { return {}; }
    tcpip2::DatagramOpenResult OpenUdp(const UdpOpenRequest &) override {
        auto session = std::make_shared<BenchDatagramSession>();
        sessions_.push_back(session);
        tcpip2::DatagramOpenResult result;
        result.handle = session.get();
        return result;
    }
    std::size_t SessionCount() const { return sessions_.size(); }

  private:
    std::vector<std::shared_ptr<BenchDatagramSession>> sessions_;
};

// Build a minimal valid IPv4+UDP datagram of exactly kTotalBytes, checksummed
// with the engine's own helpers.
std::vector<std::uint8_t> BuildUdpPacket(std::uint16_t src_port, std::uint16_t dst_port, std::size_t total_bytes) {
    const std::uint8_t src_ip[4] = {10, 0, 0, 1};
    const std::uint8_t dst_ip[4] = {10, 0, 0, 2};
    const std::size_t payload_bytes = total_bytes - 20 - 8;
    const std::uint16_t udp_len = static_cast<std::uint16_t>(8 + payload_bytes);
    const std::uint16_t ip_len = static_cast<std::uint16_t>(20 + 8 + payload_bytes);

    std::vector<std::uint8_t> pkt(total_bytes, 0xAB);
    // IPv4 header.
    pkt[0] = 0x45;
    pkt[2] = static_cast<std::uint8_t>(ip_len >> 8);
    pkt[3] = static_cast<std::uint8_t>(ip_len & 0xFF);
    pkt[4] = 0; // identification
    pkt[5] = 0;
    pkt[6] = 0; // flags (DF/MF) + fragment offset: unfragmented
    pkt[7] = 0;
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    std::memcpy(&pkt[12], src_ip, 4);
    std::memcpy(&pkt[16], dst_ip, 4);
    // The checksum field must be zero while the header checksum is computed.
    pkt[10] = 0;
    pkt[11] = 0;
    const std::uint16_t ip_checksum = tcpip2::InternetChecksum(pkt.data(), 20);
    pkt[10] = static_cast<std::uint8_t>(ip_checksum >> 8);
    pkt[11] = static_cast<std::uint8_t>(ip_checksum & 0xFF);
    // UDP header.
    pkt[20] = static_cast<std::uint8_t>(src_port >> 8);
    pkt[21] = static_cast<std::uint8_t>(src_port & 0xFF);
    pkt[22] = static_cast<std::uint8_t>(dst_port >> 8);
    pkt[23] = static_cast<std::uint8_t>(dst_port & 0xFF);
    pkt[24] = static_cast<std::uint8_t>(udp_len >> 8);
    pkt[25] = static_cast<std::uint8_t>(udp_len & 0xFF);
    // The UDP checksum field must be zero while the checksum is computed.
    pkt[26] = 0;
    pkt[27] = 0;
    const std::uint32_t seed = tcpip2::Ipv4PseudoHeaderSeed(src_ip, dst_ip, 17, udp_len);
    const std::uint16_t udp_checksum = tcpip2::InternetChecksum(pkt.data() + 20, 8 + payload_bytes, seed);
    pkt[26] = static_cast<std::uint8_t>(udp_checksum >> 8);
    pkt[27] = static_cast<std::uint8_t>(udp_checksum & 0xFF);
    return pkt;
}

ScenarioResult BenchShardDispatch() {
    constexpr std::size_t kPacketBytes = 64;
    constexpr std::size_t kPackets = 100000;
    constexpr double kTimeoutSec = 30.0;

    NetstackConfig cfg;
    cfg.shard_count = 1;
    cfg.rx_queue_count = 1;
    cfg.pool_slot_count = 4096;
    cfg.pool_slot_capacity = 2048;

    NullPacketIo io(1);
    BenchSessionFactory factory;
    RuntimeDependencies deps;
    deps.packet_io = &io;
    deps.session_factory = &factory;
    deps.clock = DefaultClock();

    Runtime runtime;
    if (!runtime.Start(cfg, deps)) {
        return {"shard-dispatch", "\"error\": \"runtime start failed\"", "{}", 0.0};
    }
    StackShard *shard = runtime.Shard(0);
    PktBufferPool *pool = runtime.ShardPool(0);
    if (shard == nullptr || pool == nullptr) {
        runtime.Stop();
        return {"shard-dispatch", "\"error\": \"shard/pool unavailable\"", "{}", 0.0};
    }

    const std::vector<std::uint8_t> packet = BuildUdpPacket(10000, 20000, kPacketBytes);
    const auto t0 = Clock::now();
    std::size_t injected = 0;
    while (injected < kPackets) {
        BufferLease lease = pool->Allocate();
        if (!lease) {
            // Pool momentarily exhausted: the shard thread is draining the
            // backlog; wait briefly and retry.
            std::this_thread::sleep_for(std::chrono::microseconds(200));
            continue;
        }
        std::memcpy(lease.Data(), packet.data(), packet.size());
        lease.Resize(packet.size());
        if (!io.Inject(0, std::move(lease))) {
            std::fprintf(stderr, "bench: shard-dispatch inject failed\n");
            std::exit(2);
        }
        ++injected;
    }
    // Wait for the shard to process every injected packet.
    while (shard->PacketsReceived() < kPackets) {
        const double waited = std::chrono::duration_cast<Seconds>(Clock::now() - t0).count();
        if (waited > kTimeoutSec) {
            std::fprintf(stderr, "bench: shard-dispatch timeout: received %zu of %zu\n", shard->PacketsReceived(),
                         kPackets);
            runtime.Stop();
            std::exit(2);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const double elapsed = std::chrono::duration_cast<Seconds>(Clock::now() - t0).count();
    const double ops = static_cast<double>(kPackets) / elapsed;

    // The measurement is only meaningful if every packet was accepted into the
    // UDP path (not dropped at parse/routing time) and the adapter session was
    // opened. Report the counters; a non-zero drop count fails the run.
    const std::size_t udp_datagrams = shard->UdpDatagramsReceived();
    const std::size_t dropped = shard->PacketsDropped();
    const std::size_t rejected = shard->UdpRejectedCount();
    const std::size_t sessions = factory.SessionCount();
    if (udp_datagrams != kPackets || dropped != 0 || rejected != 0 || sessions == 0) {
        std::fprintf(stderr,
                     "bench: shard-dispatch counters unexpected: "
                     "udp_datagrams=%zu dropped=%zu rejected=%zu sessions=%zu\n",
                     udp_datagrams, dropped, rejected, sessions);
        runtime.Stop();
        std::exit(2);
    }

    const tcpip2::StopResult stop = runtime.Stop();
    if (!stop.IsComplete()) {
        std::fprintf(stderr, "bench: shard-dispatch runtime stop incomplete\n");
        std::exit(2);
    }

    ScenarioResult r;
    r.scenario = "shard-dispatch";
    r.params_json = "\"packet_bytes\": " + std::to_string(kPacketBytes) + ", \"packets\": " + std::to_string(kPackets) +
                    ", \"shard_count\": 1, \"rx_queue_count\": 1" +
                    ", \"flows\": 1, \"sessions_opened\": " + std::to_string(sessions) +
                    ", \"udp_datagrams_received\": " + std::to_string(udp_datagrams);
    r.metrics_json = "\"ops_per_sec\": " + FormatDouble(ops) + ", \"bytes_per_sec\": " +
                     FormatDouble(static_cast<double>(kPackets) * static_cast<double>(kPacketBytes) / elapsed);
    r.ops_per_sec = ops;
    return r;
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

struct Scenario {
    const char *id;
    ScenarioResult (*fn)();
};

const Scenario kScenarios[] = {
    {"null-rx", BenchNullRx},
    {"null-tx", BenchNullTx},
    {"pool-alloc-release", BenchPoolAllocRelease},
    {"timer-wheel-advance", BenchTimerWheel},
    {"shard-dispatch", BenchShardDispatch},
};

void PrintUsage(const char *argv0) {
    std::fprintf(stderr,
                 "usage: %s [--scenario all|<id>] [--out-dir DIR]\n"
                 "  scenarios: null-rx, null-tx, pool-alloc-release,\n"
                 "             timer-wheel-advance, shard-dispatch\n",
                 argv0);
}

int RunScenario(const Scenario &s, const std::string &out_dir) {
    const ScenarioResult r = s.fn();
    if (r.metrics_json == "{}" && r.params_json.find("\"error\"") != std::string::npos) {
        std::fprintf(stderr, "bench: scenario %s failed: %s\n", s.id, r.params_json.c_str());
        return 1;
    }
    if (!WriteRecord(r, out_dir))
        return 1;
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    std::string scenario = "all";
    std::string out_dir;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--scenario" && i + 1 < argc) {
            scenario = argv[++i];
        } else if (arg == "--out-dir" && i + 1 < argc) {
            out_dir = argv[++i];
        } else {
            PrintUsage(argv[0]);
            return 2;
        }
    }

    int failures = 0;
    if (scenario == "all") {
        for (const Scenario &s : kScenarios) {
            failures += RunScenario(s, out_dir);
        }
    } else {
        const Scenario *found = nullptr;
        for (const Scenario &s : kScenarios) {
            if (scenario == s.id) {
                found = &s;
                break;
            }
        }
        if (found == nullptr) {
            std::fprintf(stderr, "bench: unknown scenario '%s'\n", scenario.c_str());
            PrintUsage(argv[0]);
            return 2;
        }
        failures += RunScenario(*found, out_dir);
    }
    return failures == 0 ? 0 : 1;
}
