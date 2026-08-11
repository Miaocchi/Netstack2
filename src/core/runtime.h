#pragma once

/**
 * @file runtime.h
 * @brief Runtime orchestration: owns shards, dispatcher, and queues.
 * @license GPL-3.0
 *
 * The Runtime wires together the packet I/O, the dispatcher, and the shard
 * threads. Start() opens queues, creates per-shard buffer pools, creates
 * shards, sets the queue->shard mapping, starts all shard threads, and
 * installs recv handlers that wake the owning shard. Stop() transitions to
 * Stopping before it clears handlers, joins shards, and drains queue TX.
 *
 * Per-shard pool model (ADR-001): each shard owns its own PktBufferPool,
 * created by Runtime::Start(). The pool's owner_thread_id_ is set to the
 * shard thread in StackShard::Run(), so Allocate()/ReturnBuffer() on the
 * shard thread take the owner-local uncontended fast path: the mutex is
 * still acquired, but only the owner shard thread contends for it on the
 * hot path. Buffers that cross shard
 * boundaries (via SPSC inbox) are returned to their originating pool's
 * return_queue_ and drained by that shard's DrainReturnQueue().
 *
 * A timed-out Stop retains queues and pools in Stopping. Only a completed Stop
 * destroys pools, after every outstanding lease has been returned.
 */

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/config.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/runtime_deps.h>
#include <tcpip2/shutdown.h>

#include <core/shard_lanes.h>

namespace tcpip2 {

class StackShard;
class PacketDispatcher;

class Runtime {
public:
    Runtime() noexcept;
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    /**
     * Start with given config and packet I/O (legacy entry point — does not
     * inject session factory, clock, or event sink). Returns false on error.
     */
    bool Start(NetstackConfig config, IPacketIo* packet_io) noexcept;

    /**
     * Start with given config and structured runtime dependencies (ADR-005).
     * Requires deps.Validate() (packet_io + session_factory non-null).
     * Returns false on error.
     */
    bool Start(NetstackConfig config, const RuntimeDependencies& deps) noexcept;

    /** Stop all shards and drain TX under @p options. Retryable on failure. */
    StopResult Stop(const StopOptions& options = {}) noexcept;

    bool IsRunning() const noexcept;
    bool IsStopping() const noexcept;

    // Access for testing
    std::size_t ShardCount() const noexcept { return shards_.size(); }
    StackShard* Shard(std::size_t i) const noexcept;
    PacketDispatcher* Dispatcher() const noexcept { return dispatcher_.get(); }

    /**
     * Access shard i's buffer pool (for test assertions). Returns nullptr
     * if the runtime is not started or i is out of range.
     */
    PktBufferPool* ShardPool(std::size_t i) const noexcept;

    // Dependency accessors (valid after Start, before Stop)
    IClock* Clock() const noexcept { return clock_; }
    ISessionFactory* SessionFactory() const noexcept { return session_factory_; }
    IEventSink* EventSink() const noexcept { return event_sink_; }

private:
    enum class State {
        Stopped,
        Starting,
        Running,
        Stopping,
    };

    bool DoStart(NetstackConfig config, const RuntimeDependencies& deps) noexcept;
    StopResult DoStop(const StopOptions& options) noexcept;
    void QuiesceShards() noexcept;
    StopResult DrainTxAndFinalize(const StopOptions& options) noexcept;
    StopResult FinalizeResources(IoError drain_error, std::size_t queue_id) noexcept;

    NetstackConfig config_;
    IPacketIo* packet_io_ = nullptr;
    ISessionFactory* session_factory_ = nullptr;
    IClock* clock_ = nullptr;
    IEventSink* event_sink_ = nullptr;
    std::vector<std::unique_ptr<PktBufferPool>> shard_pools_;
    std::vector<std::unique_ptr<StackShard>> shards_;
    std::unique_ptr<PacketDispatcher> dispatcher_;
    std::unique_ptr<ShardLanes> packet_lanes_;
    std::unique_ptr<ShardEgressLanes> egress_lanes_;
    std::vector<std::unique_ptr<IPacketQueue>> queues_;
    mutable std::mutex lifecycle_mutex_;
    std::condition_variable lifecycle_cv_;
    State state_ = State::Stopped;
    bool stop_in_progress_ = false;
    bool shards_quiesced_ = false;
    StopResult last_stop_result_;
};

} // namespace tcpip2
