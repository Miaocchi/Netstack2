#pragma once

/**
 * @file runtime.h
 * @brief Runtime orchestration: owns shards, dispatcher, and queues.
 * @license GPL-3.0
 *
 * The Runtime wires together the packet I/O, the dispatcher, and the shard
 * threads. Start() opens queues, creates per-shard buffer pools, creates
 * shards, sets the queue->shard mapping, starts all shard threads, and
 * installs recv handlers that wake the owning shard. Stop() clears handlers,
 * posts stop messages, and joins.
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
 * After Stop(), all pool outstanding buffers must be 0 — every lease that
 * entered the runtime has been released back to its pool.
 */

#include <atomic>
#include <memory>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcpip2/config.h>
#include <tcpip2/packet_io.h>
#include <tcpip2/runtime_deps.h>

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

    /** Stop all shards. Idempotent. Must not be called from shard thread. */
    void Stop() noexcept;

    bool IsRunning() const noexcept { return running_.load(std::memory_order_relaxed); }

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
    NetstackConfig config_;
    IPacketIo* packet_io_ = nullptr;
    ISessionFactory* session_factory_ = nullptr;
    IClock* clock_ = nullptr;
    IEventSink* event_sink_ = nullptr;
    std::vector<std::unique_ptr<PktBufferPool>> shard_pools_;
    std::vector<std::unique_ptr<StackShard>> shards_;
    std::unique_ptr<PacketDispatcher> dispatcher_;
    std::vector<std::unique_ptr<IPacketQueue>> queues_;
    std::atomic<bool> running_{false};
};

} // namespace tcpip2
