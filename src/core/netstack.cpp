/**
 * @file netstack.cpp
 * @brief Netstack2 facade implementation.
 * @license GPL-3.0
 *
 * Start() validates the config and (when a packet I/O is provided) starts
 * the Runtime, which creates per-shard buffer pools internally (ADR-001).
 * Stop() reports deadline and drain outcomes. The facade keeps its Runtime on
 * an incomplete stop so callers can retry without invalidating backend leases.
 */

#include <tcpip2/netstack.h>

#include <memory>
#include <utility>

#include <core/runtime.h>

namespace tcpip2 {

Netstack2::Netstack2(NetstackConfig config) noexcept
    : config_(config) {}

Netstack2::~Netstack2() {
    StopOptions final_drain;
    final_drain.timeout_ms = 0;
    Stop(final_drain);
}

bool Netstack2::Start(IPacketIo* packet_io) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) return runtime_ ? runtime_->IsRunning() : true;
    if (!config_.Validate()) return false;

    if (packet_io != nullptr) {
        runtime_ = std::unique_ptr<Runtime>(new Runtime());
        if (!runtime_->Start(config_, packet_io)) {
            runtime_.reset();
            return false;
        }
    }

    started_ = true;
    return true;
}

bool Netstack2::Start(const RuntimeDependencies& deps) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) return runtime_ ? runtime_->IsRunning() : true;
    if (!config_.Validate()) return false;
    if (!deps.Validate()) return false;

    runtime_ = std::unique_ptr<Runtime>(new Runtime());
    if (!runtime_->Start(config_, deps)) {
        runtime_.reset();
        return false;
    }

    started_ = true;
    return true;
}

StopResult Netstack2::Stop() noexcept {
    return Stop(StopOptions{});
}

StopResult Netstack2::Stop(const StopOptions& options) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    StopResult result;
    if (runtime_) {
        result = runtime_->Stop(options);
        if (result.IsComplete()) {
            runtime_.reset();
        }
    }
    if (result.IsComplete()) started_ = false;
    return result;
}

bool Netstack2::IsRunning() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_ ? runtime_->IsRunning() : started_;
}

Runtime* Netstack2::GetRuntime() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_.get();
}

} // namespace tcpip2
