/**
 * @file netstack.cpp
 * @brief Netstack2 facade implementation.
 * @license GPL-3.0
 *
 * Start() validates the config and (when a packet I/O is provided) starts
 * the Runtime, which creates per-shard buffer pools internally (ADR-001).
 * Stop() tears down the Runtime. The facade no longer owns a pool directly;
 * pool lifetime is managed by the Runtime.
 */

#include <tcpip2/netstack.h>

#include <memory>
#include <utility>

#include <core/runtime.h>

namespace tcpip2 {

Netstack2::Netstack2(NetstackConfig config) noexcept
    : config_(config) {}

Netstack2::~Netstack2() {
    Stop();
}

bool Netstack2::Start(IPacketIo* packet_io) noexcept {
    if (started_) return true;
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

void Netstack2::Stop() noexcept {
    if (runtime_) {
        runtime_->Stop();
        runtime_.reset();
    }
    started_ = false;
}

} // namespace tcpip2
