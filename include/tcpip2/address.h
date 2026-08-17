#pragma once

/**
 * @file address.h
 * @brief IPv4/IPv6 address abstraction for the Netstack2 flow model.
 * @license GPL-3.0
 *
 * Public API — frozen at NETSTACK2-API-FREEZE-001. Signature changes
 * require an ADR and a consumer compile-contract test update.
 *
 * Used by FlowKey to identify endpoints across the dispatcher and shard
 * layers. IPv4 addresses use the first 4 bytes of the internal storage;
 * IPv6 uses all 16.
 */

#include <array>
#include <cstdint>
#include <cstring>

namespace tcpip2 {

class IpAddress {
  public:
    enum class Family { Ipv4, Ipv6 };

    IpAddress() noexcept = default; // default: IPv4 0.0.0.0

    static IpAddress Ipv4(std::uint32_t addr) noexcept {
        IpAddress ip;
        ip.family_ = Family::Ipv4;
        // Store in network byte order: big-endian in bytes.
        ip.bytes_[0] = static_cast<std::uint8_t>((addr >> 24) & 0xFF);
        ip.bytes_[1] = static_cast<std::uint8_t>((addr >> 16) & 0xFF);
        ip.bytes_[2] = static_cast<std::uint8_t>((addr >> 8) & 0xFF);
        ip.bytes_[3] = static_cast<std::uint8_t>(addr & 0xFF);
        return ip;
    }

    static IpAddress Ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
        IpAddress ip;
        ip.family_ = Family::Ipv4;
        ip.bytes_[0] = a;
        ip.bytes_[1] = b;
        ip.bytes_[2] = c;
        ip.bytes_[3] = d;
        return ip;
    }

    static IpAddress Ipv6(const std::uint8_t bytes[16]) noexcept {
        IpAddress ip;
        ip.family_ = Family::Ipv6;
        std::memcpy(ip.bytes_.data(), bytes, 16);
        return ip;
    }

    Family family() const noexcept { return family_; }
    bool IsIpv4() const noexcept { return family_ == Family::Ipv4; }
    bool IsIpv6() const noexcept { return family_ == Family::Ipv6; }

    const std::uint8_t *Bytes() const noexcept { return bytes_.data(); }
    std::size_t ByteCount() const noexcept { return family_ == Family::Ipv4 ? 4 : 16; }

    bool operator==(const IpAddress &o) const noexcept {
        if (family_ != o.family_)
            return false;
        const std::size_t n = ByteCount();
        return std::memcmp(bytes_.data(), o.bytes_.data(), n) == 0;
    }

    bool operator!=(const IpAddress &o) const noexcept { return !(*this == o); }

    bool operator<(const IpAddress &o) const noexcept {
        if (family_ != o.family_)
            return family_ < o.family_;
        const std::size_t n = ByteCount();
        return std::memcmp(bytes_.data(), o.bytes_.data(), n) < 0;
    }

  private:
    Family family_ = Family::Ipv4;
    std::array<std::uint8_t, 16> bytes_ = {};
};

} // namespace tcpip2
