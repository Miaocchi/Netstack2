#pragma once

/**
 * @file pmtu.h
 * @brief Bounded PMTU (Path MTU) cache keyed by destination address.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>
#include <vector>

namespace tcpip2 {

/// PMTU bounds — per address family (RFC 1191 §7, RFC 8200 §5).
/// IPv4 minimum is 576 bytes per RFC 791; we use it as the floor for IPv4 paths.
/// IPv6 minimum is 1280 bytes per RFC 8200 §5; jumbograms are not supported.
/// IPv6 maximum is 65575 = 40 (fixed header) + 65535 (max payload length).
constexpr std::uint32_t kPmtuMinV4 = 576;    // RFC 791 IPv4 minimum
constexpr std::uint32_t kPmtuMinV6 = 1280;   // RFC 8200 IPv6 minimum
constexpr std::uint32_t kPmtuMaxV4 = 65535;   // IPv4 maximum packet size
constexpr std::uint32_t kPmtuMaxV6 = 65575;   // IPv6: 40 + 65535 (no jumbogram)
constexpr std::uint32_t kPmtuDefaultTtlMs = 600000; // 10 minutes

/// Maximum number of entries a PmtuCache may hold.
/// Caps memory and avoids unbounded allocation in the constructor.
constexpr std::size_t kPmtuMaxEntries = 4096;

/// A PMTU cache entry.
struct PmtuEntry {
    std::uint8_t dst_ip[16] = {};    // destination IP (IPv4-mapped for v4)
    std::uint8_t ip_version = 0;     // 4 or 6
    std::uint32_t pmtu = 0;          // discovered path MTU
    std::uint64_t timestamp_ms = 0;  // when set (monotonic clock)
    std::uint32_t expires_ms = kPmtuDefaultTtlMs; // TTL for this entry
};

/// Result of a PMTU lookup.
struct PmtuLookupResult {
    bool found = false;
    std::uint32_t pmtu = 0;
};

/// A bounded PMTU cache. Not thread-safe — callers must synchronize.
/// Uses linear search (entries list is small, typically < 64).
/// Eviction policy is oldest-update (the entry with the smallest timestamp_ms
/// is evicted when the cache is full).  This is not strict LRU: Lookup does not
/// refresh the timestamp.
class PmtuCache {
public:
    /// @param max_entries maximum number of entries (bounded to [1, kPmtuMaxEntries])
    explicit PmtuCache(std::size_t max_entries = 64);

    /// Look up PMTU for a destination. Returns {found=false} if not cached or expired.
    /// @param now_ms current monotonic time in milliseconds
    PmtuLookupResult Lookup(const std::uint8_t* dst_ip, std::uint8_t ip_version,
                            std::uint64_t now_ms) const noexcept;

    /// Lower the PMTU for a destination via an ICMP error (e.g. Packet Too Big).
    /// Only decreases: the stored PMTU becomes min(existing, clamped candidate).
    /// Uses the ICMP-reported MTU (32-bit, as in ICMPv6 PTB) before clamping to
    /// per-family bounds.  Does nothing if the address is null, ip_version is
    /// not 4 or 6, or the candidate (after clamping) is ≥ the existing value.
    /// If the cache is full and the entry doesn't exist, evicts the oldest entry.
    /// @param now_ms current monotonic time in milliseconds
    /// @param pmtu the MTU reported by ICMP (will be clamped per address family)
    /// @param expires_ms TTL for this entry (0 = use default)
    void LowerFromIcmp(const std::uint8_t* dst_ip, std::uint8_t ip_version,
                       std::uint32_t pmtu, std::uint64_t now_ms,
                       std::uint32_t expires_ms = 0) noexcept;

    /// Raise the PMTU for a destination after successful probe / discovery.
    /// Only increases: the stored PMTU becomes max(existing, clamped candidate).
    /// If the cache is full and the entry doesn't exist, evicts the oldest entry.
    /// @param now_ms current monotonic time in milliseconds
    /// @param pmtu the discovered path MTU (will be clamped per address family)
    /// @param expires_ms TTL for this entry (0 = use default)
    void RaiseFromProbe(const std::uint8_t* dst_ip, std::uint8_t ip_version,
                        std::uint32_t pmtu, std::uint64_t now_ms,
                        std::uint32_t expires_ms = 0) noexcept;

    /// Remove expired entries. Returns number of entries removed.
    std::size_t Purge(std::uint64_t now_ms) noexcept;

    /// Current number of entries.
    std::size_t Size() const noexcept;

private:
    /// Clamp a raw 32-bit MTU to per-family bounds.
    /// Returns false if ip_version is invalid (not 4 or 6).
    static bool ClampPmtu(std::uint32_t raw, std::uint8_t ip_version,
                          std::uint32_t& out) noexcept;

    /// Check whether an entry has expired at time now_ms.
    /// Handles clock rollback: if now_ms < timestamp_ms, the entry is
    /// considered expired (the stored timestamp is unreliable).
    static bool IsExpired(const PmtuEntry& e, std::uint64_t now_ms) noexcept;

    /// Normalize a caller-supplied address into the 16-byte internal form.
    /// Returns false if ip_version is not 4 or 6, or if dst_ip is null.
    static bool NormalizeIp(const std::uint8_t* dst_ip, std::uint8_t ip_version,
                            std::uint8_t out[16]) noexcept;

    /// Find the entry matching the normalized address and version.
    /// Returns a pointer to the entry, or nullptr if not found.
    PmtuEntry* Find(const std::uint8_t normalized[16], std::uint8_t ip_version) noexcept;

    /// Insert a new entry, evicting the oldest-update entry if the cache is full.
    void InsertNew(const std::uint8_t normalized[16], std::uint8_t ip_version,
                   std::uint32_t pmtu, std::uint64_t now_ms,
                   std::uint32_t expires_ms) noexcept;

    std::vector<PmtuEntry> entries_;
    std::size_t max_entries_;
};

} // namespace tcpip2
