#include <ip/pmtu.h>

#include <cstring>
#include <new>
#include <vector>

namespace tcpip2 {

PmtuCache::PmtuCache(std::size_t max_entries) : max_entries_(max_entries == 0 ? 1 : max_entries) {
    if (max_entries_ > kPmtuMaxEntries) {
        max_entries_ = kPmtuMaxEntries;
    }
    // reserve may throw bad_alloc; let it propagate (constructor is not noexcept).
    // max_entries_ is capped at kPmtuMaxEntries so the allocation is bounded.
    entries_.reserve(max_entries_);
}

bool PmtuCache::ClampPmtu(std::uint32_t raw, std::uint8_t ip_version, std::uint32_t &out) noexcept {
    if (ip_version != 4 && ip_version != 6)
        return false;

    const std::uint32_t min_pmtu = (ip_version == 6) ? kPmtuMinV6 : kPmtuMinV4;
    const std::uint32_t max_pmtu = (ip_version == 6) ? kPmtuMaxV6 : kPmtuMaxV4;
    if (raw < min_pmtu)
        raw = min_pmtu;
    if (raw > max_pmtu)
        raw = max_pmtu;
    out = raw;
    return true;
}

bool PmtuCache::IsExpired(const PmtuEntry &e, std::uint64_t now_ms) noexcept {
    // Clock rollback guard: if now_ms < timestamp_ms, the entry is unreliable.
    // Treat it as expired so the caller reinitialises it.
    if (now_ms < e.timestamp_ms)
        return true;
    return (now_ms - e.timestamp_ms) > e.expires_ms;
}

bool PmtuCache::NormalizeIp(const std::uint8_t *dst_ip, std::uint8_t ip_version, std::uint8_t out[16]) noexcept {
    if (dst_ip == nullptr)
        return false;
    if (ip_version == 4) {
        // IPv4-mapped IPv6: ::ffff:a.b.c.d
        std::memset(out, 0, 10);
        out[10] = 0xFF;
        out[11] = 0xFF;
        std::memcpy(out + 12, dst_ip, 4);
        return true;
    }
    if (ip_version == 6) {
        std::memcpy(out, dst_ip, 16);
        return true;
    }
    return false;
}

PmtuEntry *PmtuCache::Find(const std::uint8_t normalized[16], std::uint8_t ip_version) noexcept {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].ip_version == ip_version && std::memcmp(entries_[i].dst_ip, normalized, 16) == 0) {
            return &entries_[i];
        }
    }
    return nullptr;
}

PmtuLookupResult PmtuCache::Lookup(const std::uint8_t *dst_ip, std::uint8_t ip_version,
                                   std::uint64_t now_ms) const noexcept {
    PmtuLookupResult result;

    std::uint8_t normalized[16];
    if (!NormalizeIp(dst_ip, ip_version, normalized))
        return result;

    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const PmtuEntry &e = entries_[i];
        if (e.ip_version != ip_version)
            continue;
        if (std::memcmp(e.dst_ip, normalized, 16) != 0)
            continue;

        // Expiry check: expired entries are not returned (Purge removes them).
        if (IsExpired(e, now_ms)) {
            return result;
        }

        result.found = true;
        result.pmtu = e.pmtu;
        return result;
    }
    return result;
}

void PmtuCache::InsertNew(const std::uint8_t normalized[16], std::uint8_t ip_version, std::uint32_t pmtu,
                          std::uint64_t now_ms, std::uint32_t expires_ms) noexcept {
    // Evict the oldest-update entry if the cache is full.
    if (entries_.size() >= max_entries_) {
        std::size_t oldest = 0;
        for (std::size_t i = 1; i < entries_.size(); ++i) {
            if (entries_[i].timestamp_ms < entries_[oldest].timestamp_ms) {
                oldest = i;
            }
        }
        entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(oldest));
    }

    PmtuEntry entry;
    std::memcpy(entry.dst_ip, normalized, 16);
    entry.ip_version = ip_version;
    entry.pmtu = pmtu;
    entry.timestamp_ms = now_ms;
    entry.expires_ms = expires_ms;
    entries_.push_back(entry);
}

void PmtuCache::LowerFromIcmp(const std::uint8_t *dst_ip, std::uint8_t ip_version, std::uint32_t pmtu,
                              std::uint64_t now_ms, std::uint32_t expires_ms) noexcept {
    std::uint32_t clamped;
    if (!ClampPmtu(pmtu, ip_version, clamped))
        return;

    std::uint8_t normalized[16];
    if (!NormalizeIp(dst_ip, ip_version, normalized))
        return;

    if (expires_ms == 0)
        expires_ms = kPmtuDefaultTtlMs;

    PmtuEntry *existing = Find(normalized, ip_version);
    if (existing != nullptr) {
        // If the existing entry has expired, treat it as a fresh entry.
        if (IsExpired(*existing, now_ms)) {
            existing->pmtu = clamped;
            existing->timestamp_ms = now_ms;
            existing->expires_ms = expires_ms;
            return;
        }
        // ICMP path: only decrease.
        if (clamped < existing->pmtu) {
            existing->pmtu = clamped;
            existing->timestamp_ms = now_ms;
            existing->expires_ms = expires_ms;
        }
        return;
    }

    InsertNew(normalized, ip_version, clamped, now_ms, expires_ms);
}

void PmtuCache::RaiseFromProbe(const std::uint8_t *dst_ip, std::uint8_t ip_version, std::uint32_t pmtu,
                               std::uint64_t now_ms, std::uint32_t expires_ms) noexcept {
    std::uint32_t clamped;
    if (!ClampPmtu(pmtu, ip_version, clamped))
        return;

    std::uint8_t normalized[16];
    if (!NormalizeIp(dst_ip, ip_version, normalized))
        return;

    if (expires_ms == 0)
        expires_ms = kPmtuDefaultTtlMs;

    PmtuEntry *existing = Find(normalized, ip_version);
    if (existing != nullptr) {
        // If the existing entry has expired, treat it as a fresh entry.
        if (IsExpired(*existing, now_ms)) {
            existing->pmtu = clamped;
            existing->timestamp_ms = now_ms;
            existing->expires_ms = expires_ms;
            return;
        }
        // Probe path: only increase.
        if (clamped > existing->pmtu) {
            existing->pmtu = clamped;
            existing->timestamp_ms = now_ms;
            existing->expires_ms = expires_ms;
        }
        return;
    }

    InsertNew(normalized, ip_version, clamped, now_ms, expires_ms);
}

std::size_t PmtuCache::Purge(std::uint64_t now_ms) noexcept {
    std::size_t removed = 0;
    std::size_t i = 0;
    while (i < entries_.size()) {
        if (IsExpired(entries_[i], now_ms)) {
            entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
            ++removed;
        } else {
            ++i;
        }
    }
    return removed;
}

std::size_t PmtuCache::Size() const noexcept { return entries_.size(); }

} // namespace tcpip2
