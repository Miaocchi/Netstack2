#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/pmtu.h>

using namespace tcpip2;

namespace {

/// IPv4 address 10.0.0.2 in network byte order.
static const std::uint8_t kIpv4Addr[4] = {0x0A, 0x00, 0x00, 0x02};

/// IPv6 address 2001:db8::1.
static const std::uint8_t kIpv6Addr[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x01
};

} // namespace

TCPIP2_TEST(LookupMissEmptyCache) {
    PmtuCache cache;
    auto r = cache.Lookup(kIpv4Addr, 4, 1000);
    TCPIP2_EXPECT_FALSE(r.found);
}

TCPIP2_TEST(RaiseThenLookupIpv4) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());

    auto r = cache.Lookup(kIpv4Addr, 4, 1000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r.pmtu);
}

TCPIP2_TEST(RaiseThenLookupIpv6) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, 1300, 5000);
    auto r = cache.Lookup(kIpv6Addr, 6, 5000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1300}, r.pmtu);
}

// --- Per-family clamp tests (via RaiseFromProbe) ---

TCPIP2_TEST(ClampBelowMinimumV4) {
    PmtuCache cache;
    // 100 < kPmtuMinV4 (576) → clamped to 576
    cache.RaiseFromProbe(kIpv4Addr, 4, 100, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV4, r.pmtu);
}

TCPIP2_TEST(ClampBelowMinimumV6) {
    PmtuCache cache;
    // 500 < kPmtuMinV6 (1280) → clamped to 1280
    cache.RaiseFromProbe(kIpv6Addr, 6, 500, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV6, r.pmtu);
}

TCPIP2_TEST(ClampZeroMtuV4) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 0, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV4, r.pmtu);
}

TCPIP2_TEST(ClampZeroMtuV6) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, 0, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV6, r.pmtu);
}

TCPIP2_TEST(ClampBelowV6MinButAboveV4Min) {
    // A value valid for IPv4 but below IPv6 minimum (e.g. 1000).
    // IPv4: 1000 ≥ 576 → stored as-is.
    // IPv6: 1000 < 1280 → clamped to 1280.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1000, 0);
    cache.RaiseFromProbe(kIpv6Addr, 6, 1000, 0);

    auto r4 = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r4.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1000}, r4.pmtu);

    auto r6 = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r6.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV6, r6.pmtu);
}

TCPIP2_TEST(ClampAtMaximumV4) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, kPmtuMaxV4, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV4, r.pmtu);
}

TCPIP2_TEST(ClampAtMaximumV6) {
    // IPv6 max is 65575 (40 + 65535), not 65535.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, kPmtuMaxV6, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV6, r.pmtu);
}

TCPIP2_TEST(ClampAtV6MinimumBoundary) {
    // Exactly 1280 → stored as-is (no clamping).
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, kPmtuMinV6, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV6, r.pmtu);
}

TCPIP2_TEST(ClampAtV4MinimumBoundary) {
    // Exactly 576 → stored as-is (no clamping).
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, kPmtuMinV4, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV4, r.pmtu);
}

TCPIP2_TEST(Clamp32BitMtuAboveV6Max) {
    // ICMPv6 PTB can report a 32-bit MTU. A value > 65575 should clamp to
    // kPmtuMaxV6, not truncate to the low 16 bits.
    // 70000 = 0x11170 → low 16 bits = 0x1170 = 4464 (wrong), clamped = 65575.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, 70000, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV6, r.pmtu);
}

TCPIP2_TEST(Clamp32BitMtuMuchAboveV4Max) {
    // 0x1FFFF = 131071 → clamped must be kPmtuMaxV4 (65535).
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 131071, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV4, r.pmtu);
}

// --- IPv6 max boundary: 65575 must be representable (not truncated to 65535) ---

TCPIP2_TEST(ClampV6MaxAboveUint16Range) {
    // 65575 > UINT16_MAX (65535). With uint32_t storage this must work.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, kPmtuMaxV6, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV6, r.pmtu);
    // Ensure we're not silently storing 65535.
    TCPIP2_EXPECT_NE(std::uint32_t{65535}, r.pmtu);
}

TCPIP2_TEST(ClampV6AboveMaxClampedTo65575) {
    // 70000 > 65575 → clamped to 65575, not 65535.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv6Addr, 6, 70000, 0);
    auto r = cache.Lookup(kIpv6Addr, 6, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV6, r.pmtu);
}

TCPIP2_TEST(ClampV4MaxAtBoundary) {
    // IPv4 65535 must not be clamped.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, kPmtuMaxV4, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV4, r.pmtu);
}

TCPIP2_TEST(ClampV4AboveMaxClampedTo65535) {
    // 70000 > 65535 → clamped to 65535.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 70000, 0);
    auto r = cache.Lookup(kIpv4Addr, 4, 0);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMaxV4, r.pmtu);
}

// --- Invalid input rejection ---

TCPIP2_TEST(RejectNullAddress) {
    PmtuCache cache;
    cache.RaiseFromProbe(nullptr, 4, 1400, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cache.Size());

    cache.LowerFromIcmp(nullptr, 6, 1300, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cache.Size());
}

TCPIP2_TEST(RejectInvalidIpVersion) {
    PmtuCache cache;
    // ip_version 5 is neither 4 nor 6 → should be rejected.
    cache.RaiseFromProbe(kIpv4Addr, 5, 1400, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cache.Size());

    cache.LowerFromIcmp(kIpv6Addr, 0, 1300, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cache.Size());
}

TCPIP2_TEST(RejectInvalidVersionDoesNotRead16BytesFromIpv4Buffer) {
    // If ip_version is not 4 or 6, NormalizeIp must reject before any memcpy.
    // This test ensures we don't read 16 bytes from a 4-byte buffer.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 7, 1400, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cache.Size());
}

TCPIP2_TEST(LookupRejectsInvalidVersion) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    // Lookup with invalid version must not find anything.
    auto r = cache.Lookup(kIpv4Addr, 7, 1000);
    TCPIP2_EXPECT_FALSE(r.found);
}

TCPIP2_TEST(LookupRejectsNullAddress) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    auto r = cache.Lookup(nullptr, 4, 1000);
    TCPIP2_EXPECT_FALSE(r.found);
}

// --- LowerFromIcmp: only decreases ---

TCPIP2_TEST(IcmpLowerDecreasesPmtu) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    cache.LowerFromIcmp(kIpv4Addr, 4, 1200, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1200}, r.pmtu);
}

TCPIP2_TEST(IcmpLowerDoesNotIncrease) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 1000);

    // ICMP reports a higher MTU — should be ignored.
    cache.LowerFromIcmp(kIpv4Addr, 4, 1500, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1200}, r.pmtu);
}

TCPIP2_TEST(IcmpLowerClampsBeforeComparing) {
    // Raw MTU 100 is below IPv4 minimum; clamp to 576.
    // If existing is 1400, 576 < 1400 → should lower to 576.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    cache.LowerFromIcmp(kIpv4Addr, 4, 100, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(kPmtuMinV4, r.pmtu);
}

TCPIP2_TEST(IcmpLowerIgnoresClampedAboveExisting) {
    // Raw MTU 70000 clamps to 65535. If existing is 1400,
    // 65535 > 1400 → ICMP path should NOT raise.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    cache.LowerFromIcmp(kIpv4Addr, 4, 70000, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r.pmtu);
}

TCPIP2_TEST(IcmpLowerOnNewEntry) {
    // LowerFromIcmp on a non-existing entry should insert it.
    PmtuCache cache;
    cache.LowerFromIcmp(kIpv4Addr, 4, 1200, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());

    auto r = cache.Lookup(kIpv4Addr, 4, 1000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1200}, r.pmtu);
}

// --- RaiseFromProbe: only increases ---

TCPIP2_TEST(RaiseIncreasesPmtu) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 1000);

    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r.pmtu);
}

TCPIP2_TEST(RaiseDoesNotDecrease) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    // Probe reports a lower MTU — should be ignored.
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r.pmtu);
}

TCPIP2_TEST(RaiseClampsBeforeComparing) {
    // Raw MTU 100 clamps to 576. If existing is 1400,
    // 576 < 1400 → probe path should NOT lower.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    cache.RaiseFromProbe(kIpv4Addr, 4, 100, 2000);
    auto r = cache.Lookup(kIpv4Addr, 4, 2000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r.pmtu);
}

// --- IPv4-mapped address distinctness ---

TCPIP2_TEST(Ipv4MappedAddressDistinctFromIpv6) {
    // An IPv4 address 10.0.0.2 and an IPv6 address whose last 4 bytes
    // happen to be 0x0A000002 must be stored as separate entries.
    PmtuCache cache;
    std::uint8_t v6_looks_like_v4[16] = {};
    v6_looks_like_v4[12] = 0x0A;
    v6_looks_like_v4[13] = 0x00;
    v6_looks_like_v4[14] = 0x00;
    v6_looks_like_v4[15] = 0x02;

    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);
    cache.RaiseFromProbe(v6_looks_like_v4, 6, 1300, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{2}, cache.Size());

    auto r4 = cache.Lookup(kIpv4Addr, 4, 1000);
    TCPIP2_EXPECT_TRUE(r4.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r4.pmtu);

    auto r6 = cache.Lookup(v6_looks_like_v4, 6, 1000);
    TCPIP2_EXPECT_TRUE(r6.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1300}, r6.pmtu);
}

// --- Expiry ---

TCPIP2_TEST(LookupExpiredEntry) {
    PmtuCache cache;
    // expires_ms defaults to kPmtuDefaultTtlMs (600000).
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);

    // Just before expiry: found.
    auto r_ok = cache.Lookup(kIpv4Addr, 4, 1000 + kPmtuDefaultTtlMs);
    TCPIP2_EXPECT_TRUE(r_ok.found);

    // One ms past expiry: not found.
    auto r_exp = cache.Lookup(kIpv4Addr, 4, 1000 + kPmtuDefaultTtlMs + 1);
    TCPIP2_EXPECT_FALSE(r_exp.found);
}

TCPIP2_TEST(CustomExpiry) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000, 5000);

    // At exactly 5000 ms later: still valid (now - ts == expires → not > expires).
    auto r_ok = cache.Lookup(kIpv4Addr, 4, 6000);
    TCPIP2_EXPECT_TRUE(r_ok.found);

    // 5001 ms later: expired.
    auto r_exp = cache.Lookup(kIpv4Addr, 4, 6001);
    TCPIP2_EXPECT_FALSE(r_exp.found);
}

TCPIP2_TEST(PurgeRemovesExpired) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000, 5000);
    cache.RaiseFromProbe(kIpv6Addr, 6, 1300, 1000, 10000);

    TCPIP2_EXPECT_EQ(std::size_t{2}, cache.Size());

    // At t=6001: IPv4 entry (TTL 5000) expired, IPv6 entry (TTL 10000) still valid.
    std::size_t removed = cache.Purge(6001);
    TCPIP2_EXPECT_EQ(std::size_t{1}, removed);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());

    // IPv6 should still be findable.
    auto r = cache.Lookup(kIpv6Addr, 6, 6001);
    TCPIP2_EXPECT_TRUE(r.found);
}

TCPIP2_TEST(PurgeNoneExpired) {
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);
    std::size_t removed = cache.Purge(1100);
    TCPIP2_EXPECT_EQ(std::size_t{0}, removed);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());
}

// --- Oldest-update eviction ---

TCPIP2_TEST(EvictOldestWhenFull) {
    PmtuCache cache(2);
    // First entry at t=1000.
    std::uint8_t ip_a[4] = {10, 0, 0, 1};
    cache.RaiseFromProbe(ip_a, 4, 1400, 1000);

    // Second entry at t=2000 (newer).
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 2000); // 10.0.0.2
    TCPIP2_EXPECT_EQ(std::size_t{2}, cache.Size());

    // Third entry at t=3000: cache is full; oldest (ip_a at t=1000) should be evicted.
    std::uint8_t ip_c[4] = {10, 0, 0, 3};
    cache.RaiseFromProbe(ip_c, 4, 1400, 3000);
    TCPIP2_EXPECT_EQ(std::size_t{2}, cache.Size());

    // ip_a should be gone.
    auto r_a = cache.Lookup(ip_a, 4, 3000);
    TCPIP2_EXPECT_FALSE(r_a.found);

    // ip_c and kIpv4Addr should be present.
    auto r_c = cache.Lookup(ip_c, 4, 3000);
    TCPIP2_EXPECT_TRUE(r_c.found);
    auto r_b = cache.Lookup(kIpv4Addr, 4, 3000);
    TCPIP2_EXPECT_TRUE(r_b.found);
}

TCPIP2_TEST(ZeroMaxEntriesTreatedAsOne) {
    // A max_entries of 0 would break eviction; constructor should guard it.
    PmtuCache cache(0);
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());

    std::uint8_t ip_b[4] = {10, 0, 0, 3};
    cache.RaiseFromProbe(ip_b, 4, 1400, 2000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());
}

TCPIP2_TEST(MaxEntriesCappedAtLimit) {
    // Requesting more than kPmtuMaxEntries should be capped, not crash.
    PmtuCache cache(kPmtuMaxEntries + 100);
    // Just verify it constructs and can hold at least one entry.
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, cache.Size());
}

// --- Expired entry reinitialisation ---

TCPIP2_TEST(ExpiredEntryTreatedAsNewOnLower) {
    // An expired entry should not block a LowerFromIcmp update.
    // Set PMTU to 1400 with TTL=5000 at t=1000.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000, 5000);

    // At t=7000 the entry is expired (1000 + 5000 < 7000).
    // LowerFromIcmp with 1300 should reinitialise the entry, not be
    // blocked by the expired pmtu=1400.
    cache.LowerFromIcmp(kIpv4Addr, 4, 1300, 7000, 5000);
    auto r = cache.Lookup(kIpv4Addr, 4, 7000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1300}, r.pmtu);
}

TCPIP2_TEST(ExpiredEntryTreatedAsNewOnRaise) {
    // An expired entry should not block a RaiseFromProbe update.
    // Set PMTU to 1200 with TTL=5000 at t=1000.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 1000, 5000);

    // At t=7000 the entry is expired.
    // RaiseFromProbe with 1500 should reinitialise the entry, not be
    // blocked by the expired pmtu=1200.
    cache.RaiseFromProbe(kIpv4Addr, 4, 1500, 7000, 5000);
    auto r = cache.Lookup(kIpv4Addr, 4, 7000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1500}, r.pmtu);
}

TCPIP2_TEST(ExpiredEntryRaiseWithLowerValueReinitialises) {
    // Even if the new value is lower than the expired entry's value,
    // an expired entry should be reinitialised by RaiseFromProbe.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1500, 1000, 5000);

    // At t=7000 the entry is expired. RaiseFromProbe with 1200 (lower)
    // would be ignored if the entry were fresh, but since it's expired,
    // it should reinitialise to 1200.
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 7000, 5000);
    auto r = cache.Lookup(kIpv4Addr, 4, 7000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1200}, r.pmtu);
}

TCPIP2_TEST(ExpiredEntryLowerWithHigherValueReinitialises) {
    // Even if the new value is higher than the expired entry's value,
    // an expired entry should be reinitialised by LowerFromIcmp.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 1000, 5000);

    // At t=7000 the entry is expired. LowerFromIcmp with 1400 (higher)
    // would be ignored if the entry were fresh, but since it's expired,
    // it should reinitialise to 1400.
    cache.LowerFromIcmp(kIpv4Addr, 4, 1400, 7000, 5000);
    auto r = cache.Lookup(kIpv4Addr, 4, 7000);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1400}, r.pmtu);
}

// --- Clock rollback guard ---

TCPIP2_TEST(ClockRolloverLookupExpired) {
    // If now_ms < timestamp_ms (clock rollback), the entry should be
    // treated as expired by Lookup.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000, 600000);

    // now_ms = 500 < timestamp_ms = 1000 → expired.
    auto r = cache.Lookup(kIpv4Addr, 4, 500);
    TCPIP2_EXPECT_FALSE(r.found);
}

TCPIP2_TEST(ClockRolloverPurgeExpired) {
    // If now_ms < timestamp_ms, Purge should remove the entry.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000, 600000);

    // now_ms = 500 < timestamp_ms = 1000 → expired, should be purged.
    std::size_t removed = cache.Purge(500);
    TCPIP2_EXPECT_EQ(std::size_t{1}, removed);
    TCPIP2_EXPECT_EQ(std::size_t{0}, cache.Size());
}

TCPIP2_TEST(ClockRolloverLowerTreatedAsExpired) {
    // If now_ms < timestamp_ms, LowerFromIcmp should treat the existing
    // entry as expired and reinitialise it.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1400, 1000, 600000);

    // now_ms = 500 < timestamp_ms = 1000 → existing entry is expired.
    // LowerFromIcmp with 1300 should reinitialise to 1300.
    cache.LowerFromIcmp(kIpv4Addr, 4, 1300, 500, 600000);
    // Lookup at now_ms=500 should still see it as expired (timestamp=500,
    // but clock is still rolled back relative to... well, we just set
    // timestamp_ms=500, so Lookup at now_ms=500 is fine).
    auto r = cache.Lookup(kIpv4Addr, 4, 500);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1300}, r.pmtu);
}

TCPIP2_TEST(ClockRolloverRaiseTreatedAsExpired) {
    // If now_ms < timestamp_ms, RaiseFromProbe should treat the existing
    // entry as expired and reinitialise it.
    PmtuCache cache;
    cache.RaiseFromProbe(kIpv4Addr, 4, 1200, 1000, 600000);

    // now_ms = 500 < timestamp_ms = 1000 → existing entry is expired.
    // RaiseFromProbe with 1500 should reinitialise to 1500.
    cache.RaiseFromProbe(kIpv4Addr, 4, 1500, 500, 600000);
    auto r = cache.Lookup(kIpv4Addr, 4, 500);
    TCPIP2_EXPECT_TRUE(r.found);
    TCPIP2_EXPECT_EQ(std::uint32_t{1500}, r.pmtu);
}

TCPIP2_TEST_MAIN();
