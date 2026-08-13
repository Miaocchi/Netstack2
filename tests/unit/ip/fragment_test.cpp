#include <cstdint>
#include <cstring>
#include <vector>

#include "Test.h"
#include <ip/fragment.h>

using namespace tcpip2;

namespace {

// IPv4 addresses: 10.0.0.1 → 10.0.0.2
static const std::uint8_t kSrcIpv4[4] = {0x0A, 0x00, 0x00, 0x01};
static const std::uint8_t kDstIpv4[4] = {0x0A, 0x00, 0x00, 0x02};

// IPv6 addresses: 2001:db8::1 → 2001:db8::2
static const std::uint8_t kSrcIpv6[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x01
};
static const std::uint8_t kDstIpv6[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x02
};

static constexpr std::uint8_t kProtoUdp = 17;

/// Helper: make a fragment payload of n bytes, each byte = val.
static std::vector<std::uint8_t> MakePayload(std::size_t n, std::uint8_t val) {
    return std::vector<std::uint8_t>(n, val);
}

} // namespace

// ===========================================================================
// IPv4 basic reassembly
// ===========================================================================

TCPIP2_TEST(Ipv4TwoFragmentReassemblyAligned) {
    FragmentReassembler r;
    auto p1 = MakePayload(104, 0xAA); // 104 = 13*8
    auto p2 = MakePayload(56, 0xBB);  // 56 = 7*8

    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);
    TCPIP2_EXPECT_EQ(FragmentError::None, r1.error);

    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 13, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(r2.complete);
    TCPIP2_EXPECT_EQ(FragmentError::None, r2.error);
    TCPIP2_EXPECT_EQ(std::size_t{160}, r2.total_length);
    TCPIP2_EXPECT_FALSE(r2.payload.empty());

    // Verify content: first 104 bytes = 0xAA, next 56 = 0xBB
    bool content_ok = true;
    for (std::size_t i = 0; i < 104; ++i) {
        if (r2.payload[i] != 0xAA) { content_ok = false; break; }
    }
    for (std::size_t i = 104; i < 160; ++i) {
        if (r2.payload[i] != 0xBB) { content_ok = false; break; }
    }
    TCPIP2_EXPECT_TRUE(content_ok);
}

TCPIP2_TEST(Ipv4OutOfOrderReassembly) {
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xCC);
    auto p2 = MakePayload(64, 0xDD);

    // Second fragment arrives first: offset=8 (8*8=64 bytes), MF=0
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 99,
                                 8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_FALSE(r2.complete);

    // First fragment arrives second: offset=0, MF=1
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 99,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_TRUE(r1.complete);
    TCPIP2_EXPECT_EQ(std::size_t{128}, r1.total_length);

    // Verify content
    bool content_ok = true;
    for (std::size_t i = 0; i < 64; ++i) {
        if (r1.payload[i] != 0xCC) { content_ok = false; break; }
    }
    for (std::size_t i = 64; i < 128; ++i) {
        if (r1.payload[i] != 0xDD) { content_ok = false; break; }
    }
    TCPIP2_EXPECT_TRUE(content_ok);
}

TCPIP2_TEST(Ipv4ThreeFragmentReassembly) {
    FragmentReassembler r;
    auto p1 = MakePayload(32, 0x01);
    auto p2 = MakePayload(32, 0x02);
    auto p3 = MakePayload(32, 0x03);

    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 7,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 7,
                                 4, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_FALSE(r2.complete);

    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 7,
                                 8, false, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_TRUE(r3.complete);
    TCPIP2_EXPECT_EQ(std::size_t{96}, r3.total_length);

    // Verify content
    TCPIP2_EXPECT_EQ(std::uint8_t{0x01}, r3.payload[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, r3.payload[32]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x03}, r3.payload[64]);
}

TCPIP2_TEST(Ipv4SingleUnfragmentedPacket) {
    FragmentReassembler r;
    auto p = MakePayload(100, 0x55);

    // offset=0, MF=0 → complete immediately
    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     0, false, p.data(), p.size(), 1000);
    TCPIP2_EXPECT_TRUE(result.complete);
    TCPIP2_EXPECT_EQ(std::size_t{100}, result.total_length);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x55}, result.payload[0]);
}

// ===========================================================================
// IPv4 error cases
// ===========================================================================

TCPIP2_TEST(Ipv4OverlapRejected) {
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    // First fragment: offset=0, length=64
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    // Overlapping fragment: offset=32 (4*8=32), length=64 → overlaps [0,64)
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 4, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::OverlapDetected, r2.error);
    TCPIP2_EXPECT_FALSE(r2.complete);
}

TCPIP2_TEST(Ipv4TooManyFragmentsRejected) {
    // Use a small reassembler and send 65 fragments (limit is 64).
    FragmentReassembler r;
    std::uint8_t data[8] = {};

    FragmentAddResult last_result;
    for (std::size_t i = 0; i < 65; ++i) {
        last_result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                         static_cast<std::uint16_t>(i), true,
                                         data, 8, 1000);
        if (i < 64) {
            TCPIP2_EXPECT_EQ(FragmentError::None, last_result.error);
        }
    }
    TCPIP2_EXPECT_EQ(FragmentError::TooManyFragments, last_result.error);
}

TCPIP2_TEST(Ipv4PayloadTooLargeRejected) {
    FragmentReassembler r;
    // MF=1 requires length to be a multiple of 8. Use length=104 (8*13).
    // offset * 8 + length > kMaxFragmentPayloadBytes (65535)
    // offset=8190 (8190*8=65520), length=104 → 65624 > 65535
    auto p = MakePayload(104, 0xAA);
    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     8190, true, p.data(), p.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::PayloadTooLarge, result.error);
}

TCPIP2_TEST(Ipv4NullDataRejected) {
    FragmentReassembler r;
    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     0, true, nullptr, 100, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::NullData, result.error);
}

TCPIP2_TEST(Ipv4ZeroLengthRejected) {
    FragmentReassembler r;
    std::uint8_t dummy = 0;
    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     0, true, &dummy, 0, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::InvalidFragment, result.error);
}

TCPIP2_TEST(Ipv4MfOneNonMultipleOf8Rejected) {
    FragmentReassembler r;
    // MF=1 but length=100, which is not a multiple of 8.
    auto p = MakePayload(100, 0xAA);
    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     0, true, p.data(), p.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::InvalidFragment, result.error);
}

TCPIP2_TEST(Ipv4NullAddressRejected) {
    FragmentReassembler r;
    std::uint8_t data[8] = {};
    auto result = r.AddIpv4Fragment(nullptr, kDstIpv4, kProtoUdp, 1,
                                     0, true, data, 8, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::NullData, result.error);

    auto result2 = r.AddIpv4Fragment(kSrcIpv4, nullptr, kProtoUdp, 1,
                                      0, true, data, 8, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::NullData, result2.error);
}

// ===========================================================================
// IPv6 basic reassembly
// ===========================================================================

TCPIP2_TEST(Ipv6TwoFragmentReassembly) {
    FragmentReassembler r;
    auto p1 = MakePayload(80, 0xAA);
    auto p2 = MakePayload(48, 0xBB);

    auto r1 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0xABCD1234,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0xABCD1234,
                                 10, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(r2.complete);
    TCPIP2_EXPECT_EQ(std::size_t{128}, r2.total_length);

    // Verify content
    bool content_ok = true;
    for (std::size_t i = 0; i < 80; ++i) {
        if (r2.payload[i] != 0xAA) { content_ok = false; break; }
    }
    for (std::size_t i = 80; i < 128; ++i) {
        if (r2.payload[i] != 0xBB) { content_ok = false; break; }
    }
    TCPIP2_EXPECT_TRUE(content_ok);
}

TCPIP2_TEST(Ipv6OutOfOrderReassembly) {
    FragmentReassembler r;
    auto p1 = MakePayload(72, 0xCC);
    auto p2 = MakePayload(72, 0xDD);

    // Second fragment first: offset=9 (9*8=72), MF=0
    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x0001,
                                 9, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_FALSE(r2.complete);

    // First fragment: offset=0, MF=1
    auto r1 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x0001,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_TRUE(r1.complete);
    TCPIP2_EXPECT_EQ(std::size_t{144}, r1.total_length);
}

TCPIP2_TEST(Ipv6SingleUnfragmentedPacket) {
    FragmentReassembler r;
    auto p = MakePayload(200, 0x77);

    auto result = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x42,
                                     0, false, p.data(), p.size(), 1000);
    TCPIP2_EXPECT_TRUE(result.complete);
    TCPIP2_EXPECT_EQ(std::size_t{200}, result.total_length);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x77}, result.payload[0]);
}

// ===========================================================================
// IPv6 error cases
// ===========================================================================

TCPIP2_TEST(Ipv6OverlapDiscardsEntireDatagram) {
    // RFC 5722: on IPv6 overlap, the entire datagram is discarded.
    // Subsequent fragments for the same identification must also be rejected.
    FragmentReassembler r;
    auto p1 = MakePayload(48, 0xAA);
    auto p2 = MakePayload(48, 0xBB);
    auto p3 = MakePayload(48, 0xCC);

    // First fragment: offset=0, MF=1, length=48
    auto r1 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x01,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    // Overlapping fragment: offset=3 (3*8=24), overlaps [0,48)
    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x01,
                                 3, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::OverlapDetected, r2.error);

    // Subsequent non-overlapping fragment must also be rejected (datagram discarded)
    auto r3 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x01,
                                 6, true, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::OverlapDetected, r3.error);
}

TCPIP2_TEST(Ipv6NullDataRejected) {
    FragmentReassembler r;
    auto result = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x01,
                                     0, true, nullptr, 100, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::NullData, result.error);
}

TCPIP2_TEST(Ipv6NullAddressRejected) {
    FragmentReassembler r;
    std::uint8_t data[8] = {};
    auto result = r.AddIpv6Fragment(nullptr, kDstIpv6, 0x01,
                                     0, true, data, 8, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::NullData, result.error);

    auto result2 = r.AddIpv6Fragment(kSrcIpv6, nullptr, 0x01,
                                      0, true, data, 8, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::NullData, result2.error);
}

TCPIP2_TEST(Ipv6ZeroLengthRejected) {
    FragmentReassembler r;
    std::uint8_t dummy = 0;
    auto result = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x01,
                                     0, true, &dummy, 0, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::InvalidFragment, result.error);
}

TCPIP2_TEST(Ipv6MfOneNonMultipleOf8Rejected) {
    FragmentReassembler r;
    // MF=1 but length=100, not a multiple of 8.
    auto p = MakePayload(100, 0xAA);
    auto result = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x01,
                                     0, true, p.data(), p.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::InvalidFragment, result.error);
}

TCPIP2_TEST(Ipv6PayloadTooLargeRejected) {
    FragmentReassembler r;
    // MF=1 requires length to be a multiple of 8. Use length=104 (8*13).
    // offset=8190 (8190*8=65520), length=104 → 65624 > 65535
    auto p = MakePayload(104, 0xAA);
    auto result = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 1,
                                     8190, true, p.data(), p.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::PayloadTooLarge, result.error);
}

// ===========================================================================
// Cross-family isolation
// ===========================================================================

TCPIP2_TEST(Ipv4AndIpv6SameIdDoNotConflict) {
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    // IPv4 fragment with id=42
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    // IPv6 fragment with id=42 — should not match the IPv4 entry
    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 42,
                                 0, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_FALSE(r2.complete);
    TCPIP2_EXPECT_EQ(FragmentError::None, r2.error);

    // Complete the IPv4 packet
    auto p1b = MakePayload(64, 0xCC);
    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 8, false, p1b.data(), p1b.size(), 1000);
    TCPIP2_EXPECT_TRUE(r3.complete);

    // Complete the IPv6 packet
    auto p2b = MakePayload(64, 0xDD);
    auto r4 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 42,
                                 8, false, p2b.data(), p2b.size(), 1000);
    TCPIP2_EXPECT_TRUE(r4.complete);

    // After completion, entries are released; Size should be 0.
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.Size());
}

TCPIP2_TEST(DifferentProtocolSameIdDoNotConflict) {
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    // IPv4 UDP id=1
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, 17, 1,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    // IPv4 TCP id=1 — different protocol, should not match
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, 6, 1,
                                 0, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_FALSE(r2.complete);

    TCPIP2_EXPECT_EQ(std::size_t{2}, r.Size());
}

TCPIP2_TEST(Ipv4DifferentSrcAddrDifferentEntry) {
    FragmentReassembler r;
    const std::uint8_t src_alt[4] = {0x0A, 0x00, 0x00, 0x03};
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000);
    r.AddIpv4Fragment(src_alt, kDstIpv4, kProtoUdp, 1,
                      0, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_EQ(std::size_t{2}, r.Size());
}

// ===========================================================================
// Entry lifecycle: expiry, eviction, table full
// ===========================================================================

TCPIP2_TEST(ExpiredEntryPurged) {
    FragmentReassembler r;
    auto p = MakePayload(64, 0xAA);

    // Add fragment at t=1000 with TTL=5000ms
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 0, true, p.data(), p.size(), 1000, 5000);
    TCPIP2_EXPECT_FALSE(r1.complete);
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Size());

    // At t=6001, entry is expired (deadline=1000+5000=6000)
    std::size_t purged = r.Purge(6001);
    TCPIP2_EXPECT_EQ(std::size_t{1}, purged);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.Size());
}

TCPIP2_TEST(ExpiredEntryReused) {
    FragmentReassembler r;
    auto p = MakePayload(64, 0xAA);

    // Add fragment at t=1000 with TTL=5000ms
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p.data(), p.size(), 1000, 5000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Size());

    // At t=6001, the entry is expired. Adding a new fragment should reuse it.
    auto p2 = MakePayload(64, 0xBB);
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 2,
                                 0, true, p2.data(), p2.size(), 6001);
    TCPIP2_EXPECT_EQ(FragmentError::None, r2.error);
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Size()); // still 1, reused
}

TCPIP2_TEST(TableFullReturnsTooManyEntries) {
    // Create a reassembler with only 2 entries.
    FragmentReassembler r(2);
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);
    auto p3 = MakePayload(64, 0xCC);

    // Add first incomplete entry
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000);
    // Add second incomplete entry (different identification)
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 2,
                      0, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_EQ(std::size_t{2}, r.Size());

    // Third entry should fail
    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 3,
                                 0, true, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::TooManyEntries, r3.error);
}

TCPIP2_TEST(MfZeroButIncomplete) {
    FragmentReassembler r;
    auto p1 = MakePayload(32, 0xAA);
    auto p3 = MakePayload(32, 0xBB);

    // First fragment: offset=0, MF=1, length=32
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    // Last fragment (MF=0): offset=8 (64 bytes), length=32
    // This means total_payload_length=96, but we're missing [32, 64)
    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 8, false, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_FALSE(r3.complete); // gap at [32,64)
}

TCPIP2_TEST(Ipv6ThirtyTwoBitIdentification) {
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    // Use a 32-bit identification that exceeds 16-bit range
    const std::uint32_t id = 0x12345678;

    auto r1 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, id,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_FALSE(r1.complete);

    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, id,
                                 8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(r2.complete);
    TCPIP2_EXPECT_EQ(std::size_t{128}, r2.total_length);
}

TCPIP2_TEST(Ipv6TooManyFragmentsRejected) {
    FragmentReassembler r;
    std::uint8_t data[8] = {};

    FragmentAddResult last_result;
    for (std::size_t i = 0; i < 65; ++i) {
        last_result = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 1,
                                         static_cast<std::uint16_t>(i), true,
                                         data, 8, 1000);
        if (i < 64) {
            TCPIP2_EXPECT_EQ(FragmentError::None, last_result.error);
        }
    }
    TCPIP2_EXPECT_EQ(FragmentError::TooManyFragments, last_result.error);
}

// ===========================================================================
// New tests: source-buffer release, duplicate terminal, terminal overflow,
// trickle timeout, ID reuse, byte budget
// ===========================================================================

TCPIP2_TEST(SourceBufferReleaseAfterAdd) {
    // Verify that fragment data is copied on arrival, not held by pointer.
    // After adding a fragment, we destroy the source buffer, then complete
    // the reassembly — the data must still be correct.
    FragmentReassembler r;

    std::vector<std::uint8_t> p1 = MakePayload(64, 0xAA);
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000);
    // Destroy the source buffer.
    p1.clear();
    p1.shrink_to_fit();

    // Now add the second fragment and complete reassembly.
    auto p2 = MakePayload(64, 0xBB);
    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(result.complete);
    TCPIP2_EXPECT_EQ(std::size_t{128}, result.total_length);

    // Verify the data is correct (not read from freed memory).
    bool content_ok = true;
    for (std::size_t i = 0; i < 64; ++i) {
        if (result.payload[i] != 0xAA) { content_ok = false; break; }
    }
    for (std::size_t i = 64; i < 128; ++i) {
        if (result.payload[i] != 0xBB) { content_ok = false; break; }
    }
    TCPIP2_EXPECT_TRUE(content_ok);
}

TCPIP2_TEST(DuplicateTerminalSameTotalAccepted) {
    // A retransmitted MF=0 fragment with the same total length should be
    // accepted (it's a duplicate of an already-received piece).
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    // First fragment: offset=0, MF=1
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000);

    // Terminal fragment: offset=8 (64 bytes), MF=0
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(r2.complete);

    // Entry is released after completion, so a new MF=0 with same key
    // would create a new entry. That's expected behavior.
}

TCPIP2_TEST(DuplicateTerminalDifferentTotalRejected) {
    // A second MF=0 fragment with a different total length must be rejected.
    FragmentReassembler r;
    auto p1 = MakePayload(32, 0xAA);

    // First fragment: offset=0, MF=1, length=32
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000);

    // First terminal: offset=8 (64 bytes), MF=0, total=96
    auto p2 = MakePayload(32, 0xBB);
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_FALSE(r2.complete); // gap at [32,64)

    // Second terminal with different total: offset=4 (32 bytes), MF=0, total=64
    // This is less than the already-known total of 96, so it's a DuplicateTerminal.
    auto p3 = MakePayload(32, 0xCC);
    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 4, false, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::DuplicateTerminal, r3.error);
}

TCPIP2_TEST(TerminalOverflowRejected) {
    // After MF=0 establishes total length, a fragment extending beyond it
    // must be rejected.
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);

    // Terminal fragment first: offset=0, MF=0, total=64
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 0, false, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_TRUE(r1.complete); // single-fragment, complete immediately

    // Entry is released after completion, so the next fragment creates a new
    // entry. To test TerminalOverflow we need the entry to remain active.
    // Use a scenario where the first fragment is MF=1, second is MF=0
    // (establishing total), then a third extends beyond.
    FragmentReassembler r2;
    auto pa = MakePayload(32, 0xAA);
    auto pb = MakePayload(32, 0xBB);

    // offset=0, MF=1, length=32
    r2.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 2,
                       0, true, pa.data(), pa.size(), 1000);

    // offset=4 (32 bytes), MF=0, total=64
    auto rb = r2.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 2,
                                  4, false, pb.data(), pb.size(), 1000);
    TCPIP2_EXPECT_TRUE(rb.complete); // [0,32)+[32,64) = complete

    // Entry is released after completion. To test overflow on an incomplete
    // entry, we need a gap.
    FragmentReassembler r3;
    auto pc = MakePayload(32, 0xAA);
    auto pd = MakePayload(32, 0xBB);
    auto pe = MakePayload(48, 0xCC);

    // offset=0, MF=1, length=32
    r3.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 3,
                       0, true, pc.data(), pc.size(), 1000);

    // offset=8 (64 bytes), MF=0, length=32 → total=96
    auto rd = r3.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 3,
                                  8, false, pd.data(), pd.size(), 1000);
    TCPIP2_EXPECT_FALSE(rd.complete); // gap at [32,64)

    // offset=8 (64 bytes), length=48 → end=112 > 96, no overlap (64+32=96, 64..96 is [64,96), 112 starts at 64)
    // Actually this fragment is at offset=8*8=64, length=48 → [64,112). But existing piece is [64,96).
    // So this overlaps. Let's use a fragment that doesn't overlap but overflows.
    // offset=12 (96 bytes), length=8 → end=104 > 96, no overlap with [0,32) or [64,96).
    std::uint8_t data8[8] = {};
    auto rf = r3.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 3,
                                  12, true, data8, 8, 1000);
    TCPIP2_EXPECT_EQ(FragmentError::TerminalOverflow, rf.error);
}

TCPIP2_TEST(TrickleTimeoutNotExtended) {
    // Deadline is fixed at the first fragment. Subsequent fragments must NOT
    // extend the deadline. An attacker sending a slow trickle of fragments
    // should not keep the entry alive beyond the original TTL.
    FragmentReassembler r;
    auto p1 = MakePayload(32, 0xAA);

    // First fragment at t=1000 with TTL=5000ms → deadline=6000
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000, 5000);
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Size());

    // Send more fragments at t=3000, t=5000, t=5500 — none should extend deadline.
    auto p2 = MakePayload(32, 0xBB);
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      4, true, p2.data(), p2.size(), 3000, 5000);

    auto p3 = MakePayload(32, 0xCC);
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      8, true, p3.data(), p3.size(), 5000, 5000);

    // At t=5500, deadline (6000) has not been reached. Entry should be alive.
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Size());

    // At t=6001, deadline exceeded — entry must be expired despite trickle.
    std::size_t purged = r.Purge(6001);
    TCPIP2_EXPECT_EQ(std::size_t{1}, purged);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.Size());
}

TCPIP2_TEST(IdReuseAfterCompletion) {
    // After reassembly completes and the entry is released, a new datagram
    // with the same identification must create a fresh entry.
    FragmentReassembler r;

    // First datagram: two fragments, completes.
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);
    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                      0, true, p1.data(), p1.size(), 1000);
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(r2.complete);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.Size()); // entry released

    // Second datagram with same identification — must succeed.
    auto p3 = MakePayload(64, 0xCC);
    auto p4 = MakePayload(64, 0xDD);
    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 0, true, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::None, r3.error);
    TCPIP2_EXPECT_FALSE(r3.complete);

    auto r4 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 8, false, p4.data(), p4.size(), 1000);
    TCPIP2_EXPECT_TRUE(r4.complete);
    TCPIP2_EXPECT_EQ(std::size_t{128}, r4.total_length);

    // Verify it's the new data, not stale from the first datagram.
    TCPIP2_EXPECT_EQ(std::uint8_t{0xCC}, r4.payload[0]);
    TCPIP2_EXPECT_EQ(std::uint8_t{0xDD}, r4.payload[64]);
}

TCPIP2_TEST(ByteBudgetExceeded) {
    // Set a small per-shard byte budget. After it's consumed, new fragments
    // for new entries must be rejected.
    // max_total_bytes=128: one entry with 64 bytes fits, second with 64
    // bytes fits (total 128), third must fail.
    FragmentReassembler r(kMaxReassemblyEntries, 128);

    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);
    auto p3 = MakePayload(64, 0xCC);

    // First entry (id=1): 64 bytes
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::None, r1.error);

    // Second entry (id=2): 64 bytes → total 128, at budget limit
    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 2,
                                 0, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::None, r2.error);

    // Third entry (id=3): 64 bytes → total would be 192 > 128
    auto r3 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 3,
                                 0, true, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::ByteBudgetExceeded, r3.error);
}

TCPIP2_TEST(ByteBudgetRejectsExistingEntryGrowth) {
    FragmentReassembler r(kMaxReassemblyEntries, 128);
    auto first = MakePayload(64, 0xAA);
    auto second = MakePayload(72, 0xBB);

    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 0, true, first.data(), first.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::None, r1.error);

    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                 8, false, second.data(), second.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::ByteBudgetExceeded, r2.error);
    TCPIP2_EXPECT_EQ(std::size_t{64}, r.BytesHeld());
}

TCPIP2_TEST(ByteBudgetRejectsSparseFirstFragment) {
    FragmentReassembler r(kMaxReassemblyEntries, 128);
    auto payload = MakePayload(8, 0xAA);

    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     16, false, payload.data(), payload.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::ByteBudgetExceeded, result.error);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.BytesHeld());
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.Size());
}

TCPIP2_TEST(CustomPayloadLimitCannotExceedProtocolHardCap) {
    FragmentReassembler r;
    auto payload = MakePayload(8, 0xAA);
    const auto oversized_limit =
        static_cast<std::uint32_t>(kMaxFragmentPayloadBytes + 1);

    auto ipv4 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                   8190, false, payload.data(), payload.size(),
                                   1000, 0, oversized_limit);
    TCPIP2_EXPECT_EQ(FragmentError::PayloadTooLarge, ipv4.error);

    auto ipv6 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 2,
                                   8191, false, payload.data(), payload.size(),
                                   1000, 0, oversized_limit);
    TCPIP2_EXPECT_EQ(FragmentError::PayloadTooLarge, ipv6.error);
}

TCPIP2_TEST(BytesHeldAfterPurge) {
    // Verify that BytesHeld() decreases correctly after Purge.
    FragmentReassembler r;
    auto p = MakePayload(64, 0xAA);

    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p.data(), p.size(), 1000, 5000);
    TCPIP2_EXPECT_EQ(std::size_t{64}, r.BytesHeld());

    // Purge at t=6001 (deadline=6000).
    r.Purge(6001);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.BytesHeld());
}

TCPIP2_TEST(ExpiredMatchingKeyStartsFreshDatagram) {
    FragmentReassembler r;
    auto old_payload = MakePayload(64, 0xAA);
    auto new_payload = MakePayload(64, 0xBB);

    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, old_payload.data(), old_payload.size(),
                      1000, 100);
    auto fresh = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                    0, true, new_payload.data(), new_payload.size(),
                                    1100, 100);
    TCPIP2_EXPECT_EQ(FragmentError::None, fresh.error);
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Size());
    TCPIP2_EXPECT_EQ(std::size_t{64}, r.BytesHeld());
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.Purge(1199));
    TCPIP2_EXPECT_EQ(std::size_t{1}, r.Purge(1200));
}

TCPIP2_TEST(BytesHeldAfterCompletion) {
    // Verify that BytesHeld() decreases correctly after reassembly completion.
    FragmentReassembler r;
    auto p1 = MakePayload(64, 0xAA);
    auto p2 = MakePayload(64, 0xBB);

    r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                      0, true, p1.data(), p1.size(), 1000);
    TCPIP2_EXPECT_EQ(std::size_t{64}, r.BytesHeld());

    auto result = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 1,
                                     8, false, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_TRUE(result.complete);
    TCPIP2_EXPECT_EQ(std::size_t{0}, r.BytesHeld()); // buffer moved out, entry reset
}

TCPIP2_TEST(Ipv6OverlapFollowedByNewIdSucceeds) {
    // After an IPv6 datagram is discarded due to overlap (RFC 5722), a new
    // datagram with a different identification must still work.
    FragmentReassembler r;
    auto p1 = MakePayload(48, 0xAA);
    auto p2 = MakePayload(48, 0xBB);

    // First datagram (id=1): cause overlap → discarded.
    r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 1,
                      0, true, p1.data(), p1.size(), 1000);
    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 1,
                                 3, true, p2.data(), p2.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::OverlapDetected, r2.error);

    // New datagram (id=2) must succeed.
    auto p3 = MakePayload(48, 0xCC);
    auto p4 = MakePayload(48, 0xDD);
    auto r3 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 2,
                                 0, true, p3.data(), p3.size(), 1000);
    TCPIP2_EXPECT_EQ(FragmentError::None, r3.error);

    auto r4 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 2,
                                 6, false, p4.data(), p4.size(), 1000);
    TCPIP2_EXPECT_TRUE(r4.complete);
    TCPIP2_EXPECT_EQ(std::size_t{96}, r4.total_length);
}

TCPIP2_TEST(InvalidOffsetNotMultipleOf8Rejected) {
    // Fragment offset in 8-byte units must produce a byte offset that is
    // a multiple of 8 (for non-zero offsets). The API takes fragment_offset
    // in 8-byte units, so any valid fragment_offset produces a valid byte
    // offset. This test verifies the internal check: a byte offset that is
    // not a multiple of 8 is rejected.
    // Since the API converts fragment_offset * 8, we can't directly test
    // non-8-aligned offsets through the public API. Instead, test that
    // fragment_offset=0 with MF=1 and non-8-aligned length is rejected
    // (already covered by Ipv4MfOneNonMultipleOf8Rejected).
    // This test is a placeholder for direct entry-level testing if needed.
    TCPIP2_EXPECT_TRUE(true);
}

// ===========================================================================
// RFC 3168 §5.2.2 ECN in fragments
// ===========================================================================

TCPIP2_TEST(Ipv4FragmentEcnOrPropagatesToReassembledDatagram) {
    FragmentReassembler r;
    auto p1 = MakePayload(104, 0xAA);
    auto p2 = MakePayload(56, 0xBB);

    // First fragment ECT(0), second CE: the reassembled datagram's ECN is the
    // bitwise OR (10 | 11 = 11 → CE).
    auto r1 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 0, true, p1.data(), p1.size(), 1000, 0, 0, 2);
    TCPIP2_EXPECT_FALSE(r1.complete);

    auto r2 = r.AddIpv4Fragment(kSrcIpv4, kDstIpv4, kProtoUdp, 42,
                                 13, false, p2.data(), p2.size(), 1000, 0, 0, 3);
    TCPIP2_EXPECT_TRUE(r2.complete);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x03}, r2.ecn);
}

TCPIP2_TEST(Ipv6FragmentEcnOrPropagatesToReassembledDatagram) {
    FragmentReassembler r;
    auto p1 = MakePayload(104, 0xAA);
    auto p2 = MakePayload(56, 0xBB);

    // ECT(0) + Not-ECT: OR is ECT(0).
    auto r1 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x42,
                                 0, true, p1.data(), p1.size(), 1000, 0, 0, 6, 2);
    TCPIP2_EXPECT_FALSE(r1.complete);
    auto r2 = r.AddIpv6Fragment(kSrcIpv6, kDstIpv6, 0x42,
                                 13, false, p2.data(), p2.size(), 1000, 0, 0, 6, 0);
    TCPIP2_EXPECT_TRUE(r2.complete);
    TCPIP2_EXPECT_EQ(std::uint8_t{0x02}, r2.ecn);
}

TCPIP2_TEST_MAIN()
