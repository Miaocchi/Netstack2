#pragma once

/**
 * @file fragment.h
 * @brief Bounded IPv4/IPv6 fragment reassembly with overlap rejection.
 * @license GPL-3.0
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

#include <ip/checked.h>

namespace tcpip2 {

/// Maximum number of fragments per reassembly entry.
constexpr std::size_t kMaxFragmentsPerEntry = 64;

/// Default fragment reassembly timeout in milliseconds (RFC 791: 15s, RFC 8200: 60s).
constexpr std::uint32_t kFragmentDefaultTtlMs = 60000;

/// Maximum number of concurrent reassembly entries per shard.
constexpr std::size_t kMaxReassemblyEntries = 256;

/// Maximum total fragmentable payload bytes per datagram.
/// For IPv4: 65535 - minimum IP header (20 bytes) = 65515.
/// For IPv6: 65535 (jumbograms not supported; fragmentable part = payload length).
/// The caller must pass the correct per-datagram limit based on actual headers.
constexpr std::size_t kMaxFragmentPayloadBytes = 65535;
constexpr std::size_t kMaxIpv4FragmentPayloadBytes = 65515;

/// A single fragment within a reassembly entry.
/// Data is copied on arrival into the entry's owned buffer.
struct FragmentPiece {
    std::uint32_t offset = 0;       // byte offset in the reassembled payload
    std::uint32_t length = 0;       // payload length in bytes
};

/// Error codes for fragment reassembly.
enum class FragmentError {
    None,
    TooManyFragments,       // exceeded kMaxFragmentsPerEntry
    OverlapDetected,        // overlapping fragments (IPv4) or RFC 5722 datagram discard (IPv6)
    PayloadTooLarge,        // reassembled size would exceed max_payload_bytes
    InvalidOffset,          // non-zero offset but not a multiple of 8
    InvalidFragment,        // zero-length fragment, MF=1 with non-multiple-of-8 length, etc.
    TooManyEntries,         // reassembly table full (kMaxReassemblyEntries)
    NullData,               // null fragment data pointer or null addresses
    DuplicateTerminal,      // second MF=0 fragment with different total length
    TerminalOverflow,       // fragment beyond already-known total length
    ByteBudgetExceeded,     // per-shard total byte budget exceeded
};

/// Result of adding a fragment. When complete, the caller takes ownership
/// of the reassembled payload buffer (moved out of the entry).
struct FragmentAddResult {
    FragmentError error = FragmentError::None;
    bool complete = false;
    std::size_t total_length = 0;
    std::vector<std::uint8_t> payload;  // owning buffer (moved from entry on completion)
};

/// Key for identifying a fragment group.
/// For IPv4: src_ip[4], dst_ip[4], protocol, identification(16-bit).
/// For IPv6: src_ip[16], dst_ip[16], identification(32-bit).
struct FragmentKey {
    std::uint8_t src_ip[16] = {};
    std::uint8_t dst_ip[16] = {};
    std::uint8_t ip_version = 0;     // 4 or 6
    std::uint8_t protocol = 0;       // IPv4 only; 0 for IPv6
    std::uint32_t identification = 0;

    bool Matches(const FragmentKey& other) const noexcept {
        return ip_version == other.ip_version &&
               protocol == other.protocol &&
               identification == other.identification &&
               std::memcmp(src_ip, other.src_ip, 16) == 0 &&
               std::memcmp(dst_ip, other.dst_ip, 16) == 0;
    }
};

/// A reassembly entry holding fragments for one packet.
/// Each fragment's data is copied into an owned buffer on arrival (no UAF).
class ReassemblyEntry {
public:
    /// Add a fragment to this entry.
    /// @param offset byte offset of this fragment's payload in the reassembled packet
    /// @param data pointer to the fragment payload (copied immediately)
    /// @param length payload length in bytes
    /// @param more_fragments true if MF flag is set (more fragments follow)
    /// @param now_ms current monotonic time (used only for creation; deadline is fixed)
    /// @param expires_ms TTL for this entry (0 = use default)
    /// @param max_payload_bytes per-datagram payload upper bound
    /// @param additional_byte_budget bytes this entry may grow before exhausting the shard budget
    FragmentAddResult AddFragment(std::uint32_t offset, const std::uint8_t* data,
                                  std::uint32_t length, bool more_fragments,
                                  std::uint64_t now_ms,
                                  std::uint32_t expires_ms,
                                  std::uint32_t max_payload_bytes,
                                  std::size_t additional_byte_budget) noexcept;

    /// Check if this entry has expired. Deadline is fixed at first fragment.
    bool IsExpired(std::uint64_t now_ms) const noexcept;

    /// Mark this entry for reuse (reset all state, preserve buffer capacity).
    void Reset() noexcept;

    /// Whether this entry is in use (has at least one fragment).
    bool InUse() const noexcept { return fragment_count_ > 0; }

    /// Number of fragments currently held.
    std::size_t FragmentCount() const noexcept { return fragment_count_; }

    /// Key for this entry.
    const FragmentKey& Key() const noexcept { return key_; }

    /// Set the key for this entry.
    void SetKey(const FragmentKey& key) noexcept { key_ = key; }

    /// Creation timestamp (fixed at first fragment, not refreshed).
    std::uint64_t DeadlineMs() const noexcept { return deadline_ms_; }

    /// Bytes currently held in the entry's fragment buffer.
    std::size_t BytesHeld() const noexcept { return data_buffer_.size(); }

    /// Whether this datagram has been discarded (RFC 5722 IPv6 overlap).
    bool IsDiscarded() const noexcept { return discarded_; }

    /// Mark entry as discarded (RFC 5722: discard entire datagram on IPv6 overlap).
    void MarkDiscarded() noexcept { discarded_ = true; }

private:
    FragmentKey key_{};
    FragmentPiece pieces_[kMaxFragmentsPerEntry];
    std::size_t fragment_count_ = 0;
    std::uint32_t highest_end_ = 0;
    bool last_received_ = false;
    std::uint32_t total_payload_length_ = 0;
    std::uint64_t deadline_ms_ = 0;       // fixed at first fragment
    bool discarded_ = false;               // RFC 5722: IPv6 overlap → discard all
    std::vector<std::uint8_t> data_buffer_;  // owned, contiguous reassembly buffer

    bool HasOverlap(std::uint32_t offset, std::uint32_t length) const noexcept;
};

/// A bounded fragment reassembly table. Not thread-safe — per-shard.
/// Rejects overlapping fragments (IPv4) or discards the datagram (IPv6, RFC 5722).
/// Evicts expired entries when full. Per-shard byte budget limits total memory.
class FragmentReassembler {
public:
    /// @param max_entries maximum concurrent reassembly entries
    /// @param max_total_bytes per-shard total byte budget (0 = use default)
    explicit FragmentReassembler(std::size_t max_entries = kMaxReassemblyEntries,
                                  std::size_t max_total_bytes = 0);

    /// Add an IPv4 fragment.
    /// @param src_ip source IPv4 address (4 bytes, must not be null)
    /// @param dst_ip destination IPv4 address (4 bytes, must not be null)
    /// @param protocol IP protocol number
    /// @param identification 16-bit identification field
    /// @param fragment_offset offset in 8-byte units (from the IP header)
    /// @param more_fragments true if MF flag is set
    /// @param payload pointer to fragment payload (after IP header)
    /// @param payload_len payload length in bytes
    /// @param now_ms current monotonic time
    /// @param expires_ms TTL for this entry (0 = use default)
    /// @param max_payload_bytes per-datagram payload upper bound (0 = use default)
    FragmentAddResult AddIpv4Fragment(
        const std::uint8_t src_ip[4], const std::uint8_t dst_ip[4],
        std::uint8_t protocol, std::uint16_t identification,
        std::uint16_t fragment_offset, bool more_fragments,
        const std::uint8_t* payload, std::size_t payload_len,
        std::uint64_t now_ms, std::uint32_t expires_ms = 0,
        std::uint32_t max_payload_bytes = 0) noexcept;

    /// Add an IPv6 fragment.
    /// @param src_ip source IPv6 address (16 bytes, must not be null)
    /// @param dst_ip destination IPv6 address (16 bytes, must not be null)
    /// @param identification 32-bit identification field
    /// @param fragment_offset offset in 8-byte units (from the Fragment header)
    /// @param more_fragments true if MF flag is set
    /// @param payload pointer to fragment payload (after Fragment header)
    /// @param payload_len payload length in bytes
    /// @param now_ms current monotonic time
    /// @param expires_ms TTL for this entry (0 = use default)
    /// @param max_payload_bytes per-datagram payload upper bound (0 = use default)
    FragmentAddResult AddIpv6Fragment(
        const std::uint8_t src_ip[16], const std::uint8_t dst_ip[16],
        std::uint32_t identification,
        std::uint16_t fragment_offset, bool more_fragments,
        const std::uint8_t* payload, std::size_t payload_len,
        std::uint64_t now_ms, std::uint32_t expires_ms = 0,
        std::uint32_t max_payload_bytes = 0) noexcept;

    /// Purge expired entries. Returns number of entries removed.
    std::size_t Purge(std::uint64_t now_ms) noexcept;

    /// Current number of active entries.
    std::size_t Size() const noexcept;

    /// Total bytes held across all active entries.
    std::size_t BytesHeld() const noexcept;

private:
    std::vector<ReassemblyEntry> entries_;
    std::size_t max_entries_;
    std::size_t max_total_bytes_;
    std::size_t current_bytes_ = 0;

    ReassemblyEntry* FindOrCreate(const FragmentKey& key, std::uint64_t now_ms,
                                  std::uint32_t expires_ms,
                                  FragmentError& error) noexcept;
};

} // namespace tcpip2
