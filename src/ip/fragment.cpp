#include <ip/fragment.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>

namespace tcpip2 {

// Default per-shard byte budget: 256 entries * ~64KB ≈ 16 MB.
constexpr std::size_t kDefaultMaxTotalBytes = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// ReassemblyEntry
// ---------------------------------------------------------------------------

bool ReassemblyEntry::IsExpired(std::uint64_t now_ms) const noexcept {
    // Deadline is fixed at first fragment; never refreshed.
    // now_ms >= deadline_ms_ means the entry has expired.
    // (Clock rollback: if now_ms < deadline_ms_, the deadline has not been
    // reached, so the entry is not expired. This is consistent with the
    // monotonic-clock assumption; a non-monotonic clock may keep entries
    // alive longer, which is safe but not optimal.)
    return now_ms >= deadline_ms_;
}

void ReassemblyEntry::Reset() noexcept {
    key_ = FragmentKey{};
    for (std::size_t i = 0; i < fragment_count_; ++i) {
        pieces_[i] = FragmentPiece{};
    }
    fragment_count_ = 0;
    highest_end_ = 0;
    last_received_ = false;
    total_payload_length_ = 0;
    deadline_ms_ = 0;
    discarded_ = false;
    // Preserve capacity to avoid repeated allocation; clear size.
    data_buffer_.clear();
}

bool ReassemblyEntry::HasOverlap(std::uint32_t offset,
                                  std::uint32_t length) const noexcept {
    const std::uint32_t new_end = offset + length; // caller checks overflow
    for (std::size_t i = 0; i < fragment_count_; ++i) {
        const std::uint32_t existing_end =
            pieces_[i].offset + pieces_[i].length;
        if (offset < existing_end && pieces_[i].offset < new_end) {
            return true;
        }
    }
    return false;
}

FragmentAddResult ReassemblyEntry::AddFragment(
    std::uint32_t offset, const std::uint8_t* data,
    std::uint32_t length, bool more_fragments,
    std::uint64_t now_ms, std::uint32_t expires_ms,
    std::uint32_t max_payload_bytes,
    std::size_t additional_byte_budget) noexcept {

    FragmentAddResult result;

    // --- Basic validation ---
    if (data == nullptr) {
        result.error = FragmentError::NullData;
        return result;
    }
    if (length == 0) {
        result.error = FragmentError::InvalidFragment;
        return result;
    }
    if (fragment_count_ >= kMaxFragmentsPerEntry) {
        result.error = FragmentError::TooManyFragments;
        return result;
    }

    // --- Offset alignment: must be a multiple of 8 (unless offset == 0). ---
    if (offset != 0 && (offset % 8) != 0) {
        result.error = FragmentError::InvalidOffset;
        return result;
    }

    // --- RFC constraint: MF=1 fragments must have payload length that is a
    //     multiple of 8 (intermediate fragments must be 8-aligned). ---
    if (more_fragments && (length % 8) != 0) {
        result.error = FragmentError::InvalidFragment;
        return result;
    }

    // --- Bounds check: offset + length must fit within max_payload_bytes. ---
    std::uint32_t end = 0;
    if (!CheckedAdd<std::uint32_t>(offset, length, end)) {
        result.error = FragmentError::PayloadTooLarge;
        return result;
    }
    if (max_payload_bytes > 0 && end > max_payload_bytes) {
        result.error = FragmentError::PayloadTooLarge;
        return result;
    }

    // --- If we already know the total length (MF=0 received), reject any
    //     fragment that extends beyond it. ---
    if (last_received_ && end > total_payload_length_) {
        result.error = FragmentError::TerminalOverflow;
        return result;
    }

    // --- If this is the terminal fragment (MF=0), check for duplicate
    //     terminal with inconsistent total length. ---
    if (!more_fragments && last_received_) {
        // A second MF=0 fragment. If the total length differs, reject.
        if (end != total_payload_length_) {
            result.error = FragmentError::DuplicateTerminal;
            return result;
        }
        // Same total length — could be a duplicate of an existing piece.
        // If it overlaps, treat as overlap; otherwise accept (retransmission).
    }

    // --- Overlap detection. ---
    if (HasOverlap(offset, length)) {
        // IPv6: RFC 5722 requires discarding the entire datagram.
        // IPv4: reject the overlapping fragment but keep the entry.
        if (key_.ip_version == 6) {
            discarded_ = true;
            result.error = FragmentError::OverlapDetected;
            return result;
        }
        result.error = FragmentError::OverlapDetected;
        return result;
    }

    // --- If the datagram has been discarded (RFC 5722), reject all further
    //     fragments for this entry. ---
    if (discarded_) {
        result.error = FragmentError::OverlapDetected;
        return result;
    }

    const std::size_t required_size = static_cast<std::size_t>(end);
    if (required_size > data_buffer_.size() &&
        required_size - data_buffer_.size() > additional_byte_budget) {
        result.error = FragmentError::ByteBudgetExceeded;
        return result;
    }

    // --- Store the fragment: copy data into owned buffer. ---
    // The data_buffer_ is a contiguous reassembly buffer. We grow it to
    // accommodate the highest end seen, and copy the fragment at its offset.

    // Set fixed deadline on first fragment (not refreshed by subsequent fragments).
    if (fragment_count_ == 0) {
        if (expires_ms == 0) expires_ms = kFragmentDefaultTtlMs;
        // Saturating add: if now_ms is near UINT64_MAX, deadline wraps to
        // a very large value (entry stays alive), which is safe.
        std::uint64_t deadline = now_ms;
        if (expires_ms > std::numeric_limits<std::uint64_t>::max() - now_ms) {
            deadline = std::numeric_limits<std::uint64_t>::max();
        } else {
            deadline = now_ms + expires_ms;
        }
        deadline_ms_ = deadline;
    }

    if (data_buffer_.size() < required_size) {
        try {
            data_buffer_.resize(required_size, 0);
        } catch (...) {
            result.error = FragmentError::InvalidFragment;
            return result;
        }
    }
    std::memcpy(data_buffer_.data() + offset, data, length);

    pieces_[fragment_count_].offset = offset;
    pieces_[fragment_count_].length = length;
    ++fragment_count_;

    if (end > highest_end_) {
        highest_end_ = end;
    }

    // --- If MF=0, record the total payload length. ---
    if (!more_fragments) {
        last_received_ = true;
        total_payload_length_ = end;
    }

    // --- Check completeness. ---
    if (last_received_) {
        // Sort piece offsets to verify contiguous coverage [0, total_payload_length_).
        std::uint32_t sorted_offsets[kMaxFragmentsPerEntry];
        std::uint32_t sorted_ends[kMaxFragmentsPerEntry];
        for (std::size_t i = 0; i < fragment_count_; ++i) {
            sorted_offsets[i] = pieces_[i].offset;
            sorted_ends[i] = pieces_[i].offset + pieces_[i].length;
        }

        // Insertion sort by offset.
        for (std::size_t i = 1; i < fragment_count_; ++i) {
            std::uint32_t key_off = sorted_offsets[i];
            std::uint32_t key_end = sorted_ends[i];
            std::size_t j = i;
            while (j > 0 && sorted_offsets[j - 1] > key_off) {
                sorted_offsets[j] = sorted_offsets[j - 1];
                sorted_ends[j] = sorted_ends[j - 1];
                --j;
            }
            sorted_offsets[j] = key_off;
            sorted_ends[j] = key_end;
        }

        if (sorted_offsets[0] == 0) {
            bool complete = true;
            std::uint32_t expected_end = sorted_ends[0];
            for (std::size_t i = 1; i < fragment_count_; ++i) {
                if (sorted_offsets[i] != expected_end) {
                    complete = false;
                    break;
                }
                expected_end = sorted_ends[i];
            }
            if (complete && expected_end == total_payload_length_) {
                // --- Transfer ownership: move the buffer to the result. ---
                // Resize to exact total length (may be smaller if buffer was oversized).
                if (data_buffer_.size() > total_payload_length_) {
                    data_buffer_.resize(total_payload_length_);
                }
                result.complete = true;
                result.total_length = total_payload_length_;
                result.payload = std::move(data_buffer_);
                // data_buffer_ is now empty; entry can be Reset by caller.
                return result;
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// FragmentReassembler
// ---------------------------------------------------------------------------

FragmentReassembler::FragmentReassembler(std::size_t max_entries,
                                          std::size_t max_total_bytes)
    : max_entries_(max_entries == 0 ? 1 : max_entries)
    , max_total_bytes_(max_total_bytes == 0 ? kDefaultMaxTotalBytes
                                            : max_total_bytes) {
    if (max_entries_ > kMaxReassemblyEntries) {
        max_entries_ = kMaxReassemblyEntries;
    }
    entries_.reserve(max_entries_);
}

namespace {

void FillIpv4Mapped(const std::uint8_t src4[4], std::uint8_t out[16]) noexcept {
    std::memset(out, 0, 10);
    out[10] = 0xFF;
    out[11] = 0xFF;
    std::memcpy(out + 12, src4, 4);
}

} // namespace

FragmentAddResult FragmentReassembler::AddIpv4Fragment(
    const std::uint8_t src_ip[4], const std::uint8_t dst_ip[4],
    std::uint8_t protocol, std::uint16_t identification,
    std::uint16_t fragment_offset, bool more_fragments,
    const std::uint8_t* payload, std::size_t payload_len,
    std::uint64_t now_ms, std::uint32_t expires_ms,
    std::uint32_t max_payload_bytes) noexcept {

    FragmentAddResult result;

    if (src_ip == nullptr || dst_ip == nullptr) {
        result.error = FragmentError::NullData;
        return result;
    }
    if (payload == nullptr) {
        result.error = FragmentError::NullData;
        return result;
    }
    if (payload_len == 0) {
        result.error = FragmentError::InvalidFragment;
        return result;
    }
    // Check payload_len fits in uint32_t.
    if (payload_len > std::numeric_limits<std::uint32_t>::max()) {
        result.error = FragmentError::PayloadTooLarge;
        return result;
    }

    // Convert fragment_offset from 8-byte units to byte offset.
    std::uint32_t byte_offset = 0;
    if (!CheckedMul<std::uint32_t>(static_cast<std::uint32_t>(fragment_offset),
                                    std::uint32_t{8}, byte_offset)) {
        result.error = FragmentError::PayloadTooLarge;
        return result;
    }

    const std::uint32_t hard_payload_limit =
        static_cast<std::uint32_t>(kMaxIpv4FragmentPayloadBytes);
    if (max_payload_bytes == 0 || max_payload_bytes > hard_payload_limit) {
        max_payload_bytes = hard_payload_limit;
    }

    FragmentKey key;
    key.ip_version = 4;
    key.protocol = protocol;
    key.identification = static_cast<std::uint32_t>(identification);
    FillIpv4Mapped(src_ip, key.src_ip);
    FillIpv4Mapped(dst_ip, key.dst_ip);

    FragmentError find_error = FragmentError::None;
    ReassemblyEntry* entry = FindOrCreate(key, now_ms, expires_ms,
                                           find_error);
    if (entry == nullptr) {
        result.error = find_error;
        return result;
    }

    // Track bytes before/after for budget accounting.
    std::size_t bytes_before = entry->BytesHeld();
    const std::size_t additional_byte_budget =
        current_bytes_ < max_total_bytes_ ? max_total_bytes_ - current_bytes_ : 0;

    result = entry->AddFragment(byte_offset, payload,
                                static_cast<std::uint32_t>(payload_len),
                                more_fragments, now_ms, expires_ms,
                                max_payload_bytes, additional_byte_budget);

    std::size_t bytes_after = entry->BytesHeld();

    // Update byte budget.
    if (result.complete) {
        // Buffer was moved out; release the entry for reuse.
        current_bytes_ -= bytes_before;
        entry->Reset();
    } else if (result.error == FragmentError::None) {
        // Fragment was added; account for the delta.
        current_bytes_ += (bytes_after - bytes_before);
    }
    // On error, bytes_held didn't change.

    return result;
}

FragmentAddResult FragmentReassembler::AddIpv6Fragment(
    const std::uint8_t src_ip[16], const std::uint8_t dst_ip[16],
    std::uint32_t identification,
    std::uint16_t fragment_offset, bool more_fragments,
    const std::uint8_t* payload, std::size_t payload_len,
    std::uint64_t now_ms, std::uint32_t expires_ms,
    std::uint32_t max_payload_bytes) noexcept {

    FragmentAddResult result;

    if (src_ip == nullptr || dst_ip == nullptr) {
        result.error = FragmentError::NullData;
        return result;
    }
    if (payload == nullptr) {
        result.error = FragmentError::NullData;
        return result;
    }
    if (payload_len == 0) {
        result.error = FragmentError::InvalidFragment;
        return result;
    }
    if (payload_len > std::numeric_limits<std::uint32_t>::max()) {
        result.error = FragmentError::PayloadTooLarge;
        return result;
    }

    // Convert fragment_offset from 8-byte units to byte offset.
    std::uint32_t byte_offset = 0;
    if (!CheckedMul<std::uint32_t>(static_cast<std::uint32_t>(fragment_offset),
                                    std::uint32_t{8}, byte_offset)) {
        result.error = FragmentError::PayloadTooLarge;
        return result;
    }

    const std::uint32_t hard_payload_limit =
        static_cast<std::uint32_t>(kMaxFragmentPayloadBytes);
    if (max_payload_bytes == 0 || max_payload_bytes > hard_payload_limit) {
        max_payload_bytes = hard_payload_limit;
    }

    FragmentKey key;
    key.ip_version = 6;
    key.protocol = 0;
    key.identification = identification;
    std::memcpy(key.src_ip, src_ip, 16);
    std::memcpy(key.dst_ip, dst_ip, 16);

    FragmentError find_error = FragmentError::None;
    ReassemblyEntry* entry = FindOrCreate(key, now_ms, expires_ms,
                                           find_error);
    if (entry == nullptr) {
        result.error = find_error;
        return result;
    }

    std::size_t bytes_before = entry->BytesHeld();
    const std::size_t additional_byte_budget =
        current_bytes_ < max_total_bytes_ ? max_total_bytes_ - current_bytes_ : 0;

    result = entry->AddFragment(byte_offset, payload,
                                static_cast<std::uint32_t>(payload_len),
                                more_fragments, now_ms, expires_ms,
                                max_payload_bytes, additional_byte_budget);

    std::size_t bytes_after = entry->BytesHeld();

    if (result.complete) {
        current_bytes_ -= bytes_before;
        entry->Reset();
    } else if (result.error == FragmentError::None) {
        current_bytes_ += (bytes_after - bytes_before);
    }

    return result;
}

ReassemblyEntry* FragmentReassembler::FindOrCreate(
    const FragmentKey& key, std::uint64_t now_ms,
    std::uint32_t /*expires_ms*/,
    FragmentError& error) noexcept {

    error = FragmentError::None;

    // 1. Search for an existing matching entry.
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].InUse() && entries_[i].Key().Matches(key)) {
            if (entries_[i].IsExpired(now_ms)) {
                current_bytes_ -= entries_[i].BytesHeld();
                entries_[i].Reset();
                entries_[i].SetKey(key);
            }
            // If the entry was discarded (RFC 5722), still return it so
            // AddFragment can reject the fragment.
            return &entries_[i];
        }
    }

    // 2. Reuse a free or expired entry.
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (!entries_[i].InUse()) {
            entries_[i].SetKey(key);
            // Deadline is set in AddFragment when fragment_count_ == 0.
            return &entries_[i];
        }
        if (entries_[i].IsExpired(now_ms)) {
            // Reclaim bytes from expired entry.
            current_bytes_ -= entries_[i].BytesHeld();
            entries_[i].Reset();
            entries_[i].SetKey(key);
            return &entries_[i];
        }
    }

    // 3. Create a new entry if there is room.
    if (entries_.size() < max_entries_) {
        try {
            entries_.emplace_back();
        } catch (...) {
            error = FragmentError::TooManyEntries;
            return nullptr;
        }
        entries_.back().SetKey(key);
        return &entries_.back();
    }

    // 4. Table is full with no expired entries.
    error = FragmentError::TooManyEntries;
    return nullptr;
}

std::size_t FragmentReassembler::Purge(std::uint64_t now_ms) noexcept {
    std::size_t removed = 0;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].InUse() && entries_[i].IsExpired(now_ms)) {
            current_bytes_ -= entries_[i].BytesHeld();
            entries_[i].Reset();
            ++removed;
        }
    }
    return removed;
}

std::size_t FragmentReassembler::Size() const noexcept {
    std::size_t count = 0;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].InUse()) ++count;
    }
    return count;
}

std::size_t FragmentReassembler::BytesHeld() const noexcept {
    return current_bytes_;
}

} // namespace tcpip2
