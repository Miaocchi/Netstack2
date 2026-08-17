#pragma once

#include <cstdint>
#include <cstddef>
#include <limits>

namespace tcpip2 {

/// Returns true and stores result if a*b does not overflow T; false otherwise.
template <typename T> constexpr bool CheckedMul(T a, T b, T &result) noexcept {
    if (a == 0 || b == 0) {
        result = T{0};
        return true;
    }
    if (b > std::numeric_limits<T>::max() / a)
        return false;
    result = a * b;
    return true;
}

/// Returns true and stores result if a+b does not overflow T; false otherwise.
template <typename T> constexpr bool CheckedAdd(T a, T b, T &result) noexcept {
    if (b > std::numeric_limits<T>::max() - a)
        return false;
    result = a + b;
    return true;
}

/// A read-only, bounds-checked cursor over a byte buffer.
class ReadCursor {
  public:
    ReadCursor(const std::uint8_t *data, std::size_t size) noexcept : data_(data), size_(size) {}

    /// Remaining bytes from current position to end.
    std::size_t Remaining() const noexcept { return size_ - pos_; }

    /// Advance position by n. Returns false if would exceed bounds.
    bool Skip(std::size_t n) noexcept {
        if (n > size_ - pos_)
            return false;
        pos_ += n;
        return true;
    }

    /// Read a big-endian uint8 at current position, advance by 1.
    bool ReadU8(std::uint8_t &out) noexcept {
        if (1 > size_ - pos_)
            return false;
        out = data_[pos_];
        pos_ += 1;
        return true;
    }

    /// Read a big-endian uint16 at current position, advance by 2.
    bool ReadU16(std::uint16_t &out) noexcept {
        if (2 > size_ - pos_)
            return false;
        out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data_[pos_]) << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return true;
    }

    /// Read a big-endian uint32 at current position, advance by 4.
    bool ReadU32(std::uint32_t &out) noexcept {
        if (4 > size_ - pos_)
            return false;
        out = (static_cast<std::uint32_t>(static_cast<std::uint16_t>(data_[pos_]) << 8) << 16) |
              (static_cast<std::uint32_t>(data_[pos_ + 1]) << 16) |
              (static_cast<std::uint32_t>(static_cast<std::uint16_t>(data_[pos_ + 2]) << 8)) | data_[pos_ + 3];
        pos_ += 4;
        return true;
    }

    /// Read n bytes into out, advance by n. out must point to at least n bytes.
    bool ReadBytes(std::uint8_t *out, std::size_t n) noexcept {
        if (n > size_ - pos_)
            return false;
        for (std::size_t i = 0; i < n; ++i) {
            out[i] = data_[pos_ + i];
        }
        pos_ += n;
        return true;
    }

    /// Peek at current position without advancing. Returns nullptr if nothing remaining.
    const std::uint8_t *Peek() const noexcept {
        if (pos_ >= size_)
            return nullptr;
        return data_ + pos_;
    }

    /// Current read position (for diagnostics / offset calculation).
    std::size_t Position() const noexcept { return pos_; }

    /// Reset cursor to a new position. Returns false if out of bounds.
    bool Reset(std::size_t pos) noexcept {
        if (pos > size_)
            return false;
        pos_ = pos;
        return true;
    }

  private:
    const std::uint8_t *data_;
    std::size_t size_;
    std::size_t pos_ = 0;
};

} // namespace tcpip2
