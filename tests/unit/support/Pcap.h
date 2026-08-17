#pragma once

/**
 * @file Pcap.h
 * @brief Minimal PCAP file writer for captures.
 * @license GPL-3.0
 *
 * Emits the classic pcap global header (little-endian magic 0xa1b2c3d4) plus
 * one record header + payload per appended packet. LINKTYPE_RAW (101) is used
 * because the test packets are raw IPv4 frames (no link layer).
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcpip2 {
namespace test {

class PcapWriter final {
  public:
    void Append(std::uint64_t ts_usec, const std::vector<std::uint8_t> &packet);
    void Clear() {
        bytes_.clear();
        record_count_ = 0;
    }

    const std::vector<std::uint8_t> &Bytes() const noexcept { return bytes_; }
    std::size_t RecordCount() const noexcept { return record_count_; }

  private:
    std::vector<std::uint8_t> bytes_;
    std::size_t record_count_ = 0;
};

} // namespace test
} // namespace tcpip2
