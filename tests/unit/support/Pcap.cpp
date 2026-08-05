/**
 * @file Pcap.cpp
 * @brief PCAP (libpcap 2.4) writer.
 * @license GPL-3.0
 */

#include "Pcap.h"

#include <cstdint>

namespace tcpip2 {
namespace test {

namespace {

void AppendLe16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
}

void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
}

} // namespace

void PcapWriter::Append(std::uint64_t ts_usec, const std::vector<std::uint8_t>& packet) {
    if (bytes_.empty()) {
        // pcap global header, little-endian.
        AppendLe32(bytes_, 0xa1b2c3d4u); // magic
        AppendLe16(bytes_, 2);           // version major
        AppendLe16(bytes_, 4);           // version minor
        AppendLe32(bytes_, 0);           // thiszone
        AppendLe32(bytes_, 0);           // sigfigs
        AppendLe32(bytes_, 65535);       // snaplen
        AppendLe32(bytes_, 101);         // LINKTYPE_RAW
    }
    const std::uint64_t sec = ts_usec / 1000000u;
    const std::uint64_t usec = ts_usec % 1000000u;
    AppendLe32(bytes_, static_cast<std::uint32_t>(sec));
    AppendLe32(bytes_, static_cast<std::uint32_t>(usec));
    AppendLe32(bytes_, static_cast<std::uint32_t>(packet.size()));
    AppendLe32(bytes_, static_cast<std::uint32_t>(packet.size()));
    bytes_.insert(bytes_.end(), packet.begin(), packet.end());
    ++record_count_;
}

} // namespace test
} // namespace tcpip2
