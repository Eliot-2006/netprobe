#pragma once
// Test-only packet and PCAP-file builder (PRD 11.1, oracle O-A).
//
// Writes bytes by hand from header layouts. It deliberately shares NO code with src/decode or
// src/pcap, so decoder tests compare against an independent construction. Every function returns
// a fresh ByteVec; layers compose inside-out:
//
//     auto frame = eth(0x0800, ipv4({.proto = 6}, tcp({.dport = 80, .flags = 0x18}, payload)));
//     auto file  = pcap_file({}, {{.data = frame}});
//
// TCP/UDP checksums are left zero (the decoder does not verify them). The IPv4 header checksum is
// correct unless `bad_checksum` is set.

#include "util/bytes.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace netprobe::test {

using ByteVec = std::vector<std::byte>;
using Addr4 = std::array<std::uint8_t, 4>;
using Addr6 = std::array<std::uint8_t, 16>;

// ---- helpers ----
ByteVec bytes_of(std::string_view s);                      // ASCII/raw string -> bytes
ByteVec bytes_of(std::initializer_list<unsigned> values);  // {0x01, 0xFF} -> bytes
ByteVec counting_bytes(std::size_t n, unsigned start = 0); // start, start+1, ... (mod 256)
ByteVec concat(const ByteVec& a, const ByteVec& b);
Addr6 addr6(std::initializer_list<unsigned> leading_bytes); // zero-padded

// ---- Ethernet ----
struct VlanTag {
    std::uint16_t tpid = 0x8100; // 0x8100, 0x88A8 or 0x9100
    std::uint16_t tci = 0;       // PCP/DEI/VID (VID = low 12 bits)
};
// 14-byte Ethernet header, then each VLAN tag (TPID is written in the preceding slot, so the
// first tag's TPID takes the place of the EtherType), then `ethertype`, then `payload`.
ByteVec eth(std::uint16_t ethertype, const ByteVec& payload,
            const std::vector<VlanTag>& vlans = {});
ByteVec pad_to(ByteVec frame, std::size_t n, std::uint8_t fill = 0); // Ethernet min-frame padding

// ---- IPv4 ----
struct Ipv4Opts {
    std::uint8_t proto = 6;
    Addr4 src{10, 0, 0, 1};
    Addr4 dst{10, 0, 0, 2};
    std::uint8_t ttl = 64;
    std::uint16_t id = 0x1234;
    bool df = false;
    bool mf = false;
    std::uint16_t frag_offset = 0;               // in 8-byte units
    ByteVec options{};                           // raw; zero-padded to a multiple of 4
    std::optional<std::uint16_t> total_length{}; // override (default: header + payload)
    std::optional<std::uint8_t> ihl{};           // override IHL nibble
    std::optional<std::uint8_t> version{};       // override version nibble
    bool bad_checksum = false;
};
ByteVec ipv4(const Ipv4Opts& o, const ByteVec& payload);

// ---- IPv6 ----
// One extension header. `len` is the total size in bytes (multiple of 8, >= 8). `body` fills the
// bytes after the 2-byte (next header, hdr-ext-len) prefix; the rest is zero. Type 44 (Fragment)
// writes frag_offset/more/id into bytes 2..7 and ignores body. The next-header byte is chained
// automatically from the following header (or Ipv6Opts::next_header for the last one).
struct Ipv6Ext {
    std::uint8_t type = 0; // 0 HBH, 43 Routing, 44 Fragment, 50 ESP, 51 AH, 60 DestOpts, 135 ...
    std::size_t len = 8;
    ByteVec body{};
    std::uint16_t frag_offset = 0; // 8-byte units
    bool more = false;
    std::uint32_t frag_id = 1;
};
struct Ipv6Opts {
    std::uint8_t next_header = 6; // protocol after the extension chain
    Addr6 src = addr6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    Addr6 dst = addr6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});
    std::uint8_t hlim = 64;
    std::uint8_t traffic_class = 0;
    std::uint32_t flow_label = 0;
    std::vector<Ipv6Ext> ext{};
    std::optional<std::uint16_t> payload_length{}; // override (default: ext chain + payload)
    std::optional<std::uint8_t> version{};
};
ByteVec ipv6(const Ipv6Opts& o, const ByteVec& payload);

// ---- TCP ----
struct TcpOpts {
    std::uint16_t sport = 12345;
    std::uint16_t dport = 80;
    std::uint32_t seq = 1000;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0x10; // ACK
    std::uint16_t window = 65535;
    ByteVec options{};                         // raw; padded with EOL(0) to a multiple of 4
    std::optional<std::uint8_t> data_offset{}; // override the nibble (default from options)
};
ByteVec tcp(const TcpOpts& o, const ByteVec& payload = {});
ByteVec tcp_opt_mss(std::uint16_t mss);
ByteVec tcp_opt_wscale(std::uint8_t shift);
ByteVec tcp_opt_nop();
ByteVec tcp_opt_sack_permitted();
ByteVec tcp_opt_timestamps(std::uint32_t val, std::uint32_t echo);

// ---- UDP ----
struct UdpOpts {
    std::uint16_t sport = 5353;
    std::uint16_t dport = 53;
    std::optional<std::uint16_t> length{}; // override (default 8 + payload)
};
ByteVec udp(const UdpOpts& o, const ByteVec& payload = {});

// ---- PCAP files ----
struct PcapFileOpts {
    ByteOrder order = ByteOrder::little;
    bool nanosecond = false;
    std::uint16_t ver_major = 2, ver_minor = 4;
    std::uint32_t snaplen = 65535;
    std::uint32_t linktype_field = 1;     // raw 32-bit field: link type + FCS bits (bit 26, 28..31)
    std::optional<std::uint32_t> magic{}; // override, written in `order` (default: standard magic)
};
struct PcapRecordSpec {
    std::uint32_t ts_sec = 0;
    std::uint32_t ts_frac = 0; // microseconds or nanoseconds, per PcapFileOpts::nanosecond
    ByteVec data{};
    std::optional<std::uint32_t> incl_len{}; // override (default data.size())
    std::optional<std::uint32_t> orig_len{}; // override (default data.size())
};
ByteVec pcap_global_header(const PcapFileOpts& o);
ByteVec pcap_record(const PcapFileOpts& o, const PcapRecordSpec& r);
// Global header + records. For truncated tails, resize() the result or use pcap_record pieces.
ByteVec pcap_file(const PcapFileOpts& o, const std::vector<PcapRecordSpec>& records);
// Writes bytes to `path` (for MappedFile tests). Throws std::runtime_error on failure.
void write_file(const std::filesystem::path& path, const ByteVec& bytes);

} // namespace netprobe::test
