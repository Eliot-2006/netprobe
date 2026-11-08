#pragma once
// Layered packet decode result (PRD 6.3). decode_packet never allocates and never throws.
//
// Extension rule for parallel work: new Reason values may be appended (before `count_`);
// existing names and DecodedPacket fields must not be renamed.

#include "pcap/record.h"
#include "util/bytes.h"

#include <array>
#include <compare>
#include <cstdint>
#include <string_view>

namespace netprobe {

enum class Layer : std::uint8_t { pcap, ethernet, vlan, ipv4, ipv6, ipv6_ext, tcp, udp, count_ };
enum class DecodeKind : std::uint8_t { ok, truncated, malformed, unsupported, count_ };

enum class Reason : std::uint8_t {
    none,
    short_header,     // fewer bytes than the fixed header needs
    bad_version,      // IP version nibble wrong
    bad_ihl,          // IPv4 IHL < 5
    bad_total_length, // IPv4 total_length < IHL*4, IPv6 inconsistent
    tcp_data_offset,  // data offset < 5 or past segment end
    tcp_options,      // option walk violation (counted; segment still processed)
    udp_length,       // UDP length < 8 or > available
    vlan_depth,       // more than 2 VLAN tags
    llc,              // 802.3 length field / LLC frame
    ipv6_ext,         // unsupported IPv6 extension header (AH, ESP, Mobility, unknown)
    ipv6_ext_chain,   // more than 8 extension headers
    ipv6_jumbo,       // jumbogram
    count_
};

std::string_view to_string(Layer) noexcept;
std::string_view to_string(DecodeKind) noexcept;
std::string_view to_string(Reason) noexcept;

struct DecodeStatus {
    DecodeKind kind = DecodeKind::ok;
    Layer layer = Layer::pcap;
    Reason reason = Reason::none;
    constexpr bool ok() const noexcept { return kind == DecodeKind::ok; }
};

// IPv4 addresses are stored IPv4-mapped (::ffff:a.b.c.d) so all keys share one layout.
struct IpAddr {
    std::array<std::uint8_t, 16> b{};
    bool operator==(const IpAddr&) const = default;
    // Hand-written: Apple libc++ 15 lacks std::array::operator<=>.
    constexpr std::strong_ordering operator<=>(const IpAddr& o) const noexcept {
        for (std::size_t i = 0; i < b.size(); ++i) {
            if (b[i] != o.b[i]) {
                return b[i] <=> o.b[i];
            }
        }
        return std::strong_ordering::equal;
    }
    bool is_v4_mapped() const noexcept;
};

namespace tcp_flag {
inline constexpr std::uint8_t fin = 0x01, syn = 0x02, rst = 0x04, psh = 0x08, ack = 0x10,
                              urg = 0x20, ece = 0x40, cwr = 0x80;
}

namespace ip_proto {
inline constexpr std::uint8_t icmp = 1, tcp = 6, udp = 17, icmpv6 = 58;
}

struct DecodedPacket {
    DecodeStatus status;
    // Link layer
    std::uint16_t ethertype = 0; // innermost EtherType after VLAN tags
    std::uint8_t vlan_count = 0;
    std::array<std::uint16_t, 2> vlan_ids{}; // [0] = outer
    // Network layer
    std::uint8_t ip_version = 0; // 0 = no IP layer decoded
    std::uint8_t l4_proto = 0;   // IP protocol number
    bool is_fragment = false;
    bool l3_truncated = false;    // IP length exceeds captured bytes (snaplen)
    bool ipv4_checksum_ok = true; // meaningful only for IPv4
    bool ip_zero_length = false;  // IPv4 total_length / IPv6 payload_length == 0 (TSO)
    IpAddr src, dst;
    std::uint8_t ttl_or_hlim = 0;
    // Transport layer
    std::uint16_t src_port = 0, dst_port = 0;
    std::uint32_t seq = 0, ack = 0;
    std::uint8_t tcp_flags = 0;
    std::uint16_t window = 0;
    std::uint16_t mss = 0;
    std::uint8_t wscale = 0;
    bool has_mss = false, has_wscale = false;
    bool tcp_options_malformed = false;
    std::uint32_t udp_trailing_bytes = 0;
    std::uint32_t payload_logical_len = 0; // from IP / UDP length
    Bytes payload;                         // captured bytes, size() <= payload_logical_len

    bool is_tcp() const noexcept {
        return status.ok() && l4_proto == ip_proto::tcp && !is_fragment;
    }
    bool is_udp() const noexcept {
        return status.ok() && l4_proto == ip_proto::udp && !is_fragment;
    }
};

// Decodes an Ethernet (LINKTYPE_ETHERNET) frame.
DecodedPacket decode_packet(const PacketRecord& rec) noexcept;

} // namespace netprobe
