#pragma once
// Statistics owned by the reader thread (PRD 4.5 FR-STAT-1/2): decode counters and timeline.

#include "decode/decode.h"
#include "pcap/record.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace netprobe {

// Adaptive histogram (FR-STAT-2): fixed bucket count; width doubles (pairs merge) when a packet
// falls past the end. Packets before the origin land in bucket 0 and are counted as clamped.
class Timeline {
public:
    static constexpr std::size_t kBuckets = 256;
    static constexpr std::int64_t kInitialWidthNs = 1'000'000; // 1 ms

    struct Bucket {
        std::uint64_t packets = 0, bytes = 0;
    };

    void add(std::int64_t ts_ns, std::uint64_t bytes) noexcept;

    bool empty() const noexcept { return !started_; }
    std::int64_t origin_ns() const noexcept { return origin_; }
    std::int64_t width_ns() const noexcept { return width_; }
    std::uint64_t clamped() const noexcept { return clamped_; }
    // Buckets up to and including the last non-empty one.
    std::vector<Bucket> buckets() const;

private:
    std::array<Bucket, kBuckets> b_{};
    bool started_ = false;
    std::int64_t origin_ = 0;
    std::int64_t width_ = kInitialWidthNs;
    std::uint64_t clamped_ = 0;
};

struct DecodeCounters {
    std::uint64_t ethernet = 0, vlan_tagged = 0, ipv4 = 0, ipv6 = 0, tcp = 0, udp = 0, icmp = 0,
                  icmpv6 = 0, arp = 0, ip_fragments = 0, other_ethertype = 0, other_ip_proto = 0;
    // Anomalies (packet still processed)
    std::uint64_t ipv4_bad_checksum = 0, ip_zero_length = 0, udp_trailing_bytes = 0,
                  tcp_options_malformed = 0, tcp_flags_invalid = 0;

    static constexpr std::size_t kKinds = static_cast<std::size_t>(DecodeKind::count_);
    static constexpr std::size_t kLayers = static_cast<std::size_t>(Layer::count_);
    static constexpr std::size_t kReasons = static_cast<std::size_t>(Reason::count_);
    std::array<std::uint64_t, kKinds * kLayers * kReasons> errors{};

    // Heap-allocated: indexed directly by EtherType / protocol / VLAN ID.
    std::unique_ptr<std::array<std::uint64_t, 65536>> ethertypes =
        std::make_unique<std::array<std::uint64_t, 65536>>();
    std::array<std::uint64_t, 256> ip_protocols{};
    std::unique_ptr<std::array<std::uint64_t, 4096>> vlans =
        std::make_unique<std::array<std::uint64_t, 4096>>();

    static constexpr std::size_t error_index(DecodeKind k, Layer l, Reason r) noexcept {
        return (static_cast<std::size_t>(k) * kLayers + static_cast<std::size_t>(l)) * kReasons +
               static_cast<std::size_t>(r);
    }
    std::uint64_t error_count(DecodeKind k, Layer l, Reason r) const noexcept {
        return errors[error_index(k, l, r)];
    }
    std::uint64_t total_errors() const noexcept;
};

// SYN+FIN, SYN+RST and no-flag segments (FR-DEC-8).
constexpr bool tcp_flags_invalid(std::uint8_t f) noexcept {
    const bool syn = f & tcp_flag::syn;
    return (syn && (f & tcp_flag::fin)) || (syn && (f & tcp_flag::rst)) || f == 0;
}

class ReaderStats {
public:
    void add(const PacketRecord& rec, const DecodedPacket& pkt) noexcept;

    const DecodeCounters& counters() const noexcept { return c_; }
    const Timeline& timeline() const noexcept { return timeline_; }
    std::uint64_t packets() const noexcept { return packets_; }
    std::uint64_t captured_bytes() const noexcept { return captured_bytes_; }
    std::uint64_t original_bytes() const noexcept { return original_bytes_; }
    std::int64_t first_ts_ns() const noexcept { return first_ts_; }
    std::int64_t last_ts_ns() const noexcept { return last_ts_; }

private:
    DecodeCounters c_;
    Timeline timeline_;
    std::uint64_t packets_ = 0, captured_bytes_ = 0, original_bytes_ = 0;
    std::int64_t first_ts_ = 0, last_ts_ = 0;
};

} // namespace netprobe
