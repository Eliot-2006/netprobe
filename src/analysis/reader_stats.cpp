#include "analysis/reader_stats.h"

#include <algorithm>

namespace netprobe {

void Timeline::add(std::int64_t ts_ns, std::uint64_t bytes) noexcept {
    if (!started_) {
        started_ = true;
        origin_ = ts_ns;
    }
    std::size_t idx = 0;
    if (ts_ns < origin_) {
        ++clamped_;
    } else {
        // Divide in unsigned space: (ts - origin) can exceed INT64_MAX only via overflow, so
        // compute the delta as uint64.
        const auto delta = static_cast<std::uint64_t>(ts_ns) - static_cast<std::uint64_t>(origin_);
        while (delta / static_cast<std::uint64_t>(width_) >= kBuckets) {
            for (std::size_t i = 0; i < kBuckets / 2; ++i) {
                b_[i].packets = b_[2 * i].packets + b_[2 * i + 1].packets;
                b_[i].bytes = b_[2 * i].bytes + b_[2 * i + 1].bytes;
            }
            std::fill(b_.begin() + kBuckets / 2, b_.end(), Bucket{});
            width_ *= 2;
        }
        idx = static_cast<std::size_t>(delta / static_cast<std::uint64_t>(width_));
    }
    ++b_[idx].packets;
    b_[idx].bytes += bytes;
}

std::vector<Timeline::Bucket> Timeline::buckets() const {
    std::size_t n = kBuckets;
    while (n > 0 && b_[n - 1].packets == 0) {
        --n;
    }
    return {b_.begin(), b_.begin() + static_cast<std::ptrdiff_t>(n)};
}

std::uint64_t DecodeCounters::total_errors() const noexcept {
    std::uint64_t t = 0;
    for (std::size_t k = 1; k < kKinds; ++k) { // skip DecodeKind::ok
        for (std::size_t i = 0; i < kLayers * kReasons; ++i) {
            t += errors[k * kLayers * kReasons + i];
        }
    }
    return t;
}

void ReaderStats::add(const PacketRecord& rec, const DecodedPacket& pkt) noexcept {
    if (packets_ == 0) {
        first_ts_ = rec.ts_ns;
    }
    ++packets_;
    last_ts_ = std::max(last_ts_, rec.ts_ns);
    captured_bytes_ += rec.data.size();
    original_bytes_ += rec.orig_len;
    timeline_.add(rec.ts_ns, rec.orig_len);

    const auto& st = pkt.status;
    if (!st.ok()) {
        ++c_.errors[DecodeCounters::error_index(st.kind, st.layer, st.reason)];
    }
    if (st.ok() || st.layer != Layer::ethernet) {
        ++c_.ethernet;
    }
    if (pkt.vlan_count > 0) {
        ++c_.vlan_tagged;
        ++(*c_.vlans)[pkt.vlan_ids[0] & 0x0FFF];
    }
    // Count network-layer protocols reached, even when a deeper layer failed.
    const bool past_link = st.ok() || st.layer >= Layer::ipv4;
    if (past_link) {
        ++(*c_.ethertypes)[pkt.ethertype];
    }
    if (pkt.ip_version == 4) {
        ++c_.ipv4;
        c_.ipv4_bad_checksum += pkt.ipv4_checksum_ok ? 0u : 1u;
    } else if (pkt.ip_version == 6) {
        ++c_.ipv6;
    } else if (st.ok()) {
        if (pkt.ethertype == 0x0806) {
            ++c_.arp;
        } else {
            ++c_.other_ethertype;
        }
    }
    if (pkt.ip_version != 0) {
        c_.ip_zero_length += pkt.ip_zero_length ? 1u : 0u;
        if (pkt.is_fragment) {
            ++c_.ip_fragments;
        } else if (st.ok() || st.layer == Layer::tcp || st.layer == Layer::udp) {
            ++c_.ip_protocols[pkt.l4_proto];
            switch (pkt.l4_proto) {
            case ip_proto::tcp:
                if (st.ok()) {
                    ++c_.tcp;
                    c_.tcp_options_malformed += pkt.tcp_options_malformed ? 1u : 0u;
                    c_.tcp_flags_invalid += tcp_flags_invalid(pkt.tcp_flags) ? 1u : 0u;
                }
                break;
            case ip_proto::udp:
                if (st.ok()) {
                    ++c_.udp;
                    c_.udp_trailing_bytes += pkt.udp_trailing_bytes > 0 ? 1u : 0u;
                }
                break;
            case ip_proto::icmp:
                ++c_.icmp;
                break;
            case ip_proto::icmpv6:
                ++c_.icmpv6;
                break;
            default:
                ++c_.other_ip_proto;
            }
        }
    }
}

} // namespace netprobe
