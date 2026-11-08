#include "report/report.h"

#include <format>

namespace netprobe {

std::string render_text_summary(const Report& r, const std::vector<std::string>& outputs) {
    const auto& cap = r.capture;
    const auto& rs = *r.reader;
    const auto& c = rs.counters();
    const auto& sr = *r.flows;
    std::string out;
    auto line = [&out](std::string s) {
        out += s;
        out += '\n';
    };

    line(std::format("netprobe {}  {}  (pcap {}.{}, {}, {}, snaplen {})", NETPROBE_VERSION,
                     cap.path, cap.info.ver_major, cap.info.ver_minor,
                     cap.info.precision == TsPrecision::nano ? "nsec" : "usec",
                     link_type_name(cap.info.link_type), cap.info.snaplen));
    line(std::format("  {} packets  {}  span {}  status: {}", format_count(rs.packets()),
                     format_bytes(rs.original_bytes()),
                     format_duration(rs.packets() ? rs.last_ts_ns() - rs.first_ts_ns() : 0),
                     to_string(cap.status)));
    line(std::format("  IPv4 {}  IPv6 {}  VLAN {}  TCP {}  UDP {}  ICMP {}  ARP {}  fragments {}",
                     format_count(c.ipv4), format_count(c.ipv6), format_count(c.vlan_tagged),
                     format_count(c.tcp), format_count(c.udp), format_count(c.icmp + c.icmpv6),
                     format_count(c.arp), format_count(c.ip_fragments)));

    std::string errs;
    for (std::size_t k = 1; k < DecodeCounters::kKinds; ++k) {
        std::uint64_t total = 0;
        std::string detail;
        for (std::size_t l = 0; l < DecodeCounters::kLayers; ++l) {
            for (std::size_t rr = 0; rr < DecodeCounters::kReasons; ++rr) {
                const auto n = c.error_count(static_cast<DecodeKind>(k), static_cast<Layer>(l),
                                             static_cast<Reason>(rr));
                if (n > 0) {
                    total += n;
                    detail += std::format("{}{}.{}: {}", detail.empty() ? "" : ", ",
                                          to_string(static_cast<Layer>(l)),
                                          to_string(static_cast<Reason>(rr)), n);
                }
            }
        }
        if (total > 0) {
            errs += std::format("{}{} {} ({})", errs.empty() ? "" : "; ", total,
                                to_string(static_cast<DecodeKind>(k)), detail);
        }
    }
    line("  decode errors: " + (errs.empty() ? std::string("none") : errs));

    const auto& fc = sr.flows;
    line(std::format("  flows: {} TCP ({} full handshake, {} complete), {} UDP; {} TCP flows "
                     "with gaps ({} missing)",
                     format_count(fc.tcp_total), format_count(fc.handshake_full),
                     format_count(fc.tcp_complete), format_count(fc.udp_total),
                     format_count(fc.tcp_with_gaps), format_bytes(sr.reassembly.gap_bytes)));
    const auto& ra = sr.reassembly;
    line(std::format("  reassembly: {} delivered, {} retransmitted, {} out-of-order segments, "
                     "{} conflicting overlap bytes",
                     format_bytes(ra.delivered_bytes), format_bytes(ra.retransmitted_bytes),
                     format_count(ra.out_of_order_segments),
                     format_count(ra.conflicting_overlap_bytes)));

    const auto top = sr.top_bytes.sorted();
    if (!top.empty()) {
        line("  top flows:");
        for (std::size_t i = 0; i < top.size() && i < 10; ++i) {
            const auto& f = top[i];
            line(std::format("    #{:<8} {}:{} -> {}:{}  {}  {}  {}{}", f.id,
                             format_ip(f.client.addr), f.client.port, format_ip(f.server.addr),
                             f.server.port, f.is_tcp() ? "tcp" : "udp", format_bytes(f.bytes()),
                             to_string(f.close),
                             f.is_tcp() ? std::format("  {}", to_string(f.integrity)) : ""));
        }
    }
    if (cap.status != CaptureStatus::complete) {
        line(std::format("  warning: capture is {} ({} bytes {})", to_string(cap.status),
                         cap.truncated_tail_bytes,
                         cap.status == CaptureStatus::corrupt
                             ? "skipped after a corrupt record header"
                             : "of incomplete trailing record ignored"));
    }
    if (sr.limits_hit || ra.forced_flushes > 0) {
        line(std::format("  warning: memory limits hit ({} forced flushes, {} evicted flows); "
                         "results depend on limits",
                         ra.forced_flushes, sr.evicted_flows));
    }
    if (!outputs.empty()) {
        std::string w = "  wrote";
        for (std::size_t i = 0; i < outputs.size(); ++i) {
            w += (i ? ", " : " ") + outputs[i];
        }
        line(w);
    }
    return out;
}

} // namespace netprobe
