#include "report/json_writer.h"
#include "report/report.h"

#include <format>

namespace netprobe {
namespace {

std::string_view proto_name(std::uint8_t p) noexcept {
    return p == ip_proto::tcp ? "tcp" : p == ip_proto::udp ? "udp" : "other";
}

void write_endpoint(JsonWriter& w, std::string_view key, const Endpoint& e) {
    w.key(key);
    w.begin_object();
    w.field("address", format_ip(e.addr));
    w.field("port", e.port);
    w.end_object();
}

void write_direction(JsonWriter& w, std::string_view key, const DirSummary& d, bool tcp) {
    w.key(key);
    w.begin_object();
    w.field("packets", d.packets);
    w.field("bytes", d.bytes);
    w.field("payload_bytes", d.payload_bytes);
    if (tcp) {
        const auto& s = d.stream;
        w.field("delivered_bytes", s.delivered_bytes);
        w.field("retransmitted_bytes", s.retransmitted_bytes);
        w.field("out_of_order_segments", s.out_of_order_segments);
        w.field("overlap_bytes", s.overlap_bytes);
        w.field("conflicting_overlap_bytes", s.conflicting_overlap_bytes);
        w.field("gap_count", s.gap_count);
        w.field("gap_bytes", s.gap_bytes);
        w.key("gaps");
        w.begin_array();
        for (const auto& g : s.gaps) {
            w.begin_object();
            w.field("offset", g.offset);
            w.field("length", g.length);
            w.field("acked", g.acked);
            w.end_object();
        }
        w.end_array();
        w.field("gaps_truncated", s.gaps_truncated);
        w.field("fin", d.fin);
        w.field("data_after_rst", d.data_after_rst);
        if (d.has_mss) {
            w.field("mss", d.mss);
        }
        if (d.has_wscale) {
            w.field("wscale", d.wscale);
        }
    }
    w.end_object();
}

void write_flow(JsonWriter& w, const FlowSummary& f) {
    const bool tcp = f.is_tcp();
    w.begin_object();
    w.field("id", f.id);
    w.field("proto", proto_name(f.proto));
    w.field("ip_version", f.ip_version);
    write_endpoint(w, "client", f.client);
    write_endpoint(w, "server", f.server);
    w.field("orientation", f.orientation_handshake ? "handshake" : "first_packet");
    if (tcp) {
        w.field("handshake", to_string(f.handshake));
    }
    w.field("close_reason", to_string(f.close));
    if (tcp) {
        w.field("integrity", to_string(f.integrity));
    }
    w.field("first_ts_ns", f.first_ts_ns);
    w.field("last_ts_ns", f.last_ts_ns);
    write_direction(w, "c2s", f.c2s, tcp);
    write_direction(w, "s2c", f.s2c, tcp);
    w.end_object();
}

void write_error_group(JsonWriter& w, const DecodeCounters& c, DecodeKind kind) {
    w.key(to_string(kind));
    w.begin_object();
    // Emit "layer.reason" keys sorted as strings for a stable order.
    std::vector<std::pair<std::string, std::uint64_t>> rows;
    for (std::size_t l = 0; l < DecodeCounters::kLayers; ++l) {
        for (std::size_t r = 0; r < DecodeCounters::kReasons; ++r) {
            const auto n = c.error_count(kind, static_cast<Layer>(l), static_cast<Reason>(r));
            if (n > 0) {
                rows.emplace_back(std::format("{}.{}", to_string(static_cast<Layer>(l)),
                                              to_string(static_cast<Reason>(r))),
                                  n);
            }
        }
    }
    std::sort(rows.begin(), rows.end());
    for (const auto& [k, n] : rows) {
        w.field(k, n);
    }
    w.end_object();
}

} // namespace

std::string render_json(const Report& r) {
    const auto& o = *r.options;
    const auto& cap = r.capture;
    const auto& rs = *r.reader;
    const auto& c = rs.counters();
    const auto& sr = *r.flows;
    JsonWriter w;
    w.begin_object();
    w.field("schema_version", 1);
    w.key("tool");
    w.begin_object();
    w.field("name", "netprobe");
    w.field("version", NETPROBE_VERSION);
    w.end_object();

    w.key("options");
    w.begin_object();
    w.field("workers", o.workers);
    w.field("idle_timeout_s", o.idle_timeout_s);
    w.field("max_flows", o.max_flows);
    w.field("max_stream_buffer", o.max_stream_buffer);
    w.field("max_reassembly_memory", o.max_reassembly_memory);
    w.field("top_flows", o.top_flows);
    w.end_object();

    w.key("capture");
    w.begin_object();
    w.field("path", cap.path);
    w.field("file_size", cap.file_size);
    w.field("format", "pcap");
    w.field("byte_order", cap.info.order == ByteOrder::little ? "little" : "big");
    w.field("ts_precision", cap.info.precision == TsPrecision::nano ? "nsec" : "usec");
    w.field("version", std::format("{}.{}", cap.info.ver_major, cap.info.ver_minor));
    w.field("snaplen", cap.info.snaplen);
    w.field("link_type", cap.info.link_type);
    w.field("link_type_name", link_type_name(cap.info.link_type));
    w.field("status", to_string(cap.status));
    w.field("truncated_tail_bytes", cap.truncated_tail_bytes);
    w.field("records", rs.packets());
    w.field("captured_bytes", rs.captured_bytes());
    w.field("original_bytes", rs.original_bytes());
    w.field("records_truncated_by_snaplen", cap.counters.records_truncated_by_snaplen);
    w.field("timestamp_regressions", cap.counters.timestamp_regressions);
    w.field("first_ts_ns", rs.first_ts_ns());
    w.field("last_ts_ns", rs.last_ts_ns());
    w.field("duration_ns", rs.packets() > 0 ? rs.last_ts_ns() - rs.first_ts_ns() : 0);
    w.end_object();

    w.key("decode");
    w.begin_object();
    w.key("layers");
    w.begin_object();
    w.field("ethernet", c.ethernet);
    w.field("vlan_tagged", c.vlan_tagged);
    w.field("ipv4", c.ipv4);
    w.field("ipv6", c.ipv6);
    w.field("tcp", c.tcp);
    w.field("udp", c.udp);
    w.field("icmp", c.icmp);
    w.field("icmpv6", c.icmpv6);
    w.field("arp", c.arp);
    w.field("ip_fragments", c.ip_fragments);
    w.field("other_ethertype", c.other_ethertype);
    w.field("other_ip_proto", c.other_ip_proto);
    w.end_object();
    w.key("ethertypes");
    w.begin_object();
    for (std::size_t i = 0; i < c.ethertypes->size(); ++i) {
        if ((*c.ethertypes)[i] > 0) {
            w.field(std::format("0x{:04x}", i), (*c.ethertypes)[i]);
        }
    }
    w.end_object();
    w.key("ip_protocols");
    w.begin_object();
    for (std::size_t i = 0; i < c.ip_protocols.size(); ++i) {
        if (c.ip_protocols[i] > 0) {
            w.field(std::to_string(i), c.ip_protocols[i]);
        }
    }
    w.end_object();
    w.key("vlans");
    w.begin_object();
    for (std::size_t i = 0; i < c.vlans->size(); ++i) {
        if ((*c.vlans)[i] > 0) {
            w.field(std::to_string(i), (*c.vlans)[i]);
        }
    }
    w.end_object();
    w.key("errors");
    w.begin_object();
    write_error_group(w, c, DecodeKind::truncated);
    write_error_group(w, c, DecodeKind::malformed);
    write_error_group(w, c, DecodeKind::unsupported);
    w.end_object();
    w.key("anomalies");
    w.begin_object();
    w.field("ipv4_bad_checksum", c.ipv4_bad_checksum);
    w.field("ip_zero_length", c.ip_zero_length);
    w.field("udp_trailing_bytes", c.udp_trailing_bytes);
    w.field("tcp_options_malformed", c.tcp_options_malformed);
    w.field("tcp_flags_invalid", c.tcp_flags_invalid);
    w.field("incl_gt_orig", cap.counters.incl_gt_orig);
    w.field("ts_fraction_overflow", cap.counters.ts_fraction_overflow);
    w.field("version_anomaly", cap.info.version_anomaly ? 1 : 0);
    w.end_object();
    w.end_object();

    const auto& tl = rs.timeline();
    w.key("timeline");
    w.begin_object();
    w.field("origin_ns", tl.origin_ns());
    w.field("bucket_width_ns", tl.width_ns());
    w.field("clamped", tl.clamped());
    w.key("buckets");
    w.begin_array();
    for (const auto& b : tl.buckets()) {
        w.begin_object();
        w.field("packets", b.packets);
        w.field("bytes", b.bytes);
        w.end_object();
    }
    w.end_array();
    w.end_object();

    const auto& fc = sr.flows;
    auto close_idx = [](CloseReason cr) { return static_cast<std::size_t>(cr); };
    w.key("flows");
    w.begin_object();
    w.key("tcp");
    w.begin_object();
    w.field("total", fc.tcp_total);
    w.field("handshake_full", fc.handshake_full);
    w.field("handshake_partial", fc.handshake_partial);
    w.field("handshake_none", fc.handshake_none);
    w.field("close_fin", fc.tcp_close[close_idx(CloseReason::fin)]);
    w.field("close_rst", fc.tcp_close[close_idx(CloseReason::rst)]);
    w.field("close_idle_timeout", fc.tcp_close[close_idx(CloseReason::idle_timeout)]);
    w.field("close_end_of_capture", fc.tcp_close[close_idx(CloseReason::end_of_capture)]);
    w.field("close_reused", fc.tcp_close[close_idx(CloseReason::reused)]);
    w.field("close_evicted", fc.tcp_close[close_idx(CloseReason::evicted)]);
    w.field("complete", fc.tcp_complete);
    w.field("with_gaps", fc.tcp_with_gaps);
    w.end_object();
    w.key("udp");
    w.begin_object();
    w.field("total", fc.udp_total);
    w.field("close_idle_timeout", fc.udp_close[close_idx(CloseReason::idle_timeout)]);
    w.field("close_end_of_capture", fc.udp_close[close_idx(CloseReason::end_of_capture)]);
    w.field("close_evicted", fc.udp_close[close_idx(CloseReason::evicted)]);
    w.end_object();
    w.key("top_by_bytes");
    w.begin_array();
    for (const auto& f : sr.top_bytes.sorted()) {
        write_flow(w, f);
    }
    w.end_array();
    w.key("top_incomplete");
    w.begin_array();
    for (const auto& f : sr.top_incomplete.sorted()) {
        write_flow(w, f);
    }
    w.end_array();
    w.end_object();

    const auto& ra = sr.reassembly;
    w.key("reassembly");
    w.begin_object();
    w.field("delivered_bytes", ra.delivered_bytes);
    w.field("retransmitted_segments", ra.retransmitted_segments);
    w.field("retransmitted_bytes", ra.retransmitted_bytes);
    w.field("out_of_order_segments", ra.out_of_order_segments);
    w.field("overlap_bytes", ra.overlap_bytes);
    w.field("conflicting_overlap_bytes", ra.conflicting_overlap_bytes);
    w.field("gap_count", ra.gap_count);
    w.field("gap_bytes", ra.gap_bytes);
    w.field("acked_gap_bytes", ra.acked_gap_bytes);
    w.field("snaplen_missing_bytes", ra.snaplen_missing_bytes);
    w.field("out_of_window_segments", ra.out_of_window_segments);
    w.field("data_after_fin", ra.data_after_fin);
    w.field("data_after_rst", ra.data_after_rst);
    w.field("forced_flushes", ra.forced_flushes);
    w.field("evicted_flows", sr.evicted_flows);
    w.field("limits_hit", sr.limits_hit || ra.forced_flushes > 0);
    if (!r.deterministic) {
        // Depends on the shard count (sum of per-shard peaks), so it lives outside the
        // deterministic contract.
        w.field("peak_buffered_bytes", ra.peak_buffered_bytes);
    }
    w.end_object();

    w.key("talkers");
    w.begin_array();
    for (const auto& t : top_talkers(sr, 20)) {
        w.begin_object();
        w.field("address", format_ip(t.addr));
        w.field("bytes_sent", t.t.bytes_sent);
        w.field("bytes_received", t.t.bytes_received);
        w.field("flows", t.t.flows);
        w.end_object();
    }
    w.end_array();
    w.key("services");
    w.begin_array();
    for (const auto& s : top_services(sr, 20)) {
        w.begin_object();
        w.field("proto", proto_name(s.proto));
        w.field("port", s.port);
        w.field("label", service_label(s.proto, s.port));
        w.field("flows", s.s.flows);
        w.field("bytes", s.s.bytes);
        w.end_object();
    }
    w.end_array();

    if (!r.deterministic) {
        const auto& run = r.run;
        const double secs = static_cast<double>(run.elapsed_ns) / 1e9;
        w.key("run");
        w.begin_object();
        w.field("workers", run.workers);
        w.field("elapsed_ns", run.elapsed_ns);
        w.field("packets_per_sec", secs > 0 ? static_cast<double>(rs.packets()) / secs : 0.0);
        w.field("mib_per_sec",
                secs > 0 ? static_cast<double>(rs.captured_bytes()) / 1048576.0 / secs : 0.0);
        w.field("peak_rss_bytes", run.peak_rss_bytes);
        w.field("peak_flows", sr.peak_flows);
        w.key("host");
        w.begin_object();
        w.field("os", run.os);
        w.field("cpu_count", run.cpu_count);
        w.end_object();
        w.key("pipeline");
        w.begin_object();
        w.field("reader_stalls", run.reader_stalls);
        w.field("reader_stall_ns", run.reader_stall_ns);
        w.key("workers");
        w.begin_array();
        for (const auto& ws : run.worker_stats) {
            w.begin_object();
            w.field("packets", ws.packets);
            w.field("batches", ws.batches);
            w.field("idle_waits", ws.idle_waits);
            w.field("max_occupancy", ws.max_occupancy);
            w.end_object();
        }
        w.end_array();
        w.end_object();
        w.end_object();
    }
    w.end_object();
    return w.take();
}

} // namespace netprobe
