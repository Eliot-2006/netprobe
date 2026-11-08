// Standalone HTML report (PRD 8.2). One file, inline CSS and SVG, no scripts, no external
// requests. Every dynamic string goes through esc().

#include "report/report.h"

#include <algorithm>
#include <format>
#include <iterator>
#include <string>
#include <string_view>

namespace netprobe {
namespace {

#include "report/font_barlow.inc"

std::string esc(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out.push_back(c);
        }
    }
    return out;
}

std::string pct(std::uint64_t part, std::uint64_t whole) {
    if (whole == 0) {
        return "0%";
    }
    const double p = 100.0 * static_cast<double>(part) / static_cast<double>(whole);
    return p >= 10 || p == 0 ? std::format("{:.0f}%", p) : std::format("{:.1f}%", p);
}

std::string endpoint(const Endpoint& e) {
    const auto ip = format_ip(e.addr);
    return esc(e.addr.is_v4_mapped() ? std::format("{}:{}", ip, e.port)
                                     : std::format("[{}]:{}", ip, e.port));
}

constexpr std::string_view kStyle = R"CSS(
:root{color-scheme:light dark;
--bay:#e4e7ea;--rail:#262d33;--rail-ink:#eef0f1;--ink:#191c1f;--muted:#4c555d;--rule:#c9cfd4;
--tcp:#f1e7c9;--tcp-tab:#d6c088;--udp:#dde9f3;--udp-tab:#a9c3d9;--paper:#f7f8f9;--track:#e4e7ea;
--alert:#c2410c;--alert-ink:#9a3412;--alert-soft:#fde3d3;--bar:#4c555d;--line:#262d33;--have:#262d33;
--on-alert:#ffffff;
--cond:"NP Cond","Arial Narrow","Roboto Condensed",sans-serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root{
--bay:#101316;--rail:#030405;--rail-ink:#d9dde0;--ink:#e6e4dc;--muted:#a1a8ae;--rule:#2c3237;
--tcp:#2b281f;--tcp-tab:#4f4630;--udp:#1d2832;--udp-tab:#2f4254;--paper:#171b1f;--track:#22272c;
--alert:#fb7a45;--alert-ink:#fd9a6f;--alert-soft:#3a1f14;--bar:#8f979e;--line:#e6e4dc;--have:#b9b3a1;
--on-alert:#1f0d04}}
*{box-sizing:border-box}
html{background:var(--bay);color:var(--ink);font:15px/1.5 var(--sans);-webkit-text-size-adjust:100%}
body{margin:0 auto;max-width:1240px;padding:24px 20px 64px}
::selection{background:var(--tcp-tab);color:var(--ink)}
:focus-visible{outline:2px solid var(--alert);outline-offset:2px}
.num,td.n,th.n{font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
.mono{font-family:var(--mono);font-size:.92em}
.desig{font-family:var(--cond);font-weight:700;font-size:1.08em;letter-spacing:.02em}
.nw{white-space:nowrap}
header.capture{background:var(--rail);padding:5px}
.capstrip{display:grid;grid-template-columns:auto 1fr;background:var(--tcp)}
.capstrip .tab{background:var(--tcp-tab);color:var(--ink);writing-mode:vertical-rl;transform:rotate(180deg);
font:700 .85rem/1 var(--cond);letter-spacing:.14em;text-transform:uppercase;padding:14px 10px;
text-align:center}
.capstrip .tab.bad{background:var(--alert);color:var(--on-alert)}
.capstrip .body{padding:14px 18px 12px;min-width:0}
header.capture h1{margin:0;font:700 2.1rem/1.15 var(--cond);letter-spacing:.01em;overflow-wrap:anywhere}
dl.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));margin:12px 0 0;
border-top:1px solid var(--rule)}
dl.figs div{padding:8px 12px 2px 0;border-right:1px solid var(--rule);padding-left:12px}
dl.figs div:first-child{padding-left:0}
dl.figs div:last-child{border-right:0}
dl.figs dt{font:700 .8rem/1.2 var(--cond);letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
dl.figs dd{margin:2px 0 0;font-size:1.1rem;font-variant-numeric:tabular-nums;font-weight:600}
dl.figs dd.bad{color:var(--alert-ink)}
.capmeta{margin:10px 0 0;color:var(--muted);font-size:.82rem;display:flex;flex-wrap:wrap;gap:2px 14px}
section{margin-top:36px}
section>h2{margin:0 0 10px;font:700 1.45rem/1.2 var(--cond);letter-spacing:.02em;display:flex;
flex-wrap:wrap;align-items:baseline;gap:4px 14px}
section>h2 small{font:400 .82rem/1.3 var(--sans);color:var(--muted);letter-spacing:0}
p.note{margin:8px 0 0;color:var(--muted);font-size:.85rem;max-width:75ch}
.holder{background:var(--rail);padding:4px;display:grid;gap:4px}
ul.warn{list-style:none;margin:0}
ul.warn li{display:grid;grid-template-columns:auto 1fr;gap:12px;align-items:baseline;background:var(--paper);
padding:10px 14px}
.tag{font:700 .8rem/1.4 var(--cond);letter-spacing:.08em;text-transform:uppercase;color:var(--on-alert);
background:var(--alert);padding:0 7px}
.tag.ok{background:var(--tcp-tab);color:var(--ink)}
.panel{background:var(--paper);padding:14px 16px;border-top:3px solid var(--rail)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
svg{display:block;width:100%;height:auto}
.tl .bars rect{fill:var(--tcp-tab)}
.tl .bytes{fill:none;stroke:var(--line);stroke-width:1.6;vector-effect:non-scaling-stroke}
.tl svg{height:clamp(110px,18vw,190px)}
.tl .axis{stroke:var(--rule);stroke-width:1;vector-effect:non-scaling-stroke}
.axisrow{display:flex;justify-content:space-between;color:var(--muted);font-size:.75rem;
font-variant-numeric:tabular-nums;margin-top:4px}
.legend{display:flex;flex-wrap:wrap;gap:16px;font-size:.8rem;color:var(--muted);margin-top:6px}
.legend i{display:inline-block;width:12px;height:8px;vertical-align:middle;margin-right:6px;background:var(--tcp-tab)}
.legend i.l{height:2px;background:var(--line)}
.hbar{display:grid;grid-template-columns:minmax(90px,max-content) 1fr minmax(70px,max-content) 48px;
gap:5px 12px;align-items:center;font-size:.88rem}
.hbar .track{height:9px;background:var(--track);overflow:hidden}
.hbar .track span{display:block;height:100%;background:var(--bar)}
.hbar .track span.e{background:var(--alert)}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.88rem;background:var(--paper);border-top:3px solid var(--rail)}
caption{caption-side:top;text-align:left;font:700 1rem/1.3 var(--cond);letter-spacing:.02em;
color:var(--muted);padding:0 0 6px}
thead th{text-align:left;font:700 .8rem/1.2 var(--cond);letter-spacing:.06em;text-transform:uppercase;
color:var(--muted);padding:8px 10px 6px;white-space:nowrap;border-bottom:1px solid var(--rule)}
tbody td,tbody th{padding:7px 10px;border-bottom:1px solid var(--rule);text-align:left;font-weight:400}
tbody tr:last-child>*{border-bottom:0}
table.strips{background:var(--rail);border-top:0;border-collapse:separate;border-spacing:0 4px;
padding:0 4px}
table.strips thead th{color:var(--rail-ink);border-bottom:0;padding-top:6px}
table.strips tbody td{background:var(--tcp);border-bottom:0}
table.strips tbody tr.udp td{background:var(--udp)}
table.strips td.tab{background:var(--tcp-tab);font:700 .82rem/1 var(--cond);letter-spacing:.1em;
text-transform:uppercase;width:1%;white-space:nowrap}
table.strips tr.udp td.tab{background:var(--udp-tab)}
td.flow{min-width:260px}
td.flow .id{margin-right:8px}
.bad-t{color:var(--alert-ink);font-weight:600}
.strip{display:grid;grid-template-columns:auto 1fr;background:var(--tcp)}
.strip .tab{background:var(--tcp-tab);padding:10px 8px;writing-mode:vertical-rl;transform:rotate(180deg);
font:700 .78rem/1 var(--cond);letter-spacing:.14em;text-align:center}
.strip .body{padding:10px 14px 12px;min-width:0}
.strip .head{display:flex;flex-wrap:wrap;gap:4px 14px;align-items:baseline}
.gauge{display:grid;grid-template-columns:44px 1fr;gap:4px 10px;align-items:center;margin-top:8px}
.gauge .dir{font:700 .82rem/1 var(--cond);letter-spacing:.08em;color:var(--muted)}
.gauge svg{height:16px}
.gauge .track{fill:var(--track)}
.gauge .have{fill:var(--have)}
.gauge .gap{fill:url(#hatch);stroke:var(--alert);stroke-width:1;vector-effect:non-scaling-stroke}
.gauge .gap.unacked{fill:var(--tcp)}
.gauge .meta{grid-column:2;font-size:.8rem;color:var(--muted)}
.gauge .ranges{grid-column:2;font-size:.78rem;color:var(--muted);margin:0;padding:0;list-style:none;
display:flex;flex-wrap:wrap;gap:2px 14px}
.empty{color:var(--muted);font-size:.9rem;margin:0}
footer{margin-top:40px;color:var(--muted);font-size:.8rem}
@media (max-width:600px){body{padding:16px 12px 48px}header.capture h1{font-size:1.7rem}
dl.figs div{border-right:0;padding-left:0}
.hbar{grid-template-columns:minmax(80px,max-content) 1fr minmax(56px,max-content)}.hbar .p{display:none}}
)CSS";

class Page {
public:
    explicit Page(const Report& r) : r_(r), rs_(*r.reader), c_(rs_.counters()), sr_(*r.flows) {}
    std::string render();

private:
    void header();
    void warnings();
    void timeline();
    void protocols();
    void errors();
    void outcomes();
    void incomplete();
    void top_flows();
    void talkers_services();
    void details();
    void gauge(std::string_view dir, const DirSummary& d, std::uint64_t scale);

    template <class... A> void out(std::format_string<A...> fmt, A&&... a) {
        std::format_to(std::back_inserter(s_), fmt, std::forward<A>(a)...);
    }

    const Report& r_;
    const ReaderStats& rs_;
    const DecodeCounters& c_;
    const ShardResult& sr_;
    std::string s_;
};

std::string Page::render() {
    s_.reserve(256 << 10);
    out("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>NetProbe &middot; {}</title><style>@font-face{{font-family:\"NP Cond\";"
        "font-weight:700;font-display:swap;src:url(data:font/woff2;base64,{}) format(\"woff2\")}}"
        "{}</style></head><body>\n",
        esc(r_.capture.path), kBarlowWoff2Base64, kStyle);
    // Shared hatch pattern for ACKed gaps.
    out("<svg width=\"0\" height=\"0\" style=\"position:absolute\" aria-hidden=\"true\"><defs>"
        "<pattern id=\"hatch\" width=\"6\" height=\"6\" patternUnits=\"userSpaceOnUse\" "
        "patternTransform=\"rotate(45)\"><rect width=\"6\" height=\"6\" "
        "style=\"fill:var(--alert-soft)\"/><rect width=\"2.5\" height=\"6\" "
        "style=\"fill:var(--alert)\"/></pattern></defs></svg>\n");
    header();
    warnings();
    timeline();
    protocols();
    errors();
    outcomes();
    top_flows();
    incomplete();
    talkers_services();
    details();
    out("<footer>Generated by netprobe {}. Service names are port-number heuristics. Byte counts "
        "are frame lengths on the wire unless labeled payload.</footer>\n</body></html>\n",
        NETPROBE_VERSION);
    return std::move(s_);
}

void Page::header() {
    const auto& cap = r_.capture;
    const bool ok = cap.status == CaptureStatus::complete;
    std::string name = cap.path;
    if (auto slash = name.find_last_of('/'); slash != std::string::npos) {
        name = name.substr(slash + 1);
    }
    const auto& fc = sr_.flows;
    const auto errs = c_.total_errors();
    out("<header class=\"capture\"><div class=\"capstrip\"><div class=\"tab{}\">{}</div>"
        "<div class=\"body\"><h1 title=\"{}\">{}</h1>\n<dl class=\"figs\">",
        ok ? "" : " bad", to_string(cap.status), esc(cap.path), esc(name));
    auto fig = [&](std::string_view k, const std::string& v, bool bad = false) {
        out("<div><dt>{}</dt><dd class=\"{}\">{}</dd></div>", k, bad ? "bad" : "", v);
    };
    fig("Packets", format_count(rs_.packets()));
    fig("Bytes on wire", esc(format_bytes(rs_.original_bytes())));
    fig("Span", format_duration(rs_.packets() ? rs_.last_ts_ns() - rs_.first_ts_ns() : 0));
    fig("Flows", std::format("{} TCP &middot; {} UDP", format_count(fc.tcp_total),
                             format_count(fc.udp_total)));
    fig("Decode errors", format_count(errs), errs > 0);
    fig("Missing TCP bytes", esc(format_bytes(sr_.reassembly.gap_bytes)),
        sr_.reassembly.gap_bytes > 0);
    out("</dl>\n<p class=\"capmeta\"><span class=\"nw\">NetProbe {}</span><span class=\"nw\">"
        "{} &ndash;</span><span class=\"nw\">{} UTC</span><span class=\"nw\">pcap {}.{} "
        "{}</span><span class=\"nw\">{}"
        "</span><span class=\"nw\">snaplen {}</span></p></div></div></header>\n",
        NETPROBE_VERSION, rs_.packets() ? format_iso8601(rs_.first_ts_ns()) : "&ndash;",
        rs_.packets() ? format_iso8601(rs_.last_ts_ns()) : "&ndash;", cap.info.ver_major,
        cap.info.ver_minor, cap.info.precision == TsPrecision::nano ? "nsec" : "usec",
        link_type_name(cap.info.link_type), cap.info.snaplen);
}

void Page::warnings() {
    struct W {
        std::string tag, text;
    };
    std::vector<W> w;
    const auto& cap = r_.capture;
    const auto& ra = sr_.reassembly;
    if (cap.status != CaptureStatus::complete) {
        w.push_back(
            {std::string(to_string(cap.status)),
             std::format("The file ends early ({} trailing bytes could not be read). This "
                         "report covers the first {} records.",
                         format_count(cap.truncated_tail_bytes), format_count(rs_.packets()))});
    }
    if (sr_.limits_hit || ra.forced_flushes > 0) {
        w.push_back(
            {"limits",
             std::format("Memory limits were reached: {} forced stream flushes and {} "
                         "evicted flows. Raise --max-stream-buffer, "
                         "--max-reassembly-memory or --max-flows for exact results.",
                         format_count(ra.forced_flushes), format_count(sr_.evicted_flows))});
    }
    const auto errs = c_.total_errors();
    if (errs > 0) {
        w.push_back({"decode", std::format("{} records ({} of the capture) could not be fully "
                                           "decoded. See Decode errors below.",
                                           format_count(errs), pct(errs, rs_.packets()))});
    }
    if (sr_.flows.tcp_with_gaps > 0) {
        w.push_back({"gaps", std::format("{} TCP flow{} missing {} of stream data; {} of it was "
                                         "acknowledged by the receiver, so the capture dropped it.",
                                         format_count(sr_.flows.tcp_with_gaps),
                                         sr_.flows.tcp_with_gaps == 1 ? " is" : "s are",
                                         esc(format_bytes(ra.gap_bytes)),
                                         esc(format_bytes(ra.acked_gap_bytes)))});
    }
    if (cap.counters.records_truncated_by_snaplen > 0) {
        w.push_back(
            {"snaplen", std::format("{} records were captured shorter than they were on the "
                                    "wire (snaplen {}), so their payload is partial.",
                                    format_count(cap.counters.records_truncated_by_snaplen),
                                    cap.info.snaplen)});
    }
    if (cap.counters.timestamp_regressions > 0) {
        w.push_back({"time", std::format("{} records have timestamps earlier than the record "
                                         "before them.",
                                         format_count(cap.counters.timestamp_regressions))});
    }
    out("<section aria-labelledby=\"h-warn\"><h2 id=\"h-warn\">Findings</h2><ul class=\"warn "
        "holder\">");
    if (w.empty()) {
        out("<li><span class=\"tag ok\">clear</span><span>Capture complete, every record decoded, "
            "and every TCP stream reassembled without missing bytes.</span></li>");
    }
    for (const auto& x : w) {
        out("<li><span class=\"tag\">{}</span><span>{}</span></li>", esc(x.tag), x.text);
    }
    out("</ul></section>\n");
}

void Page::timeline() {
    const auto& tl = rs_.timeline();
    const auto buckets = tl.buckets();
    out("<section aria-labelledby=\"h-tl\"><h2 id=\"h-tl\">Traffic over time<small>{} per bar"
        "</small></h2><div class=\"panel tl\">",
        format_duration(tl.width_ns()));
    if (buckets.empty()) {
        out("<p class=\"empty\">No packets.</p></div></section>\n");
        return;
    }
    std::uint64_t maxp = 1, maxb = 1;
    for (const auto& b : buckets) {
        maxp = std::max(maxp, b.packets);
        maxb = std::max(maxb, b.bytes);
    }
    constexpr double W = 1000, H = 162, top = 8, base = 160;
    const double bw = W / static_cast<double>(buckets.size());
    out("<svg viewBox=\"0 0 {} {}\" preserveAspectRatio=\"none\" role=\"img\" "
        "aria-labelledby=\"tl-t\"><title id=\"tl-t\">Packets per {} (bars) and bytes (line) "
        "across the capture; peak {} packets and {} in one bucket.</title>"
        "<line class=\"axis\" x1=\"0\" x2=\"{}\" y1=\"{}\" y2=\"{}\"/><g class=\"bars\">",
        W, H, format_duration(tl.width_ns()), format_count(maxp), esc(format_bytes(maxb)), W, base,
        base);
    std::string line;
    for (std::size_t i = 0; i < buckets.size(); ++i) {
        const auto& b = buckets[i];
        const double h = (base - top) * static_cast<double>(b.packets) / static_cast<double>(maxp);
        const double x = static_cast<double>(i) * bw;
        if (b.packets > 0) {
            out("<rect x=\"{:.2f}\" y=\"{:.2f}\" width=\"{:.2f}\" height=\"{:.2f}\"><title>+{}: "
                "{} packets, {}</title></rect>",
                x + bw * 0.1, base - h, std::max(bw * 0.8, 0.6), h,
                format_duration(static_cast<std::int64_t>(i) * tl.width_ns()),
                format_count(b.packets), esc(format_bytes(b.bytes)));
        }
        const double y =
            base - (base - top) * static_cast<double>(b.bytes) / static_cast<double>(maxb);
        line += std::format("{:.2f},{:.2f} ", x + bw / 2, y);
    }
    out("</g><polyline class=\"bytes\" points=\"{}\"/>"
        "</svg><div class=\"axisrow\"><span>0</span><span>+{}</span></div><div "
        "class=\"legend\"><span><i></i>packets (peak {})</span>"
        "<span><i class=\"l\"></i>bytes (peak {})</span></div></div></section>\n",
        line, format_duration(static_cast<std::int64_t>(buckets.size()) * tl.width_ns()),
        format_count(maxp), esc(format_bytes(maxb)));
}

void Page::protocols() {
    const auto total = std::max<std::uint64_t>(rs_.packets(), 1);
    struct Row {
        std::string_view name;
        std::uint64_t n;
    };
    const Row layers[] = {{"Ethernet", c_.ethernet},
                          {"VLAN-tagged", c_.vlan_tagged},
                          {"IPv4", c_.ipv4},
                          {"IPv6", c_.ipv6},
                          {"TCP", c_.tcp},
                          {"UDP", c_.udp},
                          {"ICMP", c_.icmp + c_.icmpv6},
                          {"ARP", c_.arp},
                          {"IP fragments", c_.ip_fragments},
                          {"Other EtherType", c_.other_ethertype},
                          {"Other IP protocol", c_.other_ip_proto}};
    out("<section aria-labelledby=\"h-proto\"><h2 id=\"h-proto\">Protocols<small>share of {} "
        "records</small></h2><div class=\"panel\"><div class=\"hbar\">",
        format_count(rs_.packets()));
    for (const auto& l : layers) {
        if (l.n == 0) {
            continue;
        }
        const double w = 100.0 * static_cast<double>(l.n) / static_cast<double>(total);
        out("<span>{}</span><span class=\"track\" role=\"presentation\"><span style=\"width:"
            "{:.2f}%\"></span></span><span class=\"num\">{}</span><span class=\"num p\">{}</span>",
            l.name, w, format_count(l.n), pct(l.n, total));
    }
    const auto errs = c_.total_errors();
    if (errs > 0) {
        out("<span class=\"bad-t\">Decode errors</span><span class=\"track\" role=\"presentation\">"
            "<span class=\"e\" style=\"width:{:.2f}%\"></span></span><span class=\"num\">{}</span>"
            "<span class=\"num p\">{}</span>",
            100.0 * static_cast<double>(errs) / static_cast<double>(total), format_count(errs),
            pct(errs, total));
    }
    out("</div></div></section>\n");
}

void Page::errors() {
    out("<section aria-labelledby=\"h-err\"><h2 id=\"h-err\">Decode errors and anomalies</h2>");
    std::string rows;
    for (std::size_t k = 1; k < DecodeCounters::kKinds; ++k) {
        for (std::size_t l = 0; l < DecodeCounters::kLayers; ++l) {
            for (std::size_t rr = 0; rr < DecodeCounters::kReasons; ++rr) {
                const auto n = c_.error_count(static_cast<DecodeKind>(k), static_cast<Layer>(l),
                                              static_cast<Reason>(rr));
                if (n > 0) {
                    rows += std::format("<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td>"
                                        "<td class=\"n\">{}</td></tr>",
                                        to_string(static_cast<DecodeKind>(k)),
                                        to_string(static_cast<Layer>(l)),
                                        to_string(static_cast<Reason>(rr)), format_count(n));
                }
            }
        }
    }
    auto anomaly = [&](std::string_view what, std::uint64_t n) {
        if (n > 0) {
            rows += std::format("<tr><td>anomaly</td><td>&ndash;</td><td>{}</td>"
                                "<td class=\"n\">{}</td></tr>",
                                what, format_count(n));
        }
    };
    const auto& pc = r_.capture.counters;
    anomaly("IPv4 header checksum wrong (packet still processed)", c_.ipv4_bad_checksum);
    anomaly("IP length field zero, captured length used (TSO)", c_.ip_zero_length);
    anomaly("UDP datagram shorter than IP payload", c_.udp_trailing_bytes);
    anomaly("TCP options malformed (segment still processed)", c_.tcp_options_malformed);
    anomaly("Invalid TCP flag combination, not reassembled", c_.tcp_flags_invalid);
    anomaly("Record longer than original length", pc.incl_gt_orig);
    anomaly("Timestamp fraction out of range", pc.ts_fraction_overflow);
    if (rows.empty()) {
        out("<p class=\"empty\">None. Every record decoded cleanly.</p></section>\n");
        return;
    }
    out("<div class=\"scroll\"><table><thead><tr><th scope=\"col\">Kind</th><th scope=\"col\">"
        "Layer</th><th scope=\"col\">Reason</th><th scope=\"col\" class=\"n\">Records</th></tr>"
        "</thead><tbody>{}</tbody></table></div></section>\n",
        rows);
}

void Page::outcomes() {
    const auto& fc = sr_.flows;
    auto ci = [](CloseReason c) { return static_cast<std::size_t>(c); };
    out("<section aria-labelledby=\"h-out\"><h2 id=\"h-out\">Flow outcomes</h2><div "
        "class=\"grid2\">"
        "<div class=\"panel\"><div class=\"hbar\">");
    const auto t = std::max<std::uint64_t>(fc.tcp_total, 1);
    auto bar = [&](std::string_view label, std::uint64_t n, std::uint64_t whole, bool bad) {
        out("<span{}>{}</span><span class=\"track\" role=\"presentation\"><span{} style=\"width:"
            "{:.2f}%\"></span></span><span class=\"num\">{}</span><span class=\"num p\">{}</span>",
            bad && n ? " class=\"bad-t\"" : "", label, bad ? " class=\"e\"" : "",
            100.0 * static_cast<double>(n) / static_cast<double>(whole), format_count(n),
            pct(n, whole));
    };
    bar("TCP complete", fc.tcp_complete, t, false);
    bar("TCP with gaps", fc.tcp_with_gaps, t, true);
    bar("Full handshake", fc.handshake_full, t, false);
    bar("Partial handshake", fc.handshake_partial, t, false);
    bar("No handshake seen", fc.handshake_none, t, false);
    out("</div></div><div class=\"panel\"><div class=\"hbar\">");
    bar("Closed by FIN", fc.tcp_close[ci(CloseReason::fin)], t, false);
    bar("Reset (RST)", fc.tcp_close[ci(CloseReason::rst)], t, false);
    bar("Idle timeout", fc.tcp_close[ci(CloseReason::idle_timeout)], t, false);
    bar("Open at end", fc.tcp_close[ci(CloseReason::end_of_capture)], t, false);
    bar("Port reused", fc.tcp_close[ci(CloseReason::reused)], t, false);
    bar("Evicted (limit)", fc.tcp_close[ci(CloseReason::evicted)], t, true);
    out("</div></div></div></section>\n");
}

// Draws one direction on a scale shared by both directions of the flow, so bar length is the
// stream's true size relative to its peer (the stream gauge is drawn to scale).
void Page::gauge(std::string_view dir, const DirSummary& d, std::uint64_t scale) {
    const auto& s = d.stream;
    const std::uint64_t extent = s.delivered_bytes + s.gap_bytes;
    const double unit = 1000.0 / static_cast<double>(std::max<std::uint64_t>(scale, 1));
    std::string gaps, ranges;
    for (const auto& g : s.gaps) {
        const double x = unit * static_cast<double>(g.offset);
        const double w = std::max(unit * static_cast<double>(g.length), 2.0);
        gaps += std::format("<rect class=\"gap{}\" x=\"{:.2f}\" y=\"1\" width=\"{:.2f}\" "
                            "height=\"14\"><title>missing {} bytes at offset {}{}</title></rect>",
                            g.acked ? "" : " unacked", x, w, format_count(g.length),
                            format_count(g.offset), g.acked ? ", ACKed by receiver" : "");
        if (ranges.size() < 600) {
            ranges +=
                std::format("<li class=\"nw\">bytes {}&ndash;{} {}</li>", format_count(g.offset),
                            format_count(g.offset + g.length - 1), // inclusive end
                            g.acked ? "ACKed" : "not ACKed");
        }
    }
    std::string meta = std::format("{} delivered", esc(format_bytes(s.delivered_bytes)));
    if (s.gap_count > 0) {
        meta += std::format(" &middot; <span class=\"bad-t\">{} gap{}, {} missing</span>",
                            format_count(s.gap_count), s.gap_count == 1 ? "" : "s",
                            esc(format_bytes(s.gap_bytes)));
        if (s.gaps_truncated) {
            meta += std::format(" &middot; first {} shown", s.gaps.size());
        }
    }
    if (s.retransmitted_bytes > 0) {
        meta += std::format(" &middot; {} retransmitted", esc(format_bytes(s.retransmitted_bytes)));
    }
    if (s.conflicting_overlap_bytes > 0) {
        meta += std::format(" &middot; <span class=\"bad-t\">{} conflicting overlap bytes</span>",
                            format_count(s.conflicting_overlap_bytes));
    }
    out("<div class=\"gauge\"><span class=\"dir\">{}</span><svg viewBox=\"0 0 1000 16\" "
        "preserveAspectRatio=\"none\" role=\"img\" aria-label=\"{} stream: {} of {} bytes "
        "present\"><rect class=\"track\" x=\"0\" y=\"3\" width=\"1000\" height=\"10\"/>"
        "<rect class=\"have\" x=\"0\" y=\"3\" width=\"{:.2f}\" height=\"10\"/>{}</svg>"
        "<span class=\"meta\">{}</span>{}</div>",
        dir, dir, format_count(s.delivered_bytes), format_count(extent),
        unit * static_cast<double>(extent), gaps, meta,
        ranges.empty() ? std::string() : "<ul class=\"ranges\">" + ranges + "</ul>");
}

void Page::incomplete() {
    const auto flows = sr_.top_incomplete.sorted();
    out("<section aria-labelledby=\"h-inc\"><h2 id=\"h-inc\">Incomplete TCP streams<small>{} "
        "flow{}; both directions of a flow share one scale, gaps cut out</small></h2>",
        format_count(sr_.flows.tcp_with_gaps), sr_.flows.tcp_with_gaps == 1 ? "" : "s");
    if (flows.empty()) {
        out("<p class=\"empty\">None. No TCP stream is missing bytes.</p></section>\n");
        return;
    }
    out("<div class=\"holder\">");
    const std::size_t n = std::min<std::size_t>(flows.size(), 50);
    for (std::size_t i = 0; i < n; ++i) {
        const auto& f = flows[i];
        out("<article class=\"strip\" aria-label=\"flow {}\"><div class=\"tab\">TCP</div>"
            "<div class=\"body\"><div class=\"head\"><span class=\"desig\">#{}</span>"
            "<span class=\"mono\">{} &rarr; {}</span><span class=\"bad-t\">{} missing</span>"
            "<span>{} &middot; {}</span></div>",
            f.id, f.id, endpoint(f.client), endpoint(f.server),
            esc(format_bytes(f.missing_bytes())), to_string(f.close), to_string(f.integrity));
        const std::uint64_t scale = std::max(f.c2s.stream.delivered_bytes + f.c2s.stream.gap_bytes,
                                             f.s2c.stream.delivered_bytes + f.s2c.stream.gap_bytes);
        gauge("C&rarr;S", f.c2s, scale);
        gauge("S&rarr;C", f.s2c, scale);
        out("</div></article>");
    }
    out("</div>");
    if (flows.size() > n) {
        out("<p class=\"note\">{} more incomplete flows are listed in the JSON report.</p>",
            format_count(flows.size() - n));
    }
    out("<p class=\"note\">Hatched gaps were acknowledged by the receiver: the bytes were sent but "
        "the capture missed them. Outlined gaps were never acknowledged.</p></section>\n");
}

void Page::top_flows() {
    const auto flows = sr_.top_bytes.sorted();
    out("<section aria-labelledby=\"h-top\"><h2 id=\"h-top\">Top flows by bytes<small>{} of {} "
        "shown</small></h2>",
        std::min<std::size_t>(flows.size(), 100),
        format_count(sr_.flows.tcp_total + sr_.flows.udp_total));
    if (flows.empty()) {
        out("<p class=\"empty\">No TCP or UDP flows.</p></section>\n");
        return;
    }
    out("<div class=\"scroll\"><table class=\"strips\"><thead><tr><th scope=\"col\">Proto</th>"
        "<th scope=\"col\">Flow</th><th scope=\"col\" class=\"n\">Packets</th><th scope=\"col\" "
        "class=\"n\">Bytes</th><th scope=\"col\" class=\"n\">Duration</th><th scope=\"col\">Close"
        "</th><th scope=\"col\">Stream</th></tr></thead><tbody>");
    for (std::size_t i = 0; i < flows.size() && i < 100; ++i) {
        const auto& f = flows[i];
        const bool tcp = f.is_tcp();
        const bool bad = tcp && f.missing_bytes() > 0;
        out("<tr class=\"{}\"><td class=\"tab\">{}</td><td class=\"flow\"><span class=\"desig "
            "id\">#{}</span><span class=\"mono\">{} {} {}</span></td><td class=\"n\">{}</td>"
            "<td class=\"n\">{}</td><td class=\"n\">{}</td><td>{}</td><td{}>{}</td></tr>",
            tcp ? "tcp" : "udp", tcp ? "TCP" : "UDP", f.id, endpoint(f.client),
            f.orientation_handshake ? "&rarr;" : "&harr;", endpoint(f.server),
            format_count(f.c2s.packets + f.s2c.packets), esc(format_bytes(f.bytes())),
            format_duration(f.last_ts_ns - f.first_ts_ns), to_string(f.close),
            bad ? " class=\"bad-t\"" : "",
            tcp ? (bad ? std::format("{} missing", esc(format_bytes(f.missing_bytes())))
                       : std::string(to_string(f.integrity)))
                : std::string("&ndash;"));
    }
    out("</tbody></table></div><p class=\"note\">&rarr; client to server, from the TCP handshake. "
        "&harr; orientation guessed from the first packet.</p></section>\n");
}

void Page::talkers_services() {
    out("<section aria-labelledby=\"h-tk\"><h2 id=\"h-tk\">Talkers and services</h2>"
        "<div class=\"grid2\"><div class=\"scroll\"><table><caption class=\"note\" "
        "style=\"text-align:left\">Top addresses by bytes</caption><thead><tr><th scope=\"col\">"
        "Address</th><th scope=\"col\" class=\"n\">Sent</th><th scope=\"col\" class=\"n\">"
        "Received</th><th scope=\"col\" class=\"n\">Flows</th></tr></thead><tbody>");
    for (const auto& t : top_talkers(sr_, 20)) {
        out("<tr><td class=\"mono\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td>"
            "<td class=\"n\">{}</td></tr>",
            esc(format_ip(t.addr)), esc(format_bytes(t.t.bytes_sent)),
            esc(format_bytes(t.t.bytes_received)), format_count(t.t.flows));
    }
    out("</tbody></table></div><div class=\"scroll\"><table><caption class=\"note\" "
        "style=\"text-align:left\">Top services by bytes (name guessed from port)</caption><thead>"
        "<tr><th scope=\"col\">Port</th><th scope=\"col\">Service</th><th scope=\"col\" "
        "class=\"n\">Flows</th><th scope=\"col\" class=\"n\">Bytes</th></tr></thead><tbody>");
    for (const auto& s : top_services(sr_, 20)) {
        const auto label = service_label(s.proto, s.port);
        out("<tr><td class=\"mono\">{}/{}</td><td>{}</td><td class=\"n\">{}</td>"
            "<td class=\"n\">{}</td></tr>",
            s.proto == ip_proto::tcp ? "tcp" : "udp", s.port,
            label.empty() ? std::string_view("&ndash;") : label, format_count(s.s.flows),
            esc(format_bytes(s.s.bytes)));
    }
    out("</tbody></table></div></div></section>\n");
}

void Page::details() {
    const auto& ra = sr_.reassembly;
    out("<section aria-labelledby=\"h-det\"><h2 id=\"h-det\">Reassembly and run details</h2>"
        "<div class=\"grid2\"><div class=\"scroll\"><table><tbody>");
    auto row = [&](std::string_view k, const std::string& v) {
        out("<tr><th scope=\"row\" style=\"text-align:left;font-weight:400\">{}</th>"
            "<td class=\"n\">{}</td></tr>",
            k, v);
    };
    row("Stream bytes delivered", esc(format_bytes(ra.delivered_bytes)));
    row("Retransmitted bytes", esc(format_bytes(ra.retransmitted_bytes)));
    row("Out-of-order segments", format_count(ra.out_of_order_segments));
    row("Overlapping bytes (conflicting)", std::format("{} ({})", format_count(ra.overlap_bytes),
                                                       format_count(ra.conflicting_overlap_bytes)));
    row("Gaps (bytes ACKed by receiver)",
        std::format("{} ({})", format_count(ra.gap_count), esc(format_bytes(ra.acked_gap_bytes))));
    row("Bytes cut by snaplen", esc(format_bytes(ra.snaplen_missing_bytes)));
    row("Out-of-window segments", format_count(ra.out_of_window_segments));
    row("Data after FIN / RST",
        std::format("{} / {}", format_count(ra.data_after_fin), format_count(ra.data_after_rst)));
    row("Forced flushes / evicted flows",
        std::format("{} / {}", format_count(ra.forced_flushes), format_count(sr_.evicted_flows)));
    out("</tbody></table></div><div class=\"scroll\"><table><tbody>");
    const auto& o = *r_.options;
    row("Idle timeout", std::format("{} s", o.idle_timeout_s));
    row("Max concurrent flows", format_count(o.max_flows));
    row("Stream buffer / total budget",
        std::format("{} / {}", esc(format_bytes(o.max_stream_buffer)),
                    esc(format_bytes(o.max_reassembly_memory))));
    if (!r_.deterministic) {
        const auto& run = r_.run;
        const double secs = static_cast<double>(run.elapsed_ns) / 1e9;
        row("Workers", run.workers == 0 ? std::string("inline") : std::to_string(run.workers));
        row("Elapsed", std::format("{:.3f} s", secs));
        row("Throughput",
            secs > 0 ? std::format("{} packets/s", format_count(static_cast<std::uint64_t>(
                                                       static_cast<double>(rs_.packets()) / secs)))
                     : std::string("&ndash;"));
        row("Peak memory (RSS)", esc(format_bytes(run.peak_rss_bytes)));
        row("Peak reassembly buffer", esc(format_bytes(ra.peak_buffered_bytes)));
        row("Host", esc(run.os));
    }
    out("</tbody></table></div></div></section>\n");
}

} // namespace

std::string render_html(const Report& r) {
    return Page(r).render();
}

} // namespace netprobe
