#include "app.h"

#include "analysis/analyzer.h"
#include "analysis/reader_stats.h"
#include "decode/decode.h"
#include "io/mapped_file.h"
#include "pcap/reader.h"
#include "report/report.h"

#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <stdexcept>
#include <thread>

namespace netprobe {
namespace {

namespace fs = std::filesystem;

struct OutputError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Writes to a temp file in the target directory, then renames: never leaves a partial report.
void write_file_atomic(const std::string& path, const std::string& content) {
    if (path == "-") {
        if (std::fwrite(content.data(), 1, content.size(), stdout) != content.size() ||
            std::fflush(stdout) != 0) {
            throw OutputError("cannot write to stdout");
        }
        return;
    }
    const fs::path target(path);
    fs::path tmp = target;
    tmp += std::format(".tmp-{}", ::getpid());
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        f.close();
        if (!f) {
            std::error_code ec;
            fs::remove(tmp, ec);
            throw OutputError(std::format("cannot write '{}'", path));
        }
    }
    std::error_code ec;
    fs::rename(tmp, target, ec);
    if (ec) {
        fs::remove(tmp, ec);
        throw OutputError(std::format("cannot write '{}': {}", path, ec.message()));
    }
}

std::uint64_t peak_rss_bytes() {
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) != 0) {
        return 0;
    }
#if defined(__APPLE__)
    return static_cast<std::uint64_t>(ru.ru_maxrss); // bytes
#else
    return static_cast<std::uint64_t>(ru.ru_maxrss) * 1024; // KiB
#endif
}

std::string os_name() {
    utsname u{};
    if (uname(&u) != 0) {
        return "unknown";
    }
    return std::format("{} {} {}", u.sysname, u.release, u.machine);
}

struct OpenedCapture {
    MappedFile file;
    PcapReader reader;
};

// Prints the error and returns nullopt on fatal input errors (exit 2).
std::optional<OpenedCapture> open_capture(const std::string& path) {
    try {
        MappedFile file = MappedFile::open(path);
        auto res = PcapReader::open(file.bytes());
        if (res.error != OpenError::none) {
            std::fprintf(stderr, "netprobe: %s: %s\n", path.c_str(), res.message.c_str());
            return std::nullopt;
        }
        return OpenedCapture{std::move(file), std::move(*res.reader)};
    } catch (const InputError& e) {
        std::fprintf(stderr, "netprobe: %s\n", e.what());
        return std::nullopt;
    }
}

} // namespace

int run_analyze(const AnalyzeOptions& o) {
    if (o.workers > 0) {
        // ponytail: pipeline lands in M9; until then N > 0 runs inline with identical output.
    }
    const auto t0 = std::chrono::steady_clock::now();
    auto cap = open_capture(o.input);
    if (!cap) {
        return exit_input;
    }

    AnalyzerConfig cfg;
    cfg.idle_timeout_ns = static_cast<std::int64_t>(o.idle_timeout_s) * 1'000'000'000;
    cfg.max_flows = o.max_flows;
    cfg.max_stream_buffer = o.max_stream_buffer;
    cfg.reassembly_budget = o.max_reassembly_memory;
    cfg.top_k = static_cast<std::size_t>(o.top_flows);
    if (o.export_dir) {
        std::error_code ec;
        fs::create_directories(*o.export_dir, ec);
        if (ec || !fs::is_directory(*o.export_dir)) {
            std::fprintf(stderr, "netprobe: cannot create export directory '%s'\n",
                         o.export_dir->c_str());
            return exit_output;
        }
        cfg.export_dir = fs::path(*o.export_dir);
    }

    ReaderStats reader_stats;
    Analyzer analyzer(cfg);
    PacketRecord rec;
    while (cap->reader.next(rec)) {
        const DecodedPacket pkt = decode_packet(rec);
        reader_stats.add(rec, pkt);
        analyzer.process(rec, pkt);
    }
    ShardResult result = analyzer.finish();

    Report report;
    report.options = &o;
    report.capture.path = o.input;
    report.capture.file_size = cap->file.bytes().size();
    report.capture.info = cap->reader.info();
    report.capture.counters = cap->reader.counters();
    report.capture.status = cap->reader.status();
    report.capture.truncated_tail_bytes = cap->reader.truncated_tail_bytes();
    report.reader = &reader_stats;
    report.flows = &result;
    report.deterministic = o.deterministic;
    report.run.workers = o.workers;
    report.run.elapsed_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    report.run.peak_rss_bytes = peak_rss_bytes();
    report.run.cpu_count = std::thread::hardware_concurrency();
    report.run.os = os_name();

    std::vector<std::string> outputs;
    try {
        if (o.export_dir) {
            std::sort(result.exported.begin(), result.exported.end(),
                      [](const ExportRow& a, const ExportRow& b) {
                          return a.flow_id != b.flow_id ? a.flow_id < b.flow_id : a.c2s > b.c2s;
                      });
            std::string tsv =
                "flow_id\tdirection\tsrc\tsport\tdst\tdport\tdelivered_bytes\tgap_count\n";
            for (const auto& e : result.exported) {
                tsv +=
                    std::format("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n", e.flow_id,
                                e.c2s ? "c2s" : "s2c", format_ip(e.src.addr), e.src.port,
                                format_ip(e.dst.addr), e.dst.port, e.delivered_bytes, e.gap_count);
            }
            write_file_atomic((fs::path(*o.export_dir) / "streams.tsv").string(), tsv);
            if (result.export_failed) {
                throw OutputError("failed writing exported streams");
            }
            outputs.push_back(*o.export_dir + "/");
        }
        if (o.json_path) {
            write_file_atomic(*o.json_path, render_json(report));
            if (*o.json_path != "-") {
                outputs.push_back(*o.json_path);
            }
        }
        if (o.html_path) {
            write_file_atomic(*o.html_path, render_html(report));
            outputs.push_back(*o.html_path);
        }
    } catch (const OutputError& e) {
        std::fprintf(stderr, "netprobe: %s\n", e.what());
        return exit_output;
    }

    if (!o.quiet) {
        const auto text = render_text_summary(report, outputs);
        std::fwrite(text.data(), 1, text.size(), stdout);
    }
    if (report.capture.status != CaptureStatus::complete) {
        std::fprintf(stderr, "netprobe: warning: capture is %s; report covers %llu records\n",
                     std::string(to_string(report.capture.status)).c_str(),
                     static_cast<unsigned long long>(reader_stats.packets()));
        return exit_partial;
    }
    return exit_ok;
}

int run_dump(const DumpOptions& o) {
    auto cap = open_capture(o.input);
    if (!cap) {
        return exit_input;
    }
    std::string out = "index\tts_ns\torig_len\tcaplen\tstatus\tethertype\tvlan\tip_ver\tsrc\tdst\t"
                      "proto\tsport\tdport\ttcp_seq\ttcp_ack\ttcp_flags\ttcp_len\n";
    PacketRecord rec;
    std::uint64_t n = 0;
    while ((!o.limit || n < *o.limit) && cap->reader.next(rec)) {
        ++n;
        const DecodedPacket p = decode_packet(rec);
        const auto& st = p.status;
        std::string status = st.ok() ? "ok"
                                     : std::format("{}.{}.{}", to_string(st.kind),
                                                   to_string(st.layer), to_string(st.reason));
        std::string vlan;
        for (std::uint8_t i = 0; i < p.vlan_count && i < 2; ++i) {
            vlan += std::format("{}{}", i ? "," : "", p.vlan_ids[i] & 0x0FFF);
        }
        const bool l3 = p.ip_version != 0;
        const bool l4 = st.ok() && !p.is_fragment && (p.is_tcp() || p.is_udp());
        const bool tcp = l4 && p.l4_proto == ip_proto::tcp;
        out += std::format(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n", rec.index,
            rec.ts_ns, rec.orig_len, rec.data.size(), status,
            st.ok() || st.layer != Layer::ethernet ? std::format("0x{:04x}", p.ethertype) : "",
            vlan, l3 ? std::to_string(p.ip_version) : "", l3 ? format_ip(p.src) : "",
            l3 ? format_ip(p.dst) : "", l3 ? std::to_string(p.l4_proto) : "",
            l4 ? std::to_string(p.src_port) : "", l4 ? std::to_string(p.dst_port) : "",
            tcp ? std::to_string(p.seq) : "", tcp ? std::to_string(p.ack) : "",
            tcp ? std::format("0x{:02x}", p.tcp_flags) : "",
            tcp ? std::to_string(p.payload_logical_len) : "");
        if (out.size() > (1 << 20)) {
            std::fwrite(out.data(), 1, out.size(), stdout);
            out.clear();
        }
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return cap->reader.status() == CaptureStatus::complete ? exit_ok : exit_partial;
}

} // namespace netprobe
