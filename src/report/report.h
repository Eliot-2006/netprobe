#pragma once
// In-memory report model rendered by the JSON, HTML and text writers (PRD 6.11, 8).

#include "analysis/reader_stats.h"
#include "analysis/shard_result.h"
#include "cli.h"
#include "pcap/reader.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace netprobe {

struct CaptureInfo {
    std::string path;
    std::uint64_t file_size = 0;
    PcapInfo info;
    PcapCounters counters;
    CaptureStatus status = CaptureStatus::complete;
    std::uint64_t truncated_tail_bytes = 0;
};

struct WorkerRunStats {
    std::uint64_t packets = 0, batches = 0, idle_waits = 0, max_occupancy = 0;
};

struct RunInfo {
    std::uint32_t workers = 0;
    std::int64_t elapsed_ns = 0;
    std::uint64_t peak_rss_bytes = 0;
    unsigned cpu_count = 0;
    std::string os;
    std::uint64_t reader_stalls = 0, reader_stall_ns = 0;
    std::vector<WorkerRunStats> worker_stats;
};

struct Report {
    const AnalyzeOptions* options = nullptr;
    CaptureInfo capture;
    const ReaderStats* reader = nullptr;
    const ShardResult* flows = nullptr;
    RunInfo run;
    bool deterministic = false;
};

std::string render_json(const Report& r);
std::string render_text_summary(const Report& r, const std::vector<std::string>& outputs);
std::string render_html(const Report& r);

// Formatting helpers shared by renderers.
std::string format_ip(const IpAddr& a);
std::string format_bytes(std::uint64_t n); // "9.81 MiB"
std::string format_count(std::uint64_t n); // "12,403"
std::string format_duration(std::int64_t ns);
std::string format_iso8601(std::int64_t ts_ns);
std::string_view link_type_name(std::uint16_t lt) noexcept;
std::string_view service_label(std::uint8_t proto, std::uint16_t port) noexcept;
std::string_view to_string(CaptureStatus s) noexcept;

struct TalkerRow {
    IpAddr addr;
    Talker t;
};
std::vector<TalkerRow> top_talkers(const ShardResult& s, std::size_t n);
struct ServiceRow {
    std::uint8_t proto;
    std::uint16_t port;
    ServiceStats s;
};
std::vector<ServiceRow> top_services(const ShardResult& s, std::size_t n);

} // namespace netprobe
