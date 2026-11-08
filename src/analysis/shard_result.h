#pragma once
// Per-shard results and the flow summary model (PRD 4.3 FR-FLOW-9, 4.5, 8.1).

#include "flow/flow_key.h"
#include "tcp/reassembler.h"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace netprobe {

enum class Handshake : std::uint8_t { none, partial, full };
enum class CloseReason : std::uint8_t {
    fin,
    rst,
    idle_timeout,
    end_of_capture,
    reused,
    evicted,
    count_
};
enum class Integrity : std::uint8_t { complete, gaps, snaplen_truncated, open };

std::string_view to_string(Handshake) noexcept;
std::string_view to_string(CloseReason) noexcept;
std::string_view to_string(Integrity) noexcept;

struct DirSummary {
    std::uint64_t packets = 0, bytes = 0, payload_bytes = 0, data_after_rst = 0;
    bool syn = false, fin = false, rst = false, has_mss = false, has_wscale = false;
    std::uint16_t mss = 0;
    std::uint8_t wscale = 0;
    StreamStats stream; // TCP only
};

struct FlowSummary {
    std::uint64_t id = 0;
    std::uint8_t proto = 0, ip_version = 0;
    Endpoint client, server;
    bool orientation_handshake = false;
    Handshake handshake = Handshake::none;
    CloseReason close = CloseReason::end_of_capture;
    Integrity integrity = Integrity::open;
    std::int64_t first_ts_ns = 0, last_ts_ns = 0;
    DirSummary c2s, s2c;

    std::uint64_t bytes() const noexcept { return c2s.bytes + s2c.bytes; }
    std::uint64_t missing_bytes() const noexcept {
        return c2s.stream.gap_bytes + s2c.stream.gap_bytes;
    }
    bool is_tcp() const noexcept { return proto == ip_proto::tcp; }
};

// Bounded top-K under the total order (metric desc, id asc) (PRD D13). Per-shard top-K merged
// is exactly the global top-K.
class TopK {
public:
    enum class Metric : std::uint8_t { bytes, missing_bytes };
    TopK(std::size_t k, Metric m) : k_(k), metric_(m) {}
    void offer(FlowSummary s);
    void merge(TopK&& other);
    std::vector<FlowSummary> sorted() const; // best first
    std::size_t size() const noexcept { return heap_.size(); }

private:
    bool better(const FlowSummary& a, const FlowSummary& b) const noexcept;
    std::uint64_t metric(const FlowSummary& s) const noexcept {
        return metric_ == Metric::bytes ? s.bytes() : s.missing_bytes();
    }
    std::size_t k_;
    Metric metric_;
    std::vector<FlowSummary> heap_; // heap whose front is the worst kept element
};

struct Talker {
    std::uint64_t bytes_sent = 0, bytes_received = 0, flows = 0;
};
struct ServiceStats {
    std::uint64_t flows = 0, bytes = 0;
};

struct IpAddrHash {
    std::size_t operator()(const IpAddr& a) const noexcept;
};

struct FlowCounters {
    std::uint64_t tcp_total = 0, handshake_full = 0, handshake_partial = 0, handshake_none = 0;
    std::uint64_t tcp_complete = 0, tcp_with_gaps = 0;
    std::uint64_t tcp_close[static_cast<std::size_t>(CloseReason::count_)] = {};
    std::uint64_t udp_total = 0;
    std::uint64_t udp_close[static_cast<std::size_t>(CloseReason::count_)] = {};
};

struct ReassemblyTotals {
    std::uint64_t delivered_bytes = 0, retransmitted_segments = 0, retransmitted_bytes = 0;
    std::uint64_t out_of_order_segments = 0, overlap_bytes = 0, conflicting_overlap_bytes = 0;
    std::uint64_t gap_count = 0, gap_bytes = 0, acked_gap_bytes = 0, snaplen_missing_bytes = 0;
    std::uint64_t out_of_window_segments = 0, data_after_fin = 0, data_after_rst = 0;
    std::uint64_t forced_flushes = 0, peak_buffered_bytes = 0;
    void add(const StreamStats& s) noexcept;
    void add(const ReassemblyTotals& o) noexcept;
};

struct ExportRow {
    std::uint64_t flow_id;
    bool c2s;
    Endpoint src, dst;
    std::uint64_t delivered_bytes, gap_count;
};

struct ShardResult {
    explicit ShardResult(std::size_t top_k)
        : top_bytes(top_k, TopK::Metric::bytes),
          top_incomplete(top_k, TopK::Metric::missing_bytes) {}

    FlowCounters flows;
    ReassemblyTotals reassembly;
    TopK top_bytes, top_incomplete;
    std::unordered_map<IpAddr, Talker, IpAddrHash> talkers;
    std::map<std::pair<std::uint8_t, std::uint16_t>, ServiceStats> services;
    std::vector<ExportRow> exported;
    std::uint64_t peak_flows = 0, evicted_flows = 0;
    bool limits_hit = false;
    bool export_failed = false;

    // Folds `o` into this result (sums, map unions, top-K merge).
    void merge(ShardResult&& o);
};

} // namespace netprobe
