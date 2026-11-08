#include "analysis/shard_result.h"

#include <algorithm>
#include <cstring>

namespace netprobe {

std::string_view to_string(Handshake h) noexcept {
    switch (h) {
    case Handshake::none:
        return "none";
    case Handshake::partial:
        return "partial";
    case Handshake::full:
        return "full";
    }
    return "?";
}

std::string_view to_string(CloseReason c) noexcept {
    switch (c) {
    case CloseReason::fin:
        return "fin";
    case CloseReason::rst:
        return "rst";
    case CloseReason::idle_timeout:
        return "idle_timeout";
    case CloseReason::end_of_capture:
        return "end_of_capture";
    case CloseReason::reused:
        return "reused";
    case CloseReason::evicted:
        return "evicted";
    case CloseReason::count_:
        break;
    }
    return "?";
}

std::string_view to_string(Integrity i) noexcept {
    switch (i) {
    case Integrity::complete:
        return "complete";
    case Integrity::gaps:
        return "gaps";
    case Integrity::snaplen_truncated:
        return "snaplen_truncated";
    case Integrity::open:
        return "open";
    }
    return "?";
}

bool TopK::better(const FlowSummary& a, const FlowSummary& b) const noexcept {
    const auto ma = metric(a), mb = metric(b);
    return ma != mb ? ma > mb : a.id < b.id;
}

void TopK::offer(FlowSummary s) {
    if (k_ == 0) {
        return;
    }
    // std heap is a max-heap under `cmp`; with cmp = better, front() is the worst element.
    auto cmp = [this](const FlowSummary& a, const FlowSummary& b) { return better(a, b); };
    if (heap_.size() < k_) {
        heap_.push_back(std::move(s));
        std::push_heap(heap_.begin(), heap_.end(), cmp);
    } else if (better(s, heap_.front())) {
        std::pop_heap(heap_.begin(), heap_.end(), cmp);
        heap_.back() = std::move(s);
        std::push_heap(heap_.begin(), heap_.end(), cmp);
    }
}

void TopK::merge(TopK&& other) {
    for (auto& s : other.heap_) {
        offer(std::move(s));
    }
    other.heap_.clear();
}

std::vector<FlowSummary> TopK::sorted() const {
    auto v = heap_;
    std::sort(v.begin(), v.end(),
              [this](const FlowSummary& a, const FlowSummary& b) { return better(a, b); });
    return v;
}

std::size_t IpAddrHash::operator()(const IpAddr& a) const noexcept {
    std::uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, a.b.data(), 8);
    std::memcpy(&hi, a.b.data() + 8, 8);
    std::uint64_t h = lo * 0x9E3779B97F4A7C15ULL ^ hi;
    h ^= h >> 29;
    h *= 0xbf58476d1ce4e5b9ULL;
    return static_cast<std::size_t>(h ^ (h >> 32));
}

void ReassemblyTotals::add(const StreamStats& s) noexcept {
    delivered_bytes += s.delivered_bytes;
    retransmitted_segments += s.retransmitted_segments;
    retransmitted_bytes += s.retransmitted_bytes;
    out_of_order_segments += s.out_of_order_segments;
    overlap_bytes += s.overlap_bytes;
    conflicting_overlap_bytes += s.conflicting_overlap_bytes;
    gap_count += s.gap_count;
    gap_bytes += s.gap_bytes;
    acked_gap_bytes += s.acked_gap_bytes;
    snaplen_missing_bytes += s.snaplen_missing_bytes;
    out_of_window_segments += s.out_of_window_segments;
    data_after_fin += s.data_after_fin;
    forced_flushes += s.forced_flushes;
}

void ReassemblyTotals::add(const ReassemblyTotals& o) noexcept {
    delivered_bytes += o.delivered_bytes;
    retransmitted_segments += o.retransmitted_segments;
    retransmitted_bytes += o.retransmitted_bytes;
    out_of_order_segments += o.out_of_order_segments;
    overlap_bytes += o.overlap_bytes;
    conflicting_overlap_bytes += o.conflicting_overlap_bytes;
    gap_count += o.gap_count;
    gap_bytes += o.gap_bytes;
    acked_gap_bytes += o.acked_gap_bytes;
    snaplen_missing_bytes += o.snaplen_missing_bytes;
    out_of_window_segments += o.out_of_window_segments;
    data_after_fin += o.data_after_fin;
    data_after_rst += o.data_after_rst;
    forced_flushes += o.forced_flushes;
    peak_buffered_bytes += o.peak_buffered_bytes; // sum of per-shard peaks (upper bound)
}

void ShardResult::merge(ShardResult&& o) {
    auto& f = flows;
    const auto& g = o.flows;
    f.tcp_total += g.tcp_total;
    f.handshake_full += g.handshake_full;
    f.handshake_partial += g.handshake_partial;
    f.handshake_none += g.handshake_none;
    f.tcp_complete += g.tcp_complete;
    f.tcp_with_gaps += g.tcp_with_gaps;
    f.udp_total += g.udp_total;
    for (std::size_t i = 0; i < static_cast<std::size_t>(CloseReason::count_); ++i) {
        f.tcp_close[i] += g.tcp_close[i];
        f.udp_close[i] += g.udp_close[i];
    }
    reassembly.add(o.reassembly);

    top_bytes.merge(std::move(o.top_bytes));
    top_incomplete.merge(std::move(o.top_incomplete));
    for (auto& [ip, t] : o.talkers) {
        auto& d = talkers[ip];
        d.bytes_sent += t.bytes_sent;
        d.bytes_received += t.bytes_received;
        d.flows += t.flows;
    }
    for (auto& [k, s] : o.services) {
        auto& d = services[k];
        d.flows += s.flows;
        d.bytes += s.bytes;
    }
    exported.insert(exported.end(), o.exported.begin(), o.exported.end());
    peak_flows += o.peak_flows;
    evicted_flows += o.evicted_flows;
    limits_hit = limits_hit || o.limits_hit;
    export_failed = export_failed || o.export_failed;
}

} // namespace netprobe
