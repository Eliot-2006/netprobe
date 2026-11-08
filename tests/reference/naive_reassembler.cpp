#include "reference/naive_reassembler.h"
#include <algorithm>
namespace netprobe::reference {
std::optional<std::uint64_t> NaiveReassembler::offset(std::uint32_t seq) const {
    // Derive the closest congruent offset with wide arithmetic, independently of seq_diff.
    const std::uint64_t relative = static_cast<std::uint32_t>(seq - origin_);
    const std::uint64_t epoch = delivered / 0x100000000ULL;
    std::uint64_t candidate = epoch * 0x100000000ULL + relative;
    if (candidate > delivered && candidate - delivered > 0x80000000ULL) {
        if (epoch == 0)
            return std::nullopt;
        candidate -= 0x100000000ULL;
    } else if (delivered > candidate && delivered - candidate >= 0x80000000ULL) {
        candidate += 0x100000000ULL;
    }
    const auto distance = candidate > delivered ? candidate - delivered : delivered - candidate;
    if (distance > 0x40000000ULL)
        return std::nullopt;
    return candidate;
}
void NaiveReassembler::drain() {
    while (delivered < coverage_.size() && (!fin_ || delivered < *fin_) && coverage_[delivered]) {
        output.push_back(*coverage_[delivered]);
        ++delivered;
    }
}
void NaiveReassembler::segment(std::uint32_t seq, std::uint32_t logical,
                               std::span<const std::byte> captured) {
    if (logical == 0)
        return;
    auto converted = offset(seq);
    if (!converted) {
        ++counters.out_of_window_segments;
        return;
    }
    const auto start = *converted;
    auto end = start + logical;
    auto cap_end = start + std::min<std::uint64_t>(captured.size(), logical);
    highest_ = std::max(highest_, end);
    if (fin_ && end > *fin_) {
        ++counters.data_after_fin;
        end = *fin_;
        cap_end = std::min(cap_end, end);
        if (start >= end)
            return;
    }
    if (end <= delivered) {
        ++counters.retransmitted_segments;
        counters.retransmitted_bytes += end - start;
        return;
    }
    if (start < delivered)
        counters.retransmitted_bytes += delivered - start;
    const auto first = std::max(start, delivered);
    counters.snaplen_missing_bytes += end - std::max(first, cap_end);
    if (first > delivered)
        ++counters.out_of_order_segments;
    if (coverage_.size() < end)
        coverage_.resize(static_cast<std::size_t>(end));
    for (auto i = first; i < cap_end; ++i) {
        auto& cell = coverage_[i];
        const auto value = captured[static_cast<std::size_t>(i - start)];
        if (cell) {
            ++counters.overlap_bytes;
            if (*cell != value)
                ++counters.conflicting_overlap_bytes;
        } else
            cell = value;
    }
    drain();
}
void NaiveReassembler::ack(std::uint32_t seq) {
    if (auto converted = offset(seq))
        acked_ = std::max(acked_, *converted);
}
void NaiveReassembler::fin(std::uint32_t seq) {
    if (!fin_)
        fin_ = offset(seq);
}
void NaiveReassembler::flush() {
    auto end = std::max(highest_, acked_);
    if (fin_)
        end = *fin_;
    while (delivered < end) {
        if (delivered < coverage_.size() && coverage_[delivered]) {
            output.push_back(*coverage_[delivered++]);
        } else {
            const auto start = delivered++;
            while (delivered < end && (delivered >= coverage_.size() || !coverage_[delivered]))
                ++delivered;
            gaps.push_back({start, delivered - start, delivered <= acked_});
        }
    }
}
} // namespace netprobe::reference
