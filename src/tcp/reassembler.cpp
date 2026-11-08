#include "tcp/reassembler.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace netprobe {
StreamReassembler::StreamReassembler(MemoryBudget& budget, ReassemblyLimits limits) noexcept
    : budget_(&budget), limits_(limits) {}
StreamReassembler::~StreamReassembler() {
    refund_all();
}
StreamReassembler::StreamReassembler(StreamReassembler&& other) noexcept
    : StreamReassembler(*other.budget_, other.limits_) {
    *this = std::move(other);
}
StreamReassembler& StreamReassembler::operator=(StreamReassembler&& other) noexcept {
    if (this == &other)
        return *this;
    refund_all();
    budget_ = other.budget_;
    limits_ = other.limits_;
    unwrap_ = std::exchange(other.unwrap_, {});
    delivered_ = std::exchange(other.delivered_, 0);
    highest_end_ = std::exchange(other.highest_end_, 0);
    max_acked_ = std::exchange(other.max_acked_, 0);
    fin_offset_ = std::exchange(other.fin_offset_, std::nullopt);
    ooo_ptr_.swap(other.ooo_ptr_);
    buffered_accounted_ = std::exchange(other.buffered_accounted_, 0);
    delivered_bytes_ = std::exchange(other.delivered_bytes_, 0);
    fin_seen_ = std::exchange(other.fin_seen_, false);
    complete_ = std::exchange(other.complete_, false);
    rare_ = std::move(other.rare_);
    initialized_ = std::exchange(other.initialized_, false);
    return *this;
}
StreamReassembler::Map& StreamReassembler::ooo() {
    if (!ooo_ptr_) {
        ooo_ptr_ = std::make_unique<Map>();
    }
    return *ooo_ptr_;
}
StreamStats& StreamReassembler::rare() {
    if (!rare_) {
        rare_ = std::make_unique<StreamStats>();
    }
    return *rare_;
}
StreamStats StreamReassembler::stats() const {
    StreamStats s = rare_ ? *rare_ : StreamStats{};
    s.delivered_bytes = delivered_bytes_;
    s.fin_seen = fin_seen_;
    s.complete_ = complete_;
    return s;
}
void StreamReassembler::refund_all() noexcept {
    budget_->refund(buffered_accounted_);
    buffered_accounted_ = 0;
    ooo_ptr_.reset();
}
void StreamReassembler::init(std::uint32_t origin_seq) noexcept {
    refund_all();
    unwrap_.init(origin_seq);
    delivered_ = highest_end_ = max_acked_ = 0;
    fin_offset_.reset();
    delivered_bytes_ = 0;
    fin_seen_ = complete_ = false;
    rare_.reset();
    initialized_ = true;
}
void StreamReassembler::update_complete() noexcept {
    complete_ = fin_offset_ && delivered_ == *fin_offset_ && gap_count() == 0;
}
void StreamReassembler::emit_data(Bytes data, StreamSink& sink) {
    if (data.empty())
        return;
    sink.on_data(delivered_, data);
    delivered_ += data.size();
    delivered_bytes_ += data.size();
    update_complete();
}
void StreamReassembler::emit_gap(std::uint64_t end, StreamSink& sink) {
    if (end <= delivered_)
        return;
    const Gap gap{delivered_, end - delivered_, end <= max_acked_};
    sink.on_gap(gap.offset, gap.length);
    if (rare().gaps.size() < 16)
        rare().gaps.push_back(gap);
    else
        rare().gaps_truncated = true;
    ++rare().gap_count;
    rare().gap_bytes += gap.length;
    if (gap.acked)
        rare().acked_gap_bytes += gap.length;
    delivered_ = end;
    update_complete();
}
void StreamReassembler::drain(StreamSink& sink) {
    while (!ooo_empty() && ooo().begin()->first == delivered_) {
        const auto it = ooo().begin();
        auto data = Bytes(it->second.bytes);
        if (fin_offset_ && data.size() > *fin_offset_ - delivered_) {
            data = data.first(static_cast<std::size_t>(*fin_offset_ - delivered_));
            ++rare().data_after_fin; // bytes past FIN are dropped, never delivered
        }
        emit_data(data, sink);
        const auto cost = it->second.bytes.size() + kSegmentOverhead;
        budget_->refund(cost);
        buffered_accounted_ -= cost;
        ooo().erase(it);
    }
    if (ooo_ptr_ && ooo_ptr_->empty()) {
        ooo_ptr_.reset(); // back to the compact in-order state
    }
}
void StreamReassembler::on_segment(std::uint32_t seq, std::uint32_t logical_len, Bytes captured,
                                   StreamSink& sink) {
    if (logical_len == 0 || !initialized_)
        return;
    const auto converted = unwrap_.to_signed_offset(seq, delivered_);
    if (!converted ||
        (*converted > 0 && static_cast<std::uint64_t>(*converted) >
                               std::numeric_limits<std::uint64_t>::max() - logical_len)) {
        ++rare().out_of_window_segments;
        return;
    }
    if (*converted < 0) {
        // Starts before the stream origin: data sent before a mid-stream capture began (seen as
        // retransmissions in real captures, e.g. tcpreplay's smallFlows.pcap). Those bytes are
        // old; a segment that straddles the origin still carries new bytes after it.
        const auto before = static_cast<std::uint64_t>(-*converted);
        if (before >= logical_len) {
            ++rare().retransmitted_segments;
            rare().retransmitted_bytes += logical_len;
            return;
        }
        rare().retransmitted_bytes += before;
        captured = captured.subspan(std::min<std::size_t>(captured.size(), before));
        logical_len -= static_cast<std::uint32_t>(before);
    }
    auto off = static_cast<std::uint64_t>(std::max<std::int64_t>(*converted, 0));
    auto end = off + logical_len;
    captured = captured.first(std::min<std::size_t>(captured.size(), logical_len));
    auto cap_end = off + captured.size();
    highest_end_ = std::max(highest_end_, end);
    if (fin_offset_ && end > *fin_offset_) {
        ++rare().data_after_fin;
        end = *fin_offset_;
        cap_end = std::min(cap_end, end);
        if (off >= end)
            return;
    }
    if (end <= delivered_) {
        ++rare().retransmitted_segments;
        rare().retransmitted_bytes += end - off;
        return;
    }
    const auto original_off = off;
    if (off < delivered_) {
        rare().retransmitted_bytes += delivered_ - off;
        off = delivered_;
    }
    // An old captured prefix may end before delivered_; it contributes no remaining bytes.
    cap_end = std::max(cap_end, off);
    const auto skipped = std::min<std::uint64_t>(off - original_off, captured.size());
    captured = captured.subspan(static_cast<std::size_t>(skipped),
                                static_cast<std::size_t>(cap_end - off));
    if (end > cap_end) {
        rare().snaplen_missing_bytes += end - cap_end; // only touch rare() when non-zero
    }
    if (off == delivered_ && ooo_empty()) {
        emit_data(captured, sink);
        return;
    }
    if (off > delivered_)
        ++rare().out_of_order_segments;

    auto it = ooo().lower_bound(off);
    if (it != ooo().begin())
        --it;
    for (; it != ooo().end() && it->first < cap_end; ++it) {
        const auto first = std::max(off, it->first);
        const auto last = std::min(cap_end, it->first + it->second.bytes.size());
        for (auto pos = first; pos < last; ++pos) {
            ++rare().overlap_bytes;
            if (captured[static_cast<std::size_t>(pos - off)] !=
                it->second.bytes[static_cast<std::size_t>(pos - it->first)])
                ++rare().conflicting_overlap_bytes;
        }
    }
    auto pos = off;
    while (pos < cap_end) {
        it = ooo().upper_bound(pos);
        if (it != ooo().begin()) {
            const auto previous = std::prev(it);
            const auto previous_end = previous->first + previous->second.bytes.size();
            if (previous_end > pos) {
                pos = previous_end;
                continue;
            }
        }
        const auto piece_end = it == ooo().end() ? cap_end : std::min(cap_end, it->first);
        const auto cost = piece_end - pos + kSegmentOverhead;
        if (cost > limits_.max_stream_buffer - buffered_accounted_ || !budget_->can_charge(cost)) {
            ++rare().forced_flushes;
            // A plain flush could gap past not-yet-inserted incoming bytes. Merge them first.
            flush_with_incoming(off, captured, sink);
            return;
        }
        const auto piece = captured.subspan(static_cast<std::size_t>(pos - off),
                                            static_cast<std::size_t>(piece_end - pos));
        ooo().emplace(pos, Segment{{piece.begin(), piece.end()}});
        budget_->charge(cost);
        buffered_accounted_ += cost;
        pos = piece_end;
    }
    drain(sink);
    release_acked_holes(sink);
}
// PRD D7 (revised): a hole the receiver has already ACKed will never be retransmitted, so it is
// capture loss. Gaps stay lazy, but once a large run of later data is buffered behind an ACKed
// hole (far beyond any plausible ACK-before-data capture skew), declare it instead of holding
// data until the per-stream limit forces a flush.
void StreamReassembler::release_acked_holes(StreamSink& sink) {
    const std::uint64_t threshold =
        std::min<std::uint64_t>(1ULL << 20, limits_.max_stream_buffer / 2);
    while (!ooo_empty()) {
        const auto hole_end = ooo().begin()->first;
        const auto last = std::prev(ooo().end());
        const auto buffered_end = last->first + last->second.bytes.size();
        if (hole_end > max_acked_ || buffered_end - hole_end < threshold) {
            return;
        }
        emit_gap(hole_end, sink);
        drain(sink);
    }
}
void StreamReassembler::on_fin(std::uint32_t fin_seq) {
    if (!initialized_ || fin_offset_)
        return;
    const auto fin = unwrap_.to_offset(fin_seq, delivered_);
    // A FIN behind data already delivered is stale or bogus: honoring it would discard the
    // buffer and every later byte. Ignore it (independent review finding #1).
    if (!fin || *fin < delivered_)
        return;
    fin_offset_ = fin;
    fin_seen_ = true;
    // FIN is evidence of the payload end even when its preceding data was never captured.
    highest_end_ = std::max(highest_end_, *fin_offset_);
    // FIN can arrive after data was buffered, so enforce its bound on existing storage too.
    auto it = ooo_ptr_ ? ooo().lower_bound(*fin_offset_) : Map::iterator{};
    while (ooo_ptr_ && it != ooo().end()) {
        const auto cost = it->second.bytes.size() + kSegmentOverhead;
        budget_->refund(cost);
        buffered_accounted_ -= cost;
        it = ooo().erase(it);
        ++rare().data_after_fin;
    }
    // Keep any suffix allocation charged until delivery; vector::resize would not release it.
    update_complete();
}
void StreamReassembler::on_peer_ack(std::uint32_t ack) noexcept {
    if (!initialized_)
        return;
    // Unwrap against the furthest known point so a direction whose data is never captured still
    // tracks ACKs past the 2^30 window (independent review finding #9).
    if (const auto off = unwrap_.to_offset(ack, std::max(delivered_, max_acked_)))
        max_acked_ = std::max(max_acked_, *off);
}
void StreamReassembler::flush_with_incoming(std::uint64_t off, Bytes incoming, StreamSink& sink) {
    const auto cap_end = off + incoming.size();
    while (!ooo_empty() || delivered_ < cap_end) {
        if (!ooo_empty() && ooo().begin()->first == delivered_) {
            drain(sink);
        } else if (delivered_ >= off && delivered_ < cap_end) {
            const auto end = ooo_empty() ? cap_end : std::min(cap_end, ooo().begin()->first);
            emit_data(incoming.subspan(static_cast<std::size_t>(delivered_ - off),
                                       static_cast<std::size_t>(end - delivered_)),
                      sink);
        } else {
            auto next = ooo_empty() ? off : ooo().begin()->first;
            if (delivered_ < off)
                next = std::min(next, off);
            emit_gap(next, sink);
        }
    }
    auto end = std::max(max_acked_, highest_end_);
    if (fin_offset_)
        end = std::min(end, *fin_offset_);
    emit_gap(end, sink);
}
void StreamReassembler::flush(StreamSink& sink) {
    flush_with_incoming(delivered_, {}, sink);
}
bool StreamReassembler::check_invariants() const {
    std::uint64_t total = 0, previous_end = delivered_;
    static const Map kEmpty;
    for (const auto& [off, segment] : ooo_ptr_ ? *ooo_ptr_ : kEmpty) {
        if (segment.bytes.empty() || off <= delivered_ || off < previous_end)
            return false;
        previous_end = off + segment.bytes.size();
        if (fin_offset_ && off >= *fin_offset_)
            return false;
        total += segment.bytes.size() + kSegmentOverhead;
    }
    return total == buffered_accounted_ && total <= limits_.max_stream_buffer &&
           total <= budget_->current() &&
           complete_ == (fin_offset_ && delivered_ == *fin_offset_ && gap_count() == 0);
}
} // namespace netprobe
