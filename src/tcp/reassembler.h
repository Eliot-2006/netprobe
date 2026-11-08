#pragma once
#include "analysis/memory_budget.h"
#include "tcp/seq.h"
#include "tcp/stream_sink.h"
#include <cstdint>
#include <map>
#include <optional>
#include <vector>
namespace netprobe {
inline constexpr std::uint64_t kSegmentOverhead = 64;
struct ReassemblyLimits {
    std::uint64_t max_stream_buffer;
};
struct Gap {
    std::uint64_t offset = 0, length = 0;
    bool acked = false;
};
struct StreamStats {
    std::uint64_t delivered_bytes = 0, retransmitted_segments = 0, retransmitted_bytes = 0;
    std::uint64_t out_of_order_segments = 0, overlap_bytes = 0, conflicting_overlap_bytes = 0;
    std::uint64_t gap_count = 0, gap_bytes = 0, acked_gap_bytes = 0, snaplen_missing_bytes = 0;
    std::uint64_t out_of_window_segments = 0, data_after_fin = 0, forced_flushes = 0;
    std::vector<Gap> gaps;
    bool fin_seen = false;
    bool gaps_truncated = false;
    bool complete() const noexcept { return complete_; }

private:
    friend class StreamReassembler;
    bool complete_ = false;
};
class StreamReassembler {
public:
    StreamReassembler(MemoryBudget& budget, ReassemblyLimits limits) noexcept;
    ~StreamReassembler();
    StreamReassembler(const StreamReassembler&) = delete;
    StreamReassembler& operator=(const StreamReassembler&) = delete;
    StreamReassembler(StreamReassembler&& other) noexcept;
    StreamReassembler& operator=(StreamReassembler&& other) noexcept;
    // Resets the direction; origin is ISN+1 or the first observed payload sequence.
    void init(std::uint32_t origin_seq) noexcept;
    bool initialized() const noexcept { return initialized_; }
    // seq already includes the SYN adjustment; captured is borrowed only for this call.
    void on_segment(std::uint32_t seq, std::uint32_t logical_len, Bytes captured, StreamSink& sink);
    // fin_seq is the sequence occupied by FIN, excluding its consumed sequence number.
    void on_fin(std::uint32_t fin_seq) noexcept;
    void on_peer_ack(std::uint32_t ack) noexcept;
    void flush(StreamSink& sink);
    const StreamStats& stats() const noexcept { return stats_; }
    std::uint64_t buffered_bytes() const noexcept { return buffered_accounted_; }
    std::uint64_t delivered_offset() const noexcept { return delivered_; }
    bool check_invariants() const;

private:
    struct Segment {
        std::vector<std::byte> bytes;
    };
    void refund_all() noexcept;
    void emit_data(Bytes data, StreamSink& sink);
    void emit_gap(std::uint64_t end, StreamSink& sink);
    void drain(StreamSink& sink);
    void flush_with_incoming(std::uint64_t off, Bytes incoming, StreamSink& sink);
    void update_complete() noexcept;
    void release_acked_holes(StreamSink& sink);
    SeqUnwrapper unwrap_;
    bool initialized_ = false;
    std::uint64_t delivered_ = 0, highest_end_ = 0, max_acked_ = 0;
    std::optional<std::uint64_t> fin_offset_;
    std::map<std::uint64_t, Segment> ooo_;
    std::uint64_t buffered_accounted_ = 0;
    MemoryBudget* budget_;
    ReassemblyLimits limits_;
    StreamStats stats_;
};
static_assert(sizeof(StreamReassembler) <= 256);
} // namespace netprobe
