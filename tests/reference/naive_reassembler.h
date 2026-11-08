#pragma once
// Independent byte-coverage oracle: deliberately no includes from src/tcp.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>
namespace netprobe::reference {
struct Gap {
    std::uint64_t offset, length;
    bool acked;
};
struct Counters {
    std::uint64_t retransmitted_segments = 0, retransmitted_bytes = 0;
    std::uint64_t out_of_order_segments = 0, overlap_bytes = 0, conflicting_overlap_bytes = 0;
    std::uint64_t snaplen_missing_bytes = 0, out_of_window_segments = 0, data_after_fin = 0;
};
class NaiveReassembler {
public:
    explicit NaiveReassembler(std::uint32_t origin) : origin_(origin) {}
    void segment(std::uint32_t seq, std::uint32_t logical, std::span<const std::byte> captured);
    void ack(std::uint32_t seq);
    void fin(std::uint32_t seq);
    void flush();
    std::vector<std::byte> output;
    std::vector<Gap> gaps;
    Counters counters;
    std::uint64_t delivered = 0;

private:
    std::optional<std::uint64_t> offset(std::uint32_t seq) const;
    void drain();
    std::uint32_t origin_;
    std::uint64_t highest_ = 0, acked_ = 0;
    std::optional<std::uint64_t> fin_;
    std::vector<std::optional<std::byte>> coverage_;
};
} // namespace netprobe::reference
