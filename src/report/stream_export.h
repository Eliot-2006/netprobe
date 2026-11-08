#pragma once
// --export-streams sink (PRD 6.10). File names contain only digits and fixed strings.

#include "tcp/stream_sink.h"

#include <cstdint>
#include <filesystem>

namespace netprobe {

// Final name: <flow_id>_c2s.bin or <flow_id>_s2c.bin.
std::filesystem::path stream_file(const std::filesystem::path& dir, std::uint64_t flow_id,
                                  bool c2s);
// Working name while the flow is live: keyed by the flow key's fixed direction, because the
// client/server orientation can still change (a SYN after stray packets). Renamed at finalize.
std::filesystem::path stream_work_file(const std::filesystem::path& dir, std::uint64_t flow_id,
                                       bool lo_to_hi);

// ponytail: open/append/close per delivered chunk keeps one fd and is correct across shards;
// add a small LRU of open files if export throughput ever matters (it is not benchmarked).
class FileExportSink final : public StreamSink {
public:
    explicit FileExportSink(std::filesystem::path path) : path_(std::move(path)) {}
    void on_data(std::uint64_t offset, Bytes data) override;
    void on_gap(std::uint64_t, std::uint64_t) override {}
    bool failed() const noexcept { return failed_; }

private:
    std::filesystem::path path_;
    bool failed_ = false;
};

} // namespace netprobe
