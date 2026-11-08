#pragma once
// --export-streams sink (PRD 6.10). File names contain only digits and fixed strings.

#include "tcp/stream_sink.h"

#include <cstdint>
#include <filesystem>

namespace netprobe {

std::filesystem::path stream_file(const std::filesystem::path& dir, std::uint64_t flow_id,
                                  bool c2s);

// ponytail: open/append/close per delivered chunk keeps one fd and is correct across shards;
// add a small LRU of open files if export throughput ever matters (it is not benchmarked).
class FileExportSink final : public StreamSink {
public:
    FileExportSink(const std::filesystem::path& dir, std::uint64_t flow_id, bool c2s)
        : path_(stream_file(dir, flow_id, c2s)) {}
    void on_data(std::uint64_t offset, Bytes data) override;
    void on_gap(std::uint64_t, std::uint64_t) override {}
    bool failed() const noexcept { return failed_; }

private:
    std::filesystem::path path_;
    bool failed_ = false;
};

} // namespace netprobe
