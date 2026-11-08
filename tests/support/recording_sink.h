#pragma once
#include "tcp/stream_sink.h"

#include <vector>

namespace netprobe::test {
struct RecordedGap {
    std::uint64_t offset, length;
    bool operator==(const RecordedGap&) const = default;
};
class RecordingSink final : public StreamSink {
public:
    void on_data(std::uint64_t offset, Bytes data) override {
        offsets.push_back(offset);
        bytes.insert(bytes.end(), data.begin(), data.end());
    }
    void on_gap(std::uint64_t offset, std::uint64_t length) override {
        gaps.push_back({offset, length});
    }
    std::vector<std::byte> bytes;
    std::vector<std::uint64_t> offsets;
    std::vector<RecordedGap> gaps;
};
} // namespace netprobe::test
