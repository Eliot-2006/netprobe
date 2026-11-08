#pragma once
// Receiver of reassembled TCP bytes for one stream direction (PRD 4.4 FR-TCP-14).
// Invariant O1: implementations must not retain `data` spans after on_data returns.

#include "util/bytes.h"

#include <cstdint>

namespace netprobe {

class StreamSink {
public:
    virtual ~StreamSink() = default;
    // Contiguous bytes starting at stream offset `offset`.
    virtual void on_data(std::uint64_t offset, Bytes data) = 0;
    // Declared-missing range [offset, offset + length).
    virtual void on_gap(std::uint64_t offset, std::uint64_t length) = 0;
};

class NullSink final : public StreamSink {
public:
    void on_data(std::uint64_t, Bytes) override {}
    void on_gap(std::uint64_t, std::uint64_t) override {}
};

} // namespace netprobe
