#pragma once
// One PCAP record as a zero-copy view into the capture buffer (PRD 6.2).

#include "util/bytes.h"

#include <cstdint>

namespace netprobe {

struct PacketRecord {
    std::uint64_t index = 0;       // 0-based record index in the file
    std::uint64_t file_offset = 0; // offset of the 16-byte record header
    std::int64_t ts_ns = 0;        // ns since Unix epoch
    std::uint32_t orig_len = 0;    // on-the-wire length
    Bytes data;                    // incl_len captured bytes (view, never owned)
};

} // namespace netprobe
