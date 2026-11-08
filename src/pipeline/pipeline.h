#pragma once

#include "analysis/analyzer.h"
#include "analysis/reader_stats.h"
#include "io/mapped_file.h"
#include "pcap/reader.h"
#include "report/report.h"

namespace netprobe {

struct PacketDesc {
    PacketRecord record;
    DecodedPacket packet;
    std::uint64_t flow_hash = 0;
};

// Calling thread reads/decodes. Mapping must outlive the joined workers. The optional batch
// observer runs inside the worker's exception boundary (also permits deterministic fault tests).
ShardResult run_pipeline(PcapReader& reader, MappedFile& file, const AnalyzerConfig& config,
                         std::uint32_t workers, ReaderStats& stats, RunInfo& run,
                         void (*before_batch)(std::uint32_t) = nullptr);

} // namespace netprobe
