// BM_Analyzer: decode_packet + ReaderStats + Analyzer::process (+ finish) over an in-memory D3
// slice, single thread (the same per-packet work as `netprobe analyze --workers 0`, minus the
// file reader and report). Slice: first NETPROBE_BENCH_SLICE_MIB (default 32) of
// NETPROBE_BENCH_PCAP (default datasets/d3.pcap).
#include "analysis/analyzer.h"
#include "analysis/reader_stats.h"
#include "pcap/reader.h"

#if defined(__clang__) // benchmark.h and BENCHMARK() use __COUNTER__ (flagged by -Wpedantic, Clang
                       // 23)
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif
#include <benchmark/benchmark.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

using namespace netprobe;

struct Slice {
    std::vector<std::byte> mem;
    std::vector<PacketRecord> recs;
    std::uint64_t bytes = 0;
};

const Slice& slice() {
    static const Slice s = [] {
        Slice out;
        const char* path = std::getenv("NETPROBE_BENCH_PCAP");
        const char* mib = std::getenv("NETPROBE_BENCH_SLICE_MIB");
        std::FILE* f = std::fopen(path ? path : "datasets/d3.pcap", "rb");
        if (f == nullptr) {
            std::fprintf(stderr, "bench_analyzer: cannot open capture (set NETPROBE_BENCH_PCAP)\n");
            return out;
        }
        out.mem.resize((mib ? std::strtoull(mib, nullptr, 10) : 32) << 20);
        out.mem.resize(std::fread(out.mem.data(), 1, out.mem.size(), f));
        std::fclose(f);
        auto res = PcapReader::open(Bytes(out.mem));
        if (res.error != OpenError::none) {
            return out;
        }
        PacketRecord rec;
        while (res.reader->next(rec)) {
            out.recs.push_back(rec);
            out.bytes += rec.data.size();
        }
        return out;
    }();
    return s;
}

void BM_Analyzer(benchmark::State& state) {
    const Slice& s = slice();
    if (s.recs.empty()) {
        state.SkipWithError("no records");
        return;
    }
    for (auto _ : state) {
        ReaderStats stats;
        Analyzer analyzer{AnalyzerConfig{}};
        for (const auto& rec : s.recs) {
            const DecodedPacket pkt = decode_packet(rec);
            stats.add(rec, pkt);
            analyzer.process(rec, pkt);
        }
        ShardResult result = analyzer.finish();
        benchmark::DoNotOptimize(result);
    }
    const auto iters = static_cast<std::int64_t>(state.iterations());
    state.SetItemsProcessed(iters * static_cast<std::int64_t>(s.recs.size()));
    state.SetBytesProcessed(iters * static_cast<std::int64_t>(s.bytes));
}
BENCHMARK(BM_Analyzer)->Unit(benchmark::kMillisecond);

} // namespace
