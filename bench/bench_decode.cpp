// BM_Decode/<mix>: decode_packet over a pre-loaded vector of records (PRD 12.1).
// Records come from a prefix of a D3 capture (NETPROBE_BENCH_PCAP, default datasets/d3.pcap;
// NETPROBE_BENCH_SLICE_MIB, default 32). Mixes are partitions of that slice by decoded protocol.
#include "decode/decode.h"
#include "pcap/reader.h"

#if defined(__clang__) // benchmark.h and BENCHMARK() use __COUNTER__ (flagged by -Wpedantic, Clang
                       // 23)
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif
#include <benchmark/benchmark.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

using namespace netprobe;

constexpr std::array<const char*, 5> kMixes = {"d3", "tcp_v4", "udp_v4", "tcp_v6", "vlan"};

bool in_mix(std::size_t mix, const DecodedPacket& p) {
    switch (mix) {
    case 0:
        return true;
    case 1:
        return p.is_tcp() && p.ip_version == 4 && p.vlan_count == 0;
    case 2:
        return p.is_udp() && p.ip_version == 4 && p.vlan_count == 0;
    case 3:
        return p.is_tcp() && p.ip_version == 6 && p.vlan_count == 0;
    default:
        return p.vlan_count > 0;
    }
}

struct Slice {
    std::vector<std::byte> mem;
    std::array<std::vector<PacketRecord>, kMixes.size()> recs;
};

const Slice& slice() {
    static const Slice s = [] {
        Slice out;
        const char* path = std::getenv("NETPROBE_BENCH_PCAP");
        const char* mib = std::getenv("NETPROBE_BENCH_SLICE_MIB");
        std::FILE* f = std::fopen(path ? path : "datasets/d3.pcap", "rb");
        if (f == nullptr) {
            std::fprintf(stderr, "bench_decode: cannot open capture (set NETPROBE_BENCH_PCAP)\n");
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
        while (res.reader->next(rec)) { // the cut at the slice end just ends iteration
            const DecodedPacket p = decode_packet(rec);
            for (std::size_t m = 0; m < kMixes.size(); ++m) {
                if (in_mix(m, p)) {
                    out.recs[m].push_back(rec);
                }
            }
        }
        return out;
    }();
    return s;
}

void BM_Decode(benchmark::State& state, std::size_t mix) {
    const auto& recs = slice().recs[mix];
    if (recs.empty()) {
        state.SkipWithError("no records in this mix");
        return;
    }
    std::uint64_t bytes = 0;
    for (const auto& r : recs) {
        bytes += r.data.size();
    }
    for (auto _ : state) {
        for (const auto& r : recs) {
            DecodedPacket p = decode_packet(r);
            benchmark::DoNotOptimize(p);
        }
    }
    const auto iters = static_cast<std::int64_t>(state.iterations());
    state.SetItemsProcessed(iters * static_cast<std::int64_t>(recs.size()));
    state.SetBytesProcessed(iters * static_cast<std::int64_t>(bytes));
}

[[maybe_unused]] const bool registered = [] {
    for (std::size_t m = 0; m < kMixes.size(); ++m) {
        benchmark::RegisterBenchmark(std::string("BM_Decode/") + kMixes[m], BM_Decode, m);
    }
    return true;
}();

} // namespace
