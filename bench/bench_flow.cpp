// BM_FlowLookup/<flows>: make_flow_key + hash + find-or-insert on a table holding N live flows
// (PRD 12.1). Lookups visit flows in a seeded random order, so every access is a cache-cold hit
// once the table outgrows the cache. The mapped value is 8 bytes; the analyzer's real Flow node is
// much larger, so analyzer-level cache behaviour is worse than this micro-benchmark shows.
#include "flow/flow_key.h"

#if defined(__clang__) // benchmark.h and BENCHMARK() use __COUNTER__ (flagged by -Wpedantic, Clang
                       // 23)
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif
#include <benchmark/benchmark.h>

#include <algorithm>
#include <numeric>
#include <random>
#include <unordered_map>
#include <vector>

namespace {

using namespace netprobe;

DecodedPacket make_packet(std::uint32_t i) {
    DecodedPacket p;
    p.ip_version = 4;
    p.l4_proto = ip_proto::tcp;
    p.src.b[10] = p.src.b[11] = p.dst.b[10] = p.dst.b[11] = 0xff; // IPv4-mapped
    p.src.b[12] = 10;
    p.src.b[13] = static_cast<std::uint8_t>(i >> 16);
    p.src.b[14] = static_cast<std::uint8_t>(i >> 8);
    p.src.b[15] = static_cast<std::uint8_t>(i);
    p.dst.b[12] = 172;
    p.dst.b[13] = 16;
    p.dst.b[15] = static_cast<std::uint8_t>(1 + i % 250);
    p.src_port = static_cast<std::uint16_t>(1024 + (i * 7) % 60000);
    p.dst_port = 80;
    return p;
}

void BM_FlowLookup(benchmark::State& state) {
    const auto n = static_cast<std::uint32_t>(state.range(0));
    std::vector<DecodedPacket> pkts;
    pkts.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        pkts.push_back(make_packet(i));
    }
    std::vector<std::uint32_t> order(n);
    std::iota(order.begin(), order.end(), 0u);
    std::shuffle(order.begin(), order.end(), std::mt19937_64(1));

    std::unordered_map<FlowKey, std::uint64_t, FlowKeyHash> table;
    table.reserve(n);
    for (const auto& p : pkts) {
        table.try_emplace(make_flow_key(p).key, 0);
    }
    for (auto _ : state) {
        for (const std::uint32_t i : order) {
            const KeyedPacket kp = make_flow_key(pkts[i]);
            auto it = table.try_emplace(kp.key, 0).first;
            ++it->second;
            benchmark::DoNotOptimize(it);
        }
    }
    state.counters["live_flows"] = static_cast<double>(table.size());
    state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()) * n);
}
BENCHMARK(BM_FlowLookup)->Arg(1 << 10)->Arg(1 << 16)->Arg(1 << 20);

} // namespace
