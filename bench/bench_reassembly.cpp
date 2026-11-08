// BM_Reassembly_{InOrder,Reorder,Retransmit} (PRD 12.1): one TCP direction of 16384 segments of
// 1460 B (~22.8 MiB) into a NullSink. Metric: unique payload bytes per second (retransmitted
// copies are processed but not counted). Reorder: pct of segments displaced 1..8 positions later.
// Retransmit: pct of segments sent a second time 1..8 positions after the original.
#include "tcp/reassembler.h"

#if defined(__clang__) // benchmark.h and BENCHMARK() use __COUNTER__ (flagged by -Wpedantic, Clang
                       // 23)
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif
#include <benchmark/benchmark.h>

#include <algorithm>
#include <random>
#include <vector>

namespace {

using namespace netprobe;

constexpr std::uint32_t kSeg = 1460, kSegments = 16384, kOrigin = 1000;

std::vector<std::uint32_t> make_order(int reorder_pct, int dup_pct) {
    std::mt19937_64 rng(1);
    auto chance = [&](int pct) { return rng() % 100 < static_cast<unsigned>(pct); };
    std::vector<std::uint32_t> order(kSegments);
    for (std::uint32_t i = 0; i < kSegments; ++i) {
        order[i] = i;
    }
    for (std::uint32_t i = 0; i + 1 < kSegments; ++i) {
        if (chance(reorder_pct)) {
            const auto j = std::min<std::size_t>(i + 1 + rng() % 8, kSegments - 1);
            std::rotate(order.begin() + i, order.begin() + i + 1,
                        order.begin() + static_cast<std::ptrdiff_t>(j) + 1);
        }
    }
    std::vector<std::uint32_t> result;
    std::vector<std::pair<std::size_t, std::uint32_t>> pending; // (due position, segment)
    auto release_due = [&] {
        for (std::size_t k = 0; k < pending.size();) {
            if (pending[k].first <= result.size()) {
                result.push_back(pending[k].second);
                pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(k));
                k = 0;
            } else {
                ++k;
            }
        }
    };
    for (const std::uint32_t idx : order) {
        result.push_back(idx);
        if (chance(dup_pct)) {
            pending.emplace_back(result.size() + rng() % 8, idx);
        }
        release_due();
    }
    for (const auto& p : pending) {
        result.push_back(p.second);
    }
    return result;
}

void run(benchmark::State& state, int reorder_pct, int dup_pct) {
    const std::vector<std::uint32_t> order = make_order(reorder_pct, dup_pct);
    const std::vector<std::byte> payload(kSeg, std::byte{0x5a});
    auto stream = [&] {
        MemoryBudget budget(512ull << 20);
        StreamReassembler r(budget, ReassemblyLimits{4ull << 20});
        NullSink sink;
        r.init(kOrigin);
        for (const std::uint32_t idx : order) {
            r.on_segment(kOrigin + idx * kSeg, kSeg, Bytes(payload), sink);
        }
        return r.stats().delivered_bytes;
    };
    if (stream() != std::uint64_t{kSegments} * kSeg) { // the workload must really be reassembled
        state.SkipWithError("delivered bytes != stream size");
        return;
    }
    for (auto _ : state) {
        benchmark::DoNotOptimize(stream());
    }
    const auto iters = static_cast<std::int64_t>(state.iterations());
    state.SetBytesProcessed(iters * std::int64_t{kSegments} * kSeg);
    state.SetItemsProcessed(iters * static_cast<std::int64_t>(order.size()));
}

void BM_Reassembly_InOrder(benchmark::State& s) {
    run(s, 0, 0);
}
void BM_Reassembly_Reorder(benchmark::State& s) {
    run(s, static_cast<int>(s.range(0)), 0);
}
void BM_Reassembly_Retransmit(benchmark::State& s) {
    run(s, 0, static_cast<int>(s.range(0)));
}

BENCHMARK(BM_Reassembly_InOrder);
BENCHMARK(BM_Reassembly_Reorder)->Arg(1)->Arg(10)->Arg(30);
BENCHMARK(BM_Reassembly_Retransmit)->Arg(1)->Arg(10);

} // namespace
