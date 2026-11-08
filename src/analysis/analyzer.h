#pragma once
// One analysis shard (PRD 5.2, 6.7, 6.8): flow table, TCP tracking, reassembly, expiry and
// per-shard results. Self-contained (no globals), so the pipeline can run one per worker.

#include "analysis/memory_budget.h"
#include "analysis/shard_result.h"
#include "decode/decode.h"
#include "flow/flow_key.h"
#include "pcap/record.h"
#include "tcp/reassembler.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>

namespace netprobe {

struct AnalyzerConfig {
    std::int64_t idle_timeout_ns = 300'000'000'000;
    std::int64_t closed_linger_ns = 10'000'000'000; // fixed by PRD D18
    std::uint64_t max_flows = 1'000'000;            // for this shard
    std::uint64_t max_stream_buffer = 4ull << 20;
    std::uint64_t reassembly_budget = 512ull << 20; // for this shard
    std::size_t top_k = 1000;
    std::optional<std::filesystem::path> export_dir;
};

class Analyzer {
public:
    explicit Analyzer(AnalyzerConfig cfg);
    ~Analyzer();
    Analyzer(const Analyzer&) = delete;
    Analyzer& operator=(const Analyzer&) = delete;

    // Accepts every decoded packet; only non-fragmented TCP/UDP creates or updates flows.
    void process(const PacketRecord& rec, const DecodedPacket& pkt);
    // Finalizes all remaining flows and returns the shard's results. Call once.
    ShardResult finish();

    std::size_t live_flows() const noexcept { return flows_.size(); }
    const MemoryBudget& budget() const noexcept { return budget_; }

    struct Flow; // defined in analyzer.cpp

private:
    using Map = std::unordered_map<FlowKey, Flow, FlowKeyHash>;
    struct List {
        Flow* head = nullptr;
        Flow* tail = nullptr;
    };

    Map::iterator create(const FlowKey& key, Direction dir, const PacketRecord& rec,
                         const DecodedPacket& pkt);
    void update(Flow& f, Direction dir, const PacketRecord& rec, const DecodedPacket& pkt);
    void finalize(Map::iterator it, CloseReason reason);
    void evict_one();
    void sweep();
    void touch(Flow& f);
    void unlink(Flow& f);
    CloseReason natural_close(const Flow& f) const noexcept;

    AnalyzerConfig cfg_;
    MemoryBudget budget_;
    Map flows_;
    List open_, closed_;
    ShardResult result_;
    std::int64_t now_ = INT64_MIN;
    std::int64_t last_sweep_ = INT64_MIN;
    std::uint64_t since_sweep_ = 0;
};

} // namespace netprobe
