#include "pipeline/pipeline.h"

#include "pipeline/spsc_ring.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace netprobe {
namespace {
constexpr std::size_t batch_size = 256, batch_count = 8;
struct Batch {
    std::array<PacketDesc, batch_size> packets;
    std::size_t size = 0;
    std::uint64_t end_offset = 0;
};
struct Worker {
    SpscRing<Batch*, batch_count> work, free;
    std::array<Batch, batch_count> batches;
    alignas(64) std::atomic<std::uint64_t> completed_offset{0};
    WorkerRunStats metrics;
    std::exception_ptr error;
    ShardResult result{0};
    // Reader-owned, including the partial batch which has not reached the work ring yet.
    Batch* filling = nullptr;
    std::uint64_t submitted_offset = 0;
    std::uint64_t max_occupancy = 0;
};
} // namespace

ShardResult run_pipeline(PcapReader& reader, MappedFile& file, const AnalyzerConfig& config,
                         std::uint32_t workers, ReaderStats& stats, RunInfo& run,
                         void (*before_batch)(std::uint32_t)) {
    if (workers == 0) {
        throw std::invalid_argument("pipeline requires at least one worker");
    }
    std::vector<std::unique_ptr<Worker>> shards;
    for (std::uint32_t i = 0; i < workers; ++i) {
        auto worker = std::make_unique<Worker>();
        for (auto& batch : worker->batches) {
            worker->free.try_push(&batch);
        }
        shards.push_back(std::move(worker));
    }
    std::atomic<bool> failed{false};
    std::atomic<std::uint32_t> first_error{workers};
    auto fail = [&] {
        failed.store(true, std::memory_order_release);
        for (auto& shard : shards) {
            shard->work.wake_waiters();
            shard->free.wake_waiters();
        }
    };
    AnalyzerConfig shard_config = config;
    shard_config.max_flows = std::max<std::uint64_t>(1, shard_config.max_flows / workers);
    shard_config.reassembly_budget /= workers;
    std::vector<std::jthread> threads;
    threads.reserve(workers);
    std::exception_ptr reader_error;
    std::uint64_t reader_offset = 24, released_offset = 0, submitted_batches = 0;
    // Release also by reader progress, not only by submitted batches: a capture dominated by
    // non-flow packets (ARP, ICMP, malformed) submits few batches and otherwise kept the whole
    // file resident (independent audit; 290 MB mostly-ARP capture: 294 MiB RSS vs 68 MiB inline).
    constexpr std::uint64_t release_interval = 64ULL << 20;
    std::uint64_t next_release_check = release_interval;
    auto release = [&] {
        auto frontier = reader_offset;
        for (const auto& shard : shards) {
            const auto completed = shard->completed_offset.load(std::memory_order_acquire);
            if (completed < shard->submitted_offset) {
                frontier = std::min(frontier, completed);
            }
            if (shard->filling && shard->filling->size != 0) {
                frontier = std::min(frontier, shard->filling->packets[0].record.file_offset);
            }
        }
        if (frontier > released_offset) {
            file.release_before(frontier);
            released_offset = frontier;
        }
    };
    auto submit = [&](Worker& shard) {
        auto* batch = shard.filling;
        if (!shard.work.push_wait(batch, failed)) {
            return false;
        }
        shard.submitted_offset = batch->end_offset;
        shard.filling = nullptr;
        shard.max_occupancy = std::max<std::uint64_t>(shard.max_occupancy, shard.work.occupancy());
        if (++submitted_batches % 64 == 0) {
            release();
        }
        return true;
    };
    try {
        for (std::uint32_t i = 0; i < workers; ++i) {
            threads.emplace_back([&, i] {
                auto& shard = *shards[i];
                std::unique_ptr<Analyzer> analyzer;
                auto record_error = [&] {
                    shard.error = std::current_exception();
                    auto none = workers;
                    first_error.compare_exchange_strong(none, i, std::memory_order_acq_rel);
                    fail();
                };
                try {
                    analyzer = std::make_unique<Analyzer>(shard_config);
                } catch (...) {
                    record_error();
                }
                for (;;) {
                    Batch* batch = nullptr;
                    if (!shard.work.try_pop(batch)) {
                        ++shard.metrics.idle_waits;
                        if (!shard.work.pop_wait(batch, failed)) {
                            // Failure cancels blocking waits; still drain until the sentinel.
                            while (!shard.work.try_pop(batch)) {
                                std::this_thread::yield();
                            }
                        }
                    }
                    if (!batch) {
                        break;
                    }
                    if (!failed.load(std::memory_order_acquire)) {
                        try {
                            if (before_batch) {
                                before_batch(i);
                            }
                            for (std::size_t j = 0; j < batch->size; ++j) {
                                const auto& desc = batch->packets[j];
                                analyzer->process(desc.record, desc.packet);
                                ++shard.metrics.packets;
                            }
                            ++shard.metrics.batches;
                        } catch (...) {
                            record_error();
                        }
                    }
                    // O1: processing has returned; only owned OOO bytes survive this point.
                    shard.completed_offset.store(batch->end_offset, std::memory_order_release);
                    // Exactly eight batches exist, so the return ring always has room.
                    const bool returned = shard.free.try_push(batch);
                    (void)returned;
                    assert(returned);
                }
                if (!failed.load(std::memory_order_acquire)) {
                    try {
                        shard.result = analyzer->finish();
                    } catch (...) {
                        record_error();
                    }
                }
            });
        }
        PacketRecord record;
        while (!failed.load(std::memory_order_acquire) && reader.next(record)) {
            // Check before advancing reader_offset: release() frees pages below reader_offset, so
            // it must not yet include the record that has just been read but not decoded (O1).
            if (record.file_offset >= next_release_check) {
                next_release_check = record.file_offset + release_interval;
                bool ok = true;
                for (auto& shard : shards) { // a partial batch would pin its first packet's page
                    if (shard->filling && shard->filling->size != 0 && !submit(*shard)) {
                        ok = false;
                        break;
                    }
                }
                if (!ok) {
                    break;
                }
                release();
            }
            reader_offset = record.file_offset + 16 + record.data.size();
            const auto packet = decode_packet(record);
            stats.add(record, packet);
            if (!packet.is_tcp() && !packet.is_udp()) {
                continue;
            }
            const auto hash = hash_flow_key(make_flow_key(packet).key);
            auto& shard = *shards[shard_of(hash, workers)];
            if (!shard.filling) {
                if (failed.load(std::memory_order_acquire)) {
                    break;
                }
                if (!shard.free.try_pop(shard.filling)) {
                    ++run.reader_stalls;
                    const auto start = std::chrono::steady_clock::now();
                    const bool acquired = shard.free.pop_wait(shard.filling, failed);
                    run.reader_stall_ns += static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - start)
                            .count());
                    if (!acquired) {
                        break;
                    }
                }
                shard.filling->size = 0;
            }
            auto& batch = *shard.filling;
            batch.packets[batch.size++] = {record, packet, hash};
            batch.end_offset = reader_offset;
            if (batch.size == batch_size && !submit(shard)) {
                break;
            }
        }
        if (!failed.load(std::memory_order_acquire)) {
            for (auto& shard : shards) {
                if (shard->filling && shard->filling->size != 0 && !submit(*shard)) {
                    break;
                }
            }
        }
    } catch (...) {
        reader_error = std::current_exception();
        fail();
    }
    // Covers reader exceptions and partial thread creation as well as worker exceptions.
    for (std::size_t i = 0; i < threads.size(); ++i) {
        while (!shards[i]->work.try_push(nullptr)) {
            std::this_thread::yield();
        }
    }
    for (auto& thread : threads) {
        thread.join();
    }
    if (first_error.load(std::memory_order_acquire) != workers) {
        std::rethrow_exception(shards[first_error.load(std::memory_order_relaxed)]->error);
    }
    if (reader_error) {
        std::rethrow_exception(reader_error);
    }
    file.release_before(reader_offset);
    ShardResult result(config.top_k);
    run.workers = workers;
    run.worker_stats.clear();
    for (auto& shard : shards) {
        shard->metrics.max_occupancy = shard->max_occupancy;
        run.worker_stats.push_back(shard->metrics);
        result.merge(std::move(shard->result));
    }
    return result;
}
} // namespace netprobe
