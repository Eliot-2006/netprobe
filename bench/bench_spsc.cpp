#include "pipeline/spsc_ring.h"

#include <benchmark/benchmark.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <mutex>
#include <thread>

namespace {
constexpr auto stop = std::numeric_limits<std::uint64_t>::max();

class MutexQueue {
public:
    void push(std::uint64_t value) {
        std::unique_lock lock(mutex_);
        writable_.wait(lock, [&] { return size_ < slots_.size(); });
        slots_[head_++ % slots_.size()] = value;
        ++size_;
        lock.unlock();
        readable_.notify_one();
    }
    std::uint64_t pop() {
        std::unique_lock lock(mutex_);
        readable_.wait(lock, [&] { return size_ != 0; });
        const auto value = slots_[tail_++ % slots_.size()];
        --size_;
        lock.unlock();
        writable_.notify_one();
        return value;
    }

private:
    std::mutex mutex_;
    std::condition_variable readable_, writable_;
    std::array<std::uint64_t, 256> slots_{};
    std::size_t head_ = 0, tail_ = 0, size_ = 0;
};

void BM_Spsc(benchmark::State& state) {
    netprobe::SpscRing<std::uint64_t, 256> ring;
    std::atomic<bool> failed{false};
    std::jthread consumer([&] {
        std::uint64_t value = 0;
        while (ring.pop_wait(value, failed) && value != stop) {
            benchmark::DoNotOptimize(value);
        }
    });
    for (auto _ : state) {
        for (std::int64_t i = 0; i < state.range(0); ++i) {
            ring.push_wait(static_cast<std::uint64_t>(i), failed);
        }
    }
    ring.push_wait(stop, failed);
    consumer.join();
    state.SetItemsProcessed(state.iterations() * state.range(0));
}

void BM_MutexQueue(benchmark::State& state) {
    MutexQueue queue;
    std::jthread consumer([&] {
        for (;;) {
            auto value = queue.pop();
            if (value == stop) {
                return;
            }
            benchmark::DoNotOptimize(value);
        }
    });
    for (auto _ : state) {
        for (std::int64_t i = 0; i < state.range(0); ++i) {
            queue.push(static_cast<std::uint64_t>(i));
        }
    }
    queue.push(stop);
    consumer.join();
    state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_Spsc)->Arg(1)->Arg(256)->UseRealTime();
BENCHMARK(BM_MutexQueue)->Arg(1)->Arg(256)->UseRealTime();
} // namespace
