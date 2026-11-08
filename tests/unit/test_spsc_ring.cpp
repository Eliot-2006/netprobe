#include "pipeline/spsc_ring.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <limits>
#include <thread>

using namespace netprobe;

TEST(SpscRing, EmptyFullFifoAndWraparound) {
    SpscRing<std::uint32_t, 4> ring(std::numeric_limits<std::uint32_t>::max() - 2);
    std::uint32_t value = 99;
    EXPECT_FALSE(ring.try_pop(value));
    for (std::uint32_t round = 0; round < 100; ++round) {
        for (std::uint32_t i = 0; i < 4; ++i) {
            ASSERT_TRUE(ring.try_push(round * 4 + i));
        }
        EXPECT_FALSE(ring.try_push(999));
        for (std::uint32_t i = 0; i < 4; ++i) {
            ASSERT_TRUE(ring.try_pop(value));
            EXPECT_EQ(value, round * 4 + i);
        }
        EXPECT_FALSE(ring.try_pop(value));
    }
}

TEST(SpscRing, TwoThreadSequence) {
    std::uint64_t count = 100'000;
#ifdef NDEBUG
    count = 100'000'000;
#endif
    if (const char* override_count = std::getenv("NETPROBE_SPSC_ITEMS")) {
        count = std::strtoull(override_count, nullptr, 10);
    }
    SpscRing<std::uint64_t, 256> ring;
    std::atomic<bool> failed{false};
    bool ordered = true;
    std::jthread producer([&] {
        for (std::uint64_t i = 0; i < count; ++i) {
            if (!ring.push_wait(i, failed)) {
                return;
            }
        }
    });
    for (std::uint64_t i = 0; i < count; ++i) {
        std::uint64_t value = count;
        ASSERT_TRUE(ring.pop_wait(value, failed));
        ordered = ordered && value == i;
    }
    producer.join();
    EXPECT_TRUE(ordered);
}

TEST(SpscRing, FailureWakesEmptyConsumerAndFullProducer) {
    for (bool full : {false, true}) {
        SpscRing<int, 1> ring;
        std::atomic<bool> failed{false};
        if (full) {
            ASSERT_TRUE(ring.try_push(1));
        }
        std::atomic<bool> started{false};
        bool result = true;
        std::jthread waiter([&] {
            started.store(true, std::memory_order_release);
            int value = 0;
            result = full ? ring.push_wait(2, failed) : ring.pop_wait(value, failed);
        });
        while (!started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        failed.store(true, std::memory_order_release);
        ring.wake_waiters();
        waiter.join();
        EXPECT_FALSE(result);
    }
}
