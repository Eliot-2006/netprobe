#pragma once

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <thread>
#include <type_traits>

namespace netprobe {

// Exactly one producer and one consumer. On failure, store failed then call wake_waiters().
// Wait registration uses an RMW handshake: release/acquire stores alone can lose a wakeup.
template <class T, std::size_t Capacity> class SpscRing {
    static_assert(std::has_single_bit(Capacity));
    static_assert(Capacity <= std::numeric_limits<std::uint32_t>::max() / 2);
    static_assert(std::is_nothrow_copy_assignable_v<T>);
    static_assert(std::atomic<std::uint32_t>::is_always_lock_free);

public:
    explicit SpscRing(std::uint32_t initial_index = 0) noexcept
        : head_(initial_index), cached_tail_(initial_index), tail_(initial_index),
          cached_head_(initial_index) {}

    bool try_push(T value) noexcept {
        const auto head = head_.load(std::memory_order_relaxed);
        if (head - cached_tail_ == Capacity) {
            cached_tail_ = tail_.load(std::memory_order_acquire);
            if (head - cached_tail_ == Capacity) {
                return false;
            }
        }
        slots_[head & (Capacity - 1)] = value;
        head_.store(head + 1, std::memory_order_release);
        wake(consumer_waiting_);
        return true;
    }

    bool try_pop(T& value) noexcept {
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == cached_head_) {
            cached_head_ = head_.load(std::memory_order_acquire);
            if (tail == cached_head_) {
                return false;
            }
        }
        value = slots_[tail & (Capacity - 1)];
        tail_.store(tail + 1, std::memory_order_release);
        wake(producer_waiting_);
        return true;
    }

    bool push_wait(T value, const std::atomic<bool>& failed) noexcept {
        return wait(producer_waiting_, failed, [&] { return try_push(value); });
    }
    bool pop_wait(T& value, const std::atomic<bool>& failed) noexcept {
        return wait(consumer_waiting_, failed, [&] { return try_pop(value); });
    }

    void wake_waiters() noexcept {
        wake(producer_waiting_);
        wake(consumer_waiting_);
    }

    // Producer-only occupancy sample, taken immediately after publishing a batch.
    std::uint32_t occupancy() const noexcept {
        return head_.load(std::memory_order_relaxed) - tail_.load(std::memory_order_acquire);
    }

private:
    static void wake(std::atomic<std::uint32_t>& waiting) noexcept {
        if (waiting.exchange(0, std::memory_order_acq_rel) != 0) {
            waiting.notify_one();
        }
    }

    template <class Try>
    static bool wait(std::atomic<std::uint32_t>& waiting, const std::atomic<bool>& failed,
                     Try attempt) noexcept {
        for (;;) {
            for (unsigned spin = 0; spin < 64; ++spin) {
                if (failed.load(std::memory_order_acquire)) {
                    return false;
                }
                if (attempt()) {
                    return true;
                }
                std::this_thread::yield();
            }
            waiting.exchange(1, std::memory_order_acq_rel);
            if (failed.load(std::memory_order_acquire)) {
                waiting.store(0, std::memory_order_release);
                return false;
            }
            if (attempt()) {
                waiting.store(0, std::memory_order_release);
                return true;
            }
            // Wait on the registration word so cancellation changes the waited-on value too.
            waiting.wait(1, std::memory_order_acquire);
        }
    }

    alignas(64) std::atomic<std::uint32_t> head_;
    alignas(64) std::uint32_t cached_tail_;
    alignas(64) std::atomic<std::uint32_t> tail_;
    alignas(64) std::uint32_t cached_head_;
    alignas(64) std::atomic<std::uint32_t> producer_waiting_{0};
    alignas(64) std::atomic<std::uint32_t> consumer_waiting_{0};
    std::array<T, Capacity> slots_{};
};

} // namespace netprobe
