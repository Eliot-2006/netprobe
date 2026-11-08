#pragma once
// Per-shard accounting for out-of-order reassembly storage (PRD 6.8, invariant O2).

#include <algorithm>
#include <cassert>
#include <cstdint>

namespace netprobe {

class MemoryBudget {
public:
    explicit MemoryBudget(std::uint64_t limit) noexcept : limit_(limit) {}

    bool can_charge(std::uint64_t n) const noexcept {
        return n <= limit_ - std::min(current_, limit_);
    }
    void charge(std::uint64_t n) noexcept {
        current_ += n;
        peak_ = std::max(peak_, current_);
    }
    void refund(std::uint64_t n) noexcept {
        assert(current_ >= n);
        current_ -= n;
    }
    std::uint64_t limit() const noexcept { return limit_; }
    std::uint64_t current() const noexcept { return current_; }
    std::uint64_t peak() const noexcept { return peak_; }

private:
    std::uint64_t limit_;
    std::uint64_t current_ = 0;
    std::uint64_t peak_ = 0;
};

} // namespace netprobe
