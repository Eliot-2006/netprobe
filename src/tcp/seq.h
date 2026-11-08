#pragma once
#include <cstdint>
#include <limits>
#include <optional>
namespace netprobe {
constexpr std::int32_t seq_diff(std::uint32_t a, std::uint32_t b) noexcept {
    return static_cast<std::int32_t>(a - b);
}
class SeqUnwrapper {
public:
    void init(std::uint32_t origin_seq) noexcept { origin_ = origin_seq; }
    std::optional<std::uint64_t> to_offset(std::uint32_t seq,
                                           std::uint64_t reference) const noexcept {
        const auto delta = static_cast<std::int64_t>(
            seq_diff(seq, origin_ + static_cast<std::uint32_t>(reference)));
        constexpr std::int64_t window = 1LL << 30;
        if (delta < -window || delta > window)
            return std::nullopt;
        if (delta < 0) {
            const auto distance = static_cast<std::uint64_t>(-delta);
            if (reference < distance)
                return std::nullopt;
            return reference - distance;
        }
        const auto distance = static_cast<std::uint64_t>(delta);
        if (reference > std::numeric_limits<std::uint64_t>::max() - distance)
            return std::nullopt;
        return reference + distance;
    }

private:
    std::uint32_t origin_ = 0;
};
} // namespace netprobe
