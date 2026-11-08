#include "tcp/seq.h"
#include <array>
#include <gtest/gtest.h>
#include <limits>
using namespace netprobe;

TEST(Seq, ModularDifference) {
    EXPECT_EQ(seq_diff(0, 0xFFFFFFFFU), 1);
    EXPECT_EQ(seq_diff(0xFFFFFFFFU, 0), -1);
    EXPECT_EQ(seq_diff(0x80000000U, 0), std::numeric_limits<std::int32_t>::min());
}
TEST(Seq, ExhaustiveOriginDeltaMatrix) {
    constexpr std::int64_t window = 1LL << 30;
    for (auto origin :
         std::array<std::uint32_t, 6>{0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFA24}) {
        SeqUnwrapper unwrap;
        unwrap.init(origin);
        for (auto ref :
             std::array<std::uint64_t, 5>{0, 1, 1ULL << 30, 1ULL << 32, (3ULL << 32) + 1500}) {
            for (auto delta :
                 std::array<std::int64_t, 7>{-window - 1, -window, -1, 0, 1, window, window + 1}) {
                auto seq =
                    origin + static_cast<std::uint32_t>(ref) + static_cast<std::uint32_t>(delta);
                auto actual = unwrap.to_offset(seq, ref);
                if (delta < -window || delta > window ||
                    (delta < 0 && ref < static_cast<std::uint64_t>(-delta))) {
                    EXPECT_FALSE(actual) << origin << ' ' << ref << ' ' << delta;
                } else {
                    ASSERT_TRUE(actual);
                    EXPECT_EQ(*actual, delta < 0 ? ref - static_cast<std::uint64_t>(-delta)
                                                 : ref + static_cast<std::uint64_t>(delta));
                }
            }
        }
    }
}
TEST(Seq, OffsetOverflowRejected) {
    SeqUnwrapper unwrap;
    unwrap.init(0);
    EXPECT_FALSE(unwrap.to_offset(0, std::numeric_limits<std::uint64_t>::max()));
}
