#include "support/recording_sink.h"
#include "tcp/reassembler.h"
#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <numeric>
#include <random>
#include <string_view>
#include <utility>
using namespace netprobe;
using netprobe::test::RecordingSink;
namespace {
std::vector<std::byte> bytes(std::string_view text) {
    std::vector<std::byte> result;
    for (char c : text)
        result.push_back(static_cast<std::byte>(c));
    return result;
}
class Reassembler : public testing::Test {
protected:
    MemoryBudget budget{1U << 20};
    StreamReassembler stream{budget, {1U << 18}};
    RecordingSink sink;
    void SetUp() override {
        stream.init(100);
        check();
    }
    void check() {
        ASSERT_TRUE(stream.check_invariants());
        EXPECT_EQ(budget.current(), stream.buffered_bytes());
    }
    void segment(std::uint32_t offset, std::string_view text, std::uint32_t logical = 0) {
        auto data = bytes(text);
        stream.on_segment(100 + offset,
                          logical == 0 ? static_cast<std::uint32_t>(data.size()) : logical, data,
                          sink);
        check();
    }
    void fin(std::uint32_t offset) {
        stream.on_fin(100 + offset);
        check();
    }
    void ack(std::uint32_t offset) {
        stream.on_peer_ack(100 + offset);
        check();
    }
    void flush() {
        stream.flush(sink);
        check();
        EXPECT_EQ(budget.current(), 0);
    }
};
TEST_F(Reassembler, InOrderAndExactDuplicate) {
    segment(0, "abc");
    segment(0, "abc");
    segment(2, "cde");
    fin(5);
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcde"));
    EXPECT_TRUE(stream.stats().complete());
    EXPECT_EQ(stream.stats().retransmitted_segments, 1);
    EXPECT_EQ(stream.stats().retransmitted_bytes, 4);
}
TEST_F(Reassembler, ReverseAndRandomPermutation) {
    for (bool random : {false, true}) {
        MemoryBudget local_budget{10000};
        StreamReassembler local{local_budget, {10000}};
        local.init(0);
        ASSERT_TRUE(local.check_invariants());
        RecordingSink output;
        std::array<std::uint32_t, 32> order{};
        std::iota(order.begin(), order.end(), 0U);
        if (random) {
            std::mt19937 gen{42};
            std::shuffle(order.begin(), order.end(), gen);
        } else
            std::reverse(order.begin(), order.end());
        std::vector<std::byte> expected;
        for (std::uint32_t i = 0; i < 32; ++i)
            expected.push_back(static_cast<std::byte>(i));
        for (auto i : order) {
            local.on_segment(i, 1, Bytes(expected).subspan(i, 1), output);
            ASSERT_TRUE(local.check_invariants());
        }
        local.flush(output);
        ASSERT_TRUE(local.check_invariants());
        EXPECT_EQ(output.bytes, expected);
        EXPECT_EQ(local_budget.current(), 0);
    }
}
TEST_F(Reassembler, RetransmissionCoversTwoBufferedSegmentsAndHole) {
    segment(2, "cd");
    segment(6, "gh");
    segment(0, "abcdefghij");
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcdefghij"));
    EXPECT_TRUE(sink.gaps.empty());
    EXPECT_EQ(stream.stats().overlap_bytes, 4);
    EXPECT_EQ(stream.stats().out_of_order_segments, 2);
}
TEST_F(Reassembler, PartialOverlapBothSidesAndConflicts) {
    segment(3, "DEF");
    segment(1, "bcxxxgh");
    segment(0, "a");
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcDEFgh"));
    EXPECT_EQ(stream.stats().overlap_bytes, 3);
    EXPECT_EQ(stream.stats().conflicting_overlap_bytes, 3);
}
TEST_F(Reassembler, WrapAndSynPayloadCallerAdjusted) {
    stream.init(0xFFFFFF01U);
    check();
    auto data = bytes("wrapped");
    stream.on_segment(1, 7, data, sink);
    check();
    std::vector<std::byte> prefix(256, std::byte{1});
    stream.on_segment(0xFFFFFF01U, 256, prefix, sink);
    check();
    stream.on_fin(8);
    check();
    flush();
    prefix.insert(prefix.end(), data.begin(), data.end());
    EXPECT_EQ(sink.bytes, prefix);
    EXPECT_TRUE(stream.stats().complete());
}
TEST_F(Reassembler, FinThenLateFillAndDataAfterFin) {
    segment(3, "def");
    fin(6);
    segment(6, "bad");
    segment(0, "abcEXTRA");
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcdef"));
    EXPECT_TRUE(stream.stats().complete());
    EXPECT_EQ(stream.stats().data_after_fin, 2);
}
TEST_F(Reassembler, FinBoundsPreviouslyBufferedDataAndAck) {
    segment(3, "defBAD");
    segment(12, "BAD");
    ack(20);
    fin(6);
    segment(0, "abc");
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcdef"));
    EXPECT_TRUE(sink.gaps.empty());
    EXPECT_EQ(stream.delivered_offset(), 6);
}
TEST_F(Reassembler, SnaplenHoleFilledAndOldCapturedPrefix) {
    segment(0, "abc", 6);
    segment(0, "abcdef");
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcdef"));
    EXPECT_TRUE(sink.gaps.empty());
    EXPECT_EQ(stream.stats().snaplen_missing_bytes, 3);
    EXPECT_EQ(stream.stats().retransmitted_bytes, 3);
}
TEST_F(Reassembler, SnaplenEntireCapturedPrefixAlreadyDelivered) {
    segment(0, "abcd");
    segment(0, "ab", 8);
    flush();
    EXPECT_EQ(sink.bytes, bytes("abcd"));
    ASSERT_EQ(sink.gaps.size(), 1);
    EXPECT_EQ(sink.gaps[0].offset, 4);
    EXPECT_EQ(sink.gaps[0].length, 4);
    EXPECT_EQ(stream.stats().snaplen_missing_bytes, 4);
}
TEST_F(Reassembler, AckWatermarkIsLazyAndClassifiesWholeGaps) {
    ack(8);
    EXPECT_TRUE(sink.gaps.empty());
    segment(3, "d");
    segment(6, "g");
    ack(10);
    flush();
    ASSERT_EQ(stream.stats().gap_count, 3);
    EXPECT_EQ(stream.stats().gap_bytes, 8);
    EXPECT_EQ(stream.stats().acked_gap_bytes, 8);
    EXPECT_TRUE(stream.stats().gaps[2].acked);
}
TEST_F(Reassembler, PartlyAckedGapIsNotClassifiedAcked) {
    ack(2);
    segment(4, "e");
    flush();
    EXPECT_EQ(stream.stats().acked_gap_bytes, 0);
    EXPECT_FALSE(stream.stats().gaps[0].acked);
}
TEST_F(Reassembler, OutOfWindowAndZeroLengthNoOp) {
    auto data = bytes("x");
    stream.on_segment(100 + (1U << 30) + 1, 1, data, sink);
    check();
    stream.on_segment(99, 1, data, sink);
    check();
    stream.on_segment(100, 0, data, sink);
    check();
    EXPECT_EQ(stream.stats().out_of_window_segments, 2);
    EXPECT_EQ(stream.delivered_offset(), 0);
    EXPECT_EQ(budget.current(), 0);
}
TEST_F(Reassembler, GapDetailsAreBoundedAndCountersExact) {
    for (std::uint32_t i = 0; i < 20; ++i)
        segment(i * 2 + 1, "x");
    flush();
    EXPECT_EQ(stream.stats().gap_count, 20);
    EXPECT_EQ(stream.stats().gap_bytes, 20);
    EXPECT_TRUE(stream.stats().gaps_truncated);
    EXPECT_EQ(stream.stats().gaps[15].offset, 30);
}
TEST(ReassemblyLimits, ForcedFlushPreservesIncomingBytesBeforeBufferedData) {
    for (bool shard_limit : {false, true}) {
        MemoryBudget budget{shard_limit ? 70U : 10000U};
        StreamReassembler stream{budget, {shard_limit ? 10000U : 70U}};
        RecordingSink sink;
        stream.init(0);
        ASSERT_TRUE(stream.check_invariants());
        auto tail = bytes("gh");
        stream.on_segment(6, 2, tail, sink);
        ASSERT_TRUE(stream.check_invariants());
        auto head = bytes("abcdef");
        stream.on_segment(0, 6, head, sink);
        ASSERT_TRUE(stream.check_invariants());
        stream.flush(sink);
        ASSERT_TRUE(stream.check_invariants());
        EXPECT_EQ(sink.bytes, bytes("abcdefgh"));
        EXPECT_TRUE(sink.gaps.empty());
        EXPECT_EQ(stream.stats().forced_flushes, 1);
        EXPECT_EQ(budget.current(), 0);
    }
}
TEST(ReassemblyLimits, NoBudgetAndSharedBudget) {
    MemoryBudget budget{65};
    RecordingSink sink;
    StreamReassembler first{budget, {1000}}, second{budget, {0}};
    first.init(0);
    second.init(0);
    auto data = bytes("x");
    first.on_segment(10, 1, data, sink);
    ASSERT_TRUE(first.check_invariants());
    second.on_segment(5, 1, data, sink);
    ASSERT_TRUE(second.check_invariants());
    EXPECT_EQ(budget.current(), 65);
    EXPECT_EQ(second.stats().forced_flushes, 1);
    EXPECT_EQ(second.stats().gap_bytes, 5);
    first.flush(sink);
    second.flush(sink);
    EXPECT_TRUE(first.check_invariants());
    EXPECT_TRUE(second.check_invariants());
    EXPECT_EQ(budget.current(), 0);
}
TEST(ReassemblyLimits, HundredThousandTinyReversedSegments) {
    MemoryBudget budget{4096};
    StreamReassembler stream{budget, {4096}};
    NullSink sink;
    stream.init(0);
    std::array data{std::byte{1}};
    for (std::uint32_t i = 100000; i > 0; --i) {
        stream.on_segment(i, 1, data, sink);
        ASSERT_TRUE(stream.check_invariants());
        ASSERT_LE(budget.current(), 4096);
    }
    stream.flush(sink);
    EXPECT_TRUE(stream.check_invariants());
    EXPECT_EQ(budget.current(), 0);
    EXPECT_GT(stream.stats().forced_flushes, 0);
}
TEST(ReassemblyOwnership, CopyCaptureAndMoveRefundExactlyOnce) {
    MemoryBudget budget{10000};
    RecordingSink sink;
    {
        StreamReassembler original{budget, {10000}};
        original.init(0);
        auto data = bytes("bc");
        original.on_segment(1, 2, data, sink);
        ASSERT_TRUE(original.check_invariants());
        data.assign(2, std::byte{0});
        StreamReassembler moved{std::move(original)};
        EXPECT_EQ(original.buffered_bytes(), 0);
        EXPECT_TRUE(original.check_invariants());
        EXPECT_TRUE(moved.check_invariants());
        StreamReassembler assigned{budget, {10000}};
        assigned.init(0);
        assigned.on_segment(5, 2, data, sink);
        ASSERT_TRUE(assigned.check_invariants());
        assigned = std::move(moved);
        EXPECT_EQ(moved.buffered_bytes(), 0);
        EXPECT_TRUE(moved.check_invariants());
        EXPECT_TRUE(assigned.check_invariants());
        assigned.flush(sink);
        EXPECT_TRUE(assigned.check_invariants());
        EXPECT_EQ(sink.bytes, bytes("bc"));
        assigned.on_segment(10, 2, data, sink);
        EXPECT_TRUE(assigned.check_invariants());
    }
    EXPECT_EQ(budget.current(), 0);
}
TEST(ReassemblyOwnership, FastPathPassesOriginalPointer) {
    class PointerSink final : public StreamSink {
    public:
        const std::byte* expected = nullptr;
        void on_data(std::uint64_t, Bytes data) override { EXPECT_EQ(data.data(), expected); }
        void on_gap(std::uint64_t, std::uint64_t) override { FAIL(); }
    } sink;
    MemoryBudget budget{0};
    StreamReassembler stream{budget, {0}};
    stream.init(7);
    auto data = bytes("payload");
    sink.expected = data.data();
    stream.on_segment(7, 7, data, sink);
    EXPECT_TRUE(stream.check_invariants());
    EXPECT_EQ(budget.peak(), 0);
}
} // namespace

TEST(ReassemblyLayout, IdleStreamKeepsGapDetailsUnallocated) {
    MemoryBudget budget{1000};
    StreamReassembler stream{budget, {1000}};
    EXPECT_LE(sizeof(StreamReassembler), 256);
    EXPECT_TRUE(stream.stats().gaps.empty());
    EXPECT_EQ(stream.stats().gaps.capacity(), 0);
}
TEST(ReassemblyOwnership, LateFinKeepsRetainedAllocationChargedUntilDelivery) {
    MemoryBudget budget{1000};
    StreamReassembler stream{budget, {1000}};
    RecordingSink sink;
    stream.init(0);
    EXPECT_TRUE(stream.check_invariants());
    auto data = bytes("abcDEF");
    stream.on_segment(3, 6, data, sink);
    EXPECT_TRUE(stream.check_invariants());
    stream.on_fin(6);
    EXPECT_TRUE(stream.check_invariants());
    EXPECT_EQ(budget.current(), 6 + kSegmentOverhead);
    stream.flush(sink);
    EXPECT_TRUE(stream.check_invariants());
    EXPECT_EQ(sink.bytes, bytes("abc"));
    EXPECT_EQ(budget.current(), 0);
}

TEST(ReassemblyFin, FinAloneProvesTrailingMissingBytes) {
    MemoryBudget budget{1000};
    StreamReassembler stream{budget, {1000}};
    RecordingSink sink;
    stream.init(0);
    EXPECT_TRUE(stream.check_invariants());
    stream.on_fin(6);
    EXPECT_TRUE(stream.check_invariants());
    stream.flush(sink);
    EXPECT_TRUE(stream.check_invariants());
    ASSERT_EQ(sink.gaps.size(), 1);
    EXPECT_EQ(sink.gaps[0].offset, 0);
    EXPECT_EQ(sink.gaps[0].length, 6);
    EXPECT_FALSE(stream.stats().complete());
}

TEST(ReassemblyWindow, RejectsFarBehindDeliveredAsWellAsFarAhead) {
    MemoryBudget budget{1000};
    StreamReassembler stream{budget, {1000}};
    NullSink sink;
    stream.init(100);
    ASSERT_TRUE(stream.check_invariants());
    // A logical snaplen hole advances the reference without a gigabyte allocation.
    stream.on_segment(100, (1U << 30) + 16, {}, sink);
    ASSERT_TRUE(stream.check_invariants());
    stream.flush(sink);
    ASSERT_TRUE(stream.check_invariants());
    std::array data{std::byte{1}};
    stream.on_segment(100, 1, data, sink);
    ASSERT_TRUE(stream.check_invariants());
    const auto next = 100 + static_cast<std::uint32_t>(stream.delivered_offset());
    stream.on_segment(next + (1U << 30) + 1, 1, data, sink);
    ASSERT_TRUE(stream.check_invariants());
    EXPECT_EQ(stream.stats().out_of_window_segments, 2);
    EXPECT_EQ(stream.delivered_offset(), (1U << 30) + 16);
}

// PRD D7 (revised): an ACKed hole with >= threshold bytes buffered behind it is declared early.
TEST(ReassemblyAckedHole, DeclaredOnceEnoughDataIsBufferedBehindIt) {
    MemoryBudget budget{1U << 24};
    StreamReassembler s{budget, {256U << 10}}; // threshold = 128 KiB
    test::RecordingSink sink;
    s.init(1000);
    std::vector<std::byte> seg(1000, std::byte{7});
    s.on_peer_ack(1000 + 300'000);             // receiver has everything
    for (std::uint32_t i = 1; i <= 140; ++i) { // segment 0 (bytes 0..999) is lost
        s.on_segment(1000 + i * 1000, 1000, seg, sink);
        ASSERT_TRUE(s.check_invariants());
    }
    EXPECT_EQ(s.stats().gap_count, 1u);
    EXPECT_EQ(s.stats().acked_gap_bytes, 1000u);
    EXPECT_EQ(s.stats().forced_flushes, 0u);
    EXPECT_EQ(s.buffered_bytes(), 0u);
    EXPECT_EQ(s.delivered_offset(), 141'000u);
}

TEST(ReassemblyAckedHole, UnackedOrSmallHolesStayLazy) {
    MemoryBudget budget{1U << 24};
    StreamReassembler unacked{budget, {256U << 10}};
    StreamReassembler small{budget, {256U << 10}};
    test::RecordingSink sink;
    unacked.init(0);
    small.init(0);
    std::vector<std::byte> seg(1000, std::byte{1});
    small.on_peer_ack(500'000);
    for (std::uint32_t i = 1; i <= 140; ++i) {
        unacked.on_segment(i * 1000, 1000, seg, sink); // no ACK evidence at all
    }
    for (std::uint32_t i = 1; i <= 100; ++i) {
        small.on_segment(i * 1000, 1000, seg, sink); // 100 KiB < 128 KiB threshold
    }
    EXPECT_EQ(unacked.stats().gap_count, 0u);
    EXPECT_EQ(small.stats().gap_count, 0u);
    EXPECT_GT(small.buffered_bytes(), 0u);
    EXPECT_TRUE(unacked.check_invariants());
    EXPECT_TRUE(small.check_invariants());
}
