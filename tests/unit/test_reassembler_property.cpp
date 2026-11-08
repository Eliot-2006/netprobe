#include "reference/naive_reassembler.h"
#include "support/recording_sink.h"
#include "tcp/reassembler.h"
#include <algorithm>
#include <cstdlib>
#include <gtest/gtest.h>
#include <random>
#include <vector>
using namespace netprobe;
namespace {
struct Packet {
    std::uint32_t offset, logical;
    std::vector<std::byte> data;
};
TEST(ReassemblerProperty, CoverageBytesGapsAndCounters) {
    constexpr std::uint64_t seed = 0xD4D5D6D7D8ULL;
    std::mt19937_64 random{seed};
    std::uint64_t cases = 10000;
    if (const char* env = std::getenv("NETPROBE_PROPERTY_CASES"))
        cases = std::strtoull(env, nullptr, 10);
    ASSERT_GT(cases, 0);
    for (std::uint64_t case_id = 0; case_id < cases; ++case_id) {
        SCOPED_TRACE(testing::Message() << "seed=" << seed << " case=" << case_id);
        auto draw = [&random](std::uint64_t n) { return random() % n; };
        // Most cases are short; every length up to 256 KiB remains reachable.
        const auto length = static_cast<std::uint32_t>(draw(draw(8) == 0 ? 262145 : 4097));
        const auto origin = draw(4) == 0 ? 0U - static_cast<std::uint32_t>(draw(65536))
                                         : static_cast<std::uint32_t>(random());
        std::vector<std::byte> truth(length);
        for (auto& value : truth)
            value = static_cast<std::byte>(random());
        std::vector<Packet> packets;
        bool impaired = false, conflicts = false;
        for (std::uint32_t off = 0; off < length;) {
            const auto count = std::min(length - off, 1U + static_cast<std::uint32_t>(draw(1460)));
            if (draw(100) < 5) {
                impaired = true;
                off += count;
                continue;
            }
            Packet packet{off, count, {truth.begin() + off, truth.begin() + off + count}};
            if (draw(100) < 5) {
                packet.data.resize(static_cast<std::size_t>(draw(count)));
                impaired = true;
            }
            packets.push_back(packet);
            if (draw(100) < 10)
                packets.push_back(packet);
            if (draw(100) < 10) {
                const auto back = static_cast<std::uint32_t>(draw(off + 1));
                const auto size =
                    std::min(length - back, 1U + static_cast<std::uint32_t>(draw(1460)));
                Packet overlap{back, size, {truth.begin() + back, truth.begin() + back + size}};
                if (draw(4) == 0) {
                    conflicts = true;
                    for (auto& value : overlap.data)
                        value ^= std::byte{0xFF};
                }
                packets.push_back(std::move(overlap));
            }
            off += count;
        }
        for (std::size_t off = 0; off < packets.size(); off += 32) {
            auto count = std::min<std::size_t>(32, packets.size() - off);
            std::shuffle(packets.begin() + static_cast<std::ptrdiff_t>(off),
                         packets.begin() + static_cast<std::ptrdiff_t>(off + count), random);
        }
        MemoryBudget budget{1U << 22};
        StreamReassembler stream{budget, {1U << 22}};
        stream.init(origin);
        ASSERT_TRUE(stream.check_invariants());
        test::RecordingSink sink;
        reference::NaiveReassembler model{origin};
        const bool has_fin = draw(5) != 0;
        for (const auto& packet : packets) {
            if (draw(8) == 0) {
                const auto ack = origin + static_cast<std::uint32_t>(draw(length + 1));
                stream.on_peer_ack(ack);
                model.ack(ack);
                ASSERT_TRUE(stream.check_invariants());
            }
            if (has_fin && draw(8) == 0) {
                stream.on_fin(origin + length);
                model.fin(origin + length);
                ASSERT_TRUE(stream.check_invariants());
            }
            stream.on_segment(origin + packet.offset, packet.logical, packet.data, sink);
            model.segment(origin + packet.offset, packet.logical, packet.data);
            ASSERT_TRUE(stream.check_invariants());
            ASSERT_LE(budget.current(), 1U << 22);
            ASSERT_EQ(stream.delivered_offset(), model.delivered);
        }
        if (has_fin) {
            stream.on_fin(origin + length);
            model.fin(origin + length);
            ASSERT_TRUE(stream.check_invariants());
        }
        stream.flush(sink);
        model.flush();
        ASSERT_TRUE(stream.check_invariants());
        ASSERT_EQ(budget.current(), 0);
        ASSERT_EQ(sink.bytes, model.output);
        ASSERT_EQ(sink.gaps.size(), model.gaps.size());
        std::uint64_t gap_bytes = 0, acked_bytes = 0;
        for (std::size_t i = 0; i < model.gaps.size(); ++i) {
            const auto& gap = model.gaps[i];
            ASSERT_EQ(sink.gaps[i].offset, gap.offset);
            ASSERT_EQ(sink.gaps[i].length, gap.length);
            gap_bytes += gap.length;
            if (gap.acked)
                acked_bytes += gap.length;
            if (i < 16) {
                ASSERT_EQ(stream.stats().gaps[i].offset, gap.offset);
                ASSERT_EQ(stream.stats().gaps[i].length, gap.length);
                ASSERT_EQ(stream.stats().gaps[i].acked, gap.acked);
            }
        }
        const auto& actual = stream.stats();
        const auto& expected = model.counters;
        ASSERT_EQ(actual.delivered_bytes, sink.bytes.size());
        ASSERT_EQ(actual.gap_count, model.gaps.size());
        ASSERT_EQ(actual.gap_bytes, gap_bytes);
        ASSERT_EQ(actual.acked_gap_bytes, acked_bytes);
        ASSERT_EQ(actual.gaps_truncated, model.gaps.size() > 16);
        ASSERT_EQ(actual.retransmitted_segments, expected.retransmitted_segments);
        ASSERT_EQ(actual.retransmitted_bytes, expected.retransmitted_bytes);
        ASSERT_EQ(actual.out_of_order_segments, expected.out_of_order_segments);
        ASSERT_EQ(actual.overlap_bytes, expected.overlap_bytes);
        ASSERT_EQ(actual.conflicting_overlap_bytes, expected.conflicting_overlap_bytes);
        ASSERT_EQ(actual.snaplen_missing_bytes, expected.snaplen_missing_bytes);
        ASSERT_EQ(actual.out_of_window_segments, expected.out_of_window_segments);
        ASSERT_EQ(actual.data_after_fin, expected.data_after_fin);
        ASSERT_EQ(actual.complete(), has_fin && model.delivered == length && model.gaps.empty());
        if (!impaired && !conflicts)
            ASSERT_EQ(sink.bytes, truth);
    }
}
} // namespace
