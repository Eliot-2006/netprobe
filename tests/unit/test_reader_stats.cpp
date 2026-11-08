#include "analysis/reader_stats.h"

#include <gtest/gtest.h>

using namespace netprobe;

TEST(Timeline, FirstPacketSetsOriginAndBucketsByWidth) {
    Timeline t;
    t.add(1'000'000'000, 10);
    t.add(1'000'000'000 + 2'500'000, 20); // 2.5 ms -> bucket 2
    auto b = t.buckets();
    ASSERT_EQ(b.size(), 3u);
    EXPECT_EQ(b[0].packets, 1u);
    EXPECT_EQ(b[2].bytes, 20u);
    EXPECT_EQ(t.width_ns(), Timeline::kInitialWidthNs);
}

TEST(Timeline, WidthDoublesAndPreservesTotals) {
    Timeline t;
    std::uint64_t total = 0;
    for (int i = 0; i < 10'000; ++i) {
        t.add(std::int64_t{i} * 3'000'000, 1); // 30 s span
        ++total;
    }
    std::uint64_t sum = 0;
    for (auto& b : t.buckets()) {
        sum += b.packets;
    }
    EXPECT_EQ(sum, total);
    EXPECT_LE(t.buckets().size(), Timeline::kBuckets);
    // 30 s / 256 buckets needs width >= 117 ms -> 128 ms (power-of-two multiple of 1 ms).
    EXPECT_EQ(t.width_ns(), 128'000'000);
}

TEST(Timeline, HugeSpanDoesNotOverflow) {
    Timeline t;
    t.add(0, 1);
    t.add(INT64_MAX, 1);
    std::uint64_t sum = 0;
    for (auto& b : t.buckets()) {
        sum += b.packets;
    }
    EXPECT_EQ(sum, 2u);
}

TEST(Timeline, EarlierThanOriginIsClamped) {
    Timeline t;
    t.add(5'000'000'000, 1);
    t.add(1'000'000'000, 1);
    EXPECT_EQ(t.clamped(), 1u);
    EXPECT_EQ(t.buckets()[0].packets, 2u);
}

TEST(ReaderStats, CountsErrorsAndLayers) {
    ReaderStats s;
    PacketRecord rec;
    rec.orig_len = 100;
    DecodedPacket ok;
    ok.ethertype = 0x0800;
    ok.ip_version = 4;
    ok.l4_proto = ip_proto::tcp;
    ok.tcp_flags = tcp_flag::syn | tcp_flag::fin;
    ok.ipv4_checksum_ok = false;
    s.add(rec, ok);
    DecodedPacket bad;
    bad.status = {DecodeKind::truncated, Layer::ethernet, Reason::short_header};
    s.add(rec, bad);
    const auto& c = s.counters();
    EXPECT_EQ(s.packets(), 2u);
    EXPECT_EQ(c.ethernet, 1u);
    EXPECT_EQ(c.ipv4, 1u);
    EXPECT_EQ(c.tcp, 1u);
    EXPECT_EQ(c.tcp_flags_invalid, 1u);
    EXPECT_EQ(c.ipv4_bad_checksum, 1u);
    EXPECT_EQ(c.error_count(DecodeKind::truncated, Layer::ethernet, Reason::short_header), 1u);
    EXPECT_EQ(c.total_errors(), 1u);
    EXPECT_EQ((*c.ethertypes)[0x0800], 1u);
}

TEST(ReaderStats, InvalidFlagCombinations) {
    EXPECT_TRUE(tcp_flags_invalid(0));
    EXPECT_TRUE(tcp_flags_invalid(tcp_flag::syn | tcp_flag::rst));
    EXPECT_FALSE(tcp_flags_invalid(tcp_flag::syn));
    EXPECT_FALSE(tcp_flags_invalid(tcp_flag::fin | tcp_flag::ack));
}
