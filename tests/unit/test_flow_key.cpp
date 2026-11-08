#include "flow/flow_key.h"

#include <gtest/gtest.h>

#include <random>
#include <unordered_set>
#include <vector>

using namespace netprobe;

namespace {

IpAddr v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    IpAddr ip;
    ip.b[10] = 0xFF;
    ip.b[11] = 0xFF;
    ip.b[12] = a;
    ip.b[13] = b;
    ip.b[14] = c;
    ip.b[15] = d;
    return ip;
}

DecodedPacket pkt(IpAddr s, std::uint16_t sp, IpAddr d, std::uint16_t dp,
                  std::uint8_t proto = ip_proto::tcp, std::uint8_t ver = 4) {
    DecodedPacket p;
    p.ip_version = ver;
    p.l4_proto = proto;
    p.src = s;
    p.dst = d;
    p.src_port = sp;
    p.dst_port = dp;
    return p;
}

} // namespace

TEST(FlowKey, SymmetricWithOppositeDirections) {
    auto a = make_flow_key(pkt(v4(10, 0, 0, 1), 1234, v4(10, 0, 0, 2), 80));
    auto b = make_flow_key(pkt(v4(10, 0, 0, 2), 80, v4(10, 0, 0, 1), 1234));
    EXPECT_EQ(a.key, b.key);
    EXPECT_NE(a.dir, b.dir);
    EXPECT_EQ(hash_flow_key(a.key), hash_flow_key(b.key));
}

TEST(FlowKey, SameAddressDifferentPortsOrderByPort) {
    auto a = make_flow_key(pkt(v4(1, 1, 1, 1), 9, v4(1, 1, 1, 1), 5));
    EXPECT_EQ(a.key.lo.port, 5);
    EXPECT_EQ(a.dir, Direction::hi_to_lo);
}

TEST(FlowKey, ProtocolAndVersionDistinguishKeys) {
    auto t = make_flow_key(pkt(v4(1, 1, 1, 1), 1, v4(2, 2, 2, 2), 2, ip_proto::tcp));
    auto u = make_flow_key(pkt(v4(1, 1, 1, 1), 1, v4(2, 2, 2, 2), 2, ip_proto::udp));
    EXPECT_NE(t.key, u.key);
    IpAddr six{};
    six.b[15] = 1;
    auto w = make_flow_key(pkt(six, 1, v4(2, 2, 2, 2), 2, ip_proto::tcp, 6));
    EXPECT_NE(t.key, w.key);
}

TEST(FlowKey, HashDistributionAndShardBalance) {
    std::mt19937_64 rng(42);
    constexpr int kKeys = 1 << 18;
    constexpr int kBuckets = 1024;
    std::vector<int> buckets(kBuckets), shards(8);
    std::unordered_set<std::uint64_t> seen;
    for (int i = 0; i < kKeys; ++i) {
        auto r = rng();
        auto k = make_flow_key(
                     pkt(v4(10, static_cast<std::uint8_t>(r), static_cast<std::uint8_t>(r >> 8), 1),
                         static_cast<std::uint16_t>(r >> 16), v4(10, 0, 0, 2), 443))
                     .key;
        auto h = hash_flow_key(k);
        seen.insert(h);
        ++buckets[h % kBuckets];
        ++shards[shard_of(h, 8)];
    }
    // Chi-square for uniform buckets: mean 1023, sd ~45; 1300 is a loose bound.
    double expected = static_cast<double>(kKeys) / kBuckets, chi = 0;
    for (int b : buckets) {
        chi += (b - expected) * (b - expected) / expected;
    }
    EXPECT_LT(chi, 1300.0);
    for (int s : shards) {
        EXPECT_NEAR(s, kKeys / 8, kKeys / 8 * 0.03);
    }
    EXPECT_GT(seen.size(),
              static_cast<std::size_t>(kKeys * 0.9)); // keys collide (random), hashes don't
}

TEST(FlowKey, ShardOfCoversRange) {
    EXPECT_EQ(shard_of(0, 4), 0u);
    EXPECT_EQ(shard_of(~0ull, 4), 3u);
    EXPECT_EQ(shard_of(~0ull, 1), 0u);
}
