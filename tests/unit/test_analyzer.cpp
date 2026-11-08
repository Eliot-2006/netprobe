// Analyzer shard tests (PRD 4.3, 6.7, 6.8, M6): orientation, handshake classes, expiry,
// port reuse, eviction, and memory limits under adversarial input.

#include "analysis/analyzer.h"
#include "decode/decode.h"
#include "support/packet_builder.h"

#include <gtest/gtest.h>

using namespace netprobe;
using namespace netprobe::test;

namespace {

constexpr std::int64_t kSec = 1'000'000'000;
constexpr std::uint8_t SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04, PSH = 0x08;

struct Feeder {
    explicit Feeder(AnalyzerConfig cfg = {}) : a(std::move(cfg)) {}
    Analyzer a;
    std::uint64_t index = 0;

    void frame(const ByteVec& f, std::int64_t ts) {
        PacketRecord rec;
        rec.index = index++;
        rec.ts_ns = ts;
        rec.data = Bytes(f);
        rec.orig_len = static_cast<std::uint32_t>(f.size());
        a.process(rec, decode_packet(rec));
    }
    void tcp(Addr4 s, std::uint16_t sp, Addr4 d, std::uint16_t dp, std::uint8_t flags,
             std::uint32_t seq, std::uint32_t ack, const ByteVec& payload, std::int64_t ts) {
        frame(
            eth(0x0800, ipv4({.proto = 6, .src = s, .dst = d},
                             netprobe::test::tcp(
                                 {.sport = sp, .dport = dp, .seq = seq, .ack = ack, .flags = flags},
                                 payload))),
            ts);
    }
    void udp(Addr4 s, std::uint16_t sp, Addr4 d, std::uint16_t dp, std::int64_t ts) {
        frame(eth(0x0800, ipv4({.proto = 17, .src = s, .dst = d},
                               netprobe::test::udp({.sport = sp, .dport = dp}, bytes_of("x")))),
              ts);
    }
};

const Addr4 C{10, 0, 0, 1}, S{10, 0, 0, 2};

// Client C:1000 -> server S:80 full handshake, `n` bytes each way, FIN both, final ACK.
void session(Feeder& f, std::uint32_t isn_c, std::uint32_t isn_s, std::int64_t t0,
             std::uint16_t cport = 1000) {
    const auto data = counting_bytes(100);
    f.tcp(C, cport, S, 80, SYN, isn_c, 0, {}, t0);
    f.tcp(S, 80, C, cport, SYN | ACK, isn_s, isn_c + 1, {}, t0 + 1);
    f.tcp(C, cport, S, 80, ACK, isn_c + 1, isn_s + 1, {}, t0 + 2);
    f.tcp(C, cport, S, 80, PSH | ACK, isn_c + 1, isn_s + 1, data, t0 + 3);
    f.tcp(S, 80, C, cport, PSH | ACK, isn_s + 1, isn_c + 101, data, t0 + 4);
    f.tcp(C, cport, S, 80, FIN | ACK, isn_c + 101, isn_s + 101, {}, t0 + 5);
    f.tcp(S, 80, C, cport, FIN | ACK, isn_s + 101, isn_c + 102, {}, t0 + 6);
    f.tcp(C, cport, S, 80, ACK, isn_c + 102, isn_s + 102, {}, t0 + 7);
}

} // namespace

TEST(Analyzer, FullHandshakeSessionIsCompleteAndOriented) {
    Feeder f;
    session(f, 5000, 9000, kSec);
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.tcp_total, 1u);
    EXPECT_EQ(r.flows.handshake_full, 1u);
    EXPECT_EQ(r.flows.tcp_complete, 1u);
    EXPECT_EQ(r.flows.tcp_close[static_cast<int>(CloseReason::fin)], 1u);
    auto top = r.top_bytes.sorted();
    ASSERT_EQ(top.size(), 1u);
    EXPECT_EQ(top[0].client.port, 1000);
    EXPECT_EQ(top[0].server.port, 80);
    EXPECT_EQ(top[0].c2s.stream.delivered_bytes, 100u);
    EXPECT_EQ(top[0].s2c.stream.delivered_bytes, 100u);
    EXPECT_EQ(top[0].integrity, Integrity::complete);
    EXPECT_EQ(r.reassembly.delivered_bytes, 200u);
    EXPECT_EQ(r.services.at({6, 80}).flows, 1u);
    EXPECT_EQ(f.a.budget().current(), 0u);
}

TEST(Analyzer, SynAckFirstMakesReceiverTheClient) {
    Feeder f;
    f.tcp(S, 80, C, 1000, SYN | ACK, 9000, 5001, {}, kSec);
    f.tcp(C, 1000, S, 80, ACK, 5001, 9001, {}, kSec + 1);
    auto top = f.a.finish().top_bytes.sorted();
    ASSERT_EQ(top.size(), 1u);
    EXPECT_EQ(top[0].client.port, 1000);
    EXPECT_EQ(top[0].handshake, Handshake::partial);
}

TEST(Analyzer, MidstreamPickupHasNoHandshakeAndFirstSenderIsClient) {
    Feeder f;
    f.tcp(S, 80, C, 1000, PSH | ACK, 777, 555, counting_bytes(50), kSec);
    f.tcp(C, 1000, S, 80, ACK, 555, 827, {}, kSec + 1);
    auto r = f.a.finish();
    auto top = r.top_bytes.sorted();
    ASSERT_EQ(top.size(), 1u);
    EXPECT_FALSE(top[0].orientation_handshake);
    EXPECT_EQ(top[0].client.port, 80); // first packet's sender
    EXPECT_EQ(top[0].handshake, Handshake::none);
    EXPECT_EQ(top[0].c2s.stream.delivered_bytes, 50u);
    EXPECT_EQ(r.flows.handshake_none, 1u);
}

TEST(Analyzer, IdleTimeoutSplitsFlowLazily) {
    AnalyzerConfig cfg;
    cfg.idle_timeout_ns = 300 * kSec;
    Feeder f(cfg);
    f.udp(C, 5000, S, 53, kSec);
    f.udp(C, 5000, S, 53, 302 * kSec); // 301 s later: new flow
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.udp_total, 2u);
    EXPECT_EQ(r.flows.udp_close[static_cast<int>(CloseReason::idle_timeout)], 1u);
    EXPECT_EQ(r.flows.udp_close[static_cast<int>(CloseReason::end_of_capture)], 1u);
}

TEST(Analyzer, SweepFinalizesIdleFlowsWithoutTheirTraffic) {
    AnalyzerConfig cfg;
    cfg.idle_timeout_ns = 10 * kSec;
    Feeder f(cfg);
    for (std::uint16_t p = 0; p < 100; ++p) {
        f.udp(C, static_cast<std::uint16_t>(2000 + p), S, 53, kSec);
    }
    EXPECT_EQ(f.a.live_flows(), 100u);
    f.udp(C, 9999, S, 53, 20 * kSec); // advances "now" by > 1 s: sweep runs
    EXPECT_EQ(f.a.live_flows(), 1u);
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.udp_close[static_cast<int>(CloseReason::idle_timeout)], 100u);
}

TEST(Analyzer, ClosedFlowsLingerTenSecondsThenFinalize) {
    Feeder f;
    session(f, 1, 2, kSec);
    EXPECT_EQ(f.a.live_flows(), 1u);
    f.udp(C, 1, S, 2, 5 * kSec);
    EXPECT_EQ(f.a.live_flows(), 2u); // TCP flow still lingering
    f.udp(C, 1, S, 2, 12 * kSec);
    EXPECT_EQ(f.a.live_flows(), 1u); // > 10 s after its last packet
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.tcp_close[static_cast<int>(CloseReason::fin)], 1u);
}

TEST(Analyzer, NewSynWithDifferentIsnAfterCloseIsPortReuse) {
    Feeder f;
    session(f, 1000, 2000, kSec);
    session(f, 900'000, 800'000, kSec + 100);
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.tcp_total, 2u);
    EXPECT_EQ(r.flows.tcp_close[static_cast<int>(CloseReason::reused)], 1u);
    EXPECT_EQ(r.flows.tcp_complete, 2u);
    auto top = r.top_bytes.sorted();
    ASSERT_EQ(top.size(), 2u);
    EXPECT_NE(top[0].id, top[1].id);
}

TEST(Analyzer, RetransmittedSynWithSameIsnIsNotReuse) {
    Feeder f;
    f.tcp(C, 1000, S, 80, SYN, 42, 0, {}, kSec);
    f.tcp(C, 1000, S, 80, SYN, 42, 0, {}, kSec + 1);
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.tcp_total, 1u);
}

TEST(Analyzer, DataAfterRstIsCountedAndDropped) {
    Feeder f;
    f.tcp(C, 1000, S, 80, SYN, 10, 0, {}, kSec);
    f.tcp(S, 80, C, 1000, SYN | ACK, 20, 11, {}, kSec + 1);
    f.tcp(S, 80, C, 1000, RST | ACK, 21, 11, {}, kSec + 2);
    f.tcp(C, 1000, S, 80, PSH | ACK, 11, 21, counting_bytes(30), kSec + 3);
    auto r = f.a.finish();
    EXPECT_EQ(r.reassembly.data_after_rst, 1u);
    EXPECT_EQ(r.reassembly.delivered_bytes, 0u);
    EXPECT_EQ(r.flows.tcp_close[static_cast<int>(CloseReason::rst)], 1u);
}

TEST(Analyzer, InvalidFlagCombinationsAreNotReassembled) {
    Feeder f;
    f.tcp(C, 1000, S, 80, SYN | FIN, 10, 0, counting_bytes(20), kSec);
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.tcp_total, 1u);
    EXPECT_EQ(r.reassembly.delivered_bytes, 0u);
}

TEST(Analyzer, EvictionKeepsLiveFlowsAtLimit) {
    AnalyzerConfig cfg;
    cfg.max_flows = 10;
    Feeder f(cfg);
    for (std::uint16_t p = 0; p < 50; ++p) {
        f.udp(C, static_cast<std::uint16_t>(3000 + p), S, 53, kSec + p);
        ASSERT_LE(f.a.live_flows(), 10u);
    }
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.udp_total, 50u);
    EXPECT_EQ(r.evicted_flows, 40u);
    EXPECT_TRUE(r.limits_hit);
}

TEST(Analyzer, SynFloodStaysBounded) {
    AnalyzerConfig cfg;
    cfg.max_flows = 1000;
    Feeder f(cfg);
    for (std::uint32_t i = 0; i < 100'000; ++i) {
        const Addr4 src{10, static_cast<std::uint8_t>(i >> 16), static_cast<std::uint8_t>(i >> 8),
                        static_cast<std::uint8_t>(i)};
        f.tcp(src, static_cast<std::uint16_t>(i), S, 80, SYN, i, 0, {}, kSec);
    }
    EXPECT_LE(f.a.live_flows(), 1000u);
    auto r = f.a.finish();
    EXPECT_EQ(r.flows.tcp_total, 100'000u);
    EXPECT_EQ(r.top_bytes.size(), cfg.top_k);
}

TEST(Analyzer, ReassemblyBudgetHoldsAcrossManyStalledStreams) {
    AnalyzerConfig cfg;
    cfg.max_stream_buffer = 64 << 10;
    cfg.reassembly_budget = 256 << 10;
    Feeder f(cfg);
    const auto chunk = counting_bytes(1000);
    // 40 streams, each missing its first segment, so everything after is buffered.
    for (int round = 0; round < 50; ++round) {
        for (std::uint16_t s = 0; s < 40; ++s) {
            const std::uint32_t isn = 1000;
            if (round == 0) {
                f.tcp(C, static_cast<std::uint16_t>(4000 + s), S, 80, SYN, isn, 0, {}, kSec);
            }
            const auto seq = isn + 1 + 1000 + static_cast<std::uint32_t>(round) * 1000;
            f.tcp(C, static_cast<std::uint16_t>(4000 + s), S, 80, PSH | ACK, seq, 1, chunk,
                  kSec + round);
            ASSERT_LE(f.a.budget().current(), cfg.reassembly_budget + 1000 + 64);
        }
    }
    EXPECT_GT(f.a.budget().peak(), 0u);
    auto r = f.a.finish();
    EXPECT_GT(r.reassembly.forced_flushes, 0u);
    EXPECT_GE(r.reassembly.gap_count, 40u); // every stream reports at least its leading gap
    EXPECT_EQ(r.reassembly.delivered_bytes, 40u * 50u * 1000u);
    EXPECT_EQ(f.a.budget().current(), 0u);
}

TEST(TopK, KeepsBestWithIdTieBreak) {
    TopK k(2, TopK::Metric::bytes);
    auto mk = [](std::uint64_t id, std::uint64_t bytes) {
        FlowSummary s;
        s.id = id;
        s.c2s.bytes = bytes;
        return s;
    };
    k.offer(mk(5, 100));
    k.offer(mk(3, 100));
    k.offer(mk(9, 50));
    k.offer(mk(1, 100));
    auto v = k.sorted();
    ASSERT_EQ(v.size(), 2u);
    EXPECT_EQ(v[0].id, 1u);
    EXPECT_EQ(v[1].id, 3u);
    TopK other(2, TopK::Metric::bytes);
    other.offer(mk(0, 1000));
    k.merge(std::move(other));
    v = k.sorted();
    EXPECT_EQ(v[0].id, 0u);
    EXPECT_EQ(v[1].id, 1u);
}
