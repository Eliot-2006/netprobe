#include "decode/decode.h"
#include "decode/layers.h"
#include "support/packet_builder.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <deque>
#include <set>

using namespace netprobe;
using namespace netprobe::test;

namespace {

// Rvalue frames are parked here so the payload views in the result stay valid (invariant O1
// applies to production code; tests inspect results after the builder expression has ended).
const ByteVec& park(ByteVec&& v) {
    static std::deque<ByteVec> arena;
    return arena.emplace_back(std::move(v));
}

DecodedPacket dec(const ByteVec& frame, std::size_t len = SIZE_MAX) {
    PacketRecord rec;
    rec.data = Bytes(frame.data(), std::min(len, frame.size()));
    rec.orig_len = static_cast<std::uint32_t>(frame.size());
    return decode_packet(rec);
}

DecodedPacket dec(ByteVec&& frame) {
    return dec(park(std::move(frame)));
}

void expect_status(const DecodedPacket& d, DecodeKind k, Layer l, Reason r) {
    EXPECT_EQ(d.status.kind, k) << to_string(d.status.kind);
    EXPECT_EQ(d.status.layer, l) << to_string(d.status.layer);
    EXPECT_EQ(d.status.reason, r) << to_string(d.status.reason);
}
void expect_ok(const DecodedPacket& d) {
    expect_status(d, DecodeKind::ok, d.status.layer, Reason::none);
}

bool payload_is(const DecodedPacket& d, const ByteVec& v) {
    return d.payload.size() == v.size() && std::equal(v.begin(), v.end(), d.payload.begin());
}

const ByteVec kData = bytes_of("GET / HTTP/1.1\r\n");
const Addr4 kA{192, 168, 1, 10};

ByteVec v4_tcp(const TcpOpts& t = {}, const ByteVec& payload = kData, Ipv4Opts ip = {}) {
    ip.proto = 6;
    return eth(0x0800, ipv4(ip, tcp(t, payload)));
}

} // namespace

// ---- valid frames: every row of the support matrix ----
TEST(Decode, EthernetIpv4Tcp) {
    TcpOpts t{
        .sport = 40000, .dport = 443, .seq = 0xFFFFFF00u, .ack = 7, .flags = 0x18, .window = 512};
    const DecodedPacket d = dec(v4_tcp(t, kData, {.src = kA, .ttl = 33}));
    expect_ok(d);
    EXPECT_TRUE(d.is_tcp());
    EXPECT_EQ(d.ethertype, 0x0800);
    EXPECT_EQ(d.ip_version, 4);
    EXPECT_EQ(d.l4_proto, 6);
    EXPECT_EQ(d.ttl_or_hlim, 33);
    EXPECT_TRUE(d.ipv4_checksum_ok);
    EXPECT_FALSE(d.is_fragment);
    EXPECT_FALSE(d.l3_truncated);
    EXPECT_TRUE(d.src.is_v4_mapped());
    EXPECT_EQ(d.src.b[12], 192);
    EXPECT_EQ(d.src.b[15], 10);
    EXPECT_EQ(d.dst.b[15], 2);
    EXPECT_EQ(d.src_port, 40000);
    EXPECT_EQ(d.dst_port, 443);
    EXPECT_EQ(d.seq, 0xFFFFFF00u);
    EXPECT_EQ(d.ack, 7u);
    EXPECT_EQ(d.tcp_flags, 0x18);
    EXPECT_EQ(d.window, 512);
    EXPECT_EQ(d.payload_logical_len, kData.size());
    EXPECT_TRUE(payload_is(d, kData));
}

TEST(Decode, EthernetIpv6Tcp) {
    const ByteVec f = eth(0x86DD, ipv6({.next_header = 6, .hlim = 9}, tcp({.dport = 8080}, kData)));
    const DecodedPacket d = dec(f);
    expect_ok(d);
    EXPECT_TRUE(d.is_tcp());
    EXPECT_EQ(d.ip_version, 6);
    EXPECT_EQ(d.ttl_or_hlim, 9);
    EXPECT_FALSE(d.src.is_v4_mapped());
    EXPECT_EQ(d.src.b[0], 0x20);
    EXPECT_EQ(d.src.b[15], 1);
    EXPECT_EQ(d.dst.b[15], 2);
    EXPECT_EQ(d.dst_port, 8080);
    EXPECT_TRUE(payload_is(d, kData));
}

TEST(Decode, UdpV4AndV6) {
    const ByteVec p = bytes_of("dns");
    DecodedPacket d = dec(eth(0x0800, ipv4({.proto = 17}, udp({.sport = 1, .dport = 2}, p))));
    expect_ok(d);
    EXPECT_TRUE(d.is_udp());
    EXPECT_EQ(d.src_port, 1);
    EXPECT_EQ(d.dst_port, 2);
    EXPECT_EQ(d.udp_trailing_bytes, 0u);
    EXPECT_EQ(d.payload_logical_len, 3u);
    EXPECT_TRUE(payload_is(d, p));
    d = dec(eth(0x86DD, ipv6({.next_header = 17}, udp({}, p))));
    expect_ok(d);
    EXPECT_TRUE(d.is_udp());
    EXPECT_TRUE(payload_is(d, p));
}

TEST(Decode, VlanTagsRecordedOuterFirst) {
    const ByteVec inner = ipv4({}, tcp({}, kData));
    DecodedPacket d = dec(eth(0x0800, inner, {{0x8100, 0x0064}}));
    expect_ok(d);
    EXPECT_EQ(d.vlan_count, 1);
    EXPECT_EQ(d.vlan_ids[0], 100);
    EXPECT_EQ(d.ethertype, 0x0800);
    EXPECT_TRUE(d.is_tcp());

    // 802.1ad outer + 802.1Q inner; PCP/DEI bits must not leak into the VLAN ID.
    d = dec(eth(0x0800, inner, {{0x88A8, 0xE0C8}, {0x8100, 0x1FFF}}));
    expect_ok(d);
    EXPECT_EQ(d.vlan_count, 2);
    EXPECT_EQ(d.vlan_ids[0], 200);
    EXPECT_EQ(d.vlan_ids[1], 0xFFF);
    EXPECT_TRUE(payload_is(d, kData));

    d = dec(eth(0x0800, inner, {{0x9100, 5}, {0x9100, 6}}));
    expect_ok(d);
    EXPECT_EQ(d.vlan_count, 2);
}

TEST(Decode, ArpAndOtherEthertypesAreOkAndUndecoded) {
    for (std::uint16_t et : std::initializer_list<std::uint16_t>{0x0806, 0x88CC, 0x0600}) {
        const DecodedPacket d = dec(eth(et, counting_bytes(28)));
        expect_ok(d);
        EXPECT_EQ(d.ethertype, et);
        EXPECT_EQ(d.ip_version, 0);
        EXPECT_TRUE(d.payload.empty());
        EXPECT_FALSE(d.is_tcp());
    }
}

TEST(Decode, IcmpAndOtherProtocolsOkWithoutPayload) {
    for (std::uint8_t proto : std::initializer_list<std::uint8_t>{1, 47, 132}) {
        const DecodedPacket d = dec(eth(0x0800, ipv4({.proto = proto}, counting_bytes(16))));
        expect_ok(d);
        EXPECT_EQ(d.l4_proto, proto);
        EXPECT_FALSE(d.is_tcp());
        EXPECT_FALSE(d.is_udp());
        EXPECT_TRUE(d.payload.empty());
    }
    const DecodedPacket d6 = dec(eth(0x86DD, ipv6({.next_header = 58}, counting_bytes(8))));
    expect_ok(d6);
    EXPECT_EQ(d6.l4_proto, 58);
    const DecodedPacket none = dec(eth(0x86DD, ipv6({.next_header = 59}, {})));
    expect_ok(none);
    EXPECT_EQ(none.l4_proto, 59);
}

// ---- trimming (critical) ----
TEST(Decode, EthernetPaddingNeverBecomesTcpPayload) {
    // Bare ACK: 14 + 20 + 20 = 54 bytes padded to the 60-byte Ethernet minimum.
    const ByteVec f = pad_to(v4_tcp({}, {}), 60, 0);
    ASSERT_EQ(f.size(), 60u);
    DecodedPacket d = dec(f);
    expect_ok(d);
    EXPECT_EQ(d.payload.size(), 0u);
    EXPECT_EQ(d.payload_logical_len, 0u);
    // 1 byte of data plus padding: only the real byte is payload, whatever the pad bytes are.
    d = dec(pad_to(v4_tcp({}, bytes_of({0x41})), 60, 0xEE));
    expect_ok(d);
    EXPECT_TRUE(payload_is(d, bytes_of({0x41})));
    // Same for IPv6 and UDP.
    d = dec(pad_to(eth(0x86DD, ipv6({.next_header = 6}, tcp({}))), 80, 0xAA));
    expect_ok(d);
    EXPECT_EQ(d.payload.size(), 0u);
    d = dec(pad_to(eth(0x0800, ipv4({.proto = 17}, udp({}))), 60, 0xAA));
    expect_ok(d);
    EXPECT_EQ(d.payload.size(), 0u);
    EXPECT_EQ(d.udp_trailing_bytes, 0u); // padding is trimmed by IP length, not UDP trailing
}

TEST(Decode, TrailingFcsIsTrimmed) {
    ByteVec f = v4_tcp();
    for (int i = 0; i < 4; ++i) {
        f.push_back(std::byte{0xFC});
    }
    const DecodedPacket d = dec(f);
    expect_ok(d);
    EXPECT_TRUE(payload_is(d, kData));
}

// ---- IPv4 ----
TEST(Decode, Ipv4OptionsSkippedByIhl) {
    const DecodedPacket d = dec(v4_tcp({}, kData, {.options = bytes_of({1, 1, 1, 0, 7, 7, 4, 0})}));
    expect_ok(d);
    EXPECT_TRUE(d.ipv4_checksum_ok);
    EXPECT_EQ(d.src_port, 12345);
    EXPECT_TRUE(payload_is(d, kData));
}

TEST(Decode, Ipv4ZeroTotalLengthUsesCapturedLength) {
    const DecodedPacket d = dec(v4_tcp({}, kData, {.total_length = std::uint16_t{0}}));
    expect_ok(d);
    EXPECT_TRUE(d.ip_zero_length);
    EXPECT_FALSE(d.l3_truncated);
    EXPECT_TRUE(payload_is(d, kData));
    EXPECT_EQ(d.payload_logical_len, kData.size());
    // ...but the TSO rule cannot trim padding: it is all we have.
    const DecodedPacket p = dec(pad_to(v4_tcp({}, {}, {.total_length = std::uint16_t{0}}), 60, 9));
    expect_ok(p);
    EXPECT_EQ(p.payload.size(), 6u);
}

TEST(Decode, Ipv4BadIhlIsMalformed) {
    for (std::uint8_t ihl : std::initializer_list<std::uint8_t>{0, 1, 4}) {
        expect_status(dec(v4_tcp({}, kData, {.ihl = ihl})), DecodeKind::malformed, Layer::ipv4,
                      Reason::bad_ihl);
    }
}

TEST(Decode, Ipv4TotalLengthBelowHeaderIsMalformed) {
    for (std::uint16_t tl : std::initializer_list<std::uint16_t>{1, 19}) {
        expect_status(dec(v4_tcp({}, kData, {.total_length = tl})), DecodeKind::malformed,
                      Layer::ipv4, Reason::bad_total_length);
    }
    // total_length < IHL*4 with options present.
    expect_status(
        dec(v4_tcp({}, kData,
                   {.options = bytes_of({1, 1, 1, 1}), .total_length = std::uint16_t{22}})),
        DecodeKind::malformed, Layer::ipv4, Reason::bad_total_length);
}

TEST(Decode, Ipv4BadVersionIsMalformed) {
    expect_status(dec(v4_tcp({}, kData, {.version = std::uint8_t{5}})), DecodeKind::malformed,
                  Layer::ipv4, Reason::bad_version);
}

TEST(Decode, Ipv4BadChecksumCountedNotDropped) {
    const DecodedPacket d = dec(v4_tcp({}, kData, {.bad_checksum = true}));
    expect_ok(d);
    EXPECT_FALSE(d.ipv4_checksum_ok);
    EXPECT_TRUE(d.is_tcp());
    EXPECT_TRUE(payload_is(d, kData));
}

TEST(Decode, Ipv4TotalLengthBeyondCaptureIsL3Truncated) {
    const ByteVec f = v4_tcp({}, counting_bytes(100));
    const DecodedPacket d = dec(f, f.size() - 60); // 40 payload bytes captured
    expect_ok(d);
    EXPECT_TRUE(d.l3_truncated);
    EXPECT_EQ(d.payload.size(), 40u);
    EXPECT_EQ(d.payload_logical_len, 100u);
}

TEST(Decode, Ipv4FragmentsFirstMiddleLast) {
    const ByteVec body = counting_bytes(32);
    const struct {
        bool mf;
        std::uint16_t off;
    } cases[] = {{true, 0}, {true, 4}, {false, 8}};
    for (const auto& c : cases) {
        const DecodedPacket d =
            dec(eth(0x0800, ipv4({.proto = 6, .mf = c.mf, .frag_offset = c.off}, body)));
        expect_ok(d);
        EXPECT_TRUE(d.is_fragment) << c.off;
        EXPECT_FALSE(d.is_tcp());
        EXPECT_EQ(d.l4_proto, 6);
        EXPECT_EQ(d.src_port, 0);
        EXPECT_TRUE(d.payload.empty());
    }
    // DF alone is not a fragment.
    const DecodedPacket nf = dec(v4_tcp({}, kData, {.df = true}));
    EXPECT_FALSE(nf.is_fragment);
}

// ---- IPv6 ----
TEST(Decode, Ipv6ExtensionChainHbhRoutingDestOpts) {
    const ByteVec f =
        eth(0x86DD, ipv6({.next_header = 6,
                          .ext = {{.type = 0}, {.type = 43, .len = 24}, {.type = 60, .len = 16}}},
                         tcp({.dport = 99}, kData)));
    const DecodedPacket d = dec(f);
    expect_ok(d);
    EXPECT_EQ(d.status.layer, Layer::tcp);
    EXPECT_EQ(d.l4_proto, 6);
    EXPECT_EQ(d.dst_port, 99);
    EXPECT_TRUE(payload_is(d, kData));
    EXPECT_EQ(d.payload_logical_len, kData.size());
}

TEST(Decode, Ipv6EightExtensionHeadersAllowedNineRejected) {
    std::vector<Ipv6Ext> ext(8, Ipv6Ext{.type = 60});
    ByteVec f = eth(0x86DD, ipv6({.next_header = 6, .ext = ext}, tcp({}, kData)));
    expect_ok(dec(f));
    ext.push_back({.type = 60});
    f = eth(0x86DD, ipv6({.next_header = 6, .ext = ext}, tcp({}, kData)));
    expect_status(dec(f), DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_ext_chain);
}

TEST(Decode, Ipv6FragmentSetsFlagAndStopsL4) {
    for (bool more : {true, false}) {
        const ByteVec f =
            eth(0x86DD, ipv6({.next_header = 17,
                              .ext = {{.type = 44,
                                       .frag_offset = static_cast<std::uint16_t>(more ? 0 : 5),
                                       .more = more}}},
                             udp({}, kData)));
        const DecodedPacket d = dec(f);
        expect_ok(d);
        EXPECT_TRUE(d.is_fragment);
        EXPECT_EQ(d.l4_proto, 17);
        EXPECT_FALSE(d.is_udp());
        EXPECT_TRUE(d.payload.empty());
    }
    // Fragment header behind another extension header.
    const DecodedPacket d = dec(
        eth(0x86DD, ipv6({.next_header = 6, .ext = {{.type = 60}, {.type = 44, .frag_offset = 3}}},
                         counting_bytes(16))));
    expect_ok(d);
    EXPECT_TRUE(d.is_fragment);
}

TEST(Decode, Ipv6UnsupportedExtensionHeaders) {
    for (std::uint8_t t : std::initializer_list<std::uint8_t>{50, 51, 135, 139, 140}) {
        // as the first next-header, and after a walkable header
        expect_status(dec(eth(0x86DD, ipv6({.ext = {{.type = t, .len = 16}}}, counting_bytes(16)))),
                      DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_ext);
        expect_status(dec(eth(0x86DD, ipv6({.ext = {{.type = 60}, {.type = t, .len = 16}}},
                                           counting_bytes(16)))),
                      DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_ext);
    }
    expect_status(dec(eth(0x86DD, ipv6({.next_header = 50}, counting_bytes(24)))),
                  DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_ext);
}

TEST(Decode, Ipv6Jumbogram) {
    // HBH with Jumbo Payload option (type 0xC2, len 4, value), payload_length 0.
    const ByteVec jumbo = bytes_of({0xC2, 4, 0, 1, 0, 0});
    const ByteVec f = eth(0x86DD, ipv6({.next_header = 6,
                                        .ext = {{.type = 0, .body = jumbo}},
                                        .payload_length = std::uint16_t{0}},
                                       tcp({}, kData)));
    expect_status(dec(f), DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_jumbo);
    // An ordinary HBH (padding option) with payload_length 0 is the TSO case, not a jumbogram.
    const ByteVec pad = bytes_of({1, 4, 0, 0, 0, 0});
    const DecodedPacket t = dec(eth(0x86DD, ipv6({.next_header = 6,
                                                  .ext = {{.type = 0, .body = pad}},
                                                  .payload_length = std::uint16_t{0}},
                                                 tcp({}, kData))));
    expect_ok(t);
    EXPECT_TRUE(t.ip_zero_length);
    EXPECT_TRUE(payload_is(t, kData));
}

TEST(Decode, Ipv6BadVersionAndZeroLengthAndSnaplen) {
    expect_status(dec(eth(0x86DD, ipv6({.version = std::uint8_t{4}}, tcp({})))),
                  DecodeKind::malformed, Layer::ipv6, Reason::bad_version);
    const ByteVec f = eth(0x86DD, ipv6({.payload_length = std::uint16_t{0}}, tcp({}, kData)));
    DecodedPacket d = dec(f);
    expect_ok(d);
    EXPECT_TRUE(d.ip_zero_length);
    EXPECT_TRUE(payload_is(d, kData));

    const ByteVec big = eth(0x86DD, ipv6({}, tcp({}, counting_bytes(100))));
    d = dec(big, big.size() - 60);
    expect_ok(d);
    EXPECT_TRUE(d.l3_truncated);
    EXPECT_EQ(d.payload.size(), 40u);
    EXPECT_EQ(d.payload_logical_len, 100u);
}

TEST(Decode, Ipv6ExtensionLengthBeyondPayloadLengthIsMalformed) {
    // payload_length says 8 but the HBH header claims 24 bytes.
    const ByteVec f = eth(0x86DD, ipv6({.next_header = 6,
                                        .ext = {{.type = 0, .len = 24}},
                                        .payload_length = std::uint16_t{8}},
                                       counting_bytes(40)));
    expect_status(dec(f), DecodeKind::malformed, Layer::ipv6_ext, Reason::bad_total_length);
}

// ---- Ethernet / VLAN failures ----
TEST(Decode, ThreeVlanTagsUnsupported) {
    const ByteVec inner = ipv4({}, tcp({}, kData));
    expect_status(dec(eth(0x0800, inner, {{0x8100, 1}, {0x8100, 2}, {0x8100, 3}})),
                  DecodeKind::unsupported, Layer::vlan, Reason::vlan_depth);
}

TEST(Decode, LlcFramesUnsupported) {
    for (std::uint16_t len : std::initializer_list<std::uint16_t>{0, 46, 1500}) {
        expect_status(dec(eth(len, counting_bytes(60))), DecodeKind::unsupported, Layer::ethernet,
                      Reason::llc);
    }
    expect_status(dec(eth(1500, counting_bytes(60), {{0x8100, 1}})), DecodeKind::unsupported,
                  Layer::vlan, Reason::llc);
}

// ---- TCP ----
TEST(Decode, TcpOptionsMssAndWindowScaleExtracted) {
    ByteVec o = tcp_opt_mss(1460);
    for (auto b : tcp_opt_nop())
        o.push_back(b);
    for (auto b : tcp_opt_wscale(7))
        o.push_back(b);
    for (auto b : tcp_opt_sack_permitted())
        o.push_back(b);
    for (auto b : tcp_opt_timestamps(1, 2))
        o.push_back(b);
    const DecodedPacket d = dec(v4_tcp({.flags = 0x02, .options = o}, {}));
    expect_ok(d);
    EXPECT_TRUE(d.has_mss);
    EXPECT_EQ(d.mss, 1460);
    EXPECT_TRUE(d.has_wscale);
    EXPECT_EQ(d.wscale, 7);
    EXPECT_FALSE(d.tcp_options_malformed);
    EXPECT_EQ(d.payload.size(), 0u);
}

TEST(Decode, TcpWindowScaleCappedAt14) {
    const DecodedPacket d = dec(v4_tcp({.options = tcp_opt_wscale(20)}, {}));
    EXPECT_EQ(d.wscale, 14);
}

TEST(Decode, TcpNopPaddingAndEolStopTheWalk) {
    ByteVec o = bytes_of({1, 1, 1});
    for (auto b : tcp_opt_mss(536))
        o.push_back(b);
    DecodedPacket d = dec(v4_tcp({.options = o}, kData));
    expect_ok(d);
    EXPECT_TRUE(d.has_mss);
    EXPECT_FALSE(d.tcp_options_malformed);
    EXPECT_TRUE(payload_is(d, kData));
    // After EOL the rest of the option area is ignored, even if it looks malformed.
    o = bytes_of({0, 2, 4, 5, 0xB4});
    d = dec(v4_tcp({.options = o}, kData));
    expect_ok(d);
    EXPECT_FALSE(d.has_mss);
    EXPECT_FALSE(d.tcp_options_malformed);
}

TEST(Decode, TcpMalformedOptionsCountedSegmentStillOk) {
    const struct {
        const char* name;
        ByteVec opts;
    } cases[] = {
        {"len 0", bytes_of({0x0A, 0, 1, 1})},
        {"len 1", bytes_of({0x0A, 1, 1, 1})},
        {"len past end", bytes_of({0x0A, 9, 1, 1})},
        {"kind without length byte", bytes_of({1, 1, 1, 0x0A})},
        {"MSS wrong length", bytes_of({2, 3, 5, 0})},
        {"MSS too long", bytes_of({2, 6, 5, 0xB4, 0, 0, 0, 0})},
        {"wscale wrong length", bytes_of({3, 4, 7, 0})},
        {"timestamps wrong length", bytes_of({8, 4, 0, 0})},
    };
    for (const auto& c : cases) {
        const DecodedPacket d = dec(v4_tcp({.options = c.opts}, kData));
        expect_ok(d);
        EXPECT_TRUE(d.tcp_options_malformed) << c.name;
        EXPECT_TRUE(d.is_tcp()) << c.name;
        EXPECT_TRUE(payload_is(d, kData)) << c.name;
        EXPECT_FALSE(d.has_mss && std::string_view(c.name).starts_with("MSS")) << c.name;
    }
    // Reason::tcp_options is a counted condition, not a DecodeStatus: status stays ok.
    EXPECT_NE(to_string(Reason::tcp_options), "?");
}

TEST(Decode, TcpDataOffsetInvalid) {
    for (std::uint8_t off : std::initializer_list<std::uint8_t>{0, 1, 4}) {
        expect_status(dec(v4_tcp({.data_offset = off}, kData)), DecodeKind::malformed, Layer::tcp,
                      Reason::tcp_data_offset);
    }
    // 60-byte header claimed but only 20 + 16 data bytes exist in the IP payload.
    expect_status(dec(v4_tcp({.data_offset = std::uint8_t{15}}, kData)), DecodeKind::malformed,
                  Layer::tcp, Reason::tcp_data_offset);
    // data offset larger than the segment, no payload at all.
    expect_status(dec(v4_tcp({.data_offset = std::uint8_t{6}}, {})), DecodeKind::malformed,
                  Layer::tcp, Reason::tcp_data_offset);
}

TEST(Decode, TcpPayloadLogicalLengthFromIpLength) {
    const ByteVec f = v4_tcp({.options = tcp_opt_mss(1)}, counting_bytes(50));
    const DecodedPacket d = dec(f);
    EXPECT_EQ(d.payload_logical_len, 50u);
    const DecodedPacket cut = dec(f, f.size() - 30);
    expect_ok(cut);
    EXPECT_TRUE(cut.l3_truncated);
    EXPECT_EQ(cut.payload.size(), 20u);
    EXPECT_EQ(cut.payload_logical_len, 50u);
}

// ---- UDP ----
TEST(Decode, UdpLengthChecks) {
    const ByteVec p = counting_bytes(10);
    for (std::uint16_t len :
         std::initializer_list<std::uint16_t>{0, 7, 19}) { // < 8, and > L3 payload (18)
        expect_status(dec(eth(0x0800, ipv4({.proto = 17}, udp({.length = len}, p)))),
                      DecodeKind::malformed, Layer::udp, Reason::udp_length);
    }
    // length < payload: trimmed, extra bytes counted.
    const DecodedPacket d =
        dec(eth(0x0800, ipv4({.proto = 17}, udp({.length = std::uint16_t{12}}, p))));
    expect_ok(d);
    EXPECT_EQ(d.payload.size(), 4u);
    EXPECT_EQ(d.payload_logical_len, 4u);
    EXPECT_EQ(d.udp_trailing_bytes, 6u);
    // length == 8: empty datagram.
    const DecodedPacket e = dec(eth(0x0800, ipv4({.proto = 17}, udp({}, {}))));
    expect_ok(e);
    EXPECT_EQ(e.payload.size(), 0u);
}

TEST(Decode, UdpSnaplenKeepsOkWithLogicalLength) {
    const ByteVec f = eth(0x0800, ipv4({.proto = 17}, udp({}, counting_bytes(100))));
    const DecodedPacket d = dec(f, f.size() - 70);
    expect_ok(d);
    EXPECT_TRUE(d.l3_truncated);
    EXPECT_EQ(d.payload.size(), 30u);
    EXPECT_EQ(d.payload_logical_len, 100u);
}

// ---- truncation of the very first bytes ----
TEST(Decode, EmptyRecordIsTruncatedAtEthernet) {
    expect_status(dec({}), DecodeKind::truncated, Layer::ethernet, Reason::short_header);
}

// ---- exhaustive truncation sweep ----
namespace {
struct Fixture {
    const char* name;
    ByteVec frame;
    // (end offset of header, layer) in wire order. A prefix shorter than the first end that
    // exceeds it is truncated at that layer.
    std::vector<std::pair<std::size_t, Layer>> headers;
    std::size_t ip_end; // frame offset where the IP datagram ends
};

std::vector<Fixture> fixtures() {
    std::vector<Fixture> fx;
    const ByteVec pl = counting_bytes(24);
    const ByteVec mss = tcp_opt_mss(1460);

    ByteVec f = eth(0x0800, ipv4({}, tcp({}, pl)));
    fx.push_back(
        {"v4 tcp", f, {{14, Layer::ethernet}, {34, Layer::ipv4}, {54, Layer::tcp}}, f.size()});
    f = eth(0x0800,
            ipv4({.options = bytes_of({1, 1, 1, 1, 1, 1, 1, 0})}, tcp({.options = mss}, pl)));
    fx.push_back({"v4 opts tcp opts",
                  f,
                  {{14, Layer::ethernet}, {42, Layer::ipv4}, {66, Layer::tcp}},
                  f.size()});
    f = eth(0x0800, ipv4({.proto = 17}, udp({}, pl)));
    fx.push_back(
        {"v4 udp", f, {{14, Layer::ethernet}, {34, Layer::ipv4}, {42, Layer::udp}}, f.size()});
    f = eth(0x0800, ipv4({}, tcp({}, pl)), {{0x8100, 5}, {0x88A8, 6}});
    fx.push_back({"2 vlans v4 tcp",
                  f,
                  {{14, Layer::ethernet},
                   {18, Layer::vlan},
                   {22, Layer::vlan},
                   {42, Layer::ipv4},
                   {62, Layer::tcp}},
                  f.size()});
    f = eth(0x86DD, ipv6({}, tcp({}, pl)));
    fx.push_back(
        {"v6 tcp", f, {{14, Layer::ethernet}, {54, Layer::ipv6}, {74, Layer::tcp}}, f.size()});
    f = eth(0x86DD, ipv6({.next_header = 17}, udp({}, pl)));
    fx.push_back(
        {"v6 udp", f, {{14, Layer::ethernet}, {54, Layer::ipv6}, {62, Layer::udp}}, f.size()});
    f = eth(0x86DD,
            ipv6({.next_header = 6, .ext = {{.type = 0}, {.type = 60, .len = 16}}}, tcp({}, pl)));
    fx.push_back({"v6 hbh+dest tcp",
                  f,
                  {{14, Layer::ethernet},
                   {54, Layer::ipv6},
                   {62, Layer::ipv6_ext},
                   {78, Layer::ipv6_ext},
                   {98, Layer::tcp}},
                  f.size()});
    f = eth(0x0800, ipv4({.proto = 6, .mf = true}, counting_bytes(32)));
    fx.push_back({"v4 fragment", f, {{14, Layer::ethernet}, {34, Layer::ipv4}}, f.size()});
    f = eth(0x86DD, ipv6({.next_header = 17, .ext = {{.type = 44}}}, counting_bytes(32)));
    fx.push_back({"v6 fragment",
                  f,
                  {{14, Layer::ethernet}, {54, Layer::ipv6}, {62, Layer::ipv6_ext}},
                  f.size()});
    f = eth(0x0800, ipv4({.proto = 1}, counting_bytes(16)));
    fx.push_back({"v4 icmp", f, {{14, Layer::ethernet}, {34, Layer::ipv4}}, f.size()});
    f = pad_to(eth(0x0800, ipv4({}, tcp({}))), 60, 0xAB);
    fx.push_back(
        {"padded ack", f, {{14, Layer::ethernet}, {34, Layer::ipv4}, {54, Layer::tcp}}, 54});
    f = eth(0x0806, counting_bytes(28));
    fx.push_back({"arp", f, {{14, Layer::ethernet}}, 0}); // no IP datagram
    return fx;
}
} // namespace

TEST(Decode, TruncationSweepEveryPrefixOfEveryFixture) {
    for (const Fixture& fx : fixtures()) {
        for (std::size_t n = 0; n <= fx.frame.size(); ++n) {
            SCOPED_TRACE(std::string(fx.name) + " prefix " + std::to_string(n));
            const DecodedPacket d = dec(fx.frame, n);
            // Payload must always lie within the captured prefix.
            if (!d.payload.empty()) {
                EXPECT_GE(d.payload.data(), fx.frame.data());
                EXPECT_LE(d.payload.data() + d.payload.size(), fx.frame.data() + n);
            }
            EXPECT_LE(d.payload.size(), d.payload_logical_len);

            const Layer* trunc_layer = nullptr;
            for (const auto& [end, layer] : fx.headers) {
                if (n < end) {
                    trunc_layer = &layer;
                    break;
                }
            }
            if (trunc_layer != nullptr) {
                expect_status(d, DecodeKind::truncated, *trunc_layer, Reason::short_header);
            } else {
                expect_ok(d);
                EXPECT_EQ(d.l3_truncated, n < fx.ip_end);
            }
        }
    }
}

TEST(Decode, FullFixturesDecodeOkWithoutL3Truncation) {
    for (const Fixture& fx : fixtures()) {
        const DecodedPacket d = dec(fx.frame);
        expect_ok(d);
        EXPECT_FALSE(d.l3_truncated) << fx.name;
    }
}

// ---- every Reason has a producing test (above) and a name ----
TEST(Decode, EveryReasonValueProducedAndNamed) {
    std::set<Reason> produced;
    auto note = [&](const DecodedPacket& d) { produced.insert(d.status.reason); };
    const ByteVec inner = ipv4({}, tcp({}, kData));
    note(dec({}));                                                    // short_header
    note(dec(v4_tcp({}, kData, {.version = std::uint8_t{7}})));       // bad_version
    note(dec(v4_tcp({}, kData, {.ihl = std::uint8_t{2}})));           // bad_ihl
    note(dec(v4_tcp({}, kData, {.total_length = std::uint16_t{3}}))); // bad_total_length
    note(dec(v4_tcp({.data_offset = std::uint8_t{2}})));              // tcp_data_offset
    note(dec(eth(0x0800, ipv4({.proto = 17}, udp({.length = std::uint16_t{1}}))))); // udp_length
    note(dec(eth(0x0800, inner, {{0x8100, 1}, {0x8100, 1}, {0x8100, 1}})));         // vlan_depth
    note(dec(eth(100, inner)));                                                     // llc
    note(dec(eth(0x86DD, ipv6({.next_header = 51}, counting_bytes(8)))));           // ipv6_ext
    note(dec(
        eth(0x86DD, ipv6({.next_header = 6, .ext = std::vector<Ipv6Ext>(9, Ipv6Ext{.type = 60})},
                         {})))); // ipv6_ext_chain
    note(dec(eth(0x86DD, ipv6({.ext = {{.type = 0, .body = bytes_of({0xC2, 4, 0, 1, 0, 0})}},
                               .payload_length = std::uint16_t{0}},
                              {}))));     // ipv6_jumbo
    produced.insert(Reason::none);        // ok decodes
    produced.insert(Reason::tcp_options); // counted via tcp_options_malformed, see above
    EXPECT_TRUE(dec(v4_tcp({.options = bytes_of({2, 3, 0, 0})})).tcp_options_malformed);
    for (auto i = 0; i < static_cast<int>(Reason::count_); ++i) {
        const auto r = static_cast<Reason>(i);
        EXPECT_TRUE(produced.contains(r)) << to_string(r);
        EXPECT_NE(to_string(r), "?");
    }
    for (auto i = 0; i < static_cast<int>(Layer::count_); ++i) {
        EXPECT_NE(to_string(static_cast<Layer>(i)), "?");
    }
    for (auto i = 0; i < static_cast<int>(DecodeKind::count_); ++i) {
        EXPECT_NE(to_string(static_cast<DecodeKind>(i)), "?");
    }
}
