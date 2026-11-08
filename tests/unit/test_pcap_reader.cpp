#include "decode/decode.h"
#include "io/mapped_file.h"
#include "pcap/reader.h"
#include "support/packet_builder.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <deque>
#include <new>
#include <unistd.h>

// ---- allocation counter: armed only around the code under test ----
namespace {
std::atomic<bool> g_count_allocs{false};
std::atomic<std::size_t> g_allocs{0};
} // namespace

void* operator new(std::size_t n) {
    if (g_count_allocs.load(std::memory_order_relaxed)) {
        g_allocs.fetch_add(1, std::memory_order_relaxed);
    }
    if (void* p = std::malloc(n == 0 ? 1 : n)) {
        return p;
    }
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept {
    std::free(p);
}
void operator delete(void* p, std::size_t) noexcept {
    std::free(p);
}

using namespace netprobe;
using namespace netprobe::test;

namespace {

Bytes view(const ByteVec& v) {
    return {v.data(), v.size()};
}

PcapOpenResult open_ok(const ByteVec& v) {
    PcapOpenResult r = PcapReader::open(view(v));
    EXPECT_EQ(r.error, OpenError::none) << r.message;
    EXPECT_TRUE(r.reader.has_value());
    return r;
}

PcapOpenResult open_ok(ByteVec&& v) {
    static std::deque<ByteVec> arena; // keeps the file alive for the returned reader
    return open_ok(arena.emplace_back(std::move(v)));
}

ByteVec frame() {
    return eth(0x0800, ipv4({}, tcp({}, bytes_of("hello"))));
}

} // namespace

// ---- FR-PCAP-2: four magics ----
struct MagicCase {
    ByteOrder order;
    bool nano;
};
class PcapMagic : public testing::TestWithParam<MagicCase> {};

TEST_P(PcapMagic, ParsesHeaderAndTimestamps) {
    const auto [order, nano] = GetParam();
    PcapFileOpts o{.order = order, .nanosecond = nano, .snaplen = 1500};
    const ByteVec f = frame();
    const ByteVec file = pcap_file(o, {{.ts_sec = 1700000000, .ts_frac = 123456, .data = f}});
    auto r = open_ok(file);
    EXPECT_EQ(r.reader->info().order, order);
    EXPECT_EQ(r.reader->info().precision, nano ? TsPrecision::nano : TsPrecision::micro);
    EXPECT_EQ(r.reader->info().snaplen, 1500u);
    EXPECT_EQ(r.reader->info().link_type, 1);
    EXPECT_EQ(r.reader->info().ver_major, 2);
    EXPECT_EQ(r.reader->info().ver_minor, 4);
    EXPECT_FALSE(r.reader->info().version_anomaly);
    EXPECT_FALSE(r.reader->info().fcs_bits.has_value());

    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.index, 0u);
    EXPECT_EQ(rec.file_offset, 24u);
    EXPECT_EQ(rec.ts_ns, 1700000000LL * 1'000'000'000 + 123456LL * (nano ? 1 : 1000));
    EXPECT_EQ(rec.orig_len, f.size());
    ASSERT_EQ(rec.data.size(), f.size());
    EXPECT_TRUE(std::equal(f.begin(), f.end(), rec.data.begin()));
    EXPECT_FALSE(r.reader->next(rec));
    EXPECT_EQ(r.reader->status(), CaptureStatus::complete);
}

INSTANTIATE_TEST_SUITE_P(All, PcapMagic,
                         testing::Values(MagicCase{ByteOrder::little, false},
                                         MagicCase{ByteOrder::little, true},
                                         MagicCase{ByteOrder::big, false},
                                         MagicCase{ByteOrder::big, true}));

// ---- open() failures ----
TEST(PcapOpen, ShorterThanGlobalHeader) {
    for (std::size_t n : {0u, 1u, 23u}) {
        ByteVec v = pcap_global_header({});
        v.resize(n);
        auto r = PcapReader::open(view(v));
        EXPECT_EQ(r.error, OpenError::too_short) << n;
        EXPECT_FALSE(r.reader.has_value());
        EXPECT_FALSE(r.message.empty());
    }
}

TEST(PcapOpen, UnknownMagic) {
    auto r = PcapReader::open(view(pcap_global_header({.magic = 0xDEADBEEFu})));
    EXPECT_EQ(r.error, OpenError::bad_magic);
    EXPECT_NE(r.message.find("0x"), std::string::npos);
}

TEST(PcapOpen, PcapngRejectedWithHint) {
    ByteVec v = bytes_of({0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A});
    v.resize(64);
    auto r = PcapReader::open(view(v));
    EXPECT_EQ(r.error, OpenError::pcapng);
    EXPECT_NE(r.message.find("editcap -F pcap"), std::string::npos);
}

TEST(PcapOpen, MajorVersionRejected) {
    auto r = PcapReader::open(view(pcap_global_header({.ver_major = 3})));
    EXPECT_EQ(r.error, OpenError::bad_version);
    r = PcapReader::open(view(pcap_global_header({.ver_major = 1, .ver_minor = 4})));
    EXPECT_EQ(r.error, OpenError::bad_version);
}

TEST(PcapOpen, OtherMinorVersionAcceptedWithAnomaly) {
    for (ByteOrder bo : {ByteOrder::little, ByteOrder::big}) {
        auto r = open_ok(pcap_global_header({.order = bo, .ver_major = 2, .ver_minor = 3}));
        EXPECT_TRUE(r.reader->info().version_anomaly);
        EXPECT_EQ(r.reader->info().ver_minor, 3);
    }
}

TEST(PcapOpen, UnsupportedLinkTypeNamesTheNumber) {
    for (std::uint32_t lt : {0u, 101u, 113u, 228u}) {
        auto r = PcapReader::open(view(pcap_global_header({.linktype_field = lt})));
        EXPECT_EQ(r.error, OpenError::unsupported_link_type) << lt;
        EXPECT_NE(r.message.find(std::to_string(lt)), std::string::npos) << r.message;
    }
}

TEST(PcapOpen, LinkTypeIsLower16BitsAndFcsBitsRecorded) {
    // F bit (26) set, FCS length 2 words (bits 28..31) -> 32 bits; link type 1.
    const std::uint32_t field = (2u << 28) | (1u << 26) | 1u;
    for (ByteOrder bo : {ByteOrder::little, ByteOrder::big}) {
        auto r = open_ok(pcap_global_header({.order = bo, .linktype_field = field}));
        EXPECT_EQ(r.reader->info().link_type, 1);
        ASSERT_TRUE(r.reader->info().fcs_bits.has_value());
        EXPECT_EQ(*r.reader->info().fcs_bits, 32);
    }
    // FCS length bits without the F bit are ignored.
    auto r = open_ok(pcap_global_header({.linktype_field = (2u << 28) | 1u}));
    EXPECT_FALSE(r.reader->info().fcs_bits.has_value());
}

// ---- iteration ----
TEST(PcapIter, HeaderOnlyFileIsCompleteAndEmpty) {
    auto r = open_ok(pcap_global_header({}));
    PacketRecord rec;
    EXPECT_FALSE(r.reader->next(rec));
    EXPECT_EQ(r.reader->status(), CaptureStatus::complete);
    EXPECT_EQ(r.reader->truncated_tail_bytes(), 0u);
}

TEST(PcapIter, ZeroLengthRecordYieldsEmptyDataThatDecodesTruncated) {
    auto r = open_ok(pcap_file({}, {{.data = {}}, {.data = frame()}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.data.size(), 0u);
    const DecodedPacket d = decode_packet(rec);
    EXPECT_EQ(d.status.kind, DecodeKind::truncated);
    EXPECT_EQ(d.status.layer, Layer::ethernet);
    ASSERT_TRUE(r.reader->next(rec)); // iteration continues past it
    EXPECT_EQ(rec.index, 1u);
    EXPECT_EQ(rec.file_offset, 24u + 16u);
}

TEST(PcapIter, OffsetsAndIndexesAdvance) {
    const ByteVec f = frame();
    auto r = open_ok(pcap_file({}, {{.data = f}, {.data = f}, {.data = f}}));
    PacketRecord rec;
    for (std::uint64_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(r.reader->next(rec));
        EXPECT_EQ(rec.index, i);
        EXPECT_EQ(rec.file_offset, 24 + i * (16 + f.size()));
    }
    EXPECT_FALSE(r.reader->next(rec));
    EXPECT_FALSE(r.reader->next(rec)); // stays ended
}

TEST(PcapIter, SnaplenTruncationCounted) {
    const ByteVec f = frame();
    auto r = open_ok(pcap_file({}, {{.data = f, .orig_len = 1500}, {.data = f}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.orig_len, 1500u);
    EXPECT_EQ(rec.data.size(), f.size());
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(r.reader->counters().records_truncated_by_snaplen, 1u);
    EXPECT_EQ(r.reader->counters().incl_gt_orig, 0u);
    EXPECT_EQ(r.reader->status(), CaptureStatus::complete);
}

TEST(PcapIter, InclGreaterThanOrigCountedAndInclLenUsed) {
    const ByteVec f = frame();
    auto r = open_ok(pcap_file({}, {{.data = f, .orig_len = 10}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.data.size(), f.size());
    EXPECT_EQ(rec.orig_len, 10u);
    EXPECT_EQ(r.reader->counters().incl_gt_orig, 1u);
    EXPECT_EQ(r.reader->counters().records_truncated_by_snaplen, 0u);
}

TEST(PcapIter, InclLenOverMaxIsCorruptAndStopsIteration) {
    const ByteVec f = frame();
    for (ByteOrder bo : {ByteOrder::little, ByteOrder::big}) {
        PcapFileOpts o{.order = bo};
        ByteVec file = pcap_file(o, {{.data = f}});
        const ByteVec bad = pcap_record(o, {.data = {}, .incl_len = 262145u, .orig_len = 262145u});
        file.insert(file.end(), bad.begin(), bad.end());
        const ByteVec after = pcap_record(o, {.data = f});
        file.insert(file.end(), after.begin(), after.end());
        auto r = open_ok(file);
        PacketRecord rec;
        ASSERT_TRUE(r.reader->next(rec));
        EXPECT_FALSE(r.reader->next(rec));
        EXPECT_EQ(r.reader->status(), CaptureStatus::corrupt);
        EXPECT_FALSE(r.reader->next(rec)); // never resynchronizes onto the later record
    }
}

TEST(PcapIter, InclLenExactlyMaxIsAccepted) {
    ByteVec big(262144, std::byte{0});
    auto r = open_ok(pcap_file({}, {{.data = big}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.data.size(), 262144u);
    EXPECT_EQ(r.reader->status(), CaptureStatus::complete);
}

TEST(PcapIter, TruncatedRecordHeader) {
    const ByteVec f = frame();
    for (std::size_t extra : {1u, 8u, 15u}) {
        ByteVec file = pcap_file({}, {{.data = f}, {.data = f}});
        const std::size_t one = 24 + 16 + f.size();
        file.resize(one + extra);
        auto r = open_ok(file);
        PacketRecord rec;
        ASSERT_TRUE(r.reader->next(rec));
        EXPECT_FALSE(r.reader->next(rec));
        EXPECT_EQ(r.reader->status(), CaptureStatus::truncated) << extra;
        EXPECT_EQ(r.reader->truncated_tail_bytes(), extra);
    }
}

TEST(PcapIter, TruncatedRecordBody) {
    const ByteVec f = frame();
    for (std::size_t body : {std::size_t{0}, std::size_t{1}, f.size() - 1}) {
        ByteVec file = pcap_file({}, {{.data = f}, {.data = f}});
        const std::size_t one = 24 + 16 + f.size();
        file.resize(one + 16 + body);
        auto r = open_ok(file);
        PacketRecord rec;
        ASSERT_TRUE(r.reader->next(rec));
        EXPECT_FALSE(r.reader->next(rec));
        EXPECT_EQ(r.reader->status(), CaptureStatus::truncated) << body;
        EXPECT_EQ(r.reader->truncated_tail_bytes(), 16 + body);
    }
}

TEST(PcapIter, TsFractionOverflowAcceptedAndCounted) {
    auto r = open_ok(pcap_file({}, {{.ts_sec = 5, .ts_frac = 1'000'000, .data = frame()},
                                    {.ts_sec = 6, .ts_frac = 999'999, .data = frame()}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.ts_ns, 5LL * 1'000'000'000 + 1'000'000LL * 1000);
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(r.reader->counters().ts_fraction_overflow, 1u);

    auto n = open_ok(pcap_file({.nanosecond = true}, {{.ts_sec = 1, .ts_frac = 1'000'000'000u},
                                                      {.ts_sec = 2, .ts_frac = 999'999'999u}}));
    while (n.reader->next(rec)) {
    }
    EXPECT_EQ(n.reader->counters().ts_fraction_overflow, 1u);
}

TEST(PcapIter, MaxTimestampDoesNotOverflow) {
    auto r = open_ok(pcap_file({}, {{.ts_sec = 0xFFFFFFFFu, .ts_frac = 0xFFFFFFFFu, .data = {}}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_GT(rec.ts_ns, 0);
}

TEST(PcapIter, TimestampRegressionCounted) {
    auto r = open_ok(pcap_file({}, {{.ts_sec = 10, .data = frame()},
                                    {.ts_sec = 9, .data = frame()}, // regression
                                    {.ts_sec = 9, .data = frame()}, // equal: not a regression
                                    {.ts_sec = 11, .data = frame()},
                                    {.ts_sec = 10, .ts_frac = 5, .data = frame()}})); // regression
    PacketRecord rec;
    while (r.reader->next(rec)) {
    }
    EXPECT_EQ(r.reader->counters().timestamp_regressions, 2u);
    EXPECT_EQ(r.reader->status(), CaptureStatus::complete);
}

TEST(PcapIter, BigEndianRecordsParse) {
    PcapFileOpts o{.order = ByteOrder::big};
    auto r = open_ok(pcap_file(o, {{.ts_sec = 7, .ts_frac = 8, .data = frame(), .orig_len = 99}}));
    PacketRecord rec;
    ASSERT_TRUE(r.reader->next(rec));
    EXPECT_EQ(rec.ts_ns, 7'000'000'000LL + 8000);
    EXPECT_EQ(rec.orig_len, 99u);
}

// ---- no allocation on the read + decode path ----
TEST(PcapIter, NextAndDecodeDoNotAllocate) {
    const ByteVec f = frame();
    std::vector<PcapRecordSpec> recs(20000, PcapRecordSpec{.data = f});
    const ByteVec file = pcap_file({}, recs);
    auto r = open_ok(file);
    PacketRecord rec;
    std::uint64_t n = 0, ok = 0;
    g_allocs = 0;
    g_count_allocs = true;
    while (r.reader->next(rec)) {
        ++n;
        ok += decode_packet(rec).status.ok();
    }
    g_count_allocs = false;
    EXPECT_EQ(g_allocs.load(), 0u);
    EXPECT_EQ(n, 20000u);
    EXPECT_EQ(ok, 20000u);
}

// ---- MappedFile ----
namespace {
std::filesystem::path temp_path(const char* tag) {
    return std::filesystem::temp_directory_path() /
           ("netprobe_test_" + std::to_string(::getpid()) + "_" + tag);
}
} // namespace

TEST(MappedFile, MapsRegularFileAndReadsViaReader) {
    const auto path = temp_path("ok.pcap");
    const ByteVec file = pcap_file({}, {{.data = frame()}});
    write_file(path, file);
    {
        MappedFile m = MappedFile::open(path);
        ASSERT_EQ(m.bytes().size(), file.size());
        EXPECT_TRUE(std::equal(file.begin(), file.end(), m.bytes().begin()));
        MappedFile moved = std::move(m);
        EXPECT_EQ(m.bytes().size(), 0u);
        auto r = PcapReader::open(moved.bytes());
        ASSERT_EQ(r.error, OpenError::none);
        PacketRecord rec;
        EXPECT_TRUE(r.reader->next(rec));
        moved.release_before(100); // no-op, must not break reads
        EXPECT_EQ(moved.bytes().size(), file.size());
    }
    std::filesystem::remove(path);
}

TEST(MappedFile, EmptyFileIsValidAndEmpty) {
    const auto path = temp_path("empty");
    write_file(path, {});
    MappedFile m = MappedFile::open(path);
    EXPECT_EQ(m.bytes().size(), 0u);
    EXPECT_EQ(PcapReader::open(m.bytes()).error, OpenError::too_short);
    std::filesystem::remove(path);
}

TEST(MappedFile, MissingFileThrowsInputErrorNamingPath) {
    const auto path = temp_path("does_not_exist");
    try {
        MappedFile::open(path);
        FAIL() << "expected InputError";
    } catch (const InputError& e) {
        EXPECT_NE(std::string(e.what()).find(path.string()), std::string::npos) << e.what();
    }
}

TEST(MappedFile, NonRegularFileRejected) {
    EXPECT_THROW(MappedFile::open("/dev/null"), InputError);
    EXPECT_THROW(MappedFile::open(std::filesystem::temp_directory_path()), InputError);
}
