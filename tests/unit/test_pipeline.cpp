#include "pipeline/pipeline.h"
#include "support/packet_builder.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <thread>
#include <unistd.h>

using namespace netprobe;
namespace {
struct Capture {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 ("netprobe-pipeline-" + std::to_string(::getpid()) + ".pcap");
    ~Capture() { std::filesystem::remove(path); }
    void write(std::size_t count) {
        std::vector<test::PcapRecordSpec> records;
        for (std::size_t i = 0; i < count; ++i) {
            test::TcpOpts tcp;
            tcp.seq = 1000 + static_cast<std::uint32_t>(i);
            records.push_back(
                {0,
                 static_cast<std::uint32_t>(i),
                 test::eth(0x0800, test::ipv4({}, test::tcp(tcp, test::counting_bytes(1)))),
                 {},
                 {}});
        }
        test::write_file(path, test::pcap_file({}, records));
    }
};

std::string analyze(Capture& cap, std::uint32_t workers) {
    auto file = MappedFile::open(cap.path);
    auto opened = PcapReader::open(file.bytes());
    auto& reader = *opened.reader;
    ReaderStats stats;
    RunInfo run;
    AnalyzerConfig cfg;
    auto result = [&] {
        if (workers != 0) {
            return run_pipeline(reader, file, cfg, workers, stats, run);
        }
        Analyzer analyzer(cfg);
        PacketRecord rec;
        while (reader.next(rec)) {
            const auto pkt = decode_packet(rec);
            stats.add(rec, pkt);
            analyzer.process(rec, pkt);
        }
        return analyzer.finish();
    }();
    if (workers) {
        std::uint64_t packets = 0;
        for (const auto& worker : run.worker_stats) {
            packets += worker.packets;
            EXPECT_LE(worker.max_occupancy, 8u);
        }
        EXPECT_EQ(packets, stats.packets());
    }
    AnalyzeOptions options;
    Report report;
    report.options = &options;
    report.reader = &stats;
    report.flows = &result;
    report.deterministic = true;
    return render_json(report);
}
} // namespace

TEST(Pipeline, EmptyOnePacketAndMoreWorkersThanFlows) {
    Capture cap;
    for (std::size_t count : {0u, 1u, 5000u}) {
        cap.write(count);
        const auto reference = analyze(cap, 0);
        for (std::uint32_t workers : {1u, 2u, 4u, 8u}) {
            EXPECT_EQ(analyze(cap, workers), reference);
        }
    }
}

TEST(Pipeline, WorkerExceptionPropagatesWithoutHanging) {
    Capture cap;
    cap.write(100'000);
    auto file = MappedFile::open(cap.path);
    auto opened = PcapReader::open(file.bytes());
    ReaderStats stats;
    RunInfo run;
    ::alarm(10);
    EXPECT_THROW(run_pipeline(*opened.reader, file, {}, 4, stats, run,
                              [](std::uint32_t) {
                                  std::this_thread::sleep_for(std::chrono::milliseconds(20));
                                  throw std::runtime_error("worker failure");
                              }),
                 std::runtime_error);
    ::alarm(0);
}

TEST(Pipeline, ReleaseFrontierRoundsDownAndGuardsCompletedPages) {
    Capture cap;
    const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
    test::write_file(cap.path, test::counting_bytes(page * 3));
    auto file = MappedFile::open(cap.path);
    file.release_before(page - 1);
    EXPECT_EQ(file.bytes()[0], std::byte{0});
    file.release_before(page + 1);
    EXPECT_EQ(file.bytes()[page], std::byte{0});
#ifdef NETPROBE_DEBUG_GUARDS
    EXPECT_DEATH(
        {
            volatile auto value = file.bytes()[0];
            (void)value;
        },
        "");
#endif
    // Repeated and regressing calls cannot release the next, still-live page.
    file.release_before(0);
    file.release_before(page);
    EXPECT_EQ(file.bytes()[page * 2], std::byte{0});
}
