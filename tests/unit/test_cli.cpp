#include "cli.h"

#include <gtest/gtest.h>

#include <vector>

using namespace netprobe;

static CliResult parse(std::vector<std::string_view> v) {
    return parse_cli(v);
}

TEST(Cli, Defaults) {
    auto r = parse({"analyze", "x.pcap"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ(r.command, Command::analyze);
    EXPECT_EQ(r.analyze.input, "x.pcap");
    EXPECT_EQ(r.analyze.workers, 0u);
    EXPECT_EQ(r.analyze.idle_timeout_s, 300u);
    EXPECT_EQ(r.analyze.max_flows, 1'000'000u);
    EXPECT_EQ(r.analyze.max_stream_buffer, 4u << 20);
    EXPECT_EQ(r.analyze.max_reassembly_memory, 512u << 20);
    EXPECT_EQ(r.analyze.top_flows, 1000u);
    EXPECT_FALSE(r.analyze.quiet);
    EXPECT_FALSE(r.analyze.json_path);
}

TEST(Cli, AllAnalyzeOptions) {
    auto r = parse({"analyze", "--json", "o.json", "--html=o.html", "--export-streams", "d", "-q",
                    "--deterministic", "-j", "4", "--idle-timeout=60", "--max-flows", "10",
                    "--max-stream-buffer", "1M", "--max-reassembly-memory=2G", "--top-flows", "5",
                    "in.pcap"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    const auto& a = r.analyze;
    EXPECT_EQ(a.input, "in.pcap");
    EXPECT_EQ(a.json_path, "o.json");
    EXPECT_EQ(a.html_path, "o.html");
    EXPECT_EQ(a.export_dir, "d");
    EXPECT_TRUE(a.quiet);
    EXPECT_TRUE(a.deterministic);
    EXPECT_EQ(a.workers, 4u);
    EXPECT_EQ(a.idle_timeout_s, 60u);
    EXPECT_EQ(a.max_flows, 10u);
    EXPECT_EQ(a.max_stream_buffer, 1u << 20);
    EXPECT_EQ(a.max_reassembly_memory, 2ull << 30);
    EXPECT_EQ(a.top_flows, 5u);
}

TEST(Cli, JsonToStdoutImpliesQuiet) {
    auto r = parse({"analyze", "x", "-o", "-"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_TRUE(r.analyze.quiet);
    // HTML on stdout must not be followed by the text summary (independent audit L3).
    EXPECT_TRUE(parse({"analyze", "x", "--html", "-"}).analyze.quiet);
}

TEST(Cli, Dump) {
    auto r = parse({"dump", "x.pcap", "--limit", "7"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ(r.command, Command::dump);
    EXPECT_EQ(r.dump.input, "x.pcap");
    EXPECT_EQ(r.dump.limit, 7u);
    EXPECT_FALSE(parse({"dump", "x", "--json", "y"}).error.empty());
}

TEST(Cli, HelpAndVersion) {
    EXPECT_EQ(parse({"--help"}).command, Command::help);
    EXPECT_EQ(parse({"--version"}).command, Command::version);
    EXPECT_EQ(parse({"-V"}).command, Command::version);
    EXPECT_EQ(parse({"analyze", "--help"}).command, Command::help);
    EXPECT_NE(usage().find("--max-reassembly-memory"), std::string_view::npos);
}

TEST(Cli, Errors) {
    EXPECT_FALSE(parse({}).error.empty());
    EXPECT_FALSE(parse({"frobnicate"}).error.empty());
    EXPECT_FALSE(parse({"analyze"}).error.empty());                   // missing input
    EXPECT_FALSE(parse({"analyze", "a", "b"}).error.empty());         // two inputs
    EXPECT_FALSE(parse({"analyze", "a", "--bogus"}).error.empty());   // unknown flag
    EXPECT_FALSE(parse({"analyze", "a", "--json"}).error.empty());    // missing value
    EXPECT_FALSE(parse({"analyze", "a", "-j", "257"}).error.empty()); // out of range
    EXPECT_FALSE(parse({"analyze", "a", "-j", "-1"}).error.empty());
    EXPECT_FALSE(parse({"analyze", "a", "-j", "4x"}).error.empty());
    EXPECT_FALSE(parse({"analyze", "a", "--idle-timeout", "0"}).error.empty());
    EXPECT_FALSE(parse({"analyze", "a", "--max-stream-buffer", "1K"}).error.empty()); // < 64K
    EXPECT_FALSE(parse({"analyze", "a", "--top-flows", "0"}).error.empty());
    EXPECT_FALSE(parse({"analyze", "a", "--quiet=yes"}).error.empty());
    auto r = parse({"analyze", "a", "-j", "999"});
    EXPECT_NE(r.error.find("0..256"), std::string::npos) << r.error;
}

TEST(Cli, ParseSize) {
    EXPECT_EQ(parse_size("0"), 0u);
    EXPECT_EQ(parse_size("64K"), 64u << 10);
    EXPECT_EQ(parse_size("4m"), 4u << 20);
    EXPECT_EQ(parse_size("1G"), 1u << 30);
    EXPECT_FALSE(parse_size(""));
    EXPECT_FALSE(parse_size("K"));
    EXPECT_FALSE(parse_size("1T"));
    EXPECT_FALSE(parse_size("-1"));
    EXPECT_FALSE(parse_size("18446744073709551615K")); // overflow
    EXPECT_EQ(parse_size("17179869183G"), 17179869183ull << 30);
    EXPECT_FALSE(parse_size("17179869184G"));
}
