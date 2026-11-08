#pragma once
// Command-line parsing for `netprobe analyze` and `netprobe dump` (PRD 7).

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace netprobe {

struct AnalyzeOptions {
    std::string input;
    std::optional<std::string> json_path; // "-" = stdout
    std::optional<std::string> html_path;
    std::optional<std::string> export_dir;
    bool quiet = false;
    bool deterministic = false;
    std::uint32_t workers = 0;
    std::uint64_t idle_timeout_s = 300;
    std::uint64_t max_flows = 1'000'000;
    std::uint64_t max_stream_buffer = 4ull << 20;
    std::uint64_t max_reassembly_memory = 512ull << 20;
    std::uint64_t top_flows = 1000;
};

struct DumpOptions {
    std::string input;
    std::optional<std::uint64_t> limit;
};

enum class Command { analyze, dump, help, version };

struct CliResult {
    Command command = Command::help;
    AnalyzeOptions analyze;
    DumpOptions dump;
    std::string error; // non-empty => usage error (exit 1)
};

// `args` excludes argv[0].
CliResult parse_cli(std::span<const std::string_view> args);
std::string_view usage() noexcept;

// "64K", "4M", "1G" (powers of 1024) or plain bytes. nullopt on syntax error or overflow.
std::optional<std::uint64_t> parse_size(std::string_view s) noexcept;

} // namespace netprobe
