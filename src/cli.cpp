#include "cli.h"

#include <charconv>
#include <format>
#include <limits>

namespace netprobe {
namespace {

std::optional<std::uint64_t> parse_uint(std::string_view s) noexcept {
    std::uint64_t v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (s.empty() || ec != std::errc{} || ptr != s.data() + s.size()) {
        return std::nullopt;
    }
    return v;
}

struct Range {
    std::uint64_t lo, hi;
};

} // namespace

std::optional<std::uint64_t> parse_size(std::string_view s) noexcept {
    if (s.empty()) {
        return std::nullopt;
    }
    unsigned shift = 0;
    switch (s.back()) {
    case 'K':
    case 'k':
        shift = 10;
        break;
    case 'M':
    case 'm':
        shift = 20;
        break;
    case 'G':
    case 'g':
        shift = 30;
        break;
    default:
        break;
    }
    if (shift != 0) {
        s.remove_suffix(1);
    }
    auto v = parse_uint(s);
    if (!v || *v > (std::numeric_limits<std::uint64_t>::max() >> shift)) {
        return std::nullopt;
    }
    return *v << shift;
}

std::string_view usage() noexcept {
    return R"(usage:
  netprobe analyze <capture.pcap> [options]
  netprobe dump <capture.pcap> [--limit N]
  netprobe --help | --version

analyze output:
  -o, --json <path>                write JSON report ("-" = stdout; implies --quiet)
      --html <path>                write standalone HTML report
      --export-streams <dir>       write reassembled TCP streams, one file per direction
  -q, --quiet                      suppress the text summary
      --deterministic              omit timings/host fields (the "run" section)

analyze processing:
  -j, --workers <N>                0 = single-threaded (default); N >= 1 = reader + N shards
      --idle-timeout <sec>         open-flow idle timeout in capture time (default 300)
      --max-flows <N>              max concurrent flows (default 1000000)
      --max-stream-buffer <size>   out-of-order buffer per TCP direction (default 4M)
      --max-reassembly-memory <size>  total out-of-order budget (default 512M)
      --top-flows <N>              detailed flow records kept per list (default 1000)

Sizes accept K, M, G suffixes (powers of 1024).
)";
}

CliResult parse_cli(std::span<const std::string_view> args) {
    CliResult r;
    if (args.empty()) {
        r.error = "missing command";
        return r;
    }
    const std::string_view cmd = args[0];
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        r.command = Command::help;
        return r;
    }
    if (cmd == "-V" || cmd == "--version") {
        r.command = Command::version;
        return r;
    }
    if (cmd != "analyze" && cmd != "dump") {
        r.error = std::format("unknown command '{}'", cmd);
        return r;
    }
    r.command = cmd == "analyze" ? Command::analyze : Command::dump;
    std::string* input = r.command == Command::analyze ? &r.analyze.input : &r.dump.input;
    bool have_input = false;

    for (std::size_t i = 1; i < args.size(); ++i) {
        std::string_view arg = args[i];
        if (arg == "-h" || arg == "--help") {
            r.command = Command::help;
            return r;
        }
        if (arg.size() < 2 || arg[0] != '-') {
            if (have_input) {
                r.error = std::format("unexpected argument '{}'", arg);
                return r;
            }
            *input = std::string(arg);
            have_input = true;
            continue;
        }

        std::string_view name = arg;
        std::optional<std::string_view> inline_value;
        if (auto eq = arg.find('='); arg.starts_with("--") && eq != std::string_view::npos) {
            name = arg.substr(0, eq);
            inline_value = arg.substr(eq + 1);
        }
        auto take_value = [&]() -> std::optional<std::string_view> {
            if (inline_value) {
                return inline_value;
            }
            if (i + 1 >= args.size()) {
                r.error = std::format("option '{}' requires a value", name);
                return std::nullopt;
            }
            return args[++i];
        };
        auto take_number = [&](Range range, bool size) -> std::optional<std::uint64_t> {
            auto v = take_value();
            if (!v) {
                return std::nullopt;
            }
            auto n = size ? parse_size(*v) : parse_uint(*v);
            if (!n || *n < range.lo || *n > range.hi) {
                r.error = std::format("invalid value '{}' for {} (allowed {}..{})", *v, name,
                                      range.lo, range.hi);
                return std::nullopt;
            }
            return n;
        };
        auto flag_only = [&]() {
            if (inline_value) {
                r.error = std::format("option '{}' takes no value", name);
                return false;
            }
            return true;
        };

        constexpr std::uint64_t kMaxSize = 1ull << 40;
        if (r.command == Command::dump) {
            if (name == "--limit") {
                auto n = take_number({1, std::numeric_limits<std::uint64_t>::max()}, false);
                if (!n) {
                    return r;
                }
                r.dump.limit = *n;
                continue;
            }
            r.error = std::format("unknown option '{}' for dump", arg);
            return r;
        }

        AnalyzeOptions& a = r.analyze;
        if (name == "-o" || name == "--json") {
            auto v = take_value();
            if (!v) {
                return r;
            }
            a.json_path = std::string(*v);
        } else if (name == "--html") {
            auto v = take_value();
            if (!v) {
                return r;
            }
            a.html_path = std::string(*v);
        } else if (name == "--export-streams") {
            auto v = take_value();
            if (!v) {
                return r;
            }
            a.export_dir = std::string(*v);
        } else if (name == "-q" || name == "--quiet") {
            if (!flag_only()) {
                return r;
            }
            a.quiet = true;
        } else if (name == "--deterministic") {
            if (!flag_only()) {
                return r;
            }
            a.deterministic = true;
        } else if (name == "-j" || name == "--workers") {
            auto n = take_number({0, 256}, false);
            if (!n) {
                return r;
            }
            a.workers = static_cast<std::uint32_t>(*n);
        } else if (name == "--idle-timeout") {
            auto n = take_number({1, 86400}, false);
            if (!n) {
                return r;
            }
            a.idle_timeout_s = *n;
        } else if (name == "--max-flows") {
            auto n = take_number({1, 1ull << 32}, false);
            if (!n) {
                return r;
            }
            a.max_flows = *n;
        } else if (name == "--max-stream-buffer") {
            auto n = take_number({64ull << 10, kMaxSize}, true);
            if (!n) {
                return r;
            }
            a.max_stream_buffer = *n;
        } else if (name == "--max-reassembly-memory") {
            auto n = take_number({64ull << 10, kMaxSize}, true);
            if (!n) {
                return r;
            }
            a.max_reassembly_memory = *n;
        } else if (name == "--top-flows") {
            auto n = take_number({1, 1'000'000}, false);
            if (!n) {
                return r;
            }
            a.top_flows = *n;
        } else {
            r.error = std::format("unknown option '{}'", arg);
            return r;
        }
    }

    if (!have_input) {
        r.error = "missing capture file";
    }
    if (r.command == Command::analyze && r.analyze.json_path == "-") {
        r.analyze.quiet = true;
    }
    return r;
}

} // namespace netprobe
