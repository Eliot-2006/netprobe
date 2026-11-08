#include "app.h"
#include "cli.h"

#include <cstdio>
#include <exception>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
    using namespace netprobe;
    std::vector<std::string_view> args(argv + 1, argv + argc);
    const CliResult cli = parse_cli(args);
    if (!cli.error.empty()) {
        std::fprintf(stderr, "netprobe: %s\n\n%.*s", cli.error.c_str(),
                     static_cast<int>(usage().size()), usage().data());
        return exit_usage;
    }
    try {
        switch (cli.command) {
        case Command::help:
            std::fwrite(usage().data(), 1, usage().size(), stdout);
            return exit_ok;
        case Command::version:
            std::printf("netprobe %s\n", NETPROBE_VERSION);
            return exit_ok;
        case Command::analyze:
            return run_analyze(cli.analyze);
        case Command::dump:
            return run_dump(cli.dump);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "netprobe: internal error: %s\n", e.what());
        return exit_output;
    }
    return exit_usage;
}
