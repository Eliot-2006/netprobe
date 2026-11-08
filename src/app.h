#pragma once
// Top-level commands. Return process exit codes (PRD 7.3).

#include "cli.h"

namespace netprobe {

enum ExitCode : int {
    exit_ok = 0,
    exit_usage = 1,
    exit_input = 2,
    exit_partial = 3,
    exit_output = 4
};

int run_analyze(const AnalyzeOptions& opts);
int run_dump(const DumpOptions& opts);

} // namespace netprobe
