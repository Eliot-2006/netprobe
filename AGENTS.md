# AGENTS.md: working on NetProbe

`docs/PRD.md` is the source of truth. Read sections 4–6 and 11 before touching code. Status lives in
`IMPLEMENTATION_PLAN.md` (milestones) and `PROGRESS.md` (log, test results, blockers).

## Build and test

```bash
# macOS: always use Homebrew LLVM (Apple Clang 15 lacks std::format, its ASan aborts at init on
# this macOS, and it has no libFuzzer). CMake links LLVM's libc++ automatically.
# Linux: GCC 13+ or Clang 17+ (CI uses g++-13 and clang++-18).
export CXX=/opt/homebrew/opt/llvm/bin/clang++
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
cmake --preset tsan && cmake --build --preset tsan && ctest --preset tsan
cmake --preset fuzz && cmake --build --preset fuzz   # targets: build/fuzz/fuzz_*
```

Use a separate `build/<preset>` per configuration; don't mix compilers in one build dir.

Source files are globbed (`src/**/*.cpp` → `netprobe_core`, `tests/unit|support|reference/*.cpp` →
`netprobe_tests`, `tests/fuzz/fuzz_*.cpp` → one fuzzer each, `tests/integration/test_*.py` → CTest).
Adding a file needs no CMake edit; re-run the configure step.

## Rules

- No `reinterpret_cast` of packet bytes; use `util/bytes.h` loaders after a length check.
- No exceptions, logging or heap allocation on the per-packet decode path. Decode errors are
  `DecodeStatus` values.
- Never keep a `Bytes` view into capture memory after the call that produced it returns (invariant O1).
- Warnings are errors (`-Wconversion -Wsign-conversion -Wshadow -Wold-style-cast` …). Fix them; don't
  silence them.
- Test first for each decode reason and reassembler behavior. Don't weaken a test to make it pass.
- Shared headers (`util/bytes.h`, `pcap/record.h`, `decode/decode.h`, `tcp/stream_sink.h`,
  `analysis/memory_budget.h`): append, don't rename. Interface changes go through the orchestrator.
- Stay inside your task's file ownership. Don't add dependencies, protocols, flags or report fields
  beyond the PRD.
- Style: `.clang-format`; `snake_case` functions/files, `PascalCase` types, namespace `netprobe`,
  trailing `_` for private members. Mark deliberate shortcuts with a `ponytail:` comment.

## Git

- Identity is repository-local: `Eliot Boda <eliotboda@gmail.com>`. Check with `git config user.email`.
- Commit only on your own task branch, only verified work, with descriptive messages.
- **No `Co-Authored-By` or "Generated with" trailers.** No push, no merge, rebase, reset or history
  rewrite. The orchestrator integrates branches.
