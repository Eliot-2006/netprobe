# Progress log

## Environment (2026-11-07)

- Host: Apple M3 Pro (11 cores), 18 GiB RAM, macOS (Darwin 27). PRD targets Linux; this machine
  is the dev and test platform. Benchmarks taken here will be labeled macOS/arm64.
- Toolchain: Apple Clang 15 (plain builds); Homebrew LLVM 23.1.5 (ASan/UBSan/TSan/libFuzzer: Apple
  Clang 15's ASan aborts at init on this macOS). CMake and Ninja from Homebrew; tshark from Homebrew
  Wireshark.
- Agents: Paradev CLI 2.0.5; presets Claude, Codex (`gpt-6.1-sol`; no "GPT-6.1 Terra" model exists
  in the Codex catalog), Gemini 0.66.0.
- Usage/quota: no Paradev or provider CLI exposes remaining quota. Policy: at most 2 workers plus the
  orchestrator, short prompts, no retry loops on rate-limit errors.

## Log

- **M0 done.** Skeleton builds with `-Werror` in dev/asan/tsan; bytes tests pass in all three.
  libFuzzer + ASan verified with Homebrew LLVM.
