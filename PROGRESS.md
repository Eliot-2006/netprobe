# Progress log

## Environment

- Host: Apple M3 Pro (11 cores), 18 GiB RAM, macOS (Darwin 27). PRD targets Linux; Linux runs use a
  local Docker image `netprobe-dev:24.04` (Ubuntu 24.04, GCC 13, Clang 18, tshark; arm64 VM with 11
  vCPUs / 7.7 GiB). Its Dockerfile recipe is in the README.
- macOS toolchain: Homebrew LLVM 23 for every preset (Apple Clang 15 lacks `std::format`; its ASan
  aborts at init on this macOS). macOS ASan is not a gate: Homebrew libc++abi plus ASan's
  `__cxa_throw` interposition make thrown exceptions uncatchable. Linux ASan/UBSan/TSan are authoritative.
- Agents: Paradev CLI 2.0.5. Claude (Sonnet) workers; Codex (`gpt-6.1-sol`; the "GPT-6.1 Terra" model
  named in the brief does not exist in the Codex catalog); Gemini CLI login is rejected by Google
  ("client no longer supported"), so the independent reviewer runs on Antigravity (`agy`, Gemini 3.8 Flash).
- Usage/quota: no Paradev or provider CLI exposes remaining quota, so none is reported. Policy: at
  most three workers plus the orchestrator, no retry loops on rate limits. No rate-limit errors seen so far.

## Log (newest last)

- **M0** skeleton; **M1+M2** decode worker merged (68 tests, 285M fuzz_decode execs, 95M fuzz_pcap execs
  reported by worker); **M4** reassembler worker merged (10^6 property cases, 1.3M fuzz execs reported).
- **M3/M5** analyzer + reports; independent checks: 21 Scapy fixtures with ground truth, tshark
  differential (per packet, conversations, follow streams) passes on all fixtures.
- Linux sanitizers found two real bugs, both fixed with regressions: signed overflow in the first expiry
  sweep (UBSan), partial global operator new/delete replacement in a test (ASan).
- **M6** analyzer tests (100k-SYN flood bounded at 1000 flows, budget bound across 40 stalled streams).
- **M7** HTML report via Impeccable (PRODUCT.md, direction "flight-strip bay" chosen by owner, finish
  review: 8 material fixes + 3 follow-ups resolved, DESIGN.md by documenter). Samples + `scripts/demo.sh`.
- **M8** bench worker: synth_pcap, micro and e2e benchmarks, macOS baseline in docs/results.md. Its
  finding (0.1% loss → 173 forced flushes) led to the D7 revision: forced flushes 29 → 0, peak buffered
  39.7 MB → 8.5 MB on a 200 MiB capture, identical gaps.
- **M9/M10a** pipeline worker merged: 144/144 tests on macOS dev; worker reports Linux TSan/ASan clean
  with GCC 13 and Clang 18, byte-identical output for -j 0/1/2/4/8, Linux peak RSS 107.7 MiB on the
  1 GiB D2 capture with the release frontier.

## Open

- Linux scaling measurements for docs/results.md (PERF-6/7), 30-min fuzz campaign results, review findings.
- PERF targets were written for x86-64 Linux; only macOS arm64 and an arm64 Linux VM are available here.
