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

- **Independent review** (Antigravity, Gemini 3.8 Flash; 9 findings): 4 fixed with regressions
  (stale FIN, uncounted bytes past FIN, orientation after stray packets, ACK unwrap past 2^30),
  1 rejected with evidence (timeline overflow), 4 documented as deliberate deviations (PRD 2.3).
- **Fuzz instrumentation bug** found and fixed: only harnesses had coverage instrumentation, so
  earlier fuzz execution counts (including workers' reports) had almost no coverage feedback from
  the library. Fixed with `-fsanitize=fuzzer-no-link` for all libraries; 30-min campaign rerun.
- **tshark differential** on Linux (tshark 4.2.2) and macOS (4.6.9): 24/24 captures pass. Two
  evidence-backed exclusions added for tshark limits (follow output on reordered streams; 4.2
  misparsing a corrupt file).
- Linux TSan and ASan+UBSan, GCC 13 and Clang 18: 144/144 on the merged pipeline code.
- Claude usage limit was reached once mid-run and reset; work resumed without loss.

- **Final measurements** (docs/results.md section A): Linux container, GCC 13 -O2. PERF-1..7 and
  PERF-M1 (at 1 GiB) met; PERF-M2 not met (≈ 790 B per flow, upper bound; cause recorded).
  30-min instrumented fuzz campaign: 0 findings.
- **Final gates on HEAD:** Linux TSan + ASan/UBSan with Clang 18 and GCC 13: 148/148 each; macOS dev
  148/148; demo OK; tshark differential 24/24 on tshark 4.2.2 and 4.6.9; clang-format 18 clean.

- **Publication:** PR #1 merged to `main`; README, screenshots and GitHub Pages sample reports
  (`f71c2bd`). GitHub Actions `ci` ran green on the PR and on every push to `main` (`89e9432`,
  `e0e04b4`, `f71c2bd`); Pages deployed.
- **Real-world validation** (docs/validation.md): 787 public captures (tcpdump test suite at
  `f34cf40`, tcpreplay smallFlows/bigFlows; none committed). ASan+UBSan sweep: 1,574 runs, 0
  failures. tshark 4.2.2 differential: 448 captures, 0 failures after fixing four NetProbe bugs
  (lying IP length, RST payload, pre-origin retransmissions, same-ISN SYN after RST) and the
  comparison script's own errors. Stream oracle is now an independent payload rebuild.
- **Final audit** (Claude subagent; the Codex audit was stopped by OpenAI's cybersecurity content
  filter and not worked around): pipeline release stall fixed (mostly-ARP 217 MiB capture,
  `-j 2`: 222 → 133 MiB RSS; regression `test_release_frontier.py`), plus export orientation, repeated export, unbounded talkers, `--html -`, corrupt-tail byte count, `on_fin` under
  `noexcept`, per-shard `max_flows`. Two items documented as limitations (design.md 11).
- **PERF-M2:** out-of-line rare counters and lazy out-of-order map; `Analyzer::Flow` 664 → 360 B,
  ≈ 790 → ≈ 490 B per live flow measured: target met.
- **Final benchmarks** (docs/results.md A.2b): 1 GiB and 2 GiB D1/D2/D3 in the Linux container on
  a loaded host (macOS daemons, load 5–7), so absolute numbers are noisy; an interleaved A/B of
  `f71c2bd` vs the final tree shows no slowdown (D1 faster, 54 MiB smaller). PERF-M1 holds at
  2 GiB (D2 34–78 MiB).
- **Gates on the final tree:** Linux TSan and ASan+UBSan with Clang 18 and GCC 13, GCC 13
  hardened Debug, Clang 18 hardened Release: 156/156 each; macOS dev 156/156.

## Open (not done, by decision or constraint)

- No x86-64 machine was available (only an Apple M3 Pro); emulated x86-64 under Docker would
  measure the emulator, so no x86-64 numbers exist.
- Reader-thread ceiling on scaling (~2×) is measured and explained, not optimized.
