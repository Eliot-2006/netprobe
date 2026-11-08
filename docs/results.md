# NetProbe results

Every number below comes from a command recorded in this file or in `bench/run_linux_container.sh`.
Disk I/O is excluded everywhere (page cache warm). Section A is Linux: A.2 is the quiet-machine
scaling run at commit `9b23f83`, A.2b re-measures the final code at 1 GiB and 2 GiB. Section B is the
earlier macOS single-threaded baseline (M8), kept for history.

**No x86-64 hardware was available.** The only machine is an Apple M3 Pro (arm64). Docker can run
x86-64 images only through emulation, which would measure the emulator, so every Linux number here
is arm64 and no x86-64 number exists.

## A. Final code on Linux (container), single- and multi-threaded

### A.1 Setup

| Item | Value |
|---|---|
| Host | Apple M3 Pro, 11 cores, 18 GiB, running Docker Desktop |
| Guest | Ubuntu 24.04 container, kernel `Linux 7.0.14-linuxkit aarch64`, 11 vCPUs, 7.7 GiB (`out/bench-linux/env.txt`) |
| Compiler | `g++-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1)`, Release `-O2 -DNDEBUG`, no `-march=native`, no LTO |
| Code | integration branch at commit `9b23f83` (pipeline, release frontier, D7 revision, review fixes) |
| Command | `docker run --rm -v "$PWD":/src -w /src -e RUNS=5 netprobe-dev:24.04 bench/run_linux_container.sh out/bench-linux` |
| Datasets | D1/D2/D3 regenerated in the container by `synth_pcap --profile dN --size 1G` (seed 1; SHA-256 identical to section B) |
| Method | per worker count: one warm-up run, then 5 measured runs; median (min–max). Micro-benchmarks: 5 repetitions, median; CV ≤ 5 % except `BM_MutexQueue/1` (9.2 %) |
| Caveats | arm64 under a VM, not the PRD's x86-64 reference machine; no core pinning. Nothing else ran during this measurement (A.2b was not as lucky). |

### A.2 End-to-end throughput by worker count

`netprobe analyze --quiet --workers N --json <tmp>` (`out/bench-linux/e2e_*.txt`). Mpkt/s and MiB/s
are captured records and bytes per second of wall time.

| Dataset | workers | elapsed ms | Mpkt/s | MiB/s | peak RSS MiB |
|---|---|---|---|---|---|
| D3 mixed | 0 (inline) | 547 (464–864) | 3.73 (2.36–4.40) | 1815 | 253.7 |
| D3 | 1 | 400 (395–401) | 5.11 | 2483 | 196.6 |
| D3 | 2 | 269 (256–285) | 7.60 | 3696 | 196.9 |
| D3 | 4 | 265 (249–269) | 7.69 | 3741 | 200.3 |
| D3 | 8 | 258 (250–264) | 7.90 | 3842 | 208.2 |
| D1 many flows | 0 | 803 (785–878) | 3.84 | 1217 | 209.7 |
| D1 | 1 | 766 (753–911) | 4.02 | 1275 | 163.2 |
| D1 | 2 | 399 (394–414) | 7.71 | 2447 | 164.1 |
| D1 | 4 | 350 (338–361) | 8.80 | 2790 | 165.6 |
| D1 | 8 | 351 (338–450) | 8.77 | 2783 | 170.1 |
| D2 16 elephants | 0 | 180 (179–191) | 5.73 | 5608 | 78.3 |
| D2 | 1 | 151 (150–154) | 6.83 | 6686 | 33.3 |
| D2 | 2 | 158 (154–158) | 6.54 | 6402 | 34.0 |
| D2 | 4 | 163 (161–163) | 6.32 | 6192 | 39.1 |
| D2 | 8 | 169 (165–172) | 6.09 | 5963 | 46.7 |

**Scaling and its ceiling.** Throughput saturates at about 7.7–8.8 Mpkt/s from 2–4 workers on. The
reader thread (record iteration, decode, `ReaderStats`, flow hash, batching) is the serial part: at
saturation it costs about 1 / 7.9 M ≈ 127 ns per packet, against about 268 ns per packet for the
whole inline path on D3. Amdahl with serial fraction ≈ 0.47 predicts a ceiling of ≈ 2.1×, which is
what D3 shows (2.06× at 4 workers). D2's 16 elephant flows cannot be split across shards, so extra
workers only add coordination cost. `--workers 1` is faster than inline because decoding overlaps
with analysis. The next step would be moving decode or `ReaderStats` off the reader thread; no
change was made without measurements to justify it.

### A.2b Final code, 1 GiB and 2 GiB

Same container and compiler, final working tree (after the validation, audit and PERF-M2 changes).
Commands: `docker run --rm -v "$PWD":/src -w /src -e RUNS=5 netprobe-dev:24.04
bench/run_linux_container.sh out/bench-linux-final` and the same with `-e SIZE=2G` into
`out/bench-linux-2g`. The script generates, measures and deletes one dataset at a time.

**The host was not quiet:** macOS system daemons (Spotlight indexing, FileProvider, mobileassetd)
used about 3.5 cores and the load average was 5–7. The same binary's `BM_Decode/d3` measured 26.5
and 31.9 M pkt/s in two consecutive runs (38.6 in A.3), so treat absolute numbers below as
pessimistic and noisy, and A.2 as the reference for scaling.

2 GiB datasets (seed 1): D1 2,147,484,325 B, 6,157,395 packets, 563,932 flows; D2 2,147,484,480 B,
2,058,946 packets, 16 flows; D3 2,147,483,914 B, 4,085,731 packets, 89,235 flows
(`out/bench-linux-2g/datasets.txt`, with SHA-256).

| Dataset | workers | 1 GiB elapsed ms | 1 GiB Mpkt/s | 1 GiB RSS MiB | 2 GiB elapsed ms | 2 GiB Mpkt/s | 2 GiB RSS MiB |
|---|---|---|---|---|---|---|---|
| D3 | 0 | 580 (525–799) | 3.52 | 244.0 | 1384 (1328–1598) | 2.95 | 264.2 |
| D3 | 1 | 507 | 4.03 | 187.0 | 880 | 4.64 | 208.7 |
| D3 | 2 | 376 | 5.43 | 189.5 | 608 (474–815) | 6.72 | 211.0 |
| D3 | 4 | 300 | 6.80 | 191.0 | 525 | 7.78 | 216.1 |
| D3 | 8 | 336 | 6.08 | 200.5 | 542 | 7.54 | 225.6 |
| D1 | 0 | 920 (880–1012) | 3.35 | 155.2 | 1834 (1455–3072) | 3.36 | 175.0 |
| D1 | 1 | 846 | 3.64 | 108.7 | 1505 | 4.09 | 149.7 |
| D1 | 2 | 569 | 5.41 | 109.5 | 818 | 7.53 | 150.4 |
| D1 | 4 | 498 (418–604) | 6.19 | 111.1 | 721 | 8.54 | 151.8 |
| D1 | 8 | 419 | 7.34 | 115.4 | 770 | 8.00 | 155.0 |
| D2 | 0 | 210 | 4.91 | 78.3 | 428 | 4.82 | 78.4 |
| D2 | 1 | 250 | 4.12 | 32.9 | 406 | 5.07 | 33.7 |
| D2 | 2 | 191 | 5.40 | 36.2 | 326 | 6.32 | 35.1 |
| D2 | 4 | 185 | 5.56 | 40.3 | 338 | 6.10 | 39.4 |
| D2 | 8 | 193 | 5.33 | 47.2 | 331 | 6.22 | 47.1 |

Median of 5 (min–max shown where the spread exceeds 15 %). Full output in `e2e_*.txt`.

- **Memory does not grow with file size.** Doubling the file adds 0–20 MiB inline and 1–40 MiB
  with workers (more live flows and talkers), and D2 stays at 78 MiB inline and 33–47 MiB with
  workers at 2 GiB. PERF-M1 holds at the PRD's size.
- **Regression check under the same noise.** Because absolute numbers moved with host load, the
  committed code (`f71c2bd`) and the final tree were built side by side and run interleaved, 7 runs
  each, on the 1 GiB sets (`out/bench-linux-final/ab.txt`). Median ms (RSS MiB):

  | | before | after |
  |---|---|---|
  | D3 `-j 0` | 509.5 (253.7) | 499.6 (244.0) |
  | D3 `-j 4` | 260.3 (200.3) | 259.5 (189.8) |
  | D1 `-j 0` | 1181.5 (209.7) | 952.7 (155.2) |
  | D1 `-j 4` | 592.0 (165.6) | 520.5 (111.1) |

  No slowdown; D1 is faster and 54 MiB smaller because flow state shrank (A.4).

### A.3 Micro-benchmarks (`out/bench-linux/micro.json`)

| Benchmark | Median |
|---|---|
| `BM_Decode/d3` | 38.6 M pkt/s (18.2 GiB/s) |
| `BM_Decode/tcp_v4`, `tcp_v6`, `udp_v4`, `vlan` | 39.7, 37.0, 41.9, 38.9 M pkt/s |
| `BM_FlowLookup` at 1 Ki / 64 Ki / 1 Mi live flows | 23.4 / 15.9 / 4.02 M lookups/s |
| `BM_Reassembly_InOrder` (1460 B, NullSink) | 331 GiB/s: bookkeeping only, the in-order path copies nothing |
| `BM_Reassembly_Reorder` 1 % / 10 % / 30 % | 160 / 31.4 / 16.1 GiB/s |
| `BM_Reassembly_Retransmit` 1 % / 10 % | 324 / 264 GiB/s |
| `BM_Analyzer` (decode + analyzer, 32 MiB D3 slice, 1 thread) | 7.70 M pkt/s |
| `BM_Spsc` 1 / 256 items per op | 104 / 105 M items/s |
| `BM_MutexQueue` 1 / 256 items per op (baseline) | 5.9 / 6.2 M items/s |

### A.4 Memory

- **Release frontier (PERF-M1):** D2 1 GiB peak RSS is 78 MiB inline and 33–47 MiB with workers,
  versus about 1.07 GiB before the frontier existed (section B). Measured at 1 GiB, not 2 GiB.
- **Per-flow memory (PERF-M2), final code:** D1 at 64 MiB vs 1 GiB with `--idle-timeout 86400`
  gives peak live flows 20,717 vs 189,491 and peak RSS 76.2 vs 155.2 MiB (3 runs each, identical
  to within 0.1 MiB; `out/bench-linux-final/per_flow.txt`), so **≈ 491 B per live flow: target
  met.** This is an upper bound (it includes talker entries, which also grow with flows). Before
  this round the same measurement gave ≈ 790 B (82.3 vs 209.7 MiB). Change: `StreamReassembler`
  keeps its out-of-order map behind a pointer allocated on first out-of-order segment, and moves
  rarely non-zero anomaly counters into a block allocated on first use; `sizeof(Analyzer::Flow)`
  went from 664 to 360 bytes. Correctness: all 156 tests, goldens unchanged except the new
  `talkers_capped` field, and the real-world differential (docs/validation.md).
- **Pipeline release stall (fixed in the final audit):** packets that never reach a worker (ARP,
  ICMP, malformed) used to hold back the release frontier. On the regression test's 217 MiB
  mostly-ARP capture, `-j 2` peaked at 222 MiB RSS (the whole file resident) before the fix and
  133 MiB after (68 MiB inline). Regression test:
  `tests/integration/test_release_frontier.py` (Linux).
- **Reassembly buffering (D7 revision):** on a 200 MiB D2-profile capture, forced flushes went from
  29 to 0 and peak buffered bytes from 39.7 MB to 8.5 MB, with identical gaps (same file,
  before/after binaries; see commit `609e42d`).

### A.5 PRD 13 targets on this setup

| ID | Target | Measured (Linux container, A.2–A.4) | Status |
|---|---|---|---|
| PERF-1 | decode D3 ≥ 15 M pkt/s | 38.6 M pkt/s | met |
| PERF-2 | in-order reassembly ≥ 8 GiB/s | 331 GiB/s (NullSink) | met, bookkeeping rate |
| PERF-3 | 10 % reorder ≥ 1.5 GiB/s | 31.4 GiB/s | met |
| PERF-4 | e2e D3 w0 ≥ 2.5 Mpkt/s and ≥ 1.5 GiB/s | 3.73 Mpkt/s, 1.77 GiB/s (A.2); 2 GiB under load: 2.95 Mpkt/s, 1.40 GiB/s | met on a quiet host; GiB/s missed under load at 2 GiB |
| PERF-5 | e2e D1 w0 ≥ 1.5 Mpkt/s | 3.84 Mpkt/s (284k flows); 3.36 Mpkt/s at 2 GiB (564k flows) | met |
| PERF-6 | D3 w4 / w0 ≥ 2.0× | 2.06× (A.2); 1.93× (1 GiB) and 2.64× (2 GiB) on the loaded host | met on a quiet host, at the Amdahl ceiling |
| PERF-7 | w1 ≤ 20 % slower than w0 | 27 % faster on D3 | met |
| PERF-M1 | D2 peak RSS ≤ 128 MiB | 33–78 MiB at 1 GiB, 34–78 MiB at 2 GiB | met |
| PERF-M2 | ≤ 512 B per idle flow | ≈ 491 B upper bound | met (was ≈ 790 B, see A.4) |
| PERF-M3 | budget ≤ limit + one segment | enforced and tested | met (tests) |

### A.6 Fuzzing (30 minutes per target, Linux, Clang 18, ASan + UBSan, instrumented library)

| Target | Executions | exec/s | Coverage (edges) | Corpus | Findings |
|---|---|---|---|---|---|
| `fuzz_decode` | 1,333,493,678 | 740,418 | 131 | 191 | 0 |
| `fuzz_pcap` | 535,143,250 | 297,136 | 288 | 557 | 0 |
| `fuzz_reassembly` | 8,019,625 | 4,452 | 249 | 515 | 0 |

Earlier fuzz runs (including those reported by workers during development) were built before
`8d4b4bc`, when only the harnesses had coverage instrumentation; their execution counts carry
little coverage weight and are not counted here.

---

## B. M8 baseline (macOS, single-threaded, historical)


Every number below was produced by a command listed in this file. Baseline is git `f171118` plus the
bench tooling in this change. **Disk I/O is excluded**: all end-to-end runs use a page-cache-warm
file (`cat file > /dev/null`, then one discarded run).

## 1. Methodology

| Item | Value |
|---|---|
| CPU | `sysctl -n machdep.cpu.brand_string hw.ncpu hw.physicalcpu hw.memsize` → Apple M3 Pro, 11 logical / 11 physical cores, 19,327,352,832 B (18 GiB) |
| OS | macOS 27.0.1 (26A434), Darwin 27.0.0 arm64 (`sw_vers`, `uname -a`) |
| Power | AC attached (`pmset -g batt`); no governor/SMT/turbo control exists on macOS |
| Compiler | Homebrew clang 23.1.5 (`/opt/homebrew/opt/llvm/bin/clang++`), LLVM libc++ |
| Build | `cmake --preset bench -DCMAKE_CXX_FLAGS=-Wno-c2y-extensions && cmake --build --preset bench` → Release, **`-O3 -DNDEBUG`** (CMake's Release default in `build/bench/CMakeCache.txt`; the PRD says `-O2`, see §6), no `-march=native`, no LTO |
| Pinning | none: macOS has no `taskset` and Google Benchmark's affinity call fails ("Failed to set thread affinity") |
| Machine state | **Not quiet.** A `Virtualization.framework` VM (another workload) used 100–450 % CPU for much of the session; 1-min load average was 12–15 during the first runs and 5.6–5.9 during the final end-to-end runs. Load is stated next to each table. |
| Micro-benchmarks | `build/bench/netprobe_bench --benchmark_repetitions=5 --benchmark_report_aggregates_only=true`; median of 5 and CV of real time |
| End-to-end | `RUNS=9 bench/run_e2e.sh build/bench/netprobe datasets/<d>.pcap 0` (warm-up + 9 measured runs; 9 instead of 5 because the machine was noisy) of `netprobe analyze --quiet --workers 0 --json <tmp>`; values come from the JSON `run` section; median and (min–max) |
| Slice for decode/analyzer micro-benchmarks | first 32 MiB of `datasets/d3.pcap` (override with `NETPROBE_BENCH_PCAP`, `NETPROBE_BENCH_SLICE_MIB`) |

### Datasets

All generated by `synth_pcap` (seed 1, the default), each **1 GiB** rather than the PRD's 1.5–2 GiB
(disk headroom was 14 GiB). Generation timings include the file write.

```
build/bench/synth_pcap -o datasets/d1.pcap --profile d1 --size 1G
build/bench/synth_pcap -o datasets/d2.pcap --profile d2 --size 1G
build/bench/synth_pcap -o datasets/d3.pcap --profile d3 --size 1G
```

| Set | Bytes | Packets | Flows | Realized mix (from the generator's own summary line) | Gen time / rate |
|---|---|---|---|---|---|
| D1 | 1,073,741,935 | 3,079,551 | 284,140 | all TCP; 1,125,240 data segments | 0.92 s / 1107 MiB/s |
| D2 | 1,073,741,940 | 1,029,498 | 16 | reorder 0.51 %, loss 0.10 % of 687,008 data segments | 0.50 s / 2060 MiB/s |
| D3 | 1,073,742,860 | 2,042,090 | 45,468 | TCP 79.6 % / UDP 20.4 %, IPv6 10.1 %, VLAN 10.0 % (of packets); reorder 4.95 %, loss 1.00 %, retransmit 0.94 % (of 953,227 data segments); malformed 0.098 % | 1.06 s / 969 MiB/s |

SHA-256 prefixes: d1 `8c2e8eb33bb2224c`, d2 `2456032ad1c396ed`, d3 `87ca70989856273d`.
Differences from the PRD: D1 has 284k flows (1 GiB at ~3.7 KB/flow), not 1 Mi; sizes are 1 GiB.
Frame sizes in D3 are trimodal 64/576/1500 for data segments and datagrams; pure ACKs are 54 B
(not padded). R1 (real capture) is not done.

### synth_pcap checks (the bench preset builds no tests)

- Determinism: two runs of `synth_pcap -o a.pcap --profile d3 --size 50M` → `cmp` identical; `--seed 2` differs.
- `netprobe analyze` on `--profile d2 --size 20M --flows 4 --loss 0 --reorder 0`: 4 flows, all
  `handshake_full`, `gap_count 0`, `out_of_order_segments 0`, `retransmitted_segments 0`, 19,564,000 bytes delivered.
- Same with `--loss 2`: `gap_count 245`, `gap_bytes == acked_gap_bytes == 367,920`, 4/4 flows with gaps
  (loss is a capture drop that later ACKs cover).
- D3, 50 MiB: `conflicting_overlap_bytes 0` (retransmissions carry identical bytes), 107 decode errors in 99,700
  records (0.107 %, target 0.1 % malformed), spread over ipv4/ipv6 short_header, bad_ihl, bad_total_length,
  bad_version, tcp_data_offset, udp_length.

## 2. Micro-benchmarks

Decode and analyzer rows are from the first full run (`measure.sh`, load 12–15). Flow and reassembly
rows are from a re-run of those suites at load ≈ 6–7 (the first run had CV up to 59 % on them).
CV > 5 % is flagged.

| Benchmark | Median | CV |
|---|---|---|
| BM_Decode/d3 (all D3 records) | 55.4 M pkt/s, 26.1 GiB/s | 2.9 % |
| BM_Decode/tcp_v4 | 61.8 M pkt/s, 24.5 GiB/s | 0.9 % |
| BM_Decode/udp_v4 | 67.6 M pkt/s, 47.0 GiB/s | 0.8 % |
| BM_Decode/tcp_v6 | 51.2 M pkt/s, 21.1 GiB/s | 2.4 % |
| BM_Decode/vlan | 52.4 M pkt/s, 24.0 GiB/s | 3.1 % |
| BM_FlowLookup/1Ki | 32.4 M lookups/s | 0.3 % |
| BM_FlowLookup/64Ki | 18.6 M lookups/s | 3.5 % |
| BM_FlowLookup/1Mi | 4.45 M lookups/s | 1.2 % |
| BM_Reassembly_InOrder | 301 GiB/s (221 M seg/s) | **12.7 %** |
| BM_Reassembly_Reorder/1 | 167.7 GiB/s | 4.4 % |
| BM_Reassembly_Reorder/10 | 38.9 GiB/s | 0.6 % |
| BM_Reassembly_Reorder/30 | 20.7 GiB/s | 2.4 % |
| BM_Reassembly_Retransmit/1 | 301.5 GiB/s | 0.4 % |
| BM_Reassembly_Retransmit/10 | 253.6 GiB/s | 1.2 % |
| BM_Analyzer (decode + ReaderStats + Analyzer + finish, 32 MiB D3 slice) | 9.13 M pkt/s, 4.31 GiB/s | 0.6 % |

Caveats:
- Reassembly uses a `NullSink`; in-order segments are delivered without a copy, so "GiB/s" is
  ~4.5 ns of bookkeeping per 1460 B segment. Reordered segments are copied into the buffer (10 % → 38.9 GiB/s).
  Retransmit GiB/s counts unique payload bytes only.
- `BM_FlowLookup` maps to an 8-byte value; the analyzer's real `Flow` node is far larger, so its
  cache behaviour is worse (the 4.45 M/s at 1 Mi live flows is a ceiling for the table alone).
- The 32 MiB slice is a prefix of D3 (flow-table ramp-up), and exceeds the 4 MiB L2 per core.

## 3. End-to-end (`--workers 0`, page cache warm, disk I/O excluded)

Final runs, load average ≈ 5.6–5.9 (command above, 9 runs):

| Set | elapsed ms | Mpkt/s | MiB/s | peak RSS MiB |
|---|---|---|---|---|
| D1 | 692.2 (675.7–740.5) | 4.449 (4.159–4.558) | 1412 (1319–1446) | 1195 |
| D2 | 286.1 (276.4–302.3) | 3.598 (3.406–3.725) | 3524 (3336–3649) | 1071 |
| D3 | 423.4 (379.9–504.0) | 4.823 (4.052–5.376) | 2345 (1970–2614) | 1230 |

Earlier runs of the same commands at load 12–15 were slower and far noisier (medians D1 1226 ms,
D2 338 ms, D3 502 ms; max up to 1.6 s on D3 and 0.73 s on D2). Treat the table above as the
less-contended number and expect ±10–20 % on this machine. Peak RSS is about the file size because
the capture is `mmap`ed and nothing is released yet (M10).

## 4. Profile (D3, `--workers 0`)

Xcode is not installed, so `xctrace` is unavailable. Six runs of
`build/bench/netprobe analyze --quiet --json <f> datasets/d3.pcap`, each sampled with
`sample netprobe 3 1 -wait -mayDie` (1 ms), top-of-stack counts summed (1,461 samples; runs took 415–697 ms).
A first attempt on a 3 GiB D3 file took 10.5 s (page cache not warm under memory pressure) and was discarded.

| Share | Function |
|---|---|
| 19.8 % | `PcapReader::next_impl` (first touch of mmapped capture memory) |
| 9.4 % | `StreamReassembler::on_segment` |
| 9.4 % | `decode_packet` (+ `parse_ipv4` 4.9, `parse_tcp` 4.2, `parse_ethernet` 2.3 → ≈ 21 % decode in total) |
| 8.1 % | `make_flow_key` |
| 7.7 % | `ReaderStats::add` |
| 5.5 % | `_platform_memmove` (out-of-order segment copies) |
| 5.3 % / 5.1 % | `Analyzer::process` / `Analyzer::update` |
| 4.5 % | `free` (`_xzm_free_tc`) |
| 3.3 % | flow table `find` |
| 2.6 % | `std::map` node removal (reassembler out-of-order buffer) |

The profile is flat: no function above 20 %, and the largest entry is the reader's memory traffic.
Reassembly-related entries (`on_segment`, memmove, tree, free) add up to ≈ 22 %. The micro-benchmark
analyzer rate (9.1 M pkt/s) is about twice the end-to-end rate (4.8 M pkt/s); the difference is the
reader/page-fault cost, `--json` report building and process start/exit, not measured separately.

## 5. Comparison with PRD 13 targets

Targets assume x86-64 Linux with ≥ 8 cores; this is an M3 Pro on macOS with a noisy machine and 1 GiB datasets.

| ID | Target | Measured | Status |
|---|---|---|---|
| PERF-1 | decode D3 ≥ 15 M pkt/s | 55.4 M pkt/s (BM_Decode/d3) | met on this machine |
| PERF-2 | in-order reassembly ≥ 8 GiB/s | 301 GiB/s (NullSink, no copy, CV 12.7 %) | met, caveat above |
| PERF-3 | 10 % reorder ≥ 1.5 GiB/s | 38.9 GiB/s | met |
| PERF-4 | e2e D3 w0 ≥ 2.5 Mpkt/s and ≥ 1.5 GiB/s | 4.82 Mpkt/s, 2345 MiB/s = 2.29 GiB/s | met on this machine (1 GiB set) |
| PERF-5 | e2e D1 w0 ≥ 1.5 Mpkt/s | 4.45 Mpkt/s (284k flows, not 1 Mi) | met on this machine |
| PERF-6 | D3 w4 / w0 ≥ 2.0× | – | not measured (pipeline not landed) |
| PERF-7 | w1 ≤ 20 % slower than w0 | – | not measured |
| PERF-M1 | D2 peak RSS ≤ 128 MiB | 1071 MiB (1 GiB file, whole file resident) | **not met**, expected until the M10 release frontier |
| PERF-M2 | ≤ 512 B per idle flow | – | not measured (D1 `peak_flows` was 189,491; RSS is dominated by the mapped file, so Δ RSS cannot isolate it yet) |
| PERF-M3 | budget never > limit + one segment | – | tests, not benchmarks |

## 6. Observations for the orchestrator

- **`bench` preset is `-O3`, not `-O2`**: no `CMAKE_CXX_FLAGS_RELEASE` override exists, so CMake's default applies. Numbers here are `-O3`.
- **Google Benchmark v1.9.1 does not compile with LLVM 23** under its own `-pedantic-errors`
  (`__COUNTER__` flagged by `-Wc2y-extensions`). Build used `-DCMAKE_CXX_FLAGS=-Wno-c2y-extensions` at configure time
  (not in any preset), and the four `bench/*.cpp` files carry a clang-only pragma for the same warning.
  A permanent fix belongs in `CMakeLists.txt`/presets (not my files).
- **D2 buffers heavily after a loss**: `netprobe analyze` on D2 reports 496,240 out-of-order segments (of 687,008 data
  segments) with only 0.1 % loss, `peak_buffered_bytes` 40.6 MB, `forced_flushes` 173. Gaps covered by later ACKs are
  apparently not released until the per-direction buffer limit or flush. Not investigated; relevant to PERF-M1 and reassembly cost.

## 7. Optimizations

None attempted. The profile is flat, the largest entry (reader) is outside the permitted files, and PERF-1..5 are met
here, so there was no hotspot in `src/decode`, `src/flow`, `src/tcp/reassembler.cpp` or `src/analysis/analyzer.cpp`
with enough share to justify a change. No source under `src/` was modified, so there are no rejected attempts either.

## 8. Pending

- Multi-worker scaling (PERF-6, PERF-7, workers 1/2/4/8) and the Amdahl estimate (reader busy fraction): `bench/run_e2e.sh <bin> <pcap> 0 1 2 4 8` once the pipeline lands.
- Linux x86-64 numbers on the reference machine class, with `taskset` pinning, `perf stat` (IPC, cache misses) and a `perf record` flame graph.
- 2 GiB D2/D3 and the full 1 Mi-flow D1; R1 real capture (`bench/fetch_r1.sh` is not part of this task).
- PERF-M1/M2 after the memory release frontier; cold-cache runs; `-march=native`/LTO variants (would be labeled separately).
- A quiet-machine re-run of everything: this session shared the CPU with a VM workload.
