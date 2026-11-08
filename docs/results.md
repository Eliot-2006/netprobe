# NetProbe results

Every number below comes from a command recorded in this file or in `bench/run_linux_container.sh`.
Disk I/O is excluded everywhere (page cache warm). Section A is the current, final code on Linux;
section B is the earlier macOS single-threaded baseline (M8), kept for history.

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
| Caveats | arm64 under a VM, not the PRD's x86-64 reference machine; datasets 1 GiB, not 2 GiB; no real-world capture (R1); no core pinning. Nothing else ran during the measurement. |

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
- **Per-flow memory (PERF-M2):** D1 at 64 MiB vs 1 GiB with `--idle-timeout 86400` gives peak live
  flows 20,717 vs 189,491 and peak RSS 82.3 vs 209.7 MiB, so ≈ 790 B per live flow. This is an upper
  bound (it also includes per-address talker entries, which grow with flows here). The 512 B target
  is **not met**: two `StreamReassembler`s are 2 × 232 B on their own. Upgrade path: allocate
  reassembly state only for TCP flows and only after the first payload byte, and keep rarely
  non-zero counters out of line.
- **Reassembly buffering (D7 revision):** on a 200 MiB D2-profile capture, forced flushes went from
  29 to 0 and peak buffered bytes from 39.7 MB to 8.5 MB, with identical gaps (same file,
  before/after binaries; see commit `609e42d`).

### A.5 PRD 13 targets on this setup

| ID | Target | Measured (Linux container, A.2–A.4) | Status |
|---|---|---|---|
| PERF-1 | decode D3 ≥ 15 M pkt/s | 38.6 M pkt/s | met |
| PERF-2 | in-order reassembly ≥ 8 GiB/s | 331 GiB/s (NullSink) | met, bookkeeping rate |
| PERF-3 | 10 % reorder ≥ 1.5 GiB/s | 31.4 GiB/s | met |
| PERF-4 | e2e D3 w0 ≥ 2.5 Mpkt/s and ≥ 1.5 GiB/s | 3.73 Mpkt/s, 1.77 GiB/s | met |
| PERF-5 | e2e D1 w0 ≥ 1.5 Mpkt/s | 3.84 Mpkt/s (284k flows, not 1 Mi) | met |
| PERF-6 | D3 w4 / w0 ≥ 2.0× | 2.06× (7.69 / 3.73) | met, at the Amdahl ceiling |
| PERF-7 | w1 ≤ 20 % slower than w0 | 27 % faster on D3 | met |
| PERF-M1 | D2 peak RSS ≤ 128 MiB | 33–78 MiB (1 GiB file) | met at 1 GiB; 2 GiB not run |
| PERF-M2 | ≤ 512 B per idle flow | ≈ 790 B upper bound | **not met** (see A.4) |
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
