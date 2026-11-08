# NetProbe

NetProbe is an offline analyzer for classic PCAP files, written in C++20. It memory-maps a
capture, decodes Ethernet, VLAN, IPv4, IPv6, TCP and UDP, tracks flows, reassembles TCP byte
streams, and reports exactly which bytes are missing. Output is a text summary, deterministic
JSON, and a self-contained HTML report.

## What it is not

- Not a live capture tool: no libpcap, no BPF filters.
- No pcapng (it detects pcapng and suggests `editcap -F pcap in.pcapng out.pcap`).
- No IP fragment reassembly (fragments are counted).
- No application-layer dissectors (HTTP, DNS, TLS, QUIC). Service names are a port-based heuristic.
- No TCP/UDP checksum verification.
- No stdin or pipe input; the input must be a regular file.
- No interactive UI or web server. Not for Windows or 32-bit targets.
- Ethernet link type only.

## Features

- Zero-copy PCAP reader over `mmap` (four magics: micro/nanosecond, either byte order).
- Bounds-checked decoding with no `reinterpret_cast`; malformed packets are counted by layer and reason.
- Canonical bidirectional flow table with LRU expiry, port-reuse detection and flow-count eviction.
- TCP reassembly: 64-bit offsets (wraparound-safe), first-wins overlap with conflict detection,
  zero-copy in-order delivery, lazy gap declaration, bounded memory.
- Optional sharded pipeline (`--workers N`) with SPSC rings; reports are byte-identical for any N
  when no memory limit is hit.
- `dump` subcommand: one TSV line per packet, used for differential testing against `tshark`.
- Stream export: one file per direction per TCP flow.

## Quickstart

Linux needs GCC 13+ or Clang 17+, CMake 3.25+ and Ninja. macOS needs Homebrew LLVM (see below).

```bash
export CXX=/opt/homebrew/opt/llvm/bin/clang++     # macOS only; omit on Linux
cmake --preset release && cmake --build --preset release --target netprobe
build/release/netprobe analyze samples/mixed_traffic.pcap --json out.json --html out.html
```

One-command demo (builds, analyzes the three sample captures, writes JSON, HTML and exported
streams to `out/demo/`):

```bash
scripts/demo.sh
```

## Usage

```
netprobe analyze <capture.pcap> [options]
netprobe dump <capture.pcap> [--limit N]
netprobe --help | --version
```

| Option | Meaning |
|---|---|
| `-o, --json <path>` | JSON report; `-` writes to stdout and implies `--quiet` |
| `--html <path>` | standalone HTML report |
| `--export-streams <dir>` | write reassembled TCP streams |
| `-q, --quiet` | suppress the text summary |
| `--deterministic` | omit the `run` section (timings, host, RSS) and `options.workers` |
| `-j, --workers <N>` | 0 = single-threaded (default); N >= 1 = reader plus N shards (max 256) |
| `--idle-timeout <sec>` | open-flow idle timeout in capture time (default 300) |
| `--max-flows <N>` | max concurrent flows (default 1,000,000) |
| `--max-stream-buffer <size>` | out-of-order buffer per TCP direction (default 4M) |
| `--max-reassembly-memory <size>` | total out-of-order budget (default 512M) |
| `--top-flows <N>` | detailed flow records per list (default 1000, max 100,000) |

Sizes accept `K`, `M`, `G` suffixes (powers of 1024). Out-of-range values are a usage error.

| Exit code | Meaning |
|---|---|
| 0 | success, capture complete |
| 1 | usage error |
| 2 | fatal input error (cannot open, not classic PCAP, unsupported link type); no report |
| 3 | report produced, but the capture is truncated or corrupt |
| 4 | output or internal error |

## Platform and toolchain

- **Linux** is the primary target. CI builds with GCC 13 and Clang 18 on Ubuntu 24.04.
- **macOS** builds and tests pass, but only with Homebrew LLVM (`brew install llvm`): Apple Clang 15
  lacks `std::format`, its ASan aborts at start-up on the development machine, and it has no
  libFuzzer. Set `CXX=/opt/homebrew/opt/llvm/bin/clang++`; CMake links LLVM's libc++ automatically.
  `scripts/demo.sh` picks this compiler itself when `CXX` is unset.
- On macOS with Homebrew LLVM 23.1.5, the `dev`, `release`, `tsan` and `fuzz` presets work (the
  fuzz build adds `-Wl,-ld_classic` there). The `asan` preset builds but tests that throw abort
  (`MappedFile.MissingFileThrowsInputErrorNamingPath`, `MappedFile.NonRegularFileRejected`,
  `Pipeline.WorkerExceptionPropagatesWithoutHanging`): Homebrew's libc++abi and ASan's
  `__cxa_throw` interposition disagree. Run `asan` on Linux (CI does).
- On macOS, `MADV_DONTNEED` did not bound resident memory in the author's check, so the memory
  release frontier is effective on Linux only. See `docs/design.md`.
- Linux runs from a macOS host: `tools/docker/Dockerfile` builds the Ubuntu 24.04 image used for
  sanitizers, fuzzing, the tshark differential and benchmarks
  (`docker build -t netprobe-dev:24.04 tools/docker`, then
  `docker run --rm -v "$PWD":/src -w /src netprobe-dev:24.04 bench/run_linux_container.sh`).

## Repository layout

| Path | Contents |
|---|---|
| `src/` | `io/` mmap, `pcap/` reader, `decode/`, `flow/`, `tcp/` (sequence math, reassembler), `analysis/` (analyzer, stats, memory budget), `pipeline/`, `report/`, `app.cpp`, `cli.cpp` |
| `tests/` | `unit/` (GoogleTest), `integration/` (Python, run by CTest), `fixtures/` + `golden/`, `fuzz/`, `reference/` (independent reassembly model), `differential/` (`tshark`), `support/` |
| `bench/`, `tools/` | Google Benchmark suites, `run_e2e.sh`, `synth_pcap` dataset generator (`bench` preset) |
| `samples/` | three small synthetic captures used by the demo |
| `scripts/demo.sh` | one-command demo |
| `docs/` | `PRD.md`, `design.md`, `results.md` |
| `DESIGN.md` | visual design system of the HTML report |

Source files are globbed; adding one needs no CMake edit, only a re-run of the configure step.

## Testing

```bash
cmake --preset dev && cmake --build --preset dev && ctest --preset dev      # debug, hardened
cmake --preset asan && cmake --build --preset asan && ctest --preset asan   # ASan + UBSan
cmake --preset tsan && cmake --build --preset tsan && ctest --preset tsan   # ThreadSanitizer
cmake --preset fuzz && cmake --build --preset fuzz                          # build/fuzz/fuzz_*
```

Use a separate `build/<preset>` per configuration. Unit tests need network access on first
configure to fetch GoogleTest (pinned). Fuzz targets need a Clang with libFuzzer.
Verification strategy (four oracles, fuzzing, sanitizers, CI) is in `docs/design.md`.

## Results summary

Quoted from [`docs/results.md`](docs/results.md): single-threaded baseline, Apple M3 Pro, macOS,
`-O3`, page cache warm, 1 GiB synthetic datasets, a loaded machine (expect +/-10-20 %). Targets
assume x86-64 Linux with 8+ cores. Multi-worker scaling, Linux numbers and real-capture results
are not measured yet, and the results predate the `-O2` change, the ACKed-hole release and the
memory release frontier.

| Measure | Result |
|---|---|
| Decode only, D3 mix (BM_Decode/d3) | 55.4 M pkt/s (PRD target 15 M) |
| In-order reassembly, NullSink | 301 GiB/s (CV 12.7 %; PRD target 8 GiB/s) |
| Reassembly, 10 % reorder | 38.9 GiB/s (PRD target 1.5 GiB/s) |
| End-to-end D3, `--workers 0` | 4.823 Mpkt/s, 2345 MiB/s (median of 9) |
| End-to-end D1, `--workers 0` | 4.449 Mpkt/s, 1412 MiB/s |
| Peak RSS, D2 (1 GiB file) | 1071 MiB; PRD target 128 MiB **not met** at that baseline |
| Worker scaling (PERF-6, PERF-7) | not measured |

## Documentation

- [`docs/PRD.md`](docs/PRD.md): requirements, decision log, acceptance criteria.
- [`docs/design.md`](docs/design.md): architecture as built, invariants, reassembly, concurrency.
- [`docs/results.md`](docs/results.md): benchmark methodology and numbers.
- [`DESIGN.md`](DESIGN.md): HTML report visual design.
