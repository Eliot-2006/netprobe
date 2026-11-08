# NetProbe design

This document describes NetProbe as built. `docs/PRD.md` holds the requirements and the decision
log (D1 to D18); this file records what the code does, why, and where it deviates from the PRD.
Performance numbers appear only as quotations from `docs/results.md`; anything not measured is
marked unmeasured. File and function names refer to the repository at the time of writing.

## 1. Overview and data flow

NetProbe is an offline analyzer for classic PCAP files. It memory-maps the capture, decodes each
Ethernet frame, groups TCP/UDP packets into bidirectional flows, reassembles TCP byte streams with
exact accounting of missing bytes, and emits a text summary, deterministic JSON and a standalone
HTML report.

```
 capture.pcap
     |  mmap (read-only)
     v
 MappedFile --> PcapReader --> decode_packet --> ReaderStats          (main thread)
 (owns bytes)   (record =       (DecodedPacket:   (decode counters,
                 span view)      fields + payload  timeline)
                                 span, no alloc)
                                      |
             --workers 0              |             --workers N >= 1
        +-----------------------------+------------------------------+
        v                                                            v
  Analyzer (inline)                            hash(FlowKey) -> shard_of(hash, N)
                                               fill Batch (256 PacketDesc) for that shard
                                                             |
                                    work ring (SPSC, 8 slots)|   free ring (SPSC, 8 slots)
                                              +--------------+--------------+
                                              v              v              v
                                          worker 0       worker 1  ...  worker N-1
                                          Analyzer       Analyzer       Analyzer
                                              |  empty Batch* returned on the free ring
                                              v
                                         ShardResult x N
        +-----------------------------+------------------------------+
                                      v
                  ShardResult::merge + ReaderStats --> Report
                                      |
                       text summary / JsonReport / HtmlReport
```

`--workers 0` (default) runs one `Analyzer` on the calling thread and is the reference
implementation. `--workers N` adds N worker threads, each with its own `Analyzer`; the main thread
stays the single reader and dispatcher. Exit codes: 0 ok, 1 usage, 2 fatal input error, 3 report
produced but the capture is truncated or corrupt, 4 output or internal error (`src/app.h`).

## 2. Components

| Component | Source | Responsibility |
|---|---|---|
| `MappedFile` | `io/mapped_file.*` | RAII `mmap` (`PROT_READ`, `MAP_PRIVATE`, `MADV_SEQUENTIAL`). Empty file is valid. `release_before(offset)` implements the release frontier. Throws `InputError` (exit 2). |
| `PcapReader` | `pcap/reader.*` | Validates the 24-byte header (four magics, pcapng detection, version 2.x, Ethernet only), then iterates records as `PacketRecord` views. Never allocates in `next()`. Records anomaly counters. |
| `decode_packet` | `decode/*` | Stateless layered decode (Ethernet, up to 2 VLAN tags, IPv4, IPv6 with extension headers, TCP, UDP) into a `DecodedPacket`. |
| `ReaderStats` | `analysis/reader_stats.*` | Packet-level counters by layer, reason, protocol and VLAN, plus the adaptive 256-bucket timeline. Runs on the reader thread only. |
| `FlowKey`, `make_flow_key` | `flow/flow_key.*` | Canonical bidirectional key, direction, hash, `shard_of`. |
| `SeqUnwrapper` | `tcp/seq.h` | 32-bit sequence number to 64-bit stream offset. |
| `StreamReassembler` | `tcp/reassembler.*` | One TCP direction: in-order delivery, out-of-order buffer, overlap and conflict accounting, gap declaration. |
| `MemoryBudget` | `analysis/memory_budget.h` | Per-shard byte accounting for out-of-order storage. |
| `Analyzer` | `analysis/analyzer.*` | One shard: flow table, TCP handshake and close tracking, orientation, expiry, eviction, summaries. No globals. |
| `ShardResult` | `analysis/shard_result.*` | Exact aggregates, bounded top-K lists, talkers, services; `merge()` combines shards. |
| `run_pipeline` | `pipeline/pipeline.*`, `spsc_ring.h` | Threads, batches, rings, backpressure, failure propagation, release-frontier driver. |
| Reports | `report/*` | `JsonWriter`, `render_json`, `render_html`, `render_text_summary`, `FileExportSink`. |
| `app.cpp`, `cli.cpp` | | `analyze` and `dump` commands, option parsing and validation, atomic file writes, exit codes. |

## 3. Buffer ownership and invariants

The mapping owns every frame byte for the whole run. `PacketRecord::data` and
`DecodedPacket::payload` are `std::span<const std::byte>` views into it. The only bytes NetProbe
copies are out-of-order TCP segments, which live in `std::vector<std::byte>` inside a
`StreamReassembler` and are charged to a `MemoryBudget`.

**O1: no component retains a view into the mapping after the call that produced it returns.**
`StreamSink::on_data` receives a view that is valid only during the call (`tcp/stream_sink.h`);
`StreamReassembler::on_segment` borrows `captured` only for the call; batches are recycled as soon
as a worker finishes with them. O1 is what makes batch recycling and page release safe.

**O2: every byte of out-of-order storage is charged to exactly one `MemoryBudget` and refunded
exactly once.** `StreamReassembler::check_invariants()` verifies that `buffered_accounted_` equals
the sum of `payload + 64` over the map, that intervals are disjoint and past `delivered_`, that the
per-stream limit holds, and that the `complete()` flag matches its definition. The reassembler
refunds on destruction, on `init()` and on every erase, and `MemoryBudget::refund` asserts it never
goes negative.

### How the release frontier enforces O1

`MappedFile::release_before(offset)` rounds `offset` down to a page boundary and releases
everything before it:

- Release builds: `madvise(MADV_DONTNEED)`.
- Builds with `NETPROBE_DEBUG_GUARDS` (defined by `NETPROBE_HARDENING`, so the `dev`, `asan` and
  `fuzz` presets): `mprotect(PROT_NONE)` on the same range. A retained span into released bytes
  then faults on first access instead of silently reading stale data.

Single-threaded mode releases once at least 64 MiB has been consumed since the last release
(`run_analyze`). The pipeline calls `release()` every 64 submitted batches and once more after the
join. The pipeline frontier is the minimum of: the reader position, each worker's
`completed_offset` while that worker still has submitted-but-unfinished batches, and the file offset
of the first packet in any partially filled batch. A worker publishes `completed_offset`
(release store) only after `process()` has returned for the whole batch, which is exactly the O1
boundary. Tests: `Pipeline.ReleaseFrontierRoundsDownAndGuardsCompletedPages` and the determinism
test, which uses a capture larger than 64 MiB so both frontiers run.

Caveat from commit `1e8776d`: on macOS `MADV_DONTNEED` did not bound RSS in the author's check, so
the bounded-memory property is a Linux property. The memory figures that commit reports are not in
`docs/results.md` and are not reproduced here. PERF-M1 and PERF-M2 are recorded in
`docs/results.md` as not met and not measured respectively, against the pre-frontier baseline.

## 4. Decoding strategy

- **Bounds first, then load.** Every layer checks the remaining length before reading, then uses
  `load_be16/32` and `load_le*` from `util/bytes.h`, which assemble values with shifts. There is no
  `reinterpret_cast` of packet bytes anywhere (PRD D2, AGENTS.md rule); this removes alignment and
  strict-aliasing undefined behavior and compiles to a load plus byte swap.
- **Errors are values.** `DecodeStatus {kind, layer, reason}`, where kind is
  `ok | truncated | malformed | unsupported`. There are no exceptions, logging or heap allocation on
  the decode path; a unit test counts allocations around the reader. Malformed packets are counted
  by `(kind, layer, reason)` in `ReaderStats` and never abort.
- **Snaplen is not malformed.** IP total length greater than captured bytes sets `l3_truncated`
  and keeps the captured prefix as `payload`; `payload_logical_len` keeps the on-wire length so the
  reassembler can account for `snaplen_missing_bytes`.
- **Specifics.** VLAN TPIDs `0x8100`, `0x88A8`, `0x9100`, at most two tags (`vlan_depth`); EtherType
  below `0x0600` is `llc`. IPv4 validates version, IHL, total length; the header checksum is
  computed and recorded (`ipv4_checksum_ok`) but not used to reject. A zero IP length (TSO) uses
  the captured length. Fragments are flagged `is_fragment` and counted, not reassembled. IPv6 walks
  hop-by-hop, routing and destination-options headers (at most 8, `ipv6_ext_chain`), stops at the
  fragment header, rejects AH/ESP/Mobility/HIP/Shim6 (`ipv6_ext`) and jumbograms (`ipv6_jumbo`). TCP
  validates data offset; option-walk violations set `tcp_options_malformed` but the segment is
  still processed. UDP validates length.
- **Link types.** Only `LINKTYPE_ETHERNET` is accepted; other link types fail at open (exit 2).
- **Reader error model.** `max_record_len` is 262144; a larger `incl_len` marks the capture
  `corrupt` (PCAP cannot resynchronize). A short tail is `truncated`. Both end iteration, the report
  covers the processed prefix, and the exit code is 3.

## 5. Flow tracking

**Canonical key.** `FlowKey {ip_version, proto, lo, hi}` where `lo <= hi` by `(address, port)`
ordering of the two endpoints; `Direction` records whether the packet's source is `lo`. Both
directions of a connection therefore map to one key. IPv4 addresses are stored IPv4-mapped so the
layout is uniform. VLAN IDs are not part of the key (PRD D17), so identical 5-tuples in different
VLANs merge. The hash is a splitmix64-based mix of the fields (not raw memory, so padding is
irrelevant). The shard is `((hash >> 32) * N) >> 32`, using high bits so shard choice is
independent of the unordered_map's bucket bits.

**Flow ID.** The 0-based record index of the flow's first packet. It is unique without
coordination between shards and does not depend on worker count.

**Orientation.** The client is the sender of the first SYN. If the first packet seen is a SYN-ACK,
the receiver is the client. Otherwise the first packet's sender is assumed to be the client and the
report marks the orientation as guessed (`orientation_handshake` false). Handshake class is `full`
(client SYN, SYN-ACK, then a client ACK), `partial`, or `none`. Packets with invalid flag
combinations (`tcp_flags_invalid`) update packet and byte counters but are not fed to TCP state
or reassembly.

**Port reuse.** A flow that is already closing (both FINs, or RST) and receives a pure SYN whose
ISN differs from the one recorded for that direction, or a SYN in a direction that has not sent
one, is finalized with reason `reused` and a new flow starts. A retransmitted SYN with the same ISN
does not split the flow. A packet arriving after the applicable timeout also splits the flow
(`idle_timeout`, or the natural close reason for a closing flow).

**Expiry.** Two intrusive doubly linked LRU lists per shard, `open_` and `closed_`, each ordered by
last activity. Open flows expire after `--idle-timeout` (default 300 s), closed flows after a fixed
10 s linger (PRD D18). Time is capture time: `now_` is the maximum timestamp seen by the shard. A
sweep runs every 1024 flow packets or when `now_` has advanced by 1 s since the last sweep, and pops
expired heads from the lists; each pop is O(1). The invariant that lists stay sorted relies on
non-decreasing timestamps; non-monotonic captures can expire flows in a different order than a
fully sorted capture would.

**Eviction.** When the shard is at `max_flows` (`--max-flows` divided by worker count), `create()`
calls `evict_one()`: the oldest closed flow if there is one (finalized with its natural close
reason), otherwise the oldest open flow with reason `evicted`. Either sets `limits_hit`; only the
open case increments `evicted_flows`.

**Finalization.** `finalize()` flushes both reassemblers (declaring remaining gaps), builds a
`FlowSummary`, classifies integrity (`complete`, `gaps`, `snaplen_truncated`, `open`), updates exact
counters, talkers and services, and offers the summary to two bounded heaps: top flows by bytes
and top incomplete TCP flows by missing bytes. Ordering is `(metric desc, flow id asc)`, a total
order, so merging per-shard heaps yields exactly the global top-K.

## 6. TCP reassembly

`StreamReassembler` handles one direction. The algorithm lives in `on_segment()`.

**64-bit offsets.** `SeqUnwrapper::to_offset(seq, reference)` computes a signed 32-bit difference
against `origin + reference` (well defined modular arithmetic in C++20) and adds it to the 64-bit
`reference`, which is the delivered offset. Deltas beyond +/-2^30 or below zero offset are rejected
and counted as `out_of_window_segments`. All later logic uses monotonic `uint64_t` offsets, so
wraparound exists in exactly one function. The origin is ISN+1 after a SYN, or the first observed
sequence number for mid-stream pickup.

**Out-of-order buffer.** `std::map<uint64_t, Segment>` keyed by start offset, holding disjoint
intervals, all beyond `delivered_`. `check_invariants()` asserts disjointness.

**First-wins overlap with conflict detection.** An incoming segment is trimmed against buffered
coverage; only uncovered pieces are inserted. For every byte overlapping a still-buffered earlier
copy, `overlap_bytes` is incremented and, if the bytes differ, `conflicting_overlap_bytes`. Bytes
that overlap already delivered data count toward `retransmitted_bytes`. Because delivered bytes are
no longer stored, conflicts against delivered data are not detectable; the counter is exact only
where the earlier copy is still buffered.

**Zero-copy in-order path.** If a segment starts at `delivered_` and nothing is buffered, the
captured span goes straight to `sink.on_data()`; nothing is copied or charged. Only out-of-order
pieces are copied into owned vectors. After any insert, `drain()` delivers every buffered interval
that now starts at `delivered_`.

**Lazy gaps.** A gap is declared only when (a) a forced flush happens, (b) a flow is finalized
(`flush()`), or (c) the ACKed-hole release below fires. Peer ACKs feed a watermark `max_acked_`
that only classifies a gap as `acked` (the receiver got bytes the capture missed); an ACK alone
never creates a gap, because multi-queue captures often record an ACK before the data it covers.
At flush the final gap extends to `max(max_acked_, highest_end_)`, bounded by the FIN offset.
Gaps are recorded individually up to 16 per stream (`gaps_truncated` beyond that); counts and byte
totals stay exact.

**ACKed-hole release (D7 revision).** The original rule held data behind a hole until the buffer
limit forced a flush. `results.md` section 6 records the symptom on D2 at baseline (`f171118`):
496,240 out-of-order segments at 0.1 % loss, `peak_buffered_bytes` 40.6 MB, `forced_flushes` 173.
Commit `609e42d` added `release_acked_holes()`: if the first hole is at or below `max_acked_`
(the receiver already has those bytes, so no retransmission is coming) and at least
`min(1 MiB, max_stream_buffer / 2)` of later data is buffered behind it, the hole is declared as an
`acked` gap and the buffer drains. Unacked holes and small ACKed holes stay lazy. The before/after
measurement for this change is in the PRD D7 text and the commit message; `docs/results.md` has not
been re-run since, so the post-revision D2 figures are unmeasured there.

**Memory accounting and forced flush.** Each buffered piece costs `payload + 64` bytes
(`kSegmentOverhead`, an estimate of map-node and allocation overhead), which makes many tiny
segments expensive. Before inserting, the reassembler checks both the per-stream limit
(`--max-stream-buffer`, default 4 MiB) and `MemoryBudget::can_charge` (the shard's share of
`--max-reassembly-memory`, default 512 MiB split evenly across shards). A refused charge is a
`forced_flush`: `flush_with_incoming()` merges the incoming bytes with buffered intervals, delivers
data, declares the holes between them, and returns. Because the check precedes the charge, the
implementation never exceeds the limit, which is stricter than the PRD's "limit plus one segment".

**After FIN and RST.** `on_fin` records the stream end, discards buffered data past it, and later
data beyond it is trimmed and counted as `data_after_fin`. After a flow sees RST, further payload
is not reassembled and is counted as `data_after_rst`.

## 7. Concurrency

**Shard by flow.** The reader decodes, hashes the canonical key and appends a `PacketDesc`
(record, decoded packet, hash) to the target shard's current batch. Both directions of a flow hash
identically, each shard has exactly one producer, and rings are FIFO, so each flow's packets reach
its `Analyzer` in capture order with no locks. Only TCP/UDP packets are dispatched; others are
counted by the reader and dropped.

**SPSC rings and batch recycling.** Each worker owns a `work` ring (reader to worker) and a `free`
ring (worker to reader), both `SpscRing<Batch*, 8>`: power-of-two capacity, free-running 32-bit
indices, head and tail on separate cache lines with cached copies of the other side's index so the
common path touches no shared line. There are exactly eight preallocated batches of 256 packets per
worker. The reader takes an empty batch from `free`; if none is available it waits. That wait is
the backpressure, and it bounds in-flight memory to `N x 8 x 256 x sizeof(PacketDesc)` with no
other queue limit to tune. `run.reader_stalls` and `reader_stall_ns` (non-deterministic section of
the JSON) count it.

**Wakeup protocol.** A waiter spins up to 64 iterations with `yield()`, then registers by
`exchange(1)` on a per-side waiting word, re-checks the ring and the failure flag, and only then
blocks in `atomic::wait(1)`. A pusher or popper calls `exchange(0)` on the opposite waiting word
and notifies only if it saw a registration, so no syscall is made when nobody waits. The
registration uses a read-modify-write rather than a store because plain release/acquire stores can
lose a wakeup (comment in `spsc_ring.h`). The spin uses `yield`, not a pause instruction as the
PRD sketched.

**Failure handling.** A worker exception is caught at batch level and stored as an
`exception_ptr`; a compare-exchange keeps the first one, and a shared `failed` flag is set
(release) followed by `wake_waiters()` on every ring. After failure workers stop processing but keep
popping and returning batches until they see the `nullptr` sentinel, so the reader can never block
on a full ring. Every wait loop checks `failed`. The reader also catches its own exceptions. After
the loop the pipeline pushes a sentinel to every started thread, joins, then rethrows the first
worker error, else the reader error; `main` maps any exception to exit 4. The `before_batch` test
hook injects deterministic worker failures (`Pipeline.WorkerExceptionPropagatesWithoutHanging`);
`SpscRing.FailureWakesEmptyConsumerAndFullProducer` covers cancellation.

**Per-shard limits.** `max_flows` and the reassembly budget are divided by the worker count, so
there is no shared atomic counter. This is also why hitting a limit makes results depend on N.

### Determinism argument

For a fixed input and options, the JSON report (without `run`) and the HTML report with
`--deterministic` are byte-identical across runs and across `--workers` values, provided:

1. No memory limit was hit: `forced_flushes == 0` and `evicted_flows == 0` (and no closed-flow
   eviction; `limits_hit` in the report covers all of these). Limits are per shard, so otherwise
   results legitimately depend on N.
2. Capture timestamps are non-decreasing. A shard's clock is the newest timestamp it has seen, which
   is not the global clock; for monotonic captures a flow expired at a sweep would also have been
   split by the lazy per-packet check, so sharded and inline runs split the same way. Non-monotonic
   captures can differ.

Why it holds: per-flow input order is the capture order (single producer, FIFO); per-flow results
depend only on that flow's packets; aggregates are sums or maps merged by key; top-K selection uses
the total order `(metric desc, flow id asc)`; talkers sort by `(total bytes desc, address)`; map
outputs are emitted in sorted key order; flow IDs do not depend on sharding. Two fields that do
depend on N are excluded from the deterministic contract: `options.workers` and
`peak_buffered_bytes` (a sum of per-shard peaks). Both appear only when `--deterministic` is not
given. `tests/integration/test_determinism.py` compares deterministic output at workers 0, 1, 2, 4
and 8 over all fixtures plus a generated capture larger than 64 MiB (200,000 records).

**Ceilings.** The reader is a serial fraction (sequential parse, decode and hash), and a single
flow cannot be split across shards. Multi-worker scaling (PERF-6, PERF-7) is **unmeasured** in
`docs/results.md`, which predates the pipeline.

## 8. Reporting

**JSON** (`schema_version` 1, `report/json_report.cpp`, written by the in-project `JsonWriter`).
Key order is fixed in code; map-like objects (reasons, protocols, EtherTypes, VLANs) are emitted
sorted with only non-zero entries; times are integer nanoseconds and sizes integer bytes. Top-level
sections: `tool`, `options`, `capture`, decode and anomaly counters, flow and reassembly
aggregates, top flows, top incomplete flows, `talkers`, `services`, and `run`. The `run` section
(elapsed time, throughput, peak RSS, peak flows, host, pipeline stall and per-worker statistics)
is omitted under `--deterministic`, as is `options.workers`. `-o -` writes to stdout and implies
`--quiet`. All files are written to a temporary name and renamed, so a failed run does not leave a
partial report. Golden files in `tests/golden/` pin the deterministic output per fixture.

**HTML** (`report/html_report.cpp`). One file with inline CSS and SVG, no JavaScript and no
external requests; fonts are an embedded Barlow Condensed subset as a `data:` URI, with local
fallbacks. Sections follow PRD 8.2: findings, traffic timeline, protocols, decode errors, flow
outcomes, incomplete TCP streams drawn to scale with ACKed gaps hatched, top flows, talkers and
services, reassembly and run details. All text is escaped; light and dark schemes follow
`prefers-color-scheme`; layout is checked at 390 px width. `test_html.py` checks escaping of hostile
file names, absence of external references and a size cap. The visual rationale, palette and
component rules are in the root `DESIGN.md`.

## 9. Verification strategy

Four independent oracles (PRD 11.1), so no component is tested only against itself:

1. **Construction-time ground truth.** `tests/fixtures/gen_fixtures.py` (Scapy) writes 21 fixture
   captures with `.truth.json` files recording expected stream SHA-256, gaps and counters.
   `test_fixture_truth.py` runs the CLI with `--export-streams` and compares, without consulting
   golden files.
2. **Reference model.** `tests/reference/naive_reassembler.*` is a byte-coverage model that
   includes nothing from `src/tcp`. `test_reassembler_property.cpp` generates random segment
   schedules (duplicates, overlaps, reorder, wraparound origins) and compares bytes, gaps and
   counters; default 10,000 cases, `NETPROBE_PROPERTY_CASES` raises it. The PRD's 10^6-case release
   run has not been recorded in this repository.
3. **`tshark`.** `tests/differential/compare_tshark.py` compares `netprobe dump` against
   `tshark -T fields` per packet, conversations, and followed stream bytes, with documented
   exclusions (fragments, streams with gaps or conflicts, data after RST, malformed packets).
   It needs `tshark` installed and runs in CI; it is not part of `ctest`.
4. **Cross-configuration determinism.** Section 7.

Other layers: `tests/unit/` (GoogleTest) covers bytes, reader (including truncation sweeps and an
allocation counter, skipped under TSan because its runtime owns `operator new`), one case per
decode reason, flow key and shard balance, sequence arithmetic, reassembler, analyzer (expiry,
linger, port reuse, eviction, a 100k-SYN flood, budget bounds), JSON writer, CLI parser, SPSC ring
and pipeline. Three libFuzzer targets (`fuzz_decode`, `fuzz_pcap`, `fuzz_reassembly`) have seed
corpora and a dictionary; CI runs each for 60 s. The PRD asks for 30 minutes per target and
recorded stats; those runs are not recorded in `docs/results.md`.

Sanitizers: the `asan` preset is ASan + UBSan with `-fno-sanitize-recover=all`, the `tsan` preset
runs the same suite under ThreadSanitizer, and `dev` enables standard-library hardening plus the
`PROT_NONE` guard. Warnings are errors (`-Wconversion -Wsign-conversion -Wshadow -Wold-style-cast`
and others).

CI (`.github/workflows/ci.yml`): GCC 13 release and dev, Clang 18 release, ASan/UBSan and TSan on
Ubuntu 24.04; a fuzz smoke job; the `tshark` differential job; clang-format 18; and a macOS dev
build and test run. CI does not gate on performance.

## 10. Decisions that changed during implementation

- **D7, lazy gaps (commit `609e42d`).** Baseline measurement showed heavy buffering after a loss,
  so the reassembler now declares an ACKed hole once enough later data is buffered behind it.
  Gaps stay lazy otherwise. See section 6.
- **`-O2` for Release (commit `13313ad`).** CMake's default is `-O3`; `CMakeLists.txt` forces
  `-O2 -DNDEBUG` per PRD 12.2. `docs/results.md` numbers were taken at `-O3` before this change
  and are labeled so; they have not been re-run at `-O2`.
- **macOS toolchain (`b9d2740`, `ce5fecb`).** Apple Clang 15's libc++ has no `std::format`, its
  ASan aborts at start-up on the development macOS, and it has no libFuzzer. All presets use
  Homebrew LLVM there, and CMake links LLVM's libc++ and sets its rpath.
- **Deterministic JSON drops `options.workers` (`5363c29`).** The determinism contract must hold
  for any `-j`, and the option echoed the worker count. `peak_buffered_bytes` is likewise
  non-deterministic.
- **Allocator test and TSan (`5363c29`).** The reader's allocation-counting test replaces global
  `operator new/delete`, which the TSan runtime also owns, so it is skipped under TSan. An earlier
  partial replacement paired runtime `new` with `free` and was found by ASan on Linux (`f171118`).
- **Sanitizer-found fixes (`f171118`).** A signed overflow in the first sweep check, found by
  UBSan, is why `last_sweep_` starts at the first flow packet's time.
- **Fixture truncation model (`3df55d4`).** Ethernet minimum-frame padding had completed
  "truncated" headers; those frames are now unpadded with `orig_len > incl_len`, the way snaplen
  cuts occur.
- **Google Benchmark build.** v1.9.1 does not compile under Clang >= 22's `-Wc2y-extensions`
  with its own `-pedantic-errors`; the build now treats it as a SYSTEM dependency and adds
  `-Wno-c2y-extensions` where supported.

## 11. Known limitations

- Classic PCAP with Ethernet link type only. No pcapng, no raw-IP or Linux cooked captures.
- IP fragments are counted, not reassembled; fragmented flows carry no TCP/UDP detail.
- No checksum verification for TCP/UDP; the IPv4 header checksum is recorded only.
- No application-layer decoding. Service names are a port-based heuristic.
- Input must be a regular file (no stdin). Linux and macOS only.
- Conflicting-overlap detection only sees earlier copies that are still buffered.
- Orientation of flows without a SYN is a guess; midstream streams start at offset 0 at their
  first observed sequence number.
- VLAN IDs are not in the flow key.
- Timestamp-order assumptions: expiry and the determinism guarantee assume non-decreasing
  capture time.
- A single flow cannot be parallelized, and the reader thread is serial.
- Memory release: bounded RSS needs working `MADV_DONTNEED`; it did not bound RSS on macOS in the
  author's check. Per-flow memory (PERF-M2) is unmeasured, and the 2 GiB PERF-M1 gate has not been
  measured at all.
- Performance data in `docs/results.md` is single-threaded, macOS/arm64, `-O3`, on a loaded
  machine, 1 GiB datasets, no real-world capture (R1). Linux x86-64 numbers do not exist yet.
- Memory-limit behavior is deterministic per worker count but not across worker counts.

## 12. Open questions

- Should the PRD's `-O2` be re-measured? `results.md` was produced at `-O3`; the delta is unknown.
- Does the release frontier meet PERF-M1 on the reference Linux machine class at 2 GiB? Only the
  commit message of `1e8776d` reports a smaller 1 GiB Linux run.
- Should `ReaderStats` run on a separate thread? At the measured profile the reader is the largest
  single cost, but multi-worker scaling has not been measured, so there is no evidence either way.
