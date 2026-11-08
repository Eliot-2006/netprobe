# NetProbe: Product Requirements Document

| | |
|---|---|
| **Status** | Approved for implementation |
| **Version** | 1.0 |
| **Date** | 2026-11-07 |
| **Owner** | Eliot Boda |
| **Audience** | Autonomous coding agents and human reviewers implementing NetProbe |
| **Primary platform** | Linux x86-64 (Ubuntu 24.04). macOS is a supported build/test platform, not a benchmark platform. |

NetProbe is an offline network capture analyzer written in C++20. It reads classic PCAP files, decodes Ethernet/VLAN/IPv4/IPv6/TCP/UDP with bounds-checked zero-copy parsing, reconstructs TCP byte streams with explicit handling of reordering, retransmission, overlap, sequence wraparound and loss, and emits deterministic JSON and standalone HTML reports. It processes untrusted input and is built to be fuzzed, sanitized and benchmarked.

The document is normative. **MUST**, **SHOULD** and **MAY** follow RFC 2119 meaning. Requirement IDs (`FR-*`, `NFR-*`, `PERF-*`) are referenced by tests and milestone acceptance criteria.

---

## Table of contents

1. [Goals, non-goals, scope](#1-goals-non-goals-scope)
2. [Evaluation of the brief and key decisions](#2-evaluation-of-the-brief-and-key-decisions)
3. [Protocol support matrix](#3-protocol-support-matrix)
4. [Functional requirements](#4-functional-requirements)
5. [System architecture](#5-system-architecture)
6. [Component design](#6-component-design)
7. [CLI specification](#7-cli-specification)
8. [Report specification](#8-report-specification)
9. [Technology choices and dependencies](#9-technology-choices-and-dependencies)
10. [Repository layout and build](#10-repository-layout-and-build)
11. [Testing strategy](#11-testing-strategy)
12. [Benchmark methodology](#12-benchmark-methodology)
13. [Performance targets and acceptance criteria](#13-performance-targets-and-acceptance-criteria)
14. [Edge cases and failure handling](#14-edge-cases-and-failure-handling)
15. [Technical risks](#15-technical-risks)
16. [Milestones](#16-milestones)
17. [Definition of done](#17-definition-of-done)
18. [Rules for implementing agents](#18-rules-for-implementing-agents)
19. [Appendix A: What distinguishes this project](#appendix-a-what-distinguishes-this-project)
20. [Appendix B: Glossary](#appendix-b-glossary)

---

## 1. Goals, non-goals, scope

### 1.1 Goals

| ID | Goal | Measured by |
|---|---|---|
| G1 | Correctly decode the supported protocol matrix from untrusted capture files without undefined behavior. | Unit + truncation-sweep tests, per-packet differential against `tshark`, fuzzing with ASan/UBSan, zero findings. |
| G2 | Reconstruct TCP byte streams correctly under reordering, duplication, overlap, wraparound, loss, and snaplen truncation, and report exactly which bytes are missing. | Property tests against an independent reference model; generator ground truth; `tshark` stream differential. |
| G3 | Bounded memory regardless of input: per-stream, per-shard and flow-count limits that hold under adversarial captures. | Adversarial tests asserting accounted memory never exceeds limits; peak RSS measurements. |
| G4 | Measured, reproducible performance with honest methodology. | Google Benchmark suites + end-to-end harness; `docs/results.md` with hardware, compiler, datasets and spread. |
| G5 | Optional bounded parallel pipeline that preserves per-flow ordering and produces byte-identical reports for any worker count. | Determinism tests across `--workers 0,1,2,4,8`; TSan clean; scaling measurements. |
| G6 | Useful output: human summary on stdout, deterministic JSON, self-contained HTML. | Golden tests; HTML opens offline with no external requests. |
| G7 | One-command reproducible demo. | `scripts/demo.sh` succeeds on a clean Ubuntu 24.04 machine with the documented packages. |

### 1.2 Non-goals

These are out of scope for the whole project, not just the MVP. An agent MUST NOT implement them without an explicit change to this document.

- Live capture (libpcap, AF_PACKET, BPF filters).
- pcapng parsing. NetProbe detects pcapng and fails with a message that suggests `editcap -F pcap in.pcapng out.pcap`.
- IPv4/IPv6 fragment reassembly. Fragments are counted, not reassembled.
- Application-layer dissectors (HTTP, DNS, TLS, QUIC). The report may show a port-based service label, which is clearly marked as a heuristic.
- TCP/UDP checksum verification. Checksum offload makes these values unreliable in captures; Wireshark does not validate them by default either.
- Interactive UI, web server, JavaScript dashboards, charting libraries.
- Reading from stdin or pipes. Input MUST be a regular file that can be memory-mapped.
- 32-bit targets, Windows.
- SIGINT-graceful shutdown. Default signal behavior is acceptable.

### 1.3 Scope by priority

| Priority | Content |
|---|---|
| **P0 (MVP, correctness baseline)** | PCAP reader, Ethernet/VLAN/IPv4/IPv6/TCP/UDP decoding, flow table, TCP reassembler, memory limits, JSON + HTML + text output, stream export, `dump` subcommand, unit/property/golden/differential tests, ASan/UBSan, fuzz targets, demo script. |
| **P1 (resume-ready)** | Benchmarks and synthetic dataset generator, single-threaded profiling and measured optimizations, sharded parallel pipeline, TSan, mapping release frontier, scaling results, final `design.md` / `results.md`. |
| **P2 (only if P0+P1 are done)** | `LINKTYPE_RAW` (101) and `LINKTYPE_LINUX_SLL` (113) link types; `std::pmr` pools for out-of-order segments if profiling shows allocator cost; open-addressing flow table if profiling shows `std::unordered_map` cost. |

---

## 2. Evaluation of the brief and key decisions

The brief is well scoped. Most of it stands; this section records where it was tightened and why. Each decision lists the alternative considered so that `docs/design.md` can reuse it.

### 2.1 Decision log

| # | Decision | Alternatives considered | Rationale |
|---|---|---|---|
| D1 | **mmap the whole file read-only**; the reader exposes records as `std::span<const std::byte>` into the mapping. The reader core takes a `span`, so tests and fuzzers feed it in-memory buffers. | `read()` into a ring of buffers; `std::ifstream`. | Zero-copy views into a mapping that lives for the whole run make ownership trivial: no packet copies on the decode path, no buffer recycling. Page-cache-resident benchmarks become pure CPU measurements. Cost: RSS includes touched file pages; fixed by the release frontier (D11). |
| D2 | **No `reinterpret_cast` of packet bytes to header structs.** All multi-byte fields are read with `load_be16/32` helpers that assemble bytes with shifts. | `#pragma pack` structs + `ntohs`. | Casting is UB through misalignment and strict aliasing, and PCAP records are not aligned. Shift-assembly compiles to `mov`+`bswap` on GCC/Clang at `-O2`, so it costs nothing. Interview point. |
| D3 | **Decode errors are values, not exceptions.** Every parse function returns a status (`ok`/`truncated`/`malformed`/`unsupported` + layer + reason). Exceptions are only used at I/O boundaries (open, write). | `std::expected` (C++23), exceptions. | Malformed traffic is normal input, not an exceptional condition. Statuses feed per-reason counters directly. Stays inside C++20. |
| D4 | **TCP reassembly works in 64-bit stream offsets.** A 32-bit sequence number is converted to an absolute offset once, at the entry of the reassembler, using a signed 32-bit difference against the next expected sequence number. Everything after that point is monotonic `uint64_t` arithmetic. | Serial-number comparisons everywhere. | Confines wraparound handling to one audited function (`SeqUnwrapper`). Buffer, gap and overlap logic can no longer have wrap bugs. C++20 defines unsigned→signed conversion as modular, so `static_cast<int32_t>(a - b)` is well-defined. |
| D5 | **Out-of-order buffer: `std::map<uint64_t, Segment>` of disjoint intervals; first-wins overlap policy.** New data is trimmed against existing coverage on insert, so the map never holds overlapping ranges. | Sorted `std::vector`; last-wins; OS-specific policies (Snort-style). | Disjointness is a simple, checkable invariant. `std::map` is the most obviously correct starting point; replacing it is a measured P2 option. A passive observer cannot know which copy the receiver kept; first-wins is deterministic and common. Byte-level conflicts are detected and counted wherever the earlier copy is still buffered. |
| D6 | **In-order fast path is zero-copy.** A segment that starts exactly at the next expected offset, while nothing is buffered, is delivered straight from the mapped file. Only out-of-order data is copied into owned buffers. | Copy every payload. | Makes the zero-copy claim real for the common case and bounds the cost of reordering to the reordered bytes. |
| D7 | **Gaps are declared lazily**: only at forced flush (memory limit), flow finalization (close linger, idle expiry, eviction, reuse) and end of capture. Peer ACK numbers are tracked as a watermark and used to *classify* gaps (`acked`: the receiver got bytes the capture missed) but never to declare a gap early. | Declare gaps as soon as an ACK passes a hole (Wireshark "ACKed unseen segment"). | Captures from multi-queue NICs often record an ACK before the data it acknowledges. Declaring gaps early would turn harmless capture-order skew into false losses. Lazy declaration is deterministic and robust; the extra buffering is bounded by D8. |
| D8 | **Memory is accounted, not estimated after the fact.** Each buffered segment costs `payload_len + 64` bytes (the constant approximates map node + allocation overhead). Limits: per-stream buffer, per-shard reassembly budget, per-shard max concurrent flows. When a limit is hit the stream is force-flushed (gap declared, data delivered), or the least-recently-active flow is evicted. | Allocator hooks; a global atomic budget. | Deterministic, testable invariant: `accounted ≤ limit + one segment`. Per-segment overhead accounting defeats the tiny-segment attack (many 1-byte segments). Per-shard budgets avoid shared atomics. |
| D9 | **Concurrency is P1, not MVP.** The MVP is single-threaded, but the per-shard `Analyzer` is self-contained from day one: it owns its flow table, budgets and stats and has no globals. Single-threaded mode is "one shard called inline". | Concurrency in the MVP; thread pool over packets. | Correctness first, as the brief asks. Building the shard boundary early makes the pipeline purely additive later: dispatcher, queues, merge. |
| D10 | **Parallel design: one reader thread decodes and hashes; N worker shards own disjoint flow sets; one SPSC ring per worker carries batches of packet descriptors; empty batches return on a second SPSC ring.** The fixed number of batches per worker *is* the backpressure mechanism. | Parallel file chunking; MPMC queue; mutex/condvar queue; work stealing. | PCAP is not self-synchronizing (record boundaries cannot be found from an arbitrary offset), so reading must be sequential. Walking record headers is cheap. Hashing the canonical bidirectional flow key keeps both directions of a connection on one shard with a single producer, which preserves per-flow order without locks. Batching (256 packets) amortizes atomics and cache-line transfer. Known ceiling: the reader is the serial fraction (Amdahl), and one elephant flow cannot be split. Both are measured and reported, not hidden. |
| D11 | **Mapping release frontier (P1).** The reader calls `madvise(MADV_DONTNEED)` on mapped pages that every worker has finished with. In debug builds it uses `mprotect(PROT_NONE)` instead, so a dangling view faults immediately. | Windowed mapping; ignore RSS. | Without it, peak RSS ≈ file size and memory claims are meaningless. The PROT_NONE guard turns the ownership invariant "no component retains a view into the mapping after its batch returns" into something tests enforce. |
| D12 | **Report determinism.** For a given input and options, JSON/HTML output (minus the `run` section) is byte-identical across runs and across worker counts, provided no memory limit is hit (see 5.6). Flow IDs are the 0-based index of the flow's first packet, so they are globally unique without coordination. | Sequential IDs assigned by shard. | Enables golden tests and the worker-count determinism test, which is the strongest available concurrency correctness check. |
| D13 | **Exact aggregates, bounded detail lists.** Global counters are exact. Per-flow detail is kept for the top-K flows by bytes and the top-K incomplete flows by missing bytes (bounded heaps, K = `--top-flows`). Per-shard top-K merged is exactly the global top-K. | Keep every flow summary. | Prevents unbounded growth on captures with millions of flows while keeping every number in the report exact. |
| D14 | **No third-party runtime dependencies.** JSON writer, HTML generator, CLI parsing and the SPSC ring are written in-project. Test/bench only: GoogleTest, Google Benchmark (via `FetchContent`, pinned). | nlohmann/json, CLI11, fmt, moodycamel queue. | Each component is small (≤ ~150 lines) and output-only; owning them keeps output ordering deterministic and the dependency surface zero. `std::format` covers formatting. |
| D15 | **A `dump` subcommand prints one TSV line per packet** with decoded fields. | Only aggregate reports. | Enables per-packet differential testing against `tshark -T fields`, which is far stronger evidence of decoder correctness than comparing aggregates. It is also a useful debugging tool. |
| D16 | **Synthetic datasets are generated by an in-repo C++ tool (`synth_pcap`)** with a seeded PRNG and configurable impairments. Small test fixtures are generated by a Scapy script and committed. | Download large public captures only; generate everything with Scapy. | Benchmarks need multi-GiB inputs (Scapy is too slow) and reproducible impairment rates. Scapy fixtures provide an implementation-independent packet builder for tests. A real-world public capture is still benchmarked for credibility (12.3). |
| D17 | **VLAN IDs are not part of the flow key.** | Include the outer VLAN ID. | Matches `tshark` conversation semantics, which enables differential testing. Limitation documented: identical 5-tuples in different VLANs merge. |
| D18 | **One idle timeout for open flows (`--idle-timeout`, default 300 s) and a fixed 10 s linger for closed flows.** Times are capture time, never wall-clock. | Per-protocol timeouts; TCP state-machine timers. | Two LRU lists with uniform timeouts each stay sorted by construction, so expiry is O(1) per expired flow. More knobs would not change any acceptance test. |

### 2.2 Answers to the brief's open questions

| Question | Answer (details in referenced sections) |
|---|---|
| Precise protocol support matrix | Section 3. |
| How the PCAP reader works | D1, 6.2. |
| Buffer ownership model | 5.4: mapping owns all frame bytes; decoded packets and in-order deliveries are views; only out-of-order segments are copied into owned, budget-accounted buffers; views never outlive their batch. |
| Reassembly data structures and policies | D4–D8, 6.6. |
| Malformed or incomplete traffic | D3, 6.3, section 14. Nothing aborts; everything is counted by layer and reason. |
| Whether and when to add concurrency | D9, D10: after the single-threaded correctness baseline and benchmarks (M9). Shard-by-flow is the right architecture for this workload; its ceilings are documented. |
| Independent correctness tests | 11.1: four oracles (construction-time ground truth, reference model, `tshark`, cross-configuration determinism). |
| Credible benchmarks | Section 12: separate layers, warm page cache stated, median + spread, hardware recorded, no CI perf gating. |
| Distinguishing features | Appendix A. |

---

## 3. Protocol support matrix

### 3.1 File format

| Item | Support |
|---|---|
| Classic PCAP, microsecond (`0xA1B2C3D4`) | Yes, both byte orders |
| Classic PCAP, nanosecond (`0xA1B23C4D`) | Yes, both byte orders |
| Version | 2.4 expected. Other 2.x accepted with an anomaly counter; major ≠ 2 is rejected. |
| pcapng (`0x0A0D0D0A`) | Detected and rejected with a conversion hint (exit 2) |
| Files > 4 GiB | Yes (64-bit offsets) |
| Link-layer header field | Lower 16 bits = link type. FCS bits (bit 26 flag, bits 28–31 length) are recorded; FCS bytes are excluded naturally by IP length trimming. |

### 3.2 Link types

| Link type | Value | Support |
|---|---|---|
| `LINKTYPE_ETHERNET` | 1 | **P0** |
| `LINKTYPE_RAW` | 101 | P2 |
| `LINKTYPE_LINUX_SLL` | 113 | P2 |
| Anything else | — | Rejected at open with exit 2 and the link type number in the message |

### 3.3 Layers

| Layer | Supported | Counted but not decoded further | Explicitly unsupported (counted with reason) |
|---|---|---|---|
| Ethernet II | EtherType ≥ 0x0600 | ARP (0x0806), other EtherTypes (per-EtherType counter) | 802.3 length frames / LLC (value ≤ 1500) → `unsupported.llc` |
| VLAN | 802.1Q (0x8100), 802.1ad (0x88A8), legacy QinQ (0x9100); **up to 2 tags** | Per-VLAN-ID frame counts (outer tag) | > 2 tags → `unsupported.vlan_depth` |
| IPv4 | Version, IHL, total length, flags/fragment offset, TTL, protocol, addresses. Header checksum verified, counted as anomaly, **never dropped**. Options skipped by IHL. | Fragments (MF set or offset ≠ 0) → `ip_fragments`; L4 not decoded | — |
| IPv6 | Fixed header; extension chain walk over Hop-by-Hop (0), Routing (43), Destination Options (60), max 8 extension headers | Fragment header (44) → `ip_fragments`; L4 not decoded | AH (51), ESP (50), Mobility (135), others → `unsupported.ipv6_ext`; jumbograms → `unsupported.ipv6_jumbo`; chain > 8 → `unsupported.ipv6_ext_chain` |
| TCP | All header fields; options walked with bounds checks; MSS (2) and Window Scale (3) extracted; SACK-Permitted (4), SACK (5), Timestamps (8) recognized and skipped | — | — |
| UDP | Ports, length (validated and used to trim) | — | — |
| ICMP / ICMPv6 | — | Counted by protocol | Inner headers not parsed |
| Other IP protocols | — | Per-protocol-number counter | — |

### 3.4 What gets a flow

Only TCP and UDP over non-fragmented IPv4/IPv6. Only TCP gets stream reassembly. UDP flows get packet/byte statistics.

---

## 4. Functional requirements

### 4.1 PCAP input (`FR-PCAP`)

- **FR-PCAP-1** Open the input with `open` + `fstat` + `mmap(PROT_READ, MAP_PRIVATE)` and call `madvise(MADV_SEQUENTIAL)`. Non-regular files are rejected (exit 2).
- **FR-PCAP-2** Parse the 24-byte global header: magic (byte order + timestamp precision), version, snaplen, link type. A file shorter than 24 bytes, or with an unknown magic, is rejected (exit 2) with a specific message. The pcapng magic gets the conversion hint.
- **FR-PCAP-3** Iterate 16-byte record headers. Each record yields `PacketRecord{ index, file_offset, ts_ns, orig_len, data }`, where `data` is a span into the mapping of length `incl_len`.
- **FR-PCAP-4** Timestamps are normalized to `int64_t` nanoseconds since the Unix epoch. A microsecond field ≥ 1,000,000 (or a nanosecond field ≥ 10⁹) is accepted and counted as `anomaly.ts_fraction_overflow`.
- **FR-PCAP-5** `incl_len > 262144` is a corrupt record. PCAP cannot resynchronize, so iteration stops, capture status becomes `corrupt`, and the report is still produced (exit 3).
- **FR-PCAP-6** A record header or record body that extends past end of file stops iteration. Status becomes `truncated` and `truncated_tail_bytes` is recorded (exit 3).
- **FR-PCAP-7** `incl_len < orig_len` is counted as `records_truncated_by_snaplen` and is not an error. `incl_len > orig_len` is counted as `anomaly.incl_gt_orig` and processing continues with `incl_len`.
- **FR-PCAP-8** Timestamp regressions (a record earlier than its predecessor) are counted and processing continues.
- **FR-PCAP-9** A file containing only the global header produces a valid report with zero packets (exit 0).

### 4.2 Decoding (`FR-DEC`)

- **FR-DEC-1** `decode_packet(const PacketRecord&) -> DecodedPacket` performs all layers in one pass without heap allocation.
- **FR-DEC-2** Every field read is preceded by a length check against the bytes actually available. No read may go past `data.end()`.
- **FR-DEC-3** IPv4: version must be 4; IHL ≥ 5; `total_length ≥ IHL*4`. The L3 region is trimmed to `total_length`, which removes Ethernet padding and FCS. If `total_length` exceeds the captured bytes, the packet is marked `l3_truncated` (snaplen) and decoding continues on the available bytes. If `total_length == 0` and the frame carries enough bytes for a header, the captured length is used and `anomaly.ipv4_zero_total_length` is counted (TCP segmentation offload on the capturing host).
- **FR-DEC-4** IPv6: version must be 6. `payload_length` is used to trim, with the same snaplen and zero-length (TSO) rules as IPv4. The extension chain is walked as in 3.3; each extension header's length is bounds-checked before skipping.
- **FR-DEC-5** TCP: data offset ≥ 5 and `data_offset*4 ≤` available L4 bytes, otherwise `malformed.tcp_data_offset`. Option walk: EOL terminates, NOP advances 1, other kinds require a length byte ≥ 2 that fits inside the option area; violations count as `malformed.tcp_options`, and the segment is still processed (the header itself is valid). Known option kinds with the wrong length (e.g. MSS with len ≠ 4) are ignored and counted.
- **FR-DEC-6** TCP logical payload length = L3 payload length − TCP header length. That can be larger than the captured payload (snaplen truncation); both values are carried in `DecodedPacket`.
- **FR-DEC-7** UDP: `length ≥ 8` and `length ≤` L3 payload, else `malformed.udp_length`. If `length <` L3 payload, the payload is trimmed and the extra bytes are counted as `anomaly.udp_trailing_bytes`.
- **FR-DEC-8** Flag combinations SYN+FIN, SYN+RST and no-flags are counted as `anomaly.tcp_flags_invalid`. Such packets update packet counters but are not fed to the reassembler.
- **FR-DEC-9** Each failure maps to exactly one `(kind, layer, reason)` triple, and the report counts every triple. The full reason list is an `enum class`; adding a reason requires a test that produces it.

### 4.3 Flows (`FR-FLOW`)

- **FR-FLOW-1** The canonical bidirectional key is `{ip_version, l4_proto, endpoint_lo, endpoint_hi}`, where endpoints `(addr[16], port)` are ordered by `operator<=>`. IPv4 addresses are stored as IPv4-mapped IPv6 so all keys have one layout. The packet's direction is "lo→hi" or "hi→lo".
- **FR-FLOW-2** Flow ID = 0-based record index of the flow's first packet.
- **FR-FLOW-3** Orientation: the sender of a SYN without ACK is the *client*. If no SYN is seen, the client is the sender of the first observed packet, and `orientation = "first_packet"`.
- **FR-FLOW-4** Per direction, track packets, frame bytes (`orig_len`), L4 payload bytes, first/last timestamps; for TCP also SYN/FIN/RST observation, ISN, MSS, window scale.
- **FR-FLOW-5** TCP port reuse: a SYN without ACK whose sequence number differs from the recorded client ISN, arriving on a flow that is closed or closing, finalizes the old flow with `close_reason = reused` and starts a new flow (new flow ID). A retransmitted SYN with the same ISN is a no-op apart from counters.
- **FR-FLOW-6** Flow lifetime: open flows expire after `--idle-timeout` of capture time without packets; closed flows (FIN seen in both directions, or RST) are finalized 10 s of capture time after their last packet. Expiry uses two intrusive LRU lists (open, closed); "now" is the maximum timestamp seen by the shard.
- **FR-FLOW-7** When a shard holds `max_flows / shards` flows and a new flow arrives, the least-recently-active open flow is finalized with `close_reason = evicted`.
- **FR-FLOW-8** At end of capture all remaining flows are finalized with `close_reason = end_of_capture` (or `fin`/`rst` if already closed).
- **FR-FLOW-9** Finalization produces a fixed-size `FlowSummary` that updates exact global counters, the per-shard talker map and per-service counters, and is offered to both top-K heaps.

### 4.4 TCP reassembly (`FR-TCP`)

- **FR-TCP-1** One `StreamReassembler` per direction. Origin: ISN+1 if a SYN was seen in that direction; otherwise the sequence number of the first packet seen in that direction (mid-stream pickup; `handshake = partial|none`).
- **FR-TCP-2** SYN and FIN each consume one sequence number. Data on a SYN (TCP Fast Open) starts at ISN+1.
- **FR-TCP-3** Sequence → offset conversion is done only in `SeqUnwrapper` (6.5). Segments more than 2³⁰ bytes ahead of the next expected offset, or more than 2³⁰ bytes behind it, are counted as `out_of_window` and dropped.
- **FR-TCP-4** Segments entirely below the delivered offset count as retransmissions (segments and bytes). Partially old segments are trimmed; the old prefix counts as retransmitted bytes.
- **FR-TCP-5** Overlap with buffered data: first-wins. The new segment is split into pieces that cover only uncovered ranges. Overlapping bytes are compared with the buffered bytes; differing bytes are counted as `conflicting_overlap_bytes`.
- **FR-TCP-6** Zero-copy fast path as in D6. After any delivery, contiguous buffered segments are drained in order.
- **FR-TCP-7** Snaplen-truncated segments insert only the captured prefix. The uncaptured tail stays a hole, which a later retransmission may fill, and is counted as `snaplen_missing_bytes`.
- **FR-TCP-8** FIN records `fin_offset`. Data beyond `fin_offset` is counted as `anomaly.data_after_fin` and dropped. A direction is *complete* when the delivered offset reaches `fin_offset` with zero gaps.
- **FR-TCP-9** After RST, further data in either direction is counted as `data_after_rst` and dropped (until reuse per FR-FLOW-5).
- **FR-TCP-10** Peer ACKs (with the ACK flag set) update `max_acked_offset` for the opposite direction, after conversion through that direction's unwrapper.
- **FR-TCP-11** `flush(reason)` delivers all buffered data in offset order. Each hole between the delivered offset and the next buffered segment produces a gap `{offset, length, acked}`, where `acked` means the hole lies entirely below `max_acked_offset`. A trailing hole between the last delivered byte and `max(max_acked_offset, highest seen end)` is also reported as a gap.
- **FR-TCP-12** Memory limits (D8): if inserting a segment would push the stream over `--max-stream-buffer` or the shard over its reassembly budget, the stream is flushed before the insert. If the stream has nothing buffered, the segment is delivered after a gap. Each such event is counted as `forced_flushes`.
- **FR-TCP-13** Per stream, the first 16 gaps are kept in detail (`gaps_truncated = true` beyond that); gap count and gap bytes are always exact.
- **FR-TCP-14** Delivered bytes go to a `StreamSink`. Implementations: `NullSink` (default), `FileExportSink` (`--export-streams`), `RecordingSink` (tests).

### 4.5 Statistics (`FR-STAT`)

- **FR-STAT-1** Decode counters per layer, per EtherType, per IP protocol, per VLAN ID, and per `(kind, layer, reason)`.
- **FR-STAT-2** Timeline: an adaptive histogram of 256 buckets. Origin = first packet timestamp; initial bucket width 1 ms. When a packet falls beyond the last bucket, adjacent pairs are merged and the width doubles. Packets before the origin go into bucket 0 and are counted as `timeline_clamped`.
- **FR-STAT-3** Talkers: per IP address, exact bytes sent, bytes received and flow count, accumulated at flow finalization. The report lists the top 20 by total bytes.
- **FR-STAT-4** Services: per `(l4_proto, service_port)`, flows and bytes. Service port = server port when the handshake was seen, otherwise the numerically lower port. A static table of ≤ 20 well-known ports provides labels (`"https"`, `"dns"`, …), marked heuristic in the HTML.
- **FR-STAT-5** Flow outcome counters: totals by protocol, handshake class, close reason, integrity.
- **FR-STAT-6** Reassembly totals and `peak_buffered_bytes` (max over the run of the shard's accounted bytes, summed across shards at the end; in parallel mode the sum of per-shard peaks, documented as an upper bound).

### 4.6 Output (`FR-OUT`)

- **FR-OUT-1** A text summary on stdout (unless `--quiet`): capture info, packet/byte totals, protocol breakdown, flow outcomes, reassembly totals, top 10 flows, warnings.
- **FR-OUT-2** JSON per section 8.1. It is written to a temporary file in the target directory and renamed into place, so a failed run never leaves a half-written report.
- **FR-OUT-3** HTML per section 8.2, with the same atomic write.
- **FR-OUT-4** Stream export per 6.10.
- **FR-OUT-5** `dump` TSV per 7.2.

---

## 5. System architecture

### 5.1 Data flow

```
                 ┌──────────────────────────── main thread ─────────────────────────────┐
 capture.pcap ──►│ MappedFile ──► PcapReader ──► decode_packet ──► ReaderStats           │
   (mmap)        │   (owns bytes)   (records =     (DecodedPacket:   (decode counters,    │
                 │                   spans)         fields + payload   timeline)          │
                 │                                  span)                                │
                 │                                    │                                  │
                 │              workers == 0          │          workers == N ≥ 1        │
                 │          ┌─────────────────────────┴───────────┐                      │
                 │          ▼                                     ▼                      │
                 │   Analyzer (shard 0)                 Dispatcher: shard = fastrange(   │
                 │   called inline                        hash(FlowKey) >> 32, N)        │
                 └──────────┬──────────────────────────────────┬───────────────────────┘
                            │                                   │ Batch* (256 descriptors)
                            │                    ┌──────────────┼──────────────┐
                            │                    ▼              ▼              ▼
                            │              SPSC ring 0     SPSC ring 1 ... SPSC ring N-1
                            │                    │              │              │
                            │              worker 0        worker 1  ...  worker N-1
                            │              Analyzer        Analyzer       Analyzer
                            │              (FlowTable,     (own budget,   ...
                            │               Reassemblers,   own LRU,
                            │               ShardStats)     own talkers)
                            │                    │ empty Batch* back on return ring
                            ▼                    ▼
                         ShardResult ...      ShardResult[N]
                            └──────────┬─────────┘
                                       ▼
                       merge(ReaderStats, ShardResult[]) ──► Report (in-memory model)
                                       │
                       ┌───────────────┼────────────────┐
                       ▼               ▼                ▼
                 text summary     JsonReport        HtmlReport
```

### 5.2 Components

| Component | Responsibility | Owns | Thread |
|---|---|---|---|
| `MappedFile` | RAII mmap of input; release frontier (P1) | The mapping | main |
| `PcapReader` | Validate header, iterate records | Nothing (views the span) | main |
| `decode_packet` | Stateless layered decode | Nothing | main |
| `ReaderStats` | Decode counters, timeline, capture info | Counters | main |
| `Analyzer` | Flow table, TCP tracking, reassembly, expiry, shard stats, top-K | All per-flow state | one per shard |
| `StreamReassembler` | Per-direction reassembly | Out-of-order segment buffers | shard |
| `MemoryBudget` | Accounting and limits for one shard | Counters | shard |
| `Pipeline` | Threads, rings, batches, backpressure, error propagation | Batches, `std::jthread`s | main + workers |
| `Report` + `merge` | Combine reader and shard results deterministically | The report model | main |
| `JsonWriter`, `JsonReport`, `HtmlReport`, `TextSummary` | Serialization | Output buffers | main |
| `FileExportSink` | Write delivered stream bytes to disk | One open file at a time | shard |

### 5.3 Threading model

- `--workers 0` (default): no threads; the main thread runs one `Analyzer` inline. This is the reference implementation that all tests run against.
- `--workers N ≥ 1`: the main thread is the reader/dispatcher; N `std::jthread` workers each own one `Analyzer`. `--workers 1` exists to measure pipeline overhead in isolation.
- Each worker has a *work ring* (reader → worker, `Batch*`) and a *free ring* (worker → reader). `B = 8` batches per worker are preallocated. The reader fills a batch from the worker's free ring; if the free ring is empty, the reader waits. That is the backpressure. In-flight memory is fixed: `N × B × 256 × sizeof(PacketDesc)`.
- Blocking uses C++20 `std::atomic<uint32_t>::wait/notify_one` on the ring's index after a bounded spin (e.g. 64 iterations with a pause instruction). A waiter flag avoids `notify` syscalls when nobody is waiting.
- Shutdown: after the last record, the reader flushes partial batches and pushes a sentinel (`nullptr`) to every work ring, then joins. A worker that throws stores the `std::exception_ptr`, sets a shared `std::atomic<bool> failed`, and keeps draining (discarding) batches so the reader never blocks forever. The reader checks `failed` on every batch acquisition. After joining, the first stored exception is rethrown on the main thread (exit 4). There are no unbounded waits: every wait loop also checks `failed`.
- Shared mutable state between threads: the rings (atomics only), the `failed` flag, and the per-worker *completed offset* (P1, for the release frontier). Nothing else.

### 5.4 Buffer ownership and lifetimes

| Data | Owner | Lifetime | Referenced by |
|---|---|---|---|
| File bytes | `MappedFile` | Whole run (released progressively by the frontier) | `PacketRecord::data`, `DecodedPacket::payload`, in-order deliveries to sinks |
| `PacketDesc` (record + decoded fields) | `Batch` (preallocated, recycled) | Until the batch returns to the free ring | Worker during processing |
| Out-of-order segment bytes | `StreamReassembler` (`std::vector<std::byte>` per segment; P2: pmr pool per shard) | Until delivered or flushed | Its own map |
| Flow state | `FlowTable` (`std::unordered_map<FlowKey, Flow>`, node-stable) | Until finalized | Intrusive LRU links |
| `FlowSummary` | Top-K heaps in `ShardResult` | Until merge | Report |

**Invariant O1:** No component retains a `std::span` into the mapping after it returns from processing the packet that produced it. Sinks MUST NOT keep `on_data` spans. This is what makes the release frontier and batch recycling safe. In debug builds, the `PROT_NONE` frontier enforces O1.

**Invariant O2:** Every byte of out-of-order storage is charged to exactly one `MemoryBudget` and refunded exactly once. `check_invariants()` verifies that the budget equals the sum over streams.

### 5.5 Error model

| Class | Example | Handling |
|---|---|---|
| Usage | Unknown flag, missing input | Message + usage on stderr, exit 1 |
| Fatal input | Cannot open, not PCAP, pcapng, unsupported link type, major version ≠ 2 | Message on stderr, no report, exit 2 |
| Partial input | Truncated tail, corrupt record | Warning on stderr, full report of the processed prefix, status in report, exit 3 |
| Malformed packet | Any decode failure | Counted. Never logged per packet. Never fatal. |
| Output failure | Unwritable JSON/HTML path, export write error | Message on stderr, exit 4. JSON/HTML left untouched (atomic rename). |
| Internal | Exception from a worker, `bad_alloc` | Message on stderr, exit 4 |
| Invariant violation | Reassembler accounting mismatch | `assert` in debug/fuzz/sanitizer builds (abort); no runtime cost in release |

### 5.6 Determinism

Requirement **NFR-DET**: For a fixed input and options, the JSON report without the `run` section, and the HTML report generated with `--deterministic`, are byte-identical across runs and across `--workers` values, **provided no memory limit was hit** (`forced_flushes == 0` and `evicted == 0`).

Why this holds:
1. Packets of one flow reach one shard in capture order (single producer, FIFO ring).
2. Per-flow processing depends only on that flow's packets and the per-flow decision rules.
3. Expiry sweeps do not change results for captures with non-decreasing timestamps. A shard's "now" is the timestamp of a packet it received. A flow expired at sweep time satisfies `now − last_seen > T`. Any later packet of that flow has `ts ≥ now`, so the lazy per-packet rule would also have split it. Single-threaded and sharded runs therefore make the same split decisions. Non-monotonic captures may differ; this is documented, and fixtures for the determinism test are monotonic.
4. Aggregates are sums or exact maps. Top-K heaps use a total order `(bytes desc, flow_id asc)`. Maps are emitted sorted by key.
5. Memory limits are per shard (`limit / N`), so when they are hit, results legitimately depend on N. The report states the limits and whether they were hit.

---

## 6. Component design

Code sketches are normative for names and semantics, not for every detail.

### 6.1 Byte access (`util/bytes.h`)

```cpp
namespace netprobe {
using Bytes = std::span<const std::byte>;

constexpr std::uint16_t load_be16(const std::byte* p) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(p[0]) << 8) |
                                       std::to_integer<std::uint16_t>(p[1]));
}
constexpr std::uint32_t load_be32(const std::byte* p) noexcept;  // same pattern
constexpr std::uint16_t load_le16(const std::byte* p) noexcept;  // for PCAP headers
constexpr std::uint32_t load_le32(const std::byte* p) noexcept;
}
```

- PCAP headers use a `ByteOrder` chosen at open; record parsing selects `load_le*` or `load_be*` once per file through a template parameter. There is no per-field branch.
- Callers check length before calling a loader. Loaders take raw pointers only after the check; debug builds `assert` the bound through a `Bytes`-taking overload used in tests.
- Unit tests include `static_assert`s on constant inputs plus a test that `load_be32` produces correct results at every misaligned offset.

### 6.2 `MappedFile` and `PcapReader`

```cpp
class MappedFile {                     // move-only RAII
public:
    static MappedFile open(const std::filesystem::path&);  // throws InputError
    Bytes bytes() const noexcept;
    void release_before(std::uint64_t offset) noexcept;    // P1: MADV_DONTNEED / PROT_NONE in debug
};

struct PcapInfo { ByteOrder order; TsPrecision precision; std::uint16_t ver_major, ver_minor;
                  std::uint32_t snaplen; std::uint16_t link_type; std::optional<std::uint8_t> fcs_bits; };

struct PacketRecord { std::uint64_t index, file_offset; std::int64_t ts_ns;
                      std::uint32_t orig_len; Bytes data; };

struct PcapOpenResult;                    // { OpenError error; std::string message; std::optional<PcapReader> reader; }

class PcapReader {
public:
    static PcapOpenResult open(Bytes file);  // see D3: status value, no exceptions
    const PcapInfo& info() const;
    bool next(PacketRecord& out);         // false at end, truncation or corruption
    CaptureStatus status() const;         // complete | truncated | corrupt
    std::uint64_t truncated_tail_bytes() const;
};
```

`open` returns a small result struct (status + message + optional reader), since `std::expected` is C++23. `next()` is the hot loop and is not virtual. The reader never allocates.

### 6.3 Decoding

```cpp
enum class Layer : std::uint8_t { pcap, ethernet, vlan, ipv4, ipv6, ipv6_ext, tcp, udp };
enum class DecodeKind : std::uint8_t { ok, truncated, malformed, unsupported };
enum class Reason : std::uint8_t { none, short_header, bad_version, bad_ihl, bad_total_length,
    tcp_data_offset, tcp_options, udp_length, vlan_depth, llc, ipv6_ext, ipv6_ext_chain,
    ipv6_jumbo, /* ... closed list, each with a producing test */ };

struct DecodeStatus { DecodeKind kind = DecodeKind::ok; Layer layer{}; Reason reason{}; };

struct IpAddr { std::array<std::uint8_t, 16> b; };   // IPv4-mapped for v4

struct DecodedPacket {
    DecodeStatus status;
    std::uint16_t ethertype; std::uint8_t vlan_count; std::uint16_t vlan_ids[2];
    std::uint8_t ip_version;           // 0 if none
    std::uint8_t l4_proto;             // IP protocol number
    bool is_fragment, l3_truncated, ipv4_checksum_ok;
    IpAddr src, dst; std::uint8_t ttl_or_hlim;
    std::uint16_t src_port, dst_port;
    // TCP only
    std::uint32_t seq, ack; std::uint8_t tcp_flags; std::uint16_t window;
    std::uint16_t mss; std::uint8_t wscale; bool has_mss, has_wscale;
    std::uint32_t payload_logical_len;  // from IP/UDP length
    Bytes payload;                      // captured bytes, size <= logical len
};

DecodedPacket decode_packet(const PacketRecord&) noexcept;
```

Per-layer functions (`parse_ethernet`, `parse_ipv4`, …) are internal, take a `Bytes`, write into the `DecodedPacket`, and return the next layer's `Bytes` plus a status. They are exposed in an internal header so tests and fuzzers can target them individually.

Trimming order: Ethernet frame → strip VLAN tags → L3 region trimmed to IP length (padding/FCS removed) → L4 region trimmed to UDP length (UDP only) → payload.

### 6.4 Flow table

```cpp
struct Endpoint { IpAddr addr; std::uint16_t port; auto operator<=>(const Endpoint&) const = default; };
struct FlowKey  { std::uint8_t ip_version, proto; Endpoint lo, hi;
                  bool operator==(const FlowKey&) const = default; };
struct FlowKeyHash { std::size_t operator()(const FlowKey&) const noexcept; };  // 64-bit mix (e.g. two rounds of a splitmix64-style finalizer over the key's 8-byte words)

std::pair<FlowKey, Direction> make_flow_key(const DecodedPacket&) noexcept;
```

- `FlowKey` is 40 bytes with no padding bytes left uninitialized; hashing reads whole words, so the key is value-initialized and padding is impossible by layout. A `static_assert` checks size and `std::has_unique_object_representations_v`.
- Storage: `std::unordered_map<FlowKey, Flow, FlowKeyHash>` with `reserve()` sized from `max_flows / shards` capped at 64 Ki initially. Node stability allows intrusive LRU pointers.
- Shard selection uses the high 32 bits of the hash with Lemire's multiply-shift (`(h >> 32) * N >> 32`), so it is independent of the bits the table uses for buckets.
- `Flow` holds: key, id, orientation, two `DirectionState` (stats + `StreamReassembler`), TCP lifecycle state, LRU links, list membership. Target: ≤ 512 bytes per idle TCP flow including map node overhead (PERF-M2).

### 6.5 Sequence arithmetic (`tcp/seq.h`)

```cpp
constexpr std::int32_t seq_diff(std::uint32_t a, std::uint32_t b) noexcept {
    return static_cast<std::int32_t>(a - b);   // well-defined modular conversion in C++20
}

class SeqUnwrapper {
public:
    void init(std::uint32_t origin_seq) noexcept;          // offset 0 == origin_seq
    // Converts seq to an absolute offset relative to `reference` (an offset near which seq is expected).
    std::optional<std::uint64_t> to_offset(std::uint32_t seq, std::uint64_t reference) const noexcept;
};
```

`to_offset(seq, ref)` computes `d = seq_diff(seq, uint32(origin + ref))`. It returns `nullopt` if `|d| > 2^30` (out of window) or if `ref + d < 0` (before the origin), otherwise `ref + d`. The reference is the delivered offset for data, and for ACK watermarks also the delivered offset of the direction being acknowledged. Exhaustive tests cover origins `{0, 1, 2^31−1, 2^31, 2^32−1, 2^32−1500}` × deltas `{−2^30−1, −2^30, −1, 0, 1, 2^30, 2^30+1}`.

### 6.6 `StreamReassembler`

```cpp
struct ReassemblyLimits { std::uint64_t max_stream_buffer; };
struct Gap { std::uint64_t offset, length; bool acked; };

class StreamReassembler {
public:
    StreamReassembler(MemoryBudget&, const ReassemblyLimits&) noexcept;
    void init(std::uint32_t origin_seq) noexcept;
    void on_segment(std::uint32_t seq, std::uint32_t logical_len, Bytes captured, StreamSink&);
    void on_fin(std::uint32_t fin_seq) noexcept;
    void on_peer_ack(std::uint32_t ack) noexcept;
    void flush(StreamSink&);                          // declares gaps; empties buffer
    const StreamStats& stats() const noexcept;
    bool check_invariants() const;                    // tests/fuzz/debug only
private:
    SeqUnwrapper unwrap_;
    std::uint64_t delivered_ = 0;                     // next expected offset
    std::uint64_t highest_end_ = 0, max_acked_ = 0;
    std::optional<std::uint64_t> fin_offset_;
    std::map<std::uint64_t, Segment> ooo_;            // start -> owned bytes; disjoint, all > delivered_
    std::uint64_t buffered_accounted_ = 0;
    MemoryBudget* budget_;
    StreamStats stats_;                               // incl. first 16 gaps
};
```

`on_segment` algorithm (normative):

```
1. off = unwrap.to_offset(seq', delivered)  where seq' = seq + (SYN ? 1 : 0)
   if nullopt → stats.out_of_window++ ; return
2. end = off + logical_len; cap_end = off + captured.size()
   highest_end = max(highest_end, end)
   if fin_offset and end > fin_offset → trim to fin_offset, count data_after_fin
3. if end <= delivered → retransmitted_segments++, retransmitted_bytes += len; return
4. if off < delivered  → retransmitted_bytes += delivered - off; advance off/captured to delivered
5. stats.snaplen_missing_bytes += end - cap_end    (only cap_end..end is a hole; not inserted)
6. if off == delivered and ooo empty:                         // fast path, zero-copy
       sink.on_data(delivered, captured); delivered = cap_end; return
7. if off > delivered: out_of_order_segments++
8. for each buffered segment S overlapping [off, cap_end):     // first-wins
       compare overlapping bytes, conflicting_overlap_bytes += mismatches
       overlap_bytes += overlap length
   pieces = [off, cap_end) minus union(buffered ranges)
9. for each piece P:
       cost = P.size + kSegmentOverhead (64)
       if buffered_accounted + cost > max_stream_buffer or !budget.can_charge(cost):
           forced_flush (flush(sink); forced_flushes++)   // frees this stream's memory
           if piece now starts at delivered → deliver directly; continue
           // still cannot charge: deliver with gap (on_gap from delivered to P.start, then on_data)
       copy P into owned Segment, charge budget, insert into ooo
10. drain: while ooo.begin()->first == delivered → deliver, refund, erase
```

`flush` walks `ooo_` in order, emits `on_gap` for each hole and `on_data` for each segment, refunds every charge, then emits a trailing gap up to `max(max_acked_, highest_end_)` (bounded by `fin_offset_` when known) and sets `delivered_` to that point.

`check_invariants`: map keys strictly increasing and disjoint; all keys ≥ `delivered_`; no segment is adjacent to `delivered_` (it would have been drained); `buffered_accounted_` equals Σ(size + overhead); `buffered_accounted_ ≤ max_stream_buffer`.

### 6.7 TCP connection tracking (inside `Analyzer`)

A small state record per flow, not a full RFC 793 state machine:

| Field | Meaning |
|---|---|
| `syn_seen[2]`, `synack_seen`, `isn[2]` | Handshake class: `full` (SYN, SYN-ACK, and ACK from the client), `partial` (some), `none` |
| `fin_seen[2]`, `rst_seen` | Close detection |
| `state` | `open` → `closing` (FIN in both directions, or RST) |

Per-packet processing order for TCP: port-reuse check (FR-FLOW-5) → flag sanity (FR-DEC-8) → update flow/direction stats → if SYN, init that direction's reassembler origin → if ACK, `on_peer_ack` on the opposite direction → `on_segment` if `payload_logical_len > 0` or SYN/FIN → if FIN, `on_fin` → if RST, mark closing → move the flow to the correct LRU list tail.

A direction without a SYN is initialized lazily from its first packet (FR-TCP-1).

### 6.8 `MemoryBudget` and expiry

```cpp
class MemoryBudget {
public:
    explicit MemoryBudget(std::uint64_t limit) noexcept;
    bool can_charge(std::uint64_t n) const noexcept;
    void charge(std::uint64_t n) noexcept;   // updates current and peak
    void refund(std::uint64_t n) noexcept;   // asserts current >= n
    std::uint64_t current() const noexcept, peak() const noexcept;
};
```

Expiry runs at most once per 1,024 packets per shard, and also whenever the shard's "now" advances by ≥ 1 s. It pops from the head of each LRU list while `now − last_seen > timeout`. Each expired flow is flushed, summarized and erased.

### 6.9 Pipeline (P1)

```cpp
template <class T, std::size_t Capacity>      // Capacity power of two
class SpscRing {
public:
    bool try_push(T) noexcept;  bool try_pop(T&) noexcept;
    void push_wait(T, const std::atomic<bool>& failed);    // spin then atomic wait
    bool pop_wait(T&, const std::atomic<bool>& failed);
private:
    alignas(64) std::atomic<std::uint32_t> head_;  alignas(64) std::uint32_t cached_tail_;
    alignas(64) std::atomic<std::uint32_t> tail_;  alignas(64) std::uint32_t cached_head_;
    std::array<T, Capacity> slots_;
};
```

- Acquire/release ordering only; no `seq_cst`. Producer and consumer cache the other side's index to avoid reading a shared cache line on every operation.
- `PacketDesc` = `{PacketRecord, DecodedPacket, std::uint64_t flow_hash}`. Payload stays a span into the mapping (O1).
- Batches have 256 slots, `B = 8` per worker, and are sent when full or when the input ends.
- Pipeline metrics (in `run.pipeline`): per worker packets, batches, idle waits, reader stall count, total reader stall ns, max work-ring occupancy. Occupancy is sampled at every push.
- Release frontier: after processing a batch, each worker stores the file offset just past the batch's last record in its `completed_offset` atomic. Every 64 batches the reader computes the minimum over workers, among those that have batches in flight, and calls `release_before(min)` rounded down to a page.

### 6.10 Stream export

- `--export-streams DIR`: DIR is created if missing. Files are named `<flow_id>_<c2s|s2c>.bin`. Names contain only digits and fixed strings, so path traversal is impossible. A sidecar `streams.tsv` lists `flow_id, direction, src, sport, dst, dport, delivered_bytes, gap_count`.
- Only data is written; gaps are not zero-filled. Gap offsets in the report are stream offsets.
- Implementation: open in append mode, write, close for each delivery chunk. This keeps file-descriptor use at one and is correct across workers, since each flow belongs to one shard. Export mode is excluded from performance targets. The code carries a `ponytail:` comment naming the ceiling (one open/close per chunk) and the upgrade path (small LRU of open files).

### 6.11 Report generation

- `Report` is a plain struct tree built by `merge()`. JSON and HTML are both rendered from it; HTML never re-parses JSON.
- `JsonWriter`: streaming writer with explicit `begin_object`/`key`/`value`/`end_object`. It escapes `"` `\` and control characters (`\u00XX`) and emits non-ASCII bytes as-is only if they form valid UTF-8, otherwise as `�`. Integers use `std::to_chars`; there are no floats outside `run`.
- `HtmlReport`: one `std::string` built with `std::format`, with an `html_escape()` for every dynamic value (including the input path). Inline CSS and inline SVG only.

---

## 7. CLI specification

### 7.1 `netprobe analyze`

```
netprobe analyze <capture.pcap> [options]

Output:
  -o, --json <path>              Write JSON report ("-" = stdout; implies --quiet)
      --html <path>              Write standalone HTML report
      --export-streams <dir>     Write reassembled TCP streams (one file per direction)
  -q, --quiet                    Suppress the text summary
      --deterministic            Omit the "run" section (timings, host, RSS) from JSON and HTML

Processing:
  -j, --workers <N>              0 = single-threaded inline (default); N >= 1 = reader + N worker shards
      --idle-timeout <sec>       Open-flow idle timeout in capture time (default 300)
      --max-flows <N>            Max concurrent flows across all shards (default 1000000)
      --max-stream-buffer <size> Out-of-order buffer per TCP direction (default 4M)
      --max-reassembly-memory <size>  Total out-of-order budget, split evenly across shards (default 512M)
      --top-flows <N>            Detailed flow records kept per list (default 1000)

  -h, --help    -V, --version
Sizes accept K, M, G suffixes (powers of 1024).
```

- Validation: N ≤ 256 workers; sizes ≥ 64K; `--top-flows` 1..100,000; `--idle-timeout` 1..86400. Out-of-range values → exit 1 with the allowed range.
- Unknown options and duplicate positional arguments → exit 1.
- The parser is a small hand-written loop with table-driven tests.

### 7.2 `netprobe dump`

```
netprobe dump <capture.pcap> [--limit N]
```

One TSV line per record, header row first. Columns: `index ts_ns orig_len caplen status ethertype vlan ip_ver src dst proto sport dport tcp_seq tcp_ack tcp_flags tcp_len`. Missing fields are empty. Addresses use canonical text forms (`inet_ntop`-compatible; RFC 5952 for IPv6). `tcp_flags` is hex. `tcp_len` is the logical payload length. This format is what the differential script compares against `tshark -T fields`.

### 7.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, capture complete |
| 1 | Usage error |
| 2 | Fatal input error, no report |
| 3 | Report produced, capture truncated or corrupt |
| 4 | Output or internal error |

### 7.4 Text summary example (shape, not exact content)

```
netprobe 0.1.0  capture.pcap  (pcap 2.4, usec, EN10MB, snaplen 262144)
  12,403 packets  9.81 MiB  span 00:01:42.331  status: complete
  IPv4 11,920  IPv6 410  VLAN 1,200  TCP 10,880  UDP 1,402  other 121
  decode errors: 3 truncated (ipv4: 2, tcp: 1), 1 malformed (tcp_options)
  flows: 214 TCP (198 full handshake), 37 UDP; 6 TCP flows with gaps (18,240 bytes missing)
  reassembly: 8.12 MiB delivered, 1.3% retransmitted, 412 out-of-order, 0 conflicts
  top flows:
    #1022  10.0.0.5:51544 -> 93.184.216.34:443  tcp  4.10 MiB  fin  complete
    ...
  wrote report.json, report.html
```

---

## 8. Report specification

### 8.1 JSON (`schema_version: 1`)

Key order is exactly as below. Objects that are maps (EtherTypes, protocols, VLANs, reasons) are emitted with keys sorted ascending and only non-zero entries. All times are integer nanoseconds; all sizes are integer bytes.

```json
{
  "schema_version": 1,
  "tool": { "name": "netprobe", "version": "0.1.0" },
  "options": { "workers": 0, "idle_timeout_s": 300, "max_flows": 1000000,
               "max_stream_buffer": 4194304, "max_reassembly_memory": 536870912, "top_flows": 1000 },
  "capture": {
    "path": "samples/web.pcap", "file_size": 0, "format": "pcap",
    "byte_order": "little", "ts_precision": "usec", "version": "2.4",
    "snaplen": 262144, "link_type": 1, "link_type_name": "EN10MB",
    "status": "complete", "truncated_tail_bytes": 0,
    "records": 0, "captured_bytes": 0, "original_bytes": 0,
    "records_truncated_by_snaplen": 0, "timestamp_regressions": 0,
    "first_ts_ns": 0, "last_ts_ns": 0, "duration_ns": 0
  },
  "decode": {
    "layers": { "ethernet": 0, "vlan_tagged": 0, "ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0,
                "icmp": 0, "icmpv6": 0, "arp": 0, "ip_fragments": 0,
                "other_ethertype": 0, "other_ip_proto": 0 },
    "ethertypes": { "0x0800": 0 }, "ip_protocols": { "6": 0 }, "vlans": { "100": 0 },
    "errors": { "truncated":   { "ipv4.short_header": 0 },
                "malformed":   { "tcp.tcp_options": 0 },
                "unsupported": { "ipv6_ext.ipv6_ext": 0 } },
    "anomalies": { "ipv4_bad_checksum": 0, "ipv4_zero_total_length": 0, "udp_trailing_bytes": 0,
                   "tcp_flags_invalid": 0, "incl_gt_orig": 0, "ts_fraction_overflow": 0 }
  },
  "timeline": { "origin_ns": 0, "bucket_width_ns": 1000000, "clamped": 0,
                "buckets": [ { "packets": 0, "bytes": 0 } ] },
  "flows": {
    "tcp": { "total": 0, "handshake_full": 0, "handshake_partial": 0, "handshake_none": 0,
             "close_fin": 0, "close_rst": 0, "close_idle_timeout": 0, "close_end_of_capture": 0,
             "close_reused": 0, "close_evicted": 0, "complete": 0, "with_gaps": 0 },
    "udp": { "total": 0, "close_idle_timeout": 0, "close_end_of_capture": 0, "close_evicted": 0 },
    "top_by_bytes": [ "FlowSummary..." ],
    "top_incomplete": [ "FlowSummary..." ]
  },
  "reassembly": {
    "delivered_bytes": 0, "retransmitted_segments": 0, "retransmitted_bytes": 0,
    "out_of_order_segments": 0, "overlap_bytes": 0, "conflicting_overlap_bytes": 0,
    "gap_count": 0, "gap_bytes": 0, "acked_gap_bytes": 0, "snaplen_missing_bytes": 0,
    "out_of_window_segments": 0, "data_after_fin": 0, "data_after_rst": 0,
    "forced_flushes": 0, "peak_buffered_bytes": 0, "limits_hit": false
  },
  "talkers":  [ { "address": "10.0.0.1", "bytes_sent": 0, "bytes_received": 0, "flows": 0 } ],
  "services": [ { "proto": "tcp", "port": 443, "label": "https", "flows": 0, "bytes": 0 } ],
  "run": { "workers": 0, "elapsed_ns": 0, "packets_per_sec": 0.0, "mib_per_sec": 0.0,
           "peak_rss_bytes": 0, "host": { "os": "", "cpu_count": 0 },
           "pipeline": { "reader_stalls": 0, "reader_stall_ns": 0,
                         "workers": [ { "packets": 0, "batches": 0, "idle_waits": 0, "max_occupancy": 0 } ] } }
}
```

`FlowSummary`:

```json
{
  "id": 1022, "proto": "tcp", "ip_version": 4,
  "client": { "address": "10.0.0.5", "port": 51544 },
  "server": { "address": "93.184.216.34", "port": 443 },
  "orientation": "handshake", "handshake": "full",
  "close_reason": "fin", "integrity": "complete",
  "first_ts_ns": 0, "last_ts_ns": 0,
  "c2s": { "packets": 0, "bytes": 0, "payload_bytes": 0, "delivered_bytes": 0,
           "retransmitted_bytes": 0, "out_of_order_segments": 0,
           "overlap_bytes": 0, "conflicting_overlap_bytes": 0,
           "gap_count": 0, "gap_bytes": 0, "gaps": [ { "offset": 0, "length": 0, "acked": true } ],
           "gaps_truncated": false, "fin": true, "mss": 1460, "wscale": 7 },
  "s2c": { "...": "same shape" }
}
```

`integrity` ∈ `complete | gaps | snaplen_truncated | open` (`open` = ended without FIN/RST in some direction and no gaps). UDP summaries omit the TCP-only fields. `peak_rss_bytes` comes from `getrusage(RUSAGE_SELF).ru_maxrss`, normalized for platform units (KiB on Linux, bytes on macOS).

### 8.2 HTML

A single file with no external requests: no CDN, fonts, scripts or images. Required sections, in order:

1. **Header**: file name, capture status badge, packets, bytes, duration, first/last timestamp (ISO 8601 UTC).
2. **Warnings**: truncated/corrupt capture, limits hit, decode error rate > 1%. The section is omitted when there are no warnings.
3. **Traffic timeline**: inline SVG bar chart of packets per bucket with a byte series as a line; axis labels use the bucket width; each bar has a `<title>` tooltip.
4. **Protocol breakdown**: horizontal bars (SVG or CSS widths) for layers and IP protocols with counts and percentages.
5. **Decode errors and anomalies**: a table of non-zero `(kind, layer, reason)` counters.
6. **Flow outcomes**: handshake/close/integrity counts.
7. **Top flows**: table (top 100 of `top_by_bytes`) with ID, endpoints, protocol, packets, bytes, duration, close reason, integrity.
8. **Incomplete streams**: table of `top_incomplete` with per-direction gap counts, missing bytes, ACKed-gap marker, and the first gaps listed inline.
9. **Talkers and services**: two tables; service labels carry a "port heuristic" note.
10. **Reassembly and run details**: reassembly totals, limits, and (unless `--deterministic`) elapsed time, throughput, peak RSS, pipeline stats.

Requirements: dark/light via `prefers-color-scheme`; usable at 375 px width (tables scroll horizontally inside their container, not the page); `<th scope>` on tables; SVG with `role="img"` and a `<title>`; ≤ 2 MiB for `--top-flows 1000`; all dynamic text escaped (a test injects `<script>` into a fixture path and checks the output).

---

## 9. Technology choices and dependencies

| Area | Choice | Notes |
|---|---|---|
| Language | C++20 (`CMAKE_CXX_STANDARD 20`, extensions off) | Uses `std::span`, `std::endian`, `std::bit_cast`, `operator<=>`, concepts where they simplify templates, designated initializers, `std::jthread`, `std::atomic::wait/notify`, `std::format`, `[[likely]]`. No C++23 library features. |
| Compilers | GCC ≥ 13, Clang ≥ 17 (Ubuntu 24.04 ships GCC 13 and Clang 18); Apple Clang ≥ 15 on macOS | `std::format` availability sets the floor. |
| Build | CMake ≥ 3.25 with `CMakePresets.json`; Ninja | |
| Tests | GoogleTest, pinned tag (e.g. `v1.15.2`) via `FetchContent` | Test-only. |
| Benchmarks | Google Benchmark, pinned tag (e.g. `v1.9.1`) via `FetchContent` | Bench-only. |
| Fuzzing | Clang libFuzzer (`-fsanitize=fuzzer,address,undefined`) | Linux CI. On macOS, Apple Clang lacks libFuzzer; use Homebrew LLVM or Linux. |
| Sanitizers | ASan+UBSan (`-fno-sanitize-recover=all`), TSan | Separate presets. |
| Debug checks | `-D_GLIBCXX_ASSERTIONS` (libstdc++) / `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE` (libc++) in debug and sanitizer presets | Bounds-checked standard containers. |
| Static analysis | `clang-format` (check in CI); `clang-tidy` with `bugprone-*`, `performance-*`, `cert-err58-cpp` off, select `cppcoreguidelines-*`; warnings-as-errors only for `bugprone-*` | |
| Warnings | `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast`, `-Werror` in CI | |
| Test tooling | Python 3 (stdlib only) for golden/differential scripts; Scapy only for regenerating fixtures (not needed to build or test) | |
| Reference tool | `tshark` from Ubuntu 24.04 apt (Wireshark 4.2.x); version recorded in test output | |
| CI | GitHub Actions, `ubuntu-24.04` + `macos-latest` | |

Runtime dependencies of `netprobe`: libc and the C++ standard library only.

---

## 10. Repository layout and build

```
netprobe/
├── CMakeLists.txt
├── CMakePresets.json            # dev, release, asan, tsan, fuzz, bench
├── .clang-format  .clang-tidy
├── .github/workflows/ci.yml
├── README.md                    # what, quickstart, demo, results summary, limitations
├── src/
│   ├── main.cpp                 # subcommand dispatch, exit codes
│   ├── cli.{h,cpp}              # option parsing and validation
│   ├── util/bytes.h
│   ├── io/mapped_file.{h,cpp}
│   ├── pcap/reader.{h,cpp}
│   ├── decode/decode.{h,cpp}            # DecodedPacket, decode_packet
│   ├── decode/layers.{h,cpp}            # parse_ethernet/vlan/ipv4/ipv6/tcp/udp (internal)
│   ├── flow/flow_key.{h,cpp}
│   ├── tcp/seq.h
│   ├── tcp/reassembler.{h,cpp}
│   ├── tcp/stream_sink.{h,cpp}          # NullSink, FileExportSink
│   ├── analysis/analyzer.{h,cpp}        # per-shard: flow table, TCP tracking, expiry, top-K
│   ├── analysis/memory_budget.h
│   ├── analysis/stats.{h,cpp}           # ReaderStats, ShardResult, timeline, merge
│   ├── pipeline/spsc_ring.h
│   ├── pipeline/pipeline.{h,cpp}
│   └── report/{json_writer,json_report,html_report,text_summary}.{h,cpp}
├── tests/
│   ├── unit/                    # per component, GoogleTest
│   ├── support/packet_builder.{h,cpp}   # test-only frame/pcap builder
│   ├── reference/               # naive reassembly reference model
│   ├── integration/             # CLI runs, golden comparison, determinism
│   ├── fixtures/                # *.pcap + *.truth.json (+ gen_fixtures.py, Scapy)
│   ├── golden/                  # expected *.json (deterministic mode)
│   ├── differential/compare_tshark.py
│   └── fuzz/{fuzz_decode,fuzz_pcap,fuzz_reassembly}.cpp + corpus/ + pcap.dict
├── bench/
│   ├── bench_decode.cpp  bench_flow.cpp  bench_reassembly.cpp  bench_spsc.cpp
│   └── run_e2e.sh               # end-to-end harness
├── tools/synth_pcap.cpp         # deterministic synthetic capture generator
├── samples/                     # small committed demo captures (< 2 MiB total)
├── scripts/demo.sh
└── docs/PRD.md  docs/design.md  docs/results.md
```

CMake targets: `netprobe_core` (static library, everything except `main.cpp`), `netprobe` (executable), `netprobe_tests`, `netprobe_bench`, `synth_pcap`, `fuzz_*`. Options: `NETPROBE_BUILD_TESTS` (ON), `NETPROBE_BUILD_BENCH` (OFF), `NETPROBE_BUILD_FUZZ` (OFF), `NETPROBE_SANITIZE` (`""`, `"address,undefined"`, `"thread"`).

Presets:

| Preset | Build type | Extras |
|---|---|---|
| `dev` | Debug | assertions, library hardening, PROT_NONE frontier |
| `release` | Release (`-O2 -DNDEBUG`) | no `-march=native` (results also report a `-march=native` run separately, if any) |
| `asan` | RelWithDebInfo | ASan+UBSan, library hardening |
| `tsan` | RelWithDebInfo | TSan |
| `fuzz` | RelWithDebInfo, Clang | libFuzzer + ASan + UBSan |
| `bench` | Release | `NETPROBE_BUILD_BENCH=ON`, `synth_pcap` |

---

## 11. Testing strategy

### 11.1 Independent oracles

Tests that only check "the program ran" do not count. Every correctness claim is backed by at least one oracle that does not share code with the implementation:

| Oracle | What it validates | Independence |
|---|---|---|
| **O-A Construction ground truth** | Fixtures and property tests build streams from known application bytes, then segment, impair (drop/reorder/duplicate/overlap) and record exactly what they did. The expected reassembled bytes and gap ranges follow from the construction, not from NetProbe. | Scapy (fixtures) and a test-only `PacketBuilder` (unit tests). Neither uses NetProbe decoding. |
| **O-B Reference model** | `tests/reference/naive_reassembler`: a byte-coverage model (`std::vector<std::optional<std::byte>>` indexed by offset, first-write-wins). Obviously correct, O(stream length). Property tests require the real reassembler's delivered bytes, gaps and counters to equal the model's. | Shares no code with `StreamReassembler`. |
| **O-C `tshark`** | Per-packet decoded fields, conversation packet/byte counts, follow-stream bytes on gap-free, conflict-free streams. | External implementation. |
| **O-D Cross-configuration** | Same input with `--workers 0,1,2,4,8` must give identical deterministic output; inline vs pipeline. | Checks the concurrency layer against the single-threaded reference. |

### 11.2 Unit tests (GoogleTest)

| Area | Required cases |
|---|---|
| bytes | Endian loads at all alignments; `static_assert`s |
| pcap reader | 4 magics; version handling; header-only file; zero-length record; `incl_len > orig_len`; `incl_len > 262144`; truncated record header; truncated body; ts fraction overflow; timestamp regression; pcapng rejection; < 24-byte file |
| decode | Valid frames for every row of the support matrix; **exhaustive truncation sweep**: for each valid fixture frame, every prefix length 0..n decodes without error and reports `truncated` at the correct layer (or `ok` with `l3_truncated` once the L4 header is complete); Ethernet padding trimmed; FCS trimmed; IPv4 zero total length; IHL < 5; total length < IHL; bad checksum counted not dropped; fragments (first, middle, last) in v4 and v6; IPv6 ext chain (HBH+DestOpts+Routing), chain of 9, ESP; 3 VLAN tags; LLC; TCP data offset 4 and too large; option walk: NOP padding, EOL, len 0, len 1, len past end, MSS wrong length; UDP length < 8, > payload, < payload |
| flow key | Symmetry (A→B and B→A give the same key, opposite directions); v4 vs v6 never collide; hash distribution sanity (chi-square over 1 Mi random keys into 1024 buckets within a loose bound) |
| seq | Exhaustive matrix from 6.5 |
| reassembler | In-order; reverse order; random permutation; exact duplicate; retransmission covering two buffered segments and a hole; partial overlap both sides; conflicting overlap (first kept, conflict counted); ISN `0xFFFFFF00` crossing wrap with OOO across the boundary; SYN with data; FIN then late retransmission filling a hole; data after FIN; snaplen-truncated segment later filled by a full retransmission; out-of-window ahead/behind; ACK watermark classification; per-stream limit forced flush; budget limit forced flush; 10⁵ one-byte reversed segments stay within limit; `check_invariants()` after every operation |
| analyzer | Handshake classes; mid-stream pickup; RST; port reuse (same ISN vs different ISN); idle expiry; closed linger; eviction at `max_flows`; UDP flows; top-K tie ordering |
| spsc ring | Single-thread semantics; wraparound of indices; two-thread stress of 10⁸ items with sequence check (also under TSan with fewer items) |
| pipeline | Worker exception propagates and the reader does not hang; empty input; one packet; N > number of flows |
| json/html | Escaping (quotes, backslash, control chars, invalid UTF-8, `<script>`); deterministic key order; JSON parses with Python `json` (integration) |
| cli | Every flag; range errors; unknown flag; missing input; exit codes |

### 11.3 Property-based reassembly tests

A seeded generator (`std::mt19937_64`, seed printed on failure, ≥ 10,000 cases per CI run, 10⁶ in a manual/nightly target):

- Random stream length 0..256 KiB, random ISN with a 25% bias toward `2^32 − [0, 64 KiB)`.
- Segment sizes 1..1460; operations: drop (≤ 5%), duplicate (≤ 10%), reorder within a window (≤ 32 segments), overlapping re-segmentation of already-sent ranges (identical bytes, or different bytes for the conflict variant), snaplen truncation (≤ 5%), FIN at end (80%).
- Assertions: delivered byte sequence == O-B model output; gap list == model gaps; retransmitted/overlap/conflict counters == model counters; `check_invariants()` holds after every segment; accounted memory ≤ limit + one segment at every step; with no drops and no truncation, delivered bytes == original stream exactly.

### 11.4 Integration and golden tests

- Fixtures (`tests/fixtures/`, each < 64 KiB, generated by `gen_fixtures.py` with a fixed seed and committed):
  `tcp_clean_v4`, `tcp_clean_v6`, `tcp_reorder`, `tcp_loss_acked`, `tcp_retrans_overlap`, `tcp_conflict_overlap`, `tcp_wraparound`, `tcp_midstream`, `tcp_rst`, `tcp_port_reuse`, `tcp_snaplen_96`, `vlan_qinq`, `ipv6_ext_headers`, `ip_fragments`, `udp_mixed`, `malformed_mix` (one frame per malformed reason), `truncated_tail`, `corrupt_record`, `header_only`, `ts_nonmonotonic`.
- Each fixture has a `*.truth.json` written by the generator with ground truth: per-stream SHA-256 of the original application bytes, intended gap ranges, packet counts per protocol, expected malformed reasons. An integration test checks NetProbe's output against the truth (using `--export-streams` for byte checks) **independently of the golden file**.
- Golden files: `analyze --deterministic --json` output per fixture. Goldens change only via `UPDATE_GOLDEN=1 ctest -R golden`, and the diff is reviewed by a human. A golden that disagrees with its truth file is a test failure.
- Determinism test (O-D): every fixture plus a 200k-packet synthetic capture, workers ∈ {0,1,2,4,8}; outputs compared byte-for-byte.
- CLI tests: exit codes 0–4 each triggered; atomic write (output path in a read-only dir → exit 4, no partial file).

### 11.5 Differential testing against `tshark`

`tests/differential/compare_tshark.py <pcap>` (CI job, fixtures + one larger synthetic capture; locally also the real-world capture):

1. **Per packet:** `netprobe dump` vs `tshark -r f -T fields -E header=y -e frame.number -e frame.len -e frame.cap_len -e eth.type -e vlan.id -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tcp.seq_raw -e tcp.ack_raw -e tcp.flags -e tcp.len`, compared field by field. Normalization rules (frame numbering base, multiple VLAN values, IPv6 text form) live in the script and are documented there.
2. **Conversations:** `tshark -q -z conv,tcp` and `-z conv,udp` (frames and bytes per conversation) vs NetProbe flow summaries (run with a `--top-flows` large enough to include all flows).
3. **Streams:** for each TCP stream that NetProbe reports with zero gaps and zero conflicts, `tshark -q -z follow,tcp,raw,<tcp.stream>` (hex output decoded per direction) vs the exported stream files.

Exclusions are explicit and tested: IP fragments (tshark reassembles them), streams with conflicting overlaps (policies differ), and port reuse (tshark may number streams differently). Any other mismatch fails the job. The `tshark` version is printed in the job log.

### 11.6 Fuzzing

| Target | Input interpretation | Checks |
|---|---|---|
| `fuzz_decode` | Raw bytes as one Ethernet frame (`orig_len = size`) | No crash/UB; status is self-consistent (`payload` within the input; `payload.size() ≤ payload_logical_len`) |
| `fuzz_pcap` | Raw bytes as a whole PCAP file, through reader + `Analyzer` (inline) + JSON rendering into memory | No crash/UB/leak; invariants; JSON output is valid UTF-8 |
| `fuzz_reassembly` | Structured: input parsed as a sequence of ops `{seq:u32, len:u16, flags:u8, fill:u8}` driving a reassembler pair with small limits (64 KiB stream, 256 KiB budget) | `check_invariants()` after every op; budget ≤ limit + one segment; flush leaves budget at 0 |

- Seed corpora: all fixtures (frames extracted for `fuzz_decode`), plus a dictionary `pcap.dict` with magics, EtherTypes, VLAN TPIDs and IPv6 next-header values.
- CI smoke: each target for 60 s on every PR (`-max_total_time=60`); corpus cached between runs.
- Release gate: each target ≥ 30 min on Linux with zero findings. `results.md` records exec/s, total executions, corpus size and edge coverage (`-print_final_stats=1`), and line coverage of `src/decode`, `src/pcap`, `src/tcp` from an `llvm-cov` run over the corpus.
- Every crash found becomes a regression test in `tests/unit` before the fix.

### 11.7 Sanitizers and CI jobs

| Job | Runs |
|---|---|
| `build-gcc` | `release` + `dev` with GCC 13: build, all tests |
| `build-clang` | `release` with Clang 18: build, all tests |
| `asan` | All unit, property and integration tests under ASan+UBSan |
| `tsan` | SPSC, pipeline and determinism tests under TSan (smaller sizes) |
| `fuzz-smoke` | 3 targets × 60 s |
| `differential` | `apt install tshark` (non-interactive), run `compare_tshark.py` |
| `lint` | `clang-format --dry-run -Werror`, `clang-tidy` on changed files |
| `macos` | `dev` preset build + tests (portability; no fuzz/bench) |

Performance is **not** gated in CI (shared runners are too noisy). A non-blocking job MAY run benchmarks for trend visibility.

---

## 12. Benchmark methodology

### 12.1 Layers measured separately

| Benchmark | What it isolates | Metric |
|---|---|---|
| `BM_Decode/<mix>` | `decode_packet` over a pre-loaded vector of records (D3 mix and per-protocol mixes) | packets/s, bytes/s (`SetItemsProcessed`, `SetBytesProcessed`) |
| `BM_FlowLookup/<flows>` | Key build + hash + find-or-insert with 1 Ki, 64 Ki, 1 Mi live flows | lookups/s |
| `BM_Reassembly_InOrder` | 1460-byte segments, `NullSink` | payload bytes/s |
| `BM_Reassembly_Reorder/<pct>` | 1%, 10%, 30% segments displaced by up to 8 positions | payload bytes/s |
| `BM_Reassembly_Retransmit/<pct>` | 1%, 10% duplicated segments | payload bytes/s |
| `BM_Spsc` vs `BM_MutexQueue` | Ring throughput with 1 and 256 items per op; mutex/condvar baseline lives in `bench/` only | items/s |
| End-to-end (`bench/run_e2e.sh`) | `netprobe analyze --quiet --deterministic` on page-cache-warm files, workers ∈ {0,1,2,4,8} | packets/s, MiB/s, peak RSS, elapsed |

### 12.2 Rules

- Hardware and software recorded with every result: CPU model, physical/logical cores, RAM, kernel version, distribution, compiler and version, exact flags, CPU governor, SMT/turbo state, NetProbe git SHA.
- Release preset (`-O2 -DNDEBUG`, no `-march=native`). Any `-march=native` or LTO result is reported separately and labeled.
- End-to-end runs: warm the page cache (`cat file > /dev/null`, then one discarded run), then 5 measured runs; report median and min–max. State plainly that disk I/O is excluded. A cold-cache run (`echo 3 > /proc/sys/vm/drop_caches`, root required) MAY be reported separately and labeled.
- Google Benchmark: `--benchmark_repetitions=5 --benchmark_report_aggregates_only=true`; report median and CV; warn if CV > 5%.
- Pin with `taskset` when measuring single-threaded numbers; record it.
- Optimization claims require before/after numbers on the same machine in the same session. Rejected optimizations are recorded too.
- Profiling evidence (`perf stat` IPC and cache-miss rates; `perf record` flame graph of the end-to-end run) is captured for the baseline and after each optimization.
- Amdahl estimate: report the reader thread's busy fraction (from `perf` or the reader stall/idle counters) and the implied scaling ceiling next to measured scaling.

### 12.3 Datasets

`synth_pcap` (C++, seeded `std::mt19937_64`, deterministic output given seed and parameters, ~100 MiB/s+ generation) produces:

| Dataset | Description | Size |
|---|---|---|
| **D1 many-flows** | 1 Mi TCP flows, ~10 packets each (handshake, 2–6 data segments, FIN), 64–1460 B payloads, interleaved | ~1.5 GiB |
| **D2 elephants** | 16 long TCP flows, 1460 B segments, 0.5% reorder, 0.1% loss | 2 GiB |
| **D3 mixed** | Trimodal sizes (64/576/1500), 80% TCP / 20% UDP, 10% IPv6, 10% VLAN, 5% reorder, 1% loss, 1% retransmit, 0.1% malformed | 2 GiB |

Plus **R1**: one publicly available real-world capture (e.g. from the MAWI Working Group traffic archive or the Wireshark SampleCaptures collection), converted to classic PCAP if necessary. Record its URL, SHA-256, license and any conversion in `results.md`. It is downloaded by `bench/fetch_r1.sh`, never committed. If no suitably licensed large capture is available, say so in `results.md` and use the largest suitable one.

---

## 13. Performance targets and acceptance criteria

Targets apply to the reference machine class: x86-64 Linux, ≥ 8 physical cores, a CPU released in 2020 or later, page cache warm. If the available hardware is weaker, record the numbers and the hardware honestly; do not change the methodology to hit a number. A missed target must be explained in `results.md` with profiling evidence.

| ID | Metric | Target |
|---|---|---|
| PERF-1 | Decode only, D3 mix, 1 core | ≥ 15 M packets/s |
| PERF-2 | Reassembly in order, 1460 B segments | ≥ 8 GiB/s payload |
| PERF-3 | Reassembly, 10% reorder | ≥ 1.5 GiB/s payload |
| PERF-4 | End-to-end D3, `--workers 0` | ≥ 2.5 M packets/s and ≥ 1.5 GiB/s |
| PERF-5 | End-to-end D1, `--workers 0` | ≥ 1.5 M packets/s |
| PERF-6 | Scaling D3, `--workers 4` vs `--workers 0` | ≥ 2.0× throughput (8-worker result reported, no target) |
| PERF-7 | Pipeline overhead, `--workers 1` vs `--workers 0` | ≤ 20% slower |
| PERF-M1 | Peak RSS, end-to-end D2 (2 GiB), any worker count, release frontier on | ≤ 128 MiB |
| PERF-M2 | Memory per idle TCP flow (D1, measured as Δ peak RSS / live flows at peak, cross-checked with `sizeof` accounting) | ≤ 512 B |
| PERF-M3 | Accounted reassembly memory under adversarial inputs (tests) | Never > limit + one segment (hard, every test) |

Non-performance acceptance:

| ID | Criterion |
|---|---|
| NFR-SAFE-1 | All tests pass under ASan+UBSan with `-fno-sanitize-recover=all`. |
| NFR-SAFE-2 | Pipeline, SPSC and determinism tests pass under TSan. |
| NFR-SAFE-3 | Each fuzz target ≥ 30 min, zero findings; stats recorded. |
| NFR-COR-1 | Differential job passes on all fixtures and one ≥ 100k-packet synthetic capture. |
| NFR-COR-2 | Property suite (≥ 10,000 cases) passes; 10⁶ cases pass at least once before release. |
| NFR-DET | Determinism test passes (5.6). |
| NFR-BUILD | Clean build with warnings-as-errors on GCC 13 and Clang 18; macOS build and tests pass. |
| NFR-DEMO | `scripts/demo.sh` succeeds from a fresh clone on Ubuntu 24.04 with `build-essential cmake ninja-build` installed. |

---

## 14. Edge cases and failure handling

| Case | Expected behavior | Test |
|---|---|---|
| File < 24 bytes / unknown magic | Exit 2, specific message | unit + CLI |
| pcapng file | Exit 2, `editcap` hint | CLI |
| Unsupported link type | Exit 2, link type number in message | CLI |
| Header-only file | Valid empty report, exit 0 | golden |
| Truncated last record | Report of prefix, `status: truncated`, exit 3 | golden |
| `incl_len > 262144` | Stop, `status: corrupt`, exit 3 | golden |
| `incl_len = 0` | Counted, decode `truncated` at Ethernet | unit |
| `incl_len > orig_len` | Anomaly counted, use `incl_len` | unit |
| Non-monotonic timestamps | Counted; timeline clamps; determinism caveat | fixture |
| Ethernet min-frame padding | Trimmed by IP length; never treated as TCP payload | unit (critical) |
| Trailing FCS | Trimmed by IP length | unit |
| IPv4 `total_length = 0` (TSO) | Use captured length, anomaly | unit |
| IPv4 `total_length` > captured | `l3_truncated`; payload partially captured | unit |
| IPv4 options | Skipped via IHL | unit |
| Bad IPv4 checksum | Counted, processed normally | unit |
| IPv4/IPv6 fragments | Counted, no L4 decode, no flow | fixture |
| IPv6 ext chain > 8 / unknown ext | Unsupported, counted | unit |
| VLAN depth > 2 | Unsupported, counted | unit |
| TCP data offset invalid | Malformed, counted, no flow update | unit |
| Malformed TCP options | Counted, segment still processed | unit |
| SYN+FIN etc. | Anomaly, stats only, not reassembled | unit |
| Capture starts mid-connection | `handshake: none`, origin from first packet | fixture |
| Sequence wraparound | Correct offsets; property tests bias toward wrap | unit + property |
| Out-of-order / duplicates / overlaps | Per FR-TCP-4/5 | unit + property |
| Conflicting overlap | First kept; conflicts counted; excluded from tshark stream diff | fixture |
| Capture loss with ACK evidence | Gap with `acked: true` | fixture |
| Snaplen-truncated payload | Hole, `snaplen_missing_bytes`, fillable by retransmission | fixture |
| Retransmission after FIN filling a hole | Filled before linger expiry | unit |
| Data after FIN / after RST | Counted, dropped | unit |
| Port reuse | Old flow `reused`, new flow ID | fixture |
| Keep-alive (1 byte at `next−1`) | Counted as retransmitted byte; harmless | unit |
| Many tiny OOO segments | Overhead accounting forces flush within limit | unit + fuzz |
| SYN flood / millions of flows | Eviction at `max_flows`; `limits_hit: true` | unit (small limit) |
| One elephant flow with `--workers 8` | Correct; one busy shard; imbalance visible in pipeline stats | bench note |
| Worker throws | Exit 4, no hang | unit |
| Output path unwritable | Exit 4, no partial file | CLI |
| Export dir not creatable | Exit 4 before processing starts | CLI |
| Hostile strings in path | HTML-escaped | unit |

---

## 15. Technical risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `tshark` differences beyond the documented exclusions (version-dependent dissector behavior) | Medium | Differential job flaky or noisy | Pin to the Ubuntu 24.04 package; normalization rules in one script; exclusions are explicit, each with a reason; per-field mismatch reports. |
| Reader thread caps scaling below PERF-6 | Medium | Weaker parallel story | Measure the reader's busy fraction first. Options in order: keep decode minimal in the reader (key extraction only, full decode in workers), batch prefetch, then accept and document the Amdahl ceiling with evidence. |
| Reassembly bugs hidden by agreement between buggy code and buggy tests | Medium | Wrong core results | Four independent oracles (11.1); the reference model is deliberately naive; generator ground truth never comes from NetProbe output. |
| Golden files rubber-stamped | Medium | Tests lock in bugs | Goldens are checked against truth files; updates require an explicit env var and human review. |
| macOS/Linux differences (`madvise`, `ru_maxrss` units, no libFuzzer in Apple Clang) | High | Build or measurement errors | Linux is the benchmark/fuzz platform; platform differences isolated in `mapped_file.cpp` and the RSS helper; macOS CI covers build + tests only. |
| Benchmark noise | High | Unreliable numbers | Median of 5 + spread, pinned cores, recorded governor; no CI gating. |
| Scope creep (more protocols, UI) | Medium | Unfinished core | Non-goals are binding; P2 starts only after the P1 definition of done. |
| Lock-free ring subtle bugs | Low–Medium | Data races, hangs | Small, reviewed implementation; TSan; 10⁸-item stress test; mutex baseline for comparison; exit paths checked by tests. |
| Memory limits make output depend on worker count | Certain when limits are hit | Determinism caveat | Documented; `limits_hit` in report; determinism tests use inputs that stay within limits. |

---

## 16. Milestones

Milestones are in dependency order. Each one ends with: all existing tests green in `dev` and `asan` presets, clang-format clean, no new warnings, and the milestone's acceptance checks passing. Agents MUST NOT start a milestone until the previous one's acceptance criteria pass.

### M0: Skeleton and CI
- CMake project, presets, warning flags, `netprobe_core` + `netprobe` + empty test binary, `.clang-format`, `.clang-tidy`, CI with `build-gcc`, `build-clang`, `asan`, `lint`, `macos`.
- `netprobe --version` and `--help`.
- **Accept:** every CI job green; `ctest` runs one trivial test in each preset.

### M1: Bytes, mapped file, PCAP reader
- `util/bytes.h`, `MappedFile`, `PcapReader`, test `PacketBuilder` able to write PCAP files (both byte orders, both precisions).
- **Accept:** all reader unit cases in 11.2 pass, including every malformed-file case; reader iterates a 1 GiB synthetic file in-memory without allocations (verified with a counting allocator hook in the test).

### M2: Decoders
- `decode_packet` and per-layer parsers for the full P0 matrix; decode counters (`ReaderStats` decode portion); `netprobe dump`.
- `fuzz_decode` target + `fuzz` preset + `fuzz-smoke` CI job (fuzzing starts here, not at the end).
- Scapy `gen_fixtures.py` with the protocol fixtures (non-TCP-stream ones) and truth files.
- `compare_tshark.py` step 1 (per-packet) + `differential` CI job.
- **Accept:** truncation sweep passes for every fixture frame; every `Reason` value has a producing test; per-packet differential passes on all fixtures; `fuzz_decode` runs 10 minutes locally with no findings.

### M3: Flows, statistics, JSON, text summary (first end-to-end)
- `FlowKey`, `Analyzer` with flow table and per-direction stats (no reassembly yet), UDP and TCP flows, handshake/close tracking without reassembly, timeline, talkers, services, top-K, `merge`, `JsonWriter`, `JsonReport`, `TextSummary`, `analyze` CLI with all output flags (`--html` errors as "not yet implemented").
- Golden test harness with `UPDATE_GOLDEN`.
- `compare_tshark.py` step 2 (conversations).
- **Accept:** conversation differential passes; goldens agree with truth files; JSON parses with Python; exit codes 0/1/2/3 tested.

### M4: TCP reassembler (isolated)
- `seq.h`, `StreamReassembler`, `MemoryBudget`, `NullSink`, `RecordingSink`, reference model, property tests, `fuzz_reassembly`.
- **Accept:** all reassembler unit cases; property suite ≥ 10,000 cases in CI and 10⁶ once locally; `fuzz_reassembly` 10 min with no findings; `check_invariants` called after every operation in tests.

### M5: Reassembly integration
- Wire reassemblers into `Analyzer` (6.7), ACK watermark, snaplen holes, FIN/RST semantics, port reuse, `FileExportSink`, `--export-streams`, reassembly stats in JSON/text.
- TCP stream fixtures (`tcp_*`) and truth files with stream SHA-256 values.
- `fuzz_pcap` target.
- `compare_tshark.py` step 3 (follow streams).
- **Accept:** every TCP fixture's exported streams match truth hashes and truth gap ranges; stream differential passes on eligible streams; `fuzz_pcap` 10 min with no findings.

### M6: Bounded memory and expiry
- Two LRU lists, idle timeout, closed linger, `max_flows` eviction, per-stream and per-shard limits, `forced_flushes`, `limits_hit`, CLI flags.
- **Accept:** adversarial tests (tiny segments, SYN flood with `--max-flows 1000`, never-closing streams) keep accounted memory within limits; expiry tests cover both lists; goldens updated and reviewed.

### M7: HTML report, samples, demo (MVP complete)
- `HtmlReport` with all sections in 8.2; `samples/` (3 small captures: a clean web-like session, a lossy/reordered session, a mixed v4/v6/VLAN capture, all generated and committed); `scripts/demo.sh` (configure, build release, analyze each sample, write `out/demo/*.html|json`, print paths).
- **Accept:** HTML escaping test; size ≤ 2 MiB with 1000 flows; no external URLs in output (test greps for `http`, `//` in `src`/`href`); manual check of the demo report at desktop and 375 px widths; `demo.sh` passes in a clean Ubuntu 24.04 container.
- **MVP gate:** M0–M7 done, ASan/UBSan clean, three fuzz targets in CI.

### M8: Benchmarks, profiling, single-threaded optimization
- `synth_pcap`, D1–D3, R1 fetch script, the four micro-benchmark files, `run_e2e.sh`, first `docs/results.md` with baseline numbers and flame graph.
- Optimize only what the profile shows (candidates: cached hash in `FlowKey`, decode branch layout, `std::pmr::unsynchronized_pool_resource` per shard for segments, open addressing). Each change lands with before/after numbers or is recorded as rejected.
- **Accept:** PERF-1..5 met or explained with profile evidence; results document methodology per 12.2.

### M9: Parallel pipeline
- `SpscRing`, `Batch`, `Pipeline`, dispatcher, per-shard budgets/limits, worker error propagation, pipeline metrics in `run`, `tsan` CI job, determinism tests (O-D).
- **Accept:** determinism test passes for workers 0–8; TSan clean; worker-exception test exits 4 without hanging (test timeout 10 s); PERF-6 and PERF-7 measured and recorded; 10⁸-item ring stress passes in release.

### M10: Memory release frontier and final documentation
- `MappedFile::release_before`, per-worker completed offsets, PROT_NONE in debug; scaling and RSS results; `docs/design.md` (architecture, decision log from section 2 updated with what actually happened, invariants, limitations); final `docs/results.md`; README with quickstart, demo, results summary, limitations.
- 30-minute fuzz runs per target, stats recorded.
- **Accept:** PERF-M1 and PERF-M2 met or explained; full test suite passes in `dev` with PROT_NONE frontier on (proves O1); section 17 checklist complete.

---

## 17. Definition of done

The project is done when every item is true and verifiable from the repository:

- [ ] `netprobe analyze` and `netprobe dump` implement sections 4 and 7 exactly; exit codes per 7.3.
- [ ] The P0 support matrix (section 3) is implemented and each row has tests.
- [ ] Unit, property, integration, golden, determinism and CLI tests pass on GCC 13 and Clang 18 (Linux) and Apple Clang (macOS).
- [ ] ASan+UBSan: full suite clean. TSan: concurrency suites clean.
- [ ] Three fuzz targets exist; each ran ≥ 30 min with zero findings; stats and coverage in `results.md`; every past crash has a regression test.
- [ ] `tshark` differential (per packet, conversations, streams) passes in CI; exclusions are documented.
- [ ] Reassembly matches the reference model on ≥ 10⁶ generated cases (run recorded).
- [ ] Memory limits hold under adversarial tests; PERF-M1/M2 met or explained.
- [ ] `docs/results.md` contains hardware/software details, datasets (with R1 provenance), micro and end-to-end results (median + spread), scaling curve with Amdahl estimate, peak RSS, per-flow memory, before/after for each optimization (including rejected ones), and fuzz stats.
- [ ] PERF-1..7 met or explained with profile evidence.
- [ ] `docs/design.md` explains architecture, ownership invariants O1/O2, reassembly algorithm, determinism argument, concurrency design and its ceilings, and limitations.
- [ ] `scripts/demo.sh` produces JSON + HTML for the samples from a fresh clone in one command.
- [ ] HTML report is self-contained, escaped, readable on desktop and phone widths, light and dark.
- [ ] README states what NetProbe does and does not do (non-goals), with a quickstart and a results summary.
- [ ] No non-goal features were added; no runtime third-party dependencies.

---

## 18. Rules for implementing agents

1. **Git:** commit verified work only on your own task branch, using the repository-local identity (`Eliot Boda <eliotboda@gmail.com>`), with no AI `Co-Authored-By` or "Generated with" trailers. Never push, rebase, reset or rewrite history. The orchestrator integrates branches (see `AGENTS.md`).
2. Work milestone by milestone (section 16). Do not start a milestone before the previous one's acceptance criteria pass. Report test output as evidence, not a summary of it.
3. Write the test first for every reassembler behavior and every decode reason (red → green).
4. Never `reinterpret_cast` packet bytes to structs; never use `#pragma pack` for wire formats; always check length before reading.
5. No exceptions on the per-packet path; no per-packet logging; no heap allocation in `decode_packet`.
6. Do not add runtime dependencies, protocols, link types, CLI flags or report fields beyond this document. If something seems necessary, write it down as a proposal in `docs/design.md` under "Open proposals" and continue without it.
7. Keep the deterministic output contract: any change to JSON shape bumps `schema_version` and updates goldens with a reviewed diff.
8. Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and the upgrade path (e.g. the export sink in 6.10).
9. Style: `snake_case` for functions, variables and files; `PascalCase` for types; namespace `netprobe`; trailing `_` for private members; `.clang-format` (LLVM base, 100 columns) is authoritative.
10. Performance changes require before/after measurements recorded in `docs/results.md`. Without numbers, don't call it an optimization.
11. If this PRD is ambiguous or wrong, stop and record the question in `docs/design.md` under "Open questions" with your proposed resolution, then proceed with that resolution only if it is reversible.

---

## Appendix A: What distinguishes this project

Compared with a typical packet-parser tutorial:

- **Real TCP reassembly**, not "append payloads in arrival order": unwrapping into 64-bit offsets, a disjoint-interval out-of-order store, first-wins overlap with conflict detection, lazy gap declaration with ACK-based classification, snaplen holes, and bounded memory with overhead-aware accounting.
- **Untrusted-input discipline**: no casts onto packet memory, exhaustive truncation sweeps, three fuzz targets including a structured reassembly fuzzer, sanitizers in CI.
- **Independent correctness evidence**: construction ground truth, a naive reference model, per-packet and per-stream differential tests against `tshark`, cross-worker-count determinism.
- **Ownership made explicit and enforced**: zero-copy views into an mmap, a stated invariant about view lifetimes, and a debug mode that unmaps processed regions to prove it.
- **Concurrency with an argument**: shared-nothing shards, lock-free SPSC rings with batch recycling as backpressure, a written proof sketch of determinism, and measured scaling with an Amdahl ceiling.
- **Honest benchmarks**: layer-by-layer micro benchmarks, page-cache-warm end-to-end runs, recorded hardware, median and spread, rejected optimizations listed.

Resume bullet templates (fill in measured values only; never invent numbers):

- "Built NetProbe, a C++20 PCAP analyzer with zero-copy, bounds-checked decoding of Ethernet/VLAN/IPv4/IPv6/TCP/UDP, processing __ M packets/s (__ GiB/s) single-threaded on page-cached captures."
- "Implemented TCP stream reassembly handling reordering, retransmission, overlapping and conflicting segments, and 32-bit sequence wraparound, validated against a reference model on 10⁶ randomized cases and against `tshark` stream output."
- "Designed a sharded pipeline with lock-free SPSC rings and batch-recycling backpressure that preserves per-flow ordering and produces byte-identical reports for any worker count; __× throughput at 4 workers."
- "Hardened against malformed input with libFuzzer (__ M executions, 0 findings), ASan/UBSan/TSan in CI, and bounded memory (≤ __ B per flow, peak RSS __ MiB on a 2 GiB capture)."

---

## Appendix B: Glossary

| Term | Meaning |
|---|---|
| Delivered offset | Next expected byte offset of a TCP direction's stream, relative to its origin |
| Origin | Sequence number that maps to stream offset 0 (ISN+1, or first observed seq on mid-stream pickup) |
| Gap | A range of stream offsets declared missing at flush |
| ACKed gap | A gap entirely below the peer's highest ACK: the receiver got the bytes, the capture did not |
| Forced flush | A flush triggered by a memory limit rather than flow end |
| Shard | One `Analyzer` instance owning a disjoint set of flows |
| Release frontier | File offset below which no worker holds views; pages below it are released |
| Snaplen hole | Bytes counted in the TCP length but not captured because of snaplen |
| Top-K | Bounded heap of flow summaries ordered by `(bytes desc, flow_id asc)` |
