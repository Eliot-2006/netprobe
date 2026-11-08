# Implementation plan

Milestones follow PRD §16. Status: `todo` · `in progress` · `done` (verified by the orchestrator).

| Milestone | Scope | Owner | Status |
|---|---|---|---|
| M0 | CMake/presets, warnings, shared headers, CI | orchestrator | done |
| M1+M2 | MappedFile, PcapReader, decoders, PacketBuilder, fuzz_decode/fuzz_pcap(reader) | worker `decode` (Claude Sonnet) | in progress |
| M4 | seq.h, StreamReassembler, reference model, property tests, fuzz_reassembly | worker `reasm` (Codex) | in progress |
| M3a | JsonWriter, CLI option parser, Scapy fixture generator, CI | orchestrator | in progress |
| M3b | FlowKey, Analyzer (flows/stats/top-K), merge, JSON report, text summary, `analyze`/`dump` | orchestrator | todo (needs M2) |
| M5 | Reassembly integration, export sink, tshark differential | todo (needs M3b, M4) | todo |
| M6 | Expiry, eviction, limits | todo | todo |
| M7 | HTML report (Impeccable), samples, demo | todo | todo |
| M8 | synth_pcap, benchmarks, profiling, results.md | todo | todo |
| M9 | SPSC ring, pipeline, determinism, TSan | todo | todo |
| M10 | Release frontier, design.md, final docs | todo | todo |

## Integration order

1. M0 committed on `netprobe-cpp-prd-b41031f2` (integration branch).
2. Worker branches `np-decode` and `np-reasm` cut from M0; merged back with `git merge --no-ff` after
   orchestrator review + full test run in `dev` and `asan`.
3. Later milestones build on the integration branch.
