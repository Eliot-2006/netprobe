# Implementation plan

Milestones follow PRD §16. Status: `todo` · `in progress` · `done` (verified by the orchestrator).
Integration branch: `netprobe-cpp-prd-b41031f2`. Worker branches are merged with `--no-ff` after review.

| Milestone | Scope | Built by | Status |
|---|---|---|---|
| M0 | CMake/presets, warnings, shared headers, CI | orchestrator | done |
| M1+M2 | MappedFile, PcapReader, decoders, PacketBuilder, fuzz_decode/fuzz_pcap | worker `decode` (Claude Sonnet) | done |
| M3 | FlowKey, Analyzer, stats, JSON, text summary, `analyze`/`dump`, goldens, fixtures, tshark differential | orchestrator | done |
| M4 | seq.h, StreamReassembler, reference model, property tests, fuzz_reassembly | worker `reasm` (Codex) | done |
| M5 | Reassembly integration, export sink, truth tests | orchestrator | done |
| M6 | Expiry, eviction, limits, adversarial analyzer tests | orchestrator | done |
| M7 | HTML report (Impeccable: PRODUCT.md, direction, finish review, DESIGN.md), samples, demo | orchestrator + Impeccable reviewer/documenter subagents | done |
| M8 | synth_pcap, Google Benchmark suites, e2e harness, baseline results.md | worker `bench` (Claude Sonnet) | done (macOS baseline) |
| M8b | D7 revision: release ACKed holes (measured: forced flushes 29 → 0) | orchestrator | done |
| M9 | SPSC ring, sharded pipeline, determinism, TSan | worker `pipeline` (Codex) | done |
| M10a | Release frontier (MADV_DONTNEED / PROT_NONE debug guard) | worker `pipeline` (Codex) | done |
| M10b | docs/design.md, README | worker `docs` (Claude Sonnet) | done |
| M10c | Linux scaling + RSS measurements, 30-min fuzz campaign, final results.md | orchestrator | done |
| Review | Independent core review (Antigravity / Gemini 3.8 Flash): 4 fixed, 1 rejected, 4 documented | worker `review` | done |
