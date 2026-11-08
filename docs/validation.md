# Real-world validation

NetProbe was developed against synthetic captures and Scapy fixtures. This round ran it on public
captures from real networks and from tcpdump's regression suite, checked it for crashes under
sanitizers, and compared its output with tshark. It found four NetProbe bugs, several mistakes in
the comparison script itself, and a few places where tshark is wrong or simply different.

## 1. Captures and redistribution

No capture is committed to this repository. `scripts/fetch_realworld.sh` downloads them into
`datasets/realworld/` (gitignored) and verifies them.

| Source | Files | License | Pin |
|---|---|---|---|
| tcpdump test suite (`tests/*.pcap`) | 785 | BSD (tcpdump `LICENSE`) | commit `f34cf40526e1f6326138fedba2a606d1c2f089f3` |
| tcpreplay `smallFlows.pcap` | 1 (9.4 MB, 14,261 packets) | no redistribution license published | SHA-256 `77d06d3f…f75d1` |
| tcpreplay `bigFlows.pcap` | 1 (368 MB, 791,615 packets) | no redistribution license published | SHA-256 `2b630291…c42dc141` |

The tcpdump captures could be redistributed under BSD terms but are not needed in the repository.
The tcpreplay captures are public downloads without a stated license, so they are used locally only.
Regression tests derived from these files use small synthetic packets that reproduce the pattern,
not the captured bytes.

## 2. Method

1. **Robustness.** Every capture, analyzed with `-j 0` and `-j 2`, by a Clang 18
   ASan + UBSan build with hardening (`RelWithDebInfo`, `-DNETPROBE_HARDENING=ON`), in the Ubuntu
   24.04 container. A run fails if it crashes, prints a sanitizer report, or exits with anything
   other than 0 (analyzed) or 2 (input rejected).
2. **Differential.** `tests/differential/compare_tshark.py` against tshark 4.2.2 with a GCC 13
   Release build. It compares, for every record NetProbe decodes as TCP or UDP: addresses, ports,
   sequence and acknowledgment numbers, flags and payload length; per conversation, packets and
   bytes; per stream direction, the exported bytes against a rebuild of the stream from the TCP
   payloads tshark dissects. The rebuild places payloads by sequence number, first copy wins,
   which does not depend on NetProbe's reassembler. Every exclusion the script applies is counted
   in its summary and motivated by a capture in its docstring.

## 3. Results (final code)

**Robustness: no failures.** 1,574 runs: 898 analyzed (449 captures × 2 worker modes) and 676
rejected (338 captures × 2). Every rejection is `unsupported link type` (Linux cooked, raw IP,
802.11, Juniper and similar; NetProbe reads Ethernet only). No crash, no sanitizer report.

**Differential: no failures** on the 447 analyzable tcpdump captures plus `smallFlows.pcap`:

| Counter | Value |
|---|---|
| packets compared field by field | 16,795 |
| conversations compared | 916 |
| stream directions byte-compared | 1,072 |
| records not compared: not OK TCP/UDP (ARP, routing protocols, malformed, fragments) | 5,701 |
| conversations excluded: capture clock jumps past the idle timeout | 31 |
| conversations excluded: traffic more than 10 s after a FIN/RST close | 3 |
| streams excluded: gaps, conflicting overlaps, RST data or invalid flags | 26 |
| tshark follow disagrees, payload rebuild agrees with NetProbe | 1 |
| frames tshark leaves undecoded at L4 | 1 |

`smallFlows.pcap` alone: 14,209 packets, 629 conversations and 930 stream directions compared.

**bigFlows.pcap** (`--max-streams 100`, stream comparison limited for run time):
**no failures.** 786,972 packets and 27,456 conversations compared, 200 stream directions
byte-compared (22,277 not compared because of the cap). Excluded: 57 packets with IPv4 source
routes, 8 conversations with traffic after a closed-flow linger, 43 streams with gaps, conflicts
or RST data. Before the fixes in section 4, the same capture had 252 failures.

## 4. What it found

### NetProbe bugs (fixed, each with a regression test)

| Bug | Evidence | Fix | Test |
|---|---|---|---|
| An IP total length larger than the frame was treated as snaplen truncation even when the frame was not cut, so a lying header fed a phantom segment into reassembly | tcpdump `kday4.pcap`: a 66-byte frame claiming 820 bytes became a 768-byte phantom segment | truncation only when the capture cut the frame (`orig_len` covers the IP length); otherwise `malformed.bad_total_length` | `IpLengthBeyondWireLengthIsMalformedNotTruncated`, `Ipv6PayloadLengthBeyondWireLengthIsMalformed` |
| A RST segment's own payload was delivered as stream data | tcpdump `tcp_rst_data.pcap`; RFC 9293 | counted as `data_after_rst`, not delivered | `RstPayloadIsNotStreamData` |
| Retransmissions of bytes sent before a mid-stream capture started were counted out of window, and segments straddling the origin lost their new bytes | `smallFlows.pcap` (41 segments) | signed offsets: wholly old data counts as retransmission, straddling segments are trimmed | `DataBeforeMidstreamOriginIsOldNotOutOfWindow` |
| A SYN after a RST with the same ISN (a refused connection retried by the client) was merged into the refused flow | `bigFlows.pcap`; Wireshark also starts a new stream | after a RST any SYN starts a new flow | `SynAfterRstIsNewAttemptEvenWithSameIsn` |

### Comparison-script errors (fixed in the script)

- tshark decodes tunnels and embedded headers (VXLAN, Geneve, sFlow samples, ICMP errors); the
  script read inner fields. It now reads the outer header that NetProbe decodes.
- tshark's `tcp.flags` includes the AE and reserved bits; masked to the low 8 bits.
- NetProbe expires idle flows and tshark never does; NetProbe now runs with the maximum idle
  timeout and clock jumps are excluded (tcpdump's `kday*.pcap` jump years ahead).
- `tshark -z follow` was the stream oracle. On `of10_s4810.pcap` it drops bytes from a reordered
  stream that an independent payload rebuild and NetProbe agree on, so the rebuild is now the
  oracle and follow output is informational.

### Differences that are not bugs (excluded and documented)

- **Clock jumps.** NetProbe's capture clock is the largest timestamp seen, so one far-future
  timestamp idle-expires every open flow (`kday*.pcap`). Listed in design.md section 11.
- **Closed-flow linger.** FIN/RST-closed flows are finalized 10 s after their last packet (PRD
  D18); late packets start a new flow. Three conversations in `smallFlows.pcap`.
- **IPv4 source routes (LSRR/SSRR).** tshark reports the route's final destination as `ip.dst`;
  NetProbe keys on the header's destination. Traceroute probes in `bigFlows.pcap`.
- **IPv6 BIG TCP / TSO** frames with payload length 0: NetProbe decodes them, tshark 4.2 does not.
- **tshark 4.2 misparses corrupt files** (records after a bad length); those files get no
  per-packet comparison, only NetProbe's own `truncated_tail_bytes` check.

## 5. Case study: `smallFlows.pcap`

A five-minute capture from a single client network, as `netprobe analyze` reports it
(`out/realworld/smallflows.html` after running the fetch script; analysis took 15 ms on an
M3 Pro).

| | |
|---|---|
| Capture | 14,261 frames, 9.2 MB, 298.5 s; IPv4 only; 13,708 TCP, 501 UDP, 34 ICMP, 18 ARP |
| TCP flows | 488: 364 with a full handshake, 311 closed by FIN, 78 by RST, 99 still open at the end |
| Complete streams | 375 |
| Services | HTTP 329 flows (5.7 MiB), HTTPS 71 flows (2.0 MiB), port 5480 37 flows, port 8443 11 flows |
| Top talker | 192.168.3.131: 374 flows, 7.1 MiB (the client behind most of the traffic) |

**What a responder would conclude.** 18 TCP flows have gaps: 49 holes, 301,459 bytes
(294 KiB) missing. Every missing byte was later acknowledged by the receiver
(`acked_gap_bytes == gap_bytes`), so the data crossed the network and the *capture* dropped it.
The network itself was healthy: only 61 segments (8,122 bytes) were retransmitted and 91 arrived
out of order across 8.4 MB of delivered stream data. The practical consequence is that the
affected HTTP bodies cannot be rebuilt from this file. The worst case is a port-80 download
(flow 1189) that is 80,448 bytes short even though it closed cleanly with a FIN. Packet loss
statistics from tools that count retransmissions alone would not show this; it is visible only
because the reassembler checks gaps against the peer's ACKs.

## 6. Reproduce

```bash
scripts/fetch_realworld.sh
docker build -t netprobe-dev:24.04 tools/docker
docker run --rm -v "$PWD":/src -w /src netprobe-dev:24.04 bash -c '
  CXX=g++-13 cmake -S . -B /tmp/r -G Ninja -DCMAKE_BUILD_TYPE=Release -DNETPROBE_BUILD_TESTS=OFF &&
  cmake --build /tmp/r --target netprobe &&
  for f in datasets/realworld/tcpdump/tests/*.pcap datasets/realworld/smallFlows.pcap; do
    python3 tests/differential/compare_tshark.py --netprobe /tmp/r/netprobe "$f"; done'
```
