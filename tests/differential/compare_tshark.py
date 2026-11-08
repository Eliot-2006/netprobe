#!/usr/bin/env python3
"""Differential test against tshark (PRD 11.5, oracle O-C).

1. Per packet: `netprobe dump` vs `tshark -T fields` (addresses, ports, seq/ack, flags, tcp.len)
   for every record NetProbe decodes as OK TCP/UDP.
2. Conversations: packets and frame bytes per TCP/UDP conversation (tshark tcp.stream /
   udp.stream) vs NetProbe flow summaries.
3. Streams: NetProbe's exported bytes vs a rebuild of the stream from the TCP payloads tshark
   dissects (placed by sequence number, first copy wins, same origin rule as NetProbe). This is
   independent of NetProbe's reassembler and, unlike `tshark -z follow`, correct for reordered and
   retransmitted streams. `tshark -z follow` is still consulted for streams without reordering or
   retransmission, and its disagreements are reported but adjudicated by the rebuild.

Comparison rules, each motivated by a capture where a naive comparison was wrong:
- Outer headers only. tshark also decodes tunnels and embedded headers (VXLAN, Geneve, sFlow
  samples, ICMP errors); fields are chosen by the IP version and L4 protocol NetProbe decoded, so
  the first-occurrence field is the outer one.
- TCP flags: the low 8 bits (tshark includes AE/NS and reserved bits).
- NetProbe runs with the maximum idle timeout; tshark never expires flows. Conversations are
  excluded when the capture clock (running maximum timestamp) passes their start plus the idle
  timeout before their last packet (clock jumps, e.g. tcpdump's kday*.pcap), and when packets
  continue more than 10 s after NetProbe closed the flow by FIN/RST (closed-flow linger, D18;
  seen in tcpreplay's smallFlows.pcap).
- Records NetProbe reports as malformed or unsupported, IP fragments, and records past the point
  where NetProbe stops reading a truncated/corrupt file are not compared per packet. tshark 4.2
  misparses corrupt files, so those get no per-packet comparison at all.
- Streams with gaps, conflicting overlaps, data after RST, or segments with invalid flag
  combinations (not reassembled by design, FR-DEC-8) are not byte-compared.
- IPv4 packets with source-route options (LSRR/SSRR): tshark reports the route's final
  destination as ip.dst, NetProbe keys flows on the header's destination (next hop). Seen as
  traceroute probes in tcpreplay's bigFlows.pcap; excluded per packet and per conversation.
- Frames tshark leaves undecoded at L4 while NetProbe decodes them (e.g. IPv6 BIG TCP / TSO with
  payload length 0) are counted, not failed.

Usage: compare_tshark.py --netprobe build/release/netprobe [--max-streams N] capture.pcap
"""

import argparse
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

IDLE_TIMEOUT_S = 86400  # NetProbe's maximum --idle-timeout
CLOSED_LINGER_S = 10    # PRD D18: FIN/RST-closed flows are finalized 10 s after their last packet
FIELDS = ["frame.number", "frame.len", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src",
          "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.seq_raw",
          "tcp.ack_raw", "tcp.flags", "tcp.len", "tcp.stream", "udp.stream"]


def tshark_rows(cmd_tail, fields):
    cmd = ["tshark", "-n", "-o", "tcp.relative_sequence_numbers:FALSE", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"] + cmd_tail
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        vals = line.split("\t")
        vals += [""] * (len(fields) - len(vals))
        rows.append(dict(zip(fields, vals)))
    return rows


def netprobe_dump(netprobe, pcap):
    out = subprocess.run([netprobe, "dump", str(pcap)], capture_output=True, text=True).stdout
    lines = out.splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, l.split("\t"))) for l in lines[1:]]


def epoch(text):
    """tshark's frame.time_epoch, or None when it prints something unparseable (fuzzed files)."""
    try:
        return float(text)
    except ValueError:
        return None


def flags_invalid(f):
    syn = f & 0x02
    return bool((syn and f & 0x01) or (syn and f & 0x04) or f == 0)


def rebuild_streams(pcap, stream):
    """Per-direction first-wins rebuild from tshark-dissected payloads, keyed by 'ip:port'."""
    rows = tshark_rows(["-r", str(pcap), "-Y", f"tcp.stream eq {stream}"],
                       ["ip.src", "ipv6.src", "tcp.srcport", "tcp.seq_raw", "tcp.flags",
                        "tcp.payload"])
    dirs = {}
    for r in rows:
        if not r["tcp.seq_raw"] or not r["tcp.flags"]:
            continue  # tshark could not dissect this segment's header
        src = r["ip.src"] or r["ipv6.src"]
        key = f"[{src}]:{r['tcp.srcport']}" if ":" in src else f"{src}:{r['tcp.srcport']}"
        seq, flags = int(r["tcp.seq_raw"]), int(r["tcp.flags"], 16) & 0xFF
        if flags_invalid(flags):
            continue
        d = dirs.setdefault(key, {"origin": None, "bytes": {}})
        start = (seq + 1) & 0xFFFFFFFF if flags & 0x02 else seq
        if d["origin"] is None:
            d["origin"] = start  # SYN: ISN+1; mid-stream: first observed sequence number
        rel = (start - d["origin"]) & 0xFFFFFFFF
        if rel >= 1 << 31:
            continue  # behind the origin
        for i, b in enumerate(bytes.fromhex(r["tcp.payload"].replace(":", ""))):
            d["bytes"].setdefault(rel + i, b)
    out = {}
    for key, d in dirs.items():
        buf = d["bytes"]
        n = max(buf) + 1 if buf else 0
        out[key] = None if len(buf) != n else bytes(buf[i] for i in range(n))  # None: holes
    return out


def follow_raw(pcap, stream):
    out = subprocess.run(["tshark", "-n", "-r", str(pcap), "-q", "-z",
                          f"follow,tcp,raw,{stream}"], capture_output=True, text=True).stdout
    nodes, data = {}, {0: bytearray(), 1: bytearray()}
    for line in out.splitlines():
        if line.startswith("Node 0:") or line.startswith("Node 1:"):
            nodes[int(line[5])] = line.split(": ", 1)[1].strip()
        elif len(nodes) == 2 and line.strip() and not line.startswith("====="):
            data[1 if line.startswith("\t") else 0] += bytes.fromhex(line.strip())
    return {nodes.get(k): bytes(v) for k, v in data.items()}


def endpoint_text(ep):
    a = ep["address"]
    return f"[{a}]:{ep['port']}" if ":" in a else f"{a}:{ep['port']}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netprobe", required=True)
    ap.add_argument("--max-streams", type=int, default=None,
                    help="byte-compare at most N eligible TCP streams")
    ap.add_argument("pcap")
    args = ap.parse_args()
    pcap = Path(args.pcap)
    failures = []
    stats = collections.Counter()

    with tempfile.TemporaryDirectory() as td:
        js, streams = Path(td) / "r.json", Path(td) / "streams"
        subprocess.run([args.netprobe, "analyze", str(pcap), "-q", "--deterministic",
                        "--top-flows", "100000", "--idle-timeout", str(IDLE_TIMEOUT_S),
                        "--json", str(js), "--export-streams", str(streams)],
                       capture_output=True)
        rep = json.loads(js.read_text())
        cap_status = rep["capture"]["status"]
        flows = {f["id"]: f for f in rep["flows"]["top_by_bytes"]}

        ts = tshark_rows(["-r", str(pcap)], FIELDS)
        npd = netprobe_dump(args.netprobe, pcap)
        if len(ts) != len(npd) and cap_status == "complete":
            failures.append(f"record count: tshark {len(ts)} vs netprobe {len(npd)}")
        ts = ts[:len(npd)]  # truncated/corrupt files: compare the readable prefix
        source_routed = {int(r["frame.number"]) - 1 for r in tshark_rows(
            ["-r", str(pcap), "-Y", "ip.opt.type.number == 3 || ip.opt.type.number == 9"],
            ["frame.number"]) if r["frame.number"]}

        # 1. per packet
        for t, n in zip(ts, npd):
            if int(n["index"]) in source_routed:
                stats["skipped_ipv4_source_route"] += 1
                continue
            if cap_status == "corrupt":
                stats["skipped_corrupt_file"] += 1
                continue
            if n["status"] != "ok" or not n["sport"]:
                stats["skipped_not_ok_l4"] += 1
                continue
            tcp = n["proto"] == "6"
            v4 = n["ip_ver"] == "4"
            sport = t["tcp.srcport" if tcp else "udp.srcport"]
            if not sport:
                stats["tshark_no_l4_decode"] += 1  # e.g. IPv6 BIG TCP with payload length 0
                continue
            want = {"src": t["ip.src" if v4 else "ipv6.src"],
                    "dst": t["ip.dst" if v4 else "ipv6.dst"], "sport": sport,
                    "dport": t["tcp.dstport" if tcp else "udp.dstport"]}
            got = {k: n[k] for k in want}
            if tcp:
                tflags = int(t["tcp.flags"], 16) & 0xFF if t["tcp.flags"] else -1
                want.update(seq=t["tcp.seq_raw"], flags=str(tflags), len=t["tcp.len"])
                got.update(seq=n["tcp_seq"], flags=str(int(n["tcp_flags"], 16)), len=n["tcp_len"])
                if int(n["tcp_flags"], 16) & 0x10:
                    want["ack"], got["ack"] = t["tcp.ack_raw"], n["tcp_ack"]
            if want != got:
                failures.append(f"record {n['index']}: tshark {want} != netprobe {got}")
            stats["packets_compared"] += 1

        # 2. conversations, keyed by the L4 protocol NetProbe decoded (outer headers)
        clock, now = [], float("-inf")
        for t in ts:
            tm = epoch(t["frame.time_epoch"])
            now = max(now, tm) if tm is not None else now
            clock.append(now)
        conv = {}
        for i, t in enumerate(ts):
            n = npd[i]
            if n["status"] != "ok" or not n["sport"] or i in source_routed:
                continue
            key = ("tcp", t["tcp.stream"]) if n["proto"] == "6" else ("udp", t["udp.stream"])
            if not key[1]:
                continue
            c = conv.setdefault(key, {"first": i, "packets": 0, "bytes": 0, "t0": None,
                                      "t1": None, "bad_flags": False})
            c["packets"] += 1
            c["last"] = i
            c["bytes"] += int(t["frame.len"])
            tm = epoch(t["frame.time_epoch"])
            if tm is None:
                c["bad_time"] = True
            else:
                c["t0"] = tm if c["t0"] is None else min(c["t0"], tm)
                c["t1"] = tm if c["t1"] is None else max(c["t1"], tm)
            if n["proto"] == "6" and flags_invalid(int(n["tcp_flags"], 16)):
                c["bad_flags"] = True

        compared_streams = 0
        for (proto, sid), c in sorted(conv.items(), key=lambda kv: kv[1]["first"]):
            if c.get("bad_time") or c["t0"] is None:
                stats["conversations_excluded_unparseable_time"] += 1
                continue
            if clock[c["last"]] - c["t0"] > IDLE_TIMEOUT_S:
                stats["conversations_excluded_clock_passes_idle_timeout"] += 1
                continue
            f = flows.get(c["first"])
            if f is None or f["proto"] != proto:
                failures.append(f"{proto} stream {sid}: no netprobe flow starting at record "
                                f"{c['first']}")
                continue
            got_p = f["c2s"]["packets"] + f["s2c"]["packets"]
            got_b = f["c2s"]["bytes"] + f["s2c"]["bytes"]
            if (got_p, got_b) != (c["packets"], c["bytes"]) and f["close_reason"] in ("fin", "rst") \
                    and c["t1"] > f["last_ts_ns"] / 1e9 + CLOSED_LINGER_S:
                stats["conversations_excluded_traffic_after_closed_linger"] += 1
                continue
            if (got_p, got_b) != (c["packets"], c["bytes"]):
                failures.append(f"{proto} stream {sid} (flow {f['id']}): tshark "
                                f"{c['packets']} pkts/{c['bytes']} B vs netprobe {got_p}/{got_b}")
            stats["conversations_compared"] += 1

            # 3. stream bytes
            if proto != "tcp":
                continue
            if c["bad_flags"] or not all(
                    f[d]["gap_count"] == 0 and f[d]["conflicting_overlap_bytes"] == 0
                    and f[d]["data_after_rst"] == 0 for d in ("c2s", "s2c")):
                stats["streams_excluded_gaps_conflicts_rst_or_invalid_flags"] += 1
                continue
            if args.max_streams is not None and compared_streams >= args.max_streams:
                stats["streams_not_compared_cap"] += 1
                continue
            compared_streams += 1
            rebuilt = rebuild_streams(pcap, sid)
            simple = all(f[d]["out_of_order_segments"] == 0 and f[d]["retransmitted_bytes"] == 0
                         for d in ("c2s", "s2c"))
            followed = follow_raw(pcap, sid) if simple else {}
            for d, ep in (("c2s", f["client"]), ("s2c", f["server"])):
                p = streams / f"{f['id']}_{d}.bin"
                mine = p.read_bytes() if p.exists() else b""
                want = rebuilt.get(endpoint_text(ep), b"")
                if want is None:
                    stats["stream_dirs_rebuild_has_holes"] += 1
                    continue
                if mine != want:
                    failures.append(f"tcp stream {sid} {d}: payload rebuild {len(want)} B vs "
                                    f"netprobe {len(mine)} B (content differs)")
                elif simple and followed.get(endpoint_text(ep), b"") != mine:
                    stats["tshark_follow_disagrees_rebuild_agrees"] += 1
                stats["stream_dirs_compared"] += 1

    for f in failures:
        print("FAIL", f)
    print(f"{pcap.name}: " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())) +
          f", failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
