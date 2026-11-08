#!/usr/bin/env python3
"""Differential test against tshark (PRD 11.5, oracle O-C).

  1. Per packet: `netprobe dump` vs `tshark -T fields` (addresses, ports, seq/ack, flags, tcp.len)
     for every record NetProbe decodes as OK TCP/UDP.
  2. Conversations: packets and frame bytes per TCP/UDP conversation (tshark tcp.stream /
     udp.stream) vs NetProbe flow summaries.
  3. Streams: `tshark -z follow,tcp,raw` bytes vs NetProbe --export-streams files, for streams
     NetProbe reports with zero gaps and zero conflicting overlaps.

Documented exclusions: IP fragments (tshark reassembles them), streams with gaps or conflicting
overlaps (overlap policies differ), streams with data after RST (dropped by design, FR-TCP-9),
malformed/unsupported records (dissectors disagree on partial data).
Usage: compare_tshark.py --netprobe build/release/netprobe capture.pcap
"""

import argparse
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

FIELDS = ["frame.number", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.seq_raw",
          "tcp.ack_raw", "tcp.flags", "tcp.len", "tcp.stream", "udp.stream", "ip.flags.mf",
          "ip.frag_offset", "ipv6.fragment"]


def tshark_fields(pcap):
    cmd = ["tshark", "-n", "-r", str(pcap), "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=f", "-o", "tcp.relative_sequence_numbers:FALSE"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        vals = line.split("\t")
        vals += [""] * (len(FIELDS) - len(vals))
        rows.append(dict(zip(FIELDS, vals)))
    return rows


def netprobe_dump(netprobe, pcap):
    out = subprocess.run([netprobe, "dump", str(pcap)], capture_output=True, text=True).stdout
    lines = out.splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, l.split("\t"))) for l in lines[1:]]


def follow_raw(pcap, stream):
    out = subprocess.run(["tshark", "-n", "-r", str(pcap), "-q", "-z",
                          f"follow,tcp,raw,{stream}"], capture_output=True, text=True).stdout
    nodes, data = {}, {0: bytearray(), 1: bytearray()}
    for line in out.splitlines():
        if line.startswith("Node 0:") or line.startswith("Node 1:"):
            nodes[int(line[5])] = line.split(": ", 1)[1].strip()
        elif len(nodes) == 2 and line.strip() and not line.startswith("====="):
            node = 1 if line.startswith("\t") else 0
            data[node] += bytes.fromhex(line.strip())
    return nodes, data


def endpoint_text(ep):
    a = ep["address"]
    return f"[{a}]:{ep['port']}" if ":" in a else f"{a}:{ep['port']}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netprobe", required=True)
    ap.add_argument("pcap")
    args = ap.parse_args()
    pcap = Path(args.pcap)
    failures = []
    stats = collections.Counter()

    ts = tshark_fields(pcap)
    npd = netprobe_dump(args.netprobe, pcap)
    if len(ts) != len(npd):
        failures.append(f"record count: tshark {len(ts)} vs netprobe {len(npd)}")

    # 1. per packet
    for t, n in zip(ts, npd):
        if n["status"] != "ok" or not n["sport"]:
            stats["skipped_not_ok_l4"] += 1
            continue
        src = t["ip.src"] or t["ipv6.src"]
        dst = t["ip.dst"] or t["ipv6.dst"]
        tcp = n["proto"] == "6"
        want = {"src": src, "dst": dst,
                "sport": t["tcp.srcport"] if tcp else t["udp.srcport"],
                "dport": t["tcp.dstport"] if tcp else t["udp.dstport"]}
        got = {k: n[k] for k in want}
        if tcp:
            want.update(seq=t["tcp.seq_raw"], ack=t["tcp.ack_raw"],
                        flags=str(int(t["tcp.flags"], 16)) if t["tcp.flags"] else "",
                        len=t["tcp.len"])
            got.update(seq=n["tcp_seq"], ack=n["tcp_ack"], flags=str(int(n["tcp_flags"], 16)),
                       len=n["tcp_len"])
            if not (int(n["tcp_flags"], 16) & 0x10):
                want.pop("ack")
                got.pop("ack")
        if want != got:
            failures.append(f"record {n['index']}: tshark {want} != netprobe {got}")
        stats["packets_compared"] += 1

    with tempfile.TemporaryDirectory() as td:
        js, streams = Path(td) / "r.json", Path(td) / "streams"
        subprocess.run([args.netprobe, "analyze", str(pcap), "-q", "--deterministic",
                        "--top-flows", "100000", "--json", str(js), "--export-streams",
                        str(streams)], capture_output=True)
        rep = json.loads(js.read_text())
        flows = {f["id"]: f for f in rep["flows"]["top_by_bytes"]}

        # 2. conversations: group tshark frames by stream index; key by first frame index
        conv = {}
        for i, t in enumerate(ts):
            if npd[i]["status"] != "ok" or not npd[i]["sport"]:
                continue
            key = ("tcp", t["tcp.stream"]) if t["tcp.stream"] else ("udp", t["udp.stream"])
            if not key[1]:
                continue
            c = conv.setdefault(key, {"first": i, "packets": 0, "bytes": 0})
            c["packets"] += 1
            c["bytes"] += int(t["frame.len"])
        for (proto, sid), c in sorted(conv.items()):
            f = flows.get(c["first"])
            if f is None or f["proto"] != proto:
                failures.append(f"{proto} stream {sid}: no netprobe flow starting at record "
                                f"{c['first']}")
                continue
            got_p = f["c2s"]["packets"] + f["s2c"]["packets"]
            got_b = f["c2s"]["bytes"] + f["s2c"]["bytes"]
            if (got_p, got_b) != (c["packets"], c["bytes"]):
                failures.append(f"{proto} stream {sid} (flow {f['id']}): tshark "
                                f"{c['packets']} pkts/{c['bytes']} B vs netprobe "
                                f"{got_p}/{got_b}")
            stats["conversations_compared"] += 1

            # 3. stream bytes
            if proto != "tcp":
                continue
            # Exclusions: gaps, conflicting overlaps (policies differ) and data after RST
            # (NetProbe drops it by design, FR-TCP-9; tshark follow keeps it).
            clean = all(f[d]["gap_count"] == 0 and f[d]["conflicting_overlap_bytes"] == 0
                        and f[d]["data_after_rst"] == 0 for d in ("c2s", "s2c"))
            if not clean:
                stats["streams_excluded_gaps_or_conflicts"] += 1
                continue
            nodes, data = follow_raw(pcap, sid)
            client = endpoint_text(f["client"])
            for node in (0, 1):
                d = "c2s" if nodes.get(node) == client else "s2c"
                p = streams / f"{f['id']}_{d}.bin"
                mine = p.read_bytes() if p.exists() else b""
                if mine != bytes(data[node]):
                    failures.append(f"tcp stream {sid} {d}: tshark {len(data[node])} B vs "
                                    f"netprobe {len(mine)} B (content differs)")
            stats["streams_compared"] += 1

    for f in failures:
        print("FAIL", f)
    print(f"{pcap.name}: " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())) +
          f", failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
