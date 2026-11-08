#!/usr/bin/env python3
"""Checks NetProbe output against generator ground truth (PRD 11.4, oracle O-A).

For every tests/fixtures/*.pcap with a .truth.json: run `analyze --deterministic --json` with
`--export-streams`, then compare status, record counts, layers, decode errors, anomalies, flow
counts, and per-stream delivered bytes (SHA-256 of exported files) and gap lists.
Golden files are NOT consulted: this test is independent of them.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run(netprobe, pcap, outdir):
    js = outdir / "report.json"
    streams = outdir / "streams"
    p = subprocess.run([netprobe, "analyze", str(pcap), "--deterministic", "-q", "--json", str(js),
                        "--export-streams", str(streams)], capture_output=True, text=True)
    return p.returncode, json.loads(js.read_text()), streams, p.stderr


def check_fixture(netprobe, pcap, truth, failures):
    name = truth["fixture"]

    def fail(msg):
        failures.append(f"{name}: {msg}")

    with tempfile.TemporaryDirectory() as td:
        code, rep, streams, stderr = run(netprobe, pcap, Path(td))
        want_code = 0 if truth["status"] == "complete" else 3
        if code != want_code:
            fail(f"exit code {code}, want {want_code} ({stderr.strip()})")
        cap = rep["capture"]
        if cap["status"] != truth["status"]:
            fail(f"status {cap['status']} != {truth['status']}")
        if cap["records"] != truth["records"]:
            fail(f"records {cap['records']} != {truth['records']}")
        for k in ("truncated_tail_bytes", "records_truncated_by_snaplen", "timestamp_regressions"):
            if k in truth and cap[k] != truth[k]:
                fail(f"capture.{k} {cap[k]} != {truth[k]}")
        for layer, n in truth.get("layers", {}).items():
            got = rep["decode"]["layers"][layer]
            if got != n:
                fail(f"layers.{layer} {got} != {n}")
        for vlan, n in truth.get("vlans", {}).items():
            got = rep["decode"]["vlans"].get(vlan, 0)
            if got != n:
                fail(f"vlans.{vlan} {got} != {n}")
        if "decode_errors" in truth:
            got = {f"{kind}.{k}": v for kind, group in rep["decode"]["errors"].items()
                   for k, v in group.items()}
            if got != truth["decode_errors"]:
                fail(f"decode errors {got} != {truth['decode_errors']}")
        for k, n in truth.get("anomalies", {}).items():
            key = "ip_zero_length" if k == "ipv4_zero_total_length" else k
            if rep["decode"]["anomalies"][key] != n:
                fail(f"anomalies.{k} {rep['decode']['anomalies'][key]} != {n}")
        for proto, n in truth.get("flows", {}).items():
            got = rep["flows"][proto]["total"]
            if got != n:
                fail(f"flows.{proto} {got} != {n}")

        ra = rep["reassembly"]
        for key, field in (("min_out_of_order_segments", "out_of_order_segments"),
                           ("min_retransmitted_bytes", "retransmitted_bytes"),
                           ("min_conflicting_overlap_bytes", "conflicting_overlap_bytes"),
                           ("min_data_after_rst", "data_after_rst")):
            if key in truth and ra[field] < truth[key]:
                fail(f"reassembly.{field} {ra[field]} < {truth[key]}")

        flows = sorted((f for f in rep["flows"]["top_by_bytes"] if f["proto"] == "tcp"),
                       key=lambda f: f["id"])
        used = set()
        for st in truth.get("streams", []):
            match = [f for f in flows if f["id"] not in used
                     and [f["client"]["address"], f["client"]["port"]] == st["client"]
                     and [f["server"]["address"], f["server"]["port"]] == st["server"]]
            if not match:
                fail(f"no flow {st['client']} -> {st['server']}")
                continue
            f = match[0]
            used.add(f["id"])
            if f["handshake"] != st["handshake"] and not (
                    st["handshake"] == "full" and f["handshake"] == "full"):
                fail(f"flow {f['id']} handshake {f['handshake']} != {st['handshake']}")
            if f["close_reason"] != st["close"] and not (
                    f["close_reason"] == "reused" and st["close"] == "fin"):
                fail(f"flow {f['id']} close {f['close_reason']} != {st['close']}")
            for d in ("c2s", "s2c"):
                want = st[d]
                path = streams / f"{f['id']}_{d}.bin"
                data = path.read_bytes() if path.exists() else b""
                if len(data) != want["length"] or hashlib.sha256(data).hexdigest() != want["sha256"]:
                    fail(f"flow {f['id']} {d}: delivered {len(data)} bytes, sha mismatch or "
                         f"length != {want['length']}")
                got_gaps = [[g["offset"], g["length"], g["acked"]] for g in f[d]["gaps"]]
                if got_gaps != want["gaps"]:
                    fail(f"flow {f['id']} {d}: gaps {got_gaps} != {want['gaps']}")
                if want["conflict"] != (f[d]["conflicting_overlap_bytes"] > 0):
                    fail(f"flow {f['id']} {d}: conflict flag mismatch "
                         f"({f[d]['conflicting_overlap_bytes']} conflicting bytes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netprobe", required=True)
    ap.add_argument("--source-dir", required=True)
    args = ap.parse_args()
    fixtures = Path(args.source_dir) / "tests" / "fixtures"
    failures = []
    count = 0
    for truth_path in sorted(fixtures.glob("*.truth.json")):
        truth = json.loads(truth_path.read_text())
        pcap = truth_path.with_name(truth["fixture"] + ".pcap")
        check_fixture(args.netprobe, pcap, truth, failures)
        count += 1
    for f in failures:
        print("FAIL", f)
    print(f"{count} fixtures checked, {len(failures)} failures")
    return 1 if failures or count == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
