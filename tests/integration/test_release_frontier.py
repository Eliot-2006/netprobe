#!/usr/bin/env python3
"""Regression: the mapping release frontier bounds RSS in pipeline mode even when the capture is
dominated by packets that never reach a worker (independent audit finding). Before the fix, a
mostly-ARP capture kept the whole file resident with --workers N (294 MiB for a 290 MB file vs
68 MiB inline). Linux only: MADV_DONTNEED does not reduce RSS on macOS.
"""

import argparse
import json
import os
import platform
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

RECORDS = 3_000_000  # ~225 MB


def write_capture(path):
    arp = bytes.fromhex("ffffffffffff020000000001" "0806") + bytes(46)
    ip = bytearray(bytes.fromhex("450000240000400040110000") + bytes([10, 0, 0, 1, 10, 0, 0, 2]))
    s = sum(struct.unpack("!10H", bytes(ip)))
    s = (s & 0xFFFF) + (s >> 16)
    ip[10:12] = struct.pack("!H", ~s & 0xFFFF)
    udp = (bytes.fromhex("020000000002020000000001" "0800") + bytes(ip) +
           struct.pack("!HHHH", 5000, 53, 16, 0) + bytes(12))
    rec_arp = struct.pack("<IIII", 1_700_000_000, 0, len(arp), len(arp)) + arp
    rec_udp = struct.pack("<IIII", 1_700_000_000, 0, len(udp), len(udp)) + udp
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        chunk = (rec_arp * 4999 + rec_udp) * 20
        for _ in range(RECORDS // 100_000):
            out.write(chunk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netprobe", required=True)
    ap.add_argument("--source-dir", required=True)
    args = ap.parse_args()
    if platform.system() != "Linux":
        print("skipped: RSS release is only effective on Linux")
        return 0
    if os.environ.get("NETPROBE_SANITIZED"):
        print("skipped: sanitizer shadow memory makes RSS meaningless")
        return 0
    with tempfile.TemporaryDirectory() as td:
        pcap = Path(td) / "mostly_arp.pcap"
        write_capture(pcap)
        size = pcap.stat().st_size
        failures = 0
        for workers in (0, 2):
            out = subprocess.run([args.netprobe, "analyze", str(pcap), "-q", "-j", str(workers),
                                  "--json", "-"], capture_output=True, text=True, check=True)
            rss = json.loads(out.stdout)["run"]["peak_rss_bytes"]
            ok = rss < size * 0.75
            failures += not ok
            print(f"workers={workers} file={size >> 20} MiB peak_rss={rss >> 20} MiB "
                  f"{'ok' if ok else 'FAIL (whole file resident?)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
