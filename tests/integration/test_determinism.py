#!/usr/bin/env python3
"""Compare raw deterministic reports across inline and sharded execution (PRD O-D)."""

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path


def checksum(data):
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def generate_capture(path, count=200_000):
    """Interleaved TCP with reorder/loss/reuse plus UDP; >64 MiB exercises both frontiers."""
    payload = bytes(range(256)) * 2
    with Path(path).open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            flow = i % 256
            phase = (i // 256) % 8
            epoch = i // (256 * 8)
            src, dst = bytes((10, 0, flow, 1)), bytes((10, 1, flow, 2))
            port, server = 10000 + flow, 443
            base = 1000 + epoch * 10000
            proto = 6
            flags, seq, ack, body = 0x10, base + 1, 0, b""
            if phase == 0:
                flags, seq = 0x02, base
            elif phase in (1, 2, 3, 4):
                segment = {1: 0, 2: 2, 3: 1, 4: 3}[phase]
                seq, body = base + 1 + segment * len(payload), payload
                if phase == 3 and flow % 7 == 0:
                    proto = 17  # drop this TCP segment, replace it with a UDP record
            elif phase == 5:
                src, dst, port, server = dst, src, server, port
                seq, ack = 9000, base + 1 + 4 * len(payload)
            elif phase == 6:
                flags, seq = 0x14, base + 1 + 4 * len(payload)
            else:
                proto, body = 17, payload
            # Keep one OOO segment from the first pages alive until after both frontiers
            # have passed it, then fill its hole. A retained mapping view will fault in dev.
            if i == 256:
                seq = 1001 + len(payload)
            elif flow == 0 and i > 256:
                proto, body = 17, payload
            if i >= count - 2:
                src, dst = bytes((10, 0, 0, 1)), bytes((10, 1, 0, 2))
                port, server, proto = 10000, 443, 6
                flags, seq, ack, body = 0x10, 1001, 0, payload
                if i == count - 2:
                    seq += len(payload)  # overlapping OOO retransmission must read owned bytes
            if proto == 6:
                transport = struct.pack("!HHIIBBHHH", port, server, seq, ack,
                                        0x50, flags, 65535, 0, 0) + body
            else:
                transport = struct.pack("!HHHH", port, 53, 8 + len(body), 0) + body
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport),
                             0, 0, 64, proto, 0, src, dst)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            frame = b"\0" * 12 + b"\x08\x00" + ip + transport
            out.write(struct.pack("<IIII", 1 + i // 1_000_000, i % 1_000_000,
                                  len(frame), len(frame)))
            out.write(frame)


def compare(netprobe, source, capture):
    reference = None
    for workers in (0, 1, 2, 4, 8):
        proc = subprocess.run([netprobe, "analyze", str(capture), "--deterministic",
                               "--json", "-", "-j", str(workers)], cwd=source,
                              capture_output=True, timeout=120)
        if proc.returncode not in (0, 3):
            raise AssertionError(f"{capture.name}, -j {workers}: exit {proc.returncode}: "
                                 f"{proc.stderr.decode(errors='replace')}")
        report = json.loads(proc.stdout)
        if report["reassembly"]["limits_hit"]:
            raise AssertionError(f"{capture.name}: memory limit hit")
        if reference is None:
            reference = (proc.returncode, proc.stdout)
        elif (proc.returncode, proc.stdout) != reference:
            raise AssertionError(f"{capture.name}: -j {workers} differs from inline output")
    print(f"{capture.name}: identical for workers 0,1,2,4,8", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--netprobe", required=True)
    parser.add_argument("--source-dir", required=True)
    args = parser.parse_args()
    source = Path(args.source_dir).resolve()
    netprobe = str(Path(args.netprobe).resolve())
    for capture in sorted((source / "tests/fixtures").glob("*.pcap")):
        compare(netprobe, source, capture.relative_to(source))
    with tempfile.TemporaryDirectory() as tmp:
        capture = Path(tmp) / "interleaved-200k.pcap"
        generate_capture(capture)
        compare(netprobe, source, capture)


if __name__ == "__main__":
    main()
