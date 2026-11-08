#!/usr/bin/env python3
"""Golden-file test (PRD 11.4): `analyze --deterministic --json` output per fixture must match
tests/golden/<fixture>.json byte for byte. Regenerate only with UPDATE_GOLDEN=1, then review the
diff by hand; test_fixture_truth.py independently checks the values against ground truth.
"""

import argparse
import difflib
import os
import subprocess
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netprobe", required=True)
    ap.add_argument("--source-dir", required=True)
    args = ap.parse_args()
    src = Path(args.source_dir)
    golden_dir = src / "tests" / "golden"
    update = os.environ.get("UPDATE_GOLDEN") == "1"
    failures = 0
    pcaps = sorted((src / "tests" / "fixtures").glob("*.pcap"))
    for pcap in pcaps:
        rel = pcap.relative_to(src).as_posix()
        out = subprocess.run([args.netprobe, "analyze", rel, "--deterministic", "--json", "-"],
                             cwd=src, capture_output=True, text=True).stdout
        golden = golden_dir / f"{pcap.stem}.json"
        if update:
            golden_dir.mkdir(exist_ok=True)
            golden.write_text(out)
            continue
        want = golden.read_text() if golden.exists() else ""
        if out != want:
            failures += 1
            diff = difflib.unified_diff(want.splitlines(), out.splitlines(), "golden", "actual",
                                        lineterm="", n=2)
            print(f"FAIL {pcap.stem}")
            print("\n".join(list(diff)[:40]))
    print(f"{len(pcaps)} fixtures, {failures} golden mismatches" + (" (updated)" if update else ""))
    return 1 if failures or not pcaps else 0


if __name__ == "__main__":
    sys.exit(main())
