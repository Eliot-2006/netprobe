#!/usr/bin/env bash
# End-to-end harness (PRD 12.2): warm the page cache, one discarded run, then RUNS measured runs of
#   netprobe analyze --quiet --json <tmp> --workers N
# per worker count; prints median and min-max of the JSON "run" metrics. Disk I/O is excluded
# (page-cache warm). Usage: bench/run_e2e.sh <netprobe> <capture.pcap> [workers...]  (default: 0)
# Env: RUNS=5. Needs bash and python3. Pin with `taskset -c N` on Linux by prefixing this script
# (macOS has no taskset; unpinned there).
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <netprobe> <capture.pcap> [workers...]" >&2; exit 2; }
bin=$1 pcap=$2
shift 2
workers=("$@")
[ ${#workers[@]} -gt 0 ] || workers=(0)
runs=${RUNS:-5}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat "$pcap" > /dev/null
echo "file: $pcap ($(wc -c < "$pcap") bytes), runs: $runs, binary: $bin"
for w in "${workers[@]}"; do
    "$bin" analyze --quiet --workers "$w" --json "$tmp/warm.json" "$pcap" # discarded warm-up run
    for i in $(seq "$runs"); do
        "$bin" analyze --quiet --workers "$w" --json "$tmp/w${w}_$i.json" "$pcap"
    done
done

python3 -I - "$tmp" "${workers[@]}" <<'PY'
import json, statistics, sys
tmp, workers = sys.argv[1], sys.argv[2:]
metrics = [("elapsed_ms", lambda r: r["elapsed_ns"] / 1e6, "{:.1f}"),
           ("Mpkt/s", lambda r: r["packets_per_sec"] / 1e6, "{:.3f}"),
           ("MiB/s", lambda r: r["mib_per_sec"], "{:.0f}"),
           ("peak_rss_MiB", lambda r: r["peak_rss_bytes"] / 1048576, "{:.1f}")]
print("workers  " + "  ".join(f"{m[0]:>26}" for m in metrics))
for w in workers:
    runs = []
    for i in range(1, 1000):
        try:
            runs.append(json.load(open(f"{tmp}/w{w}_{i}.json"))["run"])
        except FileNotFoundError:
            break
    cells = []
    for _, get, fmt in metrics:
        v = [get(r) for r in runs]
        cells.append(f"{fmt.format(statistics.median(v))} ({fmt.format(min(v))}-{fmt.format(max(v))})".rjust(26))
    print(f"{w:>7}  " + "  ".join(cells))
PY
