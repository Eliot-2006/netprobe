#!/usr/bin/env bash
# Full benchmark pass inside the Ubuntu 24.04 dev container (see README "Linux container"):
# release build with GCC 13 (-O2, no -march=native), D1/D2/D3 generated in the container,
# micro-benchmarks, then end-to-end runs at several worker counts. Disk I/O is excluded.
#   docker run --rm -v "$PWD":/src -w /src netprobe-dev:24.04 bench/run_linux_container.sh out/bench-linux
set -euo pipefail
out=${1:-out/bench-linux}
size=${SIZE:-1G}
mkdir -p "$out"
export CXX=${CXX:-g++-13}

{
    echo "date: $(date -u +%FT%TZ)"
    echo "kernel: $(uname -srm)"
    echo "cpus: $(nproc)"
    grep -m1 -E 'model name|CPU part' /proc/cpuinfo || true
    lscpu | grep -E 'Model name|Vendor ID|^CPU\(s\)|Thread|Core' || true
    free -b | head -2
    echo "compiler: $($CXX --version | head -1)"
} > "$out/env.txt"

cmake -S . -B /tmp/bench -G Ninja -DCMAKE_BUILD_TYPE=Release -DNETPROBE_BUILD_BENCH=ON \
    -DNETPROBE_BUILD_TESTS=OFF > /dev/null
cmake --build /tmp/bench > /dev/null
grep CMAKE_CXX_FLAGS_RELEASE: /tmp/bench/CMakeCache.txt >> "$out/env.txt"

mkdir -p /data
for d in d1 d2 d3; do
    /tmp/bench/synth_pcap -o /data/$d.pcap --profile $d --size "$size" | tee -a "$out/datasets.txt"
    sha256sum /data/$d.pcap >> "$out/datasets.txt"
done

NETPROBE_BENCH_PCAP=/data/d3.pcap /tmp/bench/netprobe_bench --benchmark_repetitions=5 \
    --benchmark_report_aggregates_only=true --benchmark_out="$out/micro.json" \
    --benchmark_out_format=json > "$out/micro.txt" 2>&1

for d in d3 d1 d2; do
    RUNS=${RUNS:-5} bench/run_e2e.sh /tmp/bench/netprobe /data/$d.pcap 0 1 2 4 8 \
        > "$out/e2e_$d.txt" 2>&1
done
echo "done: $out"
