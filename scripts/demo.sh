#!/usr/bin/env bash
# One-command NetProbe demo (PRD M7): build a release binary, analyze the bundled sample captures,
# and write JSON, HTML and exported TCP streams to out/demo/.
#
#   scripts/demo.sh            # uses $CXX if set; on macOS prefers Homebrew LLVM when present
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${CXX:-}" && "$(uname)" == "Darwin" && -x /opt/homebrew/opt/llvm/bin/clang++ ]]; then
    export CXX=/opt/homebrew/opt/llvm/bin/clang++
fi

echo "==> configuring and building (release preset)"
cmake --preset release -DNETPROBE_BUILD_TESTS=OFF >/dev/null
cmake --build --preset release --target netprobe
bin=build/release/netprobe

out=out/demo
rm -rf "$out"
mkdir -p "$out"
status=0
for pcap in samples/*.pcap; do
    name=$(basename "$pcap" .pcap)
    echo
    echo "==> $pcap"
    set +e
    "$bin" analyze "$pcap" --json "$out/$name.json" --html "$out/$name.html" \
        --export-streams "$out/$name-streams"
    rc=$?
    set -e
    if [[ $rc -ne 0 && $rc -ne 3 ]]; then
        echo "netprobe failed on $pcap (exit $rc)" >&2
        status=1
    fi
done

echo
echo "==> reports written to $out/:"
ls -1 "$out"/*.html
exit $status
