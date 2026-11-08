#!/usr/bin/env bash
# Downloads the public real-world captures used in docs/validation.md into datasets/realworld/
# (gitignored). Nothing here is committed to the repository:
#   - tcpreplay sample captures (smallFlows.pcap, bigFlows.pcap): publicly downloadable from the
#     tcpreplay project's S3 bucket; no explicit redistribution license is published, so they are
#     used locally only.
#   - tcpdump's test captures (tests/*.pcap in the tcpdump repository): BSD-licensed.
# Checksums pin the exact files the documented results were produced from.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=datasets/realworld
mkdir -p "$dest"

fetch() { # url file sha256
    if [[ ! -f "$dest/$2" ]]; then
        echo "downloading $2"
        curl -sSfL -o "$dest/$2.part" "$1"
        mv "$dest/$2.part" "$dest/$2"
    fi
    echo "$3  $dest/$2" | shasum -a 256 -c -
}

fetch https://s3.amazonaws.com/tcpreplay-pcap-files/smallFlows.pcap smallFlows.pcap \
    77d06d3f33f1a95fb9f2610f20ead8ce978449077d6ba22d4945b85bd48f75d1
fetch https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap bigFlows.pcap \
    2b630291cc848c79949e12a54edebe07d20f644747db28899ac4d568c42dc141

# tcpdump test captures, pinned to the commit the documented results used.
tcpdump_commit=f34cf40526e1f6326138fedba2a606d1c2f089f3
if [[ ! -d "$dest/tcpdump/tests" ]]; then
    echo "downloading tcpdump test captures"
    curl -sSfL -o "$dest/tcpdump.tar.gz" \
        "https://github.com/the-tcpdump-group/tcpdump/archive/$tcpdump_commit.tar.gz"
    mkdir -p "$dest/tcpdump"
    tar -xzf "$dest/tcpdump.tar.gz" -C "$dest/tcpdump" --strip-components=1
fi
echo "tcpdump captures: $(ls "$dest"/tcpdump/tests/*.pcap | wc -l | tr -d ' ') files"
