#!/usr/bin/env python3
"""HTML report safety and self-containment (PRD 8.2, M7).

- A capture whose path contains markup is rendered escaped (no injected <script>).
- The page makes no external requests: no src/href/url() pointing at a scheme or //host.
- The output parses as HTML and stays under the 2 MiB budget.
"""

import argparse
import html.parser
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class Collector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.urls = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for k, v in attrs:
            if k in ("src", "href") and v:
                self.urls.append(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netprobe", required=True)
    ap.add_argument("--source-dir", required=True)
    args = ap.parse_args()
    fixtures = Path(args.source_dir) / "tests" / "fixtures"
    failures = []
    with tempfile.TemporaryDirectory() as td:
        hostile = Path(td) / "<script>alert('x')<script>&\"q\".pcap"
        shutil.copy(fixtures / "tcp_loss_acked.pcap", hostile)
        targets = [hostile] + sorted(fixtures.glob("*.pcap"))
        for pcap in targets:
            out = Path(td) / "r.html"
            p = subprocess.run([args.netprobe, "analyze", str(pcap), "-q", "--html", str(out)],
                               capture_output=True, text=True)
            if p.returncode not in (0, 3) or not out.exists():
                failures.append(f"{pcap.name}: exit {p.returncode} {p.stderr.strip()}")
                continue
            doc = out.read_text()
            c = Collector()
            c.feed(doc)
            if "script" in c.tags:
                failures.append(f"{pcap.name}: <script> element in output")
            external = [u for u in c.urls if re.match(r"^([a-z][a-z0-9+.-]*:|//)", u, re.I)]
            external += [m for m in re.findall(r"url\(\s*['\"]?((?:[a-z]+:|//)[^)]{0,20})", doc, re.I)
                         if not m.lower().startswith("data:")]
            external += re.findall(r"@import", doc)
            if external:
                failures.append(f"{pcap.name}: external references {external[:3]}")
            if len(doc.encode()) > 2 * 1024 * 1024:
                failures.append(f"{pcap.name}: {len(doc)} bytes > 2 MiB")
            if pcap == hostile and "&lt;script&gt;" not in doc:
                failures.append("hostile path not escaped as text")
    for f in failures:
        print("FAIL", f)
    print(f"{len(targets)} reports checked, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
