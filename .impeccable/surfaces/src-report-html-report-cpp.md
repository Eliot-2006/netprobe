---
version: 1
slug: "src-report-html-report-cpp"
primary_target: "src/report/html_report.cpp"
related_targets: []
---

# Surface: HTML analysis report (src/report/html_report.cpp)

Mode: operate. Reader: engineer triaging a capture. Task: decide in seconds whether the capture is
trustworthy and where problems are, then drill into exact numbers. Constraints: single offline file,
inline CSS + inline SVG, no JS required, <= 2 MiB at 1000 flows, everything escaped, light + dark,
375 px usable. Seed key: ff59ce21 (assigned direction, chosen by the owner).

## Direction contract

THESIS: A report is a strip bay: every flow is a progress strip you can read at a glance, and the
bay is ordered so trouble rises to the top. Refuses the category default of a grey card dashboard
with KPI tiles and a donut chart.

OWN-WORLD: Dark slate strip-holder rails framing paper-toned strips: buff strips for TCP, pale
blue for UDP, each with a coloured left tab. Condensed sans for flow designators, tabular figures
for every number, hairline holder dividers. One reserved alert colour (signal red-orange) used only
for problems: gaps, truncation, decode errors, limits hit. Light scheme: pale grey bay, dark ink.
Dark scheme: near-black bay, strips dimmed to muted paper tones.

STORY: Header strip states capture status first; warnings bay next; then the timeline; then
protocol and error breakdowns; then the flow bays (incomplete first, then top flows), talkers,
services, run details.

FIRST VIEWPORT: capture designator strip with status badge and five figures (packets, bytes, span,
flows, warnings), the warnings bay (or an explicit all-clear line), and the top of the timeline.

SIGNATURE: the stream gauge: each TCP direction drawn to scale as a bar of its stream offsets with
missing ranges cut out; ACKed gaps hatched in the alert colour, others outlined. Bar length is exact
(labanotation discipline: length encodes bytes).

RISK: the strip metaphor must stay type/palette/density; tables stay real tables with headers.
