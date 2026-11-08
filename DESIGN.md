---
name: NetProbe
description: Offline PCAP analysis report laid out as an air-traffic strip bay.
colors:
  bay: "#e4e7ea"
  rail: "#262d33"
  rail-ink: "#eef0f1"
  ink: "#191c1f"
  muted: "#4c555d"
  rule: "#c9cfd4"
  paper: "#f7f8f9"
  track: "#e4e7ea"
  tcp-strip: "#f1e7c9"
  tcp-tab: "#d6c088"
  udp-strip: "#dde9f3"
  udp-tab: "#a9c3d9"
  alert: "#c2410c"
  alert-ink: "#9a3412"
  alert-soft: "#fde3d3"
  on-alert: "#ffffff"
  bar: "#4c555d"
  line: "#262d33"
  have: "#262d33"
  bay-dark: "#101316"
  rail-dark: "#030405"
  rail-ink-dark: "#d9dde0"
  ink-dark: "#e6e4dc"
  muted-dark: "#a1a8ae"
  rule-dark: "#2c3237"
  paper-dark: "#171b1f"
  track-dark: "#22272c"
  tcp-strip-dark: "#2b281f"
  tcp-tab-dark: "#4f4630"
  udp-strip-dark: "#1d2832"
  udp-tab-dark: "#2f4254"
  alert-dark: "#fb7a45"
  alert-ink-dark: "#fd9a6f"
  alert-soft-dark: "#3a1f14"
  on-alert-dark: "#1f0d04"
  bar-dark: "#8f979e"
  line-dark: "#e6e4dc"
  have-dark: "#b9b3a1"
typography:
  display:
    fontFamily: "\"NP Cond\" (Barlow Condensed, embedded), \"Arial Narrow\", \"Roboto Condensed\", sans-serif"
    fontSize: "2.1rem"
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: "0.01em"
  headline:
    fontFamily: "\"NP Cond\", \"Arial Narrow\", \"Roboto Condensed\", sans-serif"
    fontSize: "1.45rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.02em"
  title:
    fontFamily: "\"NP Cond\", \"Arial Narrow\", \"Roboto Condensed\", sans-serif"
    fontSize: "1rem"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "0.02em"
  body:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
  figure:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1.1rem"
    fontWeight: 600
    fontFeature: "tnum"
  label:
    fontFamily: "\"NP Cond\", \"Arial Narrow\", \"Roboto Condensed\", sans-serif"
    fontSize: "0.8rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.06em"
  strip-tab:
    fontFamily: "\"NP Cond\", \"Arial Narrow\", \"Roboto Condensed\", sans-serif"
    fontSize: "0.82rem"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.1em"
  mono:
    fontFamily: "ui-monospace, \"SF Mono\", Menlo, Consolas, \"Liberation Mono\", monospace"
    fontSize: "0.92em"
spacing:
  rail-gap: "4px"
  strip-pad: "10px 14px"
  panel-pad: "14px 16px"
  cell-pad: "7px 10px"
  grid-gap: "16px"
  section: "36px"
components:
  capture-strip:
    backgroundColor: "{colors.tcp-strip}"
    textColor: "{colors.ink}"
    padding: "14px 18px 12px"
  capture-tab:
    backgroundColor: "{colors.tcp-tab}"
    textColor: "{colors.ink}"
    typography: "{typography.strip-tab}"
    padding: "14px 10px"
  capture-tab-bad:
    backgroundColor: "{colors.alert}"
    textColor: "{colors.on-alert}"
  strip-holder:
    backgroundColor: "{colors.rail}"
    padding: "{spacing.rail-gap}"
  strip-tcp:
    backgroundColor: "{colors.tcp-strip}"
    textColor: "{colors.ink}"
    padding: "{spacing.strip-pad}"
  strip-udp:
    backgroundColor: "{colors.udp-strip}"
    textColor: "{colors.ink}"
  strip-tab-tcp:
    backgroundColor: "{colors.tcp-tab}"
    typography: "{typography.strip-tab}"
  strip-tab-udp:
    backgroundColor: "{colors.udp-tab}"
    typography: "{typography.strip-tab}"
  tag-alert:
    backgroundColor: "{colors.alert}"
    textColor: "{colors.on-alert}"
    typography: "{typography.label}"
    padding: "0 7px"
  tag-ok:
    backgroundColor: "{colors.tcp-tab}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    padding: "0 7px"
  panel:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    padding: "{spacing.panel-pad}"
  table-header:
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    padding: "8px 10px 6px"
  table-cell:
    backgroundColor: "{colors.paper}"
    padding: "{spacing.cell-pad}"
  share-bar-track:
    backgroundColor: "{colors.track}"
    height: "9px"
  share-bar-fill:
    backgroundColor: "{colors.bar}"
  share-bar-fill-alert:
    backgroundColor: "{colors.alert}"
  stream-gauge:
    backgroundColor: "{colors.track}"
    height: "16px"
---

# Design System: NetProbe

## Overview

**Creative North Star: "The Strip Bay"**

The report is an air-traffic controller's flight-progress board. Every flow is a paper strip slotted into a dark slate holder; the bay is ordered so trouble rises to the top. The capture itself is the first strip (the designator strip), carrying the capture status on its tab and five to six key figures. Below it, findings, timeline, breakdowns, and flow bays follow in triage order. The metaphor lives in palette, type, and density only: tables stay real tables with headers, charts stay plain SVG.

Density is high and calm. Paper-toned surfaces sit on a pale grey bay (light) or near-black bay (dark), framed by thin slate rails. Condensed sans carries designators and labels, a system sans carries prose, monospace carries addresses and offsets because they are column-aligned data, and every number uses tabular figures. One signal colour, red-orange, is reserved for problems and appears nowhere else. The category default (grey card dashboard, KPI tiles, donut chart) is explicitly refused.

The whole system ships as one offline file: inline CSS, inline SVG, an embedded Barlow Condensed (bold, woff2) face, no scripts. Both colour schemes are first-class and switch on `prefers-color-scheme`.

**Key Characteristics:**
- Dark slate rails holding paper strips; buff for TCP, pale blue for UDP, each with a coloured left tab.
- One reserved alert colour for gaps, truncation, decode errors, and limits hit.
- Condensed bold for designators and labels; tabular figures for every number; monospace for addresses.
- Square corners, hairline rules, no shadows.
- Bar length encodes exact quantity; both directions of a stream share one scale.

## Colors

A muted paper-and-slate palette with a single signal colour; every token has a dimmed dark-scheme twin (the `-dark` keys).

### Primary
- **Signal Red-Orange** (alert): status tab when capture is not complete, finding tags, alert share-bar fills, gauge gap outlines and hatching, focus ring.
- **Deep Signal Ink** (alert-ink): problem text on paper (bad figures, "N B missing", gap counts), where the fill colour would fail contrast.
- **Signal Wash** (alert-soft): the pale ground between hatch stripes in ACKed-gap patterns.
- **On-Signal** (on-alert): text on alert fills.

### Secondary
- **Buff Strip** (tcp-strip) and **Buff Tab** (tcp-tab): TCP strips and their left tabs; also the capture strip, the all-clear tag, timeline packet bars, and text selection.
- **Pale Blue Strip** (udp-strip) and **Blue Tab** (udp-tab): UDP rows and their tabs.

### Neutral
- **Bay Grey** (bay): page background.
- **Slate Rail** (rail): strip holders, the capture header frame, the 3px top rule on panels and tables. **Rail Ink** (rail-ink) for header text set on the rail.
- **Ink** (ink) and **Slate Muted** (muted): body text and secondary text (labels, notes, axis, captions).
- **Hairline** (rule): dividers between figures, table rows, chart axes.
- **Paper** (paper): neutral panels and plain tables.
- **Track** (track), **Bar** (bar), **Line** (line), **Have** (have): empty share-bar tracks, normal share-bar fills, the timeline bytes line, delivered stream ranges in gauges.

### Named Rules
**The One Signal Rule.** Red-orange marks problems only: gaps, truncation, decode errors, limits hit. Never use it for emphasis, branding, or a "primary" action. A clean capture renders with no red-orange at all except the focus ring.

**The Protocol Paper Rule.** Strip colour carries protocol: buff is TCP, pale blue is UDP. Don't introduce a third paper tone without a third protocol.

## Typography

**Display Font:** Barlow Condensed Bold, embedded as "NP Cond" (with Arial Narrow, Roboto Condensed)
**Body Font:** system-ui stack
**Label/Mono Font:** ui-monospace stack for addresses, ports, offsets

**Character:** A tall, tight condensed designator face over a quiet system sans, like printed strip headings over handwritten-neutral annotation. Monospace appears only where columns must align.

### Hierarchy
- **Display** (700, 2.1rem, 1.7rem under 600px, 1.15): the capture file name on the designator strip.
- **Headline** (700, 1.45rem, 1.2): section titles; an inline muted sans subtitle (0.82rem) may follow on the same baseline.
- **Title** (700, 1rem, 1.3, muted): table captions.
- **Body** (400, 15px, 1.5): prose, findings, table cells (0.88rem); notes cap at 75ch.
- **Figure** (600, 1.1rem, tabular): headline figures on the designator strip.
- **Label** (700, 0.8rem, 0.06em, uppercase): figure labels and table headers; finding tags at 0.08em.
- **Strip tab** (700, 0.78 to 0.85rem, 0.1 to 0.14em, uppercase): protocol and status tabs; set vertically (bottom-to-top) in strip and capture tabs, horizontally in table-row tabs.

### Named Rules
**The Tabular Figures Rule.** Every number is set with tabular figures and right-aligned in tables. Columns of counts must line up digit for digit.

**The Designator Rule.** Condensed bold is for designators and labels (names, tabs, headers, flow ids). Sentences never set in it.

## Layout

A single centred column (max 1240px; padding 24px 20px 64px, 16px 12px 48px under 600px) of stacked sections 36px apart, in triage order. Paired content (flow outcomes, talkers and services, run details) uses an auto-fit grid of 320px-minimum columns with a 16px gap that collapses to one column on narrow screens. Strip holders stack strips with a 4px rail gap. Wide tables sit in a horizontal scroller rather than reflowing. The designator strip's figures auto-fit at 130px minimum, divided by hairlines that drop away under 600px. Share-bar rows are a four-column grid (label, track, count, percent); the percent column hides under 600px.

## Elevation & Depth

Flat. There are no shadows anywhere. Depth comes from the holder metaphor: paper surfaces framed by or slotted into slate rails (4 to 5px), and a 3px slate top rule on standalone panels and tables. Separation inside surfaces is hairline rules only.

### Named Rules
**The Rail, Not Shadow, Rule.** To lift a surface, put it in a rail or give it a slate top rule. Never a box-shadow.

## Shapes

Square everywhere: no border radius on strips, tabs, tags, panels, tables, bars, or gauges. Lines are 1px hairlines inside surfaces and 3 to 5px slate rails around them. The recurring silhouette is the strip: a narrow coloured tab on the left edge, a paper body to its right.

## Components

### Designator Strip (capture header)
The first strip in the bay. A slate rail (5px) frames a buff strip; the left tab carries the capture status vertically, buff when complete and signal red-orange otherwise. The body holds the file name in display type, a row of labelled figures separated by hairlines (bad figures in alert ink), and a muted metadata line.

### Flow Strip and Stream Gauge (signature)
Incomplete TCP streams render as strips in a holder: vertical TCP tab, then a head line (flow id in condensed bold, endpoints in mono, missing bytes in alert ink). Each direction gets a 16px gauge drawn to a scale shared by both directions, so bar length is exact. Delivered ranges fill in the "have" colour; gaps the receiver ACKed are hatched (45° alert stripes on alert wash, 1px alert outline); unACKed gaps are outlined only, showing strip paper through. A muted meta line and a list of byte ranges follow.

### Strip Table (flow list)
A real table with headers set on the slate rail in rail ink, rows separated by 4px rail gaps. Each row is a strip: a horizontal protocol tab cell in the tab colour, then cells on buff (TCP) or pale blue (UDP).

### Findings and Tags
Findings sit in a holder as paper rows: a tag (condensed uppercase, alert fill, no radius) followed by a plain-sentence finding. When nothing is wrong, a single row carries a buff "clear" tag and an explicit all-clear sentence.

### Panels and Plain Tables
Paper surface, 3px slate top rule, 14px 16px padding. Plain tables use condensed uppercase muted headers, 7px 10px cells, hairline row dividers, and tabular right-aligned numbers.

### Share Bars
Horizontal 9px bars on a track: label, track, count, percent. Fill is the neutral bar colour; problem categories (decode errors, TCP with gaps) fill in alert.

### Timeline
Plain SVG: buff packet bars, a 1.6px ink line for bytes, hairline axis, muted tabular axis labels, and a small legend with matching swatches.

## Do's and Don'ts

### Do:
- **Do** reserve signal red-orange (#c2410c light, #fb7a45 dark) for problems only; use alert ink for problem text on paper.
- **Do** encode protocol by strip paper: buff for TCP, pale blue for UDP, with the matching tab.
- **Do** draw quantity bars to scale, sharing one scale across directions of the same flow.
- **Do** set every number in tabular figures and right-align numeric columns.
- **Do** keep tables as real tables with headers and scope, even when styled as strips.
- **Do** ship both schemes; every new colour needs a dark-scheme twin.

### Don't:
- **Don't** build a grey card dashboard with KPI tiles or donut charts; that is the category default this world refuses.
- **Don't** add border radius or box-shadows; use rails and hairlines.
- **Don't** set prose in the condensed face, or set IP addresses and offsets in anything but monospace.
- **Don't** load external fonts, scripts, or images; the face is embedded and everything is inline.
