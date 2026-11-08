#!/usr/bin/env python3
"""Generate NetProbe test fixtures and their ground-truth files (PRD 11.4, oracle O-A).

Frames are built with Scapy (independent of NetProbe's decoder); the PCAP container is written
by hand so record lengths, snaplen, byte order and corruption are fully controlled. Every
fixture gets `<name>.pcap` and `<name>.truth.json`. Truth values come from how the fixture was
constructed, never from NetProbe output.

Usage:  .venv/bin/python tests/fixtures/gen_fixtures.py [--out tests/fixtures]
Deterministic: same Scapy version + this script => byte-identical output.
"""

import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    Jumbo,
)
from scapy.layers.l2 import ARP, Dot1AD, Dot1Q, Ether
from scapy.packet import Raw

BASE_TS_NS = 1_700_000_000 * 10**9
MAC_C = "02:00:00:00:00:01"
MAC_S = "02:00:00:00:00:02"


# ----------------------------------------------------------------------------- pcap writer
def frame_bytes(pkt) -> bytes:
    """Serialize and pad to the 60-byte Ethernet minimum, like a real NIC (padding must be
    trimmed by the decoder using the IP length, never treated as payload)."""
    b = bytes(pkt)
    return b + b"\x00" * (60 - len(b)) if len(b) < 60 else b


def write_pcap(path, records, snaplen=262144, endian="<", nsec=False, tail=b""):
    """records: list of dicts {ts_ns, data, orig_len?, incl_len?(override header field only)}."""
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    out = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, 1))
    for r in records:
        data = r["data"][:snaplen]
        orig = r.get("orig_len", len(r["data"]))
        incl = r.get("incl_len", len(data))
        sec, frac = divmod(r["ts_ns"], 10**9)
        if not nsec:
            frac //= 1000
        out += struct.pack(endian + "IIII", sec, frac, incl, orig) + data
    out += tail
    Path(path).write_bytes(bytes(out))


# ----------------------------------------------------------------------------- TCP session model
class TcpSession:
    """Builds frames for one TCP connection and records what each direction actually sent."""

    def __init__(self, cip, sip, cport, sport, isn_c, isn_s, v6=False, vlan=None):
        self.ep = {True: (cip, cport), False: (sip, sport)}  # True = client side
        self.isn = {True: isn_c, False: isn_s}
        self.next = {True: (isn_c + 1) & 0xFFFFFFFF, False: (isn_s + 1) & 0xFFFFFFFF}
        self.v6 = v6
        self.vlan = vlan

    def frame(self, from_client, flags, seq, ack, payload=b"", options=None):
        (src, sport), (dst, dport) = self.ep[from_client], self.ep[not from_client]
        l3 = IPv6(src=src, dst=dst) if self.v6 else IP(src=src, dst=dst, id=0, flags="DF")
        tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq & 0xFFFFFFFF,
                  ack=ack & 0xFFFFFFFF if "A" in flags else 0, window=65535,
                  options=options or [])
        eth = Ether(src=MAC_C if from_client else MAC_S, dst=MAC_S if from_client else MAC_C)
        pkt = eth / l3 / tcp
        if self.vlan is not None:
            pkt = eth / Dot1Q(vlan=self.vlan) / l3 / tcp
        if payload:
            pkt = pkt / Raw(payload)
        return frame_bytes(pkt)

    def handshake(self):
        c, s = self.isn[True], self.isn[False]
        return [
            self.frame(True, "S", c, 0, options=[("MSS", 1460), ("WScale", 7), ("SAckOK", b"")]),
            self.frame(False, "SA", s, c + 1, options=[("MSS", 1400), ("WScale", 8)]),
            self.frame(True, "A", c + 1, s + 1),
        ]

    def data(self, from_client, offset, chunk, flags="PA"):
        """Segment carrying `chunk` at stream offset `offset` (relative to ISN+1)."""
        seq = self.isn[from_client] + 1 + offset
        ack = self.next[not from_client]
        return self.frame(from_client, flags, seq, ack, chunk)

    def ack_only(self, from_client, ack_offset):
        """Pure ACK acknowledging peer stream offset `ack_offset`."""
        seq = self.next[from_client]
        return self.frame(from_client, "A", seq, self.isn[not from_client] + 1 + ack_offset)

    def fin(self, from_client, stream_len):
        seq = self.isn[from_client] + 1 + stream_len
        return self.frame(from_client, "FA", seq, self.next[not from_client])

    def rst(self, from_client, stream_len):
        seq = self.isn[from_client] + 1 + stream_len
        return self.frame(from_client, "R", seq, 0)

    def advance(self, from_client, n):
        self.next[from_client] = (self.next[from_client] + n) & 0xFFFFFFFF


def chunks(data, mss):
    return [(o, data[o:o + mss]) for o in range(0, len(data), mss)]


def direction_truth(delivered: bytes, gaps=(), conflict=False):
    return {"length": len(delivered), "sha256": hashlib.sha256(delivered).hexdigest(),
            "gaps": [list(g) for g in gaps], "conflict": conflict}


def stream_truth(sess, c2s, s2c, handshake="full", close="fin"):
    (cip, cport), (sip, sport) = sess.ep[True], sess.ep[False]
    return {"client": [cip, cport], "server": [sip, sport], "handshake": handshake,
            "close": close, "c2s": c2s, "s2c": s2c}


def normal_exchange(sess, req, resp, mss, order=None, drop=(), dup=(), extra=None):
    """Request (client) then response (server). `order` permutes response segments;
    `drop`/`dup` are response segment indexes. Returns frame list."""
    frames = sess.handshake()
    for off, ch in chunks(req, mss):
        frames.append(sess.data(True, off, ch))
    sess.advance(True, len(req))
    frames.append(sess.ack_only(False, len(req)))
    segs = chunks(resp, mss)
    idx = order if order is not None else list(range(len(segs)))
    for i in idx:
        if i in drop:
            continue
        frames.append(sess.data(False, *segs[i]))
        if i in dup:
            frames.append(sess.data(False, *segs[i]))
    if extra:
        frames.extend(extra)
    sess.advance(False, len(resp))
    frames.append(sess.ack_only(True, len(resp)))
    frames.append(sess.fin(True, len(req)))
    frames.append(sess.fin(False, len(resp)))
    sess.advance(True, 1)
    sess.advance(False, 1)
    frames.append(sess.ack_only(True, len(resp) + 1))
    return frames


def http_payloads(rng, body_len):
    req = (b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: netprobe-fixture\r\n"
           b"Accept: */*\r\n\r\n")
    body = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789 \n") for _ in range(body_len))
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(body_len).encode() + b"\r\n\r\n" + body)
    return req, resp


def records_from(frames, start_ts=BASE_TS_NS, step_ns=1_000_000):
    return [{"ts_ns": start_ts + i * step_ns, "data": f} for i, f in enumerate(frames)]


# ----------------------------------------------------------------------------- fixtures
FIXTURES = {}


def fixture(fn):
    FIXTURES[fn.__name__] = fn
    return fn


@fixture
def tcp_clean_v4(rng):
    s = TcpSession("10.0.0.5", "10.0.0.80", 51544, 80, 1000, 5000)
    req, resp = http_payloads(rng, 6000)
    frames = normal_exchange(s, req, resp, 1460)
    return records_from(frames), {
        "layers": {"ipv4": len(frames), "tcp": len(frames)},
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))]}


@fixture
def tcp_clean_v6(rng):
    s = TcpSession("2001:db8::5", "2001:db8::80", 40000, 443, 77777, 99999, v6=True)
    req, resp = rng.randbytes(300), rng.randbytes(9000)
    frames = normal_exchange(s, req, resp, 1440)
    return records_from(frames), {
        "layers": {"ipv6": len(frames), "tcp": len(frames)},
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))]}


@fixture
def tcp_reorder(rng):
    s = TcpSession("10.1.0.1", "10.1.0.2", 33000, 8080, 123456, 654321)
    req, resp = rng.randbytes(200), rng.randbytes(1000 * 12)
    order = [0, 2, 1, 5, 3, 4, 6, 11, 10, 9, 8, 7]
    frames = normal_exchange(s, req, resp, 1000, order=order)
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))],
        "min_out_of_order_segments": 4}


@fixture
def tcp_loss_acked(rng):
    """Server segment 3 is lost in the capture but the client ACKs everything: an ACKed gap."""
    s = TcpSession("10.2.0.1", "10.2.0.2", 33001, 8080, 42, 4242)
    req, resp = rng.randbytes(100), rng.randbytes(1000 * 8)
    frames = normal_exchange(s, req, resp, 1000, drop={3})
    delivered = resp[:3000] + resp[4000:]
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req),
                                 direction_truth(delivered, gaps=[(3000, 1000, True)]))]}


@fixture
def tcp_retrans_overlap(rng):
    """Exact duplicates plus re-segmented retransmissions that overlap with identical bytes."""
    s = TcpSession("10.3.0.1", "10.3.0.2", 33002, 9000, 0x10000000, 0x20000000)
    req, resp = rng.randbytes(100), rng.randbytes(1000 * 6)
    extra = [s.data(False, 500, resp[500:1700]),    # overlaps segs 0-1, already delivered
             s.data(False, 2500, resp[2500:5500]),  # spans 3 segments
             s.data(False, 5900, resp[5900:6000])]  # tail duplicate
    frames = normal_exchange(s, req, resp, 1000, dup={1, 4}, extra=extra)
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))],
        "min_retransmitted_bytes": 2000 + 1200 + 3000 + 100}


@fixture
def tcp_conflict_overlap(rng):
    """Segment 2 arrives first (buffered), then a conflicting copy of the same range, then the
    missing segment 1. First-wins: the first copy of segment 2 must be delivered."""
    s = TcpSession("10.4.0.1", "10.4.0.2", 33003, 9001, 7, 70000)
    req = rng.randbytes(100)
    resp = rng.randbytes(3000)
    evil = bytes(b ^ 0xFF for b in resp[1000:2000])
    frames = s.handshake()
    frames.append(s.data(True, 0, req))
    s.advance(True, len(req))
    frames.append(s.data(False, 0, resp[0:1000]))
    frames.append(s.data(False, 2000, resp[2000:3000]))     # out of order, buffered
    evil2 = bytes(b ^ 0xFF for b in resp[2000:2500])
    frames.append(s.data(False, 1500, evil[500:1000] + evil2))  # 2nd half conflicts with buffer
    frames.append(s.data(False, 1000, resp[1000:2000]))     # fills the hole
    s.advance(False, len(resp))
    frames.append(s.ack_only(True, len(resp)))
    frames.append(s.fin(True, len(req)))
    frames.append(s.fin(False, len(resp)))
    s.advance(True, 1)
    s.advance(False, 1)
    frames.append(s.ack_only(True, len(resp) + 1))
    # The conflicting packet arrives before [1500,2000) is filled, so its first half is new data
    # (first writer of that range) and its second half conflicts with the buffered [2000,2500).
    # The final [1000,2000) segment then fills [1000,1500) and conflicts on [1500,2000).
    delivered = resp[:1500] + evil[500:1000] + resp[2000:]
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req),
                                 direction_truth(delivered, conflict=True))],
        "min_conflicting_overlap_bytes": 1000}


@fixture
def tcp_wraparound(rng):
    s = TcpSession("10.5.0.1", "10.5.0.2", 33004, 9002, 0xFFFFF000, 0xFFFFFF00)
    req, resp = rng.randbytes(5000), rng.randbytes(10000)
    order = [0, 2, 1, 3, 4, 6, 5]  # reordering across the 2^32 boundary
    frames = normal_exchange(s, req, resp, 1460, order=order)
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))]}


@fixture
def tcp_midstream(rng):
    """Capture begins after the handshake; first observed packet is client data."""
    s = TcpSession("10.6.0.1", "10.6.0.2", 33005, 9003, 1_000_000, 2_000_000)
    s.advance(True, 5000)
    s.advance(False, 7000)
    req, resp = rng.randbytes(2000), rng.randbytes(4000)
    frames = []
    for off, ch in chunks(req, 1000):
        frames.append(s.data(True, 5000 + off, ch))
    for off, ch in chunks(resp, 1000):
        frames.append(s.data(False, 7000 + off, ch))
    s.advance(True, 2000)
    s.advance(False, 4000)
    frames.append(s.fin(True, 7000))
    frames.append(s.fin(False, 11000))
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp),
                                 handshake="none")]}


@fixture
def tcp_rst(rng):
    s = TcpSession("10.7.0.1", "10.7.0.2", 33006, 9004, 500, 600)
    req, resp = rng.randbytes(500), rng.randbytes(3000)
    frames = s.handshake()
    frames.append(s.data(True, 0, req))
    s.advance(True, len(req))
    for off, ch in chunks(resp, 1000):
        frames.append(s.data(False, off, ch))
    frames.append(s.rst(False, len(resp)))
    frames.append(s.data(True, 500, b"late data after reset"))
    return records_from(frames), {
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp), close="rst")],
        "min_data_after_rst": 1}


@fixture
def tcp_port_reuse(rng):
    a = TcpSession("10.8.0.1", "10.8.0.2", 33007, 9005, 1000, 2000)
    req1, resp1 = rng.randbytes(300), rng.randbytes(1500)
    frames = normal_exchange(a, req1, resp1, 1000)
    b = TcpSession("10.8.0.1", "10.8.0.2", 33007, 9005, 900_000, 800_000)
    req2, resp2 = rng.randbytes(400), rng.randbytes(2500)
    frames += normal_exchange(b, req2, resp2, 1000)
    return records_from(frames), {
        "flows": {"tcp": 2, "udp": 0},
        "streams": [stream_truth(a, direction_truth(req1), direction_truth(resp1)),
                    stream_truth(b, direction_truth(req2), direction_truth(resp2))]}


@fixture
def tcp_snaplen_96(rng):
    """snaplen 96: every data segment carries 96-14-20-20 = 42 captured payload bytes."""
    s = TcpSession("10.9.0.1", "10.9.0.2", 33008, 9006, 10, 20)
    req, resp = rng.randbytes(100), rng.randbytes(3000)
    frames = normal_exchange(s, req, resp, 1000)
    cap = 96 - 14 - 20 - 20
    def captured(data, mss):
        out, gaps = b"", []
        for off, ch in chunks(data, mss):
            out += ch[:cap]
            if len(ch) > cap:
                gaps.append((off + cap, len(ch) - cap, True))
        return out, gaps
    rq, rq_g = captured(req, 1000)
    rs, rs_g = captured(resp, 1000)
    return records_from(frames), {
        "snaplen": 96,
        "records_truncated_by_snaplen": sum(1 for f in frames if len(f) > 96),
        "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(rq, rq_g), direction_truth(rs, rs_g))]}


@fixture
def vlan_qinq(rng):
    frames = []
    for i in range(4):
        tcp = Ether(src=MAC_C, dst=MAC_S) / Dot1AD(vlan=100) / Dot1Q(vlan=200 + i) / \
            IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000 + i, dport=22, flags="S")
        frames.append(frame_bytes(tcp))
    for i in range(3):
        udp = Ether(src=MAC_C, dst=MAC_S) / Dot1Q(vlan=300) / \
            IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=5000, dport=53) / Raw(b"q" * 20)
        frames.append(frame_bytes(udp))
    return records_from(frames), {
        "layers": {"vlan_tagged": 7, "ipv4": 7, "tcp": 4, "udp": 3},
        "vlans": {"100": 4, "300": 3},
        "flows": {"tcp": 4, "udp": 1}}


@fixture
def ipv6_ext_headers(rng):
    base = Ether(src=MAC_C, dst=MAC_S)
    src, dst = "2001:db8:1::1", "2001:db8:1::2"
    frames = [
        frame_bytes(base / IPv6(src=src, dst=dst) / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() /
                    TCP(sport=4000, dport=80, flags="S")),
        frame_bytes(base / IPv6(src=src, dst=dst) / IPv6ExtHdrRouting(addresses=[]) /
                    UDP(sport=4001, dport=53) / Raw(b"x" * 10)),
        frame_bytes(base / IPv6(src=src, dst=dst, nh=50) / Raw(b"\x00" * 24)),  # ESP: unsupported
    ]
    return records_from(frames), {
        "layers": {"ipv6": 3, "tcp": 1, "udp": 1},
        "decode_errors": {"unsupported.ipv6_ext.ipv6_ext": 1},
        "flows": {"tcp": 1, "udp": 1}}


@fixture
def ip_fragments(rng):
    base = Ether(src=MAC_C, dst=MAC_S)
    big = IP(src="172.16.0.1", dst="172.16.0.2", id=77) / UDP(sport=7000, dport=7001) / \
        Raw(rng.randbytes(3000))
    from scapy.layers.inet import fragment
    v4 = [frame_bytes(base / f) for f in fragment(big, fragsize=1000)]
    v6 = [frame_bytes(base / IPv6(src="2001:db8::a", dst="2001:db8::b") /
                      IPv6ExtHdrFragment(offset=0, m=1, id=9) / UDP(sport=1, dport=2) /
                      Raw(b"y" * 100)),
          frame_bytes(base / IPv6(src="2001:db8::a", dst="2001:db8::b") /
                      IPv6ExtHdrFragment(offset=14, m=0, id=9, nh=17) / Raw(b"z" * 50))]
    frames = v4 + v6
    return records_from(frames), {
        "layers": {"ip_fragments": len(frames), "ipv4": len(v4), "ipv6": len(v6), "udp": 0},
        "flows": {"tcp": 0, "udp": 0}}


@fixture
def udp_mixed(rng):
    base = Ether(src=MAC_C, dst=MAC_S)
    frames = []
    for i in range(5):
        frames.append(frame_bytes(base / IP(src="10.10.0.1", dst="10.10.0.53") /
                                  UDP(sport=50000 + i, dport=53) / Raw(rng.randbytes(40))))
        frames.append(frame_bytes(base / IP(src="10.10.0.53", dst="10.10.0.1") /
                                  UDP(sport=53, dport=50000 + i) / Raw(rng.randbytes(120))))
    frames.append(frame_bytes(base / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                              UDP(sport=123, dport=123) / Raw(rng.randbytes(48))))
    frames.append(frame_bytes(base / IP(src="10.10.0.1", dst="10.10.0.2") / ICMP()))
    frames.append(frame_bytes(Ether(src=MAC_C, dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.10.0.9")))
    return records_from(frames), {
        "layers": {"udp": 11, "ipv4": 11, "ipv6": 1, "icmp": 1, "arp": 1},
        "flows": {"tcp": 0, "udp": 6}}


def raw_eth(ethertype, payload):
    return struct.pack("!6s6sH", bytes.fromhex("020000000002"), bytes.fromhex("020000000001"),
                       ethertype) + payload


@fixture
def malformed_mix(rng):
    """One frame per decode outcome; `per_record` lists the expected kind.layer.reason."""
    ip_ok = bytes(IP(src="1.1.1.1", dst="2.2.2.2", proto=6) / TCP(sport=1, dport=2))
    tcp_hdr = bytes(TCP(sport=1, dport=2))
    def ipv4(payload, **kw):
        return bytes(IP(src="1.1.1.1", dst="2.2.2.2", **kw) / Raw(payload))
    def patch(b, off, val):
        b = bytearray(b)
        b[off] = val
        return bytes(b)
    cases = []
    cases.append((b"\x00" * 10, "truncated.ethernet.short_header"))
    cases.append((raw_eth(0x0800, ip_ok[:10]), "truncated.ipv4.short_header"))
    cases.append((raw_eth(0x0800, patch(ip_ok, 0, 0x55)), "malformed.ipv4.bad_version"))
    cases.append((raw_eth(0x0800, patch(ip_ok, 0, 0x44)), "malformed.ipv4.bad_ihl"))
    bad_len = bytearray(ip_ok)
    bad_len[2:4] = struct.pack("!H", 10)
    cases.append((raw_eth(0x0800, bytes(bad_len)), "malformed.ipv4.bad_total_length"))
    cases.append((raw_eth(0x0800, ipv4(tcp_hdr[:12], proto=6)), "truncated.tcp.short_header"))
    doff4 = bytearray(tcp_hdr)
    doff4[12] = 0x40
    cases.append((raw_eth(0x0800, ipv4(bytes(doff4), proto=6)), "malformed.tcp.tcp_data_offset"))
    doff15 = bytearray(tcp_hdr)
    doff15[12] = 0xF0
    cases.append((raw_eth(0x0800, ipv4(bytes(doff15), proto=6)), "malformed.tcp.tcp_data_offset"))
    badopt = bytearray(bytes(TCP(sport=1, dport=2, options=[("NOP", None)] * 4)))
    badopt[20:24] = b"\x02\x00\x01\x01"  # MSS kind with length 0
    cases.append((raw_eth(0x0800, ipv4(bytes(badopt), proto=6)), "ok"))
    udp_short = bytearray(bytes(UDP(sport=1, dport=2) / Raw(b"abcd")))
    udp_short[4:6] = struct.pack("!H", 4)
    cases.append((raw_eth(0x0800, ipv4(bytes(udp_short), proto=17)), "malformed.udp.udp_length"))
    udp_long = bytearray(bytes(UDP(sport=1, dport=2) / Raw(b"abcd")))
    udp_long[4:6] = struct.pack("!H", 200)
    cases.append((raw_eth(0x0800, ipv4(bytes(udp_long), proto=17)), "malformed.udp.udp_length"))
    three = bytes(Ether(src=MAC_C, dst=MAC_S) / Dot1AD(vlan=1) / Dot1Q(vlan=2) / Dot1Q(vlan=3) / IP() / TCP())
    cases.append((three, "unsupported.vlan.vlan_depth"))
    cases.append((raw_eth(0x0026, b"\xaa\xaa\x03" + b"\x00" * 40), "unsupported.ethernet.llc"))
    v6 = bytes(IPv6(src="::1", dst="::2", nh=50) / Raw(b"\x00" * 16))
    cases.append((raw_eth(0x86DD, v6), "unsupported.ipv6_ext.ipv6_ext"))
    chain = IPv6(src="::1", dst="::2")
    for _ in range(9):
        chain = chain / IPv6ExtHdrDestOpt()
    cases.append((raw_eth(0x86DD, bytes(chain / UDP())), "unsupported.ipv6_ext.ipv6_ext_chain"))
    v6bad = bytearray(bytes(IPv6(src="::1", dst="::2") / UDP()))
    v6bad[0] = 0x40
    cases.append((raw_eth(0x86DD, bytes(v6bad)), "malformed.ipv6.bad_version"))
    cases.append((raw_eth(0x86DD, bytes(IPv6())[:30]), "truncated.ipv6.short_header"))
    jumbo = bytes(IPv6(src="::1", dst="::2", plen=0) /
                  IPv6ExtHdrHopByHop(options=[Jumbo(jumboplen=100)]) / UDP() / Raw(b"j" * 80))
    cases.append((raw_eth(0x86DD, jumbo), "unsupported.ipv6_ext.ipv6_jumbo"))
    badsum = bytearray(ip_ok)
    badsum[10:12] = b"\xde\xad"
    cases.append((raw_eth(0x0800, bytes(badsum)), "ok"))  # anomaly: ipv4_bad_checksum
    zero_len = bytearray(ip_ok)
    zero_len[2:4] = b"\x00\x00"
    cases.append((raw_eth(0x0800, bytes(zero_len)), "ok"))  # anomaly: ipv4_zero_total_length
    cases.append((frame_bytes(Ether(src=MAC_C, dst=MAC_S) / IP(src="1.1.1.1", dst="2.2.2.2") /
                              TCP(flags="SF")), "ok"))  # anomaly: tcp_flags_invalid
    frames = [frame_bytes(c[0]) if len(c[0]) >= 14 else c[0] for c in cases]
    errors = {}
    for _, k in cases:
        if k != "ok":
            errors[k] = errors.get(k, 0) + 1
    return records_from(frames), {
        "per_record": [k for _, k in cases],
        "decode_errors": errors,
        "anomalies": {"ipv4_bad_checksum": 1, "ipv4_zero_total_length": 1,
                      "tcp_flags_invalid": 1}}


@fixture
def truncated_tail(rng):
    s = TcpSession("10.11.0.1", "10.11.0.2", 33010, 80, 1, 2)
    frames = s.handshake()
    recs = records_from(frames)
    cut = struct.pack("<IIII", 1_700_000_001, 0, 200, 200) + b"\x00" * 50
    return recs, {"status": "truncated", "records": 3, "truncated_tail_bytes": len(cut),
                  "_tail": cut}


@fixture
def corrupt_record(rng):
    s = TcpSession("10.12.0.1", "10.12.0.2", 33011, 80, 1, 2)
    frames = s.handshake()
    recs = records_from(frames)
    recs.insert(2, {"ts_ns": BASE_TS_NS + 1_500_000, "data": b"\x00" * 64, "incl_len": 300000})
    return recs, {"status": "corrupt", "records": 2}


@fixture
def header_only(rng):
    return [], {"status": "complete", "records": 0, "flows": {"tcp": 0, "udp": 0}}


@fixture
def ts_nonmonotonic(rng):
    s = TcpSession("10.13.0.1", "10.13.0.2", 33012, 80, 100, 200)
    req, resp = rng.randbytes(100), rng.randbytes(2000)
    frames = normal_exchange(s, req, resp, 1000)
    recs = records_from(frames)
    recs[4]["ts_ns"] = BASE_TS_NS - 5_000_000_000  # one record 5 s in the past
    return recs, {"timestamp_regressions": 1, "flows": {"tcp": 1, "udp": 0},
                  "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))]}


@fixture
def big_endian_nsec(rng):
    s = TcpSession("10.14.0.1", "10.14.0.2", 33013, 80, 300, 400)
    req, resp = rng.randbytes(50), rng.randbytes(1200)
    frames = normal_exchange(s, req, resp, 1460)
    return records_from(frames, step_ns=1_234), {
        "_endian": ">", "_nsec": True, "flows": {"tcp": 1, "udp": 0},
        "streams": [stream_truth(s, direction_truth(req), direction_truth(resp))]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).parent))
    args = ap.parse_args()
    out = Path(args.out)
    for name, fn in FIXTURES.items():
        rng = random.Random(name)  # per-fixture seed => adding fixtures never changes others
        recs, truth = fn(rng)
        tail = truth.pop("_tail", b"")
        endian = truth.pop("_endian", "<")
        nsec = truth.pop("_nsec", False)
        snaplen = truth.get("snaplen", 262144)
        truth.setdefault("status", "complete")
        truth.setdefault("records", len(recs))
        write_pcap(out / f"{name}.pcap", recs, snaplen=snaplen, endian=endian, nsec=nsec,
                   tail=tail)
        (out / f"{name}.truth.json").write_text(json.dumps({"fixture": name, **truth},
                                                           indent=2, sort_keys=True) + "\n")
        print(f"{name:24s} {len(recs):4d} records")


if __name__ == "__main__":
    main()
