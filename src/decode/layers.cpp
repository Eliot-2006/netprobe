#include "decode/layers.h"

#include <algorithm>

namespace netprobe::layers {

namespace {

constexpr Step ok_step(Layer l, Bytes rest, std::uint32_t logical) noexcept {
    return {{DecodeKind::ok, l, Reason::none}, rest, logical};
}
constexpr Step fail_step(DecodeKind k, Layer l, Reason r) noexcept {
    return {{k, l, r}, {}, 0};
}
constexpr Step short_hdr(Layer l) noexcept {
    return fail_step(DecodeKind::truncated, l, Reason::short_header);
}

constexpr bool is_vlan_tpid(std::uint16_t t) noexcept {
    return t == 0x8100 || t == 0x88A8 || t == 0x9100;
}

void set_v4(IpAddr& a, const std::byte* p) noexcept {
    a.b.fill(0);
    a.b[10] = 0xFF;
    a.b[11] = 0xFF;
    for (std::size_t i = 0; i < 4; ++i) {
        a.b[12 + i] = load_u8(p + i);
    }
}

void set_v6(IpAddr& a, const std::byte* p) noexcept {
    for (std::size_t i = 0; i < 16; ++i) {
        a.b[i] = load_u8(p + i);
    }
}

// First min(n, size) bytes.
Bytes first(Bytes b, std::size_t n) noexcept {
    return b.first(std::min(n, b.size()));
}

// IPv6 next-header values that are extension headers we walk, or ones we refuse.
constexpr bool walkable_ext(std::uint8_t nh) noexcept {
    return nh == 0 || nh == 43 || nh == 60;
}
constexpr bool unsupported_ext(std::uint8_t nh) noexcept {
    return nh == 50 || nh == 51 || nh == 135 || nh == 139 || nh == 140;
}
constexpr std::uint8_t nh_fragment = 44;
constexpr std::size_t max_ext_headers = 8;

// True if the Hop-by-Hop header (fully captured in `h`) carries a Jumbo Payload option (0xC2).
bool hbh_has_jumbo(Bytes h) noexcept {
    std::size_t i = 2;
    while (i < h.size()) {
        const std::uint8_t t = load_u8(h.data() + i);
        if (t == 0) { // Pad1
            ++i;
            continue;
        }
        if (t == 0xC2) {
            return true;
        }
        if (i + 1 >= h.size()) {
            return false;
        }
        i += std::size_t{2} + load_u8(h.data() + i + 1);
    }
    return false;
}

} // namespace

Step parse_ethernet(Bytes f, DecodedPacket& p) noexcept {
    if (f.size() < 14) {
        return short_hdr(Layer::ethernet);
    }
    std::uint16_t et = load_be16(f.data() + 12);
    std::size_t off = 14;
    Layer layer = Layer::ethernet;
    while (is_vlan_tpid(et)) {
        if (p.vlan_count == 2) {
            return fail_step(DecodeKind::unsupported, Layer::vlan, Reason::vlan_depth);
        }
        if (f.size() < off + 4) {
            return short_hdr(Layer::vlan);
        }
        p.vlan_ids[p.vlan_count++] = load_be16(f.data() + off) & 0x0FFFu;
        et = load_be16(f.data() + off + 2);
        off += 4;
        layer = Layer::vlan;
    }
    p.ethertype = et;
    if (et < 0x0600) { // 802.3 length field: LLC/SNAP frame
        return fail_step(DecodeKind::unsupported, layer, Reason::llc);
    }
    const Bytes rest = f.subspan(off);
    return ok_step(layer, rest, static_cast<std::uint32_t>(rest.size()));
}

Step parse_ipv4(Bytes l3, DecodedPacket& p) noexcept {
    if (l3.size() < 20) {
        return short_hdr(Layer::ipv4);
    }
    const std::byte* h = l3.data();
    if ((load_u8(h) >> 4) != 4) {
        return fail_step(DecodeKind::malformed, Layer::ipv4, Reason::bad_version);
    }
    const std::size_t hlen = static_cast<std::size_t>(load_u8(h) & 0x0F) * 4;
    if (hlen < 20) {
        return fail_step(DecodeKind::malformed, Layer::ipv4, Reason::bad_ihl);
    }
    if (l3.size() < hlen) {
        return short_hdr(Layer::ipv4);
    }
    const std::size_t total = load_be16(h + 2);
    if (total != 0 && total < hlen) {
        return fail_step(DecodeKind::malformed, Layer::ipv4, Reason::bad_total_length);
    }

    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < hlen; i += 2) {
        sum += load_be16(h + i);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    p.ip_version = 4;
    p.ipv4_checksum_ok = sum == 0xFFFFu;
    p.ttl_or_hlim = load_u8(h + 8);
    p.l4_proto = load_u8(h + 9);
    set_v4(p.src, h + 12);
    set_v4(p.dst, h + 16);

    std::size_t logical_total = total;
    if (total == 0) { // TSO: the capturing host left the length unset
        p.ip_zero_length = true;
        logical_total = l3.size();
    } else if (total > l3.size()) {
        p.l3_truncated = true;
    }
    const Bytes region = first(l3, logical_total);

    const std::uint16_t frag = load_be16(h + 6);
    if ((frag & 0x2000u) != 0 || (frag & 0x1FFFu) != 0) {
        p.is_fragment = true;
        return ok_step(Layer::ipv4, {}, 0);
    }
    return ok_step(Layer::ipv4, region.subspan(hlen),
                   static_cast<std::uint32_t>(logical_total - hlen));
}

Step parse_ipv6(Bytes l3, DecodedPacket& p) noexcept {
    if (l3.size() < 40) {
        return short_hdr(Layer::ipv6);
    }
    const std::byte* h = l3.data();
    if ((load_u8(h) >> 4) != 6) {
        return fail_step(DecodeKind::malformed, Layer::ipv6, Reason::bad_version);
    }
    p.ip_version = 6;
    p.ttl_or_hlim = load_u8(h + 7);
    set_v6(p.src, h + 8);
    set_v6(p.dst, h + 24);
    std::uint8_t nh = load_u8(h + 6);
    const std::size_t plen = load_be16(h + 4);

    // The jumbo option lives in a Hop-by-Hop header, which is the first extension header.
    if (nh == 0 && l3.size() >= 48) {
        const std::size_t hl = (static_cast<std::size_t>(load_u8(h + 41)) + 1) * 8;
        if (l3.size() >= 40 + hl && hbh_has_jumbo(l3.subspan(40, hl))) {
            return fail_step(DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_jumbo);
        }
    }

    std::size_t logical = plen;
    if (plen == 0) {
        p.ip_zero_length = true;
        logical = l3.size() - 40;
    } else if (plen > l3.size() - 40) {
        p.l3_truncated = true;
    }
    Bytes region = first(l3.subspan(40), logical);
    std::size_t consumed = 0; // extension header bytes skipped

    for (std::size_t n = 0;; ++n) {
        if (unsupported_ext(nh)) {
            return fail_step(DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_ext);
        }
        if (nh != nh_fragment && !walkable_ext(nh)) {
            break;
        }
        if (n == max_ext_headers) {
            return fail_step(DecodeKind::unsupported, Layer::ipv6_ext, Reason::ipv6_ext_chain);
        }
        if (region.size() < 8) {
            return p.l3_truncated ? short_hdr(Layer::ipv6_ext)
                                  : fail_step(DecodeKind::malformed, Layer::ipv6_ext,
                                              Reason::bad_total_length);
        }
        const std::uint8_t next = load_u8(region.data());
        if (nh == nh_fragment) {
            p.is_fragment = true;
            p.l4_proto = next;
            return ok_step(Layer::ipv6_ext, {}, 0);
        }
        const std::size_t hl = (static_cast<std::size_t>(load_u8(region.data() + 1)) + 1) * 8;
        if (hl > region.size()) {
            return p.l3_truncated ? short_hdr(Layer::ipv6_ext)
                                  : fail_step(DecodeKind::malformed, Layer::ipv6_ext,
                                              Reason::bad_total_length);
        }
        region = region.subspan(hl);
        consumed += hl;
        nh = next;
    }
    p.l4_proto = nh;
    return ok_step(consumed != 0 ? Layer::ipv6_ext : Layer::ipv6, region,
                   static_cast<std::uint32_t>(logical - consumed));
}

namespace {
// Walks TCP options (already fully captured). Sets MSS/WS; returns false on any violation.
bool walk_tcp_options(Bytes o, DecodedPacket& p) noexcept {
    bool clean = true;
    std::size_t i = 0;
    while (i < o.size()) {
        const std::uint8_t kind = load_u8(o.data() + i);
        if (kind == 0) { // EOL
            break;
        }
        if (kind == 1) { // NOP
            ++i;
            continue;
        }
        if (i + 1 >= o.size()) {
            return false;
        }
        const std::size_t len = load_u8(o.data() + i + 1);
        if (len < 2 || i + len > o.size()) {
            return false;
        }
        const std::byte* d = o.data() + i + 2;
        switch (kind) {
        case 2:
            if (len == 4) {
                p.mss = load_be16(d);
                p.has_mss = true;
            } else {
                clean = false;
            }
            break;
        case 3:
            if (len == 3) {
                p.wscale = std::min<std::uint8_t>(load_u8(d), 14); // RFC 7323 cap
                p.has_wscale = true;
            } else {
                clean = false;
            }
            break;
        case 4:
            clean = clean && len == 2;
            break;
        case 5:
            clean = clean && len >= 10 && (len - 2) % 8 == 0;
            break;
        case 8:
            clean = clean && len == 10;
            break;
        default:
            break; // unknown kinds are skipped by length
        }
        i += len;
    }
    return clean;
}
} // namespace

Step parse_tcp(Bytes l4, std::uint32_t logical, DecodedPacket& p) noexcept {
    if (l4.size() < 20) {
        return short_hdr(Layer::tcp);
    }
    const std::byte* h = l4.data();
    const std::size_t hlen = static_cast<std::size_t>(load_u8(h + 12) >> 4) * 4;
    if (hlen < 20 || hlen > logical) {
        return fail_step(DecodeKind::malformed, Layer::tcp, Reason::tcp_data_offset);
    }
    if (hlen > l4.size()) {
        return short_hdr(Layer::tcp);
    }
    p.src_port = load_be16(h);
    p.dst_port = load_be16(h + 2);
    p.seq = load_be32(h + 4);
    p.ack = load_be32(h + 8);
    p.tcp_flags = load_u8(h + 13);
    p.window = load_be16(h + 14);
    p.tcp_options_malformed = !walk_tcp_options(l4.subspan(20, hlen - 20), p);
    return ok_step(Layer::tcp, l4.subspan(hlen), logical - static_cast<std::uint32_t>(hlen));
}

Step parse_udp(Bytes l4, std::uint32_t logical, DecodedPacket& p) noexcept {
    if (l4.size() < 8) {
        return short_hdr(Layer::udp);
    }
    const std::byte* h = l4.data();
    const std::uint32_t len = load_be16(h + 4);
    if (len < 8 || len > logical) {
        return fail_step(DecodeKind::malformed, Layer::udp, Reason::udp_length);
    }
    p.src_port = load_be16(h);
    p.dst_port = load_be16(h + 2);
    p.udp_trailing_bytes = logical - len;
    return ok_step(Layer::udp, first(l4.subspan(8), len - 8), len - 8);
}

} // namespace netprobe::layers
