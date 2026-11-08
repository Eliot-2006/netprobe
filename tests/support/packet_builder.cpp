#include "support/packet_builder.h"

#include <cstdio>
#include <stdexcept>

namespace netprobe::test {

namespace {
void put8(ByteVec& v, unsigned x) {
    v.push_back(static_cast<std::byte>(x & 0xFFu));
}
void put16(ByteVec& v, unsigned x) {
    put8(v, x >> 8);
    put8(v, x);
}
void put32(ByteVec& v, std::uint32_t x) {
    put16(v, x >> 16);
    put16(v, x & 0xFFFFu);
}
void put_n(ByteVec& v, const ByteVec& b) {
    v.insert(v.end(), b.begin(), b.end());
}
template <class A> void put_arr(ByteVec& v, const A& a) {
    for (auto x : a) {
        put8(v, x);
    }
}
void pad_to_multiple(ByteVec& v, std::size_t m, unsigned fill) {
    while (v.size() % m != 0) {
        put8(v, fill);
    }
}
void put_order16(ByteVec& v, ByteOrder o, std::uint16_t x) {
    if (o == ByteOrder::big) {
        put16(v, x);
    } else {
        put8(v, x);
        put8(v, x >> 8);
    }
}
void put_order32(ByteVec& v, ByteOrder o, std::uint32_t x) {
    if (o == ByteOrder::big) {
        put32(v, x);
    } else {
        put8(v, x);
        put8(v, x >> 8);
        put8(v, x >> 16);
        put8(v, x >> 24);
    }
}
} // namespace

ByteVec bytes_of(std::string_view s) {
    ByteVec v;
    for (char c : s) {
        put8(v, static_cast<unsigned char>(c));
    }
    return v;
}
ByteVec bytes_of(std::initializer_list<unsigned> values) {
    ByteVec v;
    for (unsigned x : values) {
        put8(v, x);
    }
    return v;
}
ByteVec counting_bytes(std::size_t n, unsigned start) {
    ByteVec v;
    for (std::size_t i = 0; i < n; ++i) {
        put8(v, start + static_cast<unsigned>(i));
    }
    return v;
}
ByteVec concat(const ByteVec& a, const ByteVec& b) {
    ByteVec v = a;
    put_n(v, b);
    return v;
}
Addr6 addr6(std::initializer_list<unsigned> leading_bytes) {
    Addr6 a{};
    std::size_t i = 0;
    for (unsigned x : leading_bytes) {
        a.at(i++) = static_cast<std::uint8_t>(x);
    }
    return a;
}

ByteVec eth(std::uint16_t ethertype, const ByteVec& payload, const std::vector<VlanTag>& vlans) {
    ByteVec v;
    put_arr(v, std::array<std::uint8_t, 6>{0x02, 0, 0, 0, 0, 0x02}); // dst
    put_arr(v, std::array<std::uint8_t, 6>{0x02, 0, 0, 0, 0, 0x01}); // src
    for (const VlanTag& t : vlans) {
        put16(v, t.tpid);
        put16(v, t.tci);
    }
    put16(v, ethertype);
    put_n(v, payload);
    return v;
}

ByteVec pad_to(ByteVec frame, std::size_t n, std::uint8_t fill) {
    while (frame.size() < n) {
        put8(frame, fill);
    }
    return frame;
}

ByteVec ipv4(const Ipv4Opts& o, const ByteVec& payload) {
    ByteVec opts = o.options;
    pad_to_multiple(opts, 4, 0);
    const std::size_t hlen = 20 + opts.size();
    ByteVec v;
    put8(v, (unsigned{o.version.value_or(4)} << 4) |
                o.ihl.value_or(static_cast<std::uint8_t>(hlen / 4)));
    put8(v, 0); // DSCP/ECN
    put16(v, o.total_length.value_or(static_cast<std::uint16_t>(hlen + payload.size())));
    put16(v, o.id);
    put16(v, (o.df ? 0x4000u : 0u) | (o.mf ? 0x2000u : 0u) | (o.frag_offset & 0x1FFFu));
    put8(v, o.ttl);
    put8(v, o.proto);
    put16(v, 0); // checksum placeholder
    put_arr(v, o.src);
    put_arr(v, o.dst);
    put_n(v, opts);
    // RFC 1071 over the bytes just written (honours an overridden IHL only via hlen bytes).
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < v.size(); i += 2) {
        sum += (std::to_integer<unsigned>(v[i]) << 8) | std::to_integer<unsigned>(v[i + 1]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    unsigned csum = ~sum & 0xFFFFu;
    if (o.bad_checksum) {
        csum ^= 0x0001u;
    }
    v[10] = static_cast<std::byte>(csum >> 8);
    v[11] = static_cast<std::byte>(csum & 0xFFu);
    put_n(v, payload);
    return v;
}

ByteVec ipv6(const Ipv6Opts& o, const ByteVec& payload) {
    ByteVec chain;
    for (std::size_t i = 0; i < o.ext.size(); ++i) {
        const Ipv6Ext& e = o.ext[i];
        const std::uint8_t next = i + 1 < o.ext.size() ? o.ext[i + 1].type : o.next_header;
        const std::size_t len = e.len < 8 ? 8 : e.len;
        ByteVec h;
        put8(h, next);
        put8(h, e.type == 44 ? 0u : static_cast<unsigned>(len / 8 - 1));
        if (e.type == 44) {
            put16(h, (static_cast<unsigned>(e.frag_offset) << 3) | (e.more ? 1u : 0u));
            put32(h, e.frag_id);
        } else {
            put_n(h, e.body);
        }
        while (h.size() < len) {
            put8(h, 0);
        }
        h.resize(len);
        put_n(chain, h);
    }
    ByteVec v;
    put8(v, (unsigned{o.version.value_or(6)} << 4) | (o.traffic_class >> 4u));
    put8(v, ((o.traffic_class & 0xFu) << 4) | ((o.flow_label >> 16) & 0xFu));
    put16(v, o.flow_label & 0xFFFFu);
    put16(v, o.payload_length.value_or(static_cast<std::uint16_t>(chain.size() + payload.size())));
    put8(v, o.ext.empty() ? o.next_header : o.ext.front().type);
    put8(v, o.hlim);
    put_arr(v, o.src);
    put_arr(v, o.dst);
    put_n(v, chain);
    put_n(v, payload);
    return v;
}

ByteVec tcp(const TcpOpts& o, const ByteVec& payload) {
    ByteVec opts = o.options;
    pad_to_multiple(opts, 4, 0);
    const unsigned doff = o.data_offset.value_or(static_cast<std::uint8_t>(5 + opts.size() / 4));
    ByteVec v;
    put16(v, o.sport);
    put16(v, o.dport);
    put32(v, o.seq);
    put32(v, o.ack);
    put8(v, doff << 4);
    put8(v, o.flags);
    put16(v, o.window);
    put16(v, 0); // checksum (not verified)
    put16(v, 0); // urgent pointer
    put_n(v, opts);
    put_n(v, payload);
    return v;
}
ByteVec tcp_opt_mss(std::uint16_t mss) {
    return bytes_of({2u, 4u, unsigned{mss} >> 8u, unsigned{mss} & 0xFFu});
}
ByteVec tcp_opt_wscale(std::uint8_t shift) {
    return bytes_of({3, 3, shift});
}
ByteVec tcp_opt_nop() {
    return bytes_of({1});
}
ByteVec tcp_opt_sack_permitted() {
    return bytes_of({4, 2});
}
ByteVec tcp_opt_timestamps(std::uint32_t val, std::uint32_t echo) {
    ByteVec v = bytes_of({8, 10});
    put32(v, val);
    put32(v, echo);
    return v;
}

ByteVec udp(const UdpOpts& o, const ByteVec& payload) {
    ByteVec v;
    put16(v, o.sport);
    put16(v, o.dport);
    put16(v, o.length.value_or(static_cast<std::uint16_t>(8 + payload.size())));
    put16(v, 0);
    put_n(v, payload);
    return v;
}

ByteVec pcap_global_header(const PcapFileOpts& o) {
    ByteVec v;
    // The magic is a 32-bit number written in the file's own byte order.
    put_order32(v, o.order, o.magic.value_or(o.nanosecond ? 0xA1B23C4Du : 0xA1B2C3D4u));
    put_order16(v, o.order, o.ver_major);
    put_order16(v, o.order, o.ver_minor);
    put_order32(v, o.order, 0); // thiszone
    put_order32(v, o.order, 0); // sigfigs
    put_order32(v, o.order, o.snaplen);
    put_order32(v, o.order, o.linktype_field);
    return v;
}
ByteVec pcap_record(const PcapFileOpts& o, const PcapRecordSpec& r) {
    ByteVec v;
    put_order32(v, o.order, r.ts_sec);
    put_order32(v, o.order, r.ts_frac);
    put_order32(v, o.order, r.incl_len.value_or(static_cast<std::uint32_t>(r.data.size())));
    put_order32(v, o.order, r.orig_len.value_or(static_cast<std::uint32_t>(r.data.size())));
    put_n(v, r.data);
    return v;
}
ByteVec pcap_file(const PcapFileOpts& o, const std::vector<PcapRecordSpec>& records) {
    ByteVec v = pcap_global_header(o);
    for (const PcapRecordSpec& r : records) {
        put_n(v, pcap_record(o, r));
    }
    return v;
}

void write_file(const std::filesystem::path& path, const ByteVec& bytes) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (f == nullptr) {
        throw std::runtime_error("cannot create " + path.string());
    }
    const std::size_t n = bytes.empty() ? 0 : std::fwrite(bytes.data(), 1, bytes.size(), f);
    const bool bad = std::fclose(f) != 0 || n != bytes.size();
    if (bad) {
        throw std::runtime_error("cannot write " + path.string());
    }
}

} // namespace netprobe::test
