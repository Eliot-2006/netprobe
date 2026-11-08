// synth_pcap: deterministic synthetic PCAP generator for the NetProbe benchmarks (PRD 12.3).
//
// Same arguments => identical bytes (single seeded std::mt19937_64; no libm in the generator
// path). Frames are written by hand from header layouts; nothing here depends on tests/.
//
// Model: a set of concurrently active flows; each step picks one at random and emits its next
// packet. TCP flows are well-formed (handshake, ground-truth seq/ack, FIN close). Impairments act
// on data segments only: "loss" drops the segment from the capture but the receiver's later ACKs
// still cover it (a capture loss, which is what produces acked gaps in the reassembler).
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

struct Profile {
    const char* name;
    u64 size;             // default target file size in bytes
    u64 flows;            // total flows to create; 0 = unlimited (until size is reached)
    u32 concurrent;       // simultaneously active flows
    double udp, v6, vlan; // target packet shares
    double reorder, loss, retransmit, malformed;
    bool trimodal;                  // frame sizes 64/576/1500 instead of uniform payload range
    bool alternate;                 // request/response data (D1) instead of one-way bulk with ACKs
    u32 seg_min, seg_mean, seg_cap; // data segments per flow; mean 0 = uniform [min, cap]
    u32 pay_min, pay_max;
    bool split_size; // D2: flow length derived from size / flows
};

constexpr u64 kGiB = 1ull << 30;
constexpr Profile kProfiles[] = {
    {"d1", kGiB * 3 / 2, 1u << 20, 8192, 0, 0, 0, 0, 0, 0, 0, false, true, 2, 0, 6, 64, 1460,
     false},
    {"d2", 2 * kGiB, 16, 16, 0, 0, 0, 0.005, 0.001, 0, 0, false, false, 1, 0, 1, 1460, 1460, true},
    {"d3", 2 * kGiB, 0, 2048, 0.2, 0.1, 0.1, 0.05, 0.01, 0.01, 0.001, true, false, 2, 30, 2000, 0,
     0, false},
};

constexpr u8 kFin = 0x01, kSyn = 0x02, kPsh = 0x08, kAck = 0x10;
constexpr u32 kWindow = 32; // data segments generated per refill
constexpr u16 kServerPorts[] = {80, 443, 53, 8080, 22, 25, 3306, 5001};

struct Pkt {
    u32 seq = 0, ack = 0;
    u16 payload = 0;
    u8 flags = 0;
    bool from_client = true;
    bool data = false; // eligible for loss / reorder / retransmit
};

struct Flow {
    bool tcp = true, v6 = false, bulk_from_client = false;
    u16 vlan = 0; // 0 = untagged
    std::array<u8, 4> c4{}, s4{};
    u16 cport = 0, sport = 0;
    u32 hdr = 0; // bytes before the payload (Ethernet + VLAN + IP + L4)
    u32 next_c = 0, next_s = 0;
    u32 segs_left = 0;
    u32 seg_index = 0;
    int phase = 0; // 0 handshake, 1 data, 2 fin, 3 done
    std::vector<Pkt> q;
    std::size_t head = 0;
};

struct Counters {
    u64 packets = 0, bytes = 0, flows = 0, tcp_pkts = 0, udp_pkts = 0, v6_pkts = 0, vlan_pkts = 0;
    u64 data_segs = 0, reordered = 0, lost = 0, retrans = 0, malformed = 0;
};

class Generator {
public:
    Generator(const Profile& p, u64 seed, u64 size, u64 flows)
        : p_(p), rng_(seed), size_(size), flow_limit_(flows) {
        noise_.resize(1 << 16);
        for (auto& b : noise_) {
            b = static_cast<u8>(rng_());
        }
        out_.reserve(8u << 20);
        // Pick UDP per flow so that UDP's share of *packets* matches p.udp: a TCP flow carries
        // about 1.5 n + 7 packets for n data segments (handshake, delayed ACKs, close), UDP n.
        const double n =
            p_.seg_mean == 0 ? (p_.seg_min + p_.seg_cap) / 2.0 : p_.seg_min + p_.seg_mean - 1.0;
        const double tcp_len = 1.5 * n + 7;
        udp_flow_prob_ = p_.udp * tcp_len / (n * (1 - p_.udp) + p_.udp * tcp_len);
        put_global_header();
    }

    // Returns false on I/O error.
    bool run(std::FILE* f) {
        std::vector<Flow> active;
        const u32 n = flow_limit_ != 0 ? static_cast<u32>(std::min<u64>(p_.concurrent, flow_limit_))
                                       : p_.concurrent;
        active.resize(n);
        for (auto& fl : active) {
            new_flow(fl);
        }
        while (file_bytes_ < size_ && !active.empty()) {
            const std::size_t i = static_cast<std::size_t>(rng_() % active.size());
            Flow& fl = active[i];
            while (fl.head == fl.q.size() && !(fl.tcp ? fl.phase == 3 : fl.segs_left == 0)) {
                refill(fl);
            }
            if (fl.head == fl.q.size()) { // finished
                if (flow_limit_ == 0 || c_.flows < flow_limit_) {
                    new_flow(fl);
                } else {
                    fl = std::move(active.back());
                    active.pop_back();
                }
                continue;
            }
            emit(fl, fl.q[fl.head++]);
            if (out_.size() >= (4u << 20) && !flush(f)) {
                return false;
            }
        }
        return flush(f);
    }

    const Counters& counters() const { return c_; }
    u64 file_bytes() const { return file_bytes_; }

private:
    bool chance(double p) { return (rng_() >> 32) < static_cast<u64>(p * 4294967296.0); }
    u32 below(u32 n) { return static_cast<u32>(rng_() % n); }

    bool flush(std::FILE* f) {
        const bool ok = std::fwrite(out_.data(), 1, out_.size(), f) == out_.size();
        out_.clear();
        return ok;
    }

    void put8(u8 v) { out_.push_back(v); }
    void put_le16(u16 v) {
        put8(static_cast<u8>(v));
        put8(static_cast<u8>(v >> 8));
    }
    void put_le32(u32 v) {
        put_le16(static_cast<u16>(v));
        put_le16(static_cast<u16>(v >> 16));
    }
    void put_global_header() {
        put_le32(0xa1b2c3d4u);
        put_le16(2);
        put_le16(4);
        put_le32(0);
        put_le32(0);
        put_le32(65535);
        put_le32(1);
        file_bytes_ = 24;
    }

    // ---- flow creation ----
    u32 draw_segments() {
        if (p_.seg_mean == 0) {
            return p_.seg_min + below(p_.seg_cap - p_.seg_min + 1);
        }
        u32 n = p_.seg_min;
        while (n < p_.seg_cap && !chance(1.0 / p_.seg_mean)) { // geometric, libm-free
            ++n;
        }
        return n;
    }

    void new_flow(Flow& f) {
        ++c_.flows;
        f.q.clear();
        f.head = 0;
        f.phase = 0;
        f.seg_index = 0;
        f.tcp = !chance(udp_flow_prob_);
        f.v6 = chance(p_.v6);
        f.vlan = chance(p_.vlan) ? static_cast<u16>(1 + below(4094)) : u16{0};
        const u32 serial = static_cast<u32>(c_.flows) & 0xFFFFFF;
        f.c4 = {10, static_cast<u8>(serial >> 16), static_cast<u8>(serial >> 8),
                static_cast<u8>(serial)};
        f.s4 = {172, 16, 0, static_cast<u8>(1 + below(250))};
        f.cport = static_cast<u16>(1024 + below(64000));
        f.sport = f.tcp ? kServerPorts[below(8)] : static_cast<u16>(f.cport % 2 ? 53 : 123);
        f.hdr = 14 + (f.vlan ? 4u : 0u) + (f.v6 ? 40u : 20u) + (f.tcp ? 20u : 8u);
        f.next_c = static_cast<u32>(rng_());
        f.next_s = static_cast<u32>(rng_());
        f.bulk_from_client = !p_.alternate && p_.udp > 0 && below(4) == 0; // some uploads in D3
        f.segs_left = p_.split_size && flow_limit_ != 0
                          ? static_cast<u32>(std::max<u64>(1, size_ / flow_limit_ / 1541))
                          : draw_segments();
        if (!f.tcp) {
            f.phase = 1;
        }
    }

    u32 draw_payload(const Flow& f) {
        if (p_.trimodal) {
            const u32 r = below(10);
            const u32 frame = r < 4 ? 64 : r < 6 ? 576 : 1500;
            return frame > f.hdr ? frame - f.hdr : 0;
        }
        return p_.pay_min + below(p_.pay_max - p_.pay_min + 1);
    }

    // ---- per-flow packet plans ----
    void refill(Flow& f) {
        f.q.clear();
        f.head = 0;
        if (!f.tcp) {
            refill_udp(f);
            return;
        }
        switch (f.phase) {
        case 0: // handshake
            f.q.push_back({f.next_c, 0, 0, kSyn, true, false});
            f.q.push_back({f.next_s, f.next_c + 1, 0, kSyn | kAck, false, false});
            ++f.next_c;
            ++f.next_s;
            f.q.push_back({f.next_c, f.next_s, 0, kAck, true, false});
            f.phase = 1;
            break;
        case 1:
            refill_tcp_data(f);
            if (f.segs_left == 0) {
                f.phase = 2;
            }
            break;
        case 2: // close: client FIN, server ACK, server FIN, client ACK
            f.q.push_back({f.next_c, f.next_s, 0, kFin | kAck, true, false});
            f.q.push_back({f.next_s, f.next_c + 1, 0, kAck, false, false});
            f.q.push_back({f.next_s, f.next_c + 1, 0, kFin | kAck, false, false});
            f.q.push_back({f.next_c + 1, f.next_s + 1, 0, kAck, true, false});
            f.phase = 3;
            break;
        default:
            break;
        }
    }

    void refill_udp(Flow& f) {
        const u32 n = std::min(f.segs_left, kWindow);
        for (u32 i = 0; i < n; ++i) {
            f.q.push_back(
                {0, 0, static_cast<u16>(draw_payload(f)), 0, (f.seg_index++ & 1) == 0, false});
        }
        f.segs_left -= n;
    }

    void refill_tcp_data(Flow& f) {
        const u32 n = std::min(f.segs_left, kWindow);
        std::vector<Pkt>& plan = plan_;
        plan.clear();
        for (u32 i = 0; i < n; ++i) {
            const bool from_client = p_.alternate ? (f.seg_index & 1) == 0 : f.bulk_from_client;
            ++f.seg_index;
            const u32 len = draw_payload(f);
            u32& mine = from_client ? f.next_c : f.next_s;
            const u32 peer = from_client ? f.next_s : f.next_c;
            plan.push_back({mine, peer, static_cast<u16>(len),
                            static_cast<u8>(kAck | (p_.alternate || i + 1 == n ? kPsh : 0)),
                            from_client, true});
            mine += len;
            if (!p_.alternate && ((i & 1) != 0 || i + 1 == n)) { // delayed ACK from the receiver
                plan.push_back({peer, mine, 0, kAck, !from_client, false});
            }
        }
        f.segs_left -= n;

        // Apply impairments: drop (capture loss), displace by 1..8 positions, duplicate later.
        delayed_.clear();
        for (const Pkt& pk : plan) {
            if (pk.data) {
                ++c_.data_segs;
                if (chance(p_.loss)) {
                    ++c_.lost;
                    continue;
                }
                if (chance(p_.reorder)) {
                    ++c_.reordered;
                    delayed_.push_back({f.q.size() + 1 + below(8), pk});
                    continue;
                }
                if (chance(p_.retransmit)) {
                    ++c_.retrans;
                    delayed_.push_back({f.q.size() + 1 + below(8), pk});
                }
            }
            f.q.push_back(pk);
            release_due(f);
        }
        while (!delayed_.empty()) { // anything still pending lands at the window end
            f.q.push_back(delayed_.back().second);
            delayed_.pop_back();
        }
    }

    void release_due(Flow& f) {
        for (bool moved = true; moved;) {
            moved = false;
            for (std::size_t i = 0; i < delayed_.size(); ++i) {
                if (delayed_[i].first <= f.q.size()) {
                    f.q.push_back(delayed_[i].second);
                    delayed_.erase(delayed_.begin() + static_cast<std::ptrdiff_t>(i));
                    moved = true;
                    break;
                }
            }
        }
    }

    // ---- wire format ----
    static void be16(u8* p, u32 v) {
        p[0] = static_cast<u8>(v >> 8);
        p[1] = static_cast<u8>(v);
    }
    static void be32(u8* p, u32 v) {
        be16(p, v >> 16);
        be16(p + 2, v & 0xFFFF);
    }

    void emit(const Flow& f, const Pkt& pk) {
        u8 fr[2048];
        std::size_t o = 0;
        const bool c = pk.from_client;
        for (int i = 0; i < 6; ++i) {
            fr[o++] = i == 5 ? (c ? 2 : 1) : (i == 0 ? 2 : 0); // dst mac
        }
        for (int i = 0; i < 6; ++i) {
            fr[o++] = i == 5 ? (c ? 1 : 2) : (i == 0 ? 2 : 0); // src mac
        }
        if (f.vlan) {
            be16(fr + o, 0x8100);
            be16(fr + o + 2, f.vlan);
            o += 4;
        }
        be16(fr + o, f.v6 ? 0x86DD : 0x0800);
        o += 2;
        const std::size_t l3 = o;
        const u32 l4len = (f.tcp ? (pk.flags & kSyn ? 28u : 20u) : 8u) + pk.payload;
        const u8 proto = f.tcp ? 6 : 17;
        const auto& sa = c ? f.c4 : f.s4;
        const auto& da = c ? f.s4 : f.c4;
        if (f.v6) {
            be32(fr + o, 0x60000000);
            be16(fr + o + 4, l4len);
            fr[o + 6] = proto;
            fr[o + 7] = 64;
            std::memset(fr + o + 8, 0, 32);
            const u8 prefix[] = {0x20, 0x01, 0x0d, 0xb8};
            std::memcpy(fr + o + 8, prefix, 4);
            std::memcpy(fr + o + 24, prefix, 4);
            std::memcpy(fr + o + 20, sa.data(), 4);
            std::memcpy(fr + o + 36, da.data(), 4);
            o += 40;
        } else {
            fr[o] = 0x45;
            fr[o + 1] = 0;
            be16(fr + o + 2, 20 + l4len);
            be16(fr + o + 4, ip_id_++);
            be16(fr + o + 6, 0x4000);
            fr[o + 8] = 64;
            fr[o + 9] = proto;
            be16(fr + o + 10, 0);
            std::memcpy(fr + o + 12, sa.data(), 4);
            std::memcpy(fr + o + 16, da.data(), 4);
            u32 sum = 0;
            for (int i = 0; i < 20; i += 2) {
                sum += static_cast<u32>(fr[o + static_cast<std::size_t>(i)] << 8 |
                                        fr[o + static_cast<std::size_t>(i) + 1]);
            }
            while (sum >> 16) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            be16(fr + o + 10, ~sum & 0xFFFF);
            o += 20;
        }
        const std::size_t l4 = o;
        be16(fr + o, c ? f.cport : f.sport);
        be16(fr + o + 2, c ? f.sport : f.cport);
        if (f.tcp) {
            const bool syn = pk.flags & kSyn;
            be32(fr + o + 4, pk.seq);
            be32(fr + o + 8, pk.ack);
            fr[o + 12] = syn ? 0x70 : 0x50;
            fr[o + 13] = pk.flags;
            be16(fr + o + 14, 0xFFFF);
            be32(fr + o + 16, 0);
            o += 20;
            if (syn) { // MSS 1460, NOP, window scale 7
                const u8 opts[] = {2, 4, 5, 0xb4, 1, 3, 3, 7};
                std::memcpy(fr + o, opts, 8);
                o += 8;
            }
        } else {
            be16(fr + o + 4, l4len);
            be16(fr + o + 6, 0);
            o += 8;
        }
        // TCP payload is a function of (direction, seq) so retransmissions carry identical bytes.
        const std::size_t span = noise_.size() - 2048;
        std::memcpy(fr + o,
                    noise_.data() + (f.tcp ? (pk.seq + (c ? 0u : 4099u)) % span : noise_off_),
                    pk.payload);
        noise_off_ = (noise_off_ + 997) % span;
        o += pk.payload;

        if (chance(p_.malformed)) {
            o = mutate(fr, f, l3, l4, o);
        }

        ts_us_ += 1 + below(2 * mean_gap_us_ - 1);
        put_le32(static_cast<u32>(ts_us_ / 1'000'000));
        put_le32(static_cast<u32>(ts_us_ % 1'000'000));
        put_le32(static_cast<u32>(o));
        put_le32(static_cast<u32>(o));
        out_.insert(out_.end(), fr, fr + o);
        file_bytes_ += 16 + o;
        ++c_.packets;
        c_.bytes += o;
        (f.tcp ? c_.tcp_pkts : c_.udp_pkts)++;
        c_.v6_pkts += f.v6;
        c_.vlan_pkts += f.vlan != 0;
    }

    // Returns the new frame length. Each variant maps to a decoder rejection reason.
    std::size_t mutate(u8* fr, const Flow& f, std::size_t l3, std::size_t l4, std::size_t len) {
        ++c_.malformed;
        switch (below(5)) {
        case 0:
            return l3 + 10; // cut inside the IP header
        case 1:
            fr[l3] = static_cast<u8>((fr[l3] & 0x0F) | 0x30); // bad IP version
            break;
        case 2:
            if (!f.v6) {
                fr[l3] = 0x42; // IHL 2
            } else {
                return l3 + 20; // cut inside the IPv6 header
            }
            break;
        case 3:
            if (!f.v6) {
                be16(fr + l3 + 2, 10); // total_length < header
            } else {
                be16(fr + l3 + 4, 0xFFF0); // payload_length beyond the capture
            }
            break;
        default:
            if (f.tcp) {
                fr[l4 + 12] = 0x20; // data offset 2
            } else {
                be16(fr + l4 + 4, 3); // UDP length < 8
            }
            break;
        }
        return len;
    }

    struct Delayed {
        std::size_t first;
        Pkt second;
        Delayed(std::size_t a, const Pkt& b) : first(a), second(b) {}
    };

    const Profile& p_;
    std::mt19937_64 rng_;
    u64 size_, flow_limit_;
    std::vector<u8> noise_, out_;
    std::vector<Pkt> plan_;
    std::vector<Delayed> delayed_;
    std::size_t noise_off_ = 0;
    u64 ts_us_ = 1'700'000'000ull * 1'000'000;
    u32 mean_gap_us_ = 5;
    u64 file_bytes_ = 0;
    u16 ip_id_ = 1;
    double udp_flow_prob_ = 0;
    Counters c_;
};

u64 parse_size(const char* s) {
    char* end = nullptr;
    const double v = std::strtod(s, &end);
    u64 mul = 1;
    switch (*end) {
    case 'k':
    case 'K':
        mul = 1ull << 10;
        break;
    case 'm':
    case 'M':
        mul = 1ull << 20;
        break;
    case 'g':
    case 'G':
        mul = 1ull << 30;
        break;
    default:
        break;
    }
    return static_cast<u64>(v * static_cast<double>(mul));
}

void usage() {
    std::fputs("usage: synth_pcap -o PATH [--profile d1|d2|d3] [--seed N] [--size BYTES[K|M|G]]\n"
               "                  [--flows N] [--reorder PCT] [--loss PCT]\n",
               stderr);
}

} // namespace

int main(int argc, char** argv) {
    const char* path = nullptr;
    const char* profile_name = "d3";
    u64 seed = 1;
    std::string size_arg, flows_arg, reorder_arg, loss_arg;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        const char* v = nullptr;
        if (a == "-o" || a == "--profile" || a == "--seed" || a == "--size" || a == "--flows" ||
            a == "--reorder" || a == "--loss") {
            v = val();
            if (v == nullptr) {
                usage();
                return 2;
            }
        }
        if (a == "-o")
            path = v;
        else if (a == "--profile")
            profile_name = v;
        else if (a == "--seed")
            seed = std::strtoull(v, nullptr, 10);
        else if (a == "--size")
            size_arg = v;
        else if (a == "--flows")
            flows_arg = v;
        else if (a == "--reorder")
            reorder_arg = v;
        else if (a == "--loss")
            loss_arg = v;
        else {
            usage();
            return 2;
        }
    }
    const Profile* base = nullptr;
    for (const Profile& p : kProfiles) {
        if (profile_name == std::string(p.name)) {
            base = &p;
        }
    }
    if (path == nullptr || base == nullptr) {
        usage();
        return 2;
    }
    Profile prof = *base;
    if (!reorder_arg.empty())
        prof.reorder = std::strtod(reorder_arg.c_str(), nullptr) / 100.0;
    if (!loss_arg.empty())
        prof.loss = std::strtod(loss_arg.c_str(), nullptr) / 100.0;
    const u64 size = size_arg.empty() ? prof.size : parse_size(size_arg.c_str());
    const u64 flows =
        flows_arg.empty() ? prof.flows : std::strtoull(flows_arg.c_str(), nullptr, 10);

    std::FILE* f = std::fopen(path, "wb");
    if (f == nullptr) {
        std::perror(path);
        return 1;
    }
    const auto t0 = std::chrono::steady_clock::now();
    Generator gen(prof, seed, size, flows);
    const bool ok = gen.run(f);
    const bool closed = std::fclose(f) == 0;
    if (!ok || !closed) {
        std::fprintf(stderr, "synth_pcap: write to %s failed\n", path);
        return 1;
    }
    const double secs =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    const Counters& c = gen.counters();
    const double pk = static_cast<double>(std::max<u64>(c.packets, 1));
    const double ds = static_cast<double>(std::max<u64>(c.data_segs, 1));
    std::printf(
        "synth_pcap: profile=%s seed=%llu file_bytes=%llu packets=%llu flows=%llu "
        "tcp=%.1f%% udp=%.1f%% v6=%.1f%% vlan=%.1f%% data_segs=%llu reorder=%.2f%% "
        "loss=%.2f%% retransmit=%.2f%% malformed=%.3f%% elapsed=%.2fs rate=%.0fMiB/s\n",
        prof.name, static_cast<unsigned long long>(seed),
        static_cast<unsigned long long>(gen.file_bytes()),
        static_cast<unsigned long long>(c.packets), static_cast<unsigned long long>(c.flows),
        100.0 * static_cast<double>(c.tcp_pkts) / pk, 100.0 * static_cast<double>(c.udp_pkts) / pk,
        100.0 * static_cast<double>(c.v6_pkts) / pk, 100.0 * static_cast<double>(c.vlan_pkts) / pk,
        static_cast<unsigned long long>(c.data_segs), 100.0 * static_cast<double>(c.reordered) / ds,
        100.0 * static_cast<double>(c.lost) / ds, 100.0 * static_cast<double>(c.retrans) / ds,
        100.0 * static_cast<double>(c.malformed) / pk, secs,
        static_cast<double>(gen.file_bytes()) / 1048576.0 / secs);
    return 0;
}
