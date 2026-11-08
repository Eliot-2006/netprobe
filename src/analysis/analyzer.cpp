#include "analysis/analyzer.h"

#include "analysis/reader_stats.h"
#include "report/stream_export.h"

#include <algorithm>
#include <array>
#include <cassert>

namespace netprobe {
namespace {

constexpr std::size_t idx(Direction d) noexcept {
    return static_cast<std::size_t>(d);
}
constexpr Direction other(Direction d) noexcept {
    return d == Direction::lo_to_hi ? Direction::hi_to_lo : Direction::lo_to_hi;
}

} // namespace

struct DirState {
    std::uint64_t packets = 0, bytes = 0, payload_bytes = 0, data_after_rst = 0;
    std::uint32_t isn = 0;
    std::uint16_t mss = 0;
    std::uint8_t wscale = 0;
    bool syn = false, fin = false, rst = false, has_mss = false, has_wscale = false;
};

struct Analyzer::Flow {
    Flow(MemoryBudget& b, ReassemblyLimits l) : reasm{{{b, l}, {b, l}}} {}

    const FlowKey* key = nullptr; // points at the map node's key (node-stable)
    Flow* prev = nullptr;
    Flow* next = nullptr;
    std::uint64_t id = 0;
    std::int64_t first_ts = 0, last_ts = 0;
    std::array<DirState, 2> dir{};
    std::array<StreamReassembler, 2> reasm;
    Direction client_dir = Direction::lo_to_hi; // direction in which the client sends
    bool orientation_handshake = false;
    bool synack_seen = false;
    bool client_ack_after_synack = false;
    bool rst = false;
    bool closing = false;
    bool in_closed = false;
};

Analyzer::Analyzer(AnalyzerConfig cfg)
    : cfg_(std::move(cfg)), budget_(cfg_.reassembly_budget), result_(cfg_.top_k) {
    flows_.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(cfg_.max_flows, 1 << 16)));
}

Analyzer::~Analyzer() = default;

void Analyzer::unlink(Flow& f) {
    List& l = f.in_closed ? closed_ : open_;
    (f.prev ? f.prev->next : l.head) = f.next;
    (f.next ? f.next->prev : l.tail) = f.prev;
    f.prev = f.next = nullptr;
}

void Analyzer::touch(Flow& f) {
    unlink(f);
    f.in_closed = f.closing;
    List& l = f.in_closed ? closed_ : open_;
    f.prev = l.tail;
    (l.tail ? l.tail->next : l.head) = &f;
    l.tail = &f;
}

CloseReason Analyzer::natural_close(const Flow& f) const noexcept {
    if (f.rst) {
        return CloseReason::rst;
    }
    if (f.dir[0].fin && f.dir[1].fin) {
        return CloseReason::fin;
    }
    return CloseReason::end_of_capture;
}

Analyzer::Map::iterator Analyzer::create(const FlowKey& key, Direction dir, const PacketRecord& rec,
                                         const DecodedPacket& pkt) {
    if (flows_.size() >= cfg_.max_flows) {
        evict_one();
    }
    auto [it, inserted] =
        flows_.try_emplace(key, budget_, ReassemblyLimits{cfg_.max_stream_buffer});
    assert(inserted);
    Flow& f = it->second;
    f.key = &it->first;
    f.id = rec.index;
    f.first_ts = f.last_ts = rec.ts_ns;
    f.client_dir = dir;
    if (pkt.l4_proto == ip_proto::tcp && (pkt.tcp_flags & tcp_flag::syn) &&
        !tcp_flags_invalid(pkt.tcp_flags)) {
        f.orientation_handshake = true;
        if (pkt.tcp_flags & tcp_flag::ack) {
            f.client_dir = other(dir); // first packet is the SYN-ACK: receiver is the client
        }
    }
    f.prev = open_.tail;
    (open_.tail ? open_.tail->next : open_.head) = &f;
    open_.tail = &f;
    result_.peak_flows = std::max<std::uint64_t>(result_.peak_flows, flows_.size());
    return it;
}

void Analyzer::process(const PacketRecord& rec, const DecodedPacket& pkt) {
    if (!pkt.is_tcp() && !pkt.is_udp()) {
        return;
    }
    now_ = std::max(now_, rec.ts_ns);
    if (last_sweep_ == INT64_MIN) {
        last_sweep_ = now_; // start the sweep clock at the first flow packet (no overflow)
    }
    if (++since_sweep_ >= 1024 || now_ - last_sweep_ >= 1'000'000'000) {
        sweep();
    }

    const auto [key, dir] = make_flow_key(pkt);
    const bool tcp = pkt.l4_proto == ip_proto::tcp;
    auto it = flows_.find(key);
    if (it != flows_.end()) {
        Flow& f = it->second;
        const auto timeout = f.closing ? cfg_.closed_linger_ns : cfg_.idle_timeout_ns;
        const auto fl = pkt.tcp_flags;
        const bool new_syn = tcp && (fl & tcp_flag::syn) && !(fl & tcp_flag::ack) &&
                             !tcp_flags_invalid(fl) && f.closing &&
                             (f.rst || !f.dir[idx(dir)].syn || f.dir[idx(dir)].isn != pkt.seq);
        // After a RST the connection is gone, so even a same-ISN SYN is a new attempt
        // (connection-refused retries in tcpreplay's bigFlows.pcap). After a FIN close a
        // same-ISN SYN may still be a retransmission, so the ISN must differ.
        if (rec.ts_ns - f.last_ts > timeout) {
            finalize(it, f.closing ? natural_close(f) : CloseReason::idle_timeout);
            it = flows_.end();
        } else if (new_syn) {
            finalize(it, CloseReason::reused);
            it = flows_.end();
        }
    }
    if (it == flows_.end()) {
        it = create(key, dir, rec, pkt);
    }
    Flow& f = it->second;
    update(f, dir, rec, pkt);
    touch(f);
}

void Analyzer::update(Flow& f, Direction d, const PacketRecord& rec, const DecodedPacket& pkt) {
    DirState& ds = f.dir[idx(d)];
    ++ds.packets;
    ds.bytes += rec.orig_len;
    ds.payload_bytes += pkt.payload_logical_len;
    f.last_ts = std::max(f.last_ts, rec.ts_ns);
    if (pkt.l4_proto != ip_proto::tcp || tcp_flags_invalid(pkt.tcp_flags)) {
        return;
    }

    const std::uint8_t fl = pkt.tcp_flags;
    const bool syn = fl & tcp_flag::syn;
    StreamReassembler& mine = f.reasm[idx(d)];
    StreamReassembler& peer = f.reasm[idx(other(d))];

    if (syn) {
        if (!ds.syn) {
            ds.syn = true;
            ds.isn = pkt.seq;
            if (!mine.initialized()) {
                mine.init(pkt.seq + 1);
            }
        }
        if (pkt.has_mss) {
            ds.has_mss = true;
            ds.mss = pkt.mss;
        }
        if (pkt.has_wscale) {
            ds.has_wscale = true;
            ds.wscale = pkt.wscale;
        }
        if (!(fl & tcp_flag::ack) && !f.orientation_handshake) {
            // FR-FLOW-3: the SYN sender is the client even if stray packets came first.
            f.client_dir = d;
            f.orientation_handshake = true;
        }
        if ((fl & tcp_flag::ack) && d != f.client_dir) {
            f.synack_seen = true;
        }
    }
    if (fl & tcp_flag::ack) {
        if (!syn && d == f.client_dir && f.synack_seen) {
            f.client_ack_after_synack = true;
        }
        if (peer.initialized()) {
            peer.on_peer_ack(pkt.ack);
        }
    }
    if (!mine.initialized()) {
        mine.init(pkt.seq); // mid-stream pickup: first observed seq is offset 0
    }

    if (f.rst) {
        if (pkt.payload_logical_len > 0) {
            ++ds.data_after_rst;
        }
        return;
    }

    const std::uint32_t start = pkt.seq + (syn ? 1u : 0u);
    if (pkt.payload_logical_len > 0 && (fl & tcp_flag::rst)) {
        // RST payload is diagnostic text, never delivered to the application (RFC 9293
        // 3.5.3); count it like other post-reset data. Real-world case: tcpdump's
        // tests/tcp_rst_data.pcap.
        ++ds.data_after_rst;
    } else if (pkt.payload_logical_len > 0) {
        if (cfg_.export_dir) {
            FileExportSink sink(stream_work_file(*cfg_.export_dir, f.id, d == Direction::lo_to_hi));
            mine.on_segment(start, pkt.payload_logical_len, pkt.payload, sink);
            result_.export_failed = result_.export_failed || sink.failed();
        } else {
            NullSink sink;
            mine.on_segment(start, pkt.payload_logical_len, pkt.payload, sink);
        }
    }
    if (fl & tcp_flag::fin) {
        mine.on_fin(start + pkt.payload_logical_len);
        ds.fin = true;
    }
    if (fl & tcp_flag::rst) {
        ds.rst = true;
        f.rst = true;
    }
    f.closing = f.rst || (f.dir[0].fin && f.dir[1].fin);
}

void Analyzer::finalize(Map::iterator it, CloseReason reason) {
    Flow& f = it->second;
    const Direction c = f.client_dir;
    const Direction s = other(c);
    const bool tcp = f.key->proto == ip_proto::tcp;

    if (tcp) {
        for (Direction d : {c, s}) {
            if (cfg_.export_dir) {
                FileExportSink sink(
                    stream_work_file(*cfg_.export_dir, f.id, d == Direction::lo_to_hi));
                f.reasm[idx(d)].flush(sink);
                result_.export_failed = result_.export_failed || sink.failed();
            } else {
                NullSink sink;
                f.reasm[idx(d)].flush(sink);
            }
        }
        if (cfg_.export_dir) { // orientation is final now: give the files their c2s/s2c names
            for (Direction d : {c, s}) {
                const auto work =
                    stream_work_file(*cfg_.export_dir, f.id, d == Direction::lo_to_hi);
                std::error_code ec;
                if (std::filesystem::exists(work, ec)) {
                    std::filesystem::rename(work, stream_file(*cfg_.export_dir, f.id, d == c), ec);
                    result_.export_failed = result_.export_failed || ec;
                }
            }
        }
    }

    FlowSummary sum;
    sum.id = f.id;
    sum.proto = f.key->proto;
    sum.ip_version = f.key->ip_version;
    sum.client = c == Direction::lo_to_hi ? f.key->lo : f.key->hi;
    sum.server = c == Direction::lo_to_hi ? f.key->hi : f.key->lo;
    sum.orientation_handshake = f.orientation_handshake;
    sum.close = reason;
    sum.first_ts_ns = f.first_ts;
    sum.last_ts_ns = f.last_ts;
    auto fill = [&](DirSummary& out, Direction d) {
        const DirState& ds = f.dir[idx(d)];
        out.packets = ds.packets;
        out.bytes = ds.bytes;
        out.payload_bytes = ds.payload_bytes;
        out.data_after_rst = ds.data_after_rst;
        out.syn = ds.syn;
        out.fin = ds.fin;
        out.rst = ds.rst;
        out.has_mss = ds.has_mss;
        out.mss = ds.mss;
        out.has_wscale = ds.has_wscale;
        out.wscale = ds.wscale;
        if (tcp) {
            out.stream = f.reasm[idx(d)].stats();
        }
    };
    fill(sum.c2s, c);
    fill(sum.s2c, s);

    auto& fc = result_.flows;
    const auto reason_idx = static_cast<std::size_t>(reason);
    if (tcp) {
        const bool client_syn = f.dir[idx(c)].syn;
        sum.handshake = client_syn && f.synack_seen && f.client_ack_after_synack ? Handshake::full
                        : (client_syn || f.synack_seen) ? Handshake::partial
                                                        : Handshake::none;
        const std::uint64_t missing = sum.missing_bytes();
        const std::uint64_t snap =
            sum.c2s.stream.snaplen_missing_bytes + sum.s2c.stream.snaplen_missing_bytes;
        sum.integrity = missing > 0
                            ? (snap >= missing ? Integrity::snaplen_truncated : Integrity::gaps)
                        : f.closing ? Integrity::complete
                                    : Integrity::open;
        ++fc.tcp_total;
        ++(sum.handshake == Handshake::full      ? fc.handshake_full
           : sum.handshake == Handshake::partial ? fc.handshake_partial
                                                 : fc.handshake_none);
        fc.tcp_complete += sum.integrity == Integrity::complete ? 1 : 0;
        fc.tcp_with_gaps += missing > 0 ? 1 : 0;
        ++fc.tcp_close[reason_idx];
        result_.reassembly.add(sum.c2s.stream);
        result_.reassembly.add(sum.s2c.stream);
        result_.reassembly.data_after_rst += sum.c2s.data_after_rst + sum.s2c.data_after_rst;
    } else {
        sum.integrity = Integrity::complete;
        ++fc.udp_total;
        ++fc.udp_close[reason_idx];
    }
    if (reason == CloseReason::evicted) {
        ++result_.evicted_flows;
        result_.limits_hit = true;
    }

    // One entry per distinct address: bounded at the shard's flow limit so spoofed sources cannot
    // grow it without limit (independent audit, PRD G3). Beyond the cap new addresses are not
    // tracked and the report says the talker list is incomplete.
    auto add_talker = [this](const IpAddr& a, std::uint64_t sent, std::uint64_t received) {
        auto found = result_.talkers.find(a);
        if (found == result_.talkers.end()) {
            if (result_.talkers.size() >= cfg_.max_flows) {
                result_.talkers_capped = true;
                return;
            }
            found = result_.talkers.emplace(a, Talker{}).first;
        }
        found->second.bytes_sent += sent;
        found->second.bytes_received += received;
        ++found->second.flows;
    };
    add_talker(sum.client.addr, sum.c2s.bytes, sum.s2c.bytes);
    add_talker(sum.server.addr, sum.s2c.bytes, sum.c2s.bytes);
    const std::uint16_t service_port = tcp && sum.orientation_handshake
                                           ? sum.server.port
                                           : std::min(sum.client.port, sum.server.port);
    auto& svc = result_.services[{sum.proto, service_port}];
    ++svc.flows;
    svc.bytes += sum.bytes();

    if (cfg_.export_dir && tcp) {
        for (bool c2s : {true, false}) {
            const auto& st = c2s ? sum.c2s.stream : sum.s2c.stream;
            if (st.delivered_bytes > 0 || st.gap_count > 0) {
                result_.exported.push_back({sum.id, c2s, c2s ? sum.client : sum.server,
                                            c2s ? sum.server : sum.client, st.delivered_bytes,
                                            st.gap_count});
            }
        }
    }

    if (tcp && sum.missing_bytes() > 0) {
        result_.top_incomplete.offer(sum);
    }
    result_.top_bytes.offer(std::move(sum));

    unlink(f);
    flows_.erase(it);
}

void Analyzer::evict_one() {
    result_.limits_hit = true;
    if (closed_.head != nullptr) {
        Flow& f = *closed_.head;
        finalize(flows_.find(*f.key), natural_close(f));
    } else if (open_.head != nullptr) {
        finalize(flows_.find(*open_.head->key), CloseReason::evicted);
    }
}

void Analyzer::sweep() {
    since_sweep_ = 0;
    last_sweep_ = now_;
    while (open_.head != nullptr && now_ - open_.head->last_ts > cfg_.idle_timeout_ns) {
        finalize(flows_.find(*open_.head->key), CloseReason::idle_timeout);
    }
    while (closed_.head != nullptr && now_ - closed_.head->last_ts > cfg_.closed_linger_ns) {
        Flow& f = *closed_.head;
        finalize(flows_.find(*f.key), natural_close(f));
    }
}

ShardResult Analyzer::finish() {
    while (!flows_.empty()) {
        auto it = flows_.begin();
        finalize(it, natural_close(it->second));
    }
    result_.reassembly.peak_buffered_bytes = budget_.peak();
    return std::move(result_);
}

} // namespace netprobe
