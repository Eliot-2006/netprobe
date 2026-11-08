#include "decode/decode.h"

#include "decode/layers.h"

namespace netprobe {

DecodedPacket decode_packet(const PacketRecord& rec) noexcept {
    DecodedPacket p;
    layers::Step s = layers::parse_ethernet(rec.data, p);
    if (s.status.ok()) {
        switch (p.ethertype) {
        case 0x0800:
            s = layers::parse_ipv4(s.rest, p);
            break;
        case 0x86DD:
            s = layers::parse_ipv6(s.rest, p);
            break;
        default: // ARP and everything else: counted by the caller, not decoded further
            p.status = s.status;
            return p;
        }
    }
    if (s.status.ok() && !p.is_fragment) {
        if (p.l4_proto == ip_proto::tcp) {
            s = layers::parse_tcp(s.rest, s.logical, p);
        } else if (p.l4_proto == ip_proto::udp) {
            s = layers::parse_udp(s.rest, s.logical, p);
        } else {
            s.rest = {}; // ICMP, other protocols: no payload exposed
            s.logical = 0;
        }
    }
    p.status = s.status;
    if (s.status.ok()) {
        p.payload = s.rest;
        p.payload_logical_len = s.logical;
    }
    return p;
}

} // namespace netprobe
