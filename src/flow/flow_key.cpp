#include "flow/flow_key.h"

#include <cstring>

namespace netprobe {
namespace {

constexpr std::uint64_t mix(std::uint64_t x) noexcept { // splitmix64 finalizer
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

std::uint64_t word(const IpAddr& a, std::size_t half) noexcept {
    std::uint64_t w = 0;
    std::memcpy(&w, a.b.data() + half * 8, 8);
    return w;
}

} // namespace

KeyedPacket make_flow_key(const DecodedPacket& pkt) noexcept {
    const Endpoint src{pkt.src, pkt.src_port};
    const Endpoint dst{pkt.dst, pkt.dst_port};
    KeyedPacket kp;
    kp.key.ip_version = pkt.ip_version;
    kp.key.proto = pkt.l4_proto;
    if (src <= dst) {
        kp.key.lo = src;
        kp.key.hi = dst;
        kp.dir = Direction::lo_to_hi;
    } else {
        kp.key.lo = dst;
        kp.key.hi = src;
        kp.dir = Direction::hi_to_lo;
    }
    return kp;
}

std::uint64_t hash_flow_key(const FlowKey& k) noexcept {
    std::uint64_t h = mix(static_cast<std::uint64_t>(k.ip_version) << 8 | k.proto);
    h = mix(h ^ word(k.lo.addr, 0));
    h = mix(h ^ word(k.lo.addr, 1));
    h = mix(h ^ word(k.hi.addr, 0));
    h = mix(h ^ word(k.hi.addr, 1));
    h = mix(h ^ (static_cast<std::uint64_t>(k.lo.port) << 16 | k.hi.port));
    return h;
}

} // namespace netprobe
