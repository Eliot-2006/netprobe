#pragma once
// Canonical bidirectional flow key (PRD 4.3 FR-FLOW-1, 6.4).

#include "decode/decode.h"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace netprobe {

struct Endpoint {
    IpAddr addr;
    std::uint16_t port = 0;
    bool operator==(const Endpoint&) const = default;
    constexpr std::strong_ordering operator<=>(const Endpoint& o) const noexcept {
        if (auto c = addr <=> o.addr; c != 0) {
            return c;
        }
        return port <=> o.port;
    }
};

// Layout: 1+1+(16+2)+(16+2) = 38 bytes, padded to 40. Padding is zeroed by value-init and the
// hash reads fields, not raw memory, so padding never affects hashing or equality.
struct FlowKey {
    std::uint8_t ip_version = 0;
    std::uint8_t proto = 0;
    Endpoint lo, hi; // lo <= hi
    bool operator==(const FlowKey&) const = default;
};

// lo_to_hi: packet source is `lo`.
enum class Direction : std::uint8_t { lo_to_hi = 0, hi_to_lo = 1 };

struct KeyedPacket {
    FlowKey key;
    Direction dir;
};

// Precondition: pkt.is_tcp() || pkt.is_udp().
KeyedPacket make_flow_key(const DecodedPacket& pkt) noexcept;

std::uint64_t hash_flow_key(const FlowKey& k) noexcept;

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        return static_cast<std::size_t>(hash_flow_key(k));
    }
};

// Shard index from the high 32 bits (Lemire multiply-shift), independent of table bucket bits.
constexpr std::uint32_t shard_of(std::uint64_t hash, std::uint32_t shards) noexcept {
    return static_cast<std::uint32_t>(((hash >> 32) * shards) >> 32);
}

} // namespace netprobe
