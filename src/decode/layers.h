#pragma once
// Internal per-layer parsers (PRD 6.3). Each takes the bytes of its layer, fills the relevant
// DecodedPacket fields and returns the next layer's bytes. No allocation, no exceptions.

#include "decode/decode.h"

namespace netprobe::layers {

struct Step {
    DecodeStatus status;       // ok, or the single (kind, layer, reason) failure
    Bytes rest;                // next layer's captured bytes (already trimmed to the layer length)
    std::uint32_t logical = 0; // next layer's length per the headers (>= rest.size() on snaplen)
};

// Ethernet II header plus up to 2 VLAN tags. rest = L3 bytes.
Step parse_ethernet(Bytes frame, DecodedPacket& p) noexcept;
// Header, checksum, trim to total_length, fragment flag. rest = L4 bytes (empty for fragments).
Step parse_ipv4(Bytes l3, DecodedPacket& p) noexcept;
// Fixed header plus extension chain (HBH/Routing/DestOpts/Fragment). rest = L4 bytes.
Step parse_ipv6(Bytes l3, DecodedPacket& p) noexcept;
// rest = TCP payload; logical = payload length per the IP length.
Step parse_tcp(Bytes l4, std::uint32_t logical, DecodedPacket& p) noexcept;
// rest = UDP payload; logical = UDP length - 8.
Step parse_udp(Bytes l4, std::uint32_t logical, DecodedPacket& p) noexcept;

} // namespace netprobe::layers
