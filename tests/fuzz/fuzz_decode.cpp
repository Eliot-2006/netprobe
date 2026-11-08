// Raw bytes as one Ethernet frame (PRD 11.6). Checks self-consistency of the result.
// ponytail: the fuzz CMake target links netprobe_core uninstrumented, so libFuzzer would see no
// coverage inside the decoder. Compile the code under test into this TU so it is instrumented.
#include "decode/decode.cpp"
#include "decode/decode.h"
#include "decode/layers.cpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace netprobe;
    const auto* base = reinterpret_cast<const std::byte*>(data);
    PacketRecord rec;
    rec.orig_len = static_cast<std::uint32_t>(size);
    rec.data = Bytes(base, size);
    const DecodedPacket d = decode_packet(rec);

    const bool in_bounds =
        d.payload.empty() ||
        (d.payload.data() >= base && d.payload.data() + d.payload.size() <= base + size);
    if (!in_bounds || d.payload.size() > d.payload_logical_len) {
        std::abort();
    }
    if (!d.status.ok() && !d.payload.empty()) {
        std::abort(); // failed decodes expose no payload
    }
    if (d.status.ok() != (d.status.reason == Reason::none) || d.vlan_count > 2) {
        std::abort();
    }
    return 0;
}
