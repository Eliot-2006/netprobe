// Raw bytes as a whole PCAP file (PRD 11.6): open, iterate, decode every record.
// ponytail: the fuzz CMake target links netprobe_core uninstrumented, so libFuzzer would see no
// coverage inside the decoder. Compile the code under test into this TU so it is instrumented.
#include "decode/decode.cpp"
#include "decode/decode.h"
#include "decode/layers.cpp"
#include "pcap/reader.cpp"
#include "pcap/reader.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace netprobe;
    const Bytes file(reinterpret_cast<const std::byte*>(data), size);
    PcapOpenResult r = PcapReader::open(file);
    if ((r.error == OpenError::none) != r.reader.has_value()) {
        std::abort();
    }
    if (!r.reader) {
        return 0;
    }
    PacketRecord rec;
    std::uint64_t expected_index = 0;
    while (r.reader->next(rec)) {
        const bool inside =
            rec.data.empty() || (rec.data.data() >= file.data() &&
                                 rec.data.data() + rec.data.size() <= file.data() + size);
        if (!inside || rec.index != expected_index++ ||
            rec.data.size() > PcapReader::max_record_len) {
            std::abort();
        }
        const DecodedPacket d = decode_packet(rec);
        if (d.payload.size() > d.payload_logical_len) {
            std::abort();
        }
    }
    if (r.reader->status() == CaptureStatus::truncated && r.reader->truncated_tail_bytes() == 0) {
        std::abort();
    }
    return 0;
}
