#include "tcp/reassembler.h"
#include "util/bytes.h"

#include <algorithm>
#include <array>
#include <cstdlib>

using namespace netprobe;
namespace {
void require(bool condition) {
    if (!condition)
        std::abort();
}
} // namespace
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Copy op bytes individually; never cast an input buffer to a packet or op struct.
    MemoryBudget budget{256U * 1024};
    std::array streams{StreamReassembler{budget, {64U * 1024}},
                       StreamReassembler{budget, {64U * 1024}}};
    streams[0].init(0xFFFFFF00U);
    streams[1].init(0);
    NullSink sink;
    std::array<std::byte, 65535> payload{};
    for (std::size_t pos = 0; size - pos >= 8; pos += 8) {
        const std::array op{
            static_cast<std::byte>(data[pos]),     static_cast<std::byte>(data[pos + 1]),
            static_cast<std::byte>(data[pos + 2]), static_cast<std::byte>(data[pos + 3]),
            static_cast<std::byte>(data[pos + 4]), static_cast<std::byte>(data[pos + 5])};
        const auto seq = load_le32(op.data());
        const auto len = load_le16(op.data() + 4);
        const auto flags = data[pos + 6];
        auto& stream = streams[flags & 1U];
        if ((flags & 2U) != 0)
            streams[(flags & 1U) ^ 1U].on_peer_ack(seq);
        require(streams[0].check_invariants());
        require(streams[1].check_invariants());
        auto captured = static_cast<std::size_t>(len);
        if ((flags & 4U) != 0)
            captured = captured * data[pos + 7] / 255;
        std::fill_n(payload.begin(), captured, static_cast<std::byte>(data[pos + 7]));
        stream.on_segment(seq, len, Bytes(payload).first(captured), sink);
        require(stream.check_invariants());
        if ((flags & 8U) != 0)
            stream.on_fin(seq + len);
        require(stream.check_invariants());
        if ((flags & 16U) != 0)
            stream.flush(sink);
        require(streams[0].check_invariants());
        require(streams[1].check_invariants());
        require(budget.current() == streams[0].buffered_bytes() + streams[1].buffered_bytes());
        require(budget.current() <= budget.limit() + len + kSegmentOverhead);
    }
    for (auto& stream : streams) {
        stream.flush(sink);
        require(stream.check_invariants());
    }
    require(budget.current() == 0);
    return 0;
}
