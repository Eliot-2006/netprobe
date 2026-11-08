#include "pcap/reader.h"

#include <string>
#include <utility>

namespace netprobe {

namespace {
constexpr std::size_t global_header_len = 24;
constexpr std::size_t record_header_len = 16;
constexpr std::uint32_t magic_micro = 0xA1B2C3D4u;
constexpr std::uint32_t magic_nano = 0xA1B23C4Du;
constexpr std::uint32_t magic_micro_swapped = 0xD4C3B2A1u;
constexpr std::uint32_t magic_nano_swapped = 0x4D3CB2A1u;
constexpr std::uint32_t magic_pcapng = 0x0A0D0D0Au; // same bytes in both orders
constexpr std::uint32_t fcs_present_bit = 1u << 26;

PcapOpenResult fail(OpenError e, std::string msg) {
    PcapOpenResult r;
    r.error = e;
    r.message = std::move(msg);
    return r;
}

template <ByteOrder Order> void parse_rest(const std::byte* p, PcapInfo& info, std::uint32_t& lt) {
    info.ver_major = load16<Order>(p + 4);
    info.ver_minor = load16<Order>(p + 6);
    info.snaplen = load32<Order>(p + 16);
    lt = load32<Order>(p + 20);
}
} // namespace

PcapOpenResult PcapReader::open(Bytes file) {
    if (file.size() < global_header_len) {
        return fail(OpenError::too_short,
                    "file is " + std::to_string(file.size()) +
                        " bytes, shorter than the 24-byte PCAP global header");
    }
    const std::byte* p = file.data();
    const std::uint32_t magic = load_le32(p);
    PcapInfo info;
    std::uint32_t lt = 0;
    switch (magic) {
    case magic_micro:
        info.order = ByteOrder::little;
        info.precision = TsPrecision::micro;
        break;
    case magic_nano:
        info.order = ByteOrder::little;
        info.precision = TsPrecision::nano;
        break;
    case magic_micro_swapped:
        info.order = ByteOrder::big;
        info.precision = TsPrecision::micro;
        break;
    case magic_nano_swapped:
        info.order = ByteOrder::big;
        info.precision = TsPrecision::nano;
        break;
    case magic_pcapng:
        return fail(OpenError::pcapng,
                    "pcapng files are not supported; convert with: editcap -F pcap in.pcapng "
                    "out.pcap");
    default: {
        static constexpr char hex[] = "0123456789abcdef";
        std::string m = "unknown file magic 0x";
        for (int shift = 28; shift >= 0; shift -= 4) {
            m += hex[(load_be32(p) >> shift) & 0xF];
        }
        return fail(OpenError::bad_magic, m + " (not a classic PCAP file)");
    }
    }
    if (info.order == ByteOrder::little) {
        parse_rest<ByteOrder::little>(p, info, lt);
    } else {
        parse_rest<ByteOrder::big>(p, info, lt);
    }
    if (info.ver_major != 2) {
        return fail(OpenError::bad_version,
                    "unsupported PCAP version " + std::to_string(info.ver_major) + "." +
                        std::to_string(info.ver_minor) + " (major version 2 required)");
    }
    info.version_anomaly = info.ver_minor != 4;
    info.link_type = static_cast<std::uint16_t>(lt & 0xFFFFu);
    if ((lt & fcs_present_bit) != 0) {
        info.fcs_bits = static_cast<std::uint8_t>(((lt >> 28) & 0xFu) * 16u);
    }
    if (info.link_type != linktype_ethernet) {
        return fail(OpenError::unsupported_link_type,
                    "unsupported link type " + std::to_string(info.link_type) +
                        " (only LINKTYPE_ETHERNET (1) is supported)");
    }
    PcapOpenResult r;
    r.reader.emplace(PcapReader(file, info));
    return r;
}

bool PcapReader::next(PacketRecord& out) noexcept {
    if (done_) {
        return false;
    }
    return info_.order == ByteOrder::little ? next_impl<ByteOrder::little>(out)
                                            : next_impl<ByteOrder::big>(out);
}

template <ByteOrder Order> bool PcapReader::next_impl(PacketRecord& out) noexcept {
    const std::uint64_t remaining = file_.size() - pos_;
    if (remaining == 0) {
        done_ = true;
        return false;
    }
    if (remaining < record_header_len) {
        status_ = CaptureStatus::truncated;
        tail_bytes_ = remaining;
        done_ = true;
        return false;
    }
    const std::byte* h = file_.data() + pos_;
    const std::uint32_t sec = load32<Order>(h);
    const std::uint32_t frac = load32<Order>(h + 4);
    const std::uint32_t incl = load32<Order>(h + 8);
    const std::uint32_t orig = load32<Order>(h + 12);
    if (incl > max_record_len) {
        status_ = CaptureStatus::corrupt; // PCAP cannot resynchronize
        done_ = true;
        return false;
    }
    if (remaining - record_header_len < incl) {
        status_ = CaptureStatus::truncated;
        tail_bytes_ = remaining;
        done_ = true;
        return false;
    }

    std::int64_t ts = static_cast<std::int64_t>(sec) * 1'000'000'000;
    if (info_.precision == TsPrecision::micro) {
        counters_.ts_fraction_overflow += frac >= 1'000'000u;
        ts += static_cast<std::int64_t>(frac) * 1000;
    } else {
        counters_.ts_fraction_overflow += frac >= 1'000'000'000u;
        ts += static_cast<std::int64_t>(frac);
    }
    counters_.timestamp_regressions += index_ > 0 && ts < prev_ts_ns_;
    prev_ts_ns_ = ts;
    counters_.records_truncated_by_snaplen += incl < orig;
    counters_.incl_gt_orig += incl > orig;

    out.index = index_++;
    out.file_offset = pos_;
    out.ts_ns = ts;
    out.orig_len = orig;
    out.data = Bytes(h + record_header_len, incl);
    pos_ += record_header_len + incl;
    return true;
}

} // namespace netprobe
