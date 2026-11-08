#pragma once
// Classic PCAP reader over a byte span (PRD 3.1, 4.1, 6.2). Zero-copy, never allocates in next().

#include "pcap/record.h"
#include "util/bytes.h"

#include <cstdint>
#include <optional>
#include <string>

namespace netprobe {

enum class TsPrecision : std::uint8_t { micro, nano };

struct PcapInfo {
    ByteOrder order = ByteOrder::little;
    TsPrecision precision = TsPrecision::micro;
    std::uint16_t ver_major = 0, ver_minor = 0;
    std::uint32_t snaplen = 0;
    std::uint16_t link_type = 0;          // lower 16 bits of the header field
    std::optional<std::uint8_t> fcs_bits; // set when the header's F bit (26) is set
    bool version_anomaly = false;         // version is 2.x but not 2.4
};

// How iteration ended (or `complete` while it has not hit a problem).
enum class CaptureStatus : std::uint8_t { complete, truncated, corrupt };

// Anomaly counters, valid for records returned so far.
struct PcapCounters {
    std::uint64_t records_truncated_by_snaplen = 0; // incl_len < orig_len
    std::uint64_t incl_gt_orig = 0;                 // incl_len > orig_len (used as is)
    std::uint64_t ts_fraction_overflow = 0;         // usec >= 1e6 or nsec >= 1e9
    std::uint64_t timestamp_regressions = 0;        // ts earlier than the previous record
};

enum class OpenError : std::uint8_t {
    none,
    too_short,             // < 24 bytes
    bad_magic,             // unknown magic
    pcapng,                // pcapng detected; message carries the editcap hint
    bad_version,           // major != 2
    unsupported_link_type, // anything but LINKTYPE_ETHERNET
};

struct PcapOpenResult;

class PcapReader {
public:
    static constexpr std::uint32_t max_record_len = 262144;
    static constexpr std::uint16_t linktype_ethernet = 1;

    // Parses the 24-byte global header. On failure `error != none` and `message` is specific
    // (exit-2 class). `file` must outlive the reader and every record it returns.
    static PcapOpenResult open(Bytes file);

    const PcapInfo& info() const noexcept { return info_; }
    const PcapCounters& counters() const noexcept { return counters_; }

    // Next record, or false at clean end, truncation or corruption (see status()).
    bool next(PacketRecord& out) noexcept;

    CaptureStatus status() const noexcept { return status_; }
    // Bytes from the start of the incomplete record header/body to end of file (status truncated).
    std::uint64_t truncated_tail_bytes() const noexcept { return tail_bytes_; }

private:
    PcapReader(Bytes file, const PcapInfo& info) noexcept : file_(file), info_(info) {}
    template <ByteOrder Order> bool next_impl(PacketRecord& out) noexcept;

    Bytes file_;
    PcapInfo info_;
    PcapCounters counters_;
    std::uint64_t pos_ = 24;
    std::uint64_t index_ = 0;
    std::int64_t prev_ts_ns_ = 0;
    std::uint64_t tail_bytes_ = 0;
    CaptureStatus status_ = CaptureStatus::complete;
    bool done_ = false;
};

struct PcapOpenResult {
    OpenError error = OpenError::none;
    std::string message;
    std::optional<PcapReader> reader; // engaged iff error == none
};

} // namespace netprobe
