#include "decode/decode.h"

namespace netprobe {

std::string_view to_string(Layer l) noexcept {
    switch (l) {
    case Layer::pcap:
        return "pcap";
    case Layer::ethernet:
        return "ethernet";
    case Layer::vlan:
        return "vlan";
    case Layer::ipv4:
        return "ipv4";
    case Layer::ipv6:
        return "ipv6";
    case Layer::ipv6_ext:
        return "ipv6_ext";
    case Layer::tcp:
        return "tcp";
    case Layer::udp:
        return "udp";
    case Layer::count_:
        break;
    }
    return "?";
}

std::string_view to_string(DecodeKind k) noexcept {
    switch (k) {
    case DecodeKind::ok:
        return "ok";
    case DecodeKind::truncated:
        return "truncated";
    case DecodeKind::malformed:
        return "malformed";
    case DecodeKind::unsupported:
        return "unsupported";
    case DecodeKind::count_:
        break;
    }
    return "?";
}

std::string_view to_string(Reason r) noexcept {
    switch (r) {
    case Reason::none:
        return "none";
    case Reason::short_header:
        return "short_header";
    case Reason::bad_version:
        return "bad_version";
    case Reason::bad_ihl:
        return "bad_ihl";
    case Reason::bad_total_length:
        return "bad_total_length";
    case Reason::tcp_data_offset:
        return "tcp_data_offset";
    case Reason::tcp_options:
        return "tcp_options";
    case Reason::udp_length:
        return "udp_length";
    case Reason::vlan_depth:
        return "vlan_depth";
    case Reason::llc:
        return "llc";
    case Reason::ipv6_ext:
        return "ipv6_ext";
    case Reason::ipv6_ext_chain:
        return "ipv6_ext_chain";
    case Reason::ipv6_jumbo:
        return "ipv6_jumbo";
    case Reason::count_:
        break;
    }
    return "?";
}

bool IpAddr::is_v4_mapped() const noexcept {
    for (int i = 0; i < 10; ++i) {
        if (b[static_cast<std::size_t>(i)] != 0) {
            return false;
        }
    }
    return b[10] == 0xFF && b[11] == 0xFF;
}

} // namespace netprobe
