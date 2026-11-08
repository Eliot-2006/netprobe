#include "report/report.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <format>

namespace netprobe {

std::string format_ip(const IpAddr& a) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (a.is_v4_mapped()) {
        return std::format("{}.{}.{}.{}", a.b[12], a.b[13], a.b[14], a.b[15]);
    }
    if (inet_ntop(AF_INET6, a.b.data(), buf, sizeof buf) == nullptr) {
        return "?";
    }
    return buf;
}

std::string format_bytes(std::uint64_t n) {
    static constexpr const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    if (n < 1024) {
        return std::format("{} B", n);
    }
    double v = static_cast<double>(n);
    std::size_t u = 0;
    while (v >= 1024 && u + 1 < std::size(units)) {
        v /= 1024;
        ++u;
    }
    return std::format("{:.2f} {}", v, units[u]);
}

std::string format_count(std::uint64_t n) {
    std::string digits = std::to_string(n), out;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i > 0 && (digits.size() - i) % 3 == 0) {
            out.push_back(',');
        }
        out.push_back(digits[i]);
    }
    return out;
}

std::string format_duration(std::int64_t ns) {
    if (ns < 0) {
        ns = 0;
    }
    const auto ms = ns / 1'000'000;
    const auto h = ms / 3'600'000, m = ms / 60'000 % 60, s = ms / 1000 % 60, rem = ms % 1000;
    return std::format("{:02}:{:02}:{:02}.{:03}", h, m, s, rem);
}

std::string format_iso8601(std::int64_t ts_ns) {
    using namespace std::chrono;
    const sys_time<nanoseconds> tp{nanoseconds{ts_ns}};
    const auto secs = floor<seconds>(tp);
    const auto days = floor<std::chrono::days>(secs);
    const year_month_day ymd{days};
    const hh_mm_ss hms{secs - days};
    const auto frac = duration_cast<microseconds>(tp - secs).count();
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                       hms.hours().count(), hms.minutes().count(), hms.seconds().count(), frac);
}

std::string_view link_type_name(std::uint16_t lt) noexcept {
    switch (lt) {
    case 1:
        return "EN10MB";
    case 101:
        return "RAW";
    case 113:
        return "LINUX_SLL";
    default:
        return "UNKNOWN";
    }
}

std::string_view service_label(std::uint8_t proto, std::uint16_t port) noexcept {
    struct Entry {
        std::uint8_t proto;
        std::uint16_t port;
        std::string_view name;
    };
    static constexpr Entry table[] = {
        {6, 20, "ftp-data"}, {6, 21, "ftp"},        {6, 22, "ssh"},     {6, 23, "telnet"},
        {6, 25, "smtp"},     {17, 53, "dns"},       {6, 53, "dns"},     {17, 67, "dhcp"},
        {6, 80, "http"},     {17, 123, "ntp"},      {6, 143, "imap"},   {17, 161, "snmp"},
        {6, 443, "https"},   {17, 443, "quic"},     {6, 445, "smb"},    {6, 993, "imaps"},
        {6, 3306, "mysql"},  {6, 5432, "postgres"}, {6, 6379, "redis"}, {6, 8080, "http-alt"},
    };
    for (const auto& e : table) {
        if (e.proto == proto && e.port == port) {
            return e.name;
        }
    }
    return {};
}

std::string_view to_string(CaptureStatus s) noexcept {
    switch (s) {
    case CaptureStatus::complete:
        return "complete";
    case CaptureStatus::truncated:
        return "truncated";
    case CaptureStatus::corrupt:
        return "corrupt";
    }
    return "?";
}

std::vector<TalkerRow> top_talkers(const ShardResult& s, std::size_t n) {
    std::vector<TalkerRow> rows;
    rows.reserve(s.talkers.size());
    for (const auto& [ip, t] : s.talkers) {
        rows.push_back({ip, t});
    }
    auto total = [](const TalkerRow& r) { return r.t.bytes_sent + r.t.bytes_received; };
    std::sort(rows.begin(), rows.end(), [&](const TalkerRow& a, const TalkerRow& b) {
        return total(a) != total(b) ? total(a) > total(b) : a.addr < b.addr;
    });
    rows.resize(std::min(rows.size(), n));
    return rows;
}

std::vector<ServiceRow> top_services(const ShardResult& s, std::size_t n) {
    std::vector<ServiceRow> rows;
    for (const auto& [k, v] : s.services) {
        rows.push_back({k.first, k.second, v});
    }
    std::stable_sort(rows.begin(), rows.end(), [](const ServiceRow& a, const ServiceRow& b) {
        return a.s.bytes > b.s.bytes; // map order (proto, port) breaks ties
    });
    rows.resize(std::min(rows.size(), n));
    return rows;
}

} // namespace netprobe
