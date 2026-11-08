#pragma once
// Streaming JSON writer with deterministic, pretty-printed output (PRD 6.11).
// Strings are escaped; invalid UTF-8 is replaced with U+FFFD so output is always valid JSON.

#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace netprobe {

class JsonWriter {
public:
    void begin_object();
    void end_object();
    void begin_array();
    void end_array();
    void key(std::string_view k);

    void value(std::string_view s);
    void value(const char* s) { value(std::string_view(s)); }
    void value(bool b);
    void value(double d); // fixed, 3 decimals; only used for non-deterministic run fields
    template <std::integral T>
        requires(!std::same_as<T, bool>)
    void value(T v) {
        if constexpr (std::is_signed_v<T>) {
            write_int(static_cast<std::int64_t>(v));
        } else {
            write_uint(static_cast<std::uint64_t>(v));
        }
    }
    void null();

    template <class T> void field(std::string_view k, const T& v) {
        key(k);
        value(v);
    }

    const std::string& str() const noexcept { return out_; }
    std::string take() noexcept { return std::move(out_); }

private:
    void before_value();
    void newline();
    void write_int(std::int64_t v);
    void write_uint(std::uint64_t v);

    struct Frame {
        bool is_object;
        bool empty = true;
    };
    std::string out_;
    std::vector<Frame> stack_;
    bool after_key_ = false;
};

// Appends `s` as a quoted JSON string literal.
void append_json_string(std::string& out, std::string_view s);

} // namespace netprobe
