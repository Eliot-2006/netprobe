#include "report/json_writer.h"

#include <cassert>
#include <charconv>
#include <cmath>

namespace netprobe {
namespace {

// Length of the valid UTF-8 sequence starting at s[i], or 0 if invalid (RFC 3629).
std::size_t utf8_sequence_length(std::string_view s, std::size_t i) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    std::size_t len = 0;
    std::uint32_t cp = 0;
    if (b0 < 0x80) {
        return 1;
    } else if ((b0 & 0xE0) == 0xC0) {
        len = 2;
        cp = b0 & 0x1Fu;
    } else if ((b0 & 0xF0) == 0xE0) {
        len = 3;
        cp = b0 & 0x0Fu;
    } else if ((b0 & 0xF8) == 0xF0) {
        len = 4;
        cp = b0 & 0x07u;
    } else {
        return 0;
    }
    if (i + len > s.size()) {
        return 0;
    }
    for (std::size_t k = 1; k < len; ++k) {
        const auto b = static_cast<unsigned char>(s[i + k]);
        if ((b & 0xC0) != 0x80) {
            return 0;
        }
        cp = (cp << 6) | (b & 0x3Fu);
    }
    const bool overlong =
        (len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000);
    const bool surrogate = cp >= 0xD800 && cp <= 0xDFFF;
    if (overlong || surrogate || cp > 0x10FFFF) {
        return 0;
    }
    return len;
}

} // namespace

void append_json_string(std::string& out, std::string_view s) {
    static constexpr char hex[] = "0123456789abcdef";
    out.push_back('"');
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(static_cast<char>(c));
            ++i;
        } else if (c < 0x20) {
            switch (c) {
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += "\\u00";
                out.push_back(hex[c >> 4]);
                out.push_back(hex[c & 0xF]);
            }
            ++i;
        } else if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
        } else if (const auto n = utf8_sequence_length(s, i); n != 0) {
            out.append(s.substr(i, n));
            i += n;
        } else {
            out += "\\ufffd";
            ++i;
        }
    }
    out.push_back('"');
}

void JsonWriter::newline() {
    out_.push_back('\n');
    out_.append(stack_.size() * 2, ' ');
}

void JsonWriter::before_value() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!stack_.empty()) {
        assert(!stack_.back().is_object && "object members need key() first");
        if (!stack_.back().empty) {
            out_.push_back(',');
        }
        stack_.back().empty = false;
        newline();
    }
}

void JsonWriter::key(std::string_view k) {
    assert(!stack_.empty() && stack_.back().is_object && !after_key_);
    if (!stack_.back().empty) {
        out_.push_back(',');
    }
    stack_.back().empty = false;
    newline();
    append_json_string(out_, k);
    out_ += ": ";
    after_key_ = true;
}

void JsonWriter::begin_object() {
    before_value();
    out_.push_back('{');
    stack_.push_back({true});
}

void JsonWriter::begin_array() {
    before_value();
    out_.push_back('[');
    stack_.push_back({false});
}

void JsonWriter::end_object() {
    assert(!stack_.empty() && stack_.back().is_object && !after_key_);
    const bool empty = stack_.back().empty;
    stack_.pop_back();
    if (!empty) {
        newline();
    }
    out_.push_back('}');
    if (stack_.empty()) {
        out_.push_back('\n');
    }
}

void JsonWriter::end_array() {
    assert(!stack_.empty() && !stack_.back().is_object);
    const bool empty = stack_.back().empty;
    stack_.pop_back();
    if (!empty) {
        newline();
    }
    out_.push_back(']');
}

void JsonWriter::value(std::string_view s) {
    before_value();
    append_json_string(out_, s);
}

void JsonWriter::value(bool b) {
    before_value();
    out_ += b ? "true" : "false";
}

void JsonWriter::value(double d) {
    before_value();
    if (!std::isfinite(d)) {
        out_ += "null";
        return;
    }
    char buf[64];
    auto [end, ec] = std::to_chars(buf, buf + sizeof buf, d, std::chars_format::fixed, 3);
    out_.append(buf, ec == std::errc{} ? end : buf);
}

void JsonWriter::null() {
    before_value();
    out_ += "null";
}

void JsonWriter::write_int(std::int64_t v) {
    before_value();
    char buf[24];
    auto [end, ec] = std::to_chars(buf, buf + sizeof buf, v);
    out_.append(buf, end);
}

void JsonWriter::write_uint(std::uint64_t v) {
    before_value();
    char buf[24];
    auto [end, ec] = std::to_chars(buf, buf + sizeof buf, v);
    out_.append(buf, end);
}

} // namespace netprobe
