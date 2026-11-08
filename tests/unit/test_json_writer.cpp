#include "report/json_writer.h"

#include <gtest/gtest.h>

#include <cmath>
#include <limits>

using namespace netprobe;

static std::string quoted(std::string_view s) {
    std::string out;
    append_json_string(out, s);
    return out;
}

TEST(JsonWriter, NestedStructureIsPrettyAndOrdered) {
    JsonWriter w;
    w.begin_object();
    w.field("b", 1u);
    w.field("a", -2);
    w.key("list");
    w.begin_array();
    w.value(true);
    w.begin_object();
    w.end_object();
    w.begin_array();
    w.end_array();
    w.null();
    w.end_array();
    w.field("s", "x");
    w.end_object();
    EXPECT_EQ(w.str(), "{\n"
                       "  \"b\": 1,\n"
                       "  \"a\": -2,\n"
                       "  \"list\": [\n"
                       "    true,\n"
                       "    {},\n"
                       "    [],\n"
                       "    null\n"
                       "  ],\n"
                       "  \"s\": \"x\"\n"
                       "}\n");
}

TEST(JsonWriter, IntegerExtremes) {
    JsonWriter w;
    w.begin_array();
    w.value(std::uint64_t{18446744073709551615u});
    w.value(std::int64_t{INT64_MIN});
    w.value(std::uint8_t{255});
    w.end_array();
    EXPECT_NE(w.str().find("18446744073709551615"), std::string::npos);
    EXPECT_NE(w.str().find("-9223372036854775808"), std::string::npos);
    EXPECT_NE(w.str().find("255"), std::string::npos);
}

TEST(JsonWriter, DoublesAreFixedAndNonFiniteIsNull) {
    JsonWriter w;
    w.begin_array();
    w.value(1.5);
    w.value(std::numeric_limits<double>::quiet_NaN());
    w.end_array();
    EXPECT_NE(w.str().find("1.500"), std::string::npos);
    EXPECT_NE(w.str().find("null"), std::string::npos);
}

TEST(JsonEscape, QuotesBackslashAndControls) {
    EXPECT_EQ(quoted("a\"b\\c"), R"("a\"b\\c")");
    EXPECT_EQ(quoted("\n\r\t"), R"("\n\r\t")");
    EXPECT_EQ(quoted(std::string_view("\x00\x01\x1f", 3)), "\"\\u0000\\u0001\\u001f\"");
    EXPECT_EQ(quoted("<script>"), R"("<script>")"); // HTML escaping is the HTML writer's job
}

TEST(JsonEscape, ValidUtf8PassesThrough) {
    EXPECT_EQ(quoted("caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80"),
              "\"caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80\"");
}

TEST(JsonEscape, InvalidUtf8BecomesReplacement) {
    EXPECT_EQ(quoted("\xFF"), "\"\\ufffd\"");
    EXPECT_EQ(quoted("\xC3"), "\"\\ufffd\"");                                  // truncated sequence
    EXPECT_EQ(quoted("\xC0\xAF"), "\"\\ufffd\\ufffd\"");                       // overlong '/'
    EXPECT_EQ(quoted("\xED\xA0\x80"), "\"\\ufffd\\ufffd\\ufffd\"");            // UTF-16 surrogate
    EXPECT_EQ(quoted("\xF4\x90\x80\x80"), "\"\\ufffd\\ufffd\\ufffd\\ufffd\""); // > U+10FFFF
    EXPECT_EQ(quoted("a\xE2\x82z"), "\"a\\ufffd\\ufffdz\"");
}
