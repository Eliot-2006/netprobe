#include "util/bytes.h"

#include <gtest/gtest.h>

#include <array>

using namespace netprobe;

static_assert(load_be16(std::array{std::byte{0x12}, std::byte{0x34}}.data()) == 0x1234);
static_assert(load_le16(std::array{std::byte{0x12}, std::byte{0x34}}.data()) == 0x3412);
static_assert(load_be32(std::array{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                                   std::byte{0xEF}}
                            .data()) == 0xDEADBEEFu);
static_assert(load_le32(std::array{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                                   std::byte{0xEF}}
                            .data()) == 0xEFBEADDEu);

TEST(Bytes, LoadsAtEveryAlignment) {
    std::array<std::byte, 16> buf{};
    for (std::size_t off = 0; off + 4 <= buf.size(); ++off) {
        buf.fill(std::byte{0});
        buf[off] = std::byte{0x01};
        buf[off + 1] = std::byte{0x02};
        buf[off + 2] = std::byte{0x03};
        buf[off + 3] = std::byte{0x04};
        EXPECT_EQ(load_be32(buf.data() + off), 0x01020304u) << off;
        EXPECT_EQ(load_le32(buf.data() + off), 0x04030201u) << off;
        EXPECT_EQ(load_be16(buf.data() + off), 0x0102u) << off;
        EXPECT_EQ((load32<ByteOrder::big>(buf.data() + off)), 0x01020304u);
        EXPECT_EQ((load16<ByteOrder::little>(buf.data() + off)), 0x0201u);
    }
}

TEST(Bytes, HighBitsDoNotSignExtend) {
    std::array<std::byte, 4> buf{std::byte{0xFF}, std::byte{0xFE}, std::byte{0x80},
                                 std::byte{0x81}};
    EXPECT_EQ(load_be32(buf.data()), 0xFFFE8081u);
    EXPECT_EQ(load_be16(buf.data()), 0xFFFEu);
}
