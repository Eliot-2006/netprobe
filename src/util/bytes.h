#pragma once
// Byte-level access to untrusted wire data.
//
// Rule: never reinterpret_cast packet memory to a struct (misalignment + strict aliasing UB).
// Callers check lengths first; these loaders assemble values with shifts, which GCC/Clang
// compile to a single load (+ bswap) at -O2.

#include <cstddef>
#include <cstdint>
#include <span>

namespace netprobe {

using Bytes = std::span<const std::byte>;

constexpr std::uint8_t load_u8(const std::byte* p) noexcept {
    return std::to_integer<std::uint8_t>(p[0]);
}

constexpr std::uint16_t load_be16(const std::byte* p) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(p[0]) << 8) |
                                      std::to_integer<std::uint16_t>(p[1]));
}

constexpr std::uint32_t load_be32(const std::byte* p) noexcept {
    return (std::to_integer<std::uint32_t>(p[0]) << 24) |
           (std::to_integer<std::uint32_t>(p[1]) << 16) |
           (std::to_integer<std::uint32_t>(p[2]) << 8) | std::to_integer<std::uint32_t>(p[3]);
}

constexpr std::uint16_t load_le16(const std::byte* p) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(p[1]) << 8) |
                                      std::to_integer<std::uint16_t>(p[0]));
}

constexpr std::uint32_t load_le32(const std::byte* p) noexcept {
    return (std::to_integer<std::uint32_t>(p[3]) << 24) |
           (std::to_integer<std::uint32_t>(p[2]) << 16) |
           (std::to_integer<std::uint32_t>(p[1]) << 8) | std::to_integer<std::uint32_t>(p[0]);
}

enum class ByteOrder : std::uint8_t { little, big };

template <ByteOrder Order> constexpr std::uint16_t load16(const std::byte* p) noexcept {
    if constexpr (Order == ByteOrder::big) {
        return load_be16(p);
    } else {
        return load_le16(p);
    }
}

template <ByteOrder Order> constexpr std::uint32_t load32(const std::byte* p) noexcept {
    if constexpr (Order == ByteOrder::big) {
        return load_be32(p);
    } else {
        return load_le32(p);
    }
}

} // namespace netprobe
