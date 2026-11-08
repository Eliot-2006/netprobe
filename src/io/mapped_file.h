#pragma once
// Read-only memory-mapped file (PRD 6.2, FR-PCAP-1).

#include "util/bytes.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>

namespace netprobe {

// Fatal input problem (cannot open, not a regular file, mmap failure). Maps to exit code 2.
class InputError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Move-only RAII mapping: PROT_READ, MAP_PRIVATE, MADV_SEQUENTIAL. An empty file is valid and
// yields empty bytes() without calling mmap (mmap of length 0 is an error).
class MappedFile {
public:
    // Throws InputError with a message naming the path and the cause.
    static MappedFile open(const std::filesystem::path& path);

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& o) noexcept;
    MappedFile& operator=(MappedFile&& o) noexcept;
    ~MappedFile();

    Bytes bytes() const noexcept { return {data_, size_}; }

    // ponytail: no-op until M10 (release frontier: MADV_DONTNEED / PROT_NONE in debug builds).
    void release_before(std::uint64_t offset) noexcept;

private:
    MappedFile(const std::byte* data, std::size_t size) noexcept : data_(data), size_(size) {}
    void reset() noexcept;

    const std::byte* data_ = nullptr;
    std::size_t size_ = 0;
};

} // namespace netprobe
