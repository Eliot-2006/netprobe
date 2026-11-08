#include "io/mapped_file.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace netprobe {

namespace {
[[noreturn]] void fail(const std::filesystem::path& path, const char* what, int err) {
    std::string msg = "cannot read '" + path.string() + "': " + what;
    if (err != 0) {
        msg += ": ";
        msg += std::strerror(err);
    }
    throw InputError(msg);
}

struct Fd {
    int fd;
    ~Fd() {
        if (fd >= 0) {
            ::close(fd);
        }
    }
};
} // namespace

MappedFile MappedFile::open(const std::filesystem::path& path) {
    Fd f{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (f.fd < 0) {
        fail(path, "open failed", errno);
    }
    struct stat st = {};
    if (::fstat(f.fd, &st) != 0) {
        fail(path, "fstat failed", errno);
    }
    if (!S_ISREG(st.st_mode)) {
        fail(path, "not a regular file", 0);
    }
    if (st.st_size == 0) {
        return MappedFile(nullptr, 0);
    }
    const auto size = static_cast<std::size_t>(st.st_size);
    void* p = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, f.fd, 0);
    if (p == MAP_FAILED) {
        fail(path, "mmap failed", errno);
    }
    ::madvise(p, size, MADV_SEQUENTIAL); // advisory only; failure is harmless
    return MappedFile(static_cast<const std::byte*>(p), size);
}

MappedFile::MappedFile(MappedFile&& o) noexcept
    : data_(std::exchange(o.data_, nullptr)), size_(std::exchange(o.size_, 0)) {}

MappedFile& MappedFile::operator=(MappedFile&& o) noexcept {
    if (this != &o) {
        reset();
        data_ = std::exchange(o.data_, nullptr);
        size_ = std::exchange(o.size_, 0);
    }
    return *this;
}

MappedFile::~MappedFile() {
    reset();
}

void MappedFile::reset() noexcept {
    if (data_ != nullptr) {
        ::munmap(const_cast<std::byte*>(data_), size_);
        data_ = nullptr;
        size_ = 0;
    }
}

void MappedFile::release_before(std::uint64_t offset) noexcept {
    const auto page_size = ::sysconf(_SC_PAGESIZE);
    if (data_ == nullptr || page_size <= 0) {
        return;
    }
    const auto page = static_cast<std::uint64_t>(page_size);
    const auto end = std::min<std::uint64_t>(offset, size_) / page * page;
    if (end == 0) {
        return;
    }
    // Drop the pages in every build, so memory behaves the same with and without guards.
    ::madvise(const_cast<std::byte*>(data_), static_cast<std::size_t>(end), MADV_DONTNEED);
#ifdef NETPROBE_DEBUG_GUARDS
    // Debug/hardened builds also make released pages inaccessible: a dangling view faults
    // instead of silently re-reading the file (enforces invariant O1).
    ::mprotect(const_cast<std::byte*>(data_), static_cast<std::size_t>(end), PROT_NONE);
#endif
}

} // namespace netprobe
