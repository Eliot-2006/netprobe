#include "report/stream_export.h"

#include <cstdio>
#include <string>

namespace netprobe {

std::filesystem::path stream_file(const std::filesystem::path& dir, std::uint64_t flow_id,
                                  bool c2s) {
    return dir / (std::to_string(flow_id) + (c2s ? "_c2s.bin" : "_s2c.bin"));
}

void FileExportSink::on_data(std::uint64_t, Bytes data) {
    if (failed_ || data.empty()) {
        return;
    }
    std::FILE* f = std::fopen(path_.c_str(), "ab");
    if (f == nullptr) {
        failed_ = true;
        return;
    }
    if (std::fwrite(data.data(), 1, data.size(), f) != data.size()) {
        failed_ = true;
    }
    if (std::fclose(f) != 0) {
        failed_ = true;
    }
}

} // namespace netprobe
