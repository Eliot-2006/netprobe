#include "report/report.h"

namespace netprobe {

// ponytail: placeholder until M7 (HTML report design); replaced wholesale there.
std::string render_html(const Report&) {
    return "<!doctype html><meta charset=\"utf-8\"><title>NetProbe report</title>"
           "<p>HTML report not implemented yet.</p>\n";
}

} // namespace netprobe
