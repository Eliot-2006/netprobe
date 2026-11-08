#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc >= 2 && (std::strcmp(argv[1], "--version") == 0 || std::strcmp(argv[1], "-V") == 0)) {
        std::printf("netprobe %s\n", NETPROBE_VERSION);
        return 0;
    }
    std::fprintf(stderr, "usage: netprobe <analyze|dump> <capture.pcap> [options]\n");
    return 1;
}
