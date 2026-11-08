FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections && \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential g++-13 clang-18 libclang-rt-18-dev llvm-18 cmake ninja-build git ca-certificates \
      python3 tshark clang-format-18 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
