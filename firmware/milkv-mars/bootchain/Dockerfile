FROM ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu \
    bison flex bc python3 python3-dev python3-setuptools swig \
    libssl-dev libgnutls28-dev device-tree-compiler u-boot-tools \
    dosfstools mtools gdisk git ca-certificates file \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
