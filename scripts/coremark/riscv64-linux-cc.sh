#!/bin/sh
# Debian sysroot is exported by the benchmark preparation guest.
set -eu
: "COREMARK_SYSROOT:?Set COREMARK_SYSROOT to the exported Debian sysroot}"
rustroot=$(rustc --print sysroot)
rusthost=$(rustc -vV | sed -n 's/^host: //p')
exec clang --target=riscv64-unknown-linux-gnu --sysroot="$COREMARK_SYSROOT" \
  --gcc-toolchain="$COREMARK_SYSROOT/usr" \
  -fuse-ld="$rustroot/lib/rustlib/$rusthost/bin/gcc-ld/ld.lld" "$@"
