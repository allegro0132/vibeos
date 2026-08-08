#!/bin/sh
# Boot VibeOS interactively under QEMU. Exit with Ctrl-A then X.
set -e
cd "$(dirname "$0")"
# The bare-metal cargo config lives in kernel/.cargo so that `cargo test` at the
# workspace root still builds the libraries for the host.
RUSTC_BOOTSTRAP=1 sh -c 'cd kernel && cargo build --release' >&2
exec qemu-system-riscv64 \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -nographic -bios default \
  -kernel target/riscv64gc-unknown-none-elf/release/vibeos-kernel
