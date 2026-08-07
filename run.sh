#!/bin/sh
# Boot VibeOS interactively under QEMU. Exit with Ctrl-A then X.
set -e
RUSTC_BOOTSTRAP=1 cargo build --release >&2
exec qemu-system-riscv64 \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -nographic -bios default \
  -kernel target/riscv64gc-unknown-none-elf/release/vibeos-kernel
