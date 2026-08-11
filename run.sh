#!/bin/sh
# Boot VibeOS interactively under QEMU. Exit with Ctrl-A then X.
set -eu
cd "$(dirname "$0")"
# The bare-metal Cargo config lives under firmware/ so workspace-root host
# tests remain host builds.
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "run.sh: rustup and an exact rust-toolchain.toml channel are required" >&2
  exit 1
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
(cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release) >&2
exec qemu-system-riscv64 \
  -machine virt -cpu rv64 -smp 4 -m 128M -accel tcg,thread=multi \
  -nographic -bios default \
  -kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
