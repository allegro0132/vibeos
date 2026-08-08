#!/bin/sh
# Boot VibeOS interactively under QEMU. Exit with Ctrl-A then X.
set -eu
cd "$(dirname "$0")"
# The bare-metal cargo config lives in kernel/.cargo so that `cargo test` at the
# workspace root still builds the libraries for the host.
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "run.sh: rustup and an exact rust-toolchain.toml channel are required" >&2
  exit 1
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
(cd kernel && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release) >&2
exec qemu-system-riscv64 \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -nographic -bios default \
  -kernel target/riscv64gc-unknown-none-elf/release/vibeos-kernel
