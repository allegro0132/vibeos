#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

dependency_tree=$(cargo tree \
  -p vibeos-blob-format \
  --target riscv64imac-unknown-none-elf \
  --locked \
  --offline)
printf '%s\n' "$dependency_tree"
if printf '%s\n' "$dependency_tree" | grep -q 'cpufeatures'; then
  echo "check-blob-sha2: bare-metal blob-format unexpectedly selects cpufeatures" >&2
  exit 1
fi

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "check-blob-sha2: pinned rustup toolchain is required" >&2
  exit 1
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
(
  cd firmware/qemu-virt
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
    rustup run "$toolchain" cargo check --release --features legacy-shell --locked --offline
)

echo "ok   blob sha2 no_std target graph and firmware build"
