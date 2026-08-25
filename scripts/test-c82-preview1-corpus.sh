#!/bin/sh
# Host-only C8.2 gate. It must never boot QEMU or register the acceptance
# corpus with the ordinary loader/graph/vsh paths.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL test-c82-preview1-corpus: $*" >&2
  exit 1
}

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
cargo_bin=$(rustup which --toolchain "$toolchain" cargo)
rustc_bin=$(rustup which --toolchain "$toolchain" rustc)
rustdoc_bin=$(rustup which --toolchain "$toolchain" rustdoc)
[ -x "$cargo_bin" ] || fail 'pinned cargo is unavailable'
[ -x "$rustc_bin" ] || fail 'pinned rustc is unavailable'
[ -x "$rustdoc_bin" ] || fail 'pinned rustdoc is unavailable'

echo 'C8.2 host gate: source-to-admitted-byte reproducibility' >&2
./scripts/rebuild-c82-preview1-corpus.sh >&2

echo 'C8.2 host gate: bounded host-only componentizer tests' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-c82-preview1-corpus >&2

echo 'C8.2 host gate: production Core inspector/runtime tests' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-wasm-runtime --tests >&2

echo 'C8.2 host gate: bounded stream prefix and state-machine tests' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-component-host --tests >&2

echo 'C8.2 host gate: canonical validator/profile tests' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-component-format >&2

echo 'C8.2 host gate: feature-gated acceptance broker tests' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-component-admission \
  --features preview1-corpus-acceptance >&2

echo 'C8.2 host gate: independent fixture and named mutation verification' >&2
env PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/verify-c82-preview1-corpus.py --fixture --selftest >&2

echo 'C8.2 host gate: feature-off and ordinary admission isolation' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-component-admission --no-default-features >&2

echo 'C8.2 host gate: loader remains ordinary and corpus-unaware' >&2
env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" test --locked --offline \
  -p vibeos-component-loader >&2

echo 'C8.2 host gate: RISC-V feature closure without boot or registration' >&2
(
  cd firmware/qemu-virt
  env RUSTC="$rustc_bin" RUSTDOC="$rustdoc_bin" \
    "$cargo_bin" check --locked --offline --release \
    --target riscv64imac-unknown-none-elf \
    -p vibeos-component-admission \
    --features preview1-corpus-acceptance >&2
)

echo 'C8.2 host gate: PASS runtime_ready=false ordinary_registration=false' >&2
