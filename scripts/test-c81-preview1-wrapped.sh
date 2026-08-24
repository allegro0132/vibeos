#!/bin/sh
# Host-only C8.1 gate.  It must never boot QEMU or invoke wrapped guest code.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL test-c81-preview1-wrapped: $*" >&2
  exit 1
}

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
cargo_bin=$(rustup which --toolchain "$toolchain" cargo)
rustc_bin=$(rustup which --toolchain "$toolchain" rustc)
[ -x "$cargo_bin" ] || fail 'pinned cargo is unavailable'
[ -x "$rustc_bin" ] || fail 'pinned rustc is unavailable'

echo 'C8.1 host gate: deterministic componentizer tests' >&2
env RUSTC="$rustc_bin" "$cargo_bin" test --locked --offline \
  -p vibeos-c81-preview1-componentizer --test componentizer >&2

echo 'C8.1 host gate: feature-gated validation-only admission tests' >&2
env RUSTC="$rustc_bin" "$cargo_bin" test --locked --offline \
  -p vibeos-component-admission --features preview1-wrapped-admission \
  --test preview1_wrapped >&2

echo 'C8.1 host gate: canonical component-format tests' >&2
env RUSTC="$rustc_bin" "$cargo_bin" test --locked --offline \
  -p vibeos-component-format --tests >&2

echo 'C8.1 host gate: independent mutation selftest' >&2
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify-c81-preview1-wrapped.py \
  --selftest >&2

echo 'C8.1 host gate: independent checked-in fixture verification' >&2
exec env PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/verify-c81-preview1-wrapped.py --fixture
