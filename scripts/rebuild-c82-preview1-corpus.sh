#!/bin/sh
# Rebuild the checked-in C8.2 Rust and C guests with the exact reviewed
# toolchains, then prove that sanitization and componentization reproduce the
# admitted fixtures byte for byte.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL rebuild-c82-preview1-corpus: $*" >&2
  exit 1
}

sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

require_sha256() {
  label=$1
  path=$2
  expected=$3
  [ -f "$path" ] || fail "$label is missing: $path"
  observed=$(sha256 "$path")
  [ "$observed" = "$expected" ] || \
    fail "$label SHA-256 differs: expected $expected, observed $observed"
}

require_size_sha256() {
  label=$1
  path=$2
  expected_size=$3
  expected_sha256=$4
  observed_size=$(wc -c < "$path" | tr -d '[:space:]')
  [ "$observed_size" = "$expected_size" ] || \
    fail "$label length differs: expected $expected_size, observed $observed_size"
  require_sha256 "$label" "$path" "$expected_sha256"
}

command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
command -v shasum >/dev/null 2>&1 || fail 'shasum is required'
command -v cmp >/dev/null 2>&1 || fail 'cmp is required'
command -v mktemp >/dev/null 2>&1 || fail 'mktemp is required'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ "$toolchain" = "nightly-2026-08-01" ] || fail 'unexpected repository toolchain'
rustc_bin=$(rustup which --toolchain "$toolchain" rustc)
rustdoc_bin=$(rustup which --toolchain "$toolchain" rustdoc)
cargo_bin=$(rustup which --toolchain "$toolchain" cargo)
[ -x "$rustc_bin" ] || fail 'pinned rustc is unavailable'
[ -x "$rustdoc_bin" ] || fail 'pinned rustdoc is unavailable'
[ -x "$cargo_bin" ] || fail 'pinned cargo is unavailable'

rust_host=$("$rustc_bin" --version --verbose | sed -n 's/^host: //p')
[ "$rust_host" = "aarch64-apple-darwin" ] || \
  fail "the reviewed C8.2 rebuild host is aarch64-apple-darwin, observed $rust_host"
rust_commit=$("$rustc_bin" --version --verbose | sed -n 's/^commit-hash: //p')
[ "$rust_commit" = "ad3d0bc141a02cf446e384136d250a1f6950fed5" ] || \
  fail "pinned rustc commit differs: $rust_commit"
require_sha256 \
  'pinned rustc' \
  "$rustc_bin" \
  'fa817099946eee0d4a4ed1d6593b05596f34f92181363e467c6253e84ce431af'

rust_toolchain_root=$(CDPATH='' cd -- "$(dirname "$rustc_bin")/.." && pwd -P)
rust_lld="$rust_toolchain_root/lib/rustlib/$rust_host/bin/rust-lld"
require_sha256 \
  'pinned Rust linker' \
  "$rust_lld" \
  '6f44b61e91d6d7b6ba80bb75391587bb4fa832b248281bd67d519516cde43f98'
rustup target list --installed --toolchain "$toolchain" | \
  grep -qx 'wasm32-wasip1' || fail 'pinned wasm32-wasip1 target is unavailable'

: "${C82_WASI_SDK_PATH:?set C82_WASI_SDK_PATH to the extracted wasi-sdk-33.0-arm64-macos root}"
wasi_sdk=$(CDPATH='' cd -- "$C82_WASI_SDK_PATH" && pwd -P) || \
  fail 'C82_WASI_SDK_PATH is not a readable directory'
clang_bin="$wasi_sdk/bin/clang"
wasm_ld_bin="$wasi_sdk/bin/wasm-ld"
require_sha256 \
  'wasi-sdk-33 clang' \
  "$clang_bin" \
  '356b0fdc2006a584582b4958c4ed461813d7492ca412f21727ba7875af93433d'
require_sha256 \
  'wasi-sdk-33 wasm-ld' \
  "$wasm_ld_bin" \
  '1682e0d83e144ce8e9b3d5f9dbb628ffdbe404c374c86b5757c00bce4a4d1f24'
"$clang_bin" --version | grep -q 'clang version 22.1.0-wasi-sdk' || \
  fail 'wasi-sdk clang version differs'
"$clang_bin" --version | grep -q '4434dabb69916856b824f68a64b029c67175e532' || \
  fail 'wasi-sdk LLVM commit differs'
"$wasm_ld_bin" --version | grep -q 'LLD 22.1.0' || fail 'wasi-sdk LLD version differs'

rust_source='policy/image/artifacts/c82-rust-ascii-filter.rs'
c_source='policy/image/artifacts/c82-c-ascii-filter.c'
adapter='policy/image/artifacts/c81-wasmtime-v48.0.0-preview1-command-adapter.wasm'
require_sha256 \
  'checked-in Rust source' \
  "$rust_source" \
  '9d85748409e086e57c8de799299376a2755422eb9ad0e35a01eea71c3ac71dff'
require_sha256 \
  'checked-in C source' \
  "$c_source" \
  'fb9b1d6b0c7a80d71a1f0707dc74cdbfc058c8f52f63f5f59e16b049a80fc096'

c82_rebuild_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/vibeos-c82-rebuild.XXXXXX")
case "$c82_rebuild_dir" in
  "${TMPDIR:-/private/tmp}"/vibeos-c82-rebuild.*) ;;
  *) fail 'mktemp returned an unexpected rebuild directory' ;;
esac
trap 'rm -rf "$c82_rebuild_dir"' EXIT HUP INT TERM

echo 'C8.2 source gate: rebuild exact Rust compiler Core' >&2
"$rustc_bin" \
  "$rust_source" \
  --edition=2024 \
  --crate-name c82_rust_ascii_filter \
  --target wasm32-wasip1 \
  -C target-cpu=mvp \
  -C link-self-contained=no \
  -C panic=abort \
  -C opt-level=z \
  -C lto=fat \
  -C codegen-units=1 \
  -C linker="$rust_lld" \
  -C link-arg=-z \
  -C link-arg=stack-size=65536 \
  -C link-arg=--initial-memory=131072 \
  -C link-arg=--max-memory=1048576 \
  -C link-arg=--export-memory \
  -C link-arg=--strip-all \
  -o "$c82_rebuild_dir/rust.compiler.core.wasm"
require_size_sha256 \
  'rebuilt Rust compiler Core' \
  "$c82_rebuild_dir/rust.compiler.core.wasm" \
  959 \
  '5bac5d59d47f51aec03b4704fbb2fcf08277a55603d40febf23cdd126746dd3a'

echo 'C8.2 source gate: rebuild exact C compiler Core' >&2
"$clang_bin" \
  --target=wasm32-wasip1 \
  -O2 \
  -ffreestanding \
  -fno-builtin \
  -nostdlib \
  "$c_source" \
  -Wl,--no-entry \
  -Wl,--export=_start \
  -Wl,--export-memory \
  -Wl,--stack-first \
  -Wl,-z,stack-size=65536 \
  -Wl,--initial-memory=131072 \
  -Wl,--max-memory=1048576 \
  -Wl,--strip-all \
  -o "$c82_rebuild_dir/c.compiler.core.wasm"
require_size_sha256 \
  'rebuilt C compiler Core' \
  "$c82_rebuild_dir/c.compiler.core.wasm" \
  1186 \
  'ccc1ca33e84f4ed8e94a28e65ed5419fb4d8942a4dd5e67fe50fe158fff090e4'

echo 'C8.2 source gate: build the pinned sanitizer/componentizer' >&2
env \
  CARGO_TARGET_DIR="$c82_rebuild_dir/cargo-target" \
  RUSTC="$rustc_bin" \
  RUSTDOC="$rustdoc_bin" \
  "$cargo_bin" build --locked --offline \
  -p vibeos-c82-preview1-corpus \
  --bin vibeos-c82-preview1-corpus >&2
componentizer="$c82_rebuild_dir/cargo-target/debug/vibeos-c82-preview1-corpus"
[ -x "$componentizer" ] || fail 'C8.2 componentizer binary is unavailable'

for language in rust c; do
  echo "C8.2 source gate: reproduce $language admitted fixtures" >&2
  "$componentizer" \
    --core "$c82_rebuild_dir/$language.compiler.core.wasm" \
    --adapter "$adapter" \
    --sanitized-core-output "$c82_rebuild_dir/$language.core.wasm" \
    --output "$c82_rebuild_dir/$language.component.wasm" >&2
  cmp \
    "$c82_rebuild_dir/$language.core.wasm" \
    "policy/image/artifacts/c82-$language-ascii-filter.core.wasm" || \
    fail "$language sanitized Core does not reproduce the checked-in fixture"
  cmp \
    "$c82_rebuild_dir/$language.component.wasm" \
    "policy/image/artifacts/c82-$language-ascii-filter.preview1-wrapped.component.wasm" || \
    fail "$language Component does not reproduce the checked-in fixture"
done

echo 'C8.2 source gate: PASS source_to_compiler_core_to_component=true' >&2
