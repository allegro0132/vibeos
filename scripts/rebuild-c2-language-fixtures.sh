#!/bin/sh
# Rebuild the C2.3 Rust and C Canonical ABI guests with the exact reviewed
# toolchains, then compare the generated Core modules byte for byte.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL rebuild-c2-language-fixtures: $*" >&2
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
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ "$toolchain" = "nightly-2026-08-01" ] || fail 'unexpected repository toolchain'
rustc_bin=$(rustup which --toolchain "$toolchain" rustc)
[ -x "$rustc_bin" ] || fail 'pinned rustc is unavailable'

rust_host=$("$rustc_bin" --version --verbose | sed -n 's/^host: //p')
[ "$rust_host" = "aarch64-apple-darwin" ] || \
  fail "the reviewed C2.3 rebuild host is aarch64-apple-darwin, observed $rust_host"
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

: "${C2_WASI_SDK_PATH:?set C2_WASI_SDK_PATH to the extracted wasi-sdk-33.0-arm64-macos root}"
wasi_sdk=$(CDPATH='' cd -- "$C2_WASI_SDK_PATH" && pwd -P) || \
  fail 'C2_WASI_SDK_PATH is not a readable directory'
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

rust_source='component-format/tests/corpus/guests/typed_guest.rs'
c_source='component-format/tests/corpus/guests/typed_guest.c'
wit_source='component-format/tests/corpus/wit/canonical-values.wit'
sanitizer='scripts/sanitize-c2-language-core.py'
rust_fixture='component-runtime/tests/fixtures/language/canonical-values-rust.core.wasm'
c_fixture='component-runtime/tests/fixtures/language/canonical-values-c.core.wasm'
require_size_sha256 \
  'checked-in Rust source' "$rust_source" 4498 \
  '6cbd0295b8ba932163ba70443cacabc62edeec84104f116cbdb48cef990bd021'
require_size_sha256 \
  'checked-in C source' "$c_source" 4337 \
  'c1bbc09cdce9b21237e6efc596530421c4c1696df03964a3a1ea6a31beeab877'
require_size_sha256 \
  'checked-in WIT contract' "$wit_source" 631 \
  '9f8d2aad8b904f8ee28d4a18154752e6ed76bf6db66754a07fef7d9e6ffea24c'
require_size_sha256 \
  'checked-in Core sanitizer' "$sanitizer" 7059 \
  '1536bceca3750ffed0301757e8b255c11882fc5fa06389240a37b8b877ac894c'
require_size_sha256 \
  'checked-in sanitized Rust Core fixture' "$rust_fixture" 557 \
  '79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52'
require_size_sha256 \
  'checked-in sanitized C Core fixture' "$c_fixture" 1030 \
  '20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e'

python3 -B "$sanitizer" --selftest

c2_rebuild_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/vibeos-c2-language.XXXXXX")
case "$c2_rebuild_dir" in
  "${TMPDIR:-/private/tmp}"/vibeos-c2-language.*) ;;
  *) fail 'mktemp returned an unexpected rebuild directory' ;;
esac
trap 'rm -rf "$c2_rebuild_dir"' EXIT HUP INT TERM

echo 'C2.3 source gate: rebuild exact Rust Core fixture' >&2
"$rustc_bin" \
  "$rust_source" \
  --edition=2024 \
  --crate-name c2_rust_canonical_values \
  --crate-type=cdylib \
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
  -C link-arg=--max-memory=131072 \
  -C link-arg=--export-memory \
  -C link-arg=--export=cabi_realloc \
  -C link-arg=--export=transform \
  -C link-arg=--export=cabi_post_transform \
  -C link-arg=--strip-all \
  -o "$c2_rebuild_dir/rust.compiler.core.wasm"
require_size_sha256 \
  'rebuilt Rust compiler Core' "$c2_rebuild_dir/rust.compiler.core.wasm" 567 \
  '149ff653148bf98c6929c9392e5239d1cf3516f3902329a05d0bec3762a0fa11'
python3 -B "$sanitizer" \
  "$c2_rebuild_dir/rust.compiler.core.wasm" \
  "$c2_rebuild_dir/rust.sanitized.core.wasm"
require_size_sha256 \
  'rebuilt sanitized Rust Core' "$c2_rebuild_dir/rust.sanitized.core.wasm" 557 \
  '79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52'
cmp "$c2_rebuild_dir/rust.sanitized.core.wasm" "$rust_fixture" || \
  fail 'rebuilt sanitized Rust Core differs byte-for-byte'

echo 'C2.3 source gate: rebuild exact C Core fixture' >&2
"$clang_bin" \
  --target=wasm32-wasip1 \
  -O2 \
  -ffreestanding \
  -fno-builtin \
  -nostdlib \
  "$c_source" \
  -Wl,--no-entry \
  -Wl,--export=cabi_realloc \
  -Wl,--export=transform \
  -Wl,--export=cabi_post_transform \
  -Wl,--export-memory \
  -Wl,--stack-first \
  -Wl,-z,stack-size=65536 \
  -Wl,--initial-memory=131072 \
  -Wl,--max-memory=131072 \
  -Wl,--strip-all \
  -o "$c2_rebuild_dir/c.compiler.core.wasm"
require_size_sha256 \
  'rebuilt C compiler Core' "$c2_rebuild_dir/c.compiler.core.wasm" 1040 \
  'e3d7284a26c34448465ebc12f5024e41e4cc9cae9943f251523a85863ae2aa91'
python3 -B "$sanitizer" \
  "$c2_rebuild_dir/c.compiler.core.wasm" \
  "$c2_rebuild_dir/c.sanitized.core.wasm"
require_size_sha256 \
  'rebuilt sanitized C Core' "$c2_rebuild_dir/c.sanitized.core.wasm" 1030 \
  '20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e'
cmp "$c2_rebuild_dir/c.sanitized.core.wasm" "$c_fixture" || \
  fail 'rebuilt sanitized C Core differs byte-for-byte'

echo 'C2.3 source gate: Rust and C sanitized Core fixtures reproduce exactly' >&2
