#!/bin/sh
# Compile the unmodified official CoreMark POSIX port for WASI execution/timing.
set -eu
cd "$(dirname "$0")/.."
revision=1f483d5b8316753a742cbf5590caf5bd0a4e4777
source_dir=${COREMARK_SOURCE_DIR:-target/coremark-upstream}
: "${WASI_SDK_PATH:?set WASI_SDK_PATH to wasi-sdk 33}"
"$WASI_SDK_PATH/bin/clang" --version | head -1 | grep -q '22.1.0-wasi-sdk'
if [ ! -e "$source_dir" ]; then
  mkdir -p "$source_dir"
  git -C "$source_dir" init -q
  git -C "$source_dir" fetch --depth 1 https://github.com/eembc/coremark.git "$revision"
  git -C "$source_dir" checkout --detach FETCH_HEAD
fi
[ "$(git -C "$source_dir" rev-parse HEAD)" = "$revision" ] || {
  echo "CoreMark source must be at $revision" >&2
  exit 1
}
git -C "$source_dir" diff --quiet HEAD -- . || {
  echo 'CoreMark source must be unmodified' >&2
  exit 1
}
mkdir -p target/coremark-wasi
"$WASI_SDK_PATH/bin/clang" --target=wasm32-wasip1 -O3 -msign-ext -mbulk-memory \
  -DITERATIONS=1 '-DFLAGS_STR="-O3 -msign-ext -mbulk-memory -DITERATIONS=1"' \
  '-DMEM_LOCATION="WASI linear memory"' -I"$source_dir" -I"$source_dir/posix" \
  "$source_dir/core_list_join.c" "$source_dir/core_main.c" \
  "$source_dir/core_matrix.c" "$source_dir/core_state.c" \
  "$source_dir/core_util.c" "$source_dir/posix/core_portme.c" \
  -Wl,--max-memory=16777216 -Wl,-z,stack-size=65536 -Wl,--strip-all \
  -o target/coremark-wasi/coremark.wasm
shasum -a 256 target/coremark-wasi/coremark.wasm
