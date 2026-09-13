#!/bin/sh
# Build genuine standard-library programs; never rewrite the compiler output.
set -eu
cd "$(dirname "$0")/.."
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
: "${WASI_SDK_PATH:?set WASI_SDK_PATH to wasi-sdk-33.0-arm64-macos}"
"$WASI_SDK_PATH/bin/clang" --version | head -1 | grep -q '22.1.0-wasi-sdk' || exit 1
mkdir -p target/wasi-examples
export CARGO_TARGET_DIR="$PWD/target/wasi-examples/rust-target"
export RUSTFLAGS='-C target-cpu=mvp -C target-feature=+mutable-globals,+sign-ext,+bulk-memory,+reference-types,+multivalue,+nontrapping-fptoint -C link-arg=--max-memory=16777216 -C link-arg=-z -C link-arg=stack-size=65536'
rustup run "$toolchain" cargo build --manifest-path tests/wasi/rust/Cargo.toml \
    -Z build-std=std,panic_abort --target wasm32-wasip1 --release
cp "$CARGO_TARGET_DIR/wasm32-wasip1/release/wasi-hello.wasm" target/wasi-examples/rust-hello.wasm
"$WASI_SDK_PATH/bin/clang" --target=wasm32-wasip1 -Oz -msign-ext -mbulk-memory \
    tests/wasi/hello.c -Wl,--max-memory=16777216 -Wl,-z,stack-size=65536 -Wl,--strip-all \
    -o target/wasi-examples/c-hello.wasm
# wasi-threads: imported shared memory (re-exported for the command contract),
# wasi::thread-spawn and wasi_thread_start, from the SDK's threads sysroot.
"$WASI_SDK_PATH/bin/clang" --target=wasm32-wasi-threads -pthread -O2 -msign-ext -mbulk-memory \
    tests/wasi/threads.c -Wl,--max-memory=16777216 -Wl,--import-memory -Wl,--export-memory -Wl,-z,stack-size=65536 -Wl,--strip-all \
    -o target/wasi-examples/c-threads.wasm
shasum -a 256 target/wasi-examples/*-hello.wasm target/wasi-examples/c-threads.wasm
