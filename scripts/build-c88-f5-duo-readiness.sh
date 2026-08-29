#!/bin/sh
# Cross-link the inert-sentinel C8.8-F5 Milk-V Duo readiness ELF.
#
# This command only compiles and links; it neither produces deployable media
# nor touches a device or executes the result. Ambient evidence bindings are
# cleared and then the reserved, non-evidence sentinel identity is supplied so
# the complete producer remains linked. The immutable execution arm is zero,
# so an accidentally booted readiness ELF fails closed before qualification.
set -eu

if [ "$#" -ne 0 ]; then
  echo "usage: $0" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' \
  "$repo_root/rust-toolchain.toml")

if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "build-c88-f5-duo-readiness.sh: pinned rustup toolchain is unavailable" >&2
  exit 1
fi

pinned_cargo=$(rustup which --toolchain "$toolchain" cargo)
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
if [ ! -x "$pinned_cargo" ] || [ ! -x "$pinned_rustc" ] || \
   [ ! -x "$pinned_rustdoc" ]; then
  echo "build-c88-f5-duo-readiness.sh: pinned Rust tools are not executable" >&2
  exit 1
fi

target_parent="$repo_root/target"
target_dir="$target_parent/c88-f5-duo-readiness/build"
if [ -L "$target_parent" ] || [ -L "$target_parent/c88-f5-duo-readiness" ] || \
   [ -L "$target_dir" ]; then
  echo "build-c88-f5-duo-readiness.sh: refusing a symlinked target path" >&2
  exit 1
fi
mkdir -p "$target_dir"
if [ ! -d "$target_dir" ] || [ -L "$target_dir" ]; then
  echo "build-c88-f5-duo-readiness.sh: target directory is not a fixed directory" >&2
  exit 1
fi

# Never let an ambient publication identity turn this compile-only command
# into an evidence-bearing build. A future physical runner must own every
# binding under its separately reviewed contract.
unset VIBEOS_C88_F5_SOURCE_COMMIT
unset VIBEOS_C88_F5_SOURCE_TREE
unset VIBEOS_C88_F5_CHALLENGE
unset VIBEOS_C88_F5_RUN_ID
unset VIBEOS_C88_F5_MANIFEST_SHA256
unset VIBEOS_C88_F5_TRANSCRIPT_SCHEMA_SHA256
unset VIBEOS_C88_F5_DUO_SOURCE_COMMIT
unset VIBEOS_C88_F5_DUO_SOURCE_TREE
unset VIBEOS_C88_F5_DUO_CHALLENGE
unset VIBEOS_C88_F5_DUO_RUN_ID
unset VIBEOS_C88_F5_DUO_MANIFEST_SHA256
unset VIBEOS_C88_F5_DUO_TRANSCRIPT_SCHEMA_SHA256
unset RUSTFLAGS
unset CARGO_ENCODED_RUSTFLAGS
unset RUSTC_WRAPPER
unset RUSTC_WORKSPACE_WRAPPER
unset CARGO_BUILD_RUSTC_WRAPPER
unset CARGO_BUILD_TARGET

duo_source_commit=d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1
duo_source_tree=d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
duo_challenge=d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3
duo_run_id=c5c8ec42e56fbeaf38106965e5ec6735cb86a93af530cd37f5002dba1971b4ac
duo_manifest_sha256=1c85f22cacee7c8eb7693578052fe0452169eace99f1dab06e08aa0e42771b11
duo_transcript_schema_sha256=e25d9a38d194993906b7fe5ec9708654ea31e2386ac61f0fa360ed8ad1eb7439
duo_rustflags='-C linker=ld.lld -C linker-flavor=ld -C target-feature=+zicsr,+zifencei -C link-arg=--gc-sections -C force-frame-pointers=yes -Z fmt-debug=none'
readonly duo_source_commit duo_source_tree duo_challenge duo_run_id
readonly duo_manifest_sha256 duo_transcript_schema_sha256 duo_rustflags

(
  cd "$repo_root/firmware/milkv-duo"
  VIBEOS_C88_F5_DUO_SOURCE_COMMIT="$duo_source_commit" \
    VIBEOS_C88_F5_DUO_SOURCE_TREE="$duo_source_tree" \
    VIBEOS_C88_F5_DUO_CHALLENGE="$duo_challenge" \
    VIBEOS_C88_F5_DUO_RUN_ID="$duo_run_id" \
    VIBEOS_C88_F5_DUO_MANIFEST_SHA256="$duo_manifest_sha256" \
    VIBEOS_C88_F5_DUO_TRANSCRIPT_SCHEMA_SHA256="$duo_transcript_schema_sha256" \
    CARGO_INCREMENTAL=0 \
    CARGO_NET_OFFLINE=true \
    CARGO_TARGET_DIR="$target_dir" \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="$duo_rustflags" \
    RUSTC="$pinned_rustc" \
    RUSTDOC="$pinned_rustdoc" \
    "$pinned_cargo" build \
      --release \
      --locked \
      --offline \
      --no-default-features \
      --features wasm-c88-f5-float-duo-compile-readiness
)

built_elf="$target_dir/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
if [ -L "$built_elf" ] || [ ! -f "$built_elf" ] || [ ! -s "$built_elf" ]; then
  echo "build-c88-f5-duo-readiness.sh: linked ELF is missing or invalid" >&2
  exit 1
fi

echo "C8.8-F5 Milk-V Duo compile readiness: PASS"
echo "Inert-sentinel compile-only ELF (not physical evidence): $built_elf"
