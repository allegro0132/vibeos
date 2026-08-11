#!/bin/sh
# Build the Milk-V Duo kernel image and, when an SDK is supplied, its FIT.
set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

diagnostic=false
ssh_acceptance=false
jitterentropy_probe=false
sdk_arg=
for arg in "$@"; do
  case "$arg" in
    --diagnostic) diagnostic=true ;;
    --ssh-acceptance) ssh_acceptance=true ;;
    --jitterentropy-probe) jitterentropy_probe=true ;;
    -*) echo "usage: $0 [--diagnostic|--ssh-acceptance|--jitterentropy-probe] [duo-buildroot-sdk-root]" >&2; exit 2 ;;
    *)
      if [ -n "$sdk_arg" ]; then
        echo "usage: $0 [--diagnostic|--ssh-acceptance|--jitterentropy-probe] [duo-buildroot-sdk-root]" >&2
        exit 2
      fi
      sdk_arg=$arg
      ;;
  esac
done

mode_count=0
[ "$diagnostic" = true ] && mode_count=$((mode_count + 1))
[ "$ssh_acceptance" = true ] && mode_count=$((mode_count + 1))
[ "$jitterentropy_probe" = true ] && mode_count=$((mode_count + 1))
if [ "$mode_count" -gt 1 ]; then
  echo "build-milkv-duo.sh: image mode options are mutually exclusive" >&2
  exit 2
fi

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' \
  "$repo_root/rust-toolchain.toml")
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "build-milkv-duo.sh: rustup and an exact rust-toolchain.toml channel are required" >&2
  exit 1
fi

pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
sysroot=$("$pinned_rustc" --print sysroot)
host=$("$pinned_rustc" -vV | sed -n 's/^host: //p')
rust_objcopy="$sysroot/lib/rustlib/$host/bin/rust-objcopy"
if [ -z "$host" ] || [ ! -x "$rust_objcopy" ]; then
  echo "build-milkv-duo.sh: pinned rust-objcopy not found: $rust_objcopy" >&2
  exit 1
fi

sdk_root=
mkimage=
sdk_dtb=
if [ -n "$sdk_arg" ]; then
  if [ ! -d "$sdk_arg" ]; then
    echo "build-milkv-duo.sh: SDK root is not a directory: $sdk_arg" >&2
    exit 1
  fi
  sdk_root=$(cd -- "$sdk_arg" && pwd)
  sdk_build="$sdk_root/u-boot-2021.10/build/cv1800b_milkv_duo_sd"
  mkimage="$sdk_build/tools/mkimage"
  sdk_dtb="$sdk_root/linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb"
  if [ ! -x "$mkimage" ]; then
    echo "build-milkv-duo.sh: SDK mkimage not found or not executable: $mkimage" >&2
    exit 1
  fi
  if ! "$mkimage" -V >/dev/null 2>&1; then
    echo "build-milkv-duo.sh: SDK mkimage cannot run on this host; build the" >&2
    echo "  kernel without an SDK argument, then package it inside the SDK container" >&2
    exit 1
  fi
  if [ ! -f "$sdk_dtb" ]; then
    echo "build-milkv-duo.sh: SDK device tree not found: $sdk_dtb" >&2
    exit 1
  fi
fi

features=net-shell
output_dir="$repo_root/target/milkv-duo"
output_elf="$output_dir/vibeos-milkv-duo.elf"
if [ "$diagnostic" = true ]; then
  features=legacy-shell
  output_dir="$repo_root/target/milkv-duo-diagnostic"
  output_elf="$output_dir/vibeos-milkv-duo-diagnostic.elf"
elif [ "$ssh_acceptance" = true ]; then
  features=milkv-ssh-acceptance
  output_dir="$repo_root/target/milkv-duo-ssh-acceptance"
  output_elf="$output_dir/vibeos-milkv-duo-ssh-acceptance.elf"
elif [ "$jitterentropy_probe" = true ]; then
  features=milkv-jitterentropy-probe
  output_dir="$repo_root/target/milkv-duo-jitterentropy-probe"
  output_elf="$output_dir/vibeos-milkv-duo-jitterentropy-probe.elf"
fi

(
  cd "$repo_root/firmware/milkv-duo"
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
    rustup run "$toolchain" cargo build --release --no-default-features \
      --features "$features"
)

built_elf="$repo_root/target/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
output_bin="$output_dir/vibeos-milkv-duo.bin"

if [ ! -f "$built_elf" ]; then
  echo "build-milkv-duo.sh: kernel ELF not found after build: $built_elf" >&2
  exit 1
fi

mkdir -p "$output_dir"
cp "$built_elf" "$output_elf"
if [ "$(uname -s)" = Darwin ]; then
  DYLD_LIBRARY_PATH="$sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    "$rust_objcopy" -O binary "$output_elf" "$output_bin"
else
  "$rust_objcopy" -O binary "$output_elf" "$output_bin"
fi

echo "Milk-V Duo ELF: $output_elf"
echo "Milk-V Duo binary: $output_bin"

if [ -n "$sdk_root" ]; then
  output_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
  output_its="$output_dir/milkv-duo.its"
  cp "$sdk_dtb" "$output_dtb"
  cp "$script_dir/milkv-duo.its" "$output_its"
  (
    cd "$output_dir"
    "$mkimage" -f milkv-duo.its boot.sd
    "$mkimage" -l boot.sd
  )
  echo "Milk-V Duo FIT: $output_dir/boot.sd"
fi
