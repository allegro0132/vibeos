#!/bin/sh
# Boot VibeOS interactively under QEMU and execute the real Core-WASM demo.
# The demo's exact task-owned profiling contract requires one hart.
# Exit with Ctrl-A then X.
set -eu
cd "$(dirname "$0")"
# The bare-metal Cargo config lives under firmware/ so workspace-root host
# tests remain host builds.
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "run.sh: rustup and an exact rust-toolchain.toml channel are required" >&2
  exit 1
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
RUN_FEATURES=${RUN_FEATURES:-file-tree,wasm-c84-core-poll-qemu-acceptance}
(case ",$RUN_FEATURES," in
  *,wasm-c84-core-poll-qemu-acceptance,*) ;;
  *) echo "run.sh: RUN_FEATURES must include wasm-c84-core-poll-qemu-acceptance" >&2; exit 1 ;;
esac)
(cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features "$RUN_FEATURES") >&2

FILE_TREE_DISK=${FILE_TREE_DISK:-target/file-tree.raw}
if [ ! -e "$FILE_TREE_DISK" ]; then
  mkdir -p "$(dirname "$FILE_TREE_DISK")"
  dd if=/dev/zero of="$FILE_TREE_DISK" bs=1m count=128 >/dev/null 2>&1
fi

exec qemu-system-riscv64 \
  -machine virt -cpu rv64 -smp 1 -m 128M -accel tcg,thread=single \
  -nographic -bios default \
  -kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt \
  -drive if=none,id=file-tree-disk,format=raw,file="$FILE_TREE_DISK",cache=writeback \
  -device virtio-blk-device,drive=file-tree-disk,bus=virtio-mmio-bus.0,queue-size=8 \
  -global virtio-mmio.force-legacy=false
