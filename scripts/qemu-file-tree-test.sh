#!/bin/sh
# Multi-boot acceptance for the capability-rooted persistent file tree.
set -eu

cd "$(dirname "$0")/.."
KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}

case "$QEMU_SMP" in
  ''|*[!0-9]*|0) echo "qemu-file-tree-test.sh: QEMU_SMP must be positive" >&2; exit 2 ;;
esac

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "qemu-file-tree-test.sh: pinned rustup toolchain is required" >&2
  exit 2
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
(cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features file-tree) >&2

work=$(mktemp -d)
disk="$work/file-tree.raw"
prefix="$work/unmanaged-prefix.baseline"

cleanup() {
  if [ "${KEEP_FILE_TREE_EVIDENCE:-0}" = "1" ] || [ -f "$work/FAILED" ]; then
    echo "file-tree evidence retained at $work" >&2
  else
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

dd if=/dev/zero of="$disk" bs=1m count=128 >/dev/null 2>&1
dd if="$disk" of="$prefix" bs=512 count=64 >/dev/null 2>&1

run_boot() {
  boot=$1
  case_file="tests/cases/file_tree.boot$boot"
  log="$work/boot$boot.log"
  echo "file-tree: boot $boot" >&2
  python3 -B scripts/qemu-vsh-driver.py --case "$case_file" --log "$log" -- \
    qemu-system-riscv64 -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
      -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
      -drive if=none,id=file-tree-disk,format=raw,file="$disk",cache=writeback \
      -device virtio-blk-device,drive=file-tree-disk,bus=virtio-mmio-bus.0,queue-size=8 \
      -global virtio-mmio.force-legacy=false
  if grep -a -Eq '\[!\] (fatal trap|panic)|panicked at|boot fail-closed|recovery failed closed' "$log"; then
    echo "FAIL file-tree: boot $boot reported a fatal outcome" >&2
    sed -n '1,220p' "$log" >&2
    return 1
  fi
}

fail_with_log() {
  message=$1
  log=$2
  : > "$work/FAILED"
  echo "FAIL file-tree: $message" >&2
  sed -n '1,320p' "$log" >&2
  exit 1
}

verify_image() {
  boot=$1
  evidence="$work/boot$boot.json"
  python3 -B scripts/verify-storage-v2-migration.py \
    --expect-native --expect-file-tree \
    --unmanaged-prefix-baseline "$prefix" "$disk" > "$evidence"
  python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    evidence = json.load(source)
tree = evidence["equivalence"]["file_tree"]
expected = (int(sys.argv[2]), int(sys.argv[3]))
actual = (tree["inodes"], tree["dirents"])
if evidence["status"] != "ok" or not tree["verified"] or actual != expected:
    raise SystemExit(f"file-tree image mismatch: expected {expected}, observed {actual}")
' "$evidence" "$2" "$3"
}

verify_hard_links() {
  log=$1
  python3 -c '
import re, sys
text = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
cfg = re.findall(r"(?:^|\n)cfg:(\d+):2:23(?:\r|\n)", text)
hard = re.findall(r"(?:^|\n)hard:(\d+):2:23(?:\r|\n)", text)
if not cfg or not hard or cfg[-1] != hard[-1]:
    raise SystemExit("hard-link FileId/link-count evidence is absent or inconsistent")
' "$log"
}

run_boot 1
if ! verify_hard_links "$work/boot1.log"; then
  fail_with_log "boot 1 hard-link evidence failed" "$work/boot1.log"
fi
[ "$(grep -a -o 'VIBE_FILE_TREE_UPDATED' "$work/boot1.log" | wc -l | tr -d ' ')" -ge 3 ] \
  || fail_with_log "boot 1 content evidence failed" "$work/boot1.log"
grep -a -F -q '@home/etc/config' "$work/boot1.log" \
  || fail_with_log "boot 1 canonical symlink evidence failed" "$work/boot1.log"
verify_image 1 4 4 || fail_with_log "boot 1 powered-off verification failed" "$work/boot1.log"

run_boot 2
if ! verify_hard_links "$work/boot2.log"; then
  fail_with_log "boot 2 hard-link recovery failed" "$work/boot2.log"
fi
[ "$(grep -a -o 'VIBE_FILE_TREE_UPDATED' "$work/boot2.log" | wc -l | tr -d ' ')" -ge 1 ] \
  || fail_with_log "boot 2 content recovery failed" "$work/boot2.log"
grep -a -F -q '@home/etc/config' "$work/boot2.log" \
  || fail_with_log "boot 2 canonical symlink recovery failed" "$work/boot2.log"
verify_image 2 1 0 || fail_with_log "boot 2 recursive removal verification failed" "$work/boot2.log"

run_boot 3
[ "$(grep -a -o 'VIBE_FILE_TREE_BOOT3_OK' "$work/boot3.log" | wc -l | tr -d ' ')" -ge 2 ] \
  || fail_with_log "boot 3 completion marker failed" "$work/boot3.log"
verify_image 3 1 0 || fail_with_log "boot 3 cold recovery verification failed" "$work/boot3.log"

mkdir -p target
cp "$work/boot3.json" target/file-tree-verifier.json
echo "PASS file-tree: durable hard links, symlink, recursive removal, GC pressure, cold recovery, powered-off verification"
