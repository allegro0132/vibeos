#!/bin/sh
# End-to-end QEMU virt PCI/XHCI acceptance: HID input, BOT/SCSI I/O, hotplug.
set -eu

cd "$(dirname "$0")/.."
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-1}
KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
SEED='VIBEOS-USB-SECTOR-7-SEED-v1'
WRITE='VIBEOS-USB-SECTOR-8-WRITE-v1'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "qemu-usb-test.sh: rustup and the pinned toolchain are required" >&2
  exit 1
fi
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "qemu-usb-test.sh: $QEMU_BIN not found" >&2
  exit 1
fi

pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
(cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features legacy-shell) >&2

work=$(mktemp -d)
cleanup() {
  rm -f "$work/stick.raw" "$work/serial.log" "$work/expected" "$work/observed"
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

truncate -s 8M "$work/stick.raw"
printf '%s' "$SEED" | dd of="$work/stick.raw" bs=1 seek=$((7 * 512)) conv=notrunc >/dev/null 2>&1

# QMP on stdio needs no host socket. Every sendkey is a press/release pair;
# VibeOS must receive both command lines exclusively through usb-kbd.
{
  printf '%s\n' '{"execute":"qmp_capabilities"}'
  sleep 6
  for key in u s b spc t e s t ret; do
    printf '{"execute":"human-monitor-command","arguments":{"command-line":"sendkey %s"}}\n' "$key"
    sleep 0.15
  done
  sleep 3
  printf '%s\n' '{"execute":"device_del","arguments":{"id":"kbd"}}'
  sleep 1
  printf '%s\n' '{"execute":"device_add","arguments":{"driver":"usb-kbd","id":"kbd2","bus":"xhci.0"}}'
  sleep 2
  for key in u s b spc i n f o ret; do
    printf '{"execute":"human-monitor-command","arguments":{"command-line":"sendkey %s"}}\n' "$key"
    sleep 0.15
  done
  sleep 2
  printf '%s\n' '{"execute":"quit"}'
} | "$QEMU_BIN" \
  -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
  -display none -serial "file:$work/serial.log" -monitor none -qmp stdio \
  -bios default -kernel "$KERNEL" \
  -device qemu-xhci,id=xhci \
  -device usb-kbd,id=kbd,bus=xhci.0 \
  -drive "if=none,id=stick,format=raw,file=$work/stick.raw,cache=writeback" \
  -device usb-storage,id=disk,bus=xhci.0,drive=stick \
  >/dev/null 2>&1

if grep -a -q '\[!\] panic' "$work/serial.log"; then
  echo "FAIL usb: guest panicked" >&2
  sed -n '/\[!\] panic/,+4p' "$work/serial.log" >&2
  exit 1
fi
grep -a -Eq 'pci +2 function\(s\).*MMIO 0x40000000\.\.0x80000000' "$work/serial.log"
grep -a -Eq 'usb +XHCI 0x0100 @ 0x40000000.*2 device\(s\)' "$work/serial.log"
grep -a -q 'USB STORAGE TEST OK (sector 7 read, sector 8 write/read)' "$work/serial.log"
grep -a -Eq 'mass-storage +16384 sectors' "$work/serial.log"
grep -a -q 'hid-keyboard' "$work/serial.log"

dd if=/dev/zero of="$work/expected" bs=512 count=1 >/dev/null 2>&1
printf '%s' "$WRITE" | dd of="$work/expected" bs=1 conv=notrunc >/dev/null 2>&1
dd if="$work/stick.raw" of="$work/observed" bs=512 skip=8 count=1 >/dev/null 2>&1
if ! cmp -s "$work/expected" "$work/observed"; then
  echo "FAIL usb: backing sector 8 did not retain the guest write" >&2
  exit 1
fi

echo "ok   usb (PCI BAR/INTx, XHCI, HID hotplug, BOT/SCSI backing I/O verified)"
