#!/bin/sh
# qrun.sh <seconds> -- run VibeOS, kill QEMU after N seconds.
# QEMU stays in the foreground so it keeps our stdin (the shell's input).
cd "$(dirname "$0")"
SECS=${1:-8}
( sleep "$SECS"; pkill -f 'qemu-system-riscv64.*vibeos-kernel' >/dev/null 2>&1 ) &
qemu-system-riscv64 -machine virt -cpu rv64 -smp 1 -m 128M -nographic \
  -bios default -kernel target/riscv64gc-unknown-none-elf/release/vibeos-kernel
exit 0
