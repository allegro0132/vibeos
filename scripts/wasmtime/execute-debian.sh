#!/bin/sh
# Run the no_std Wasmtime/custom-platform native execution tests on RV64 Linux.
# This isolates RISC-V code/ABI/trap behavior; it is not a VibeOS benchmark.
set -eu
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
cp /mnt/coremark/execute-custom /root/wasmtime-execute-custom
chmod +x /root/wasmtime-execute-custom
{ uname -a; sha256sum /root/wasmtime-execute-custom; } > /mnt/results/environment.txt
/root/wasmtime-execute-custom > /mnt/results/execute.stdout 2> /mnt/results/execute.stderr
sync
