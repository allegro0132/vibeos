#!/bin/sh
# Both profiles use GC, speed, 100 billion fuel, max stack 32 KiB, no COW.
# Only the explicit/movable vs guarded/fixed memory and trap configuration differs.
set -eu
timeout 60 systemctl is-system-running --wait || true
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
cp /mnt/coremark/wasmtime-vm-control /root/wasmtime-vm-control
cp /mnt/coremark/coremark.wasm /root/coremark.wasm
chmod +x /root/wasmtime-vm-control
{ uname -a; cat /proc/cpuinfo; sha256sum /root/wasmtime-vm-control /root/coremark.wasm; } > /mnt/results/environment.txt
for sample in performance-1 performance-2 performance-3 validation; do
    case "$sample" in validation) seeds='0x3415 0x3415 0x66';; *) seeds='0 0 0x66';; esac
    for profile in explicit-gc guards-gc; do
        /root/wasmtime-vm-control --fuel --profile "$profile" /root/coremark.wasm $seeds 60000 < /dev/null > "/mnt/results/$profile-$sample.stdout" 2> "/mnt/results/$profile-$sample.stderr"
        cat "/mnt/results/$profile-$sample.stdout"
        grep -q 'Correct operation validated' "/mnt/results/$profile-$sample.stdout"
        awk '/Total time \(secs\)/ {if ($NF<10) exit 1; good=1} END {if (!good) exit 1}' "/mnt/results/$profile-$sample.stdout"
    done
done
sync
