#!/bin/sh
# Same no_std adapter/configuration as the VibeOS trusted synchronous probe.
set -eu
timeout 60 systemctl is-system-running --wait || true
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
cp /mnt/coremark/wasi-custom /root/wasi-custom
cp /mnt/coremark/coremark.wasm /root/coremark.wasm
chmod +x /root/wasi-custom
{ uname -a; cat /proc/cpuinfo; sha256sum /root/wasi-custom /root/coremark.wasm; } > /mnt/results/environment.txt
for sample in performance-1 performance-2 performance-3 validation; do
    case "$sample" in validation) seeds='0x3415 0x3415 0x66';; *) seeds='0 0 0x66';; esac
    /root/wasi-custom /root/coremark.wasm $seeds 60000 < /dev/null > "/mnt/results/$sample.stdout" 2> "/mnt/results/$sample.stderr"
    cat "/mnt/results/$sample.stdout"
    grep -q 'Correct operation validated' "/mnt/results/$sample.stdout"
    awk '/Total time \(secs\)/ {if ($NF<10) exit 1; good=1} END {if (!good) exit 1}' "/mnt/results/$sample.stdout"
done
sync
