#!/bin/sh
# Requires an already provisioned Debian measurement overlay; no network setup.
set -eu
timeout 60 systemctl is-system-running --wait || true
mountpoint -q /mnt/coremark || mount -t 9p -o trans=virtio,version=9p2000.L,ro coremark /mnt/coremark
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
command -v cc > /mnt/results/compiler-path.txt
mkdir -p /root/coremark
cp -r /mnt/coremark/source/. /root/coremark/
cd /root/coremark
cc -O3 -DITERATIONS=1 '-DFLAGS_STR="-O3 -DITERATIONS=1"' '-DMEM_LOCATION="Debian process memory"' -I. -Iposix core_list_join.c core_main.c core_matrix.c core_state.c core_util.c posix/core_portme.c -o coremark
{ uname -a; cat /etc/os-release; cc --version; lscpu; sha256sum coremark; sha256sum *.c *.h posix/core_portme.*; dpkg-query -W gcc gcc-14 libc6 libc6-dev linux-image-riscv64; } > /mnt/results/environment.txt
./coremark 0 0 0x66 1000 > /mnt/results/calibration.stdout
seconds=$(awk '/Total time \(secs\)/ {print $NF}' /mnt/results/calibration.stdout)
iterations=$(awk -v t="$seconds" 'BEGIN {if (t<=0) exit 1; printf "%d\n", (20000/t)+1}')
for sample in performance-1 performance-2 performance-3 validation; do
  case "$sample" in validation) seeds='0x3415 0x3415 0x66';; *) seeds='0 0 0x66';; esac
  ./coremark $seeds "$iterations" > "/mnt/results/$sample.stdout" 2> "/mnt/results/$sample.stderr"
  cat "/mnt/results/$sample.stdout"
  grep -q 'Correct operation validated' "/mnt/results/$sample.stdout"
  awk '/Total time \(secs\)/ {if ($NF<10) exit 1; good=1} END {if (!good) exit 1}' "/mnt/results/$sample.stdout"
done
sync
