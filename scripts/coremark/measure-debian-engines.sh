#!/bin/sh
# Inputs: identical coremark.wasm, the two RV64 runners, original CoreMark source.
set -eu
timeout 60 systemctl is-system-running --wait || true
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
mkdir -p /root/coremark-engines
cp -r /mnt/coremark/source/. /root/coremark-engines/
cp /mnt/coremark/wasmi /mnt/coremark/wasmtime /mnt/coremark/coremark.wasm /root/coremark-engines/
cd /root/coremark-engines
chmod +x wasmi wasmtime
cc -O3 -DITERATIONS=1 '-DFLAGS_STR="-O3 -DITERATIONS=1"' '-DMEM_LOCATION="Debian process memory"' -I. -Iposix core_list_join.c core_main.c core_matrix.c core_state.c core_util.c posix/core_portme.c -o coremark
{ uname -a; cat /etc/os-release; cc --version; lscpu; sha256sum coremark coremark.wasm wasmi wasmtime; dpkg-query -W gcc libc6 libc6-dev; } > /mnt/results/measurement-environment.txt
run() {
  mode=$1; shift
  case "$mode" in
    native) /usr/bin/time -v ./coremark "$@";;
    wasmi) /usr/bin/time -v ./wasmi coremark.wasm "$@";;
    wasmtime) /usr/bin/time -v ./wasmtime coremark.wasm "$@";;
    wasmtime-fuel) /usr/bin/time -v ./wasmtime --fuel coremark.wasm "$@";;
  esac
}
for mode in ${COREMARK_MODES:-native wasmi wasmtime wasmtime-fuel}; do
  run "$mode" 0 0 0x66 1000 > "/mnt/results/$mode-calibration.stdout" 2> "/mnt/results/$mode-calibration.stderr"
  seconds=$(awk '/Total time \(secs\)/ {print $NF}' "/mnt/results/$mode-calibration.stdout")
  awk -v t="$seconds" 'BEGIN {if (t<=0) exit 1; printf "%d\n", (25000/t)+1}' > "/mnt/results/$mode-iterations"
done
# Interleave engines; avoid measuring during package installation or compilation.
for sample in performance-1 performance-2 performance-3 validation; do
  case "$sample" in validation) seeds='0x3415 0x3415 0x66';; *) seeds='0 0 0x66';; esac
  for mode in ${COREMARK_MODES:-native wasmi wasmtime wasmtime-fuel}; do
    iterations=$(cat "/mnt/results/$mode-iterations")
    run "$mode" $seeds "$iterations" > "/mnt/results/$mode-$sample.stdout" 2> "/mnt/results/$mode-$sample.stderr"
    cat "/mnt/results/$mode-$sample.stdout"
    grep -q 'Correct operation validated' "/mnt/results/$mode-$sample.stdout"
    awk '/Total time \(secs\)/ {if ($NF<10) exit 1; good=1} END {if (!good) exit 1}' "/mnt/results/$mode-$sample.stdout"
  done
done
sync
