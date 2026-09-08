#!/bin/sh
# Local QEMU WASI development image. Uses explicit public SSH test identities.
set -eu
cd "$(dirname "$0")/.."
work=${WASI_WORK_DIR:-target/wasi-qemu}
port=${WASI_SSH_PORT:-22222}
feature=wasi-ssh-upload
set -- -icount shift=0,align=off,sleep=off
memory=128M
harts=4
if [ "${WASI_BENCHMARK:-0}" = 1 ]; then
  feature=wasi-benchmark
  # Real virtual-clock progression, without instruction-count time dilation.
  set -- -rtc base=utc,clock=vm
  memory=1G
  harts=1
fi
mkdir -p "$work"
if [ "${WASI_SKIP_BUILD:-0}" != 1 ]; then
  (cd firmware/qemu-virt && cargo build --locked --offline --release --features "$feature")
fi
python3 - "$work" "$port" <<'PY'
import importlib.util, pathlib, sys
work=pathlib.Path(sys.argv[1])
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
peer=module('wasi_peer','scripts/openssh-peer.py')
peer.write_expected_known_hosts(work/'known_hosts','127.0.0.1',int(sys.argv[2]))
PY
if [ ! -f "$work/id_ed25519" ]; then
  python3 scripts/openssh-test-key.py --fixture accepted --output "$work/id_ed25519"
fi
if [ ! -f "$work/disk.raw" ]; then
  python3 - "$work/disk.raw" <<'PY'
import sys
with open(sys.argv[1],'xb') as f:f.truncate(128*1024*1024)
PY
fi
exec qemu-system-riscv64 \
  -machine virt -cpu rv64 -smp "$harts" -m "$memory" -accel tcg,thread=single \
  "$@" -nographic -bios default \
  -kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt \
  -object rng-random,id=wasi-rng,filename=/dev/urandom \
  -device virtio-rng-device,rng=wasi-rng,bus=virtio-mmio-bus.1 \
  -netdev "user,id=wasi-net,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:$port-10.0.2.15:2222" \
  -device virtio-net-device,netdev=wasi-net,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01 \
  -drive "if=none,id=wasi-disk,format=raw,file=$work/disk.raw,cache=writeback" \
  -device virtio-blk-device,drive=wasi-disk,bus=virtio-mmio-bus.2,queue-size=8 \
  -global virtio-mmio.force-legacy=false
