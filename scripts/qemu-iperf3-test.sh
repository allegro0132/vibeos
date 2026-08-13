#!/bin/sh
# Build the bounded iperf3 server image and validate it with the host client.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
IPERF3_BIN=${IPERF3_BIN:-iperf3}
IPERF3_HOST_PORT=${IPERF3_HOST_PORT:-}
IPERF3_SECONDS=${IPERF3_SECONDS:-1}
IPERF3_TIMEOUT=${IPERF3_TIMEOUT:-45}

QEMU_PID=""
TEST_TMP=""
QEMU_INPUT=""

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  exec 3>&-
  if [ -n "$TEST_TMP" ]; then
    rm -f "$TEST_TMP/qemu.log" "$TEST_TMP/forward.json" "$TEST_TMP/reverse.json" "$QEMU_INPUT"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  exit "$status"
}

fail() {
  echo "FAIL iperf3-server: $*" >&2
  if [ -n "$TEST_TMP" ] && [ -s "$TEST_TMP/forward.json" ]; then
    echo "--- forward iperf3 result ---" >&2
    cat "$TEST_TMP/forward.json" >&2
  fi
  if [ -n "$TEST_TMP" ] && [ -s "$TEST_TMP/reverse.json" ]; then
    echo "--- reverse iperf3 result ---" >&2
    cat "$TEST_TMP/reverse.json" >&2
  fi
  if [ -n "$TEST_TMP" ] && [ -s "$TEST_TMP/qemu.log" ]; then
    tail -80 "$TEST_TMP/qemu.log" >&2 || true
  fi
  exit 1
}

run_iperf() {
  output=$1
  shift
  "$IPERF3_BIN" "$@" >"$output" 2>&1 &
  client_pid=$!
  ticks=0
  while kill -0 "$client_pid" 2>/dev/null && [ "$ticks" -lt 150 ]; do
    sleep 0.1
    ticks=$((ticks + 1))
  done
  if kill -0 "$client_pid" 2>/dev/null; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
    return 1
  fi
  wait "$client_pid"
}

validate_received_bytes() {
  python3 -B -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["end"]["sum_received"]["bytes"] > 0' "$1"
}

for command in rustup python3 "$QEMU_BIN" "$IPERF3_BIN"; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail "rust-toolchain.toml must select an exact channel"
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) || fail "cannot locate rustc"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) || fail "cannot locate rustdoc"

echo "iperf3-server: building QEMU image"
(cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --no-default-features --features iperf3-server) \
  || fail "kernel build failed"

TEST_TMP=$(mktemp -d) || fail "cannot create temporary directory"
QEMU_INPUT="$TEST_TMP/qemu-input"
mkfifo "$QEMU_INPUT" || fail "cannot create QEMU input FIFO"
exec 3<>"$QEMU_INPUT"

if [ -z "$IPERF3_HOST_PORT" ]; then
  IPERF3_HOST_PORT=$(python3 -B scripts/tcp-peer.py --pick-port) \
    || fail "cannot select an unused loopback port"
fi

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 4 -m 128M -accel tcg,thread=multi \
  -nographic -bios default -kernel "$KERNEL" \
  -netdev "user,id=vibeos-iperf,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${IPERF3_HOST_PORT}-10.0.2.15:5201" \
  -device "virtio-net-device,netdev=vibeos-iperf,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01" \
  -global virtio-mmio.force-legacy=false \
  <&3 >"$TEST_TMP/qemu.log" 2>&1 &
QEMU_PID=$!

attempt=0
sleep 2
while [ "$attempt" -lt "$IPERF3_TIMEOUT" ]; do
  if run_iperf "$TEST_TMP/forward.json" \
      -c 127.0.0.1 -p "$IPERF3_HOST_PORT" -t "$IPERF3_SECONDS" \
      --connect-timeout 1000 --json; then
    break
  fi
  kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU exited before the listener became ready"
  sleep 1
  attempt=$((attempt + 1))
done
[ "$attempt" -lt "$IPERF3_TIMEOUT" ] || fail "forward test did not complete"
validate_received_bytes "$TEST_TMP/forward.json" \
  || fail "forward result did not report received bytes"

attempt=0
while [ "$attempt" -lt 10 ]; do
  if run_iperf "$TEST_TMP/reverse.json" \
      -c 127.0.0.1 -p "$IPERF3_HOST_PORT" -t "$IPERF3_SECONDS" \
      --connect-timeout 1000 -R --json; then
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done
[ "$attempt" -lt 10 ] || fail "reverse test did not complete"
validate_received_bytes "$TEST_TMP/reverse.json" \
  || fail "reverse result did not report received bytes"

echo "PASS iperf3-server: host iperf3 completed forward and reverse TCP tests"
