#!/bin/sh
# Build the dedicated TCP echo image and verify it through QEMU user networking.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-kernel
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
TCP_HOST_PORT=${TCP_HOST_PORT:-}
TCP_GUEST_PORT=2222
TCP_TIMEOUT=${TCP_TIMEOUT:-45}
TCP_PORT_ATTEMPTS=${TCP_PORT_ATTEMPTS:-3}

QEMU_PID=""
TEST_TMP=""
QEMU_LOG=""
RESULT_REPORTED=0

stop_qemu() {
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
  fi
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  stop_qemu
  if [ -n "$TEST_TMP" ]; then
    rm -f "$QEMU_LOG"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo "FAIL tcp-echo: test aborted unexpectedly" >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL tcp-echo: $*" >&2
  if [ -n "$QEMU_LOG" ] && [ -s "$QEMU_LOG" ]; then
    echo "--- QEMU transcript (last 80 lines) ---" >&2
    tail -80 "$QEMU_LOG" >&2 || true
  fi
  exit 1
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$QEMU_SMP" in
  ''|*[!0-9]*|0) fail "QEMU_SMP must be a positive integer" ;;
esac
case "$TCP_PORT_ATTEMPTS" in
  ''|*[!0-9]*|0) fail "TCP_PORT_ATTEMPTS must be a positive integer" ;;
esac
if [ -n "$TCP_HOST_PORT" ]; then
  case "$TCP_HOST_PORT" in
    ''|*[!0-9]*) fail "TCP_HOST_PORT must be an integer in the range 1..65535" ;;
  esac
  if [ "$TCP_HOST_PORT" -lt 1 ] || [ "$TCP_HOST_PORT" -gt 65535 ]; then
    fail "TCP_HOST_PORT must be an integer in the range 1..65535"
  fi
fi

for command in rustup python3 "$QEMU_BIN"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    fail "required command not found: $command"
  fi
done

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ]; then
  fail "rust-toolchain.toml must select an exact channel"
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate rustc for toolchain $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate rustdoc for toolchain $toolchain"

if ! python3 -B scripts/tcp-peer.py --selftest >/dev/null; then
  fail "host TCP peer self-test failed"
fi

echo "tcp-echo: building kernel feature tcp-echo"
if ! (cd kernel && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features tcp-echo) >&2; then
  fail "kernel build failed"
fi

TEST_TMP=$(mktemp -d) || fail "cannot create temporary directory"
QEMU_LOG="$TEST_TMP/qemu.log"

dynamic_port=1
if [ -n "$TCP_HOST_PORT" ]; then
  dynamic_port=0
fi

attempt=1
while [ "$attempt" -le "$TCP_PORT_ATTEMPTS" ]; do
  if [ "$dynamic_port" -eq 1 ]; then
    TCP_HOST_PORT=$(python3 -B scripts/tcp-peer.py --pick-port) \
      || fail "cannot select an unused loopback port"
  fi
  : > "$QEMU_LOG"

  echo "tcp-echo: starting QEMU (127.0.0.1:$TCP_HOST_PORT -> 10.0.2.15:$TCP_GUEST_PORT)"
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
    -accel "$QEMU_ACCEL" \
    -nographic -bios default -kernel "$KERNEL" \
    -netdev "user,id=vibeos-tcp,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${TCP_HOST_PORT}-10.0.2.15:${TCP_GUEST_PORT}" \
    -device "virtio-net-device,netdev=vibeos-tcp,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01" \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!

  # Port-selection and QEMU binding are separate operations.  If another
  # process wins that race, QEMU fails immediately and a fresh port is tried.
  sleep 0.25
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
    if [ "$dynamic_port" -eq 1 ] \
      && [ "$attempt" -lt "$TCP_PORT_ATTEMPTS" ] \
      && grep -a -qi 'could not set up host forwarding rule' "$QEMU_LOG"; then
      echo "tcp-echo: host port $TCP_HOST_PORT was claimed; retrying"
      attempt=$((attempt + 1))
      continue
    fi
    fail "QEMU exited before the guest listener became ready"
  fi

  echo "tcp-echo: waiting up to ${TCP_TIMEOUT}s for an exact byte-stream echo"
  if python3 -B scripts/tcp-peer.py \
    --port "$TCP_HOST_PORT" --timeout "$TCP_TIMEOUT"; then
    RESULT_REPORTED=1
    echo "PASS tcp-echo: exact echo through QEMU host forwarding"
    exit 0
  fi

  # A bind race can also surface between the initial liveness check and the
  # client attempt.  Only retry that diagnosed case; guest failures stay loud.
  if [ "$dynamic_port" -eq 1 ] \
    && [ "$attempt" -lt "$TCP_PORT_ATTEMPTS" ] \
    && ! kill -0 "$QEMU_PID" 2>/dev/null \
    && grep -a -qi 'could not set up host forwarding rule' "$QEMU_LOG"; then
    stop_qemu
    echo "tcp-echo: host port $TCP_HOST_PORT was claimed; retrying"
    attempt=$((attempt + 1))
    continue
  fi
  fail "guest did not return the deterministic payload exactly"
done

fail "could not bind a loopback host-forward port after $TCP_PORT_ATTEMPTS attempts"
