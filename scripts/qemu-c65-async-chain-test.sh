#!/bin/sh
# C6.5 three-node async wake/backpressure/cancellation acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C65_TIMEOUT=${C65_TIMEOUT:-60}
PASS_MARKER='WASM_C65_ASYNC_CHAIN PASS nodes=3 internal_edges=2 host_deliveries=2 causes=backend-fault,cancelled cascades=2 consumer_first=2 no_active_poll=1 lost_wakes=0 guest_calls=0 runtime_ready=0 fuel_consumed=0 peak_depths=8,8,8 registry_occupied=0 registry_header_mismatches=0'
FAIL_MARKER='WASM_C65_ASYNC_CHAIN FAIL'

TEST_TMP=$(mktemp -d)
QEMU_LOG="$TEST_TMP/qemu.log"
QEMU_PID=""
KILLER_PID=""
RESULT_REPORTED=0

# shellcheck disable=SC2329  # Invoked by the EXIT/signal trap.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$KILLER_PID" ]; then
    kill "$KILLER_PID" 2>/dev/null || true
    wait "$KILLER_PID" 2>/dev/null || true
  fi
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  rm -f "$QEMU_LOG"
  rmdir "$TEST_TMP" 2>/dev/null || true
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-c65-async-chain-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c65-async-chain-test: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 100 lines) ---' >&2
    tail -100 "$QEMU_LOG" >&2 || true
  fi
  exit 1
}

count_exact_pass() {
  LC_ALL=C tr '\r' '\n' <"$QEMU_LOG" |
    awk -v marker="$PASS_MARKER" '
      BEGIN { clear_line = sprintf("%c", 27) "[2K" }
      $0 == marker || $0 == clear_line marker { count += 1 }
      END { print count + 0 }
    '
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C6.5 SMP gate'
case "$C65_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C65_TIMEOUT must be a positive integer' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

(cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release \
    --features wasm-c65-async-chain-acceptance) >&2

"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C65_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!

remaining=$((C65_TIMEOUT * 10))
while [ "$remaining" -gt 0 ]; do
  if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
    fail 'guest reported async-chain lifecycle failure'
  fi
  if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
    fail 'guest reported a panic or fatal error'
  fi
  pass_count=$(count_exact_pass)
  [ "$pass_count" -le 1 ] || fail 'guest published duplicate PASS markers'
  if [ "$pass_count" -eq 1 ]; then
    sleep 0.1
    if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
      fail 'guest reported async-chain failure after PASS'
    fi
    if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
      fail 'guest reported a panic or fatal error after PASS'
    fi
    pass_count=$(count_exact_pass)
    [ "$pass_count" -eq 1 ] || fail 'guest did not publish exactly one PASS marker'
    RESULT_REPORTED=1
    echo 'PASS qemu-c65-async-chain-test: exact wake/backpressure/cause propagation completed'
    exit 0
  fi
  kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited before publishing a result'
  sleep 0.1
  remaining=$((remaining - 1))
done

fail 'timed out waiting for the exact C6.5 marker'
