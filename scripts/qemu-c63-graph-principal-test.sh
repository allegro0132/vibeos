#!/bin/sh
# C6.3 two-node Component graph principal lifecycle acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C63_TIMEOUT=${C63_TIMEOUT:-60}
PASS_MARKER='WASM_C63_GRAPH_PRINCIPAL PASS nodes=2 runtime_unavailable=2 fuel_consumed=0 peak_slots=0 live_slots=0 registry_occupied=0 registry_header_mismatches=0'
FAIL_MARKER='WASM_C63_GRAPH_PRINCIPAL FAIL'

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
    echo 'FAIL qemu-c63-graph-principal-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c63-graph-principal-test: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 100 lines) ---' >&2
    tail -100 "$QEMU_LOG" >&2 || true
  fi
  exit 1
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$QEMU_SMP" in
  ''|*[!0-9]*|0) fail 'QEMU_SMP must be a positive integer' ;;
esac
case "$C63_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C63_TIMEOUT must be a positive integer' ;;
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
    --features wasm-c63-graph-principal-acceptance) >&2

"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C63_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!

remaining=$((C63_TIMEOUT * 10))
while [ "$remaining" -gt 0 ]; do
  if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
    fail 'guest reported lifecycle failure'
  fi
  if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
    fail 'guest reported a panic or fatal error'
  fi
  pass_count=$(grep -a -F -c "$PASS_MARKER" "$QEMU_LOG" || true)
  [ "$pass_count" -le 1 ] || fail 'guest published duplicate PASS markers'
  if [ "$pass_count" -eq 1 ]; then
    sleep 0.1
    if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
      fail 'guest reported lifecycle failure after PASS'
    fi
    if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
      fail 'guest reported a panic or fatal error after PASS'
    fi
    pass_count=$(grep -a -F -c "$PASS_MARKER" "$QEMU_LOG" || true)
    [ "$pass_count" -eq 1 ] || fail 'guest did not publish exactly one PASS marker'
    RESULT_REPORTED=1
    echo 'PASS qemu-c63-graph-principal-test: exact two-node lifecycle completed'
    exit 0
  fi
  kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited before publishing a result'
  sleep 0.1
  remaining=$((remaining - 1))
done

fail 'timed out waiting for the exact C6.3 marker'
