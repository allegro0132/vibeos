#!/bin/sh
# C6.7 semantic-only typed graph and policy-label diagnostic acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C67_TIMEOUT=${C67_TIMEOUT:-60}
C67_SMP1_TIMEOUT=${C67_SMP1_TIMEOUT:-5}
BEGIN_MARKER='WASM_C67_INFORMATION_FLOW BEGIN'
END_MARKER='WASM_C67_INFORMATION_FLOW END'
PASS_MARKER='WASM_C67_INFORMATION_FLOW PASS harts=4 nodes=3 edges=2 principal_policy_labels=3 typed_edges=2 async_edges=2 published=1 exact_render=1 negative_rejections=5 forbidden_classes=5 forbidden_hits=0 manifest_only=1 runtime_ready=0 guest_calls=0 registry_occupied=0 registry_header_mismatches=0'
FAIL_MARKER='WASM_C67_INFORMATION_FLOW FAIL'

TEST_TMP=$(mktemp -d)
QEMU_LOG="$TEST_TMP/qemu.log"
SMP1_LOG="$TEST_TMP/qemu-smp1.log"
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
  rm -f "$QEMU_LOG" "$SMP1_LOG"
  rmdir "$TEST_TMP" 2>/dev/null || true
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-c67-information-flow-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c67-information-flow-test: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 120 lines) ---' >&2
    tail -120 "$QEMU_LOG" >&2 || true
  fi
  if [ -s "$SMP1_LOG" ]; then
    echo '--- QEMU SMP1 transcript (last 80 lines) ---' >&2
    tail -80 "$SMP1_LOG" >&2 || true
  fi
  exit 1
}

count_exact() {
  log=$1
  marker=$2
  LC_ALL=C tr '\r' '\n' <"$log" |
    awk -v marker="$marker" '$0 == marker { count += 1 } END { print count + 0 }'
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C6.7 SMP gate'
case "$C67_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C67_TIMEOUT must be a positive integer' ;;
esac
case "$C67_SMP1_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C67_SMP1_TIMEOUT must be a positive integer' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

scripts/verify-c67-information-flow.py --selftest >&2

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

(cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release \
    --features wasm-c67-information-flow-acceptance) >&2

# The target report is intentionally a four-hart acceptance root. A one-hart
# boot must fail closed exactly once and must never publish a report block or PASS.
"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$SMP1_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C67_SMP1_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
wait "$KILLER_PID" 2>/dev/null || true
KILLER_PID=""
grep -a -F -q "$BEGIN_MARKER" "$SMP1_LOG" && fail 'single-hart boot contained BEGIN'
grep -a -F -q "$END_MARKER" "$SMP1_LOG" && fail 'single-hart boot contained END'
grep -a -F -q 'WASM_C67_INFORMATION_FLOW PASS' "$SMP1_LOG" && \
  fail 'single-hart boot contained PASS'
[ "$(count_exact "$SMP1_LOG" "$FAIL_MARKER")" -eq 1 ] || \
  fail 'single-hart boot did not fail closed exactly once'
if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$SMP1_LOG"; then
  fail 'single-hart boot reported a panic or fatal error'
fi

"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C67_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!

remaining=$((C67_TIMEOUT * 10))
while [ "$remaining" -gt 0 ]; do
  if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
    fail 'guest reported information-flow inspection failure'
  fi
  if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
    fail 'guest reported a panic or fatal error'
  fi
  pass_count=$(count_exact "$QEMU_LOG" "$PASS_MARKER")
  [ "$pass_count" -le 1 ] || fail 'guest published duplicate PASS markers'
  if [ "$pass_count" -eq 1 ]; then
    sleep 0.1
    if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
      fail 'guest reported information-flow failure after PASS'
    fi
    if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
      fail 'guest reported a panic or fatal error after PASS'
    fi
    [ "$(count_exact "$QEMU_LOG" "$BEGIN_MARKER")" -eq 1 ] || fail 'BEGIN count is not exactly one'
    [ "$(count_exact "$QEMU_LOG" "$END_MARKER")" -eq 1 ] || fail 'END count is not exactly one'
    [ "$(count_exact "$QEMU_LOG" "$PASS_MARKER")" -eq 1 ] || fail 'PASS count is not exactly one'
    scripts/verify-c67-information-flow.py --selftest "$QEMU_LOG" >&2 || \
      fail 'closed schema or exact golden verification failed'
    RESULT_REPORTED=1
    echo 'PASS qemu-c67-information-flow-test: exact semantic-only report completed'
    exit 0
  fi
  kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited before publishing a result'
  sleep 0.1
  remaining=$((remaining - 1))
done

fail 'timed out waiting for the exact C6.7 marker'
