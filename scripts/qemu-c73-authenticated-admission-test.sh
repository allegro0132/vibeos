#!/bin/sh
# C7.3 exact development-pin and detached operator-authentication acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C73_TIMEOUT=${C73_TIMEOUT:-60}
C73_SMP1_TIMEOUT=${C73_SMP1_TIMEOUT:-5}
PASS_MARKER='WASM_C73_AUTHENTICATED_ADMISSION PASS development_accepted=1 operator_p1_accepted=2 operator_p2_accepted=1 wrong_signer_rejected=1 unknown_signer_rejected=1 revoked_signer_rejected=1 old_policy_rejected=1 artifact_mutations_rejected=2 module_mutations_rejected=2 wit_mutations_rejected=2 adapter_mutations_rejected=2 limit_mutations_rejected=2 profile_mutations_rejected=2 signature_replays_rejected=2 content_hash_only_rejected=1 runtime_unavailable=4 runtime_ready=0 guest_calls=0 raw_ids=0'
FAIL_MARKER='WASM_C73_AUTHENTICATED_ADMISSION FAIL'

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
    echo 'FAIL qemu-c73-authenticated-admission-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c73-authenticated-admission-test: $*" >&2
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

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C7.3 SMP gate'
case "$C73_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C73_TIMEOUT must be a positive integer' ;;
esac
case "$C73_SMP1_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C73_SMP1_TIMEOUT must be a positive integer' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

scripts/verify-c73-authenticated-admission.py --selftest >&2

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

(cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --offline \
    --features wasm-c73-authenticated-admission-acceptance) >&2

# C7.3 is a four-hart acceptance root. A one-hart boot must publish exactly
# one closed failure and must never publish a successful authentication report.
"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$SMP1_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C73_SMP1_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
wait "$KILLER_PID" 2>/dev/null || true
KILLER_PID=""
grep -a -F -q 'WASM_C73_AUTHENTICATED_ADMISSION PASS' "$SMP1_LOG" && \
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
(sleep "$C73_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!

remaining=$((C73_TIMEOUT * 10))
while [ "$remaining" -gt 0 ]; do
  if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
    fail 'guest reported authenticated-admission failure'
  fi
  if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
    fail 'guest reported a panic or fatal error'
  fi
  pass_count=$(count_exact "$QEMU_LOG" "$PASS_MARKER")
  [ "$pass_count" -le 1 ] || fail 'guest published duplicate PASS markers'
  if [ "$pass_count" -eq 1 ]; then
    sleep 0.1
    [ "$(count_exact "$QEMU_LOG" "$PASS_MARKER")" -eq 1 ] || \
      fail 'PASS count changed after publication'
    grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG" && \
      fail 'guest reported failure after PASS'
    scripts/verify-c73-authenticated-admission.py --selftest "$QEMU_LOG" >&2 || \
      fail 'independent policy/signature or closed marker verification failed'
    RESULT_REPORTED=1
    echo 'PASS qemu-c73-authenticated-admission-test: exact authenticated admission report completed'
    exit 0
  fi
  kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited before publishing a result'
  sleep 0.1
  remaining=$((remaining - 1))
done

fail 'timed out waiting for the exact C7.3 marker'
