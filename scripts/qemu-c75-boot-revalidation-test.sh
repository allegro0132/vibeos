#!/bin/sh
# C7.5 fresh-validation-on-every-boot acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C75_TIMEOUT=${C75_TIMEOUT:-180}
C75_SMP1_TIMEOUT=${C75_SMP1_TIMEOUT:-10}
COMMON='physical_readback=1 fresh_component=1 fresh_core=1 fresh_wit=1 fresh_adapter_absence=1 fresh_hashes=1 fresh_limits=1 fresh_signer=1 fresh_engine_identity=1 publication_after_validation=1 early_runtime_objects=0 component_cspaces=0 component_resources=0 component_tasks=0 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0'
BOOT1_PASS="WASM_C75_BOOT_REVALIDATION PASS durable_state=installed image_candidate=1 preappend_validation=1 $COMMON"
BOOT2_PASS="WASM_C75_BOOT_REVALIDATION PASS durable_state=existing image_candidate=0 preappend_validation=0 $COMMON"
FAIL_MARKER='WASM_C75_BOOT_REVALIDATION FAIL'

TEST_TMP=$(mktemp -d)
BOOT1_LOG="$TEST_TMP/qemu-boot1.log"
BOOT2_LOG="$TEST_TMP/qemu-boot2.log"
QEMU_LOG="$BOOT1_LOG"
SMP1_LOG="$TEST_TMP/qemu-smp1.log"
DISK="$TEST_TMP/c75-storage-v2.raw"
POST_INSTALL_DISK="$TEST_TMP/c75-post-install.raw"
EVIDENCE="$TEST_TMP/c75-evidence.json"
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
  if [ "${KEEP_C75_EVIDENCE:-0}" = 1 ]; then
    echo "C7.5 evidence retained at $TEST_TMP" >&2
  else
    rm -rf -- "$TEST_TMP"
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-c75-boot-revalidation-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c75-boot-revalidation-test: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 180 lines) ---' >&2
    tail -180 "$QEMU_LOG" >&2 || true
  fi
  if [ -s "$SMP1_LOG" ]; then
    echo '--- QEMU SMP1 transcript (last 100 lines) ---' >&2
    tail -100 "$SMP1_LOG" >&2 || true
  fi
  exit 1
}

count_exact() {
  log=$1
  marker=$2
  LC_ALL=C tr '\r' '\n' <"$log" |
    awk -v marker="$marker" '$0 == marker { count += 1 } END { print count + 0 }'
}

stop_qemu() {
  if [ -n "$KILLER_PID" ]; then
    kill "$KILLER_PID" 2>/dev/null || true
    wait "$KILLER_PID" 2>/dev/null || true
    KILLER_PID=""
  fi
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
  fi
}

run_storage_v2_boot() {
  boot=$1
  expected=$2
  QEMU_LOG=$3
  echo "C7.5: Storage V2 boot $boot" >&2
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
    -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
    -drive if=none,id=c75-disk,format=raw,file="$DISK",cache=writeback \
    -device virtio-blk-device,drive=c75-disk,bus=virtio-mmio-bus.0,queue-size=8 \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  (sleep "$C75_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
  KILLER_PID=$!

  remaining=$((C75_TIMEOUT * 10))
  while [ "$remaining" -gt 0 ]; do
    if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
      fail "boot $boot reported revalidation failure"
    fi
    if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
      fail "boot $boot reported a panic or fatal error"
    fi
    pass_count=$(count_exact "$QEMU_LOG" "$expected")
    [ "$pass_count" -le 1 ] || fail "boot $boot published duplicate exact PASS markers"
    if [ "$pass_count" -eq 1 ]; then
      sleep 0.2
      [ "$(count_exact "$QEMU_LOG" "$expected")" -eq 1 ] || \
        fail "boot $boot exact PASS count changed after publication"
      [ "$(grep -a -F -c 'WASM_C75_BOOT_REVALIDATION PASS' "$QEMU_LOG" || true)" -eq 1 ] || \
        fail "boot $boot emitted a non-exact or duplicate PASS-family marker"
      grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG" && \
        fail "boot $boot reported failure after PASS"
      stop_qemu
      return 0
    fi
    kill -0 "$QEMU_PID" 2>/dev/null || fail "boot $boot exited before publishing a result"
    sleep 0.1
    remaining=$((remaining - 1))
  done
  fail "boot $boot timed out waiting for the exact C7.5 marker"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C7.5 gate'
case "$C75_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C75_TIMEOUT must be a positive integer' ;;
esac
case "$C75_SMP1_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C75_SMP1_TIMEOUT must be a positive integer' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

python3 -B scripts/verify-c75-boot-revalidation.py --selftest >&2

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

(cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --offline \
    --features wasm-c75-boot-revalidation-acceptance) >&2

# The C7.5 image is four-hart-only. A one-hart boot must fail before receiving
# a disk or consulting either current policy or an image installation fixture.
"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$SMP1_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C75_SMP1_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
wait "$KILLER_PID" 2>/dev/null || true
KILLER_PID=""
grep -a -F -q 'WASM_C75_BOOT_REVALIDATION PASS' "$SMP1_LOG" && \
  fail 'single-hart boot contained PASS'
[ "$(count_exact "$SMP1_LOG" "$FAIL_MARKER")" -eq 1 ] || \
  fail 'single-hart boot did not fail closed exactly once'
[ "$(grep -a -F -c 'WASM_C75_BOOT_REVALIDATION FAIL' "$SMP1_LOG" || true)" -eq 1 ] || \
  fail 'single-hart boot emitted a non-exact or duplicate FAIL-family marker'
if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$SMP1_LOG"; then
  fail 'single-hart boot reported a panic or fatal error'
fi

# Boot 1 probes the blank durable namespace before it is allowed to consult
# and prevalidate the image candidate. Both boots then converge on physical
# payload readback and current-policy/current-engine fresh validation. Boot 2
# must take the existing branch, use no candidate bytes, and leave every disk
# byte unchanged.
dd if=/dev/zero of="$DISK" bs=1m count=128 >/dev/null 2>&1
run_storage_v2_boot 1 "$BOOT1_PASS" "$BOOT1_LOG"
cp "$DISK" "$POST_INSTALL_DISK"
run_storage_v2_boot 2 "$BOOT2_PASS" "$BOOT2_LOG"
QEMU_LOG="$BOOT2_LOG"
cmp -s "$POST_INSTALL_DISK" "$DISK" || \
  fail 'cold existing boot mutated the already-committed Storage V2 image'
python3 -B scripts/verify-c75-boot-revalidation.py \
  "$DISK" --boot1-log "$BOOT1_LOG" --boot2-log "$BOOT2_LOG" >"$EVIDENCE" || \
  fail 'C7.5 powered-off/two-boot evidence verification failed'
grep -F -q '"status":"ok"' "$EVIDENCE" || \
  fail 'C7.5 verifier did not report exact success'
mkdir -p target
cp "$EVIDENCE" target/c75-boot-revalidation-verifier.json
RESULT_REPORTED=1
echo 'PASS qemu-c75-boot-revalidation-test: vacant install, cold durable recovery, fresh validation, no early runtime objects, and no-write boot 2 verified'
