#!/bin/sh
# C7.4 Storage V2 crash-safe Component publication acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C74_TIMEOUT=${C74_TIMEOUT:-180}
C74_SMP1_TIMEOUT=${C74_SMP1_TIMEOUT:-10}
PASS_MARKER='WASM_C74_CRASH_SAFE_PUBLICATION PASS evidence_committed=1 artifact_committed=1 root_committed=1 command_published=1 early_publications=0 durable_read=1 durable_grant=0 durable_invoke=0 component_tasks=0 runtime_ready=0 guest_calls=0 raw_ids=0 storage_v2_only=1 policy_v2=1 physical_readback=1'
FAIL_MARKER='WASM_C74_CRASH_SAFE_PUBLICATION FAIL'

TEST_TMP=$(mktemp -d)
BOOT1_LOG="$TEST_TMP/qemu-boot1.log"
BOOT2_LOG="$TEST_TMP/qemu-boot2.log"
QEMU_LOG="$BOOT1_LOG"
SMP1_LOG="$TEST_TMP/qemu-smp1.log"
DISK="$TEST_TMP/c74-storage-v2.raw"
POST_INSTALL_DISK="$TEST_TMP/c74-post-install.raw"
EVIDENCE="$TEST_TMP/powered-off.json"
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
  if [ "${KEEP_C74_EVIDENCE:-0}" = 1 ]; then
    echo "C7.4 evidence retained at $TEST_TMP" >&2
  else
    rm -rf -- "$TEST_TMP"
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-c74-crash-safe-publication-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c74-crash-safe-publication-test: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 160 lines) ---' >&2
    tail -160 "$QEMU_LOG" >&2 || true
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
  QEMU_LOG=$2
  echo "C7.4: Storage V2 boot $boot" >&2
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
    -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
    -drive if=none,id=c74-disk,format=raw,file="$DISK",cache=writeback \
    -device virtio-blk-device,drive=c74-disk,bus=virtio-mmio-bus.0,queue-size=8 \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  (sleep "$C74_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
  KILLER_PID=$!

  remaining=$((C74_TIMEOUT * 10))
  while [ "$remaining" -gt 0 ]; do
    if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
      fail "boot $boot reported crash-safe-publication failure"
    fi
    if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
      fail "boot $boot reported a panic or fatal error"
    fi
    pass_count=$(count_exact "$QEMU_LOG" "$PASS_MARKER")
    [ "$pass_count" -le 1 ] || fail "boot $boot published duplicate exact PASS markers"
    if [ "$pass_count" -eq 1 ]; then
      sleep 0.2
      [ "$(count_exact "$QEMU_LOG" "$PASS_MARKER")" -eq 1 ] || \
        fail "boot $boot exact PASS count changed after publication"
      [ "$(grep -a -F -c 'WASM_C74_CRASH_SAFE_PUBLICATION PASS' "$QEMU_LOG" || true)" -eq 1 ] || \
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

  fail "boot $boot timed out waiting for the exact C7.4 marker"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C7.4 gate'
case "$C74_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C74_TIMEOUT must be a positive integer' ;;
esac
case "$C74_SMP1_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C74_SMP1_TIMEOUT must be a positive integer' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

python3 -B scripts/verify-c74-crash-safe-publication.py --selftest >&2

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

(cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --offline \
    --features wasm-c74-crash-safe-publication-acceptance) >&2

# This image requires exactly four online harts. Without a disk, the one-hart
# boot must still close before touching any persistence path and report once.
"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$SMP1_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C74_SMP1_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
wait "$KILLER_PID" 2>/dev/null || true
KILLER_PID=""
grep -a -F -q 'WASM_C74_CRASH_SAFE_PUBLICATION PASS' "$SMP1_LOG" && \
  fail 'single-hart boot contained PASS'
[ "$(count_exact "$SMP1_LOG" "$FAIL_MARKER")" -eq 1 ] || \
  fail 'single-hart boot did not fail closed exactly once'
[ "$(grep -a -F -c 'WASM_C74_CRASH_SAFE_PUBLICATION FAIL' "$SMP1_LOG" || true)" -eq 1 ] || \
  fail 'single-hart boot emitted a non-exact or duplicate FAIL-family marker'
if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$SMP1_LOG"; then
  fail 'single-hart boot reported a panic or fatal error'
fi

# A blank image exercises native Storage V2 format with the exact policy-v2
# root. Boot 1 performs the sole append. Boot 2 cold-recovers the same media,
# revalidates the exact evidence attachment through the boot-compaction policy,
# and takes the installer's exact-existing/no-append branch. The image is
# inspected only after both QEMU processes have stopped.
dd if=/dev/zero of="$DISK" bs=1m count=128 >/dev/null 2>&1
run_storage_v2_boot 1 "$BOOT1_LOG"
cp "$DISK" "$POST_INSTALL_DISK"
run_storage_v2_boot 2 "$BOOT2_LOG"
QEMU_LOG="$BOOT2_LOG"
cmp -s "$POST_INSTALL_DISK" "$DISK" || \
  fail 'cold exact-existing boot mutated the already-committed Storage V2 image'
python3 -B scripts/verify-c74-crash-safe-publication.py "$DISK" >"$EVIDENCE" || \
  fail 'powered-off Storage V2 policy/signature verification failed'
grep -F -q '"status":"ok"' "$EVIDENCE" || \
  fail 'powered-off verifier did not report exact success'
mkdir -p target
cp "$EVIDENCE" target/c74-crash-safe-publication-verifier.json
RESULT_REPORTED=1
echo 'PASS qemu-c74-crash-safe-publication-test: install, cold exact-existing replay, and powered-off Storage V2 evidence verified'
