#!/bin/sh
# C7.6 durable three-boot graph-version replacement acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C76_TIMEOUT=${C76_TIMEOUT:-240}
C76_SMP1_TIMEOUT=${C76_SMP1_TIMEOUT:-10}
COMMON='runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0'
BOOT1_PASS="WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=installed_g0 versions=1 replacements=0 image_candidate=1 physical_readback=1 fresh_graphs=1 current_visible=1 candidate_runtime_objects=0 $COMMON"
BOOT2_PASS="WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=replaced_g1 versions=2 replacements=1 image_candidate=1 durable_before_candidate=1 physical_readback=1 fresh_graphs=2 policy_cancel=1 candidate_hidden=1 old_terminal_before_new_visible=1 siblings_stable=2 sibling_restarts=0 old_routes_retired=2 fresh_routes=2 stale_replacement_tokens=2 late_wake_stale=1 visibility_linearizations=1 mixed_versions=0 fail_stop_armed=1 $COMMON"
BOOT3_PASS="WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=existing_g1 versions=2 replacements=1 image_candidate=0 no_write=1 physical_readback=1 fresh_graphs=2 successor_visible=1 candidate_runtime_objects=0 $COMMON"
FAIL_MARKER='WASM_C76_GRAPH_VERSION_REPLACEMENT FAIL'

TEST_TMP=$(mktemp -d)
BOOT1_LOG="$TEST_TMP/qemu-boot1.log"
BOOT2_LOG="$TEST_TMP/qemu-boot2.log"
BOOT3_LOG="$TEST_TMP/qemu-boot3.log"
QEMU_LOG="$BOOT1_LOG"
SMP1_LOG="$TEST_TMP/qemu-smp1.log"
DISK="$TEST_TMP/c76-storage-v3.raw"
G0_DISK="$TEST_TMP/c76-post-g0.raw"
G1_DISK="$TEST_TMP/c76-post-g1.raw"
EVIDENCE="$TEST_TMP/c76-evidence.json"
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
  if [ "${KEEP_C76_EVIDENCE:-0}" = 1 ]; then
    echo "C7.6 evidence retained at $TEST_TMP" >&2
  else
    rm -rf -- "$TEST_TMP"
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-test-c76-graph-version-replacement: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-test-c76-graph-version-replacement: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 220 lines) ---' >&2
    tail -220 "$QEMU_LOG" >&2 || true
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

run_storage_v3_boot() {
  boot=$1
  expected=$2
  QEMU_LOG=$3
  echo "C7.6: Storage V3 boot $boot" >&2
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
    -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
    -drive if=none,id=c76-disk,format=raw,file="$DISK",cache=writeback \
    -device virtio-blk-device,drive=c76-disk,bus=virtio-mmio-bus.0,queue-size=8 \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  (sleep "$C76_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
  KILLER_PID=$!

  remaining=$((C76_TIMEOUT * 10))
  while [ "$remaining" -gt 0 ]; do
    if grep -a -F -q "$FAIL_MARKER" "$QEMU_LOG"; then
      fail "boot $boot reported graph-version replacement failure"
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
      [ "$(grep -a -F -c 'WASM_C76_GRAPH_VERSION_REPLACEMENT PASS' "$QEMU_LOG" || true)" -eq 1 ] || \
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
  fail "boot $boot timed out waiting for the exact C7.6 marker"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C7.6 gate'
case "$C76_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C76_TIMEOUT must be a positive integer' ;;
esac
case "$C76_SMP1_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C76_SMP1_TIMEOUT must be a positive integer' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

python3 -B scripts/verify-c76-graph-version-replacement.py --selftest >&2

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

(cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --offline \
    --features wasm-c76-graph-version-replacement-acceptance) >&2

# The fixed graph lifecycle is a four-hart gate. A one-hart boot receives no
# disk and must fail before image lookup or any persistence operation.
"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
  </dev/null >"$SMP1_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C76_SMP1_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
wait "$KILLER_PID" 2>/dev/null || true
KILLER_PID=""
grep -a -F -q 'WASM_C76_GRAPH_VERSION_REPLACEMENT PASS' "$SMP1_LOG" && \
  fail 'single-hart boot contained PASS'
[ "$(count_exact "$SMP1_LOG" "$FAIL_MARKER")" -eq 1 ] || \
  fail 'single-hart boot did not fail closed exactly once'
[ "$(grep -a -F -c 'WASM_C76_GRAPH_VERSION_REPLACEMENT FAIL' "$SMP1_LOG" || true)" -eq 1 ] || \
  fail 'single-hart boot emitted a non-exact or duplicate FAIL-family marker'
if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$SMP1_LOG"; then
  fail 'single-hart boot reported a panic or fatal error'
fi

# One disk crosses three cold boots. Boot 1 appends complete G0, boot 2 appends
# complete G1 plus the tombstone-first same-slot root transition, and boot 3
# physically revalidates G0/G1 without consulting image bytes or writing.
dd if=/dev/zero of="$DISK" bs=1m count=128 >/dev/null 2>&1
run_storage_v3_boot 1 "$BOOT1_PASS" "$BOOT1_LOG"
cp "$DISK" "$G0_DISK"
run_storage_v3_boot 2 "$BOOT2_PASS" "$BOOT2_LOG"
QEMU_LOG="$BOOT2_LOG"
if cmp -s "$G0_DISK" "$DISK"; then
  fail 'replacement boot did not change the committed G0 disk'
fi
cp "$DISK" "$G1_DISK"
run_storage_v3_boot 3 "$BOOT3_PASS" "$BOOT3_LOG"
QEMU_LOG="$BOOT3_LOG"
cmp -s "$G1_DISK" "$DISK" || \
  fail 'cold G1 recovery mutated the already-committed Storage V3 image'

python3 -B scripts/verify-c76-graph-version-replacement.py \
  "$DISK" \
  --g0-image "$G0_DISK" \
  --g1-image "$G1_DISK" \
  --boot1-log "$BOOT1_LOG" \
  --boot2-log "$BOOT2_LOG" \
  --boot3-log "$BOOT3_LOG" >"$EVIDENCE" || \
  fail 'C7.6 independent powered-off/three-boot verification failed'
grep -F -q '"status":"ok"' "$EVIDENCE" || \
  fail 'C7.6 verifier did not report exact success'
grep -F -q '"c78_independent_disk_scope":false' "$EVIDENCE" || \
  fail 'C7.6 verifier claimed the reserved C7.8 disk scope'
grep -F -q '"runtime_ready":false' "$EVIDENCE" || \
  fail 'C7.6 verifier did not keep runtime_ready=false'
grep -F -q '"guest_calls":0' "$EVIDENCE" || \
  fail 'C7.6 verifier did not keep guest_calls=0'
grep -F -q '"raw_ids":0' "$EVIDENCE" || \
  fail 'C7.6 verifier did not keep raw_ids=0'
grep -F -q '"ambient_lookup":0' "$EVIDENCE" || \
  fail 'C7.6 verifier did not keep ambient_lookup=0'
grep -F -q '"vsh":0' "$EVIDENCE" || \
  fail 'C7.6 verifier did not keep vsh=0'
grep -F -q '"mixed_versions":0' "$EVIDENCE" || \
  fail 'C7.6 verifier did not prove mixed_versions=0'
grep -F -q '"retirement_action":"PolicyCancel"' "$EVIDENCE" || \
  fail 'C7.6 verifier did not prove PolicyCancel'
grep -F -q '"old_terminal_before_new_visible":true' "$EVIDENCE" || \
  fail 'C7.6 verifier did not prove old-terminal-before-new-visible'
mkdir -p target
cp "$EVIDENCE" target/c76-graph-version-replacement-verifier.json
RESULT_REPORTED=1
echo 'PASS qemu-test-c76-graph-version-replacement: G0 install, G1 replacement, cold no-write G1 recovery, exact V3 history, and lifecycle isolation verified'
