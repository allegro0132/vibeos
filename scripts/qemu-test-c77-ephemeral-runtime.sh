#!/bin/sh
# C7.7 exact-C7.6-G1 seed plus two cold no-write ephemeral-runtime boots.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
C76_TIMEOUT=${C76_TIMEOUT:-240}
C77_TIMEOUT=${C77_TIMEOUT:-240}
C77_CAPTURE_ONLY=${C77_CAPTURE_ONLY:-0}

C76_COMMON='runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0'
C76_BOOT1_PASS="WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=installed_g0 versions=1 replacements=0 image_candidate=1 physical_readback=1 fresh_graphs=1 current_visible=1 candidate_runtime_objects=0 $C76_COMMON"
C76_BOOT2_PASS="WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=replaced_g1 versions=2 replacements=1 image_candidate=1 durable_before_candidate=1 physical_readback=1 fresh_graphs=2 policy_cancel=1 candidate_hidden=1 old_terminal_before_new_visible=1 siblings_stable=2 sibling_restarts=0 old_routes_retired=2 fresh_routes=2 stale_replacement_tokens=2 late_wake_stale=1 visibility_linearizations=1 mixed_versions=0 fail_stop_armed=1 $C76_COMMON"
C76_BOOT3_PASS="WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=existing_g1 versions=2 replacements=1 image_candidate=0 no_write=1 physical_readback=1 fresh_graphs=2 successor_visible=1 candidate_runtime_objects=0 $C76_COMMON"
C76_FAIL='WASM_C76_GRAPH_VERSION_REPLACEMENT FAIL'
C76_FAMILY='WASM_C76_GRAPH_VERSION_REPLACEMENT'

# Expected C7.7 marker/API. Keep this string byte-identical to C77_PASS in the
# host verifier when the Rust mainline surface is connected.
C77_COMMON='durable_state=existing_g1 graph_only=1 physical_readback=1 fresh_validation=1 same_manifest=1 cold_start_empty=1 fresh_tasks=3 fresh_arenas=3 fresh_cspaces=3 fresh_memories=3 memory_bytes=196608 fresh_resource_tables=3 live_resources=4 fresh_fuel_accounts=3 fuel_consumed=0 fresh_pending_ledgers=3 active_pending_calls=1 pending_cut=parked cold_no_write=1 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0'
C77_PASS="WASM_C77_EPHEMERAL_RUNTIME PASS $C77_COMMON"
C77_FAIL='WASM_C77_EPHEMERAL_RUNTIME FAIL'
C77_FAMILY='WASM_C77_EPHEMERAL_RUNTIME'

if [ -n "${C77_EVIDENCE_DIR:-}" ]; then
  TEST_TMP=$C77_EVIDENCE_DIR
  if [ -L "$TEST_TMP" ]; then
    echo 'FAIL qemu-test-c77-ephemeral-runtime: C77_EVIDENCE_DIR must not be a symlink' >&2
    exit 1
  fi
  if [ -e "$TEST_TMP" ]; then
    if [ ! -d "$TEST_TMP" ]; then
      echo 'FAIL qemu-test-c77-ephemeral-runtime: C77_EVIDENCE_DIR is not a directory' >&2
      exit 1
    fi
    if [ -n "$(find "$TEST_TMP" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      echo 'FAIL qemu-test-c77-ephemeral-runtime: C77_EVIDENCE_DIR must be empty' >&2
      exit 1
    fi
  else
    mkdir -p "$TEST_TMP"
    if [ -L "$TEST_TMP" ]; then
      echo 'FAIL qemu-test-c77-ephemeral-runtime: C77_EVIDENCE_DIR resolved to a symlink' >&2
      exit 1
    fi
  fi
  TEST_TMP_OWNED=0
else
  TEST_TMP=$(mktemp -d)
  TEST_TMP_OWNED=1
fi
DISK="$TEST_TMP/c77-storage-v3.raw"
C76_G0_DISK="$TEST_TMP/c76-post-g0.raw"
C76_G1_DISK="$TEST_TMP/c76-post-g1.raw"
SEED_DISK="$TEST_TMP/c76-post-cold-g1.raw"
C77_COLD1_DISK="$TEST_TMP/c77-post-cold1.raw"
C76_BOOT1_LOG="$TEST_TMP/c76-boot1.log"
C76_BOOT2_LOG="$TEST_TMP/c76-boot2.log"
C76_BOOT3_LOG="$TEST_TMP/c76-boot3.log"
C77_BOOT1_LOG="$TEST_TMP/c77-boot1.log"
C77_BOOT2_LOG="$TEST_TMP/c77-boot2.log"
SEED_EVIDENCE="$TEST_TMP/c76-seed-evidence.json"
EVIDENCE="$TEST_TMP/c77-evidence.json"
QEMU_LOG="$C76_BOOT1_LOG"
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
  if [ "${KEEP_C77_EVIDENCE:-0}" = 1 ] || [ "$TEST_TMP_OWNED" -eq 0 ]; then
    echo "C7.7 evidence retained at $TEST_TMP" >&2
  else
    rm -rf -- "$TEST_TMP"
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-test-c77-ephemeral-runtime: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-test-c77-ephemeral-runtime: $*" >&2
  if [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU transcript (last 240 lines) ---' >&2
    tail -240 "$QEMU_LOG" >&2 || true
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

run_boot() {
  label=$1
  expected=$2
  fail_marker=$3
  family=$4
  timeout=$5
  QEMU_LOG=$6
  echo "$label" >&2
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
    -accel "$QEMU_ACCEL" -nographic -bios default -kernel "$KERNEL" \
    -drive if=none,id=c77-disk,format=raw,file="$DISK",cache=writeback \
    -device virtio-blk-device,drive=c77-disk,bus=virtio-mmio-bus.0,queue-size=8 \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  (sleep "$timeout"; kill "$QEMU_PID" 2>/dev/null || true) &
  KILLER_PID=$!

  remaining=$((timeout * 10))
  while [ "$remaining" -gt 0 ]; do
    if grep -a -F -q "$fail_marker" "$QEMU_LOG"; then
      fail "$label reported FAIL"
    fi
    if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
      fail "$label reported a panic or fatal error"
    fi
    pass_count=$(count_exact "$QEMU_LOG" "$expected")
    [ "$pass_count" -le 1 ] || fail "$label published duplicate exact PASS markers"
    if [ "$pass_count" -eq 1 ]; then
      sleep 0.2
      [ "$(count_exact "$QEMU_LOG" "$expected")" -eq 1 ] || \
        fail "$label exact PASS count changed after publication"
      [ "$(grep -a -F -c "$family PASS" "$QEMU_LOG" || true)" -eq 1 ] || \
        fail "$label emitted a non-exact or duplicate PASS-family marker"
      grep -a -F -q "$fail_marker" "$QEMU_LOG" && \
        fail "$label reported failure after PASS"
      stop_qemu
      return 0
    fi
    kill -0 "$QEMU_PID" 2>/dev/null || fail "$label exited before publishing a result"
    sleep 0.1
    remaining=$((remaining - 1))
  done
  fail "$label timed out waiting for its exact marker"
}

build_acceptance() {
  feature=$1
  echo "C7.7: building $feature" >&2
  (cd firmware/qemu-virt && \
    RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
    rustup run "$toolchain" cargo build --release --locked --offline \
      --features "$feature") >&2
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ "$QEMU_SMP" = 4 ] || fail 'QEMU_SMP must be exactly 4 for the C7.7 gate'
case "$C76_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C76_TIMEOUT must be a positive integer' ;;
esac
case "$C77_TIMEOUT" in
  ''|*[!0-9]*|0) fail 'C77_TIMEOUT must be a positive integer' ;;
esac
case "$C77_CAPTURE_ONLY" in
  0|1) ;;
  *) fail 'C77_CAPTURE_ONLY must be 0 or 1' ;;
esac
command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "QEMU binary not found: $QEMU_BIN"

# Includes the complete C7.6 mutation suite plus C7.7 marker/token/no-write
# mutations. It imports no production Rust and writes no pycache.
if [ "$C77_CAPTURE_ONLY" -eq 0 ]; then
  python3 -B scripts/verify-c77-ephemeral-runtime.py --selftest >&2
fi

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)

# Seed only through the real C7.6 image: G0 install, G1 replacement, then one
# cold ExistingG1 boot. The ordinary C7.7 gate requires the narrow C7.6
# fixed-vector verdict before the C7.7 kernel runs. C7.8 uses capture-only
# mode: it records these same real boots but leaves all disk/content verdicts
# to the independent C7.8 parser.
build_acceptance wasm-c76-graph-version-replacement-acceptance
dd if=/dev/zero of="$DISK" bs=1m count=128 >/dev/null 2>&1
run_boot 'C7.7 seed: C7.6 boot 1' "$C76_BOOT1_PASS" "$C76_FAIL" \
  "$C76_FAMILY" "$C76_TIMEOUT" "$C76_BOOT1_LOG"
cp "$DISK" "$C76_G0_DISK"
run_boot 'C7.7 seed: C7.6 boot 2' "$C76_BOOT2_PASS" "$C76_FAIL" \
  "$C76_FAMILY" "$C76_TIMEOUT" "$C76_BOOT2_LOG"
cp "$DISK" "$C76_G1_DISK"
run_boot 'C7.7 seed: C7.6 boot 3' "$C76_BOOT3_PASS" "$C76_FAIL" \
  "$C76_FAMILY" "$C76_TIMEOUT" "$C76_BOOT3_LOG"
if [ "$C77_CAPTURE_ONLY" -eq 0 ]; then
  cmp -s "$C76_G1_DISK" "$DISK" || \
    fail 'C7.6 cold seed boot changed the committed G1 image'
fi
cp "$DISK" "$SEED_DISK"

if [ "$C77_CAPTURE_ONLY" -eq 0 ]; then
  python3 -B scripts/verify-c76-graph-version-replacement.py \
    "$SEED_DISK" \
    --g0-image "$C76_G0_DISK" \
    --g1-image "$C76_G1_DISK" \
    --boot1-log "$C76_BOOT1_LOG" \
    --boot2-log "$C76_BOOT2_LOG" \
    --boot3-log "$C76_BOOT3_LOG" >"$SEED_EVIDENCE" || \
    fail 'C7.6 verifier rejected the exact G1 seed'
  grep -F -q '"status":"ok"' "$SEED_EVIDENCE" || \
    fail 'C7.6 seed verifier did not report exact success'
  grep -F -q '"c78_independent_disk_scope":false' "$SEED_EVIDENCE" || \
    fail 'C7.6 seed verifier exceeded the reserved C7.8 scope'
fi

# The authorized C7.7 feature consumes the already-proved exact G1 disk. Both
# cold boots must leave every byte unchanged while rebuilding only fresh
# boot-local runtime state.
build_acceptance wasm-c77-ephemeral-runtime-acceptance
run_boot 'C7.7 cold runtime boot 1' "$C77_PASS" "$C77_FAIL" \
  "$C77_FAMILY" "$C77_TIMEOUT" "$C77_BOOT1_LOG"
if [ "$C77_CAPTURE_ONLY" -eq 0 ]; then
  cmp -s "$SEED_DISK" "$DISK" || \
    fail 'first C7.7 cold boot mutated the exact G1 seed'
fi
cp "$DISK" "$C77_COLD1_DISK"
run_boot 'C7.7 cold runtime boot 2' "$C77_PASS" "$C77_FAIL" \
  "$C77_FAMILY" "$C77_TIMEOUT" "$C77_BOOT2_LOG"
if [ "$C77_CAPTURE_ONLY" -eq 0 ]; then
  cmp -s "$SEED_DISK" "$DISK" || \
    fail 'second C7.7 cold boot mutated the exact G1 seed'
  cmp -s "$C77_COLD1_DISK" "$DISK" || \
    fail 'C7.7 cold boots produced different powered-off images'
fi

if [ "$C77_CAPTURE_ONLY" -eq 1 ]; then
  RESULT_REPORTED=1
  echo 'PASS qemu-test-c77-ephemeral-runtime: five QEMU snapshots collected without a fixed-vector host verdict'
  exit 0
fi

python3 -B scripts/verify-c77-ephemeral-runtime.py \
  "$DISK" \
  --c76-g0-image "$C76_G0_DISK" \
  --c76-g1-image "$C76_G1_DISK" \
  --seed-image "$SEED_DISK" \
  --cold1-image "$C77_COLD1_DISK" \
  --c76-boot1-log "$C76_BOOT1_LOG" \
  --c76-boot2-log "$C76_BOOT2_LOG" \
  --c76-boot3-log "$C76_BOOT3_LOG" \
  --boot1-log "$C77_BOOT1_LOG" \
  --boot2-log "$C77_BOOT2_LOG" >"$EVIDENCE" || \
  fail 'C7.7 exact-seed/two-cold-boot host verification failed'
grep -F -q '"status":"ok"' "$EVIDENCE" || \
  fail 'C7.7 verifier did not report exact success'
grep -F -q '"scope":"exact-c76-g1-fixture-only"' "$EVIDENCE" || \
  fail 'C7.7 verifier generalized beyond the exact C7.6 G1 fixture'
grep -F -q '"cold_boot1_exact_no_write":true' "$EVIDENCE" || \
  fail 'C7.7 verifier did not prove first cold-boot disk equality'
grep -F -q '"cold_boot2_exact_no_write":true' "$EVIDENCE" || \
  fail 'C7.7 verifier did not prove second cold-boot disk equality'
grep -F -q '"raw_tokens":0' "$EVIDENCE" || \
  fail 'C7.7 verifier did not keep raw tokens absent'
grep -F -q '"runtime_ready":false' "$EVIDENCE" || \
  fail 'C7.7 verifier did not keep runtime_ready=false'
grep -F -q '"guest_calls":0' "$EVIDENCE" || \
  fail 'C7.7 verifier did not keep guest_calls=0'
grep -F -q '"c78_independent_disk_scope":false' "$EVIDENCE" || \
  fail 'C7.7 verifier claimed the reserved C7.8 disk scope'

mkdir -p target
cp "$EVIDENCE" target/c77-ephemeral-runtime-verifier.json
RESULT_REPORTED=1
echo 'PASS qemu-test-c77-ephemeral-runtime: exact C7.6 G1 seed and two byte-identical cold ephemeral-runtime boots verified'
