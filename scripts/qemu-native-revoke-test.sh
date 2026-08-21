#!/bin/sh
# C5.4c exact-incarnation managed-native revoke/fault acceptance.
# Destructive winners run in isolated boots and never replace qemu-ssh-test.sh.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
SSH_HOST_PORT=${SSH_HOST_PORT:-}
SSH_GUEST_PORT=2222
SSH_PORT_ATTEMPTS=${SSH_PORT_ATTEMPTS:-3}
SSH_READY_TIMEOUT=${SSH_READY_TIMEOUT:-45}
SSH_COMMAND_TIMEOUT=${SSH_COMMAND_TIMEOUT:-15}
SSH_BOOT_TIMEOUT=${SSH_BOOT_TIMEOUT:-240}

SSH_READY_LOG_PATTERN=${SSH_READY_LOG_PATTERN:-'ssh-test listening on 10\.0\.2\.15:2222'}
SSH_FAILURE_LOG_PATTERN=${SSH_FAILURE_LOG_PATTERN:-'FAIL ssh-test:'}
WASM_C48_POLICY_PATTERN='WASM_C48_ACCEPTANCE PASS.*policy=passed'
WASM_C52_COUNTER_PATTERN='WASM_C52_ACCEPTANCE PASS parks=20 resumes=20 cross_hart_signals=20 stale_rejects=20 live_faults=20'
WASM_C53_COUNTER_PATTERN='WASM_C53_ACCEPTANCE PASS pairs=20 input_chunks=180 output_chunks=180 xor_bytes=184320 backend_pending=20 backend_wakes=20 host_pending=20 exact_wakes=20 exact_resumes=20 late_wake_rejects=20 eof=20 normal_closes=40 terminal_matches=20 terminal_orders=20 close_races=3 terminal_mappings=3 start_error_terminals=2 terminal_races=3 cancel_busy_retries=3 completion_busy_retries=3 mismatches=9 duplicate_fault_rejects=1 aba_rejects=1 harts=4'
C54_HEALTHY_PATTERN='WASM_C54_NATIVE_REVOKE PASS starts=2 claims=1 pending_claims=1 cap_revokes=1 backend_cancels=1 core_already_consumed=1 consumed_deltas=1 runtime_cancel_acks=1 cancel_idles=1 partial_total=1024 partial_first=257 partial_second=767 waiting_ops=1 cancelled_terminals=1 cspace_resets=2 reaper_notifies=2 acks=2 late_wake_stale=1 restart_stale_claim=1 restart_stale_backend=1 replacement_success=1'
C54_LINEARIZED_PATTERN='WASM_C54_NATIVE_LINEARIZED_GUARD PASS starts=1 claims=1 deferred_claims=1 backend_effects=1 cap_revokes=0 backend_cancels=0 runtime_cancel_acks=0 terminals=0 cspace_resets=0 reaper_notifies=0 acks=0 raw_reclaims=0'
C54_RAW_INVOKING_PATTERN='WASM_C54_NATIVE_RAW_FAULT_GUARD PASS phase=backend-invoking starts=1 raw_faults=1 raw_reclaims=0 terminals=0 cspace_resets=0 reaper_notifies=0 acks=0'
C54_RAW_LINEARIZED_PATTERN='WASM_C54_NATIVE_RAW_FAULT_GUARD PASS phase=backend-linearized starts=1 raw_faults=1 raw_reclaims=0 terminals=0 cspace_resets=0 reaper_notifies=0 acks=0'
C54_FAILURE_PATTERN='WASM_C54_NATIVE_.*FAIL|WASM_C54_NATIVE_.* FAIL'

TEST_TMP=""
QEMU_PID=""
KILLER_PID=""
QEMU_LOG=""
PEER_LOG=""
PEER_PID=""
ACCEPTED_KEY=""
REJECTED_KEY=""
HOST_KEY_BASELINE=""
RESULT_REPORTED=0

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
  if [ -n "$PEER_PID" ]; then
    wait "$PEER_PID" 2>/dev/null || true
    PEER_PID=""
  fi
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  stop_qemu
  if [ -n "$TEST_TMP" ]; then
    rm -f "$TEST_TMP"/* 2>/dev/null || true
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo "FAIL qemu-native-revoke-test: test aborted unexpectedly" >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-native-revoke-test: $*" >&2
  if [ -n "$PEER_LOG" ] && [ -s "$PEER_LOG" ]; then
    echo "--- OpenSSH peer output ---" >&2
    tail -80 "$PEER_LOG" >&2 || true
  fi
  if [ -n "$QEMU_LOG" ] && [ -s "$QEMU_LOG" ]; then
    echo "--- QEMU transcript (last 160 lines) ---" >&2
    tail -160 "$QEMU_LOG" >&2 || true
  fi
  exit 1
}

require_positive_integer() {
  value=$1
  label=$2
  case "$value" in
    ''|*[!0-9]*|0) fail "$label must be a positive integer" ;;
  esac
}

wait_for_pattern() {
  pattern=$1
  label=$2
  remaining=$SSH_BOOT_TIMEOUT
  while :; do
    kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU exited while waiting for $label"
    if grep -a -E -q "$SSH_FAILURE_LOG_PATTERN|$C54_FAILURE_PATTERN" "$QEMU_LOG"; then
      fail "guest reported a failure while waiting for $label"
    fi
    count=$(grep -a -F -c "$pattern" "$QEMU_LOG" || true)
    if [ "$count" -eq 1 ]; then
      return
    fi
    [ "$count" -eq 0 ] || fail "$label was published more than once"
    if [ -n "$PEER_PID" ] && ! kill -0 "$PEER_PID" 2>/dev/null; then
      wait "$PEER_PID" 2>/dev/null || true
      PEER_PID=""
      fail "OpenSSH peer exited before $label"
    fi
    [ "$remaining" -gt 0 ] || fail "$label was not published"
    sleep 1
    remaining=$((remaining - 1))
  done
}

check_baseline() {
  scenario=$1
  grep -a -E -q "$SSH_READY_LOG_PATTERN" "$QEMU_LOG" \
    || fail "$scenario boot did not publish the SSH listener marker"
  for failure in \
    'WASM_C48_ACCEPTANCE FAIL' \
    'WASM_C52_ACCEPTANCE FAIL' \
    'WASM_C53_ACCEPTANCE FAIL'; do
    if grep -a -F -q "$failure" "$QEMU_LOG"; then
      fail "$scenario boot reported $failure"
    fi
  done
  [ "$(grep -a -F -c 'WASM_C48_ACCEPTANCE PASS' "$QEMU_LOG" || true)" -eq 1 ] \
    || fail "$scenario boot did not publish exactly one C4.8 PASS"
  [ "$(grep -a -E -c "$WASM_C48_POLICY_PATTERN" "$QEMU_LOG" || true)" -eq 1 ] \
    || fail "$scenario boot did not publish the C4.8 policy gate"
  [ "$(grep -a -F -c "$WASM_C52_COUNTER_PATTERN" "$QEMU_LOG" || true)" -eq 1 ] \
    || fail "$scenario boot did not publish exact C5.2 counters"
  [ "$(grep -a -F -c "$WASM_C53_COUNTER_PATTERN" "$QEMU_LOG" || true)" -eq 1 ] \
    || fail "$scenario boot did not publish exact C5.3 counters"
}

wait_for_baseline() {
  scenario=$1
  remaining=$SSH_BOOT_TIMEOUT
  while :; do
    kill -0 "$QEMU_PID" 2>/dev/null \
      || fail "QEMU exited while waiting for $scenario C4.8/C5.2/C5.3 baseline"
    if grep -a -E -q "$SSH_FAILURE_LOG_PATTERN|$C54_FAILURE_PATTERN" "$QEMU_LOG"; then
      fail "$scenario boot reported a failure before OpenSSH"
    fi
    for failure in \
      'WASM_C48_ACCEPTANCE FAIL' \
      'WASM_C52_ACCEPTANCE FAIL' \
      'WASM_C53_ACCEPTANCE FAIL'; do
      if grep -a -F -q "$failure" "$QEMU_LOG"; then
        fail "$scenario boot reported $failure before OpenSSH"
      fi
    done
    if grep -a -E -q 'WASM_C54_NATIVE_.* PASS' "$QEMU_LOG"; then
      fail "$scenario boot published C5.4c evidence before its exact native invocation"
    fi
    c48=$(grep -a -E -c "$WASM_C48_POLICY_PATTERN" "$QEMU_LOG" || true)
    c52=$(grep -a -F -c "$WASM_C52_COUNTER_PATTERN" "$QEMU_LOG" || true)
    c53=$(grep -a -F -c "$WASM_C53_COUNTER_PATTERN" "$QEMU_LOG" || true)
    [ "$c48" -le 1 ] && [ "$c52" -le 1 ] && [ "$c53" -le 1 ] \
      || fail "$scenario boot duplicated a baseline PASS marker"
    if [ "$c48" -eq 1 ] && [ "$c52" -eq 1 ] && [ "$c53" -eq 1 ]; then
      check_baseline "$scenario"
      return
    fi
    [ "$remaining" -gt 0 ] \
      || fail "$scenario boot did not publish exact C4.8/C5.2/C5.3 baseline counters"
    sleep 1
    remaining=$((remaining - 1))
  done
}

start_qemu() {
  scenario=$1
  QEMU_LOG="$TEST_TMP/qemu-$scenario.log"
  PEER_LOG="$TEST_TMP/peer-$scenario.log"
  attempt=1
  while [ "$attempt" -le "$SSH_PORT_ATTEMPTS" ]; do
    if [ "$DYNAMIC_PORT" -eq 1 ]; then
      SSH_HOST_PORT=$(python3 -B scripts/openssh-peer.py --pick-port) \
        || fail "cannot select an unused loopback port"
    fi
    : > "$QEMU_LOG"
    : > "$PEER_LOG"
    echo "c54c: $scenario boot (127.0.0.1:$SSH_HOST_PORT -> 10.0.2.15:$SSH_GUEST_PORT)"
    "$QEMU_BIN" \
      -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
      -accel "$QEMU_ACCEL" \
      -nographic -bios default -kernel "$KERNEL" \
      -object "rng-random,id=vibeos-c54-rng,filename=/dev/urandom" \
      -device "virtio-rng-device,rng=vibeos-c54-rng,bus=virtio-mmio-bus.1" \
      -netdev "user,id=vibeos-c54-net,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${SSH_HOST_PORT}-10.0.2.15:${SSH_GUEST_PORT}" \
      -device "virtio-net-device,netdev=vibeos-c54-net,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01" \
      -global virtio-mmio.force-legacy=false \
      </dev/null >"$QEMU_LOG" 2>&1 &
    QEMU_PID=$!
    ( sleep "$SSH_BOOT_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true ) &
    KILLER_PID=$!
    sleep 0.25
    if kill -0 "$QEMU_PID" 2>/dev/null; then
      return
    fi
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
    kill "$KILLER_PID" 2>/dev/null || true
    wait "$KILLER_PID" 2>/dev/null || true
    KILLER_PID=""
    if [ "$DYNAMIC_PORT" -eq 1 ] \
      && [ "$attempt" -lt "$SSH_PORT_ATTEMPTS" ] \
      && grep -a -qi 'could not set up host forwarding rule' "$QEMU_LOG"; then
      attempt=$((attempt + 1))
      continue
    fi
    fail "$scenario QEMU exited before OpenSSH readiness"
  done
  fail "could not bind a loopback host-forward port"
}

run_peer() {
  scenario=$1
  known_hosts="$TEST_TMP/known-hosts-$scenario"
  host_key="$TEST_TMP/host-key-$scenario"
  set -- python3 -B scripts/openssh-peer.py \
    --host localhost \
    --port "$SSH_HOST_PORT" \
    --accepted-key "$ACCEPTED_KEY" \
    --rejected-key "$REJECTED_KEY" \
    --known-hosts "$known_hosts" \
    --host-key-output "$host_key" \
    --ready-timeout "$SSH_READY_TIMEOUT" \
    --command-timeout "$SSH_COMMAND_TIMEOUT" \
    --native-revoke-scenario "$scenario"
  if [ "$scenario" = healthy ]; then
    if ! "$@" >"$PEER_LOG" 2>&1; then
      fail "$scenario OpenSSH peer failed"
    fi
  else
    # The destructive command intentionally has no terminal or reset. Keep the
    # real OpenSSH connection live while the script waits only for the guest's
    # exact no-reclaim guard, then terminate this isolated boot.
    "$@" >"$PEER_LOG" 2>&1 &
    PEER_PID=$!
  fi
}

wait_for_host_key_evidence() {
  scenario=$1
  host_key=$2
  remaining=$SSH_READY_TIMEOUT
  while [ ! -s "$host_key" ]; do
    kill -0 "$QEMU_PID" 2>/dev/null \
      || fail "$scenario QEMU exited before host-key evidence"
    if [ -n "$PEER_PID" ] && ! kill -0 "$PEER_PID" 2>/dev/null; then
      wait "$PEER_PID" 2>/dev/null || true
      PEER_PID=""
      fail "$scenario OpenSSH peer exited before host-key evidence"
    fi
    [ "$remaining" -gt 0 ] \
      || fail "$scenario OpenSSH peer did not publish host-key evidence"
    sleep 1
    remaining=$((remaining - 1))
  done
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for value_label in \
  "$QEMU_SMP:QEMU_SMP" \
  "$SSH_PORT_ATTEMPTS:SSH_PORT_ATTEMPTS" \
  "$SSH_READY_TIMEOUT:SSH_READY_TIMEOUT" \
  "$SSH_COMMAND_TIMEOUT:SSH_COMMAND_TIMEOUT" \
  "$SSH_BOOT_TIMEOUT:SSH_BOOT_TIMEOUT"; do
  require_positive_integer "${value_label%%:*}" "${value_label#*:}"
done
[ "$QEMU_SMP" -ge 4 ] || fail "QEMU_SMP must be at least 4"
if [ -n "$SSH_HOST_PORT" ]; then
  require_positive_integer "$SSH_HOST_PORT" SSH_HOST_PORT
  [ "$SSH_HOST_PORT" -le 65535 ] || fail "SSH_HOST_PORT must be at most 65535"
fi
DYNAMIC_PORT=1
[ -z "$SSH_HOST_PORT" ] || DYNAMIC_PORT=0

for command in cmp rustup python3 ssh ssh-keygen "$QEMU_BIN"; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail "rust-toolchain.toml must select an exact channel"
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate pinned rustc"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate pinned rustdoc"

python3 -B scripts/openssh-test-key.py --selftest >/dev/null \
  || fail "OpenSSH key fixture self-test failed"
python3 -B scripts/openssh-peer.py --selftest >/dev/null \
  || fail "OpenSSH peer self-test failed"

echo "c54c: building isolated managed-native revoke acceptance image"
if ! (cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release \
    --features ssh-native-async-revoke-qemu-acceptance) >&2; then
  fail "kernel build failed"
fi

TEST_TMP=$(mktemp -d) || fail "cannot create temporary directory"
ACCEPTED_KEY="$TEST_TMP/id-ed25519-accepted"
REJECTED_KEY="$TEST_TMP/id-ed25519-rejected"
python3 -B scripts/openssh-test-key.py \
  --fixture accepted --comment vibeos-c54-accepted-test-only --output "$ACCEPTED_KEY" \
  >/dev/null || fail "cannot generate accepted key"
python3 -B scripts/openssh-test-key.py \
  --fixture rejected --comment vibeos-c54-rejected-test-only --output "$REJECTED_KEY" \
  >/dev/null || fail "cannot generate rejected key"

for scenario in healthy linearized raw-invoking raw-linearized; do
  start_qemu "$scenario"
  wait_for_baseline "$scenario"
  run_peer "$scenario"
  scenario_host_key="$TEST_TMP/host-key-$scenario"
  wait_for_host_key_evidence "$scenario" "$scenario_host_key"
  if [ -z "$HOST_KEY_BASELINE" ]; then
    HOST_KEY_BASELINE=$scenario_host_key
  else
    cmp -s "$HOST_KEY_BASELINE" "$scenario_host_key" \
      || fail "$scenario boot changed the deterministic SSH host identity"
  fi
  case "$scenario" in
    healthy) marker=$C54_HEALTHY_PATTERN ;;
    linearized) marker=$C54_LINEARIZED_PATTERN ;;
    raw-invoking) marker=$C54_RAW_INVOKING_PATTERN ;;
    raw-linearized) marker=$C54_RAW_LINEARIZED_PATTERN ;;
  esac
  wait_for_pattern "$marker" "$scenario exact guard marker"
  check_baseline "$scenario"
  marker_count=$(grep -a -F -c "$marker" "$QEMU_LOG" || true)
  [ "$marker_count" -eq 1 ] || fail "$scenario marker count changed after peer exit"
  c54_pass_count=$(grep -a -E -c \
    'WASM_C54_NATIVE_(REVOKE|LINEARIZED_GUARD|RAW_FAULT_GUARD) PASS' \
    "$QEMU_LOG" || true)
  [ "$c54_pass_count" -eq 1 ] \
    || fail "$scenario boot did not isolate exactly one C5.4c PASS marker"
  if [ "$scenario" = healthy ]; then
    sed -n '1,8p' "$PEER_LOG"
  fi
  stop_qemu
done

RESULT_REPORTED=1
echo "PASS qemu-native-revoke-test: healthy exact Pending revoke/AlreadyConsumed/partial-spill/restart cleanup and isolated BackendLinearized/raw-fault no-reclaim guards passed; legacy C4.8/C5.2/C5.3 and OpenSSH auth/PTY/sync policy assertions remained live"
