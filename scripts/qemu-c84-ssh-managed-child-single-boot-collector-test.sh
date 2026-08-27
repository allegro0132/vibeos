#!/bin/sh
# C8.4 diagnostic-only private 24-sample single-cold-boot collector gate.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
C84_SSH_TIMEOUT=${C84_SSH_TIMEOUT:-720}
C84_SSH_READY_TIMEOUT=${C84_SSH_READY_TIMEOUT:-45}
C84_SSH_COMMAND_TIMEOUT=${C84_SSH_COMMAND_TIMEOUT:-30}
C84_SSH_MARKER_TIMEOUT=${C84_SSH_MARKER_TIMEOUT:-30}
FEATURE=wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance
SOURCE_SENTINEL=1111111111111111111111111111111111111111
CHALLENGE_SENTINEL=2222222222222222222222222222222222222222222222222222222222222222

FAMILY='WASM_C84_SSH_MANAGED_CHILD_SINGLE_BOOT_COLLECTOR'
TRUSTED_FAMILY='WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE'
FINISH_FAMILY='WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY'
IRQ_FAMILY='WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY'
PHASE_FAMILY='WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR'
CORE_FAMILY='WASM_C84_SSH_MANAGED_CHILD_CORE'
REQUEST_FAMILY='WASM_C84_SSH_REQUEST_PARENT'

TEST_TMP=""
QEMU_PID=""
KILLER_PID=""
CURRENT_QEMU_LOG=""
CURRENT_PEER_LOG=""
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
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  stop_qemu
  if [ -n "$TEST_TMP" ]; then
    rm -f "$TEST_TMP/id_ed25519_accepted" "$TEST_TMP/id_ed25519_rejected"
    rm -f "$TEST_TMP/failure-known-hosts" "$TEST_TMP/success-known-hosts"
    rm -f "$TEST_TMP/failure-host-key" "$TEST_TMP/success-host-key"
    rm -f "$TEST_TMP/failure-qemu.log" "$TEST_TMP/success-qemu.log"
    rm -f "$TEST_TMP/failure-peer.log" "$TEST_TMP/success-peer.log"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-c84-ssh-managed-child-single-boot-collector-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c84-ssh-managed-child-single-boot-collector-test: $*" >&2
  if [ -n "$CURRENT_PEER_LOG" ] && [ -s "$CURRENT_PEER_LOG" ]; then
    echo '--- OpenSSH collector driver output ---' >&2
    tail -100 "$CURRENT_PEER_LOG" >&2 || true
  fi
  if [ -n "$CURRENT_QEMU_LOG" ] && [ -s "$CURRENT_QEMU_LOG" ]; then
    echo '--- QEMU serial output (last 400 lines) ---' >&2
    tail -400 "$CURRENT_QEMU_LOG" >&2 || true
  fi
  exit 1
}

positive_integer() {
  value=$1
  label=$2
  case "$value" in
    ''|*[!0-9]*|0) fail "$label must be a positive integer" ;;
  esac
}

family_count() {
  log=$1
  family=$2
  grep -a -F -c "$family" "$log" || true
}

marker_signature() {
  log=$1
  echo \
    "$(family_count "$log" "$FAMILY")" \
    "$(family_count "$log" "$PHASE_FAMILY")" \
    "$(family_count "$log" "$CORE_FAMILY")" \
    "$(family_count "$log" "$REQUEST_FAMILY")" \
    "$(family_count "$log" "$IRQ_FAMILY")" \
    "$(family_count "$log" "$FINISH_FAMILY")" \
    "$(family_count "$log" "$TRUSTED_FAMILY")"
}

require_counts() {
  scenario=$1
  log=$2
  collector=$(family_count "$log" "$FAMILY")
  phase=$(family_count "$log" "$PHASE_FAMILY")
  core=$(family_count "$log" "$CORE_FAMILY")
  request=$(family_count "$log" "$REQUEST_FAMILY")
  irq=$(family_count "$log" "$IRQ_FAMILY")
  finish=$(family_count "$log" "$FINISH_FAMILY")
  trusted=$(family_count "$log" "$TRUSTED_FAMILY")
  if [ "$scenario" = failure ]; then
    [ "$collector" -eq 3 ] || fail "failure boot collector count differs: $collector"
    case "$phase" in
      5|6) ;;
      *) fail "failure boot phase count differs: $phase" ;;
    esac
    [ "$core" -eq 4 ] || fail "failure boot Core count differs: $core"
    [ "$request" -eq 2 ] || fail "failure boot request count differs: $request"
    [ "$irq" -eq 3 ] || fail "failure boot IRQ count differs: $irq"
    [ "$finish" -eq 1 ] || fail "failure boot finish count differs: $finish"
    [ "$trusted" -eq 1 ] || fail "failure boot trusted count differs: $trusted"
  else
    [ "$collector" -eq 27 ] || fail "success boot collector count differs: $collector"
    [ "$phase" -eq 169 ] || fail "success boot phase count differs: $phase"
    [ "$core" -eq 120 ] || fail "success boot Core count differs: $core"
    [ "$request" -eq 48 ] || fail "success boot request count differs: $request"
    [ "$irq" -eq 26 ] || fail "success boot IRQ count differs: $irq"
    [ "$finish" -eq 24 ] || fail "success boot finish count differs: $finish"
    [ "$trusted" -eq 24 ] || fail "success boot trusted count differs: $trusted"
  fi
}

start_qemu() {
  log=$1
  port=$2
  CURRENT_QEMU_LOG=$log
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp 1 -m 128M \
    -accel tcg,thread=single -nographic -bios default -kernel "$KERNEL" \
    -object rng-random,id=vibeos-c84-ssh-rng,filename=/dev/urandom \
    -device virtio-rng-device,rng=vibeos-c84-ssh-rng,bus=virtio-mmio-bus.1 \
    -netdev "user,id=vibeos-c84-ssh,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${port}-10.0.2.15:2222" \
    -device virtio-net-device,netdev=vibeos-c84-ssh,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01 \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$log" 2>&1 &
  QEMU_PID=$!
  (sleep "$C84_SSH_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
  KILLER_PID=$!
}

freeze_and_verify_boot() {
  scenario=$1
  log=$2
  require_counts "$scenario" "$log"
  before=$(marker_signature "$log")
  sleep 0.3
  after=$(marker_signature "$log")
  [ "$after" = "$before" ] || fail "$scenario boot emitted a late marker after peer closure"

  stop_qemu
  frozen=$(marker_signature "$log")
  [ "$frozen" = "$after" ] || fail "$scenario boot emitted a marker while freezing QEMU"
  require_counts "$scenario" "$log"

  if grep -a -E -q 'WASM_[A-Z0-9_]+ FAIL([[:space:]]|$)|\[!\] (fatal|panic)|panicked at' "$log"; then
    fail "$scenario boot reported a WASM failure, panic, or fatal error"
  fi
  for prefix in 'VIBE_WASM_AOT_META ' 'VIBE_WASM_AOT_SAMPLE ' 'VIBE_WASM_AOT_END '; do
    if grep -a -F -q "$prefix" "$log"; then
      fail "$scenario QEMU boot leaked formal UART prefix $prefix"
    fi
  done
  foreign_families=$(grep -a -o -E 'WASM_[A-Z0-9_]+' "$log" \
    | sort -u \
    | grep -E -v "^(${FAMILY}|${TRUSTED_FAMILY}|${FINISH_FAMILY}|${IRQ_FAMILY}|${PHASE_FAMILY}|${CORE_FAMILY}|${REQUEST_FAMILY})$" || true)
  [ -z "$foreign_families" ] \
    || fail "$scenario boot emitted foreign WASM families: $foreign_families"

  python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py \
    --verify-log-only --scenario "$scenario" --qemu-log "$log" >&2 \
    || fail "$scenario frozen collector transcript verification failed"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

positive_integer "$C84_SSH_TIMEOUT" C84_SSH_TIMEOUT
positive_integer "$C84_SSH_READY_TIMEOUT" C84_SSH_READY_TIMEOUT
positive_integer "$C84_SSH_COMMAND_TIMEOUT" C84_SSH_COMMAND_TIMEOUT
positive_integer "$C84_SSH_MARKER_TIMEOUT" C84_SSH_MARKER_TIMEOUT

for command in rustup python3 ssh ssh-keygen "$QEMU_BIN"; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source >&2 \
  || fail 'portable publisher verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source >&2 \
  || fail 'static finish/verify verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source >&2 \
  || fail 'static verified-stream sibling verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py --selftest --check-source >&2 \
  || fail 'static trusted-sample verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-single-boot-collector.py --selftest --check-source >&2 \
  || fail 'static single-boot collector verification failed'
python3 -B scripts/openssh-test-key.py --selftest >/dev/null \
  || fail 'OpenSSH key fixture self-test failed'
python3 -B scripts/openssh-peer.py --selftest >/dev/null \
  || fail 'maintained OpenSSH peer self-test failed'
python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py --selftest >/dev/null \
  || fail 'trusted-sample predecessor parser self-test failed'
python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py --selftest >/dev/null \
  || fail 'single-boot collector parser self-test failed'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate pinned rustc for $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate pinned rustdoc for $toolchain"

echo 'qemu-c84-ssh-managed-child-single-boot-collector-test: building one isolated single-hart image for two boots'
if ! (cd firmware/qemu-virt && \
  VIBEOS_C84_SOURCE_COMMIT="$SOURCE_SENTINEL" \
  VIBEOS_C84_CHALLENGE="$CHALLENGE_SENTINEL" \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --no-default-features \
    --features "$FEATURE") >&2; then
  fail 'collector kernel build failed'
fi

TEST_TMP=$(mktemp -d) || fail 'cannot create temporary directory'
ACCEPTED_KEY="$TEST_TMP/id_ed25519_accepted"
REJECTED_KEY="$TEST_TMP/id_ed25519_rejected"
FAILURE_KNOWN_HOSTS="$TEST_TMP/failure-known-hosts"
SUCCESS_KNOWN_HOSTS="$TEST_TMP/success-known-hosts"
FAILURE_QEMU_LOG="$TEST_TMP/failure-qemu.log"
SUCCESS_QEMU_LOG="$TEST_TMP/success-qemu.log"
FAILURE_PEER_LOG="$TEST_TMP/failure-peer.log"
SUCCESS_PEER_LOG="$TEST_TMP/success-peer.log"
FAILURE_HOST_KEY="$TEST_TMP/failure-host-key"
SUCCESS_HOST_KEY="$TEST_TMP/success-host-key"

python3 -B scripts/openssh-test-key.py \
  --fixture accepted --comment vibeos-c84-accepted-test-only --output "$ACCEPTED_KEY" \
  >/dev/null || fail 'cannot generate accepted OpenSSH fixture'
python3 -B scripts/openssh-test-key.py \
  --fixture rejected --comment vibeos-c84-rejected-test-only --output "$REJECTED_KEY" \
  >/dev/null || fail 'cannot generate rejected OpenSSH fixture'

FAILURE_PORT=$(python3 -B scripts/openssh-peer.py --pick-port) \
  || fail 'cannot select a failure-boot loopback port'
positive_integer "$FAILURE_PORT" FAILURE_PORT
CURRENT_PEER_LOG=$FAILURE_PEER_LOG
start_qemu "$FAILURE_QEMU_LOG" "$FAILURE_PORT"
if ! python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py \
  --scenario failure --host localhost --port "$FAILURE_PORT" \
  --accepted-key "$ACCEPTED_KEY" --rejected-key "$REJECTED_KEY" \
  --known-hosts "$FAILURE_KNOWN_HOSTS" --host-key-output "$FAILURE_HOST_KEY" \
  --qemu-log "$FAILURE_QEMU_LOG" \
  --ready-timeout "$C84_SSH_READY_TIMEOUT" \
  --command-timeout "$C84_SSH_COMMAND_TIMEOUT" \
  --marker-timeout "$C84_SSH_MARKER_TIMEOUT" \
  >"$FAILURE_PEER_LOG" 2>&1; then
  fail 'failure-boot OpenSSH collector sequence failed'
fi
kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited during the failure-boot sequence'
freeze_and_verify_boot failure "$FAILURE_QEMU_LOG"

SUCCESS_PORT=$(python3 -B scripts/openssh-peer.py --pick-port) \
  || fail 'cannot select a success-boot loopback port'
positive_integer "$SUCCESS_PORT" SUCCESS_PORT
CURRENT_PEER_LOG=$SUCCESS_PEER_LOG
start_qemu "$SUCCESS_QEMU_LOG" "$SUCCESS_PORT"
if ! python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py \
  --scenario success --host localhost --port "$SUCCESS_PORT" \
  --accepted-key "$ACCEPTED_KEY" --rejected-key "$REJECTED_KEY" \
  --known-hosts "$SUCCESS_KNOWN_HOSTS" --host-key-output "$SUCCESS_HOST_KEY" \
  --qemu-log "$SUCCESS_QEMU_LOG" \
  --ready-timeout "$C84_SSH_READY_TIMEOUT" \
  --command-timeout "$C84_SSH_COMMAND_TIMEOUT" \
  --marker-timeout "$C84_SSH_MARKER_TIMEOUT" \
  >"$SUCCESS_PEER_LOG" 2>&1; then
  fail 'success-boot OpenSSH collector sequence failed'
fi
kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited during the success-boot sequence'
freeze_and_verify_boot success "$SUCCESS_QEMU_LOG"

python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py \
  --verify-pair --failure-log "$FAILURE_QEMU_LOG" --success-log "$SUCCESS_QEMU_LOG" >&2 \
  || fail 'same-image two-boot collector pair verification failed'

RESULT_REPORTED=1
sed -n '1,4p' "$FAILURE_PEER_LOG"
sed -n '1,4p' "$SUCCESS_PEER_LOG"
echo 'PASS qemu-c84-ssh-managed-child-single-boot-collector-test: one built image failed permanently after an active epoch-1 disconnect with one META audit commit, while a fresh boot committed META + 24 ordered SAMPLE records + END, rejected attempt 25, preserved every predecessor projection, and emitted zero formal UART prefixes (diagnostic evidence only)'
