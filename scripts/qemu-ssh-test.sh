#!/bin/sh
# Build the QEMU-only SSH image and drive it with the host OpenSSH client.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-kernel
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
SSH_HOST_PORT=${SSH_HOST_PORT:-}
SSH_GUEST_PORT=2222
SSH_PORT_ATTEMPTS=${SSH_PORT_ATTEMPTS:-3}
SSH_READY_TIMEOUT=${SSH_READY_TIMEOUT:-45}
SSH_COMMAND_TIMEOUT=${SSH_COMMAND_TIMEOUT:-15}
SSH_BOOT_TIMEOUT=${SSH_BOOT_TIMEOUT:-240}

# These are the explicit serial-log contract of the QEMU-only component. A
# caller testing a deliberate diagnostic wording change can override the two
# patterns without weakening the OpenSSH wire-level readiness check.
SSH_READY_LOG_PATTERN=${SSH_READY_LOG_PATTERN:-'ssh-test listening on 10\.0\.2\.15:2222'}
SSH_FAILURE_LOG_PATTERN=${SSH_FAILURE_LOG_PATTERN:-'FAIL ssh-test:'}

TEST_TMP=""
QEMU_PID=""
KILLER_PID=""
QEMU_LOG=""
PEER_LOG=""
ACCEPTED_KEY=""
REJECTED_KEY=""
KNOWN_HOSTS_ONE=""
KNOWN_HOSTS_TWO=""
HOST_KEY_ONE=""
HOST_KEY_TWO=""
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

remove_if_set() {
  if [ -n "$1" ]; then
    rm -f "$1"
  fi
}

# shellcheck disable=SC2329  # Invoked by the EXIT trap.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  stop_qemu
  remove_if_set "$ACCEPTED_KEY"
  remove_if_set "$REJECTED_KEY"
  remove_if_set "$KNOWN_HOSTS_ONE"
  remove_if_set "$KNOWN_HOSTS_TWO"
  remove_if_set "$HOST_KEY_ONE"
  remove_if_set "$HOST_KEY_TWO"
  if [ -n "$TEST_TMP" ]; then
    rm -f "$TEST_TMP/qemu-1.log" "$TEST_TMP/qemu-2.log"
    rm -f "$TEST_TMP/peer-1.log" "$TEST_TMP/peer-2.log"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo "FAIL ssh-test: test aborted unexpectedly" >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-ssh-test: $*" >&2
  if [ -n "$PEER_LOG" ] && [ -s "$PEER_LOG" ]; then
    echo "--- OpenSSH peer output ---" >&2
    tail -80 "$PEER_LOG" >&2 || true
  fi
  if [ -n "$QEMU_LOG" ] && [ -s "$QEMU_LOG" ]; then
    echo "--- QEMU transcript (last 120 lines) ---" >&2
    tail -120 "$QEMU_LOG" >&2 || true
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

check_boot_log() {
  boot=$1
  grep -a -E -q "$SSH_READY_LOG_PATTERN" "$QEMU_LOG" \
    || fail "boot $boot did not publish the SSH listener marker"
  if grep -a -E -q "$SSH_FAILURE_LOG_PATTERN" "$QEMU_LOG"; then
    fail "boot $boot reported a component-fatal SSH error"
  fi
}

wait_for_log_count() {
  pattern=$1
  minimum=$2
  label=$3
  remaining=$SSH_COMMAND_TIMEOUT
  while :; do
    kill -0 "$QEMU_PID" 2>/dev/null \
      || fail "QEMU exited while waiting for $label"
    if grep -a -E -q "$SSH_FAILURE_LOG_PATTERN" "$QEMU_LOG"; then
      fail "guest reported a component-fatal SSH error while waiting for $label"
    fi
    count=$(grep -a -E -c "$pattern" "$QEMU_LOG" || true)
    if [ "$count" -ge "$minimum" ]; then
      return
    fi
    if [ "$remaining" -eq 0 ]; then
      fail "$label"
    fi
    sleep 1
    remaining=$((remaining - 1))
  done
}

start_qemu() {
  boot=$1
  QEMU_LOG="$TEST_TMP/qemu-$boot.log"
  PEER_LOG="$TEST_TMP/peer-$boot.log"
  attempt=1
  while [ "$attempt" -le "$SSH_PORT_ATTEMPTS" ]; do
    if [ "$DYNAMIC_PORT" -eq 1 ]; then
      SSH_HOST_PORT=$(python3 -B scripts/openssh-peer.py --pick-port) \
        || fail "cannot select an unused loopback port"
    fi
    : > "$QEMU_LOG"
    : > "$PEER_LOG"

    echo "ssh-test: QEMU boot $boot (127.0.0.1:$SSH_HOST_PORT -> 10.0.2.15:$SSH_GUEST_PORT)"
    "$QEMU_BIN" \
      -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
      -accel "$QEMU_ACCEL" \
      -nographic -bios default -kernel "$KERNEL" \
      -object "rng-random,id=vibeos-ssh-rng-$boot,filename=/dev/urandom" \
      -device "virtio-rng-device,rng=vibeos-ssh-rng-$boot,bus=virtio-mmio-bus.1" \
      -netdev "user,id=vibeos-ssh,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${SSH_HOST_PORT}-10.0.2.15:${SSH_GUEST_PORT}" \
      -device "virtio-net-device,netdev=vibeos-ssh,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01" \
      -global virtio-mmio.force-legacy=false \
      </dev/null >"$QEMU_LOG" 2>&1 &
    QEMU_PID=$!
    ( sleep "$SSH_BOOT_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true ) &
    KILLER_PID=$!

    # Selecting a free port and asking QEMU to bind it are separate actions.
    # Retry only a diagnosed host-forward race; guest failures stay loud.
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
      echo "ssh-test: host port $SSH_HOST_PORT was claimed; retrying"
      attempt=$((attempt + 1))
      continue
    fi
    fail "QEMU boot $boot exited before OpenSSH readiness"
  done
  fail "could not bind a loopback host-forward port after $SSH_PORT_ATTEMPTS attempts"
}

run_peer() {
  boot=$1
  mode=$2
  known_hosts=$3
  host_key=$4
  set -- python3 -B scripts/openssh-peer.py \
    --host localhost \
    --port "$SSH_HOST_PORT" \
    --known-hosts "$known_hosts" \
    --host-key-output "$host_key" \
    --ready-timeout "$SSH_READY_TIMEOUT" \
    --command-timeout "$SSH_COMMAND_TIMEOUT"
  if [ "$mode" = functional ]; then
    set -- "$@" --accepted-key "$ACCEPTED_KEY" --rejected-key "$REJECTED_KEY"
  else
    set -- "$@" --accepted-key "$ACCEPTED_KEY" --scan-only
  fi

  if ! "$@" >"$PEER_LOG" 2>&1; then
    fail "OpenSSH peer failed during boot $boot"
  fi
  kill -0 "$QEMU_PID" 2>/dev/null \
    || fail "QEMU boot $boot exited during OpenSSH acceptance"
  check_boot_log "$boot"
  sed -n '1,8p' "$PEER_LOG"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_positive_integer "$QEMU_SMP" QEMU_SMP
require_positive_integer "$SSH_PORT_ATTEMPTS" SSH_PORT_ATTEMPTS
require_positive_integer "$SSH_READY_TIMEOUT" SSH_READY_TIMEOUT
require_positive_integer "$SSH_COMMAND_TIMEOUT" SSH_COMMAND_TIMEOUT
require_positive_integer "$SSH_BOOT_TIMEOUT" SSH_BOOT_TIMEOUT
if [ -n "$SSH_HOST_PORT" ]; then
  require_positive_integer "$SSH_HOST_PORT" SSH_HOST_PORT
  if [ "$SSH_HOST_PORT" -gt 65535 ]; then
    fail "SSH_HOST_PORT must be in the range 1..65535"
  fi
fi

DYNAMIC_PORT=1
if [ -n "$SSH_HOST_PORT" ]; then
  DYNAMIC_PORT=0
fi

for command in rustup python3 ssh ssh-keygen "$QEMU_BIN"; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "required command not found: $command"
done

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail "rust-toolchain.toml must select an exact channel"
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate rustc for toolchain $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate rustdoc for toolchain $toolchain"

python3 -B scripts/openssh-test-key.py --selftest >/dev/null \
  || fail "OpenSSH key fixture self-test failed"
python3 -B scripts/openssh-peer.py --selftest >/dev/null \
  || fail "OpenSSH peer self-test failed"

echo "ssh-test: building the explicit QEMU test-identity image"
if ! (cd kernel && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features ssh-test) >&2; then
  fail "kernel build failed"
fi

TEST_TMP=$(mktemp -d) || fail "cannot create temporary directory"
ACCEPTED_KEY="$TEST_TMP/id_ed25519_accepted"
REJECTED_KEY="$TEST_TMP/id_ed25519_rejected"
KNOWN_HOSTS_ONE="$TEST_TMP/known_hosts_1"
KNOWN_HOSTS_TWO="$TEST_TMP/known_hosts_2"
HOST_KEY_ONE="$TEST_TMP/host_key_1"
HOST_KEY_TWO="$TEST_TMP/host_key_2"

python3 -B scripts/openssh-test-key.py \
  --fixture accepted --comment vibeos-accepted-test-only --output "$ACCEPTED_KEY" \
  >/dev/null || fail "cannot generate the accepted OpenSSH fixture"
python3 -B scripts/openssh-test-key.py \
  --fixture rejected --comment vibeos-rejected-test-only --output "$REJECTED_KEY" \
  >/dev/null || fail "cannot generate the rejected OpenSSH fixture"

start_qemu 1
run_peer 1 functional "$KNOWN_HOSTS_ONE" "$HOST_KEY_ONE"

wait_for_log_count 'ssh-test exec complete: status 0' 4 \
  "boot 1 did not complete readiness true plus authorized echo/true and post-shell true commands"
wait_for_log_count 'ssh-test exec complete: status 1' 1 \
  "boot 1 did not publish the authorized false exit status"
wait_for_log_count 'ssh-test shell complete: status 0' 1 \
  "boot 1 did not publish the successful interactive shell completion"
status_zero_count=$(grep -a -E -c 'ssh-test exec complete: status 0' "$QEMU_LOG" || true)
status_one_count=$(grep -a -E -c 'ssh-test exec complete: status 1' "$QEMU_LOG" || true)
shell_status_zero_count=$(grep -a -F -c 'ssh-test shell complete: status 0' "$QEMU_LOG" || true)
[ "$status_zero_count" -ge 4 ] \
  || fail "boot 1 did not complete readiness true plus authorized echo/true and post-shell true commands"
[ "$status_one_count" -ge 1 ] \
  || fail "boot 1 did not publish the authorized false exit status"
[ "$shell_status_zero_count" -eq 1 ] \
  || fail "boot 1 did not publish exactly one successful interactive shell completion"
stop_qemu

start_qemu 2
run_peer 2 scan "$KNOWN_HOSTS_TWO" "$HOST_KEY_TWO"
wait_for_log_count 'ssh-test exec complete: status 0' 1 \
  "boot 2 did not complete its strict authenticated readiness command"
status_zero_count=$(grep -a -E -c 'ssh-test exec complete: status 0' "$QEMU_LOG" || true)
[ "$status_zero_count" -ge 1 ] \
  || fail "boot 2 did not complete its strict authenticated readiness command"
stop_qemu

cmp -s "$HOST_KEY_ONE" "$HOST_KEY_TWO" \
  || fail "the deterministic SSH host identity changed across QEMU boots"

RESULT_REPORTED=1
echo "PASS qemu-ssh-test: exact test host key stable across boots; OpenSSH forced curve25519/Ed25519/ChaCha20-Poly1305; interactive PTY/shell, exec/auth, and request policy enforced"
