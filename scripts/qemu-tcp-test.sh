#!/bin/sh
# Build the dedicated TCP echo image and verify it through QEMU user networking.
set -eu

cd "$(dirname "$0")/.."
./scripts/prepare-jitterentropy-rs.sh

TCP_TEST_MODE=${1:-echo}
case "$TCP_TEST_MODE" in
  echo) TCP_FEATURE=tcp-echo; TEST_NAME=tcp-echo ;;
  recovery) TCP_FEATURE=tcp-echo-recovery-test; TEST_NAME=tcp-recovery ;;
  *) echo "usage: $0 [echo|recovery]" >&2; exit 2 ;;
esac

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
TCP_HOST_PORT=${TCP_HOST_PORT:-}
TCP_GUEST_PORT=2222
TCP_TIMEOUT=${TCP_TIMEOUT:-45}
TCP_RECOVERY_TIMEOUT=${TCP_RECOVERY_TIMEOUT:-120}
TCP_PORT_ATTEMPTS=${TCP_PORT_ATTEMPTS:-3}

QEMU_PID=""
PEER_PID=""
TEST_TMP=""
QEMU_LOG=""
PEER_LOG=""
RECOVERY_READY=""
RECOVERY_CONTINUE=""
QEMU_INPUT=""
RESULT_REPORTED=0

stop_qemu() {
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
  fi
}

# shellcheck disable=SC2329  # Invoked by the EXIT-trap cleanup function.
stop_peer() {
  if [ -n "$PEER_PID" ]; then
    kill "$PEER_PID" 2>/dev/null || true
    wait "$PEER_PID" 2>/dev/null || true
    PEER_PID=""
  fi
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  stop_peer
  stop_qemu
  exec 3>&-
  if [ -n "$TEST_TMP" ]; then
    rm -f "$QEMU_LOG" "$PEER_LOG" "$RECOVERY_READY" "$RECOVERY_CONTINUE" "$QEMU_INPUT"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo "FAIL $TEST_NAME: test aborted unexpectedly" >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL $TEST_NAME: $*" >&2
  if [ -n "$QEMU_LOG" ] && [ -s "$QEMU_LOG" ]; then
    echo "--- QEMU transcript (last 80 lines) ---" >&2
    tail -80 "$QEMU_LOG" >&2 || true
  fi
  exit 1
}

latest_session() {
  grep -a -o 'tcp-session epoch=[0-9][0-9]* generation=[0-9][0-9]* ingress-device=[0-9][0-9]* ingress-stack=[0-9][0-9]* egress-device=[0-9][0-9]* egress-stack=[0-9][0-9]* stack-component=[0-9][0-9]* driver-component=[0-9][0-9]*' "$QEMU_LOG" \
    | tail -1 || true
}

session_field() {
  field_name=$1
  field_line=$2
  printf '%s\n' "$field_line" | sed -n "s/.*${field_name}=\\([0-9][0-9]*\\).*/\\1/p"
}

fixed_count() {
  grep -a -F -c "$1" "$QEMU_LOG" || true
}

run_recovery_phase() {
  recovery_kind=$1
  rm -f "$RECOVERY_READY" "$RECOVERY_CONTINUE" "$PEER_LOG"

  case "$recovery_kind" in
    stack)
      recovery_command=tcp-fault
      request_marker='tcp-echo fault requested'
      fault_marker='injected TCP stack fault'
      ingress_field=ingress-stack
      egress_field=egress-stack
      ;;
    device)
      recovery_command=tcp-device-fault
      request_marker='tcp-echo driver fault requested'
      fault_marker='injected virtio-net fault with a live TCP stream'
      ingress_field=ingress-device
      egress_field=egress-device
      ;;
    *) fail "internal recovery kind is invalid: $recovery_kind" ;;
  esac

  echo "$TEST_NAME: opening a stream and faulting the $recovery_kind incarnation"
  python3 -B scripts/tcp-peer.py \
    --recovery \
    --port "$TCP_HOST_PORT" \
    --timeout "$TCP_RECOVERY_TIMEOUT" \
    --recovery-ready "$RECOVERY_READY" \
    --recovery-continue "$RECOVERY_CONTINUE" \
    >"$PEER_LOG" 2>&1 &
  PEER_PID=$!

  ready_attempt=0
  while [ ! -s "$RECOVERY_READY" ] && [ "$ready_attempt" -lt 1200 ]; do
    if ! kill -0 "$PEER_PID" 2>/dev/null; then
      wait "$PEER_PID" 2>/dev/null || true
      PEER_PID=""
      fail "$recovery_kind recovery peer exited before the initial echo"
    fi
    sleep 0.05
    ready_attempt=$((ready_attempt + 1))
  done
  [ -s "$RECOVERY_READY" ] \
    || fail "$recovery_kind recovery stream did not become ready"

  printf 'tcp-session\n' >&3
  session_attempt=0
  session_line=""
  while [ "$session_attempt" -lt 200 ]; do
    session_line=$(latest_session)
    [ -n "$session_line" ] && break
    sleep 0.05
    session_attempt=$((session_attempt + 1))
  done
  [ -n "$session_line" ] || fail "guest did not report the initial packet session"
  epoch_before=$(session_field epoch "$session_line")
  generation_before=$(session_field generation "$session_line")
  stack_component_before=$(session_field stack-component "$session_line")
  driver_component_before=$(session_field driver-component "$session_line")
  [ -n "$epoch_before" ] && [ -n "$generation_before" ] \
    && [ -n "$stack_component_before" ] && [ -n "$driver_component_before" ] \
    || fail "initial packet-session fields were malformed"

  request_before=$(fixed_count "$request_marker")
  fault_before=$(fixed_count "$fault_marker")
  printf '%s\n' "$recovery_command" >&3
  fault_attempt=0
  while [ "$fault_attempt" -lt 200 ]; do
    request_after=$(fixed_count "$request_marker")
    fault_after=$(fixed_count "$fault_marker")
    if [ "$request_after" -gt "$request_before" ] \
      && [ "$fault_after" -gt "$fault_before" ]; then
      break
    fi
    sleep 0.05
    fault_attempt=$((fault_attempt + 1))
  done
  [ "$request_after" -gt "$request_before" ] \
    || fail "$recovery_kind fault command did not acknowledge successful staging"
  [ "$fault_after" -gt "$fault_before" ] \
    || fail "$recovery_kind component did not reach the injected fault boundary"

  recovery_attempt=0
  generation_after=0
  epoch_after=0
  stack_component_after=0
  driver_component_after=0
  while [ "$recovery_attempt" -lt 400 ]; do
    printf 'tcp-session\n' >&3
    sleep 0.05
    session_line=$(latest_session)
    epoch_after=$(session_field epoch "$session_line")
    generation_after=$(session_field generation "$session_line")
    stack_component_after=$(session_field stack-component "$session_line")
    driver_component_after=$(session_field driver-component "$session_line")
    if [ -n "$epoch_after" ] && [ -n "$generation_after" ]; then
      if [ "$recovery_kind" = stack ] \
        && [ "$epoch_after" -eq "$epoch_before" ] \
        && [ "$generation_after" -gt "$generation_before" ] \
        && [ "$stack_component_after" -eq $((stack_component_before + 1)) ] \
        && [ "$driver_component_after" -eq "$driver_component_before" ]; then
        break
      fi
      if [ "$recovery_kind" = device ] \
        && [ "$epoch_after" -gt "$epoch_before" ] \
        && [ "$generation_after" -gt "$generation_before" ] \
        && [ "$stack_component_after" -eq "$stack_component_before" ] \
        && [ "$driver_component_after" -eq $((driver_component_before + 1)) ]; then
        break
      fi
    fi
    recovery_attempt=$((recovery_attempt + 1))
  done
  epoch_after=${epoch_after:-0}
  generation_after=${generation_after:-0}
  if [ "$recovery_kind" = stack ]; then
    [ "$epoch_after" -eq "$epoch_before" ] \
      && [ "$generation_after" -gt "$generation_before" ] \
      && [ "$stack_component_after" -eq $((stack_component_before + 1)) ] \
      && [ "$driver_component_after" -eq "$driver_component_before" ] \
      || fail "stack restart did not advance exactly one component incarnation"
  else
    [ "$epoch_after" -gt "$epoch_before" ] \
      && [ "$generation_after" -gt "$generation_before" ] \
      && [ "$stack_component_after" -eq "$stack_component_before" ] \
      && [ "$driver_component_after" -eq $((driver_component_before + 1)) ] \
      || fail "driver restart did not advance exactly one component incarnation"
  fi

  ingress_before=$(session_field "$ingress_field" "$session_line")
  egress_before=$(session_field "$egress_field" "$session_line")
  [ -n "$ingress_before" ] && [ -n "$egress_before" ] \
    || fail "$recovery_kind rejection baselines were malformed"
  release_before=$(fixed_count 'tcp-echo stale release complete')
  release_complete=0
  stale_attempt=0
  stale_ingress=$ingress_before
  stale_egress=$egress_before
  while [ "$stale_attempt" -lt 400 ]; do
    if [ "$release_complete" -eq 0 ]; then
      printf 'tcp-release\n' >&3
    fi
    printf 'tcp-session\n' >&3
    sleep 0.05
    release_after=$(fixed_count 'tcp-echo stale release complete')
    if [ "$release_after" -gt "$release_before" ]; then
      release_complete=1
    fi
    session_line=$(latest_session)
    stale_ingress=$(session_field "$ingress_field" "$session_line")
    stale_egress=$(session_field "$egress_field" "$session_line")
    if [ "$release_complete" -eq 1 ] \
      && [ -n "$stale_ingress" ] && [ -n "$stale_egress" ] \
      && [ "$stale_ingress" -gt "$ingress_before" ] \
      && [ "$stale_egress" -gt "$egress_before" ]; then
      break
    fi
    stale_attempt=$((stale_attempt + 1))
  done
  [ "$release_complete" -eq 1 ] \
    || fail "$recovery_kind stale probes were not fully released"
  stale_ingress=${stale_ingress:-0}
  stale_egress=${stale_egress:-0}
  [ "$stale_ingress" -gt "$ingress_before" ] \
    && [ "$stale_egress" -gt "$egress_before" ] \
    || fail "$recovery_kind stale probes did not increment both coordinate rejection counters"

  : > "$RECOVERY_CONTINUE"
  if ! wait "$PEER_PID"; then
    PEER_PID=""
    fail "$recovery_kind old/new TCP stream assertion failed"
  fi
  PEER_PID=""
  kill -0 "$QEMU_PID" 2>/dev/null \
    || fail "QEMU exited during $recovery_kind recovery"
  sed -n '1,5p' "$PEER_LOG"
  echo "PASS tcp-$recovery_kind-recovery: epoch $epoch_before -> $epoch_after, generation $generation_before -> $generation_after, component incarnation exact, coordinate-stale RX/TX rejected"
}

run_network_config_phase() {
  prompt_attempt=0
  while [ "$prompt_attempt" -lt 400 ]; do
    grep -a -F -q 'vsh> ' "$QEMU_LOG" && break
    kill -0 "$QEMU_PID" 2>/dev/null \
      || fail "QEMU exited before the vsh network configuration check"
    sleep 0.05
    prompt_attempt=$((prompt_attempt + 1))
  done
  grep -a -F -q 'vsh> ' "$QEMU_LOG" \
    || fail "vsh prompt did not become ready"

  printf 'ip link show\n' >&3
  static_attempt=0
  while [ "$static_attempt" -lt 200 ]; do
    grep -a -F -q 'link/ether 02:00:00:00:00:01' "$QEMU_LOG" && break
    sleep 0.05
    static_attempt=$((static_attempt + 1))
  done
  grep -a -F -q 'link/ether 02:00:00:00:00:01' "$QEMU_LOG" \
    || fail "ip link show did not report the configured interface"

  printf 'ip -4 addr show dev net0\n' >&3
  static_attempt=0
  while [ "$static_attempt" -lt 200 ]; do
    grep -a -F -q 'inet 10.0.2.15/24 scope global net0' "$QEMU_LOG" && break
    sleep 0.05
    static_attempt=$((static_attempt + 1))
  done
  grep -a -F -q 'inet 10.0.2.15/24 scope global net0' "$QEMU_LOG" \
    || fail "ip addr show did not report the initial static address"

  echo "$TEST_NAME: switching net0 from static IPv4 to DHCP"
  printf 'dhclient net0\n' >&3
  dhcp_start_attempt=0
  while [ "$dhcp_start_attempt" -lt 200 ]; do
    grep -a -F -q 'DHCP discovery started' "$QEMU_LOG" && break
    sleep 0.05
    dhcp_start_attempt=$((dhcp_start_attempt + 1))
  done
  grep -a -F -q 'DHCP discovery started' "$QEMU_LOG" \
    || fail "dhclient command was not acknowledged"
  dhcp_attempt=0
  while [ "$dhcp_attempt" -lt 400 ]; do
    printf 'ip -4 addr show dev net0\n' >&3
    sleep 0.05
    if grep -a -F -q 'inet 10.0.2.15/24 scope global dynamic net0' "$QEMU_LOG"; then
      break
    fi
    dhcp_attempt=$((dhcp_attempt + 1))
  done
  grep -a -F -q 'inet 10.0.2.15/24 scope global dynamic net0' "$QEMU_LOG" \
    || fail "DHCP did not acquire the QEMU user-network lease"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$QEMU_SMP" in
  ''|*[!0-9]*|0) fail "QEMU_SMP must be a positive integer" ;;
esac
case "$TCP_PORT_ATTEMPTS" in
  ''|*[!0-9]*|0) fail "TCP_PORT_ATTEMPTS must be a positive integer" ;;
esac
if [ -n "$TCP_HOST_PORT" ]; then
  case "$TCP_HOST_PORT" in
    ''|*[!0-9]*) fail "TCP_HOST_PORT must be an integer in the range 1..65535" ;;
  esac
  if [ "$TCP_HOST_PORT" -lt 1 ] || [ "$TCP_HOST_PORT" -gt 65535 ]; then
    fail "TCP_HOST_PORT must be an integer in the range 1..65535"
  fi
fi

for command in rustup python3 "$QEMU_BIN"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    fail "required command not found: $command"
  fi
done

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ]; then
  fail "rust-toolchain.toml must select an exact channel"
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate rustc for toolchain $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate rustdoc for toolchain $toolchain"

if ! python3 -B scripts/tcp-peer.py --selftest >/dev/null; then
  fail "host TCP peer self-test failed"
fi

echo "$TEST_NAME: building kernel feature $TCP_FEATURE"
if ! (cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features "$TCP_FEATURE") >&2; then
  fail "kernel build failed"
fi

TEST_TMP=$(mktemp -d) || fail "cannot create temporary directory"
QEMU_LOG="$TEST_TMP/qemu.log"
PEER_LOG="$TEST_TMP/peer.log"
RECOVERY_READY="$TEST_TMP/recovery-ready"
RECOVERY_CONTINUE="$TEST_TMP/recovery-continue"
QEMU_INPUT="$TEST_TMP/qemu-input"
mkfifo "$QEMU_INPUT" || fail "cannot create QEMU input FIFO"
exec 3<>"$QEMU_INPUT"

dynamic_port=1
if [ -n "$TCP_HOST_PORT" ]; then
  dynamic_port=0
fi

attempt=1
while [ "$attempt" -le "$TCP_PORT_ATTEMPTS" ]; do
  if [ "$dynamic_port" -eq 1 ]; then
    TCP_HOST_PORT=$(python3 -B scripts/tcp-peer.py --pick-port) \
      || fail "cannot select an unused loopback port"
  fi
  : > "$QEMU_LOG"

  echo "$TEST_NAME: starting QEMU (127.0.0.1:$TCP_HOST_PORT -> 10.0.2.15:$TCP_GUEST_PORT)"
  set -- "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
    -accel "$QEMU_ACCEL" \
    -nographic -bios default -kernel "$KERNEL" \
    -netdev "user,id=vibeos-tcp,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${TCP_HOST_PORT}-10.0.2.15:${TCP_GUEST_PORT}" \
    -device "virtio-net-device,netdev=vibeos-tcp,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01" \
    -global virtio-mmio.force-legacy=false
  "$@" <&3 >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!

  # Port-selection and QEMU binding are separate operations.  If another
  # process wins that race, QEMU fails immediately and a fresh port is tried.
  sleep 0.25
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
    if [ "$dynamic_port" -eq 1 ] \
      && [ "$attempt" -lt "$TCP_PORT_ATTEMPTS" ] \
      && grep -a -qi 'could not set up host forwarding rule' "$QEMU_LOG"; then
      echo "$TEST_NAME: host port $TCP_HOST_PORT was claimed; retrying"
      attempt=$((attempt + 1))
      continue
    fi
    fail "QEMU exited before the guest listener became ready"
  fi

  if [ "$TCP_TEST_MODE" = "recovery" ]; then
    run_recovery_phase stack
    run_recovery_phase device
    RESULT_REPORTED=1
    echo "PASS tcp-recovery: stack generation and device epoch recovery both rejected retired traffic"
    exit 0
  fi

  run_network_config_phase

  echo "$TEST_NAME: waiting up to ${TCP_TIMEOUT}s for an exact byte-stream echo"
  if python3 -B scripts/tcp-peer.py \
    --port "$TCP_HOST_PORT" --timeout "$TCP_TIMEOUT"; then
    RESULT_REPORTED=1
    echo "PASS $TEST_NAME: exact echo through QEMU host forwarding"
    exit 0
  fi

  # A bind race can also surface between the initial liveness check and the
  # client attempt.  Only retry that diagnosed case; guest failures stay loud.
  if [ "$dynamic_port" -eq 1 ] \
    && [ "$attempt" -lt "$TCP_PORT_ATTEMPTS" ] \
    && ! kill -0 "$QEMU_PID" 2>/dev/null \
    && grep -a -qi 'could not set up host forwarding rule' "$QEMU_LOG"; then
    stop_qemu
    echo "$TEST_NAME: host port $TCP_HOST_PORT was claimed; retrying"
    attempt=$((attempt + 1))
    continue
  fi
  fail "guest did not return the deterministic payload exactly"
done

fail "could not bind a loopback host-forward port after $TCP_PORT_ATTEMPTS attempts"
