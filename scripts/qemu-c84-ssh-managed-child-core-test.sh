#!/bin/sh
# C8.4 real managed-child and ordinary Core-observer OpenSSH gate.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
C84_SSH_TIMEOUT=${C84_SSH_TIMEOUT:-180}
C84_SSH_READY_TIMEOUT=${C84_SSH_READY_TIMEOUT:-45}
C84_SSH_COMMAND_TIMEOUT=${C84_SSH_COMMAND_TIMEOUT:-20}
C84_SSH_MARKER_TIMEOUT=${C84_SSH_MARKER_TIMEOUT:-20}
FEATURE=wasm-c84-ssh-managed-child-core-qemu-acceptance
FAMILY='WASM_C84_SSH_MANAGED_CHILD_CORE'
REQUEST_PARENT_FAMILY='WASM_C84_SSH_REQUEST_PARENT'

TEST_TMP=""
QEMU_PID=""
KILLER_PID=""
QEMU_LOG=""
PEER_LOG=""
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
    rm -f "$TEST_TMP/known_hosts" "$TEST_TMP/host_key" "$TEST_TMP/qemu.log" "$TEST_TMP/peer.log"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-c84-ssh-managed-child-core-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c84-ssh-managed-child-core-test: $*" >&2
  if [ -n "$PEER_LOG" ] && [ -s "$PEER_LOG" ]; then
    echo '--- OpenSSH driver output ---' >&2
    tail -100 "$PEER_LOG" >&2 || true
  fi
  if [ -n "$QEMU_LOG" ] && [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU serial output (last 200 lines) ---' >&2
    tail -200 "$QEMU_LOG" >&2 || true
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

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

positive_integer "$C84_SSH_TIMEOUT" C84_SSH_TIMEOUT
positive_integer "$C84_SSH_READY_TIMEOUT" C84_SSH_READY_TIMEOUT
positive_integer "$C84_SSH_COMMAND_TIMEOUT" C84_SSH_COMMAND_TIMEOUT
positive_integer "$C84_SSH_MARKER_TIMEOUT" C84_SSH_MARKER_TIMEOUT

for command in rustup python3 ssh ssh-keygen "$QEMU_BIN"; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

python3 -B scripts/verify-c84-ssh-profile-request-parent.py --selftest --check-source >&2 \
  || fail 'static request-parent ownership verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-core.py --selftest --check-source >&2 \
  || fail 'static managed-child/Core ownership verification failed'
python3 -B scripts/openssh-test-key.py --selftest >/dev/null \
  || fail 'OpenSSH key fixture self-test failed'
python3 -B scripts/openssh-peer.py --selftest >/dev/null \
  || fail 'maintained OpenSSH peer self-test failed'
python3 -B scripts/c84-ssh-managed-child-core-peer.py --selftest >/dev/null \
  || fail 'managed-child marker parser self-test failed'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate pinned rustc for $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate pinned rustdoc for $toolchain"

echo 'qemu-c84-ssh-managed-child-core-test: building isolated single-hart OpenSSH image'
if ! (cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --features "$FEATURE") >&2; then
  fail 'kernel build failed'
fi

TEST_TMP=$(mktemp -d) || fail 'cannot create temporary directory'
ACCEPTED_KEY="$TEST_TMP/id_ed25519_accepted"
REJECTED_KEY="$TEST_TMP/id_ed25519_rejected"
KNOWN_HOSTS="$TEST_TMP/known_hosts"
HOST_KEY="$TEST_TMP/host_key"
QEMU_LOG="$TEST_TMP/qemu.log"
PEER_LOG="$TEST_TMP/peer.log"

python3 -B scripts/openssh-test-key.py \
  --fixture accepted --comment vibeos-c84-accepted-test-only --output "$ACCEPTED_KEY" \
  >/dev/null || fail 'cannot generate accepted OpenSSH fixture'
python3 -B scripts/openssh-test-key.py \
  --fixture rejected --comment vibeos-c84-rejected-test-only --output "$REJECTED_KEY" \
  >/dev/null || fail 'cannot generate rejected OpenSSH fixture'

SSH_HOST_PORT=$(python3 -B scripts/openssh-peer.py --pick-port) \
  || fail 'cannot select an unused loopback port'
positive_integer "$SSH_HOST_PORT" SSH_HOST_PORT

"$QEMU_BIN" \
  -machine virt -cpu rv64 -smp 1 -m 128M \
  -accel tcg,thread=single -nographic -bios default -kernel "$KERNEL" \
  -object rng-random,id=vibeos-c84-ssh-rng,filename=/dev/urandom \
  -device virtio-rng-device,rng=vibeos-c84-ssh-rng,bus=virtio-mmio-bus.1 \
  -netdev "user,id=vibeos-c84-ssh,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${SSH_HOST_PORT}-10.0.2.15:2222" \
  -device virtio-net-device,netdev=vibeos-c84-ssh,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01 \
  -global virtio-mmio.force-legacy=false \
  </dev/null >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!
(sleep "$C84_SSH_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true) &
KILLER_PID=$!

if ! python3 -B scripts/c84-ssh-managed-child-core-peer.py \
  --host localhost \
  --port "$SSH_HOST_PORT" \
  --accepted-key "$ACCEPTED_KEY" \
  --rejected-key "$REJECTED_KEY" \
  --known-hosts "$KNOWN_HOSTS" \
  --host-key-output "$HOST_KEY" \
  --qemu-log "$QEMU_LOG" \
  --ready-timeout "$C84_SSH_READY_TIMEOUT" \
  --command-timeout "$C84_SSH_COMMAND_TIMEOUT" \
  --marker-timeout "$C84_SSH_MARKER_TIMEOUT" \
  >"$PEER_LOG" 2>&1; then
  fail 'real OpenSSH managed-child/Core sequence failed'
fi

kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited during the OpenSSH sequence'
family_count_before=$(grep -a -F -c "$FAMILY" "$QEMU_LOG" || true)
[ "$family_count_before" -eq 19 ] \
  || fail "closed peer transcript did not contain exactly 19 managed-child markers: $family_count_before"
sleep 0.2
family_count_after=$(grep -a -F -c "$FAMILY" "$QEMU_LOG" || true)
[ "$family_count_after" -eq "$family_count_before" ] \
  || fail "late managed-child marker arrived after peer closure: before=$family_count_before after=$family_count_after"
stop_qemu
family_count_frozen=$(grep -a -F -c "$FAMILY" "$QEMU_LOG" || true)
[ "$family_count_frozen" -eq "$family_count_after" ] \
  || fail "managed-child marker arrived while freezing QEMU: before=$family_count_after frozen=$family_count_frozen"
if grep -a -E -q 'WASM_[A-Z0-9_]+ FAIL' "$QEMU_LOG" \
  || grep -a -F -q "$REQUEST_PARENT_FAMILY FAIL" "$QEMU_LOG"; then
  fail 'guest reported a managed-child or request-parent failure after the final response'
fi
if grep -a -E -q '\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
  fail 'guest reported a panic or fatal error'
fi
if grep -a -E -q 'WASM_C48_ACCEPTANCE|WASM_C53_NATIVE_SSH_ACCEPTANCE|WASM_C84_(PROFILE_SLOT|CORE_POLL|PROFILE_CHILD_DELEGATION|PROFILE_IRQ_OVERLAY)' "$QEMU_LOG"; then
  fail 'diagnostic image unexpectedly published a formal or isolated acceptance result'
fi
python3 -B scripts/verify-c84-ssh-profile-request-parent.py --qemu-log "$QEMU_LOG" >&2 \
  || fail 'closed request-parent UART sequence verification failed'

RESULT_REPORTED=1
sed -n '1,8p' "$PEER_LOG"
echo 'PASS qemu-c84-ssh-managed-child-core-test: real OpenSSH exact target admission, clean managed-child/Core release, CORE-first active-Drop cleanup, post-Drop readiness, replacement reuse, identity/crypto, and diagnostic-only isolation passed on one QEMU hart (integration evidence only)'
