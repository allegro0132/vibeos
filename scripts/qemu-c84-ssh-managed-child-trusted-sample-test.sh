#!/bin/sh
# C8.4 real SSH trusted terminal-evidence/opaque-sample/discard gate.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
C84_SSH_TIMEOUT=${C84_SSH_TIMEOUT:-180}
C84_SSH_READY_TIMEOUT=${C84_SSH_READY_TIMEOUT:-45}
C84_SSH_COMMAND_TIMEOUT=${C84_SSH_COMMAND_TIMEOUT:-20}
C84_SSH_MARKER_TIMEOUT=${C84_SSH_MARKER_TIMEOUT:-20}
FEATURE=wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance
FAMILY='WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE'
FINISH_FAMILY='WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY'
IRQ_FAMILY='WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY'
PHASE_FAMILY='WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR'
CORE_FAMILY='WASM_C84_SSH_MANAGED_CHILD_CORE'
REQUEST_FAMILY='WASM_C84_SSH_REQUEST_PARENT'

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
    echo 'FAIL qemu-c84-ssh-managed-child-trusted-sample-test: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-c84-ssh-managed-child-trusted-sample-test: $*" >&2
  if [ -n "$PEER_LOG" ] && [ -s "$PEER_LOG" ]; then
    echo '--- OpenSSH driver output ---' >&2
    tail -100 "$PEER_LOG" >&2 || true
  fi
  if [ -n "$QEMU_LOG" ] && [ -s "$QEMU_LOG" ]; then
    echo '--- QEMU serial output (last 300 lines) ---' >&2
    tail -300 "$QEMU_LOG" >&2 || true
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
  grep -a -F -c "$1" "$QEMU_LOG" || true
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

# Freeze the portable publisher and both alternate finish successors before the
# trusted producer. The trusted feature itself inherits finish/verify directly;
# it must never borrow the verified-stream transcript or publish a SAMPLE.
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source >&2 \
  || fail 'portable publisher verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source >&2 \
  || fail 'static finish/verify/discard verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source >&2 \
  || fail 'static verified-stream sibling verification failed'
python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py --selftest --check-source >&2 \
  || fail 'static trusted-sample verification failed'
python3 -B scripts/openssh-test-key.py --selftest >/dev/null \
  || fail 'OpenSSH key fixture self-test failed'
python3 -B scripts/openssh-peer.py --selftest >/dev/null \
  || fail 'maintained OpenSSH peer self-test failed'
python3 -B scripts/c84-ssh-managed-child-finish-verify-peer.py --selftest >/dev/null \
  || fail 'finish/verify parser self-test failed'
python3 -B scripts/c84-ssh-managed-child-verified-stream-peer.py --selftest >/dev/null \
  || fail 'verified-stream parser self-test failed'
python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py --selftest >/dev/null \
  || fail 'trusted-sample parser self-test failed'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate pinned rustc for $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate pinned rustdoc for $toolchain"

echo 'qemu-c84-ssh-managed-child-trusted-sample-test: building isolated single-hart OpenSSH image'
if ! (cd firmware/qemu-virt && \
  RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --locked --no-default-features \
    --features "$FEATURE") >&2; then
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

if ! python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py \
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
  fail 'real OpenSSH trusted-sample sequence failed'
fi

kill -0 "$QEMU_PID" 2>/dev/null || fail 'QEMU exited during the OpenSSH sequence'
trusted_count_before=$(family_count "$FAMILY")
[ "$trusted_count_before" -eq 4 ] \
  || fail "closed peer transcript did not contain exactly 4 trusted-sample markers: $trusted_count_before"
finish_count_before=$(family_count "$FINISH_FAMILY")
[ "$finish_count_before" -eq 4 ] \
  || fail "closed peer transcript did not preserve exactly 4 finish/verify markers: $finish_count_before"
irq_count_before=$(family_count "$IRQ_FAMILY")
[ "$irq_count_before" -eq 6 ] \
  || fail "closed peer transcript did not preserve exactly 6 IRQ markers: $irq_count_before"
phase_count_before=$(family_count "$PHASE_FAMILY")
case "$phase_count_before" in
  27|28) ;;
  *) fail "closed peer transcript did not preserve 27/28 phase markers: $phase_count_before" ;;
esac
core_count_before=$(family_count "$CORE_FAMILY")
[ "$core_count_before" -eq 19 ] \
  || fail "closed peer transcript did not preserve exactly 19 Core markers: $core_count_before"
request_count_before=$(family_count "$REQUEST_FAMILY")
[ "$request_count_before" -eq 8 ] \
  || fail "closed peer transcript did not preserve exactly 8 request markers: $request_count_before"

sleep 0.2
trusted_count_after=$(family_count "$FAMILY")
finish_count_after=$(family_count "$FINISH_FAMILY")
irq_count_after=$(family_count "$IRQ_FAMILY")
phase_count_after=$(family_count "$PHASE_FAMILY")
core_count_after=$(family_count "$CORE_FAMILY")
request_count_after=$(family_count "$REQUEST_FAMILY")
[ "$trusted_count_after" -eq "$trusted_count_before" ] || fail 'late trusted marker arrived after peer closure'
[ "$finish_count_after" -eq "$finish_count_before" ] || fail 'late finish marker arrived after peer closure'
[ "$irq_count_after" -eq "$irq_count_before" ] || fail 'late IRQ marker arrived after peer closure'
[ "$phase_count_after" -eq "$phase_count_before" ] || fail 'late phase marker arrived after peer closure'
[ "$core_count_after" -eq "$core_count_before" ] || fail 'late Core marker arrived after peer closure'
[ "$request_count_after" -eq "$request_count_before" ] || fail 'late request marker arrived after peer closure'

# Stop the UART producer before the final exact parse so a partial late record
# cannot be hidden or admitted.
stop_qemu
trusted_count_frozen=$(family_count "$FAMILY")
finish_count_frozen=$(family_count "$FINISH_FAMILY")
irq_count_frozen=$(family_count "$IRQ_FAMILY")
phase_count_frozen=$(family_count "$PHASE_FAMILY")
core_count_frozen=$(family_count "$CORE_FAMILY")
request_count_frozen=$(family_count "$REQUEST_FAMILY")
[ "$trusted_count_frozen" -eq "$trusted_count_after" ] || fail 'trusted marker arrived while freezing QEMU'
[ "$finish_count_frozen" -eq "$finish_count_after" ] || fail 'finish marker arrived while freezing QEMU'
[ "$irq_count_frozen" -eq "$irq_count_after" ] || fail 'IRQ marker arrived while freezing QEMU'
[ "$phase_count_frozen" -eq "$phase_count_after" ] || fail 'phase marker arrived while freezing QEMU'
[ "$core_count_frozen" -eq "$core_count_after" ] || fail 'Core marker arrived while freezing QEMU'
[ "$request_count_frozen" -eq "$request_count_after" ] || fail 'request marker arrived while freezing QEMU'

if grep -a -E -q 'WASM_[A-Z0-9_]+ FAIL|\[!\] (fatal|panic)|panicked at' "$QEMU_LOG"; then
  fail 'guest reported a WASM failure, panic, or fatal error'
fi
if grep -a -E -q 'WASM_C48_ACCEPTANCE|WASM_C53(_NATIVE_SSH)?_ACCEPTANCE|WASM_C84_(PROFILE_SLOT|CORE_POLL|PROFILE_CHILD_DELEGATION|PROFILE_IRQ_OVERLAY)' "$QEMU_LOG"; then
  fail 'diagnostic image unexpectedly published a formal or isolated acceptance result'
fi
if grep -a -E -q "(${FAMILY}|${FINISH_FAMILY}|${IRQ_FAMILY}|${PHASE_FAMILY}|${CORE_FAMILY}|${REQUEST_FAMILY}) (PASS|META|SAMPLE|END|PUBLISH|PUBLISHER|SCHEMA|COLLECTOR)([ =]|$)" "$QEMU_LOG"; then
  fail 'diagnostic image emitted forbidden publisher, schema, collector, or formal telemetry'
fi
foreign_families=$(grep -a -o -E 'WASM_[A-Z0-9_]+' "$QEMU_LOG" \
  | sort -u \
  | grep -E -v "^(${FAMILY}|${FINISH_FAMILY}|${IRQ_FAMILY}|${PHASE_FAMILY}|${CORE_FAMILY}|${REQUEST_FAMILY})$" || true)
[ -z "$foreign_families" ] \
  || fail "diagnostic image emitted foreign WASM families: $foreign_families"

python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py \
  --verify-log-only --qemu-log "$QEMU_LOG" >&2 \
  || fail 'frozen trusted/finish/IRQ/phase/Core/request transcript verification failed'

RESULT_REPORTED=1
sed -n '1,8p' "$PEER_LOG"
echo 'PASS qemu-c84-ssh-managed-child-trusted-sample-test: epochs 1/2/4 proved exact Success, full SSH/Component drain, formal IO and nonsaturated runtime metrics, minted one opaque trusted bundle, discarded and acknowledged it to clean Ready; epoch 3 minted no bundle and every predecessor remained exact on one QEMU hart (integration evidence only)'
