#!/bin/sh
# Build and boot the QEMU-only N3 entropy/identity acceptance image twice.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-kernel
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
QEMU_ACCEL=${QEMU_ACCEL:-tcg}
SSH_SECURITY_TIMEOUT=${SSH_SECURITY_TIMEOUT:-20}
TEST_TMP=""
QEMU_PID=""
KILLER_PID=""

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  if [ -n "$KILLER_PID" ]; then
    kill "$KILLER_PID" 2>/dev/null || true
    wait "$KILLER_PID" 2>/dev/null || true
  fi
  if [ -n "$TEST_TMP" ]; then
    rm -f "$TEST_TMP/boot-1.log" "$TEST_TMP/boot-2.log"
    rmdir "$TEST_TMP" 2>/dev/null || true
  fi
  exit "$status"
}

fail() {
  echo "FAIL ssh-security-test: $*" >&2
  exit 1
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$SSH_SECURITY_TIMEOUT" in
  ''|*[!0-9]*|0) fail "SSH_SECURITY_TIMEOUT must be a positive integer" ;;
esac

for command in rustup "$QEMU_BIN"; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail "rust-toolchain.toml must select an exact channel"
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) \
  || fail "cannot locate rustc for $toolchain"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) \
  || fail "cannot locate rustdoc for $toolchain"

echo "ssh-security-test: building the explicit test-identity image"
(cd kernel && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features ssh-security-test) >&2 \
  || fail "kernel build failed"

TEST_TMP=$(mktemp -d) || fail "cannot create temporary directory"

boot_once() {
  boot=$1
  log="$TEST_TMP/boot-$boot.log"
  echo "ssh-security-test: QEMU boot $boot" >&2
  "$QEMU_BIN" \
    -machine virt -cpu rv64 -smp 1 -m 128M \
    -accel "$QEMU_ACCEL" \
    -nographic -bios default -kernel "$KERNEL" \
    -object "rng-random,id=vibeos-rng-$boot,filename=/dev/urandom" \
    -device "virtio-rng-device,rng=vibeos-rng-$boot,bus=virtio-mmio-bus.0" \
    -global virtio-mmio.force-legacy=false \
    </dev/null >"$log" 2>&1 &
  QEMU_PID=$!
  ( sleep "$SSH_SECURITY_TIMEOUT"; kill "$QEMU_PID" 2>/dev/null || true ) &
  KILLER_PID=$!
  wait "$QEMU_PID" 2>/dev/null || true
  QEMU_PID=""
  kill "$KILLER_PID" 2>/dev/null || true
  wait "$KILLER_PID" 2>/dev/null || true
  KILLER_PID=""

  grep -a -F -q 'N3 SSH SECURITY TEST IDENTITY -- NOT FOR PRODUCTION' "$log" \
    || fail "boot $boot did not identify the deterministic test image"
  grep -a -F -q 'ssh-security virtio-rng PASS: bounded 64-byte transport sample' "$log" \
    || fail "boot $boot did not obtain a bounded virtio-rng transport sample"
  grep -a -F -q 'ssh-security DRBG PASS: distinct audited domain streams' "$log" \
    || fail "boot $boot did not prove random-domain separation"
  grep -a -F -q 'ssh-security auth PASS: profile 1 accepted, alternate key rejected' "$log" \
    || fail "boot $boot did not enforce the immutable binary auth policy"
  grep -a -F -q 'PASS ssh-security-test' "$log" \
    || fail "boot $boot did not reach the final acceptance marker"
  if grep -a -F -q 'FAIL ssh-security-test:' "$log"; then
    fail "boot $boot reported an in-guest failure"
  fi

  key=$(sed -n 's/.*ssh-security signer PASS: generation 1 host-key \([0-9a-f]\{64\}\).*/\1/p' "$log" \
    | tail -1)
  marker=$(sed -n 's/.*ssh-security freshness marker: \([0-9a-f]\{128\}\).*/\1/p' "$log" \
    | tail -1)
  [ -n "$key" ] || fail "boot $boot did not publish an exact binary host key"
  [ -n "$marker" ] || fail "boot $boot did not publish a signed transport-freshness marker"
  printf '%s %s\n' "$key" "$marker"
}

boot_one=$(boot_once 1)
boot_two=$(boot_once 2)
key_one=${boot_one%% *}
key_two=${boot_two%% *}
marker_one=${boot_one#* }
marker_two=${boot_two#* }
[ "$key_one" = "$key_two" ] || fail "test host identity changed across reboot"
[ "$marker_one" != "$marker_two" ] \
  || fail "signed virtio-rng transport sample repeated across boots"

echo "PASS ssh-security-test: virtio-rng transport/freshness smoke, zeroizing domain DRBG, opaque signer, binary auth, stable test identity"
