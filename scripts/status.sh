#!/bin/sh
# Print current repository/test inventory as stable key=value records.
# Use --check in CI to require the rustc commit recorded beside the exact pin.
set -eu
LC_ALL=C
export LC_ALL
cd "$(dirname "$0")/.."
./scripts/prepare-jitterentropy-rs.sh

case $# in
  0) check=0 ;;
  1)
    if [ "$1" != "--check" ]; then
      echo "usage: $0 [--check]" >&2
      exit 2
    fi
    check=1
    ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

RUSTC=${RUSTC:-}
CARGO=${CARGO:-}
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
expected_commit=$(sed -n 's/^# rustc-commit: \([0-9a-f][0-9a-f]*\)$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || [ -z "$expected_commit" ]; then
  echo "status: malformed rust-toolchain.toml" >&2
  exit 1
fi

if { [ -z "$RUSTC" ] || [ -z "$CARGO" ]; } && ! command -v rustup >/dev/null 2>&1; then
  echo "status: rustup is required to inspect pinned toolchain $toolchain" >&2
  exit 1
fi
if [ -z "$CARGO" ]; then
  pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
  pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
fi
run_rustc() {
  if [ -n "$RUSTC" ]; then
    "$RUSTC" "$@"
  else
    rustup run "$toolchain" rustc "$@"
  fi
}
run_cargo() {
  if [ -n "$CARGO" ]; then
    "$CARGO" "$@"
  else
    RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
      rustup run "$toolchain" cargo "$@"
  fi
}

if rustc_version=$(run_rustc -Vv 2>/dev/null); then
  actual_commit=$(printf '%s\n' "$rustc_version" | sed -n 's/^commit-hash: //p')
else
  actual_commit=unavailable
fi
if [ "$actual_commit" = "$expected_commit" ]; then
  toolchain_match=true
else
  toolchain_match=false
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/vibeos-status.XXXXXX")
# shellcheck disable=SC2329 # Invoked by the EXIT trap below.
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! run_cargo test --workspace \
  --exclude vibeos-kernel \
  --exclude vibeos-firmware-qemu-virt \
  --exclude vibeos-firmware-milkv-duo -- --list --format terse \
  >"$tmpdir/host-tests" 2>"$tmpdir/cargo.stderr"; then
  sed -n '1,40p' "$tmpdir/cargo.stderr" >&2
  echo "status: cargo could not enumerate host tests" >&2
  exit 1
fi
if ! run_cargo test --manifest-path vendor/sunset/Cargo.toml -p sunset \
  --no-default-features --features alloc -- --list --format terse \
  >>"$tmpdir/host-tests" 2>"$tmpdir/sunset-cargo.stderr"; then
  sed -n '1,40p' "$tmpdir/sunset-cargo.stderr" >&2
  echo "status: cargo could not enumerate Sunset host tests" >&2
  exit 1
fi
if ! run_cargo test --workspace \
  --exclude vibeos-kernel \
  --exclude vibeos-firmware-qemu-virt \
  --exclude vibeos-firmware-milkv-duo -- --list --ignored --format terse \
  >"$tmpdir/ignored-tests" 2>"$tmpdir/cargo-ignored.stderr"; then
  sed -n '1,40p' "$tmpdir/cargo-ignored.stderr" >&2
  echo "status: cargo could not enumerate ignored host tests" >&2
  exit 1
fi
if ! run_cargo test --manifest-path vendor/sunset/Cargo.toml -p sunset \
  --no-default-features --features alloc -- --list --ignored --format terse \
  >>"$tmpdir/ignored-tests" 2>"$tmpdir/sunset-cargo-ignored.stderr"; then
  sed -n '1,40p' "$tmpdir/sunset-cargo-ignored.stderr" >&2
  echo "status: cargo could not enumerate ignored Sunset host tests" >&2
  exit 1
fi
host_tests_discovered=$(awk '/: test$/ { count++ } END { print count + 0 }' "$tmpdir/host-tests")
host_tests_ignored=$(awk '/: test$/ { count++ } END { print count + 0 }' "$tmpdir/ignored-tests")
host_tests=$((host_tests_discovered - host_tests_ignored))

count_files() {
  count=0
  for path in "$1"/*."$2"; do
    [ -f "$path" ] || continue
    count=$((count + 1))
  done
  printf '%s\n' "$count"
}

qemu_cases=$(count_files tests/cases in)
golden_transcripts=$(count_files tests/golden txt)
differential_programs=$(count_files tests/programs rs)
differential_expectations=$(count_files tests/programs expected)
differential_pairs_match=true
for src in tests/programs/*.rs; do
  [ -f "$src" ] || continue
  if [ ! -f "${src%.rs}.expected" ]; then
    differential_pairs_match=false
  fi
done
for out in tests/programs/*.expected; do
  [ -f "$out" ] || continue
  if [ ! -f "${out%.expected}.rs" ]; then
    differential_pairs_match=false
  fi
done

printf 'toolchain=%s\n' "$toolchain"
printf 'rustc_expected_commit=%s\n' "$expected_commit"
printf 'rustc_actual_commit=%s\n' "$actual_commit"
printf 'rustc_matches_pin=%s\n' "$toolchain_match"
printf 'host_tests=%s\n' "$host_tests"
printf 'host_tests_ignored=%s\n' "$host_tests_ignored"
printf 'host_tests_discovered=%s\n' "$host_tests_discovered"
printf 'qemu_cases=%s\n' "$qemu_cases"
printf 'golden_transcripts=%s\n' "$golden_transcripts"
printf 'differential_programs=%s\n' "$differential_programs"
printf 'differential_expectations=%s\n' "$differential_expectations"
printf 'differential_pairs_match=%s\n' "$differential_pairs_match"

if [ "$check" = "1" ] && [ "$toolchain_match" != "true" ]; then
  echo "status: active rustc does not match rust-toolchain.toml" >&2
  exit 1
fi
if [ "$check" = "1" ] && [ "$differential_pairs_match" != "true" ]; then
  echo "status: differential sources and expectations are not paired" >&2
  exit 1
fi
