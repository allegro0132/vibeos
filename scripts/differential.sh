#!/bin/sh
# Differential testing: compile each corpus program with the pinned real rustc,
# run it, and compare its exact output with the committed expectation. Every
# program in tests/programs/ is valid Rust *and* valid in the VibeOS subset, so
# rustc is a free oracle for our code generator.
#
# Verification is read-only. Pass --update to replace expectations intentionally;
# the QEMU `differential` case then checks that VibeOS agrees with those bytes.
set -eu
LC_ALL=C
export LC_ALL
cd "$(dirname "$0")/.."

case $# in
  0) update=0 ;;
  1)
    if [ "$1" != "--update" ]; then
      echo "usage: $0 [--update]" >&2
      exit 2
    fi
    update=1
    ;;
  *)
    echo "usage: $0 [--update]" >&2
    exit 2
    ;;
esac

RUSTC=${RUSTC:-}
CORPUS_DIR=${CORPUS_DIR:-tests/programs}
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
expected_commit=$(sed -n 's/^# rustc-commit: \([0-9a-f][0-9a-f]*\)$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || [ -z "$expected_commit" ]; then
  echo "FAIL: rust-toolchain.toml has no exact channel/commit record" >&2
  exit 1
fi

if [ -z "$RUSTC" ] && ! command -v rustup >/dev/null 2>&1; then
  echo "FAIL: rustup is required to run the pinned $toolchain compiler" >&2
  exit 1
fi
run_rustc() {
  if [ -n "$RUSTC" ]; then
    "$RUSTC" "$@"
  else
    rustup run "$toolchain" rustc "$@"
  fi
}

if ! rustc_version=$(run_rustc -Vv 2>/dev/null); then
  echo "FAIL: cannot run rustc from pinned toolchain $toolchain" >&2
  exit 1
fi
actual_commit=$(printf '%s\n' "$rustc_version" | sed -n 's/^commit-hash: //p')
if [ "$actual_commit" != "$expected_commit" ]; then
  echo "FAIL: rustc commit $actual_commit does not match pinned $expected_commit" >&2
  echo "      install the toolchain from rust-toolchain.toml with rustup" >&2
  exit 1
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/vibeos-differential.XXXXXX")
pending_update=
# shellcheck disable=SC2329 # Invoked by the EXIT trap below.
cleanup() {
  if [ -n "$pending_update" ]; then
    rm -f "$pending_update"
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sources=0
for src in "$CORPUS_DIR"/*.rs; do
  [ -f "$src" ] || continue
  sources=$((sources + 1))
done

if [ "$sources" -eq 0 ]; then
  echo "FAIL: no Rust programs found in $CORPUS_DIR" >&2
  exit 1
fi

# An orphan expectation would be concatenated into the QEMU oracle even though
# no Rust source regenerated it, so reject it in both verify and update modes.
for out in "$CORPUS_DIR"/*.expected; do
  [ -f "$out" ] || continue
  src=${out%.expected}.rs
  if [ ! -f "$src" ]; then
    echo "FAIL: orphan expectation $out has no matching $src" >&2
    exit 1
  fi
done

fail=0
for src in "$CORPUS_DIR"/*.rs; do
  name=$(basename "$src" .rs)
  out="$CORPUS_DIR/$name.expected"
  bin="$tmpdir/$name"
  actual="$tmpdir/$name.actual"
  errors="$tmpdir/$name.stderr"

  # -A warnings: the corpus is written in the subset's style (explicit returns,
  # no iterators), which is idiomatic here and noisy to rustc.
  if ! run_rustc --edition 2021 -O -A warnings -o "$bin" "$src" 2>"$errors"; then
    echo "FAIL $name: real rustc rejected it -- the corpus must stay valid Rust"
    sed -n '1,10s/^/     /p' "$errors"
    fail=1
    continue
  fi

  if ! "$bin" >"$actual"; then
    echo "FAIL $name: real-rustc binary exited unsuccessfully"
    fail=1
    continue
  fi

  if [ "$update" = "1" ]; then
    # Publish only after every corpus program compiled and ran successfully.
    continue
  elif [ ! -f "$out" ]; then
    echo "FAIL     $name: missing $out; run with --update to create it"
    fail=1
  elif cmp -s "$out" "$actual"; then
    echo "ok       $name"
  else
    echo "FAIL     $name: rustc output changed"
    diff -u "$out" "$actual" | sed -n '1,80p' || true
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit "$fail"
fi

if [ "$update" = "1" ]; then
  for src in "$CORPUS_DIR"/*.rs; do
    name=$(basename "$src" .rs)
    out="$CORPUS_DIR/$name.expected"
    actual="$tmpdir/$name.actual"
    pending_update=$(mktemp "$CORPUS_DIR/.$name.expected.XXXXXX")
    cp "$actual" "$pending_update"
    chmod 0644 "$pending_update"
    mv "$pending_update" "$out"
    pending_update=
    echo "recorded $name"
  done
fi

exit $fail
