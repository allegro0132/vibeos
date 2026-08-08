#!/bin/sh
# Differential testing: compile each corpus program with the real rustc, run it,
# and record the output. Every program in tests/programs/ is valid Rust *and*
# valid in the VibeOS subset, so rustc is a free oracle for our code generator.
#
# This script produces the expectations. The QEMU `differential` case checks
# that VibeOS agrees with them.
set -eu
cd "$(dirname "$0")/.."

fail=0
for src in tests/programs/*.rs; do
  name=$(basename "$src" .rs)
  out="tests/programs/$name.expected"
  bin="$(mktemp -d)/$name"

  # -A warnings: the corpus is written in the subset's style (explicit returns,
  # no iterators), which is idiomatic here and noisy to rustc.
  if ! rustc --edition 2021 -O -A warnings -o "$bin" "$src" 2>/tmp/rustc.err; then
    echo "FAIL $name: real rustc rejected it -- the corpus must stay valid Rust"
    sed 's/^/     /' /tmp/rustc.err | head -10
    fail=1
    continue
  fi

  actual="$("$bin")"
  if [ "${1:-}" = "--update" ] || [ ! -f "$out" ]; then
    printf '%s\n' "$actual" > "$out"
    echo "recorded $name"
  elif [ "$actual" = "$(cat "$out")" ]; then
    echo "ok       $name"
  else
    echo "FAIL     $name: rustc output changed"
    diff -u "$out" /dev/stdin <<EOF2
$actual
EOF2
    fail=1
  fi
done
exit $fail
