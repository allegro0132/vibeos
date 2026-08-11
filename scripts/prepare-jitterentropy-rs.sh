#!/bin/sh
set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
submodule="$repo_root/vendor/jitterentropy-rs"
patch_file="$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch"
expected=c5bd2e17194fe3a04d17f74027bb67622579405f

if [ ! -e "$submodule/.git" ]; then
  echo "prepare-jitterentropy-rs: missing submodule; run:" >&2
  echo "  git submodule update --init vendor/jitterentropy-rs" >&2
  exit 1
fi

actual=$(git -C "$submodule" rev-parse HEAD)
if [ "$actual" != "$expected" ]; then
  echo "prepare-jitterentropy-rs: expected $expected, found $actual" >&2
  exit 1
fi

if git -C "$submodule" apply --unidiff-zero --reverse --check "$patch_file" >/dev/null 2>&1; then
  observed=$(mktemp "${TMPDIR:-/tmp}/vibeos-jitterentropy-patch.XXXXXX")
  trap 'rm -f "$observed"' EXIT
  git -C "$submodule" diff --unified=0 --binary >"$observed"
  if ! cmp -s "$patch_file" "$observed"; then
    echo "prepare-jitterentropy-rs: applied tree differs from the recorded patch" >&2
    exit 1
  fi
  echo "jitterentropy-rs: VibeOS patch already applied"
elif git -C "$submodule" apply --unidiff-zero --check "$patch_file"; then
  git -C "$submodule" apply --unidiff-zero "$patch_file"
  echo "jitterentropy-rs: applied VibeOS qualification patch"
else
  echo "prepare-jitterentropy-rs: submodule has unexpected modifications" >&2
  exit 1
fi
