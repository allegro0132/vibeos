#!/bin/sh
set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
submodule="$repo_root/vendor/jitterentropy-rs"
patch_file="$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch"
generated_root="$repo_root/target/vendor"
destination="$generated_root/jitterentropy-rs"
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
if [ -n "$(git -C "$submodule" status --porcelain --untracked-files=all)" ]; then
  echo "prepare-jitterentropy-rs: submodule must remain pristine and read-only" >&2
  git -C "$submodule" status --short >&2
  exit 1
fi

mkdir -p "$generated_root"
staging=$(mktemp -d "$generated_root/.jitterentropy-rs.XXXXXX")
cleanup() {
  if [ -n "$staging" ]; then
    rm -rf -- "$staging"
  fi
}
trap cleanup EXIT HUP INT TERM

git -C "$submodule" archive --format=tar "$expected" | tar -xf - -C "$staging"
patch -s -d "$staging" -p1 --batch --forward <"$patch_file"

case "$destination" in
  "$repo_root"/target/vendor/jitterentropy-rs) ;;
  *) echo "prepare-jitterentropy-rs: unsafe generated destination" >&2; exit 1 ;;
esac
rm -rf -- "$destination"
mv "$staging" "$destination"
staging=

echo "jitterentropy-rs: prepared patched copy in target/vendor/jitterentropy-rs"
