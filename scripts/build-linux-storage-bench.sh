#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
if [ "$#" -ne 2 ]; then
  echo "usage: $0 EDK2_RISCV_CODE.fd EDK2_RISCV_VARS.fd" >&2
  exit 2
fi
firmware_code=$1
firmware_vars=$2
test -f "$firmware_code" && test -f "$firmware_vars"

build=20260810-2566
filename=debian-13-nocloud-riscv64-$build.qcow2
url=https://cloud.debian.org/images/cloud/trixie/$build/$filename
expected=cfd1a935ba054a641ebea26dcf2713844d0e757944a9f575d26b26a04c94e4994a637c99517b39c313c98dcc4eb13ccca8dcccd4062519457a2f2816836d4cf6
output=$PWD/target/storage-bench-debian
base=$output/$filename
configured=$output/debian-13-nocloud-riscv64-configured.qcow2
variables=$output/debian-13-nocloud-riscv64-vars.fd
data=$output/storage-bench-ext4.raw
agent=$output/storage-bench-agent
mkdir -p "$output"

if [ ! -f "$base" ]; then
  curl -fL "$url" -o "$base"
fi
actual=$(shasum -a 512 "$base" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  echo "build-linux-storage-bench: Debian image SHA-512 mismatch" >&2
  exit 1
fi

# Debian supplies the compiler and e2fsprogs as binary riscv64 packages. This
# compiles only the benchmark agent; no toolchain or libc is built from source.
docker run --rm --platform linux/riscv64 \
  -v "$PWD:/workspace" -w /workspace debian:trixie-slim sh -lc \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libc6-dev e2fsprogs && gcc -O2 -static -Wall -Wextra -Werror benchmarks/storage/linux/package/storage-bench-agent/src/storage-bench-agent.c -o target/storage-bench-debian/storage-bench-agent && truncate -s 1G target/storage-bench-debian/storage-bench-ext4.raw && mkfs.ext4 -F -t ext4 -b 4096 -L VIBE_BENCH_DATA -U 0f21c8d5-c551-41ae-a9f8-9d15d45af175 -E lazy_itable_init=0,lazy_journal_init=0 -O metadata_csum,64bit target/storage-bench-debian/storage-bench-ext4.raw'

if [ ! -f "$configured" ]; then
  python3 -B scripts/storage-bench.py provision-debian \
    --base-image "$base" --firmware-code "$firmware_code" \
    --firmware-vars "$firmware_vars" --output-root "$configured" \
    --output-vars "$variables"
fi

shasum -a 256 "$base" "$configured" "$variables" "$data" "$agent" \
  > "$output/SHA256SUMS"
echo "Debian storage benchmark artifacts: $output"
