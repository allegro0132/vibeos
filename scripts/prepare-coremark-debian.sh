#!/bin/sh
# Pinned official Debian 13 RISC-V image and original guest kernel/initrd, kept outside Git.
set -eu
cd "$(dirname "$0")/.."
work=${COREMARK_DEBIAN_WORK:-target/coremark-benchmark/debian}
mkdir -p "$work"
image=debian-13-nocloud-riscv64-20260831-2587.qcow2
url=https://cloud.debian.org/images/cloud/trixie/20260831-2587
sha=3e7dcf0c4a561939d2dd05afde045464f40febd1ecb0de4c1a8b27862d718c3929bf36df8e6c52eb3181364ae106fdb1d5119d192f686cd9ec3ea47b9b0405e6
if [ ! -f "$work/base.qcow2" ] || [ "$(shasum -a 512 "$work/base.qcow2" | cut -d ' ' -f 1)" != "$sha" ]; then
  for attempt in 1 2 3 4 5 6; do
    curl -fL --connect-timeout 20 --max-time 900 -C - "$url/$image" -o "$work/base.qcow2" && break
  done
fi
[ "$(shasum -a 512 "$work/base.qcow2" | cut -d ' ' -f 1)" = "$sha" ]
printf '%s  debian-13-nocloud-riscv64.qcow2\n' "$sha" > "$work/SHA512SUMS"
curl -fL "$url/debian-13-nocloud-riscv64-20260831-2587.json" -o "$work/image.json"
# 7z reads qcow2, GPT and ext4 without mounting the guest filesystem on macOS.
mkdir -p "$work/inspect" "$work/extracted"
7z x -y -o"$work/inspect" "$work/base.qcow2" 0.img
7z x -y -o"$work/extracted" "$work/inspect/0.img" \
  boot/vmlinux-6.12.107+deb13-riscv64 boot/initrd.img-6.12.107+deb13-riscv64
