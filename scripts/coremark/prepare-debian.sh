#!/bin/sh
set -eu
timeout 60 systemctl is-system-running --wait || true
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
export DEBIAN_FRONTEND=noninteractive
apt-get update > /mnt/results/apt.log 2>&1
apt-get install -y --no-install-recommends gcc libc6-dev make time >> /mnt/results/apt.log 2>&1
# Stream one archive across 9p; do not preserve guest ownership on macOS.
# Linux netfilter headers contain case-only names on a case-sensitive guest FS.
tar -C / --exclude='usr/include/linux/netfilter*' -cf /mnt/results/sysroot.tar usr/lib/riscv64-linux-gnu usr/lib/gcc usr/include
{ uname -a; cc --version; dpkg-query -W libc6 libc6-dev gcc; } > /mnt/results/environment.txt
sync
