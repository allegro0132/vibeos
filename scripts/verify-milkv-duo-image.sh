#!/usr/bin/env bash
# Verify the final Milk-V Duo SD image without mounting or modifying it.
set -euo pipefail
export LC_ALL=C

diagnostic=false
ssh_acceptance=false
jitterentropy_probe=false
jitterentropy_ssh_probe=false
iperf3_server=false
sdk_arg=
for arg in "$@"; do
  case "$arg" in
    --diagnostic) diagnostic=true ;;
    --ssh-acceptance) ssh_acceptance=true ;;
    --jitterentropy-probe) jitterentropy_probe=true ;;
    --jitterentropy-ssh-probe) jitterentropy_ssh_probe=true ;;
    --iperf3-server) iperf3_server=true ;;
    -*) echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server] <duo-buildroot-sdk-root>" >&2; exit 2 ;;
    *)
      if [[ -n "$sdk_arg" ]]; then
        echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server] <duo-buildroot-sdk-root>" >&2
        exit 2
      fi
      sdk_arg=$arg
      ;;
  esac
done
mode_count=0
[[ "$diagnostic" == true ]] && ((mode_count += 1))
[[ "$ssh_acceptance" == true ]] && ((mode_count += 1))
[[ "$jitterentropy_probe" == true ]] && ((mode_count += 1))
[[ "$jitterentropy_ssh_probe" == true ]] && ((mode_count += 1))
[[ "$iperf3_server" == true ]] && ((mode_count += 1))
if ((mode_count > 1)); then
  echo "verify-milkv-duo-image.sh: image mode options are mutually exclusive" >&2
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server] <duo-buildroot-sdk-root>" >&2
  exit 2
fi
if [[ -z "$sdk_arg" ]]; then
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server] <duo-buildroot-sdk-root>" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
sdk_root=$(cd -- "$sdk_arg" && pwd -P)

output_dir="$repo_root/target/milkv-duo"
image_name="vibeos-milkv-duo-sd.img"
if [[ "$diagnostic" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-diagnostic"
  image_name="vibeos-milkv-duo-diagnostic-sd.img"
elif [[ "$ssh_acceptance" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-ssh-acceptance"
  image_name="vibeos-milkv-duo-ssh-acceptance-sd.img"
elif [[ "$jitterentropy_probe" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-jitterentropy-probe"
  image_name="vibeos-milkv-duo-jitterentropy-probe-sd.img"
elif [[ "$jitterentropy_ssh_probe" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-jitterentropy-ssh-probe"
  image_name="vibeos-milkv-duo-jitterentropy-ssh-probe-sd.img"
elif [[ "$iperf3_server" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-iperf3-server"
  image_name="vibeos-milkv-duo-iperf3-server-sd.img"
fi
image="$output_dir/$image_name"
expected_fit="$output_dir/boot.sd"
expected_kernel="$output_dir/vibeos-milkv-duo.bin"
mkimage="$sdk_root/u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/mkimage"
dumpimage="$sdk_root/u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/dumpimage"
expected_dtb="$sdk_root/linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb"
expected_fip="$sdk_root/install/soc_cv1800b_milkv_duo_sd/fip.bin"

die() {
  echo "verify-milkv-duo-image.sh: $*" >&2
  exit 1
}

expect_eq() {
  local label=$1 actual=$2 expected=$3
  [[ "$actual" == "$expected" ]] ||
    die "$label: got '$actual', expected '$expected'"
}

for tool in mdir mcopy cmp sha256sum fdtget python3 tr; do
  command -v "$tool" >/dev/null || die "required tool is missing: $tool"
done
[[ -f "$image" ]] || die "final image not found: $image"
[[ -f "$expected_fit" ]] || die "expected FIT not found: $expected_fit"
[[ -f "$expected_kernel" ]] || die "expected kernel not found: $expected_kernel"
[[ -f "$expected_dtb" ]] || die "SDK Linux DTB not found: $expected_dtb"
[[ -f "$expected_fip" ]] || die "SDK FIP not found: $expected_fip"
[[ -x "$mkimage" ]] || die "SDK mkimage not found: $mkimage"
[[ -x "$dumpimage" ]] || die "SDK dumpimage not found: $dumpimage"

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT

echo "== MBR partition table =="
p1_start=$(python3 - "$image" <<'PY'
import os
import struct
import sys

path = sys.argv[1]
sector_size = 512
with open(path, "rb") as image_file:
    mbr = image_file.read(sector_size)

def fail(message):
    raise SystemExit(f"verify-milkv-duo-image.sh: {message}")

if len(mbr) != sector_size:
    fail("image is shorter than one MBR sector")
if mbr[510:512] != b"\x55\xaa":
    fail(f"invalid MBR signature: {mbr[510:512].hex()}")

partitions = []
for index in range(4):
    entry = mbr[446 + 16 * index:446 + 16 * (index + 1)]
    boot = entry[0]
    part_type = entry[4]
    start, size = struct.unpack_from("<II", entry, 8)
    if boot or part_type or start or size:
        partitions.append((index + 1, boot, part_type, start, size))

if len(partitions) != 2 or partitions[0][0] != 1 or partitions[1][0] != 2:
    fail(f"expected MBR boot and VibeOS data partitions, got {partitions!r}")

_, p1_boot, p1_type, p1_start, p1_size = partitions[0]
_, p2_boot, p2_type, p2_start, p2_size = partitions[1]
if p1_boot != 0x80:
    fail(f"partition 1 boot flag is 0x{p1_boot:02x}, expected 0x80")
if p1_type != 0x0C:
    fail(f"partition 1 type is 0x{p1_type:02x}, expected FAT32 LBA 0x0c")

expected_boot_sectors = 128 * 1024 * 1024 // sector_size
if p1_size != expected_boot_sectors:
    fail(f"boot partition has {p1_size} sectors, expected {expected_boot_sectors}")
if p1_start == 0:
    fail("boot partition starts at sector zero")
if p2_boot != 0:
    fail(f"partition 2 boot flag is 0x{p2_boot:02x}, expected 0")
if p2_type != 0xDA:
    fail(f"partition 2 type is 0x{p2_type:02x}, expected raw VibeOS data 0xda")
if p2_start != p1_start + p1_size:
    fail(f"data partition starts at {p2_start}, expected {p1_start + p1_size}")
expected_data_sectors = 4 * 1024 * 1024 // sector_size
if p2_size != expected_data_sectors:
    fail(f"data partition has {p2_size} sectors, expected {expected_data_sectors}")

image_bytes = os.path.getsize(path)
required_bytes = (p2_start + p2_size) * sector_size
if required_bytes != image_bytes:
    fail(f"two-partition image should be exactly {required_bytes} bytes, got {image_bytes}")

print(f"image bytes: {image_bytes}", file=sys.stderr)
print(f"partition 1: start={p1_start} sectors={p1_size} type=0x{p1_type:02x} bootable", file=sys.stderr)
print(f"partition 2: start={p2_start} sectors={p2_size} type=0x{p2_type:02x} raw data", file=sys.stderr)
print(p1_start)
PY
)

python3 - "$image" <<'PY'
import struct
import sys

path = sys.argv[1]
sector_size = 512
seed = b"VIBEOS-BLK-SECTOR-7-SEED-v1"
with open(path, "rb") as image_file:
    mbr = image_file.read(sector_size)
    p2_start = struct.unpack_from("<I", mbr, 446 + 16 + 8)[0]
    image_file.seek((p2_start + 7) * sector_size)
    sector7 = image_file.read(sector_size)
    image_file.seek((p2_start + 8) * sector_size)
    sector8 = image_file.read(sector_size)
if not sector7.startswith(seed) or any(sector7[len(seed):]):
    raise SystemExit("verify-milkv-duo-image.sh: data sector 7 seed is not canonical")
if any(sector8):
    raise SystemExit("verify-milkv-duo-image.sh: data sector 8 is not initially zero")
PY

echo "== FAT boot partition =="
fat_image="${image}@@$((p1_start * 512))"
mdir -i "$fat_image" ::/
mcopy -i "$fat_image" ::/boot.sd "$temp_dir/fat-boot.sd"
mcopy -i "$fat_image" ::/fip.bin "$temp_dir/fat-fip.bin"

echo "== FIT byte comparison =="
sha256sum "$expected_fit" "$temp_dir/fat-boot.sd" "$expected_fip" "$temp_dir/fat-fip.bin"
cmp -s "$expected_fit" "$temp_dir/fat-boot.sd" ||
  die "boot.sd extracted from FAT differs from target FIT"
cmp -s "$expected_fip" "$temp_dir/fat-fip.bin" ||
  die "fip.bin extracted from FAT differs from the SDK FIP"

echo "== FIT listing =="
"$mkimage" -l "$temp_dir/fat-boot.sd"

expect_prop() {
  local node=$1 property=$2 expected=$3 actual
  actual=$(fdtget -t s "$temp_dir/fat-boot.sd" "$node" "$property")
  expect_eq "$node/$property" "$actual" "$expected"
}

expect_addr() {
  local node=$1 property=$2 expected_low=$3 cells high low extra
  cells=$(fdtget -t x "$temp_dir/fat-boot.sd" "$node" "$property")
  read -r high low extra <<<"$cells"
  [[ -n "${high:-}" && -n "${low:-}" && -z "${extra:-}" ]] ||
    die "$node/$property is not exactly two 32-bit cells: '$cells'"
  high=${high#0x}; high=${high#0X}
  low=${low#0x}; low=${low#0X}
  ((16#$high == 0)) || die "$node/$property high cell is non-zero"
  ((16#$low == 16#$expected_low)) ||
    die "$node/$property is 0x$high$low, expected 0x$expected_low"
}

expect_prop /images/kernel type kernel
expect_prop /images/kernel arch riscv
expect_prop /images/kernel os linux
expect_prop /images/kernel compression none
expect_addr /images/kernel load 80200000
expect_addr /images/kernel entry 80200000
expect_prop /images/fdt type flat_dt
expect_prop /images/fdt arch riscv
expect_prop /images/fdt compression none
expect_prop /configurations default config-cv1800b_milkv_duo_sd
expect_prop /configurations/config-cv1800b_milkv_duo_sd kernel kernel
expect_prop /configurations/config-cv1800b_milkv_duo_sd fdt fdt
expect_prop /images/kernel/hash algo crc32
expect_prop /images/fdt/hash algo crc32

"$dumpimage" -T flat_dt -p 0 -o "$temp_dir/kernel.bin" "$temp_dir/fat-boot.sd"
"$dumpimage" -T flat_dt -p 1 -o "$temp_dir/fdt.dtb" "$temp_dir/fat-boot.sd"
cmp -s "$expected_kernel" "$temp_dir/kernel.bin" ||
  die "FIT kernel payload differs from this build's VibeOS kernel"
cmp -s "$expected_dtb" "$temp_dir/fdt.dtb" ||
  die "FIT FDT payload differs from the SDK Linux DTB"
echo "FIT payloads match this build's VibeOS kernel and SDK Linux DTB"

verify_crc32() {
  local node=$1 payload=$2 stored actual
  stored=$(fdtget -t x "$temp_dir/fat-boot.sd" "$node/hash" value | tr -d '[:space:]')
  stored=${stored#0x}; stored=${stored#0X}
  stored=$(printf '%08x' "$((16#$stored))")
  actual=$(python3 -c \
    'import sys, zlib
data = open(sys.argv[1], "rb").read()
print(f"{zlib.crc32(data) & 0xffffffff:08x}")' \
    "$payload")
  expect_eq "$node CRC32" "$actual" "$stored"
  echo "$node CRC32 OK: $actual"
}

verify_crc32 /images/kernel "$temp_dir/kernel.bin"
verify_crc32 /images/fdt "$temp_dir/fdt.dtb"
echo "PASS: FAT boot + raw data MBR image, FIP, FIT metadata, and payload CRC32 hashes are valid"
