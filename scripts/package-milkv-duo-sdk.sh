#!/usr/bin/env bash
# Package an already-built VibeOS binary with an already-built Duo SDK.
#
# Run this in the same Linux/amd64 environment that built the SDK. On an
# Apple-Silicon host that normally means the official Milk-V Docker image.
set -eo pipefail

diagnostic=false
ssh_acceptance=false
jitterentropy_probe=false
jitterentropy_ssh_probe=false
sdk_arg=
for arg in "$@"; do
  case "$arg" in
    --diagnostic) diagnostic=true ;;
    --ssh-acceptance) ssh_acceptance=true ;;
    --jitterentropy-probe) jitterentropy_probe=true ;;
    --jitterentropy-ssh-probe) jitterentropy_ssh_probe=true ;;
    -*) echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe] <duo-buildroot-sdk-root>" >&2; exit 2 ;;
    *)
      if [[ -n "$sdk_arg" ]]; then
        echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe] <duo-buildroot-sdk-root>" >&2
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
if ((mode_count > 1)); then
  echo "package-milkv-duo-sdk.sh: image mode options are mutually exclusive" >&2
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe] <duo-buildroot-sdk-root>" >&2
  exit 2
fi
if [[ -z "$sdk_arg" ]]; then
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe] <duo-buildroot-sdk-root>" >&2
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
fi
kernel_bin="$output_dir/vibeos-milkv-duo.bin"
output_its="$output_dir/milkv-duo.its"
output_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
output_fit="$output_dir/boot.sd"
output_image="$output_dir/$image_name"
temp_fit="$output_dir/.boot.sd.$$.tmp"
temp_image="$output_dir/.vibeos-milkv-duo-sd.img.$$.tmp"
pack_dir=""

sdk_build="$sdk_root/u-boot-2021.10/build/cv1800b_milkv_duo_sd"
mkimage="$sdk_build/tools/mkimage"
sdk_dtb="$sdk_root/linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb"
sdk_output="$sdk_root/install/soc_cv1800b_milkv_duo_sd"
sdk_fip="$sdk_output/fip.bin"
genimage="$sdk_root/buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage"
if [[ ! -f "$genimage" ]]; then
  # Buildroot's per-package directory mode keeps host tools under the package
  # staging tree instead of merging them into output/host.
  genimage="$sdk_root/buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/per-package/host-genimage/host/bin/genimage"
fi
genimage_lib=$(cd -- "$(dirname -- "$genimage")/../lib" && pwd -P)

published=false
mkdir -p "$output_dir"
rm -f "$output_fit" "$output_image" "$temp_fit" "$temp_image"
cleanup() {
  rm -f "$temp_fit" "$temp_image"
  if [[ -n "$pack_dir" && "$pack_dir" == "$output_dir"/.vibeos-pack.* ]]; then
    rm -rf -- "$pack_dir"
  fi
  if [[ "$published" != true ]]; then
    rm -f "$output_fit" "$output_image"
  fi
}
trap cleanup EXIT

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "package-milkv-duo-sdk.sh: required file not found: $1" >&2
    exit 1
  fi
}

require_file "$kernel_bin"
require_file "$script_dir/milkv-duo.its"
require_file "$script_dir/milkv-duo-genimage.cfg"
require_file "$mkimage"
require_file "$sdk_dtb"
require_file "$sdk_fip"
require_file "$genimage"
if [[ ! -x "$mkimage" ]] || ! "$mkimage" -V >/dev/null 2>&1; then
  echo "package-milkv-duo-sdk.sh: SDK mkimage cannot run here: $mkimage" >&2
  exit 1
fi
if [[ ! -x "$genimage" ]]; then
  echo "package-milkv-duo-sdk.sh: SDK genimage cannot run here: $genimage" >&2
  exit 1
fi

cp "$script_dir/milkv-duo.its" "$output_its"
cp "$sdk_dtb" "$output_dtb"

(
  cd "$output_dir"
  "$mkimage" -f milkv-duo.its "$(basename -- "$temp_fit")"
  "$mkimage" -l "$(basename -- "$temp_fit")"
)

pack_dir=$(mktemp -d "$output_dir/.vibeos-pack.XXXXXX")
mkdir -p "$pack_dir/input/rawimages" "$pack_dir/root" "$pack_dir/output" "$pack_dir/tmp"
cp "$sdk_fip" "$pack_dir/input/fip.bin"
cp "$temp_fit" "$pack_dir/input/rawimages/boot.sd"
cmp "$temp_fit" "$pack_dir/input/rawimages/boot.sd"
python3 - "$pack_dir/input/vibe-data.bin" <<'PY'
import sys

path = sys.argv[1]
sector_size = 512
seed = b"VIBEOS-BLK-SECTOR-7-SEED-v1"
with open(path, "wb") as data:
    data.truncate(4 * 1024 * 1024)
with open(path, "r+b") as data:
    data.seek(7 * sector_size)
    data.write(seed)
PY

LD_LIBRARY_PATH="$genimage_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$genimage" \
  --config "$script_dir/milkv-duo-genimage.cfg" \
  --rootpath "$pack_dir/root" \
  --tmppath "$pack_dir/tmp" \
  --inputpath "$pack_dir/input" \
  --outputpath "$pack_dir/output"

packed_image="$pack_dir/output/vibeos-milkv-duo-sd.img"
require_file "$packed_image"
if [[ ! -s "$packed_image" ]]; then
  echo "package-milkv-duo-sdk.sh: genimage produced an empty SD image: $packed_image" >&2
  exit 1
fi
cp "$packed_image" "$temp_image"
mv "$temp_fit" "$output_fit"
mv "$temp_image" "$output_image"
verify_args=("$sdk_root")
if [[ "$diagnostic" == true ]]; then
  verify_args=(--diagnostic "$sdk_root")
elif [[ "$ssh_acceptance" == true ]]; then
  verify_args=(--ssh-acceptance "$sdk_root")
elif [[ "$jitterentropy_probe" == true ]]; then
  verify_args=(--jitterentropy-probe "$sdk_root")
elif [[ "$jitterentropy_ssh_probe" == true ]]; then
  verify_args=(--jitterentropy-ssh-probe "$sdk_root")
fi
if ! "$script_dir/verify-milkv-duo-image.sh" "${verify_args[@]}"; then
  echo "package-milkv-duo-sdk.sh: refusing to publish an unverified SD image" >&2
  exit 1
fi
published=true

echo "Milk-V Duo FIT: $output_fit"
echo "Milk-V Duo SD image: $output_image"
