#!/usr/bin/env bash
# Verify the final Milk-V Duo SD image without mounting or modifying it.
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: $0 --selftest" >&2
  echo "       $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs | --wasm-aot-profile] [--artifact-root=<absolute-path>] <duo-buildroot-sdk-root>" >&2
}

verify_raw_data_partition() {
  python3 - "$@" <<'PY'
import os
import struct
import sys
import tempfile

SECTOR_SIZE = 512
# 512 MiB, matching policy/image BLOCK_DATA_SLICE for milkv-duo-sd
# (first_sector 262_145, sector_count 1_048_576).
EXPECTED_DATA_SECTORS = 512 * 1024 * 1024 // SECTOR_SIZE
SEED_SECTOR = 7
SEED = b"VIBEOS-BLK-SECTOR-7-SEED-v1"
EXPECTED_SEED_SECTOR = SEED + bytes(SECTOR_SIZE - len(SEED))
SCAN_CHUNK_BYTES = 1024 * 1024


class Violation(Exception):
    pass


def scan_zero_region(image_file, partition_offset, start, length):
    image_file.seek(partition_offset + start)
    consumed = 0
    while consumed < length:
        requested = min(SCAN_CHUNK_BYTES, length - consumed)
        chunk = image_file.read(requested)
        if len(chunk) != requested:
            raise Violation(
                f"data partition ended while scanning logical byte {start + consumed}"
            )
        if chunk.count(0) != len(chunk):
            index = next(index for index, value in enumerate(chunk) if value)
            logical_byte = start + consumed + index
            sector, byte_in_sector = divmod(logical_byte, SECTOR_SIZE)
            raise Violation(
                f"non-zero byte 0x{chunk[index]:02x} at data logical sector "
                f"{sector}, byte {byte_in_sector}; only sector {SEED_SECTOR} may be non-zero"
            )
        consumed += len(chunk)


def verify_region(image_file, start_sector, sector_count):
    if sector_count != EXPECTED_DATA_SECTORS:
        raise Violation(
            f"data partition has {sector_count} sectors, expected {EXPECTED_DATA_SECTORS}"
        )

    partition_offset = start_sector * SECTOR_SIZE
    partition_bytes = sector_count * SECTOR_SIZE
    image_bytes = os.fstat(image_file.fileno()).st_size
    required_bytes = partition_offset + partition_bytes
    if image_bytes < required_bytes:
        raise Violation(
            f"data partition ends at byte {required_bytes}, but image has {image_bytes} bytes"
        )

    seed_offset = SEED_SECTOR * SECTOR_SIZE
    scan_zero_region(image_file, partition_offset, 0, seed_offset)

    image_file.seek(partition_offset + seed_offset)
    actual_seed_sector = image_file.read(SECTOR_SIZE)
    if actual_seed_sector != EXPECTED_SEED_SECTOR:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(actual_seed_sector, EXPECTED_SEED_SECTOR)
                )
                if actual != expected
            ),
            min(len(actual_seed_sector), SECTOR_SIZE),
        )
        raise Violation(
            f"data logical sector {SEED_SECTOR} is not canonical "
            f"(first mismatch at byte {mismatch})"
        )

    suffix_start = seed_offset + SECTOR_SIZE
    scan_zero_region(
        image_file,
        partition_offset,
        suffix_start,
        partition_bytes - suffix_start,
    )


def verify_image(path):
    with open(path, "rb") as image_file:
        mbr = image_file.read(SECTOR_SIZE)
        if len(mbr) != SECTOR_SIZE:
            raise Violation("image is shorter than one MBR sector")
        p2_entry = 446 + 16
        p2_start, p2_size = struct.unpack_from("<II", mbr, p2_entry + 8)
        verify_region(image_file, p2_start, p2_size)


def expect_rejected(label, image_file, offset, replacement, expected_message):
    image_file.seek(offset)
    original = image_file.read(len(replacement))
    image_file.seek(offset)
    image_file.write(replacement)
    try:
        verify_region(image_file, 0, EXPECTED_DATA_SECTORS)
    except Violation as error:
        if expected_message not in str(error):
            raise RuntimeError(
                f"selftest {label!r} failed for the wrong reason: {error}"
            ) from error
    else:
        raise RuntimeError(f"selftest {label!r} was accepted")
    finally:
        image_file.seek(offset)
        image_file.write(original)


def run_selftest():
    partition_bytes = EXPECTED_DATA_SECTORS * SECTOR_SIZE
    with tempfile.TemporaryFile() as image_file:
        image_file.truncate(partition_bytes)
        image_file.seek(SEED_SECTOR * SECTOR_SIZE)
        image_file.write(SEED)
        verify_region(image_file, 0, EXPECTED_DATA_SECTORS)

        try:
            verify_region(image_file, 0, 4 * 1024 * 1024 // SECTOR_SIZE)
        except Violation as error:
            if f"expected {EXPECTED_DATA_SECTORS}" not in str(error):
                raise RuntimeError(
                    f"selftest 'old-4MiB-layout' failed for the wrong reason: {error}"
                ) from error
        else:
            raise RuntimeError("selftest 'old-4MiB-layout' was accepted")

        expect_rejected("prefix-byte", image_file, 0, b"\x01", "logical sector 0")
        expect_rejected(
            "corrupt-seed",
            image_file,
            SEED_SECTOR * SECTOR_SIZE,
            b"\x00",
            "sector 7 is not canonical",
        )
        expect_rejected(
            "seed-padding",
            image_file,
            SEED_SECTOR * SECTOR_SIZE + len(SEED),
            b"\x01",
            "sector 7 is not canonical",
        )
        expect_rejected(
            "first-suffix-sector",
            image_file,
            (SEED_SECTOR + 1) * SECTOR_SIZE,
            b"\x01",
            "logical sector 8",
        )
        expect_rejected(
            "partition-final-byte",
            image_file,
            partition_bytes - 1,
            b"\x01",
            f"logical sector {EXPECTED_DATA_SECTORS - 1}",
        )

        image_file.truncate(partition_bytes - 1)
        try:
            verify_region(image_file, 0, EXPECTED_DATA_SECTORS)
        except Violation as error:
            if "but image has" not in str(error):
                raise RuntimeError(
                    f"selftest 'truncated-partition' failed for the wrong reason: {error}"
                ) from error
        else:
            raise RuntimeError("selftest 'truncated-partition' was accepted")

    print("verify-milkv-duo-image.sh raw data selftest: PASS (7 negative cases)")


try:
    if sys.argv[1:] == ["--selftest"]:
        run_selftest()
    elif len(sys.argv) == 2:
        verify_image(sys.argv[1])
    else:
        raise RuntimeError("internal raw-data verifier invocation is invalid")
except (OSError, RuntimeError, Violation) as error:
    raise SystemExit(f"verify-milkv-duo-image.sh: {error}")
PY
}

diagnostic=false
ssh_acceptance=false
jitterentropy_probe=false
jitterentropy_ssh_probe=false
selftest=false
iperf3_server=false
file_tree=false
runtime_costs=false
wasm_aot_profile=false
runtime_costs_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
wasm_aot_profile_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
wasm_aot_profile_sdk_container_digest=sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
artifact_root_arg=
sdk_arg=
for arg in "$@"; do
  case "$arg" in
    --diagnostic) diagnostic=true ;;
    --ssh-acceptance) ssh_acceptance=true ;;
    --jitterentropy-probe) jitterentropy_probe=true ;;
    --jitterentropy-ssh-probe) jitterentropy_ssh_probe=true ;;
    --selftest) selftest=true ;;
    --iperf3-server) iperf3_server=true ;;
    --file-tree) file_tree=true ;;
    --runtime-costs) runtime_costs=true ;;
    --wasm-aot-profile) wasm_aot_profile=true ;;
    --artifact-root=*)
      if [[ -n "$artifact_root_arg" || -z "${arg#*=}" ]]; then
        usage
        exit 2
      fi
      artifact_root_arg=${arg#*=}
      ;;
    -*) usage; exit 2 ;;
    *)
      if [[ -n "$sdk_arg" ]]; then
        usage
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
[[ "$file_tree" == true ]] && ((mode_count += 1))
[[ "$runtime_costs" == true ]] && ((mode_count += 1))
[[ "$wasm_aot_profile" == true ]] && ((mode_count += 1))
if ((mode_count > 1)); then
  echo "verify-milkv-duo-image.sh: image mode options are mutually exclusive" >&2
  usage
  exit 2
fi
if [[ "$selftest" == true ]]; then
  if ((mode_count != 0)) || [[ -n "$sdk_arg" || -n "$artifact_root_arg" ]]; then
    echo "verify-milkv-duo-image.sh: --selftest does not accept an SDK root or image mode" >&2
    usage
    exit 2
  fi
  command -v python3 >/dev/null || {
    echo "verify-milkv-duo-image.sh: required tool is missing: python3" >&2
    exit 1
  }
  verify_raw_data_partition --selftest
  exit 0
fi
if [[ -z "$sdk_arg" ]]; then
  usage
  exit 2
fi
if [[ -n "$artifact_root_arg" && "$wasm_aot_profile" != true ]]; then
  echo "verify-milkv-duo-image.sh: --artifact-root is restricted to --wasm-aot-profile" >&2
  usage
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
sdk_root=$(cd -- "$sdk_arg" && pwd -P)
if [[ "$wasm_aot_profile" == true ]]; then
  for c84_git_environment_name in ${!GIT_@}; do
    unset "$c84_git_environment_name"
  done
  c84_docker_git_config=/etc/vibeos-c84.gitconfig
  c84_docker_git_config_template="$script_dir/c84-docker.gitconfig"
  if [[ "$repo_root" != /home/vibeos || "$sdk_root" != /home/work ]]; then
    echo "verify-milkv-duo-image.sh: C8.4 requires source /home/vibeos and SDK /home/work inside the pinned container" >&2
    exit 2
  fi
  command -v python3 >/dev/null || {
    echo "verify-milkv-duo-image.sh: required C8.4 tool is missing: python3" >&2
    exit 1
  }
  python3 - "$c84_docker_git_config_template" "$c84_docker_git_config" <<'PY'
import errno
import os
import pathlib
import stat
import sys

expected = (
    b"[safe]\n"
    b"\tdirectory = /home/vibeos\n"
    b"\tdirectory = /home/vibeos/vendor/jitterentropy-rs\n"
    b"\tdirectory = /home/vibeos/vendor/sunset\n"
    b"\tdirectory = /home/work\n"
)


def stable_regular(path_text, label):
    path = pathlib.Path(path_text)
    try:
        before_lstat = path.lstat()
        if stat.S_ISLNK(before_lstat.st_mode) or not stat.S_ISREG(before_lstat.st_mode):
            raise SystemExit(f"verify-milkv-duo-image.sh: {label} is not a regular non-symlink file: {path}")
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
    except OSError as error:
        raise SystemExit(f"verify-milkv-duo-image.sh: cannot read {label} {path}: {error}")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SystemExit(f"verify-milkv-duo-image.sh: {label} changed while it was read: {path}")
    return data


template = stable_regular(sys.argv[1], "committed C8.4 Docker Git config")
runtime = stable_regular(sys.argv[2], "mounted C8.4 Docker Git config")
if template != expected or runtime != expected:
    raise SystemExit("verify-milkv-duo-image.sh: C8.4 Docker Git config bytes differ from the closed allowlist")
for path, label in (
    (sys.argv[1], "committed C8.4 Docker Git config"),
    (sys.argv[2], "mounted C8.4 Docker Git config"),
):
    try:
        descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EROFS):
            raise SystemExit(f"verify-milkv-duo-image.sh: cannot prove {label} is read-only: {error}")
    else:
        os.close(descriptor)
        raise SystemExit(f"verify-milkv-duo-image.sh: {label} is writable")
PY
  export GIT_CONFIG_GLOBAL="$c84_docker_git_config"
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_NO_REPLACE_OBJECTS=1
  export GIT_OPTIONAL_LOCKS=0
  export HOME=/nonexistent
  export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
  export TZ=UTC
fi
if [[ "$runtime_costs" == true ]]; then
  if ! sdk_git_root=$(git --no-optional-locks -C "$sdk_root" rev-parse --show-toplevel 2>/dev/null) ||
     ! sdk_head=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD 2>/dev/null); then
    echo "verify-milkv-duo-image.sh: runtime-cost SDK root is not a readable Git checkout: $sdk_root" >&2
    exit 1
  fi
  sdk_git_root=$(cd -- "$sdk_git_root" && pwd -P)
  if [[ "$sdk_git_root" != "$sdk_root" ]]; then
    echo "verify-milkv-duo-image.sh: runtime-cost SDK path must name its Git root: $sdk_root" >&2
    exit 1
  fi
  if [[ "$sdk_head" != "$runtime_costs_sdk_commit" ]]; then
    echo "verify-milkv-duo-image.sh: runtime-cost SDK HEAD is $sdk_head, expected $runtime_costs_sdk_commit" >&2
    exit 1
  fi
  if ! sdk_status=$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    echo "verify-milkv-duo-image.sh: cannot read runtime-cost SDK status" >&2
    exit 1
  fi
  if [[ -n "$sdk_status" ]]; then
    echo "verify-milkv-duo-image.sh: runtime-cost SDK checkout is not clean" >&2
    exit 1
  fi
fi
if [[ "$wasm_aot_profile" == true ]]; then
  require_wasm_aot_profile_identity() {
    local identity_name=$1 identity_value=$2 identity_length=$3 zero_value=$4 test_value=$5
    if [[ ${#identity_value} -ne $identity_length || "$identity_value" == *[!0123456789abcdef]* ]]; then
      echo "verify-milkv-duo-image.sh: $identity_name must be exactly $identity_length lowercase hexadecimal characters" >&2
      exit 2
    fi
    if [[ "$identity_value" == "$zero_value" || "$identity_value" == "$test_value" ]]; then
      echo "verify-milkv-duo-image.sh: $identity_name uses a forbidden unbound/test sentinel" >&2
      exit 2
    fi
  }
  wasm_aot_profile_source_commit=${VIBEOS_C84_SOURCE_COMMIT-}
  wasm_aot_profile_challenge=${VIBEOS_C84_CHALLENGE-}
  wasm_aot_profile_declared_container=${VIBEOS_C84_SDK_CONTAINER_DIGEST-}
  require_wasm_aot_profile_identity VIBEOS_C84_SOURCE_COMMIT \
    "$wasm_aot_profile_source_commit" 40 \
    0000000000000000000000000000000000000000 \
    1111111111111111111111111111111111111111
  require_wasm_aot_profile_identity VIBEOS_C84_CHALLENGE \
    "$wasm_aot_profile_challenge" 64 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    2222222222222222222222222222222222222222222222222222222222222222
  if [[ "$wasm_aot_profile_declared_container" != "$wasm_aot_profile_sdk_container_digest" ]]; then
    echo "verify-milkv-duo-image.sh: VIBEOS_C84_SDK_CONTAINER_DIGEST must equal $wasm_aot_profile_sdk_container_digest" >&2
    exit 2
  fi
  if ! sdk_git_root=$(git --no-optional-locks -C "$sdk_root" rev-parse --show-toplevel 2>/dev/null) ||
     ! sdk_head=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD 2>/dev/null); then
    echo "verify-milkv-duo-image.sh: WebAssembly AOT profile SDK root is not a readable Git checkout: $sdk_root" >&2
    exit 1
  fi
  sdk_git_root=$(cd -- "$sdk_git_root" && pwd -P)
  if [[ "$sdk_git_root" != "$sdk_root" || "$sdk_head" != "$wasm_aot_profile_sdk_commit" ]]; then
    echo "verify-milkv-duo-image.sh: WebAssembly AOT profile SDK root/HEAD differs" >&2
    exit 1
  fi
  if ! sdk_status=$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    echo "verify-milkv-duo-image.sh: cannot read WebAssembly AOT profile SDK status" >&2
    exit 1
  fi
  if [[ -n "$sdk_status" ]]; then
    echo "verify-milkv-duo-image.sh: WebAssembly AOT profile SDK checkout is not clean" >&2
    exit 1
  fi
  if ! repo_head=$(git --no-optional-locks -C "$repo_root" rev-parse HEAD) ||
     ! repo_status=$(git --no-optional-locks -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=all); then
    echo "verify-milkv-duo-image.sh: cannot read WebAssembly AOT profile superproject" >&2
    exit 1
  fi
  if [[ "$repo_head" != "$wasm_aot_profile_source_commit" || -n "$repo_status" ]]; then
    echo "verify-milkv-duo-image.sh: WebAssembly AOT profile superproject differs" >&2
    exit 1
  fi
  jitterentropy_submodule="$repo_root/vendor/jitterentropy-rs"
  jitterentropy_patch="$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch"
  if ! jitterentropy_head=$(git --no-optional-locks -C "$jitterentropy_submodule" rev-parse HEAD) ||
     [[ "$jitterentropy_head" != c5bd2e17194fe3a04d17f74027bb67622579405f ]]; then
    echo "verify-milkv-duo-image.sh: jitterentropy-rs HEAD differs" >&2
    exit 1
  fi
  python3 - "$jitterentropy_submodule" "$jitterentropy_patch" <<'PY'
import pathlib
import subprocess
import sys

submodule = pathlib.Path(sys.argv[1]).resolve(strict=True)
patch = pathlib.Path(sys.argv[2]).resolve(strict=True).read_bytes()
observed = subprocess.run(
    ["git", "--no-optional-locks", "-C", str(submodule), "diff", "--unified=0", "--binary"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if observed != patch:
    raise SystemExit("verify-milkv-duo-image.sh: jitterentropy-rs diff differs from the recorded patch")
if subprocess.run(
    ["git", "--no-optional-locks", "-C", str(submodule), "diff", "--cached", "--quiet", "--exit-code"],
).returncode != 0:
    raise SystemExit("verify-milkv-duo-image.sh: jitterentropy-rs has staged changes")
untracked = subprocess.run(
    ["git", "--no-optional-locks", "-C", str(submodule), "ls-files", "--others", "--exclude-standard", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if untracked:
    raise SystemExit("verify-milkv-duo-image.sh: jitterentropy-rs has untracked files")
PY
  sunset_submodule="$repo_root/vendor/sunset"
  if ! sunset_head=$(git --no-optional-locks -C "$sunset_submodule" rev-parse HEAD) ||
     ! sunset_status=$(git --no-optional-locks -C "$sunset_submodule" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    echo "verify-milkv-duo-image.sh: cannot read sunset submodule state" >&2
    exit 1
  fi
  if [[ "$sunset_head" != f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e || -n "$sunset_status" ]]; then
    echo "verify-milkv-duo-image.sh: sunset submodule differs" >&2
    exit 1
  fi
fi

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
elif [[ "$file_tree" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-file-tree"
  image_name="vibeos-milkv-duo-file-tree-sd.img"
elif [[ "$runtime_costs" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-runtime-costs"
  image_name="vibeos-milkv-duo-runtime-costs-sd.img"
elif [[ "$wasm_aot_profile" == true ]]; then
  output_dir="$repo_root/target/milkv-duo-wasm-aot-profile"
  image_name="vibeos-milkv-duo-wasm-aot-profile-sd.img"
fi
if [[ -n "$artifact_root_arg" ]]; then
  if [[ "$artifact_root_arg" != /* || ! -d "$artifact_root_arg" || -L "$artifact_root_arg" ]]; then
    die_root=${artifact_root_arg:-<empty>}
    echo "verify-milkv-duo-image.sh: C8.4 artifact root must be an existing absolute non-symlink directory: $die_root" >&2
    exit 2
  fi
  output_dir=$(cd -- "$artifact_root_arg" && pwd -P)
fi
image="$output_dir/$image_name"
expected_fit="$output_dir/boot.sd"
expected_kernel="$output_dir/vibeos-milkv-duo.bin"
expected_its="$output_dir/milkv-duo.its"
packaged_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
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
if [[ "$wasm_aot_profile" == true ]]; then
  for artifact in "$image" "$expected_fit" "$expected_kernel" "$expected_its" "$packaged_dtb" "$expected_dtb" "$expected_fip"; do
    [[ -f "$artifact" && ! -L "$artifact" ]] || die "C8.4 input is not a regular non-symlink file: $artifact"
  done
  cmp -s "$expected_its" "$script_dir/milkv-duo.its" ||
    die "packaged FIT source differs from the repository recipe"
  cmp -s "$packaged_dtb" "$expected_dtb" ||
    die "packaged DTB differs from the SDK Linux DTB"
fi

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
# Keep the packaged image's physical LBA contract synchronized with
# policy/image and the SDHCI logical-to-physical adapter.
expected_data_start = 262_145
if p2_start != expected_data_start:
    fail(f"data partition starts at {p2_start}, policy requires {expected_data_start}")
expected_data_sectors = 512 * 1024 * 1024 // sector_size
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

verify_raw_data_partition "$image"
echo "raw data partition: canonical sector 7 seed + zero-filled remainder verified"

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
if [[ "$wasm_aot_profile" == true ]]; then
  python3 - "$expected_kernel" "$expected_fit" "$image" \
    "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" <<'PY'
import pathlib
import sys

source_commit = sys.argv[-2].encode("ascii")
challenge = sys.argv[-1].encode("ascii")
for name in sys.argv[1:-2]:
    path = pathlib.Path(name).resolve(strict=True)
    found = [False, False]
    overlap = max(len(source_commit), len(challenge)) - 1
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            window = tail + chunk
            found[0] = found[0] or source_commit in window
            found[1] = found[1] or challenge in window
            tail = window[-overlap:]
    if not all(found):
        raise SystemExit(f"verify-milkv-duo-image.sh: source/challenge missing from {path}")
print("C8.4 source/challenge bytes are present in kernel, FIT, and full image")
PY
fi
if [[ "$runtime_costs" == true ]]; then
  if ! sdk_head_after=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD) ||
     ! sdk_status_after=$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    die "cannot recheck runtime-cost SDK checkout"
  fi
  if [[ "$sdk_head_after" != "$runtime_costs_sdk_commit" || -n "$sdk_status_after" ]]; then
    die "runtime-cost SDK checkout changed during image verification"
  fi
fi
if [[ "$wasm_aot_profile" == true ]]; then
  if ! sdk_head_after=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD) ||
     ! sdk_status_after=$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ||
     ! repo_head_after=$(git --no-optional-locks -C "$repo_root" rev-parse HEAD) ||
     ! repo_status_after=$(git --no-optional-locks -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=all) ||
     ! jitterentropy_head_after=$(git --no-optional-locks -C "$jitterentropy_submodule" rev-parse HEAD) ||
     ! sunset_head_after=$(git --no-optional-locks -C "$sunset_submodule" rev-parse HEAD) ||
     ! sunset_status_after=$(git --no-optional-locks -C "$sunset_submodule" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    die "cannot recheck C8.4 SDK/source checkout"
  fi
  if [[ "$sdk_head_after" != "$wasm_aot_profile_sdk_commit" || -n "$sdk_status_after" ||
        "$repo_head_after" != "$wasm_aot_profile_source_commit" || -n "$repo_status_after" ||
        "$jitterentropy_head_after" != c5bd2e17194fe3a04d17f74027bb67622579405f ||
        "$sunset_head_after" != f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e || -n "$sunset_status_after" ]]; then
    die "C8.4 SDK/source checkout changed during image verification"
  fi
  python3 - "$jitterentropy_submodule" "$jitterentropy_patch" <<'PY'
import pathlib
import subprocess
import sys

observed = subprocess.run(
    ["git", "--no-optional-locks", "-C", sys.argv[1], "diff", "--unified=0", "--binary"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if observed != pathlib.Path(sys.argv[2]).read_bytes():
    raise SystemExit("verify-milkv-duo-image.sh: jitterentropy-rs changed during image verification")
if subprocess.run(
    ["git", "--no-optional-locks", "-C", sys.argv[1], "diff", "--cached", "--quiet", "--exit-code"],
).returncode != 0:
    raise SystemExit("verify-milkv-duo-image.sh: jitterentropy-rs gained staged changes during image verification")
untracked = subprocess.run(
    ["git", "--no-optional-locks", "-C", sys.argv[1], "ls-files", "--others", "--exclude-standard", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if untracked:
    raise SystemExit("verify-milkv-duo-image.sh: jitterentropy-rs gained untracked files during image verification")
PY
  python3 - \
    "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" \
    "$expected_kernel" "$expected_its" "$packaged_dtb" "$expected_dtb" \
    "$expected_fit" "$image" "$expected_fip" \
    "$mkimage" "$dumpimage" "$c84_docker_git_config" \
    "$(command -v mdir)" "$(command -v mcopy)" \
    "$(command -v cmp)" "$(command -v sha256sum)" \
    "$(command -v fdtget)" "$(command -v python3)" "$(command -v tr)" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

source_commit, challenge = sys.argv[1:3]
artifact_names = (
    "kernel_binary", "fit_source", "packaged_dtb", "sdk_dtb",
    "fit_boot_sd", "full_sd_image", "sdk_fip",
)
tool_names = (
    "sdk_mkimage", "sdk_dumpimage", "git_config", "mdir", "mcopy",
    "cmp", "sha256sum", "fdtget", "python3", "tr",
)
artifact_paths = sys.argv[3:10]
tool_paths = sys.argv[10:20]
if len(artifact_paths) != len(artifact_names) or len(tool_paths) != len(tool_names):
    raise SystemExit("verify-milkv-duo-image.sh: canonical report arguments differ")


def identity(name):
    path = pathlib.Path(name).resolve(strict=True)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise SystemExit(f"verify-milkv-duo-image.sh: report input is not a non-empty regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        raise SystemExit(f"verify-milkv-duo-image.sh: report input changed while hashing: {path}")
    return {"sha256": digest.hexdigest(), "bytes": before.st_size}


report = {
    "schema": "vibeos.c84.duo-wasm-aot-profile.image-audit-report",
    "version": 1,
    "source_commit": source_commit,
    "challenge": challenge,
    "artifacts": {name: identity(path) for name, path in zip(artifact_names, artifact_paths)},
    "tools": {name: identity(path) for name, path in zip(tool_names, tool_paths)},
}
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
PY
  echo "PASS: C8.4 FAT boot + raw data MBR image, FIP, FIT metadata, kernel/DTB payloads, and CRC32 hashes are valid"
else
  echo "PASS: FAT boot + raw data MBR image, FIP, FIT metadata, and payload CRC32 hashes are valid"
fi
