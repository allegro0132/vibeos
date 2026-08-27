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
iperf3_server=false
file_tree=false
runtime_costs=false
wasm_aot_profile=false
runtime_costs_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
runtime_costs_sdk_container_digest=sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
wasm_aot_profile_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
wasm_aot_profile_sdk_container_digest=sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
sdk_arg=
for arg in "$@"; do
  case "$arg" in
    --diagnostic) diagnostic=true ;;
    --ssh-acceptance) ssh_acceptance=true ;;
    --jitterentropy-probe) jitterentropy_probe=true ;;
    --jitterentropy-ssh-probe) jitterentropy_ssh_probe=true ;;
    --iperf3-server) iperf3_server=true ;;
    --file-tree) file_tree=true ;;
    --runtime-costs) runtime_costs=true ;;
    --wasm-aot-profile) wasm_aot_profile=true ;;
    -*) echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs | --wasm-aot-profile] <duo-buildroot-sdk-root>" >&2; exit 2 ;;
    *)
      if [[ -n "$sdk_arg" ]]; then
        echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs | --wasm-aot-profile] <duo-buildroot-sdk-root>" >&2
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
  echo "package-milkv-duo-sdk.sh: image mode options are mutually exclusive" >&2
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs | --wasm-aot-profile] <duo-buildroot-sdk-root>" >&2
  exit 2
fi
if [[ -z "$sdk_arg" ]]; then
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs | --wasm-aot-profile] <duo-buildroot-sdk-root>" >&2
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
    echo "package-milkv-duo-sdk.sh: C8.4 requires source /home/vibeos and SDK /home/work inside the pinned container" >&2
    exit 2
  fi
  command -v python3 >/dev/null || {
    echo "package-milkv-duo-sdk.sh: required C8.4 tool is missing: python3" >&2
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
            raise SystemExit(f"package-milkv-duo-sdk.sh: {label} is not a regular non-symlink file: {path}")
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
    except OSError as error:
        raise SystemExit(f"package-milkv-duo-sdk.sh: cannot read {label} {path}: {error}")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SystemExit(f"package-milkv-duo-sdk.sh: {label} changed while it was read: {path}")
    return data


template = stable_regular(sys.argv[1], "committed C8.4 Docker Git config")
runtime = stable_regular(sys.argv[2], "mounted C8.4 Docker Git config")
if template != expected or runtime != expected:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 Docker Git config bytes differ from the closed allowlist")
for path, label in (
    (sys.argv[1], "committed C8.4 Docker Git config"),
    (sys.argv[2], "mounted C8.4 Docker Git config"),
):
    try:
        descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EROFS):
            raise SystemExit(f"package-milkv-duo-sdk.sh: cannot prove {label} is read-only: {error}")
    else:
        os.close(descriptor)
        raise SystemExit(f"package-milkv-duo-sdk.sh: {label} is writable")
PY
  export GIT_CONFIG_GLOBAL="$c84_docker_git_config"
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_NO_REPLACE_OBJECTS=1
  export GIT_OPTIONAL_LOCKS=0
  export HOME=/nonexistent
  export LC_ALL=C
  export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
  export TZ=UTC
fi
if [[ "$runtime_costs" == true ]]; then
  require_runtime_identity() {
    local identity_name=$1 identity_value=$2 identity_length=$3 unbound_value=$4
    if [[ ${#identity_value} -ne $identity_length || "$identity_value" == *[!0123456789abcdef]* ]]; then
      echo "package-milkv-duo-sdk.sh: $identity_name must be exactly $identity_length lowercase hexadecimal characters" >&2
      exit 2
    fi
    if [[ "$identity_value" == "$unbound_value" ]]; then
      echo "package-milkv-duo-sdk.sh: $identity_name must not use the unbound all-zero sentinel" >&2
      exit 2
    fi
    if { [[ "$identity_name" == VIBEOS_C83_SOURCE_COMMIT ]] &&
         [[ "$identity_value" == 1111111111111111111111111111111111111111 ]]; } ||
       { [[ "$identity_name" == VIBEOS_C83_CHALLENGE ]] &&
         [[ "$identity_value" == 2222222222222222222222222222222222222222222222222222222222222222 ]]; }; then
      echo "package-milkv-duo-sdk.sh: $identity_name must not use the documented test-only sentinel" >&2
      exit 2
    fi
  }
  runtime_costs_source_commit=${VIBEOS_C83_SOURCE_COMMIT-}
  runtime_costs_challenge=${VIBEOS_C83_CHALLENGE-}
  runtime_costs_declared_container=${VIBEOS_C83_SDK_CONTAINER_DIGEST-}
  require_runtime_identity VIBEOS_C83_SOURCE_COMMIT "$runtime_costs_source_commit" 40 \
    0000000000000000000000000000000000000000
  require_runtime_identity VIBEOS_C83_CHALLENGE "$runtime_costs_challenge" 64 \
    0000000000000000000000000000000000000000000000000000000000000000
  if [[ "$runtime_costs_declared_container" != "$runtime_costs_sdk_container_digest" ]]; then
    echo "package-milkv-duo-sdk.sh: VIBEOS_C83_SDK_CONTAINER_DIGEST must equal $runtime_costs_sdk_container_digest" >&2
    exit 2
  fi
  if ! sdk_git_root=$(git --no-optional-locks -C "$sdk_root" rev-parse --show-toplevel 2>/dev/null) ||
     ! sdk_head=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD 2>/dev/null); then
    echo "package-milkv-duo-sdk.sh: runtime-cost SDK root is not a readable Git checkout: $sdk_root" >&2
    exit 1
  fi
  sdk_git_root=$(cd -- "$sdk_git_root" && pwd -P)
  if [[ "$sdk_git_root" != "$sdk_root" ]]; then
    echo "package-milkv-duo-sdk.sh: runtime-cost SDK path must name its Git root: $sdk_root" >&2
    exit 1
  fi
  if [[ "$sdk_head" != "$runtime_costs_sdk_commit" ]]; then
    echo "package-milkv-duo-sdk.sh: runtime-cost SDK HEAD is $sdk_head, expected $runtime_costs_sdk_commit" >&2
    exit 1
  fi
  sdk_status=$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
  if [[ -n "$sdk_status" ]]; then
    echo "package-milkv-duo-sdk.sh: runtime-cost SDK checkout is not clean" >&2
    exit 1
  fi
  if ! vibe_head=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null); then
    echo "package-milkv-duo-sdk.sh: cannot read VibeOS source HEAD" >&2
    exit 1
  fi
  if [[ "$vibe_head" != "$runtime_costs_source_commit" ]]; then
    echo "package-milkv-duo-sdk.sh: VibeOS HEAD is $vibe_head, expected $runtime_costs_source_commit" >&2
    exit 1
  fi
  vibe_status=$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
  if [[ -n "$vibe_status" ]]; then
    echo "package-milkv-duo-sdk.sh: runtime-cost packaging requires a clean VibeOS worktree" >&2
    exit 1
  fi
  package_started_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
fi
if [[ "$wasm_aot_profile" == true ]]; then
  require_wasm_aot_profile_identity() {
    local identity_name=$1 identity_value=$2 identity_length=$3 zero_value=$4 test_value=$5
    if [[ ${#identity_value} -ne identity_length || "$identity_value" == *[!0123456789abcdef]* ]]; then
      echo "package-milkv-duo-sdk.sh: $identity_name must be exactly $identity_length lowercase hexadecimal characters" >&2
      exit 2
    fi
    if [[ "$identity_value" == "$zero_value" ]]; then
      echo "package-milkv-duo-sdk.sh: $identity_name must not use the unbound all-zero sentinel" >&2
      exit 2
    fi
    if [[ "$identity_value" == "$test_value" ]]; then
      echo "package-milkv-duo-sdk.sh: $identity_name must not use the QEMU-only test sentinel" >&2
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
    echo "package-milkv-duo-sdk.sh: VIBEOS_C84_SDK_CONTAINER_DIGEST must equal $wasm_aot_profile_sdk_container_digest" >&2
    exit 2
  fi
  if ! sdk_git_root=$(git --no-optional-locks -C "$sdk_root" rev-parse --show-toplevel 2>/dev/null) ||
     ! sdk_head=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD 2>/dev/null); then
    echo "package-milkv-duo-sdk.sh: WebAssembly AOT profile SDK root is not a readable Git checkout: $sdk_root" >&2
    exit 1
  fi
  sdk_git_root=$(cd -- "$sdk_git_root" && pwd -P)
  if [[ "$sdk_git_root" != "$sdk_root" ]]; then
    echo "package-milkv-duo-sdk.sh: WebAssembly AOT profile SDK path must name its Git root: $sdk_root" >&2
    exit 1
  fi
  if [[ "$sdk_head" != "$wasm_aot_profile_sdk_commit" ]]; then
    echo "package-milkv-duo-sdk.sh: WebAssembly AOT profile SDK HEAD is $sdk_head, expected $wasm_aot_profile_sdk_commit" >&2
    exit 1
  fi
  if [[ -n $(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
    echo "package-milkv-duo-sdk.sh: WebAssembly AOT profile SDK checkout is not clean" >&2
    exit 1
  fi
  if ! vibe_head=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null); then
    echo "package-milkv-duo-sdk.sh: cannot read VibeOS source HEAD" >&2
    exit 1
  fi
  if [[ "$vibe_head" != "$wasm_aot_profile_source_commit" ]]; then
    echo "package-milkv-duo-sdk.sh: VibeOS HEAD is $vibe_head, expected $wasm_aot_profile_source_commit" >&2
    exit 1
  fi
  if [[ -n $(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=all) ]]; then
    echo "package-milkv-duo-sdk.sh: WebAssembly AOT profile superproject is not clean" >&2
    exit 1
  fi
  "$script_dir/prepare-jitterentropy-rs.sh" >/dev/null
  jitterentropy_submodule="$repo_root/vendor/jitterentropy-rs"
  jitterentropy_patch="$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch"
  jitterentropy_head=$(git -C "$jitterentropy_submodule" rev-parse HEAD)
  if [[ "$jitterentropy_head" != c5bd2e17194fe3a04d17f74027bb67622579405f ]]; then
    echo "package-milkv-duo-sdk.sh: jitterentropy-rs HEAD differs" >&2
    exit 1
  fi
  jitterentropy_diff_record=$(python3 - "$jitterentropy_submodule" "$jitterentropy_patch" <<'PY'
import datetime
import hashlib
import pathlib
import subprocess
import sys

submodule = pathlib.Path(sys.argv[1]).resolve(strict=True)
patch = pathlib.Path(sys.argv[2]).resolve(strict=True).read_bytes()
observed = subprocess.run(
    ["git", "-C", str(submodule), "diff", "--unified=0", "--binary"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if observed != patch:
    raise SystemExit("package-milkv-duo-sdk.sh: jitterentropy-rs diff differs from the recorded patch")
if subprocess.run(
    ["git", "-C", str(submodule), "diff", "--cached", "--quiet", "--exit-code"],
).returncode != 0:
    raise SystemExit("package-milkv-duo-sdk.sh: jitterentropy-rs has staged changes")
untracked = subprocess.run(
    ["git", "-C", str(submodule), "ls-files", "--others", "--exclude-standard", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if untracked:
    raise SystemExit("package-milkv-duo-sdk.sh: jitterentropy-rs has untracked files")
print(f"{hashlib.sha256(observed).hexdigest()}:{len(observed)}")
PY
  )
  jitterentropy_diff_sha256=${jitterentropy_diff_record%:*}
  jitterentropy_diff_bytes=${jitterentropy_diff_record#*:}
  sunset_submodule="$repo_root/vendor/sunset"
  sunset_head=$(git -C "$sunset_submodule" rev-parse HEAD)
  if [[ "$sunset_head" != f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e ]] ||
     [[ -n $(git -C "$sunset_submodule" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
    echo "package-milkv-duo-sdk.sh: sunset submodule differs" >&2
    exit 1
  fi
  package_started_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
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
kernel_bin="$output_dir/vibeos-milkv-duo.bin"
kernel_elf="$output_dir/vibeos-milkv-duo-runtime-costs.elf"
if [[ "$wasm_aot_profile" == true ]]; then
  kernel_elf="$output_dir/vibeos-milkv-duo-wasm-aot-profile.elf"
fi
final_output_its="$output_dir/milkv-duo.its"
final_output_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
final_output_fit="$output_dir/boot.sd"
final_output_image="$output_dir/$image_name"
final_output_audit="$output_dir/image-verifier-audit.log"
final_output_envelope="$output_dir/package-envelope.json"
package_work_dir="$output_dir"
package_lock=
c84_stage=
c84_links_created=false
if [[ "$wasm_aot_profile" == true ]]; then
  if [[ -L "$repo_root/target" || ! -d "$repo_root/target" ]]; then
    echo "package-milkv-duo-sdk.sh: C8.4 target parent is not a fixed directory: $repo_root/target" >&2
    exit 1
  fi
  if [[ ! -d "$output_dir" || -L "$output_dir" ]]; then
    echo "package-milkv-duo-sdk.sh: C8.4 build output must be an existing non-symlink directory: $output_dir" >&2
    exit 1
  fi
  if [[ $(cd -- "$output_dir/.." && pwd -P) != "$repo_root/target" ]] ||
     [[ $(basename -- "$output_dir") != milkv-duo-wasm-aot-profile ]]; then
    echo "package-milkv-duo-sdk.sh: C8.4 output directory differs from the fixed target" >&2
    exit 1
  fi
  package_lock="$repo_root/target/.milkv-duo-wasm-aot-profile.package.lock"
  if ! mkdir -- "$package_lock" 2>/dev/null; then
    echo "package-milkv-duo-sdk.sh: C8.4 package lock already exists: $package_lock" >&2
    exit 1
  fi
  c84_early_cleanup() {
    if [[ -n "$c84_stage" && "$c84_stage" == "$repo_root"/target/.milkv-duo-wasm-aot-profile-package.* ]]; then
      rm -rf -- "$c84_stage"
    fi
    if [[ -n "$package_lock" && -d "$package_lock" && ! -L "$package_lock" ]]; then
      rmdir -- "$package_lock" 2>/dev/null || true
    fi
  }
  trap c84_early_cleanup EXIT
  for final_path in \
    "$final_output_its" "$final_output_dtb" "$final_output_fit" \
    "$final_output_image" "$final_output_audit" "$final_output_envelope"; do
    if [[ -e "$final_path" || -L "$final_path" ]]; then
      rmdir -- "$package_lock"
      echo "package-milkv-duo-sdk.sh: refusing to replace existing C8.4 output: $final_path" >&2
      exit 1
    fi
  done
  c84_stage=$(mktemp -d "$repo_root/target/.milkv-duo-wasm-aot-profile-package.XXXXXX")
  package_work_dir="$c84_stage"
fi
output_its="$package_work_dir/milkv-duo.its"
output_dtb="$package_work_dir/cv1800b_milkv_duo_sd.dtb"
output_fit="$package_work_dir/boot.sd"
output_image="$package_work_dir/$image_name"
temp_fit="$package_work_dir/.boot.sd.$$.tmp"
temp_image="$package_work_dir/.vibeos-milkv-duo-sd.img.$$.tmp"
output_audit="$package_work_dir/image-verifier-audit.log"
output_envelope="$package_work_dir/package-envelope.json"
staged_kernel_bin="$package_work_dir/vibeos-milkv-duo.bin"
build_envelope="$output_dir/build-envelope.json"
evidence_checker="$script_dir/verify-c83-evidence.py"
if [[ "$wasm_aot_profile" == true ]]; then
  evidence_checker="$script_dir/verify-c84-aot-decision.py"
fi
temp_audit="$package_work_dir/.image-verifier-audit.$$.tmp"
temp_envelope="$package_work_dir/.package-envelope.$$.tmp"
pack_dir=""

sdk_build="$sdk_root/u-boot-2021.10/build/cv1800b_milkv_duo_sd"
mkimage="$sdk_build/tools/mkimage"
dumpimage="$sdk_build/tools/dumpimage"
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
if [[ "$wasm_aot_profile" != true ]]; then
  mkdir -p "$output_dir"
  rm -f "$output_fit" "$output_image" "$temp_fit" "$temp_image"
fi
if [[ "$runtime_costs" == true ]]; then
  rm -f "$output_audit" "$output_envelope" "$temp_audit" "$temp_envelope"
fi
cleanup() {
  rm -f "$temp_fit" "$temp_image" "$temp_audit" "$temp_envelope"
  if [[ -n "$pack_dir" && "$pack_dir" == "$package_work_dir"/.vibeos-pack.* ]]; then
    rm -rf -- "$pack_dir"
  fi
  if [[ "$wasm_aot_profile" == true ]]; then
    if [[ "$c84_links_created" == true && "$published" != true ]]; then
      python3 - \
        "$output_its" "$final_output_its" "$output_dtb" "$final_output_dtb" \
        "$output_fit" "$final_output_fit" "$output_image" "$final_output_image" \
        "$output_audit" "$final_output_audit" "$output_envelope" "$final_output_envelope" <<'PY' || true
import os
import pathlib
import sys

for source_name, destination_name in zip(sys.argv[1::2], sys.argv[2::2]):
    source = pathlib.Path(source_name)
    destination = pathlib.Path(destination_name)
    try:
        source_stat = source.stat()
        destination_stat = destination.lstat()
    except FileNotFoundError:
        continue
    if destination.is_symlink():
        continue
    if (source_stat.st_dev, source_stat.st_ino) == (destination_stat.st_dev, destination_stat.st_ino):
        os.unlink(destination)
PY
    fi
    if [[ -n "$c84_stage" && "$c84_stage" == "$repo_root"/target/.milkv-duo-wasm-aot-profile-package.* ]]; then
      rm -rf -- "$c84_stage"
    fi
    if [[ -n "$package_lock" && -d "$package_lock" && ! -L "$package_lock" ]]; then
      rmdir -- "$package_lock" 2>/dev/null || true
    fi
  elif [[ "$published" != true ]]; then
    rm -f "$output_fit" "$output_image"
    if [[ "$runtime_costs" == true ]]; then
      rm -f "$output_audit" "$output_envelope"
    fi
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
if [[ "$runtime_costs" == true || "$wasm_aot_profile" == true ]]; then
  require_file "$kernel_elf"
  require_file "$dumpimage"
  require_file "$build_envelope"
  require_file "$evidence_checker"
fi
if [[ ! -x "$mkimage" ]] || ! "$mkimage" -V >/dev/null 2>&1; then
  echo "package-milkv-duo-sdk.sh: SDK mkimage cannot run here: $mkimage" >&2
  exit 1
fi
if [[ ! -x "$genimage" ]]; then
  echo "package-milkv-duo-sdk.sh: SDK genimage cannot run here: $genimage" >&2
  exit 1
fi

if [[ "$runtime_costs" == true ]]; then
  validated_build_content_sha256=$(python3 - \
    "$build_envelope" "$runtime_costs_source_commit" "$runtime_costs_challenge" \
    "$repo_root" "$kernel_elf" "$kernel_bin" \
    "$script_dir/build-milkv-duo.sh" "$repo_root/firmware/milkv-duo/Cargo.toml" \
    "$repo_root/firmware/milkv-duo/build.rs" "$repo_root/firmware/milkv-duo/linker.ld" \
    "$repo_root/firmware/.cargo/config.toml" "$repo_root/kernel/Cargo.toml" \
    "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" \
    "$repo_root/benchmarks/wasm-runtime/workloads-v1.json" "$repo_root/rust-toolchain.toml" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import stat
import sys

(
    envelope_path,
    source_commit,
    challenge,
    source_root,
    kernel_elf,
    kernel_bin,
    build_script,
    firmware_manifest,
    firmware_build_script,
    firmware_linker_script,
    firmware_cargo_config,
    kernel_manifest,
    workspace_manifest,
    cargo_lock,
    workload_manifest,
    toolchain_contract,
) = sys.argv[1:]


def fail(message):
    raise SystemExit(f"package-milkv-duo-sdk.sh: build-envelope preflight failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} fields are not closed")
    return value


def identity_record(value, label):
    record = exact(value, {"path", "sha256", "bytes"}, label)
    if (
        not isinstance(record["path"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
        or isinstance(record["bytes"], bool)
        or not isinstance(record["bytes"], int)
        or record["bytes"] <= 0
    ):
        fail(f"{label} identity is malformed")
    return record


def local_identity(path, *, scan=False):
    resolved = pathlib.Path(path).resolve(strict=True)
    before = resolved.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"cannot measure non-regular or empty file: {resolved}")
    digest = hashlib.sha256()
    found = [False, False]
    needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
    overlap = max(map(len, needles)) - 1
    tail = b""
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            if scan:
                window = tail + chunk
                found = [was_found or needle in window for was_found, needle in zip(found, needles)]
                tail = window[-overlap:]
    after = resolved.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"file changed while hashing: {resolved}")
    if scan and not all(found):
        fail(f"built artifact does not embed source/challenge: {resolved}")
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


def match(local, recorded, label):
    if local["sha256"] != recorded["sha256"] or local["bytes"] != recorded["bytes"]:
        fail(f"{label} differs from the build envelope")


path = pathlib.Path(envelope_path).resolve(strict=True)
before = path.stat()
try:
    root = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode build envelope: {error}")
root = exact(root, {"schema", "version", "status", "content_sha256", "content"}, "build envelope")
if (
    root["schema"] != "vibeos.c83.duo-runtime-costs.build-envelope"
    or root["version"] != 1
    or root["status"] != "closed"
):
    fail("build envelope identity/status differs")
content = exact(
    root["content"],
    {
        "platform",
        "source_commit",
        "challenge",
        "source",
        "command",
        "objcopy_command",
        "objcopy_environment",
        "environment",
        "toolchain",
        "artifacts",
        "tools",
        "timestamps_utc",
    },
    "build content",
)
canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(canonical).hexdigest() != root["content_sha256"]:
    fail("build content address differs")
if content["platform"] != "milkv-duo-cv1800b":
    fail("build platform differs")
if content["source_commit"] != source_commit or content["challenge"] != challenge:
    fail("build source/challenge differs")
source = exact(content["source"], {"root", "head", "worktree_clean", "status_policy"}, "build source")
if (
    source["head"] != source_commit
    or source["worktree_clean"] is not True
    or source["status_policy"] != "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none"
    or not isinstance(source["root"], str)
    or not source["root"]
):
    fail("build source checkout attestation differs")

toolchain = exact(
    content["toolchain"],
    {"channel", "rustc_verbose", "rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"},
    "build toolchain",
)
for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
    identity_record(toolchain[name], f"build toolchain {name}")
contract_text = pathlib.Path(toolchain_contract).read_text(encoding="utf-8")
channel_match = re.search(r'^channel = "([^"]+)"$', contract_text, re.MULTILINE)
rustc_match = re.search(r"^# rustc (.+)$", contract_text, re.MULTILINE)
commit_match = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", contract_text, re.MULTILINE)
if not channel_match or not rustc_match or not commit_match:
    fail("toolchain contract is incomplete")
if toolchain["channel"] != channel_match.group(1):
    fail("build toolchain channel differs")
verbose_lines = toolchain["rustc_verbose"].splitlines() if isinstance(toolchain["rustc_verbose"], str) else []
if not verbose_lines or verbose_lines[0] != f"rustc {rustc_match.group(1)}":
    fail("build rustc identity differs")
if f"commit-hash: {commit_match.group(1)}" not in verbose_lines:
    fail("build rustc commit differs")

expected_command = [
    toolchain["rustup"]["path"],
    "run",
    toolchain["channel"],
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--no-default-features",
    "--features",
    "wasm-c83-runtime-costs",
]
if content["command"] != expected_command:
    fail("build command differs from the closed runtime-cost command")
artifacts = exact(content["artifacts"], {"kernel_elf", "kernel_binary"}, "build artifacts")
artifact_records = {
    "kernel_elf": identity_record(artifacts["kernel_elf"], "build kernel ELF"),
    "kernel_binary": identity_record(artifacts["kernel_binary"], "build kernel binary"),
}
match(local_identity(kernel_elf, scan=True), artifact_records["kernel_elf"], "kernel ELF")
match(local_identity(kernel_bin, scan=True), artifact_records["kernel_binary"], "kernel binary")
expected_objcopy = [
    toolchain["rust_objcopy"]["path"],
    "-O",
    "binary",
    artifact_records["kernel_elf"]["path"],
    artifact_records["kernel_binary"]["path"],
]
if content["objcopy_command"] != expected_objcopy:
    fail("objcopy command differs")
objcopy_environment = exact(
    content["objcopy_environment"],
    {"mode", "allowed_keys", "values"},
    "objcopy environment",
)
if objcopy_environment["mode"] != "env -i":
    fail("objcopy did not use an empty environment")
objcopy_keys = objcopy_environment["allowed_keys"]
objcopy_values = objcopy_environment["values"]
if objcopy_keys == ["LC_ALL", "PATH", "TZ"]:
    if objcopy_values != {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}:
        fail("objcopy environment values differ")
elif objcopy_keys == ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"]:
    expected_lib = str(pathlib.Path(toolchain["rust_objcopy"]["path"]).parents[3])
    if objcopy_values != {
        "DYLD_LIBRARY_PATH": expected_lib,
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }:
        fail("Darwin objcopy environment values differ")
else:
    fail("objcopy environment allowlist differs")

environment = exact(content["environment"], {"mode", "allowed_keys", "values", "cargo_home_isolation"}, "build environment")
expected_keys = [
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "HOME",
    "LC_ALL",
    "PATH",
    "RUSTC",
    "RUSTDOC",
    "RUSTUP_HOME",
    "SOURCE_DATE_EPOCH",
    "TMPDIR",
    "TZ",
    "VIBEOS_C83_CHALLENGE",
    "VIBEOS_C83_SOURCE_COMMIT",
]
if environment["mode"] != "env -i" or environment["allowed_keys"] != expected_keys:
    fail("build environment allowlist differs")
values = exact(environment["values"], set(expected_keys), "build environment values")
if (
    values["CARGO_HOME"] != "<isolated-cargo-home>"
    or values["HOME"] != "<isolated-cargo-home>/home"
    or values["TMPDIR"] != "<isolated-cargo-home>/tmp"
    or values["CARGO_INCREMENTAL"] != "0"
    or values["CARGO_NET_OFFLINE"] != "true"
    or values["LC_ALL"] != "C"
    or values["TZ"] != "UTC"
    or values["VIBEOS_C83_SOURCE_COMMIT"] != source_commit
    or values["VIBEOS_C83_CHALLENGE"] != challenge
    or values["RUSTC"] != toolchain["rustc"]["path"]
    or values["RUSTDOC"] != toolchain["rustdoc"]["path"]
    or not isinstance(values["RUSTUP_HOME"], str)
    or not values["RUSTUP_HOME"]
    or not isinstance(values["SOURCE_DATE_EPOCH"], str)
    or not values["SOURCE_DATE_EPOCH"].isdigit()
):
    fail("build environment values differ")
path_parts = values["PATH"].split(":") if isinstance(values["PATH"], str) else []
if (
    len(path_parts) != 5
    or pathlib.PurePath(path_parts[0]).name != "closed-bin"
    or not pathlib.PurePath(path_parts[0]).parent.name.startswith("vibeos-c83-cargo-home.")
    or path_parts[1:] != ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
):
    fail("build PATH is not the isolated linker path plus fixed system paths")
expected_target_suffix = pathlib.PurePath("target/c83-milkv-build") / source_commit / challenge
target_parts = pathlib.PurePath(values["CARGO_TARGET_DIR"]).parts
if tuple(target_parts[-len(expected_target_suffix.parts) :]) != expected_target_suffix.parts:
    fail("build target directory differs")
isolation = exact(
    environment["cargo_home_isolation"],
    {"ambient_config_loaded", "temporary", "cache_source", "registry_cache_symlinked", "git_cache_symlinked"},
    "Cargo-home isolation",
)
if isolation["ambient_config_loaded"] is not False or isolation["temporary"] is not True:
    fail("ambient Cargo configuration was not closed")
if not isinstance(isolation["cache_source"], str) or not isolation["cache_source"]:
    fail("Cargo cache source is empty")
for name in ("registry_cache_symlinked", "git_cache_symlinked"):
    if not isinstance(isolation[name], bool):
        fail(f"Cargo-home isolation {name} is not boolean")

expected_tools = {
    "build_script": build_script,
    "firmware_manifest": firmware_manifest,
    "firmware_build_script": firmware_build_script,
    "firmware_linker_script": firmware_linker_script,
    "firmware_cargo_config": firmware_cargo_config,
    "kernel_manifest": kernel_manifest,
    "workspace_manifest": workspace_manifest,
    "cargo_lock": cargo_lock,
    "workload_manifest": workload_manifest,
    "toolchain_contract": toolchain_contract,
}
tools = exact(content["tools"], set(expected_tools), "build tools")
for name, local_path in expected_tools.items():
    recorded = identity_record(tools[name], f"build tool {name}")
    match(local_identity(local_path), recorded, f"build tool {name}")

timestamps = exact(
    content["timestamps_utc"],
    {"build_started", "build_completed", "envelope_closed"},
    "build timestamps",
)
for name, value in timestamps.items():
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"build timestamp {name} is not UTC")
    try:
        datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"build timestamp {name} is invalid: {error}")
after = path.stat()
if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
    after.st_dev,
    after.st_ino,
    after.st_size,
    after.st_mtime_ns,
):
    fail("build envelope changed during preflight")
print(root["content_sha256"])
PY
  )
  echo "package-milkv-duo-sdk.sh runtime-cost build-envelope preflight: PASS content=$validated_build_content_sha256"
fi
if [[ "$wasm_aot_profile" == true ]]; then
  validated_build_record=$(python3 - \
    "$build_envelope" "$wasm_aot_profile_source_commit" \
    "$wasm_aot_profile_challenge" "$repo_root" "$kernel_elf" "$kernel_bin" \
    "$script_dir/build-milkv-duo.sh" "$script_dir/prepare-jitterentropy-rs.sh" \
    "$jitterentropy_patch" "$jitterentropy_submodule" "$jitterentropy_head" \
    "$jitterentropy_diff_sha256" "$jitterentropy_diff_bytes" \
    "$sunset_submodule" "$sunset_head" "$repo_root/.gitmodules" \
    "$repo_root/firmware/milkv-duo/Cargo.toml" \
    "$repo_root/firmware/milkv-duo/build.rs" \
    "$repo_root/firmware/milkv-duo/linker.ld" \
    "$repo_root/firmware/.cargo/config.toml" "$repo_root/kernel/Cargo.toml" \
    "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" \
    "$repo_root/benchmarks/wasm-aot-decision/workloads-v1.json" \
    "$repo_root/benchmarks/wasm-aot-decision/schema-v1.json" \
    "$repo_root/rust-toolchain.toml" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import stat
import sys

(
    envelope_path,
    source_commit,
    challenge,
    source_root,
    kernel_elf,
    kernel_bin,
    build_script,
    prepare_jitterentropy_script,
    jitterentropy_patch,
    jitterentropy_submodule,
    jitterentropy_head,
    jitterentropy_diff_sha256,
    jitterentropy_diff_bytes,
    sunset_submodule,
    sunset_head,
    gitmodules,
    firmware_manifest,
    firmware_build_script,
    firmware_linker_script,
    firmware_cargo_config,
    kernel_manifest,
    workspace_manifest,
    cargo_lock,
    workload_manifest,
    transcript_schema,
    toolchain_contract,
) = sys.argv[1:]


def fail(message):
    raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 build-envelope preflight failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} fields are not closed")
    return value


def identity_record(value, label):
    record = exact(value, {"path", "sha256", "bytes"}, label)
    if (
        not isinstance(record["path"], str)
        or not record["path"]
        or not isinstance(record["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or type(record["bytes"]) is not int
        or record["bytes"] <= 0
    ):
        fail(f"{label} identity is malformed")
    return record


def local_identity(path, *, scan=False):
    resolved = pathlib.Path(path).resolve(strict=True)
    before = resolved.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"cannot measure non-regular or empty file: {resolved}")
    digest = hashlib.sha256()
    needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
    found = [False, False]
    overlap = max(map(len, needles)) - 1
    tail = b""
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            if scan:
                window = tail + chunk
                found = [seen or needle in window for seen, needle in zip(found, needles)]
                tail = window[-overlap:]
    after = resolved.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"file changed while hashing: {resolved}")
    if scan and not all(found):
        fail(f"built artifact does not embed source/challenge: {resolved}")
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


def match(local, recorded, label):
    if local["sha256"] != recorded["sha256"] or local["bytes"] != recorded["bytes"]:
        fail(f"{label} differs from the build envelope")


path = pathlib.Path(envelope_path).resolve(strict=True)
before = path.stat()
if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
    fail("build envelope is not a non-empty regular file")
try:
    root = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode build envelope: {error}")
root = exact(root, {"schema", "version", "status", "content_sha256", "content"}, "build envelope")
if (
    root["schema"] != "vibeos.c84.duo-wasm-aot-profile.build-envelope"
    or type(root["version"]) is not int
    or root["version"] != 1
    or root["status"] != "closed"
    or not isinstance(root["content_sha256"], str)
    or re.fullmatch(r"[0-9a-f]{64}", root["content_sha256"]) is None
):
    fail("build envelope identity/status differs")
content = exact(
    root["content"],
    {
        "platform", "source_commit", "challenge", "run_id", "source", "command",
        "objcopy_command", "objcopy_environment", "environment", "toolchain",
        "artifacts", "tools", "timestamps_utc",
    },
    "build content",
)
canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(canonical).hexdigest() != root["content_sha256"]:
    fail("build content address differs")
if content["platform"] != "milkv-duo-cv1800b":
    fail("build platform differs")
if content["source_commit"] != source_commit or content["challenge"] != challenge:
    fail("build source/challenge differs")
source = exact(
    content["source"],
    {"root", "head", "superproject_clean", "status_policy", "jitterentropy", "sunset"},
    "build source",
)
if (
    source["head"] != source_commit
    or source["superproject_clean"] is not True
    or source["status_policy"] != "git status --porcelain=v1 --untracked-files=all --ignore-submodules=all"
    or source["root"] != "."
):
    fail("build source checkout attestation differs")
jitter = exact(
    source["jitterentropy"],
    {"path", "head", "patch_sha256", "patch_bytes", "observed_diff_sha256", "observed_diff_bytes", "policy"},
    "jitterentropy source",
)
patch_local = local_identity(jitterentropy_patch)
if (
    jitter["path"] != "vendor/jitterentropy-rs"
    or jitter["head"] != jitterentropy_head
    or jitter["patch_sha256"] != patch_local["sha256"]
    or jitter["patch_bytes"] != patch_local["bytes"]
    or jitter["observed_diff_sha256"] != jitterentropy_diff_sha256
    or jitter["observed_diff_bytes"] != int(jitterentropy_diff_bytes)
    or jitter["policy"] != "exact recorded patch verified by prepare-jitterentropy-rs.sh"
):
    fail("jitterentropy patch attestation differs")
sunset = exact(source["sunset"], {"path", "head", "worktree_clean", "status_policy"}, "sunset source")
if (
    sunset["path"] != "vendor/sunset"
    or sunset["head"] != sunset_head
    or sunset["worktree_clean"] is not True
    or sunset["status_policy"] != "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none"
):
    fail("sunset source attestation differs")

toolchain = exact(
    content["toolchain"],
    {
        "provenance", "channel", "rustc_verbose", "rustup", "cargo", "rustc",
        "rustdoc", "rust_objcopy", "linker",
    },
    "build toolchain",
)
if toolchain["provenance"] != "build-runner-self-measured; package cross-platform live rehash unavailable":
    fail("build toolchain provenance differs")
for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
    record = identity_record(toolchain[name], f"build toolchain {name}")
    if not pathlib.PurePath(record["path"]).is_absolute():
        fail(f"build toolchain {name} build-runner path is not absolute")
contract_text = pathlib.Path(toolchain_contract).read_text(encoding="utf-8")
channel_match = re.search(r'^channel = "([^"]+)"$', contract_text, re.MULTILINE)
rustc_match = re.search(r"^# rustc (.+)$", contract_text, re.MULTILINE)
commit_match = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", contract_text, re.MULTILINE)
if not channel_match or not rustc_match or not commit_match:
    fail("toolchain contract is incomplete")
verbose_lines = toolchain["rustc_verbose"].splitlines() if isinstance(toolchain["rustc_verbose"], str) else []
if (
    toolchain["channel"] != channel_match.group(1)
    or not verbose_lines
    or verbose_lines[0] != f"rustc {rustc_match.group(1)}"
    or f"commit-hash: {commit_match.group(1)}" not in verbose_lines
):
    fail("build toolchain pin differs")
expected_command = [
    toolchain["rustup"]["path"], "run", toolchain["channel"], "cargo", "build",
    "--release", "--locked", "--offline", "--no-default-features", "--features",
    "wasm-c84-ssh-managed-child-single-boot-collector",
]
if content["command"] != expected_command:
    fail("build command differs")
artifacts = exact(content["artifacts"], {"kernel_elf", "kernel_binary"}, "build artifacts")
artifact_records = {
    "kernel_elf": identity_record(artifacts["kernel_elf"], "build kernel ELF"),
    "kernel_binary": identity_record(artifacts["kernel_binary"], "build kernel binary"),
}
stage_root = (
    pathlib.PurePosixPath("target")
    / f".milkv-duo-wasm-aot-profile.stage.{source_commit}.{challenge}"
)
expected_artifact_paths = {
    "kernel_elf": str(stage_root / "vibeos-milkv-duo-wasm-aot-profile.elf"),
    "kernel_binary": str(stage_root / "vibeos-milkv-duo.bin"),
}
for name, record in artifact_records.items():
    if record["path"] != expected_artifact_paths[name]:
        fail(f"build {name} logical path differs")
match(local_identity(kernel_elf, scan=True), artifact_records["kernel_elf"], "kernel ELF")
match(local_identity(kernel_bin, scan=True), artifact_records["kernel_binary"], "kernel binary")
expected_objcopy = [
    toolchain["rust_objcopy"]["path"], "-O", "binary",
    artifact_records["kernel_elf"]["path"], artifact_records["kernel_binary"]["path"],
]
if content["objcopy_command"] != expected_objcopy:
    fail("objcopy command differs")
objcopy = exact(content["objcopy_environment"], {"mode", "allowed_keys", "values"}, "objcopy environment")
if objcopy["mode"] != "env -i" or objcopy["allowed_keys"] not in (
    ["LC_ALL", "PATH", "TZ"],
    ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"],
):
    fail("objcopy environment differs")
if set(objcopy["values"]) != set(objcopy["allowed_keys"]):
    fail("objcopy environment values are not closed")
if objcopy["values"].get("LC_ALL") != "C" or objcopy["values"].get("PATH") != "/usr/bin:/bin" or objcopy["values"].get("TZ") != "UTC":
    fail("objcopy environment values differ")
environment = exact(content["environment"], {"mode", "allowed_keys", "values", "cargo_home_isolation"}, "build environment")
expected_keys = [
    "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "HOME",
    "LC_ALL", "PATH", "RUSTC", "RUSTDOC", "RUSTUP_HOME", "SOURCE_DATE_EPOCH", "TMPDIR",
    "TZ", "VIBEOS_C84_CHALLENGE", "VIBEOS_C84_SOURCE_COMMIT",
]
if environment["mode"] != "env -i" or environment["allowed_keys"] != expected_keys:
    fail("build environment allowlist differs")
values = exact(environment["values"], set(expected_keys), "build environment values")
if (
    values["CARGO_HOME"] != "<isolated-cargo-home>"
    or values["HOME"] != "<isolated-cargo-home>/home"
    or values["TMPDIR"] != "<isolated-cargo-home>/tmp"
    or values["CARGO_INCREMENTAL"] != "0"
    or values["CARGO_NET_OFFLINE"] != "true"
    or values["LC_ALL"] != "C"
    or values["TZ"] != "UTC"
    or values["VIBEOS_C84_SOURCE_COMMIT"] != source_commit
    or values["VIBEOS_C84_CHALLENGE"] != challenge
    or values["RUSTC"] != toolchain["rustc"]["path"]
    or values["RUSTDOC"] != toolchain["rustdoc"]["path"]
    or not isinstance(values["SOURCE_DATE_EPOCH"], str)
    or not values["SOURCE_DATE_EPOCH"].isdigit()
):
    fail("build environment values differ")
path_parts = values["PATH"].split(":") if isinstance(values["PATH"], str) else []
if (
    len(path_parts) != 5
    or pathlib.PurePath(path_parts[0]).name != "closed-bin"
    or not pathlib.PurePath(path_parts[0]).parent.name.startswith("vibeos-c84-cargo-home.")
    or path_parts[1:] != ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
):
    fail("build PATH differs")
expected_target = pathlib.PurePath("target/c84-milkv-build") / source_commit / challenge
target_parts = pathlib.PurePath(values["CARGO_TARGET_DIR"]).parts
if tuple(target_parts[-len(expected_target.parts):]) != expected_target.parts:
    fail("build target directory differs")
isolation = exact(
    environment["cargo_home_isolation"],
    {"ambient_config_loaded", "temporary", "cache_source", "registry_cache_symlinked", "git_cache_symlinked"},
    "Cargo-home isolation",
)
if isolation["ambient_config_loaded"] is not False or isolation["temporary"] is not True:
    fail("ambient Cargo configuration was not closed")
if type(isolation["registry_cache_symlinked"]) is not bool or type(isolation["git_cache_symlinked"]) is not bool:
    fail("Cargo cache attestations are not boolean")
expected_tools = {
    "build_script": (build_script, "scripts/build-milkv-duo.sh"),
    "prepare_jitterentropy_script": (prepare_jitterentropy_script, "scripts/prepare-jitterentropy-rs.sh"),
    "jitterentropy_patch": (jitterentropy_patch, "patches/jitterentropy-rs/0001-vibeos-qualification.patch"),
    "gitmodules": (gitmodules, ".gitmodules"),
    "firmware_manifest": (firmware_manifest, "firmware/milkv-duo/Cargo.toml"),
    "firmware_build_script": (firmware_build_script, "firmware/milkv-duo/build.rs"),
    "firmware_linker_script": (firmware_linker_script, "firmware/milkv-duo/linker.ld"),
    "firmware_cargo_config": (firmware_cargo_config, "firmware/.cargo/config.toml"),
    "kernel_manifest": (kernel_manifest, "kernel/Cargo.toml"),
    "workspace_manifest": (workspace_manifest, "Cargo.toml"),
    "cargo_lock": (cargo_lock, "Cargo.lock"),
    "workload_manifest": (workload_manifest, "benchmarks/wasm-aot-decision/workloads-v1.json"),
    "transcript_schema": (transcript_schema, "benchmarks/wasm-aot-decision/schema-v1.json"),
    "toolchain_contract": (toolchain_contract, "rust-toolchain.toml"),
}
tools = exact(content["tools"], set(expected_tools), "build tools")
for name, (local_path, logical_path) in expected_tools.items():
    record = identity_record(tools[name], f"build tool {name}")
    if record["path"] != logical_path:
        fail(f"build tool {name} logical path differs")
    match(local_identity(local_path), record, f"build tool {name}")
try:
    workload = json.loads(pathlib.Path(workload_manifest).read_text(encoding="utf-8"))
    fixture = workload["fixture"]
    fields = [
        "vibeos.c84.aot-decision.run-id.v1", source_commit, challenge,
        fixture["artifact"]["sha256"], fixture["input"]["sha256"], fixture["output"]["sha256"],
        tools["workload_manifest"]["sha256"], tools["transcript_schema"]["sha256"],
    ]
except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
    fail(f"cannot derive run id: {error}")
expected_run_id = hashlib.sha256("\0".join(fields).encode("ascii")).hexdigest()
if content["run_id"] != expected_run_id:
    fail("run id does not bind the C8.4 campaign")
timestamps = exact(content["timestamps_utc"], {"build_started", "build_completed", "envelope_closed"}, "build timestamps")
parsed = []
for name in ("build_started", "build_completed", "envelope_closed"):
    value = timestamps[name]
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"build timestamp {name} is not UTC")
    try:
        parsed.append(datetime.datetime.fromisoformat(value[:-1] + "+00:00"))
    except ValueError as error:
        fail(f"build timestamp {name} is invalid: {error}")
if parsed != sorted(parsed):
    fail("build timestamps are reversed")
after = path.stat()
if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
):
    fail("build envelope changed during preflight")
print(f'{root["content_sha256"]}:{artifact_records["kernel_binary"]["sha256"]}:{artifact_records["kernel_binary"]["bytes"]}')
PY
  )
  IFS=: read -r validated_build_content_sha256 validated_kernel_sha256 validated_kernel_bytes <<<"$validated_build_record"
  if [[ ! "$validated_build_content_sha256" =~ ^[0-9a-f]{64}$ ]] ||
     [[ ! "$validated_kernel_sha256" =~ ^[0-9a-f]{64}$ ]] ||
     [[ ! "$validated_kernel_bytes" =~ ^[1-9][0-9]*$ ]]; then
    echo "package-milkv-duo-sdk.sh: C8.4 validated build identity record is malformed" >&2
    exit 1
  fi
  echo "package-milkv-duo-sdk.sh C8.4 build-envelope preflight: PASS content=$validated_build_content_sha256"
  python3 - "$kernel_bin" "$staged_kernel_bin" "$validated_kernel_sha256" "$validated_kernel_bytes" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected_sha256 = sys.argv[3]
expected_bytes = int(sys.argv[4])
if stat.S_ISLNK(source.lstat().st_mode) or not source.is_file():
    raise SystemExit("package-milkv-duo-sdk.sh: canonical C8.4 kernel is not a regular non-symlink file")
if destination.exists() or destination.is_symlink():
    raise SystemExit("package-milkv-duo-sdk.sh: staged C8.4 kernel destination already exists")
before = source.stat()
digest = hashlib.sha256()
count = 0
with source.open("rb") as input_file, destination.open("xb") as output_file:
    while chunk := input_file.read(4 * 1024 * 1024):
        digest.update(chunk)
        count += len(chunk)
        output_file.write(chunk)
    output_file.flush()
    os.fsync(output_file.fileno())
after = source.stat()
if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
):
    raise SystemExit("package-milkv-duo-sdk.sh: canonical C8.4 kernel changed during stable copy")
if count != expected_bytes or digest.hexdigest() != expected_sha256:
    raise SystemExit("package-milkv-duo-sdk.sh: canonical C8.4 kernel differs from build-envelope identity")
copied = destination.read_bytes()
if len(copied) != expected_bytes or hashlib.sha256(copied).hexdigest() != expected_sha256:
    raise SystemExit("package-milkv-duo-sdk.sh: staged C8.4 kernel differs after stable copy")
parent_descriptor = os.open(destination.parent, os.O_RDONLY)
try:
    os.fsync(parent_descriptor)
finally:
    os.close(parent_descriptor)
PY
fi

cp "$script_dir/milkv-duo.its" "$output_its"
cp "$sdk_dtb" "$output_dtb"

(
  cd "$package_work_dir"
  if [[ "$wasm_aot_profile" == true ]]; then
    env -i LC_ALL=C PATH=/usr/bin:/bin TZ=UTC \
      "$mkimage" -f milkv-duo.its "$(basename -- "$temp_fit")"
    env -i LC_ALL=C PATH=/usr/bin:/bin TZ=UTC \
      "$mkimage" -l "$(basename -- "$temp_fit")"
  else
    "$mkimage" -f milkv-duo.its "$(basename -- "$temp_fit")"
    "$mkimage" -l "$(basename -- "$temp_fit")"
  fi
)

pack_dir=$(mktemp -d "$package_work_dir/.vibeos-pack.XXXXXX")
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
    data.truncate(512 * 1024 * 1024)
with open(path, "r+b") as data:
    data.seek(7 * sector_size)
    data.write(seed)
PY

if [[ "$wasm_aot_profile" == true ]]; then
  env -i HOME=/nonexistent LC_ALL=C LD_LIBRARY_PATH="$genimage_lib" \
    PATH="$(dirname -- "$genimage"):/usr/bin:/bin:/usr/sbin:/sbin" TZ=UTC \
    "$genimage" \
    --config "$script_dir/milkv-duo-genimage.cfg" \
    --rootpath "$pack_dir/root" \
    --tmppath "$pack_dir/tmp" \
    --inputpath "$pack_dir/input" \
    --outputpath "$pack_dir/output"
else
  LD_LIBRARY_PATH="$genimage_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$genimage" \
    --config "$script_dir/milkv-duo-genimage.cfg" \
    --rootpath "$pack_dir/root" \
    --tmppath "$pack_dir/tmp" \
    --inputpath "$pack_dir/input" \
    --outputpath "$pack_dir/output"
fi

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
elif [[ "$iperf3_server" == true ]]; then
  verify_args=(--iperf3-server "$sdk_root")
elif [[ "$file_tree" == true ]]; then
  verify_args=(--file-tree "$sdk_root")
elif [[ "$runtime_costs" == true ]]; then
  verify_args=(--runtime-costs "$sdk_root")
elif [[ "$wasm_aot_profile" == true ]]; then
  verify_args=(--wasm-aot-profile "--artifact-root=$package_work_dir" "$sdk_root")
fi
if [[ "$runtime_costs" == true ]]; then
  if ! "$script_dir/verify-milkv-duo-image.sh" "${verify_args[@]}" >"$temp_audit" 2>&1; then
    cat "$temp_audit" >&2
    echo "package-milkv-duo-sdk.sh: refusing to publish an unverified SD image" >&2
    exit 1
  fi
  cat "$temp_audit"
  mv "$temp_audit" "$output_audit"
  verification_completed_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
  if [[ $(git --no-optional-locks -C "$sdk_root" rev-parse HEAD) != "$runtime_costs_sdk_commit" ]] ||
     [[ -n $(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
    echo "package-milkv-duo-sdk.sh: SDK checkout changed before evidence closure" >&2
    exit 1
  fi
  if [[ $(git -C "$repo_root" rev-parse HEAD) != "$runtime_costs_source_commit" ]] ||
     [[ -n $(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
    echo "package-milkv-duo-sdk.sh: VibeOS source changed before evidence closure" >&2
    exit 1
  fi
  python3 - \
    "$temp_envelope" "$runtime_costs_source_commit" "$runtime_costs_challenge" \
    "$sdk_root" "$runtime_costs_sdk_commit" "$runtime_costs_declared_container" \
    "$repo_root" "$kernel_elf" "$kernel_bin" "$output_fit" "$output_image" \
    "$sdk_fip" "$sdk_dtb" "$output_audit" \
    "$script_dir/package-milkv-duo-sdk.sh" "$script_dir/verify-milkv-duo-image.sh" \
    "$script_dir/build-milkv-duo.sh" "$script_dir/milkv-duo.its" \
    "$script_dir/milkv-duo-genimage.cfg" "$repo_root/benchmarks/wasm-runtime/workloads-v1.json" \
    "$repo_root/rust-toolchain.toml" "$evidence_checker" "$mkimage" "$dumpimage" "$genimage" \
    "$build_envelope" "$validated_build_content_sha256" \
    "$package_started_utc" "$verification_completed_utc" <<'PY'
import datetime
import hashlib
import json
import pathlib
import stat
import sys

(
    destination,
    source_commit,
    challenge,
    sdk_root,
    sdk_commit,
    container_digest,
    source_root,
    kernel_elf,
    kernel_bin,
    fit,
    image,
    sdk_fip,
    sdk_dtb,
    audit_log,
    package_script,
    image_verifier,
    build_script,
    its_source,
    genimage_config,
    workload_manifest,
    toolchain_contract,
    evidence_checker,
    mkimage,
    dumpimage,
    genimage,
    build_envelope,
    validated_build_content_sha256,
    packaging_started_utc,
    image_verified_utc,
) = sys.argv[1:]


def fail(message):
    raise SystemExit(f"package-milkv-duo-sdk.sh: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def identity(path, *, require_build_identity=False):
    resolved = pathlib.Path(path).resolve(strict=True)
    before = resolved.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"cannot attest non-regular or empty file: {resolved}")
    digest = hashlib.sha256()
    found_source = False
    found_challenge = False
    overlap = max(len(source_commit), len(challenge)) - 1
    tail = b""
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            if require_build_identity:
                window = tail + chunk
                found_source = found_source or source_commit.encode("ascii") in window
                found_challenge = found_challenge or challenge.encode("ascii") in window
                tail = window[-overlap:]
    after = resolved.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"file changed while hashing: {resolved}")
    if require_build_identity and not (found_source and found_challenge):
        fail(f"measured artifact does not embed source/challenge: {resolved}")
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


audit_bytes = pathlib.Path(audit_log).read_bytes()
if b"PASS: FAT boot + raw data MBR image" not in audit_bytes:
    fail("image verifier audit log has no terminal PASS marker")
audit_identity = identity(audit_log)
if pathlib.Path(audit_log).read_bytes() != audit_bytes:
    fail("image verifier audit changed while package evidence was assembled")

artifacts = {
    "kernel_elf": identity(kernel_elf, require_build_identity=True),
    "kernel_binary": identity(kernel_bin, require_build_identity=True),
    "fit_boot_sd": identity(fit, require_build_identity=True),
    "full_sd_image": identity(image, require_build_identity=True),
    "sdk_fip": identity(sdk_fip),
    "sdk_dtb": identity(sdk_dtb),
}
tools = {
    "package_script": identity(package_script),
    "image_verifier_script": identity(image_verifier),
    "build_script": identity(build_script),
    "fit_source": identity(its_source),
    "genimage_config": identity(genimage_config),
    "workload_manifest": identity(workload_manifest),
    "toolchain_contract": identity(toolchain_contract),
    "evidence_checker": identity(evidence_checker),
    "sdk_mkimage": identity(mkimage),
    "sdk_dumpimage": identity(dumpimage),
    "sdk_genimage": identity(genimage),
}
try:
    build_root = json.loads(
        pathlib.Path(build_envelope).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode build envelope at package closure: {error}")
if set(build_root) != {"schema", "version", "status", "content_sha256", "content"}:
    fail("build envelope fields are not closed at package closure")
if (
    build_root["schema"] != "vibeos.c83.duo-runtime-costs.build-envelope"
    or build_root["version"] != 1
    or build_root["status"] != "closed"
):
    fail("build envelope identity/status differs at package closure")
build_content = build_root["content"]
build_canonical = json.dumps(build_content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(build_canonical).hexdigest() != build_root["content_sha256"]:
    fail("build envelope content address differs at package closure")
if build_root["content_sha256"] != validated_build_content_sha256:
    fail("build envelope differs from the fully validated preflight content")
if build_content.get("source_commit") != source_commit or build_content.get("challenge") != challenge:
    fail("build envelope source/challenge differs at package closure")
build_artifacts = build_content.get("artifacts")
if not isinstance(build_artifacts, dict) or set(build_artifacts) != {"kernel_elf", "kernel_binary"}:
    fail("build envelope artifact fields differ at package closure")
for role in ("kernel_elf", "kernel_binary"):
    record = build_artifacts[role]
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        fail(f"build envelope {role} identity is malformed at package closure")
    if record["sha256"] != artifacts[role]["sha256"] or record["bytes"] != artifacts[role]["bytes"]:
        fail(f"build envelope {role} differs at package closure")
build_envelope_identity = identity(build_envelope)
try:
    build_root_recheck = json.loads(
        pathlib.Path(build_envelope).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot re-decode build envelope at package closure: {error}")
if build_root_recheck != build_root:
    fail("build envelope changed while package evidence was assembled")
build = {
    "content_sha256": build_root["content_sha256"],
    "envelope": build_envelope_identity,
}
closed_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
content = {
    "platform": "milkv-duo-cv1800b",
    "source_commit": source_commit,
    "challenge": challenge,
    "source": {
        "root": str(pathlib.Path(source_root).resolve(strict=True)),
        "head": source_commit,
        "worktree_clean": True,
        "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
    },
    "sdk": {
        "root": str(pathlib.Path(sdk_root).resolve(strict=True)),
        "commit": sdk_commit,
        "declared_container_digest": container_digest,
        "worktree_clean": True,
        "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
    },
    "build": build,
    "artifacts": artifacts,
    "verifier": {
        "status": "PASS",
        "audit_log": audit_identity,
        "invocation": ["scripts/verify-milkv-duo-image.sh", "--runtime-costs", "<sdk-root>"],
    },
    "tools": tools,
    "timestamps_utc": {
        "packaging_started": packaging_started_utc,
        "image_verified": image_verified_utc,
        "envelope_closed": closed_utc,
    },
}
canonical_content = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
envelope = {
    "schema": "vibeos.c83.duo-runtime-costs.package-envelope",
    "version": 1,
    "status": "closed",
    "content_sha256": hashlib.sha256(canonical_content).hexdigest(),
    "content": content,
}
with pathlib.Path(destination).open("x", encoding="utf-8") as output:
    json.dump(envelope, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  mv "$temp_envelope" "$output_envelope"
  python3 - "$output_envelope" <<'PY'
import hashlib
import json
import pathlib
import sys

envelope_path = pathlib.Path(sys.argv[1]).resolve(strict=True)


def fail(message):
    raise SystemExit(f"package-milkv-duo-sdk.sh: closure rehash failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


envelope_before = envelope_path.stat()
envelope_bytes = envelope_path.read_bytes()
try:
    envelope = json.loads(
        envelope_bytes.decode("utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode package envelope: {error}")
if set(envelope) != {"schema", "version", "status", "content_sha256", "content"}:
    fail("package envelope fields are not closed")
if (
    envelope["schema"] != "vibeos.c83.duo-runtime-costs.package-envelope"
    or envelope["version"] != 1
    or envelope["status"] != "closed"
):
    fail("package envelope identity/status differs")
content = envelope.get("content")
if not isinstance(content, dict):
    fail("package content is missing")
canonical_content = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(canonical_content).hexdigest() != envelope.get("content_sha256"):
    fail("content address differs")

records = []
for section_name in ("artifacts", "tools"):
    section = content.get(section_name)
    if not isinstance(section, dict):
        fail(f"{section_name} section is missing")
    records.extend((f"{section_name}.{name}", record) for name, record in section.items())
verifier = content.get("verifier")
if not isinstance(verifier, dict):
    fail("verifier section is missing")
records.append(("verifier.audit_log", verifier.get("audit_log")))
build = content.get("build")
if not isinstance(build, dict) or set(build) != {"content_sha256", "envelope"}:
    fail("build section is missing or malformed")
records.append(("build.envelope", build.get("envelope")))

snapshots = {}
for label, record in records:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        fail(f"{label} identity is malformed")
    path = pathlib.Path(record["path"]).resolve(strict=True)
    snapshots[label] = (path, path.stat())

for label, record in records:
    path, before = snapshots[label]
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    if before.st_size != record["bytes"] or digest.hexdigest() != record["sha256"]:
        fail(f"{label} no longer matches the package envelope")

for label, (path, before) in snapshots.items():
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"{label} changed during the closure rehash")
envelope_after = envelope_path.stat()
if (envelope_before.st_dev, envelope_before.st_ino, envelope_before.st_size, envelope_before.st_mtime_ns) != (
    envelope_after.st_dev,
    envelope_after.st_ino,
    envelope_after.st_size,
    envelope_after.st_mtime_ns,
):
    fail("package envelope changed during closure rehash")
print("package-milkv-duo-sdk.sh runtime-cost package closure rehash: PASS")
PY
  if [[ $(git --no-optional-locks -C "$sdk_root" rev-parse HEAD) != "$runtime_costs_sdk_commit" ]] ||
     [[ -n $(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
    echo "package-milkv-duo-sdk.sh: SDK checkout changed after envelope closure" >&2
    exit 1
  fi
  if [[ $(git -C "$repo_root" rev-parse HEAD) != "$runtime_costs_source_commit" ]] ||
     [[ -n $(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
    echo "package-milkv-duo-sdk.sh: VibeOS source changed after envelope closure" >&2
    exit 1
  fi
elif [[ "$wasm_aot_profile" == true ]]; then
  c84_pass_marker="PASS: C8.4 FAT boot + raw data MBR image, FIP, FIT metadata, kernel/DTB payloads, and CRC32 hashes are valid"
  c84_report_schema=vibeos.c84.duo-wasm-aot-profile.image-audit-report
  c84_verify_path=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
  verifier_tool_names=(mdir mcopy cmp sha256sum fdtget python3 tr)
  verifier_tool_paths=()
  for verifier_tool_name in "${verifier_tool_names[@]}"; do
    if ! verifier_tool_path=$(PATH="$c84_verify_path" command -v "$verifier_tool_name"); then
      echo "package-milkv-duo-sdk.sh: required C8.4 verifier tool is missing: $verifier_tool_name" >&2
      exit 1
    fi
    verifier_tool_path=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$verifier_tool_path")
    verifier_tool_paths+=("$verifier_tool_path")
  done
  if ! env -i \
    GIT_CONFIG_GLOBAL="$c84_docker_git_config" GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 HOME=/nonexistent \
    LC_ALL=C PATH="$c84_verify_path" TZ=UTC \
    VIBEOS_C84_CHALLENGE="$wasm_aot_profile_challenge" \
    VIBEOS_C84_SDK_CONTAINER_DIGEST="$wasm_aot_profile_declared_container" \
    VIBEOS_C84_SOURCE_COMMIT="$wasm_aot_profile_source_commit" \
    "$script_dir/verify-milkv-duo-image.sh" "${verify_args[@]}" >"$temp_audit" 2>&1; then
    cat "$temp_audit" >&2
    echo "package-milkv-duo-sdk.sh: refusing to publish an unverified C8.4 SD image" >&2
    exit 1
  fi
  validated_audit_report_sha256=$(python3 - \
    "$temp_audit" "$c84_pass_marker" "$c84_report_schema" \
    "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" \
    "$staged_kernel_bin" "$output_its" "$output_dtb" "$sdk_dtb" \
    "$output_fit" "$output_image" "$sdk_fip" "$mkimage" "$dumpimage" \
    "$c84_docker_git_config_template" \
    "${verifier_tool_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
marker = sys.argv[2]
report_schema = sys.argv[3]
source_commit = sys.argv[4]
challenge = sys.argv[5]
artifact_names = (
    "kernel_binary", "fit_source", "packaged_dtb", "sdk_dtb",
    "fit_boot_sd", "full_sd_image", "sdk_fip",
)
tool_names = (
    "sdk_mkimage", "sdk_dumpimage", "git_config", "mdir", "mcopy",
    "cmp", "sha256sum", "fdtget", "python3", "tr",
)
artifact_paths = sys.argv[6:13]
tool_paths = sys.argv[13:23]
data = path.read_bytes()
try:
    text = data.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 verifier audit is not UTF-8: {error}")
lines = text.splitlines()
if not data.endswith((marker + "\n").encode("utf-8")) or len(lines) < 2 or lines[-1] != marker:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 verifier audit lacks the exact terminal PASS marker")
if text.count(marker) != 1 or text.count(f'"schema":"{report_schema}"') != 1:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 verifier audit marker/report is not unique")
if re.search(r"\b(?:panic|fatal|fail|failed|failure)\b", text, re.IGNORECASE):
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 verifier audit contains a forbidden failure token")
report_line = lines[-2]


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 audit report has duplicate member {key!r}")
        result[key] = value
    return result


try:
    report = json.loads(report_line, object_pairs_hook=reject_duplicate_members)
except json.JSONDecodeError as error:
    raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 canonical audit report is invalid: {error}")
if not isinstance(report, dict) or set(report) != {
    "schema", "version", "source_commit", "challenge", "artifacts", "tools",
}:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 audit report fields are not closed")
if (
    report["schema"] != report_schema or type(report["version"]) is not int
    or report["version"] != 1 or report["source_commit"] != source_commit
    or report["challenge"] != challenge
):
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 audit report identity differs")
canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
if canonical != report_line:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 audit report is not canonical JSON")
if not isinstance(report["artifacts"], dict) or set(report["artifacts"]) != set(artifact_names):
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 audit artifact fields differ")
if not isinstance(report["tools"], dict) or set(report["tools"]) != set(tool_names):
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 audit tool fields differ")


def identity(name):
    resolved = pathlib.Path(name).resolve(strict=True)
    before = resolved.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 audit input is not regular: {resolved}")
    digest = hashlib.sha256()
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    after = resolved.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 audit input changed: {resolved}")
    return {"sha256": digest.hexdigest(), "bytes": before.st_size}


for role, actual_path in zip(artifact_names, artifact_paths):
    if report["artifacts"].get(role) != identity(actual_path):
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 audit artifact {role} differs")
for role, actual_path in zip(tool_names, tool_paths):
    if report["tools"].get(role) != identity(actual_path):
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 audit tool {role} differs")
print(hashlib.sha256(report_line.encode("utf-8")).hexdigest())
PY
  )
  cat "$temp_audit"
  mv "$temp_audit" "$output_audit"
  verification_completed_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')

  verify_c84_input_state() {
    if [[ $(git --no-optional-locks -C "$sdk_root" rev-parse HEAD) != "$wasm_aot_profile_sdk_commit" ]] ||
       [[ -n $(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
      echo "package-milkv-duo-sdk.sh: C8.4 SDK checkout changed during packaging" >&2
      return 1
    fi
    if [[ $(git -C "$repo_root" rev-parse HEAD) != "$wasm_aot_profile_source_commit" ]] ||
       [[ -n $(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=all) ]]; then
      echo "package-milkv-duo-sdk.sh: C8.4 superproject changed during packaging" >&2
      return 1
    fi
    if [[ $(git -C "$jitterentropy_submodule" rev-parse HEAD) != c5bd2e17194fe3a04d17f74027bb67622579405f ]] ||
       [[ $(git -C "$sunset_submodule" rev-parse HEAD) != f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e ]] ||
       [[ -n $(git -C "$sunset_submodule" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) ]]; then
      echo "package-milkv-duo-sdk.sh: C8.4 reviewed submodule state changed during packaging" >&2
      return 1
    fi
    python3 - "$jitterentropy_submodule" "$jitterentropy_patch" <<'PY'
import pathlib
import subprocess
import sys

observed = subprocess.run(
    ["git", "-C", sys.argv[1], "diff", "--unified=0", "--binary"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if observed != pathlib.Path(sys.argv[2]).read_bytes():
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 jitterentropy-rs diff changed during packaging")
if subprocess.run(
    ["git", "-C", sys.argv[1], "diff", "--cached", "--quiet", "--exit-code"],
).returncode != 0:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 jitterentropy-rs gained staged changes during packaging")
untracked = subprocess.run(
    ["git", "-C", sys.argv[1], "ls-files", "--others", "--exclude-standard", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
if untracked:
    raise SystemExit("package-milkv-duo-sdk.sh: C8.4 jitterentropy-rs gained untracked files during packaging")
PY
    python3 - "$kernel_bin" "$staged_kernel_bin" "$validated_kernel_sha256" "$validated_kernel_bytes" <<'PY'
import hashlib
import pathlib
import stat
import sys

expected_sha256 = sys.argv[3]
expected_bytes = int(sys.argv[4])
for name in sys.argv[1:3]:
    path = pathlib.Path(name)
    if stat.S_ISLNK(path.lstat().st_mode) or not path.is_file():
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 kernel input is not regular: {path}")
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 kernel changed while rehashing: {path}")
    if before.st_size != expected_bytes or digest.hexdigest() != expected_sha256:
        raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 kernel differs from build envelope: {path}")
PY
  }
  verify_c84_input_state

  python3 - \
    "$temp_envelope" "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" \
    "$sdk_root" "$wasm_aot_profile_sdk_commit" "$wasm_aot_profile_declared_container" \
    "$repo_root" "$jitterentropy_submodule" "$jitterentropy_patch" \
    "$jitterentropy_head" "$jitterentropy_diff_sha256" "$jitterentropy_diff_bytes" \
    "$sunset_submodule" "$sunset_head" \
    "$kernel_elf" "$kernel_bin" "$staged_kernel_bin" \
    "$output_its" "$final_output_its" "$output_dtb" "$final_output_dtb" \
    "$output_fit" "$final_output_fit" "$output_image" "$final_output_image" \
    "$sdk_fip" "$sdk_dtb" "$output_audit" "$final_output_audit" \
    "$script_dir/package-milkv-duo-sdk.sh" "$script_dir/verify-milkv-duo-image.sh" \
    "$c84_docker_git_config_template" \
    "$script_dir/build-milkv-duo.sh" "$script_dir/prepare-jitterentropy-rs.sh" \
    "$repo_root/.gitmodules" "$script_dir/milkv-duo.its" \
    "$script_dir/milkv-duo-genimage.cfg" \
    "$repo_root/benchmarks/wasm-aot-decision/workloads-v1.json" \
    "$repo_root/benchmarks/wasm-aot-decision/schema-v1.json" \
    "$repo_root/rust-toolchain.toml" "$evidence_checker" \
    "$mkimage" "$dumpimage" "$genimage" "$genimage_lib" \
    "$build_envelope" "$validated_build_content_sha256" \
    "$package_started_utc" "$verification_completed_utc" "$c84_pass_marker" \
    "$c84_report_schema" "$validated_audit_report_sha256" "$c84_verify_path" \
    "${verifier_tool_paths[@]}" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import stat
import sys

(
    destination, source_commit, challenge, sdk_root, sdk_commit, container_digest,
    source_root, jitterentropy_submodule, jitterentropy_patch, jitterentropy_head,
    jitterentropy_diff_sha256, jitterentropy_diff_bytes, sunset_submodule, sunset_head,
    kernel_elf, kernel_bin, staged_kernel_bin, staged_its, final_its, staged_dtb, final_dtb,
    staged_fit, final_fit, staged_image, final_image, sdk_fip, sdk_dtb,
    staged_audit, final_audit, package_script, image_verifier, docker_git_config,
    build_script,
    prepare_jitterentropy_script, gitmodules, its_source, genimage_config,
    workload_manifest, transcript_schema, toolchain_contract, evidence_checker,
    mkimage, dumpimage, genimage, genimage_lib, build_envelope,
    validated_build_content_sha256, packaging_started_utc, image_verified_utc,
    pass_marker, report_schema, validated_audit_report_sha256, verifier_path,
    verifier_mdir, verifier_mcopy, verifier_cmp,
    verifier_sha256sum, verifier_fdtget, verifier_python3, verifier_tr,
) = sys.argv[1:]


def fail(message):
    raise SystemExit(f"package-milkv-duo-sdk.sh: C8.4 package closure failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} fields are not closed")
    return value


def identity(measured_path, recorded_path=None, *, scan=False, reject_symlink=False):
    measured = pathlib.Path(measured_path)
    if reject_symlink and stat.S_ISLNK(measured.lstat().st_mode):
        fail(f"refusing symlink artifact: {measured}")
    resolved = measured.resolve(strict=True)
    before = resolved.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"cannot measure non-regular or empty file: {resolved}")
    digest = hashlib.sha256()
    needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
    found = [False, False]
    overlap = max(map(len, needles)) - 1
    tail = b""
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            if scan:
                window = tail + chunk
                found = [seen or needle in window for seen, needle in zip(found, needles)]
                tail = window[-overlap:]
    after = resolved.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        fail(f"file changed while hashing: {resolved}")
    if scan and not all(found):
        fail(f"artifact does not embed source/challenge: {resolved}")
    if recorded_path is None:
        record = resolved
    else:
        candidate = pathlib.Path(recorded_path)
        record = candidate.parent.resolve(strict=True) / candidate.name
    return {"path": str(record), "sha256": digest.hexdigest(), "bytes": before.st_size}


def match(left, right, label):
    if left["sha256"] != right["sha256"] or left["bytes"] != right["bytes"]:
        fail(f"{label} differs")


audit_data = pathlib.Path(staged_audit).read_bytes()
try:
    audit_text = audit_data.decode("utf-8")
except UnicodeDecodeError as error:
    fail(f"verifier audit is not UTF-8: {error}")
audit_lines = audit_text.splitlines()
if not audit_data.endswith((pass_marker + "\n").encode("utf-8")) or len(audit_lines) < 2 or audit_lines[-1] != pass_marker:
    fail("verifier audit exact terminal marker differs")
if audit_text.count(pass_marker) != 1 or audit_text.count(f'"schema":"{report_schema}"') != 1:
    fail("verifier audit marker/report is not unique")
if re.search(r"\b(?:panic|fatal|fail|failed|failure)\b", audit_text, re.IGNORECASE):
    fail("verifier audit contains a forbidden failure token")
report_line = audit_lines[-2]
try:
    audit_report = json.loads(report_line, object_pairs_hook=reject_duplicate_members)
except json.JSONDecodeError as error:
    fail(f"cannot decode canonical audit report: {error}")
audit_report = exact(
    audit_report,
    {"schema", "version", "source_commit", "challenge", "artifacts", "tools"},
    "image audit report",
)
if (
    audit_report["schema"] != report_schema
    or type(audit_report["version"]) is not int
    or audit_report["version"] != 1
    or audit_report["source_commit"] != source_commit
    or audit_report["challenge"] != challenge
):
    fail("image audit report identity differs")
canonical_report = json.dumps(audit_report, sort_keys=True, separators=(",", ":"))
if canonical_report != report_line:
    fail("image audit report is not canonical JSON")
if hashlib.sha256(report_line.encode("utf-8")).hexdigest() != validated_audit_report_sha256:
    fail("image audit report differs from the validated verifier output")

artifacts = {
    "kernel_elf": identity(kernel_elf, scan=True, reject_symlink=True),
    "kernel_binary": identity(staged_kernel_bin, kernel_bin, scan=True, reject_symlink=True),
    "packaged_fit_source": identity(staged_its, final_its, reject_symlink=True),
    "packaged_dtb": identity(staged_dtb, final_dtb, reject_symlink=True),
    "fit_boot_sd": identity(staged_fit, final_fit, scan=True, reject_symlink=True),
    "full_sd_image": identity(staged_image, final_image, scan=True, reject_symlink=True),
    "sdk_fip": identity(sdk_fip),
    "sdk_dtb": identity(sdk_dtb),
}
tools = {
    "package_script": identity(package_script),
    "image_verifier_script": identity(image_verifier),
    "docker_git_config": identity(docker_git_config),
    "build_script": identity(build_script),
    "prepare_jitterentropy_script": identity(prepare_jitterentropy_script),
    "jitterentropy_patch": identity(jitterentropy_patch),
    "gitmodules": identity(gitmodules),
    "fit_source": identity(its_source),
    "genimage_config": identity(genimage_config),
    "workload_manifest": identity(workload_manifest),
    "transcript_schema": identity(transcript_schema),
    "toolchain_contract": identity(toolchain_contract),
    "evidence_checker": identity(evidence_checker),
    "sdk_mkimage": identity(mkimage),
    "sdk_dumpimage": identity(dumpimage),
    "sdk_genimage": identity(genimage),
    "verifier_mdir": identity(verifier_mdir),
    "verifier_mcopy": identity(verifier_mcopy),
    "verifier_cmp": identity(verifier_cmp),
    "verifier_sha256sum": identity(verifier_sha256sum),
    "verifier_fdtget": identity(verifier_fdtget),
    "verifier_python3": identity(verifier_python3),
    "verifier_tr": identity(verifier_tr),
}
report_artifact_roles = {
    "kernel_binary": "kernel_binary",
    "fit_source": "packaged_fit_source",
    "packaged_dtb": "packaged_dtb",
    "sdk_dtb": "sdk_dtb",
    "fit_boot_sd": "fit_boot_sd",
    "full_sd_image": "full_sd_image",
    "sdk_fip": "sdk_fip",
}
report_tool_roles = {
    "sdk_mkimage": "sdk_mkimage", "sdk_dumpimage": "sdk_dumpimage",
    "git_config": "docker_git_config",
    "mdir": "verifier_mdir", "mcopy": "verifier_mcopy",
    "cmp": "verifier_cmp", "sha256sum": "verifier_sha256sum",
    "fdtget": "verifier_fdtget", "python3": "verifier_python3", "tr": "verifier_tr",
}
if not isinstance(audit_report["artifacts"], dict) or set(audit_report["artifacts"]) != set(report_artifact_roles):
    fail("image audit artifact fields differ")
if not isinstance(audit_report["tools"], dict) or set(audit_report["tools"]) != set(report_tool_roles):
    fail("image audit tool fields differ")
for report_role, envelope_role in report_artifact_roles.items():
    expected = {key: artifacts[envelope_role][key] for key in ("sha256", "bytes")}
    if audit_report["artifacts"].get(report_role) != expected:
        fail(f"image audit artifact {report_role} differs")
for report_role, envelope_role in report_tool_roles.items():
    expected = {key: tools[envelope_role][key] for key in ("sha256", "bytes")}
    if audit_report["tools"].get(report_role) != expected:
        fail(f"image audit tool {report_role} differs")

build_path = pathlib.Path(build_envelope).resolve(strict=True)
build_before = build_path.stat()
try:
    build_root = json.loads(build_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode build envelope: {error}")
build_root = exact(build_root, {"schema", "version", "status", "content_sha256", "content"}, "build envelope")
if (
    build_root["schema"] != "vibeos.c84.duo-wasm-aot-profile.build-envelope"
    or type(build_root["version"]) is not int
    or build_root["version"] != 1
    or build_root["status"] != "closed"
    or build_root["content_sha256"] != validated_build_content_sha256
):
    fail("build envelope identity/status differs")
build_content = build_root["content"]
if not isinstance(build_content, dict):
    fail("build content is missing")
canonical_build = json.dumps(build_content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(canonical_build).hexdigest() != build_root["content_sha256"]:
    fail("build content address differs")
if build_content.get("source_commit") != source_commit or build_content.get("challenge") != challenge:
    fail("build source/challenge differs")
run_id = build_content.get("run_id")
if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
    fail("build run_id is malformed")
build_artifacts = build_content.get("artifacts")
if not isinstance(build_artifacts, dict) or set(build_artifacts) != {"kernel_elf", "kernel_binary"}:
    fail("build artifact fields differ")
for role in ("kernel_elf", "kernel_binary"):
    record = build_artifacts[role]
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        fail(f"build {role} identity is malformed")
    match(artifacts[role], record, f"build {role}")
build_identity = identity(build_envelope)
build_after = build_path.stat()
if (build_before.st_dev, build_before.st_ino, build_before.st_size, build_before.st_mtime_ns) != (
    build_after.st_dev, build_after.st_ino, build_after.st_size, build_after.st_mtime_ns,
):
    fail("build envelope changed during package closure")

timestamps = [packaging_started_utc, image_verified_utc]
parsed = []
for value in timestamps:
    if not value.endswith("Z"):
        fail("package timestamp is not UTC")
    try:
        parsed.append(datetime.datetime.fromisoformat(value[:-1] + "+00:00"))
    except ValueError as error:
        fail(f"package timestamp is invalid: {error}")
if parsed != sorted(parsed):
    fail("package timestamps are reversed")
closed_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

source = {
    "root": str(pathlib.Path(source_root).resolve(strict=True)),
    "head": source_commit,
    "superproject_clean": True,
    "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=all",
    "jitterentropy": {
        "path": str(pathlib.Path(jitterentropy_submodule).resolve(strict=True)),
        "head": jitterentropy_head,
        "patch_sha256": tools["jitterentropy_patch"]["sha256"],
        "patch_bytes": tools["jitterentropy_patch"]["bytes"],
        "observed_diff_sha256": jitterentropy_diff_sha256,
        "observed_diff_bytes": int(jitterentropy_diff_bytes),
        "policy": "exact recorded patch verified by prepare-jitterentropy-rs.sh",
    },
    "sunset": {
        "path": str(pathlib.Path(sunset_submodule).resolve(strict=True)),
        "head": sunset_head,
        "worktree_clean": True,
        "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
    },
}
sdk = {
    "root": str(pathlib.Path(sdk_root).resolve(strict=True)),
    "commit": sdk_commit,
    "commit_provenance": "operator-declared; local checkout HEAD equality verified",
    "declared_container_digest": container_digest,
    "container_digest_provenance": "operator-declared; runtime container identity not attested",
    "worktree_clean": True,
    "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
}
environment = {
    "fit_tools": {
        "mode": "env -i",
        "allowed_keys": ["LC_ALL", "PATH", "TZ"],
        "values": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    },
    "genimage": {
        "mode": "env -i",
        "allowed_keys": ["HOME", "LC_ALL", "LD_LIBRARY_PATH", "PATH", "TZ"],
        "values": {
            "HOME": "/nonexistent", "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(pathlib.Path(genimage_lib).resolve(strict=True)),
            "PATH": f"{pathlib.Path(genimage).resolve(strict=True).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TZ": "UTC",
        },
    },
    "image_verifier": {
        "mode": "env -i",
        "allowed_keys": [
            "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
            "GIT_OPTIONAL_LOCKS",
            "HOME", "LC_ALL", "PATH", "TZ",
            "VIBEOS_C84_CHALLENGE", "VIBEOS_C84_SDK_CONTAINER_DIGEST", "VIBEOS_C84_SOURCE_COMMIT",
        ],
        "values": {
            "GIT_CONFIG_GLOBAL": "/etc/vibeos-c84.gitconfig",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": "/nonexistent",
            "LC_ALL": "C", "PATH": verifier_path, "TZ": "UTC",
            "VIBEOS_C84_CHALLENGE": challenge,
            "VIBEOS_C84_SDK_CONTAINER_DIGEST": container_digest,
            "VIBEOS_C84_SOURCE_COMMIT": source_commit,
        },
    },
}
content = {
    "platform": "milkv-duo-cv1800b",
    "source_commit": source_commit,
    "challenge": challenge,
    "run_id": run_id,
    "source": source,
    "sdk": sdk,
    "build": {"content_sha256": build_root["content_sha256"], "envelope": build_identity},
    "command": ["scripts/package-milkv-duo-sdk.sh", "--wasm-aot-profile", "<sdk-root>"],
    "environment": environment,
    "artifacts": artifacts,
    "verifier": {
        "status": "PASS", "exit_code": 0, "exact_pass_marker": pass_marker,
        "report": audit_report, "report_sha256": validated_audit_report_sha256,
        "audit_log": identity(staged_audit, final_audit, reject_symlink=True),
        "invocation": [
            "scripts/verify-milkv-duo-image.sh", "--wasm-aot-profile",
            "--artifact-root=<staging-artifact-root>", "<sdk-root>",
        ],
    },
    "tools": tools,
    "timestamps_utc": {
        "packaging_started": packaging_started_utc,
        "image_verified": image_verified_utc,
        "envelope_closed": closed_utc,
    },
}
canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
envelope = {
    "schema": "vibeos.c84.duo-wasm-aot-profile.package-envelope",
    "version": 1,
    "status": "closed",
    "content_sha256": hashlib.sha256(canonical).hexdigest(),
    "content": content,
}
with pathlib.Path(destination).open("x", encoding="utf-8") as output:
    json.dump(envelope, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  mv "$temp_envelope" "$output_envelope"
  verify_c84_input_state

  c84_links_created=true
  python3 - \
    "$output_its" "$final_output_its" "$output_dtb" "$final_output_dtb" \
    "$output_fit" "$final_output_fit" "$output_image" "$final_output_image" \
    "$output_audit" "$final_output_audit" "$output_envelope" "$final_output_envelope" \
    "$c84_pass_marker" "$validated_build_content_sha256" \
    "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

pairs = [(pathlib.Path(a), pathlib.Path(b)) for a, b in zip(sys.argv[1:13:2], sys.argv[2:13:2])]
pass_marker, build_content_sha256, source_commit, challenge = sys.argv[13:]
created = []


def fail(message):
    raise RuntimeError(f"package-milkv-duo-sdk.sh: C8.4 atomic publication failed: {message}")


def reject_duplicate_members(pairs_value):
    result = {}
    for key, value in pairs_value:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} fields are not closed")
    return value


def identity_record(value, label):
    record = exact(value, {"path", "sha256", "bytes"}, label)
    if (
        not isinstance(record["path"], str) or not record["path"]
        or not isinstance(record["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or type(record["bytes"]) is not int or record["bytes"] <= 0
    ):
        fail(f"{label} is malformed")
    return record


def measurement_record(value, label):
    if not isinstance(value, dict) or set(value) != {"sha256", "bytes"}:
        fail(f"{label} fields are not closed")
    if (
        not isinstance(value["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
        or type(value["bytes"]) is not int
        or value["bytes"] <= 0
    ):
        fail(f"{label} is malformed")
    return value


def rehash(record, label):
    record = identity_record(record, label)
    path = pathlib.Path(record["path"])
    if stat.S_ISLNK(path.lstat().st_mode):
        fail(f"{label} is a symlink")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} is not regular")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        fail(f"{label} changed while hashing")
    if before.st_size != record["bytes"] or digest.hexdigest() != record["sha256"]:
        fail(f"{label} differs from envelope")


try:
    destination_parent = pairs[0][1].parent
    if stat.S_ISLNK(destination_parent.lstat().st_mode) or not destination_parent.is_dir():
        fail("publication parent is not a fixed non-symlink directory")
    for source, destination in pairs:
        if source.is_symlink() or not source.is_file():
            fail(f"staged output is not a regular non-symlink file: {source}")
        if destination.parent != destination_parent or stat.S_ISLNK(destination.parent.lstat().st_mode):
            fail(f"destination parent differs: {destination}")
        if destination.exists() or destination.is_symlink():
            fail(f"destination already exists: {destination}")
        descriptor = os.open(source, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for source, destination in pairs:
        os.link(source, destination)
        created.append((source, destination))
    parent_descriptor = os.open(destination_parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)

    envelope_path = pairs[-1][1]
    envelope_before = envelope_path.stat()
    try:
        root = json.loads(envelope_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode package envelope: {error}")
    root = exact(root, {"schema", "version", "status", "content_sha256", "content"}, "package envelope")
    if (
        root["schema"] != "vibeos.c84.duo-wasm-aot-profile.package-envelope"
        or type(root["version"]) is not int or root["version"] != 1
        or root["status"] != "closed"
        or not isinstance(root["content_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", root["content_sha256"]) is None
    ):
        fail("package envelope identity/status differs")
    content = exact(
        root["content"],
        {"platform", "source_commit", "challenge", "run_id", "source", "sdk", "build", "command", "environment", "artifacts", "verifier", "tools", "timestamps_utc"},
        "package content",
    )
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != root["content_sha256"]:
        fail("package content address differs")
    if (
        content["platform"] != "milkv-duo-cv1800b"
        or content["source_commit"] != source_commit
        or content["challenge"] != challenge
        or not isinstance(content["run_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", content["run_id"]) is None
    ):
        fail("package campaign identity differs")
    source = exact(content["source"], {"root", "head", "superproject_clean", "status_policy", "jitterentropy", "sunset"}, "source")
    if (
        source["head"] != source_commit or source["superproject_clean"] is not True
        or source["status_policy"] != "git status --porcelain=v1 --untracked-files=all --ignore-submodules=all"
    ):
        fail("source attestation differs")
    jitter = exact(source["jitterentropy"], {"path", "head", "patch_sha256", "patch_bytes", "observed_diff_sha256", "observed_diff_bytes", "policy"}, "jitterentropy")
    for key in ("patch_bytes", "observed_diff_bytes"):
        if type(jitter[key]) is not int or jitter[key] <= 0:
            fail(f"jitterentropy {key} is malformed")
    if (
        jitter["head"] != "c5bd2e17194fe3a04d17f74027bb67622579405f"
        or jitter["patch_sha256"] != jitter["observed_diff_sha256"]
        or jitter["patch_bytes"] != jitter["observed_diff_bytes"]
        or jitter["policy"] != "exact recorded patch verified by prepare-jitterentropy-rs.sh"
    ):
        fail("jitterentropy reviewed delta differs")
    sunset = exact(source["sunset"], {"path", "head", "worktree_clean", "status_policy"}, "sunset")
    if (
        sunset["head"] != "f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e"
        or sunset["worktree_clean"] is not True
        or sunset["status_policy"] != "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none"
    ):
        fail("sunset clean state differs")
    sdk = exact(content["sdk"], {"root", "commit", "commit_provenance", "declared_container_digest", "container_digest_provenance", "worktree_clean", "status_policy"}, "SDK")
    if (
        sdk["commit"] != "23eb84fecb29585dbb5728d6b7e2475ff273baac"
        or sdk["declared_container_digest"] != "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679"
        or sdk["commit_provenance"] != "operator-declared; local checkout HEAD equality verified"
        or sdk["container_digest_provenance"] != "operator-declared; runtime container identity not attested"
        or sdk["worktree_clean"] is not True
        or sdk["status_policy"] != "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none"
    ):
        fail("SDK declared provenance differs")
    build = exact(content["build"], {"content_sha256", "envelope"}, "build reference")
    if build["content_sha256"] != build_content_sha256:
        fail("build content reference differs")
    if content["command"] != ["scripts/package-milkv-duo-sdk.sh", "--wasm-aot-profile", "<sdk-root>"]:
        fail("package command differs")
    environment = exact(content["environment"], {"fit_tools", "genimage", "image_verifier"}, "environment")
    environment_records = {}
    for name, keys in {
        "fit_tools": ["LC_ALL", "PATH", "TZ"],
        "genimage": ["HOME", "LC_ALL", "LD_LIBRARY_PATH", "PATH", "TZ"],
        "image_verifier": ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS", "GIT_OPTIONAL_LOCKS", "HOME", "LC_ALL", "PATH", "TZ", "VIBEOS_C84_CHALLENGE", "VIBEOS_C84_SDK_CONTAINER_DIGEST", "VIBEOS_C84_SOURCE_COMMIT"],
    }.items():
        record = exact(environment[name], {"mode", "allowed_keys", "values"}, f"environment {name}")
        if record["mode"] != "env -i" or record["allowed_keys"] != keys:
            fail(f"environment {name} allowlist differs")
        exact(record["values"], set(keys), f"environment {name} values")
        environment_records[name] = record["values"]
    if environment_records["fit_tools"] != {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}:
        fail("FIT tool environment values differ")
    gen_values = environment_records["genimage"]
    if (
        gen_values["HOME"] != "/nonexistent" or gen_values["LC_ALL"] != "C"
        or gen_values["TZ"] != "UTC" or not gen_values["LD_LIBRARY_PATH"]
        or not gen_values["PATH"].endswith(":/usr/bin:/bin:/usr/sbin:/sbin")
    ):
        fail("genimage environment values differ")
    verifier_values = environment_records["image_verifier"]
    if (
        verifier_values["GIT_CONFIG_GLOBAL"] != "/etc/vibeos-c84.gitconfig"
        or verifier_values["GIT_CONFIG_NOSYSTEM"] != "1"
        or verifier_values["GIT_NO_REPLACE_OBJECTS"] != "1"
        or verifier_values["GIT_OPTIONAL_LOCKS"] != "0"
        or verifier_values["HOME"] != "/nonexistent"
        or verifier_values["LC_ALL"] != "C"
        or verifier_values["TZ"] != "UTC"
        or verifier_values["VIBEOS_C84_SOURCE_COMMIT"] != source_commit
        or verifier_values["VIBEOS_C84_CHALLENGE"] != challenge
        or verifier_values["VIBEOS_C84_SDK_CONTAINER_DIGEST"] != sdk["declared_container_digest"]
    ):
        fail("image-verifier environment values differ")
    artifacts = exact(content["artifacts"], {"kernel_elf", "kernel_binary", "packaged_fit_source", "packaged_dtb", "fit_boot_sd", "full_sd_image", "sdk_fip", "sdk_dtb"}, "artifacts")
    tools = exact(content["tools"], {"package_script", "image_verifier_script", "docker_git_config", "build_script", "prepare_jitterentropy_script", "jitterentropy_patch", "gitmodules", "fit_source", "genimage_config", "workload_manifest", "transcript_schema", "toolchain_contract", "evidence_checker", "sdk_mkimage", "sdk_dumpimage", "sdk_genimage", "verifier_mdir", "verifier_mcopy", "verifier_cmp", "verifier_sha256sum", "verifier_fdtget", "verifier_python3", "verifier_tr"}, "tools")
    if (
        jitter["patch_sha256"] != tools["jitterentropy_patch"].get("sha256")
        or jitter["patch_bytes"] != tools["jitterentropy_patch"].get("bytes")
    ):
        fail("jitterentropy source record differs from pinned patch tool")
    verifier = exact(content["verifier"], {"status", "exit_code", "exact_pass_marker", "report", "report_sha256", "audit_log", "invocation"}, "verifier")
    if (
        verifier["status"] != "PASS" or type(verifier["exit_code"]) is not int
        or verifier["exit_code"] != 0 or verifier["exact_pass_marker"] != pass_marker
        or verifier["invocation"] != ["scripts/verify-milkv-duo-image.sh", "--wasm-aot-profile", "--artifact-root=<staging-artifact-root>", "<sdk-root>"]
    ):
        fail("verifier attestation differs")
    report = exact(
        verifier["report"],
        {"schema", "version", "source_commit", "challenge", "artifacts", "tools"},
        "image audit report",
    )
    if (
        report["schema"] != "vibeos.c84.duo-wasm-aot-profile.image-audit-report"
        or type(report["version"]) is not int or report["version"] != 1
        or report["source_commit"] != source_commit or report["challenge"] != challenge
    ):
        fail("image audit report identity differs")
    canonical_report = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if (
        not isinstance(verifier["report_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", verifier["report_sha256"]) is None
        or hashlib.sha256(canonical_report.encode("utf-8")).hexdigest() != verifier["report_sha256"]
    ):
        fail("image audit report content address differs")
    report_artifact_roles = {
        "kernel_binary": "kernel_binary", "fit_source": "packaged_fit_source",
        "packaged_dtb": "packaged_dtb", "sdk_dtb": "sdk_dtb",
        "fit_boot_sd": "fit_boot_sd", "full_sd_image": "full_sd_image", "sdk_fip": "sdk_fip",
    }
    report_tool_roles = {
        "sdk_mkimage": "sdk_mkimage", "sdk_dumpimage": "sdk_dumpimage",
        "git_config": "docker_git_config",
        "mdir": "verifier_mdir", "mcopy": "verifier_mcopy",
        "cmp": "verifier_cmp", "sha256sum": "verifier_sha256sum",
        "fdtget": "verifier_fdtget", "python3": "verifier_python3", "tr": "verifier_tr",
    }
    report_artifacts = exact(report["artifacts"], set(report_artifact_roles), "image audit artifacts")
    report_tools = exact(report["tools"], set(report_tool_roles), "image audit tools")
    for report_role, envelope_role in report_artifact_roles.items():
        measurement = measurement_record(report_artifacts[report_role], f"image audit artifacts.{report_role}")
        identity = identity_record(artifacts[envelope_role], f"artifacts.{envelope_role}")
        if measurement != {key: identity[key] for key in ("sha256", "bytes")}:
            fail(f"image audit artifact {report_role} differs from package artifact")
    for report_role, envelope_role in report_tool_roles.items():
        measurement = measurement_record(report_tools[report_role], f"image audit tools.{report_role}")
        identity = identity_record(tools[envelope_role], f"tools.{envelope_role}")
        if measurement != {key: identity[key] for key in ("sha256", "bytes")}:
            fail(f"image audit tool {report_role} differs from package tool")
    timestamps = exact(content["timestamps_utc"], {"packaging_started", "image_verified", "envelope_closed"}, "timestamps")
    parsed = []
    for name in ("packaging_started", "image_verified", "envelope_closed"):
        value = timestamps[name]
        if not isinstance(value, str) or not value.endswith("Z"):
            fail(f"timestamp {name} is not UTC")
        try:
            parsed.append(datetime.datetime.fromisoformat(value[:-1] + "+00:00"))
        except ValueError as error:
            fail(f"timestamp {name} is invalid: {error}")
    if parsed != sorted(parsed):
        fail("package timestamps are reversed")
    expected_published_paths = {
        "packaged_fit_source": pairs[0][1], "packaged_dtb": pairs[1][1],
        "fit_boot_sd": pairs[2][1], "full_sd_image": pairs[3][1],
    }
    for name, path in expected_published_paths.items():
        if pathlib.Path(artifacts[name]["path"]).resolve(strict=True) != path.resolve(strict=True):
            fail(f"artifacts.{name} publication path differs")
    if pathlib.Path(verifier["audit_log"]["path"]).resolve(strict=True) != pairs[4][1].resolve(strict=True):
        fail("verifier audit publication path differs")
    for name, record in artifacts.items():
        rehash(record, f"artifacts.{name}")
    for name, record in tools.items():
        rehash(record, f"tools.{name}")
    rehash(verifier["audit_log"], "verifier.audit_log")
    rehash(build["envelope"], "build.envelope")
    audit = pathlib.Path(verifier["audit_log"]["path"]).read_bytes()
    try:
        audit_lines = audit.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"published audit is not UTF-8: {error}")
    if (
        not audit.endswith((pass_marker + "\n").encode("utf-8"))
        or len(audit_lines) < 2 or audit_lines[-1] != pass_marker
        or audit_lines[-2] != canonical_report
        or audit.decode("utf-8").count(pass_marker) != 1
        or audit.decode("utf-8").count('"schema":"vibeos.c84.duo-wasm-aot-profile.image-audit-report"') != 1
    ):
        fail("published audit exact PASS marker differs")
    if re.search(rb"\b(?:panic|fatal|fail|failed|failure)\b", audit, re.IGNORECASE):
        fail("published audit contains a forbidden failure token")
    envelope_after = envelope_path.stat()
    if (envelope_before.st_dev, envelope_before.st_ino, envelope_before.st_size, envelope_before.st_mtime_ns) != (
        envelope_after.st_dev, envelope_after.st_ino, envelope_after.st_size, envelope_after.st_mtime_ns,
    ):
        fail("package envelope changed during closure rehash")
except BaseException as error:
    for source, destination in reversed(created):
        try:
            source_stat = source.stat()
            destination_stat = destination.lstat()
            if not destination.is_symlink() and (source_stat.st_dev, source_stat.st_ino) == (destination_stat.st_dev, destination_stat.st_ino):
                os.unlink(destination)
        except FileNotFoundError:
            pass
    try:
        parent_descriptor = os.open(pairs[0][1].parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError:
        pass
    raise SystemExit(str(error))

print("package-milkv-duo-sdk.sh C8.4 atomic publication + package closure rehash: PASS")
PY
  verify_c84_input_state
else
  if ! "$script_dir/verify-milkv-duo-image.sh" "${verify_args[@]}"; then
    echo "package-milkv-duo-sdk.sh: refusing to publish an unverified SD image" >&2
    exit 1
  fi
fi
published=true

if [[ "$wasm_aot_profile" != true ]]; then
  echo "Milk-V Duo FIT: $output_fit"
  echo "Milk-V Duo SD image: $output_image"
fi
if [[ "$runtime_costs" == true ]]; then
  echo "Milk-V Duo runtime-cost image audit: $output_audit"
  echo "Milk-V Duo runtime-cost package envelope: $output_envelope"
elif [[ "$wasm_aot_profile" == true ]]; then
  echo "Milk-V Duo FIT: $final_output_fit"
  echo "Milk-V Duo SD image: $final_output_image"
  echo "Milk-V Duo WebAssembly AOT profile image audit: $final_output_audit"
  echo "Milk-V Duo WebAssembly AOT profile package envelope: $final_output_envelope"
fi
