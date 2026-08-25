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
runtime_costs_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
runtime_costs_sdk_container_digest=sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
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
    -*) echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs] <duo-buildroot-sdk-root>" >&2; exit 2 ;;
    *)
      if [[ -n "$sdk_arg" ]]; then
        echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs] <duo-buildroot-sdk-root>" >&2
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
if ((mode_count > 1)); then
  echo "package-milkv-duo-sdk.sh: image mode options are mutually exclusive" >&2
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs] <duo-buildroot-sdk-root>" >&2
  exit 2
fi
if [[ -z "$sdk_arg" ]]; then
  echo "usage: $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs] <duo-buildroot-sdk-root>" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
sdk_root=$(cd -- "$sdk_arg" && pwd -P)
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
fi
kernel_bin="$output_dir/vibeos-milkv-duo.bin"
kernel_elf="$output_dir/vibeos-milkv-duo-runtime-costs.elf"
output_its="$output_dir/milkv-duo.its"
output_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
output_fit="$output_dir/boot.sd"
output_image="$output_dir/$image_name"
temp_fit="$output_dir/.boot.sd.$$.tmp"
temp_image="$output_dir/.vibeos-milkv-duo-sd.img.$$.tmp"
output_audit="$output_dir/image-verifier-audit.log"
output_envelope="$output_dir/package-envelope.json"
build_envelope="$output_dir/build-envelope.json"
evidence_checker="$script_dir/verify-c83-evidence.py"
temp_audit="$output_dir/.image-verifier-audit.$$.tmp"
temp_envelope="$output_dir/.package-envelope.$$.tmp"
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
mkdir -p "$output_dir"
rm -f "$output_fit" "$output_image" "$temp_fit" "$temp_image"
if [[ "$runtime_costs" == true ]]; then
  rm -f "$output_audit" "$output_envelope" "$temp_audit" "$temp_envelope"
fi
cleanup() {
  rm -f "$temp_fit" "$temp_image" "$temp_audit" "$temp_envelope"
  if [[ -n "$pack_dir" && "$pack_dir" == "$output_dir"/.vibeos-pack.* ]]; then
    rm -rf -- "$pack_dir"
  fi
  if [[ "$published" != true ]]; then
    rm -f "$output_fit" "$output_image"
    if [[ "$runtime_costs" == true ]]; then
      rm -f "$output_audit" "$output_envelope"
    fi
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
if [[ "$runtime_costs" == true ]]; then
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
    data.truncate(512 * 1024 * 1024)
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
elif [[ "$iperf3_server" == true ]]; then
  verify_args=(--iperf3-server "$sdk_root")
elif [[ "$file_tree" == true ]]; then
  verify_args=(--file-tree "$sdk_root")
elif [[ "$runtime_costs" == true ]]; then
  verify_args=(--runtime-costs "$sdk_root")
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
else
  if ! "$script_dir/verify-milkv-duo-image.sh" "${verify_args[@]}"; then
    echo "package-milkv-duo-sdk.sh: refusing to publish an unverified SD image" >&2
    exit 1
  fi
fi
published=true

echo "Milk-V Duo FIT: $output_fit"
echo "Milk-V Duo SD image: $output_image"
if [[ "$runtime_costs" == true ]]; then
  echo "Milk-V Duo runtime-cost image audit: $output_audit"
  echo "Milk-V Duo runtime-cost package envelope: $output_envelope"
fi
