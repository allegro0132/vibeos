#!/bin/sh
# Build the Milk-V Duo kernel image and, when an SDK is supplied, its FIT.
set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

diagnostic=false
ssh_acceptance=false
jitterentropy_probe=false
jitterentropy_ssh_probe=false
iperf3_server=false
file_tree=false
runtime_costs=false
runtime_costs_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
runtime_costs_cargo_home_sandbox=
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
    -*) echo "usage: $0 [--diagnostic|--ssh-acceptance|--jitterentropy-probe|--jitterentropy-ssh-probe|--iperf3-server|--file-tree|--runtime-costs] [duo-buildroot-sdk-root]" >&2; exit 2 ;;
    *)
      if [ -n "$sdk_arg" ]; then
        echo "usage: $0 [--diagnostic|--ssh-acceptance|--jitterentropy-probe|--jitterentropy-ssh-probe|--iperf3-server|--file-tree|--runtime-costs] [duo-buildroot-sdk-root]" >&2
        exit 2
      fi
      sdk_arg=$arg
      ;;
  esac
done

mode_count=0
[ "$diagnostic" = true ] && mode_count=$((mode_count + 1))
[ "$ssh_acceptance" = true ] && mode_count=$((mode_count + 1))
[ "$jitterentropy_probe" = true ] && mode_count=$((mode_count + 1))
[ "$jitterentropy_ssh_probe" = true ] && mode_count=$((mode_count + 1))
[ "$iperf3_server" = true ] && mode_count=$((mode_count + 1))
[ "$file_tree" = true ] && mode_count=$((mode_count + 1))
[ "$runtime_costs" = true ] && mode_count=$((mode_count + 1))
if [ "$mode_count" -gt 1 ]; then
  echo "build-milkv-duo.sh: image mode options are mutually exclusive" >&2
  exit 2
fi

require_runtime_identity() {
  identity_name=$1
  identity_value=$2
  identity_length=$3
  unbound_value=$4
  if [ -z "$identity_value" ]; then
    echo "build-milkv-duo.sh: $identity_name is required with --runtime-costs" >&2
    exit 2
  fi
  if [ "${#identity_value}" -ne "$identity_length" ]; then
    echo "build-milkv-duo.sh: $identity_name must be exactly $identity_length lowercase hexadecimal characters" >&2
    exit 2
  fi
  case "$identity_value" in
    *[!0123456789abcdef]*)
      echo "build-milkv-duo.sh: $identity_name must be exactly $identity_length lowercase hexadecimal characters" >&2
      exit 2
      ;;
  esac
  if [ "$identity_value" = "$unbound_value" ]; then
    echo "build-milkv-duo.sh: $identity_name must not use the unbound all-zero sentinel" >&2
    exit 2
  fi
  if { [ "$identity_name" = VIBEOS_C83_SOURCE_COMMIT ] &&
       [ "$identity_value" = 1111111111111111111111111111111111111111 ]; } ||
     { [ "$identity_name" = VIBEOS_C83_CHALLENGE ] &&
       [ "$identity_value" = 2222222222222222222222222222222222222222222222222222222222222222 ]; }; then
    echo "build-milkv-duo.sh: $identity_name must not use the documented test-only sentinel" >&2
    exit 2
  fi
}

cleanup_runtime_costs_build() {
  if [ -n "$runtime_costs_cargo_home_sandbox" ] &&
     [ -d "$runtime_costs_cargo_home_sandbox" ]; then
    case "$runtime_costs_cargo_home_sandbox" in
      "${runtime_costs_tmpdir-}"/vibeos-c83-cargo-home.*)
        rm -rf -- "$runtime_costs_cargo_home_sandbox"
        ;;
      *)
        echo "build-milkv-duo.sh: refusing to remove unexpected temporary Cargo home: $runtime_costs_cargo_home_sandbox" >&2
        ;;
    esac
  fi
}
trap cleanup_runtime_costs_build EXIT

if [ "$runtime_costs" = true ]; then
  require_runtime_identity VIBEOS_C83_SOURCE_COMMIT \
    "${VIBEOS_C83_SOURCE_COMMIT-}" 40 \
    0000000000000000000000000000000000000000
  require_runtime_identity VIBEOS_C83_CHALLENGE \
    "${VIBEOS_C83_CHALLENGE-}" 64 \
    0000000000000000000000000000000000000000000000000000000000000000
  runtime_costs_source_commit=$VIBEOS_C83_SOURCE_COMMIT
  runtime_costs_challenge=$VIBEOS_C83_CHALLENGE
  if ! runtime_costs_head=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null); then
    echo "build-milkv-duo.sh: cannot read VibeOS source HEAD" >&2
    exit 1
  fi
  if [ "$runtime_costs_head" != "$runtime_costs_source_commit" ]; then
    echo "build-milkv-duo.sh: VibeOS HEAD is $runtime_costs_head, expected $runtime_costs_source_commit" >&2
    exit 1
  fi
  if [ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
    echo "build-milkv-duo.sh: runtime-cost build requires a clean VibeOS worktree" >&2
    exit 1
  fi
  if [ -z "${HOME-}" ] || [ -z "${PATH-}" ]; then
    echo "build-milkv-duo.sh: HOME and PATH are required for the sanitized runtime-cost build" >&2
    exit 1
  fi
  runtime_costs_rustup_home=${RUSTUP_HOME-"$HOME/.rustup"}
  runtime_costs_cache_cargo_home=${CARGO_HOME-"$HOME/.cargo"}
  runtime_costs_tmpdir=${TMPDIR-/tmp}
  runtime_costs_rustup_home=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$runtime_costs_rustup_home")
  runtime_costs_cache_cargo_home=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$runtime_costs_cache_cargo_home")
  runtime_costs_tmpdir=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$runtime_costs_tmpdir")
  runtime_costs_target_dir="$repo_root/target/c83-milkv-build/$runtime_costs_source_commit/$runtime_costs_challenge"
  runtime_costs_source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$runtime_costs_source_commit")
  runtime_costs_build_started_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
  export VIBEOS_C83_SOURCE_COMMIT VIBEOS_C83_CHALLENGE
fi

if [ "$diagnostic" = false ] && [ "$ssh_acceptance" = false ] && [ "$iperf3_server" = false ] && [ "$runtime_costs" = false ]; then
  "$script_dir/prepare-jitterentropy-rs.sh"
fi

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' \
  "$repo_root/rust-toolchain.toml")
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "build-milkv-duo.sh: rustup and an exact rust-toolchain.toml channel are required" >&2
  exit 1
fi

pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
pinned_cargo=$(rustup which --toolchain "$toolchain" cargo)
sysroot=$("$pinned_rustc" --print sysroot)
host=$("$pinned_rustc" -vV | sed -n 's/^host: //p')
rust_objcopy="$sysroot/lib/rustlib/$host/bin/rust-objcopy"
if [ -z "$host" ] || [ ! -x "$rust_objcopy" ] || [ ! -x "$pinned_cargo" ]; then
  echo "build-milkv-duo.sh: pinned rust-objcopy not found: $rust_objcopy" >&2
  exit 1
fi

if [ "$runtime_costs" = true ]; then
  runtime_costs_rustup=$(command -v rustup)
  runtime_costs_rustup=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$runtime_costs_rustup")
  if ! runtime_costs_linker=$(command -v ld.lld 2>/dev/null); then
    echo "build-milkv-duo.sh: ld.lld is required for the closed runtime-cost build" >&2
    exit 1
  fi
  runtime_costs_linker=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$runtime_costs_linker")
  runtime_costs_rustc_verbose=$("$pinned_rustc" -vV)
  runtime_costs_expected_rustc=$(sed -n 's/^# rustc //p' "$repo_root/rust-toolchain.toml")
  runtime_costs_expected_rustc_commit=$(sed -n 's/^# rustc-commit: //p' "$repo_root/rust-toolchain.toml")
  runtime_costs_actual_rustc=$(printf '%s\n' "$runtime_costs_rustc_verbose" | sed -n '1p')
  runtime_costs_actual_rustc_commit=$(printf '%s\n' "$runtime_costs_rustc_verbose" | sed -n 's/^commit-hash: //p')
  if [ -z "$runtime_costs_expected_rustc" ] ||
     [ -z "$runtime_costs_expected_rustc_commit" ] ||
     [ "$runtime_costs_actual_rustc" != "$runtime_costs_expected_rustc" ] ||
     [ "$runtime_costs_actual_rustc_commit" != "$runtime_costs_expected_rustc_commit" ]; then
    echo "build-milkv-duo.sh: installed runtime-cost rustc differs from rust-toolchain.toml" >&2
    exit 1
  fi
  if [ ! -d "$runtime_costs_tmpdir" ]; then
    echo "build-milkv-duo.sh: TMPDIR is not a directory: $runtime_costs_tmpdir" >&2
    exit 1
  fi
  runtime_costs_cargo_home_sandbox=$(mktemp -d "$runtime_costs_tmpdir/vibeos-c83-cargo-home.XXXXXX")
  mkdir -p \
    "$runtime_costs_cargo_home_sandbox/home" \
    "$runtime_costs_cargo_home_sandbox/tmp" \
    "$runtime_costs_cargo_home_sandbox/closed-bin"
  ln -s "$runtime_costs_linker" "$runtime_costs_cargo_home_sandbox/closed-bin/ld.lld"
  runtime_costs_registry_cache=false
  runtime_costs_git_cache=false
  if [ -d "$runtime_costs_cache_cargo_home/registry" ]; then
    ln -s "$runtime_costs_cache_cargo_home/registry" "$runtime_costs_cargo_home_sandbox/registry"
    runtime_costs_registry_cache=true
  fi
  if [ -d "$runtime_costs_cache_cargo_home/git" ]; then
    ln -s "$runtime_costs_cache_cargo_home/git" "$runtime_costs_cargo_home_sandbox/git"
    runtime_costs_git_cache=true
  fi
  if [ -e "$runtime_costs_cargo_home_sandbox/config" ] ||
     [ -e "$runtime_costs_cargo_home_sandbox/config.toml" ]; then
    echo "build-milkv-duo.sh: isolated Cargo home unexpectedly contains a config" >&2
    exit 1
  fi
  runtime_costs_build_path="$runtime_costs_cargo_home_sandbox/closed-bin:/usr/bin:/bin:/usr/sbin:/sbin"
fi

sdk_root=
mkimage=
sdk_dtb=
if [ -n "$sdk_arg" ]; then
  if [ ! -d "$sdk_arg" ]; then
    echo "build-milkv-duo.sh: SDK root is not a directory: $sdk_arg" >&2
    exit 1
  fi
  sdk_root=$(cd -- "$sdk_arg" && pwd)
  if [ "$runtime_costs" = true ]; then
    if ! sdk_git_root=$(git --no-optional-locks -C "$sdk_root" rev-parse --show-toplevel 2>/dev/null) ||
       ! sdk_head=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD 2>/dev/null); then
      echo "build-milkv-duo.sh: runtime-cost SDK root is not a readable Git checkout: $sdk_root" >&2
      exit 1
    fi
    sdk_git_root=$(cd -- "$sdk_git_root" && pwd)
    if [ "$sdk_git_root" != "$sdk_root" ]; then
      echo "build-milkv-duo.sh: runtime-cost SDK path must name its Git root: $sdk_root" >&2
      exit 1
    fi
    if [ "$sdk_head" != "$runtime_costs_sdk_commit" ]; then
      echo "build-milkv-duo.sh: runtime-cost SDK HEAD is $sdk_head, expected $runtime_costs_sdk_commit" >&2
      exit 1
    fi
    if [ -n "$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
      echo "build-milkv-duo.sh: runtime-cost SDK checkout is not clean" >&2
      exit 1
    fi
  fi
  sdk_build="$sdk_root/u-boot-2021.10/build/cv1800b_milkv_duo_sd"
  mkimage="$sdk_build/tools/mkimage"
  sdk_dtb="$sdk_root/linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb"
  if [ ! -x "$mkimage" ]; then
    echo "build-milkv-duo.sh: SDK mkimage not found or not executable: $mkimage" >&2
    exit 1
  fi
  if ! "$mkimage" -V >/dev/null 2>&1; then
    echo "build-milkv-duo.sh: SDK mkimage cannot run on this host; build the" >&2
    echo "  kernel without an SDK argument, then package it inside the SDK container" >&2
    exit 1
  fi
  if [ ! -f "$sdk_dtb" ]; then
    echo "build-milkv-duo.sh: SDK device tree not found: $sdk_dtb" >&2
    exit 1
  fi
fi

features=milkv-ssh
output_dir="$repo_root/target/milkv-duo"
output_elf="$output_dir/vibeos-milkv-duo.elf"
if [ "$diagnostic" = true ]; then
  features=legacy-shell
  output_dir="$repo_root/target/milkv-duo-diagnostic"
  output_elf="$output_dir/vibeos-milkv-duo-diagnostic.elf"
elif [ "$ssh_acceptance" = true ]; then
  features=milkv-ssh-acceptance
  output_dir="$repo_root/target/milkv-duo-ssh-acceptance"
  output_elf="$output_dir/vibeos-milkv-duo-ssh-acceptance.elf"
elif [ "$jitterentropy_probe" = true ]; then
  features=milkv-jitterentropy-probe
  output_dir="$repo_root/target/milkv-duo-jitterentropy-probe"
  output_elf="$output_dir/vibeos-milkv-duo-jitterentropy-probe.elf"
elif [ "$jitterentropy_ssh_probe" = true ]; then
  features=milkv-jitterentropy-ssh-probe
  output_dir="$repo_root/target/milkv-duo-jitterentropy-ssh-probe"
  output_elf="$output_dir/vibeos-milkv-duo-jitterentropy-ssh-probe.elf"
elif [ "$iperf3_server" = true ]; then
  features=milkv-iperf3-server
  output_dir="$repo_root/target/milkv-duo-iperf3-server"
  output_elf="$output_dir/vibeos-milkv-duo-iperf3-server.elf"
elif [ "$file_tree" = true ]; then
  features=milkv-ssh,file-tree
  output_dir="$repo_root/target/milkv-duo-file-tree"
  output_elf="$output_dir/vibeos-milkv-duo-file-tree.elf"
elif [ "$runtime_costs" = true ]; then
  features=wasm-c83-runtime-costs
  output_dir="$repo_root/target/milkv-duo-runtime-costs"
  output_elf="$output_dir/vibeos-milkv-duo-runtime-costs.elf"
fi
output_bin="$output_dir/vibeos-milkv-duo.bin"

if [ "$runtime_costs" = true ]; then
  runtime_costs_build_envelope="$output_dir/build-envelope.json"
  runtime_costs_temp_envelope="$output_dir/.build-envelope.$$.tmp"
  case "$runtime_costs_target_dir" in
    "$repo_root/target/c83-milkv-build/$runtime_costs_source_commit/$runtime_costs_challenge") ;;
    *)
      echo "build-milkv-duo.sh: refusing to clear unexpected runtime-cost target directory" >&2
      exit 1
      ;;
  esac
  rm -rf -- "$runtime_costs_target_dir"
  mkdir -p "$output_dir"
  rm -f -- \
    "$output_elf" "$output_bin" "$runtime_costs_build_envelope" "$runtime_costs_temp_envelope" \
    "$output_dir/boot.sd" "$output_dir/milkv-duo.its" \
    "$output_dir/cv1800b_milkv_duo_sd.dtb" \
    "$output_dir/vibeos-milkv-duo-runtime-costs-sd.img" \
    "$output_dir/image-verifier-audit.log" "$output_dir/package-envelope.json"
fi

(
  cd "$repo_root/firmware/milkv-duo"
  if [ "$runtime_costs" = true ]; then
    env -i \
      PATH="$runtime_costs_build_path" \
      HOME="$runtime_costs_cargo_home_sandbox/home" \
      RUSTUP_HOME="$runtime_costs_rustup_home" \
      CARGO_HOME="$runtime_costs_cargo_home_sandbox" \
      TMPDIR="$runtime_costs_cargo_home_sandbox/tmp" \
      LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$runtime_costs_source_date_epoch" \
      VIBEOS_C83_SOURCE_COMMIT="$runtime_costs_source_commit" \
      VIBEOS_C83_CHALLENGE="$runtime_costs_challenge" \
      RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
      CARGO_TARGET_DIR="$runtime_costs_target_dir" \
      CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
      "$runtime_costs_rustup" run "$toolchain" cargo build \
        --release --locked --offline --no-default-features --features "$features"
  else
    RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
      rustup run "$toolchain" cargo build --release --no-default-features \
        --features "$features"
  fi
)

if [ "$runtime_costs" = true ]; then
  built_elf="$runtime_costs_target_dir/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
else
  built_elf="$repo_root/target/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
fi

if [ ! -f "$built_elf" ]; then
  echo "build-milkv-duo.sh: kernel ELF not found after build: $built_elf" >&2
  exit 1
fi

mkdir -p "$output_dir"
cp "$built_elf" "$output_elf"
if [ "$runtime_costs" = true ]; then
  runtime_costs_objcopy_os=$(uname -s)
  if [ "$runtime_costs_objcopy_os" = Darwin ]; then
    env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC DYLD_LIBRARY_PATH="$sysroot/lib" \
      "$rust_objcopy" -O binary "$output_elf" "$output_bin"
  else
    env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
      "$rust_objcopy" -O binary "$output_elf" "$output_bin"
  fi
elif [ "$(uname -s)" = Darwin ]; then
  DYLD_LIBRARY_PATH="$sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    "$rust_objcopy" -O binary "$output_elf" "$output_bin"
else
  "$rust_objcopy" -O binary "$output_elf" "$output_bin"
fi

echo "Milk-V Duo ELF: $output_elf"
echo "Milk-V Duo binary: $output_bin"

if [ -n "$sdk_root" ]; then
  output_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
  output_its="$output_dir/milkv-duo.its"
  cp "$sdk_dtb" "$output_dtb"
  cp "$script_dir/milkv-duo.its" "$output_its"
  (
    cd "$output_dir"
    "$mkimage" -f milkv-duo.its boot.sd
    "$mkimage" -l boot.sd
  )
  echo "Milk-V Duo FIT: $output_dir/boot.sd"
fi

if [ "$runtime_costs" = true ]; then
  runtime_costs_build_completed_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
  if [ "$(git -C "$repo_root" rev-parse HEAD)" != "$runtime_costs_source_commit" ] ||
     [ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
    echo "build-milkv-duo.sh: VibeOS source changed during the runtime-cost build" >&2
    exit 1
  fi
  if [ -n "$sdk_root" ] &&
     { [ "$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD)" != "$runtime_costs_sdk_commit" ] ||
       [ -n "$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; }; then
    echo "build-milkv-duo.sh: runtime-cost SDK checkout changed during the build" >&2
    exit 1
  fi
  python3 - \
    "$runtime_costs_temp_envelope" "$runtime_costs_source_commit" "$runtime_costs_challenge" \
    "$repo_root" "$output_elf" "$output_bin" \
    "$script_dir/build-milkv-duo.sh" "$repo_root/firmware/milkv-duo/Cargo.toml" \
    "$repo_root/firmware/milkv-duo/build.rs" "$repo_root/firmware/milkv-duo/linker.ld" \
    "$repo_root/firmware/.cargo/config.toml" "$repo_root/kernel/Cargo.toml" \
    "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" \
    "$repo_root/benchmarks/wasm-runtime/workloads-v1.json" "$repo_root/rust-toolchain.toml" \
    "$runtime_costs_rustup" "$pinned_cargo" "$pinned_rustc" "$pinned_rustdoc" \
    "$rust_objcopy" "$runtime_costs_linker" "$toolchain" "$runtime_costs_rustc_verbose" \
    "$runtime_costs_target_dir" "$runtime_costs_cache_cargo_home" \
    "$runtime_costs_registry_cache" "$runtime_costs_git_cache" \
    "$runtime_costs_build_path" "$runtime_costs_rustup_home" "$runtime_costs_source_date_epoch" \
    "$runtime_costs_objcopy_os" "$sysroot" \
    "$runtime_costs_build_started_utc" "$runtime_costs_build_completed_utc" <<'PY'
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
    rustup,
    cargo,
    rustc,
    rustdoc,
    rust_objcopy,
    linker,
    toolchain_channel,
    rustc_verbose,
    target_dir,
    cache_cargo_home,
    registry_cache,
    git_cache,
    build_path,
    rustup_home,
    source_date_epoch,
    objcopy_os,
    sysroot,
    build_started_utc,
    build_completed_utc,
) = sys.argv[1:]


def fail(message):
    raise SystemExit(f"build-milkv-duo.sh: {message}")


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
        fail(f"built artifact does not embed source/challenge: {resolved}")
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


artifacts = {
    "kernel_elf": identity(kernel_elf, require_build_identity=True),
    "kernel_binary": identity(kernel_bin, require_build_identity=True),
}
tools = {
    "build_script": identity(build_script),
    "firmware_manifest": identity(firmware_manifest),
    "firmware_build_script": identity(firmware_build_script),
    "firmware_linker_script": identity(firmware_linker_script),
    "firmware_cargo_config": identity(firmware_cargo_config),
    "kernel_manifest": identity(kernel_manifest),
    "workspace_manifest": identity(workspace_manifest),
    "cargo_lock": identity(cargo_lock),
    "workload_manifest": identity(workload_manifest),
    "toolchain_contract": identity(toolchain_contract),
}
toolchain = {
    "channel": toolchain_channel,
    "rustc_verbose": rustc_verbose,
    "rustup": identity(rustup),
    "cargo": identity(cargo),
    "rustc": identity(rustc),
    "rustdoc": identity(rustdoc),
    "rust_objcopy": identity(rust_objcopy),
    "linker": identity(linker),
}
allowed_keys = [
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
environment = {
    "mode": "env -i",
    "allowed_keys": allowed_keys,
    "values": {
        "CARGO_HOME": "<isolated-cargo-home>",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(pathlib.Path(target_dir).resolve()),
        "HOME": "<isolated-cargo-home>/home",
        "LC_ALL": "C",
        "PATH": build_path,
        "RUSTC": str(pathlib.Path(rustc).resolve(strict=True)),
        "RUSTDOC": str(pathlib.Path(rustdoc).resolve(strict=True)),
        "RUSTUP_HOME": str(pathlib.Path(rustup_home).expanduser().resolve()),
        "SOURCE_DATE_EPOCH": source_date_epoch,
        "TMPDIR": "<isolated-cargo-home>/tmp",
        "TZ": "UTC",
        "VIBEOS_C83_CHALLENGE": challenge,
        "VIBEOS_C83_SOURCE_COMMIT": source_commit,
    },
    "cargo_home_isolation": {
        "ambient_config_loaded": False,
        "temporary": True,
        "cache_source": str(pathlib.Path(cache_cargo_home).expanduser().resolve()),
        "registry_cache_symlinked": registry_cache == "true",
        "git_cache_symlinked": git_cache == "true",
    },
}
command = [
    str(pathlib.Path(rustup).resolve(strict=True)),
    "run",
    toolchain_channel,
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--no-default-features",
    "--features",
    "wasm-c83-runtime-costs",
]
objcopy_command = [
    str(pathlib.Path(rust_objcopy).resolve(strict=True)),
    "-O",
    "binary",
    str(pathlib.Path(kernel_elf).resolve(strict=True)),
    str(pathlib.Path(kernel_bin).resolve(strict=True)),
]
objcopy_allowed_keys = ["LC_ALL", "PATH", "TZ"]
objcopy_values = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}
if objcopy_os == "Darwin":
    objcopy_allowed_keys.insert(0, "DYLD_LIBRARY_PATH")
    objcopy_values["DYLD_LIBRARY_PATH"] = str(pathlib.Path(sysroot).resolve(strict=True) / "lib")
objcopy_environment = {
    "mode": "env -i",
    "allowed_keys": objcopy_allowed_keys,
    "values": objcopy_values,
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
    "command": command,
    "objcopy_command": objcopy_command,
    "objcopy_environment": objcopy_environment,
    "environment": environment,
    "toolchain": toolchain,
    "artifacts": artifacts,
    "tools": tools,
    "timestamps_utc": {
        "build_started": build_started_utc,
        "build_completed": build_completed_utc,
        "envelope_closed": closed_utc,
    },
}
canonical_content = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
envelope = {
    "schema": "vibeos.c83.duo-runtime-costs.build-envelope",
    "version": 1,
    "status": "closed",
    "content_sha256": hashlib.sha256(canonical_content).hexdigest(),
    "content": content,
}
with pathlib.Path(destination).open("x", encoding="utf-8") as output:
    json.dump(envelope, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  mv "$runtime_costs_temp_envelope" "$runtime_costs_build_envelope"
  python3 - "$runtime_costs_build_envelope" "$runtime_costs_source_commit" "$runtime_costs_challenge" <<'PY'
import hashlib
import json
import pathlib
import sys

envelope_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
source_commit = sys.argv[2]
challenge = sys.argv[3]


def fail(message):
    raise SystemExit(f"build-milkv-duo.sh: closure rehash failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


envelope_before = envelope_path.stat()
try:
    envelope = json.loads(
        envelope_path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode build envelope: {error}")
if set(envelope) != {"schema", "version", "status", "content_sha256", "content"}:
    fail("build envelope fields are not closed")
if (
    envelope["schema"] != "vibeos.c83.duo-runtime-costs.build-envelope"
    or envelope["version"] != 1
    or envelope["status"] != "closed"
):
    fail("build envelope identity/status differs")
content = envelope["content"]
canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(canonical).hexdigest() != envelope["content_sha256"]:
    fail("content address differs")
if content.get("source_commit") != source_commit or content.get("challenge") != challenge:
    fail("build identity differs")

records = []
for section_name in ("artifacts", "tools"):
    section = content.get(section_name)
    if not isinstance(section, dict):
        fail(f"{section_name} section is missing")
    records.extend((f"{section_name}.{name}", record) for name, record in section.items())
toolchain = content.get("toolchain")
if not isinstance(toolchain, dict):
    fail("toolchain section is missing")
for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
    records.append((f"toolchain.{name}", toolchain.get(name)))

snapshots = {}
for label, record in records:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        fail(f"{label} identity is malformed")
    path = pathlib.Path(record["path"]).resolve(strict=True)
    snapshots[label] = (path, path.stat())

needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
for label, record in records:
    path, before = snapshots[label]
    digest = hashlib.sha256()
    found = [False, False]
    overlap = max(map(len, needles)) - 1
    tail = b""
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            if label.startswith("artifacts."):
                window = tail + chunk
                found = [was_found or needle in window for was_found, needle in zip(found, needles)]
                tail = window[-overlap:]
    if before.st_size != record["bytes"] or digest.hexdigest() != record["sha256"]:
        fail(f"{label} no longer matches the build envelope")
    if label.startswith("artifacts.") and not all(found):
        fail(f"{label} no longer embeds source/challenge")

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
    fail("build envelope changed during the closure rehash")
print("build-milkv-duo.sh runtime-cost build closure rehash: PASS")
PY
  if [ "$(git -C "$repo_root" rev-parse HEAD)" != "$runtime_costs_source_commit" ] ||
     [ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
    echo "build-milkv-duo.sh: VibeOS source changed before build-envelope publication" >&2
    exit 1
  fi
  if [ -n "$sdk_root" ] &&
     { [ "$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD)" != "$runtime_costs_sdk_commit" ] ||
       [ -n "$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; }; then
    echo "build-milkv-duo.sh: runtime-cost SDK checkout changed before build-envelope publication" >&2
    exit 1
  fi
  if [ "$("$pinned_rustc" -vV)" != "$runtime_costs_rustc_verbose" ]; then
    echo "build-milkv-duo.sh: pinned rustc changed before build-envelope publication" >&2
    exit 1
  fi
  echo "Milk-V Duo runtime-cost build envelope: $runtime_costs_build_envelope"
fi
