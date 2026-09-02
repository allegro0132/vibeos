#!/bin/sh
# Build the Milk-V Duo kernel image and, for legacy modes with an SDK, its FIT.
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
wasm_aot_profile=false
runtime_costs_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
wasm_aot_profile_sdk_commit=23eb84fecb29585dbb5728d6b7e2475ff273baac
runtime_costs_cargo_home_sandbox=
wasm_aot_profile_cargo_home_sandbox=
wasm_aot_profile_registry_cache=false
wasm_aot_profile_git_cache=false
wasm_aot_profile_stage_dir=
wasm_aot_profile_publish_lock=
wasm_aot_profile_publish_lock_held=false
wasm_aot_profile_source_envelope=
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
    -*) echo "usage: $0 [--diagnostic|--ssh-acceptance|--jitterentropy-probe|--jitterentropy-ssh-probe|--iperf3-server|--file-tree|--runtime-costs] [duo-buildroot-sdk-root]" >&2; echo "       $0 --wasm-aot-profile" >&2; exit 2 ;;
    *)
      if [ -n "$sdk_arg" ]; then
        echo "usage: $0 [--diagnostic|--ssh-acceptance|--jitterentropy-probe|--jitterentropy-ssh-probe|--iperf3-server|--file-tree|--runtime-costs] [duo-buildroot-sdk-root]" >&2
        echo "       $0 --wasm-aot-profile" >&2
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
[ "$wasm_aot_profile" = true ] && mode_count=$((mode_count + 1))
if [ "$mode_count" -gt 1 ]; then
  echo "build-milkv-duo.sh: image mode options are mutually exclusive" >&2
  exit 2
fi
if [ "$wasm_aot_profile" = true ] && [ -n "$sdk_arg" ]; then
  echo "build-milkv-duo.sh: --wasm-aot-profile does not accept an SDK argument; run package-milkv-duo-sdk.sh --wasm-aot-profile separately" >&2
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

require_wasm_aot_profile_identity() {
  identity_name=$1
  identity_value=$2
  identity_length=$3
  zero_value=$4
  test_value=$5
  if [ -z "$identity_value" ]; then
    echo "build-milkv-duo.sh: $identity_name is required with --wasm-aot-profile" >&2
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
  if [ "$identity_value" = "$zero_value" ]; then
    echo "build-milkv-duo.sh: $identity_name must not use the unbound all-zero sentinel" >&2
    exit 2
  fi
  if [ "$identity_value" = "$test_value" ]; then
    echo "build-milkv-duo.sh: $identity_name must not use the QEMU-only test sentinel" >&2
    exit 2
  fi
}

verify_wasm_aot_profile_source() {
  python3 -B "$script_dir/c84-source-materialization.py" verify \
    --destination "$repo_root" \
    --source-commit "$wasm_aot_profile_source_commit" \
    --challenge "$wasm_aot_profile_challenge"
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

cleanup_wasm_aot_profile_build() {
  if [ -n "$wasm_aot_profile_cargo_home_sandbox" ] &&
     [ -d "$wasm_aot_profile_cargo_home_sandbox" ]; then
    case "$wasm_aot_profile_cargo_home_sandbox" in
      "${wasm_aot_profile_tmpdir-}"/vibeos-c84-cargo-home.*)
        rm -rf -- "$wasm_aot_profile_cargo_home_sandbox"
        ;;
      *)
        echo "build-milkv-duo.sh: refusing to remove unexpected temporary C8.4 Cargo home: $wasm_aot_profile_cargo_home_sandbox" >&2
        ;;
    esac
  fi
  if [ -n "$wasm_aot_profile_stage_dir" ] &&
     [ -d "$wasm_aot_profile_stage_dir" ]; then
    case "$wasm_aot_profile_stage_dir" in
      "$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit.$wasm_aot_profile_challenge")
        for staged_name in \
          .build-envelope.*.tmp build-envelope.json \
          vibeos-milkv-duo-wasm-aot-profile.elf vibeos-milkv-duo.bin; do
          for staged_path in "$wasm_aot_profile_stage_dir"/$staged_name; do
            if [ -e "$staged_path" ] || [ -L "$staged_path" ]; then
              if [ -f "$staged_path" ] && [ ! -L "$staged_path" ]; then
                rm -f -- "$staged_path"
              else
                echo "build-milkv-duo.sh: refusing to remove unexpected C8.4 staging entry: $staged_path" >&2
              fi
            fi
          done
        done
        if ! rmdir -- "$wasm_aot_profile_stage_dir" 2>/dev/null; then
          echo "build-milkv-duo.sh: preserving non-empty C8.4 staging directory: $wasm_aot_profile_stage_dir" >&2
        fi
        ;;
      *)
        echo "build-milkv-duo.sh: refusing to remove unexpected WebAssembly AOT profile staging directory: $wasm_aot_profile_stage_dir" >&2
        ;;
    esac
  fi
  if [ "$wasm_aot_profile_publish_lock_held" = true ] &&
     [ -d "$wasm_aot_profile_publish_lock" ]; then
    case "$wasm_aot_profile_publish_lock" in
      "$repo_root/target/.milkv-duo-wasm-aot-profile.publish.lock")
        if ! rmdir -- "$wasm_aot_profile_publish_lock"; then
          echo "build-milkv-duo.sh: cannot release WebAssembly AOT profile publication lock: $wasm_aot_profile_publish_lock" >&2
        fi
        ;;
      *)
        echo "build-milkv-duo.sh: refusing to remove unexpected WebAssembly AOT profile publication lock: $wasm_aot_profile_publish_lock" >&2
        ;;
    esac
  fi
}

cleanup_build() {
  cleanup_runtime_costs_build
  cleanup_wasm_aot_profile_build
}
trap cleanup_build EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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

if [ "$wasm_aot_profile" = true ]; then
  require_wasm_aot_profile_identity VIBEOS_C84_SOURCE_COMMIT \
    "${VIBEOS_C84_SOURCE_COMMIT-}" 40 \
    0000000000000000000000000000000000000000 \
    1111111111111111111111111111111111111111
  require_wasm_aot_profile_identity VIBEOS_C84_CHALLENGE \
    "${VIBEOS_C84_CHALLENGE-}" 64 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    2222222222222222222222222222222222222222222222222222222222222222
  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT
  wasm_aot_profile_challenge=$VIBEOS_C84_CHALLENGE
  verify_wasm_aot_profile_source
  wasm_aot_profile_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge/source-materialization-envelope.json"
  wasm_aot_profile_target_dir="$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge"
  if [ -z "${HOME-}" ] || [ -z "${PATH-}" ]; then
    echo "build-milkv-duo.sh: HOME and PATH are required for the sanitized WebAssembly AOT profile build" >&2
    exit 1
  fi
  wasm_aot_profile_rustup_home=${RUSTUP_HOME-"$HOME/.rustup"}
  wasm_aot_profile_cache_cargo_home=${CARGO_HOME-"$HOME/.cargo"}
  wasm_aot_profile_tmpdir=${TMPDIR-/tmp}
  wasm_aot_profile_rustup_home=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$wasm_aot_profile_rustup_home")
  wasm_aot_profile_cache_cargo_home=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$wasm_aot_profile_cache_cargo_home")
  wasm_aot_profile_tmpdir=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$wasm_aot_profile_tmpdir")
  wasm_aot_profile_source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$wasm_aot_profile_source_commit")
  wasm_aot_profile_build_started_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
  wasm_aot_profile_publish_dir="$repo_root/target/milkv-duo-wasm-aot-profile"
  wasm_aot_profile_publish_lock="$repo_root/target/.milkv-duo-wasm-aot-profile.publish.lock"
  case "$wasm_aot_profile_target_dir" in
    "$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge") ;;
    *)
      echo "build-milkv-duo.sh: refusing to clear unexpected WebAssembly AOT profile target directory" >&2
      exit 1
      ;;
  esac
  case "$wasm_aot_profile_publish_dir" in
    "$repo_root/target/milkv-duo-wasm-aot-profile") ;;
    *)
      echo "build-milkv-duo.sh: refusing to clear unexpected WebAssembly AOT profile publication directory" >&2
      exit 1
      ;;
  esac
  if [ -L "$repo_root/target" ]; then
    echo "build-milkv-duo.sh: refusing symlink target directory: $repo_root/target" >&2
    exit 1
  fi
  mkdir -p "$repo_root/target"
  if [ ! -d "$repo_root/target" ] || [ -L "$repo_root/target" ]; then
    echo "build-milkv-duo.sh: C8.4 target parent is not a fixed directory: $repo_root/target" >&2
    exit 1
  fi
  if ! mkdir "$wasm_aot_profile_publish_lock"; then
    echo "build-milkv-duo.sh: another WebAssembly AOT profile publication is active" >&2
    exit 1
  fi
  wasm_aot_profile_publish_lock_held=true
  if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then
    echo "build-milkv-duo.sh: WebAssembly AOT profile publication is no-clobber: $wasm_aot_profile_publish_dir already exists" >&2
    exit 1
  fi
  if [ -e "$wasm_aot_profile_target_dir" ] || [ -L "$wasm_aot_profile_target_dir" ]; then
    echo "build-milkv-duo.sh: WebAssembly AOT profile target is no-clobber: $wasm_aot_profile_target_dir already exists" >&2
    exit 1
  fi
  wasm_aot_profile_stage_dir="$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit.$wasm_aot_profile_challenge"
  if [ -e "$wasm_aot_profile_stage_dir" ] || [ -L "$wasm_aot_profile_stage_dir" ] ||
     ! mkdir "$wasm_aot_profile_stage_dir"; then
    echo "build-milkv-duo.sh: WebAssembly AOT profile staging is no-clobber: $wasm_aot_profile_stage_dir" >&2
    exit 1
  fi
  export VIBEOS_C84_SOURCE_COMMIT VIBEOS_C84_CHALLENGE
fi

if [ "$diagnostic" = false ] && [ "$ssh_acceptance" = false ] &&
   [ "$iperf3_server" = false ] && [ "$runtime_costs" = false ] &&
   [ "$wasm_aot_profile" = false ]; then
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
  runtime_costs_expected_rustc=$(sed -n 's/^# \(rustc .*$\)/\1/p' "$repo_root/rust-toolchain.toml")
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

if [ "$wasm_aot_profile" = true ]; then
  wasm_aot_profile_rustup=$(command -v rustup)
  wasm_aot_profile_rustup=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$wasm_aot_profile_rustup")
  if ! wasm_aot_profile_linker=$(command -v ld.lld 2>/dev/null); then
    echo "build-milkv-duo.sh: ld.lld is required for the closed WebAssembly AOT profile build" >&2
    exit 1
  fi
  wasm_aot_profile_linker=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$wasm_aot_profile_linker")
  wasm_aot_profile_rustc_verbose=$("$pinned_rustc" -vV)
  wasm_aot_profile_expected_rustc=$(sed -n 's/^# \(rustc .*$\)/\1/p' "$repo_root/rust-toolchain.toml")
  wasm_aot_profile_expected_rustc_commit=$(sed -n 's/^# rustc-commit: //p' "$repo_root/rust-toolchain.toml")
  wasm_aot_profile_actual_rustc=$(printf '%s\n' "$wasm_aot_profile_rustc_verbose" | sed -n '1p')
  wasm_aot_profile_actual_rustc_commit=$(printf '%s\n' "$wasm_aot_profile_rustc_verbose" | sed -n 's/^commit-hash: //p')
  if [ -z "$wasm_aot_profile_expected_rustc" ] ||
     [ -z "$wasm_aot_profile_expected_rustc_commit" ] ||
     [ "$wasm_aot_profile_actual_rustc" != "$wasm_aot_profile_expected_rustc" ] ||
     [ "$wasm_aot_profile_actual_rustc_commit" != "$wasm_aot_profile_expected_rustc_commit" ]; then
    echo "build-milkv-duo.sh: installed WebAssembly AOT profile rustc differs from rust-toolchain.toml" >&2
    exit 1
  fi
  if [ ! -d "$wasm_aot_profile_tmpdir" ]; then
    echo "build-milkv-duo.sh: TMPDIR is not a directory: $wasm_aot_profile_tmpdir" >&2
    exit 1
  fi
  wasm_aot_profile_cargo_home_sandbox=$(mktemp -d "$wasm_aot_profile_tmpdir/vibeos-c84-cargo-home.XXXXXX")
  mkdir -p \
    "$wasm_aot_profile_cargo_home_sandbox/home" \
    "$wasm_aot_profile_cargo_home_sandbox/tmp" \
    "$wasm_aot_profile_cargo_home_sandbox/closed-bin"
  ln -s "$wasm_aot_profile_linker" "$wasm_aot_profile_cargo_home_sandbox/closed-bin/ld.lld"
  if [ -d "$wasm_aot_profile_cache_cargo_home/registry" ]; then
    ln -s "$wasm_aot_profile_cache_cargo_home/registry" "$wasm_aot_profile_cargo_home_sandbox/registry"
    wasm_aot_profile_registry_cache=true
  fi
  if [ -d "$wasm_aot_profile_cache_cargo_home/git" ]; then
    ln -s "$wasm_aot_profile_cache_cargo_home/git" "$wasm_aot_profile_cargo_home_sandbox/git"
    wasm_aot_profile_git_cache=true
  fi
  if [ -e "$wasm_aot_profile_cargo_home_sandbox/config" ] ||
     [ -e "$wasm_aot_profile_cargo_home_sandbox/config.toml" ]; then
    echo "build-milkv-duo.sh: isolated C8.4 Cargo home unexpectedly contains a config" >&2
    exit 1
  fi
  wasm_aot_profile_build_path="$wasm_aot_profile_cargo_home_sandbox/closed-bin:/usr/bin:/bin:/usr/sbin:/sbin"
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
  if [ "$runtime_costs" = true ] || [ "$wasm_aot_profile" = true ]; then
    if ! sdk_git_root=$(git --no-optional-locks -C "$sdk_root" rev-parse --show-toplevel 2>/dev/null) ||
       ! sdk_head=$(git --no-optional-locks -C "$sdk_root" rev-parse HEAD 2>/dev/null); then
      if [ "$runtime_costs" = true ]; then
        echo "build-milkv-duo.sh: runtime-cost SDK root is not a readable Git checkout: $sdk_root" >&2
      else
        echo "build-milkv-duo.sh: WebAssembly AOT profile SDK root is not a readable Git checkout: $sdk_root" >&2
      fi
      exit 1
    fi
    sdk_git_root=$(cd -- "$sdk_git_root" && pwd)
    if [ "$sdk_git_root" != "$sdk_root" ]; then
      if [ "$runtime_costs" = true ]; then
        echo "build-milkv-duo.sh: runtime-cost SDK path must name its Git root: $sdk_root" >&2
      else
        echo "build-milkv-duo.sh: WebAssembly AOT profile SDK path must name its Git root: $sdk_root" >&2
      fi
      exit 1
    fi
    if [ "$runtime_costs" = true ] && [ "$sdk_head" != "$runtime_costs_sdk_commit" ]; then
      echo "build-milkv-duo.sh: runtime-cost SDK HEAD is $sdk_head, expected $runtime_costs_sdk_commit" >&2
      exit 1
    fi
    if [ "$wasm_aot_profile" = true ] && [ "$sdk_head" != "$wasm_aot_profile_sdk_commit" ]; then
      echo "build-milkv-duo.sh: WebAssembly AOT profile SDK HEAD is $sdk_head, expected $wasm_aot_profile_sdk_commit" >&2
      exit 1
    fi
    if [ -n "$(git --no-optional-locks -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
      if [ "$runtime_costs" = true ]; then
        echo "build-milkv-duo.sh: runtime-cost SDK checkout is not clean" >&2
      else
        echo "build-milkv-duo.sh: WebAssembly AOT profile SDK checkout is not clean" >&2
      fi
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
elif [ "$wasm_aot_profile" = true ]; then
  features=wasm-c84-ssh-managed-child-single-boot-collector
  output_dir="$repo_root/target/milkv-duo-wasm-aot-profile"
  output_elf="$output_dir/vibeos-milkv-duo-wasm-aot-profile.elf"
fi
output_bin="$output_dir/vibeos-milkv-duo.bin"

if [ "$wasm_aot_profile" = true ]; then
  output_dir=$wasm_aot_profile_stage_dir
  output_elf="$output_dir/vibeos-milkv-duo-wasm-aot-profile.elf"
  output_bin="$output_dir/vibeos-milkv-duo.bin"
fi

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
  elif [ "$wasm_aot_profile" = true ]; then
    env -i \
      PATH="$wasm_aot_profile_build_path" \
      HOME="$wasm_aot_profile_cargo_home_sandbox/home" \
      RUSTUP_HOME="$wasm_aot_profile_rustup_home" \
      CARGO_HOME="$wasm_aot_profile_cargo_home_sandbox" \
      TMPDIR="$wasm_aot_profile_cargo_home_sandbox/tmp" \
      LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$wasm_aot_profile_source_date_epoch" \
      VIBEOS_C84_SOURCE_COMMIT="$wasm_aot_profile_source_commit" \
      VIBEOS_C84_CHALLENGE="$wasm_aot_profile_challenge" \
      RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
      CARGO_TARGET_DIR="$wasm_aot_profile_target_dir" \
      CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
      "$wasm_aot_profile_rustup" run "$toolchain" cargo build \
        --release --locked --offline \
        --no-default-features --features "$features"
  else
    RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
      rustup run "$toolchain" cargo build --release --no-default-features \
        --features "$features"
  fi
)

if [ "$runtime_costs" = true ]; then
  built_elf="$runtime_costs_target_dir/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
elif [ "$wasm_aot_profile" = true ]; then
  built_elf="$wasm_aot_profile_target_dir/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
else
  built_elf="$repo_root/target/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"
fi

if [ ! -f "$built_elf" ]; then
  echo "build-milkv-duo.sh: kernel ELF not found after build: $built_elf" >&2
  exit 1
fi
if [ "$wasm_aot_profile" = true ]; then
  verify_wasm_aot_profile_source
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
elif [ "$wasm_aot_profile" = true ]; then
  wasm_aot_profile_objcopy_os=$(uname -s)
  if [ "$wasm_aot_profile_objcopy_os" = Darwin ]; then
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

if [ "$wasm_aot_profile" = false ]; then
  echo "Milk-V Duo ELF: $output_elf"
  echo "Milk-V Duo binary: $output_bin"
fi

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
  if [ "$wasm_aot_profile" = false ]; then
    echo "Milk-V Duo FIT: $output_dir/boot.sd"
  fi
fi

if [ "$wasm_aot_profile" = true ]; then
  for artifact in "$output_elf" "$output_bin"; do
    if [ -L "$artifact" ] || [ ! -f "$artifact" ] || [ ! -s "$artifact" ]; then
      echo "build-milkv-duo.sh: staged artifact is not a non-empty regular file: $artifact" >&2
      exit 1
    fi
    if ! grep -a -F -q "$wasm_aot_profile_source_commit" "$artifact"; then
      echo "build-milkv-duo.sh: bound source commit is absent from $artifact" >&2
      exit 1
    fi
    if ! grep -a -F -q "$wasm_aot_profile_challenge" "$artifact"; then
      echo "build-milkv-duo.sh: bound challenge is absent from $artifact" >&2
      exit 1
    fi
  done
  if [ -n "$sdk_root" ]; then
    output_dtb="$output_dir/cv1800b_milkv_duo_sd.dtb"
    output_its="$output_dir/milkv-duo.its"
    output_fit="$output_dir/boot.sd"
    for artifact in "$output_dtb" "$output_its" "$output_fit"; do
      if [ -L "$artifact" ] || [ ! -f "$artifact" ] || [ ! -s "$artifact" ]; then
        echo "build-milkv-duo.sh: staged package artifact is not a non-empty regular file: $artifact" >&2
        exit 1
      fi
    done
    if ! cmp -s "$sdk_dtb" "$output_dtb"; then
      echo "build-milkv-duo.sh: staged device tree differs from the selected SDK input" >&2
      exit 1
    fi
    if ! cmp -s "$script_dir/milkv-duo.its" "$output_its"; then
      echo "build-milkv-duo.sh: staged FIT recipe differs from the repository input" >&2
      exit 1
    fi
    if ! grep -a -F -q "$wasm_aot_profile_source_commit" "$output_fit" ||
       ! grep -a -F -q "$wasm_aot_profile_challenge" "$output_fit"; then
      echo "build-milkv-duo.sh: staged FIT does not contain the bound kernel identity" >&2
      exit 1
    fi
  fi
  wasm_aot_profile_build_completed_utc=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')
  wasm_aot_profile_build_envelope="$output_dir/build-envelope.json"
  wasm_aot_profile_temp_envelope="$output_dir/.build-envelope.$$.tmp"
  jitterentropy_patch="$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch"
  python3 - \
    "$wasm_aot_profile_temp_envelope" "$wasm_aot_profile_source_commit" \
    "$wasm_aot_profile_challenge" "$repo_root" "$output_elf" "$output_bin" \
    "$script_dir/build-milkv-duo.sh" "$script_dir/c84-source-materialization.py" \
    "$wasm_aot_profile_source_envelope" "$jitterentropy_patch" \
    "$repo_root/.gitmodules" \
    "$repo_root/firmware/milkv-duo/Cargo.toml" \
    "$repo_root/firmware/milkv-duo/build.rs" \
    "$repo_root/firmware/milkv-duo/linker.ld" \
    "$repo_root/firmware/.cargo/config.toml" "$repo_root/kernel/Cargo.toml" \
    "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" \
    "$repo_root/benchmarks/wasm-aot-decision/workloads-v1.json" \
    "$repo_root/benchmarks/wasm-aot-decision/schema-v1.json" \
    "$repo_root/rust-toolchain.toml" "$wasm_aot_profile_rustup" \
    "$pinned_cargo" "$pinned_rustc" "$pinned_rustdoc" "$rust_objcopy" \
    "$wasm_aot_profile_linker" "$toolchain" "$wasm_aot_profile_rustc_verbose" \
    "$wasm_aot_profile_target_dir" "$wasm_aot_profile_cache_cargo_home" \
    "$wasm_aot_profile_registry_cache" "$wasm_aot_profile_git_cache" \
    "$wasm_aot_profile_build_path" "$wasm_aot_profile_rustup_home" \
    "$wasm_aot_profile_source_date_epoch" "$wasm_aot_profile_objcopy_os" \
    "$sysroot" "$wasm_aot_profile_build_started_utc" \
    "$wasm_aot_profile_build_completed_utc" <<'PY'
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
    source_materializer_script,
    source_materialization_envelope,
    jitterentropy_patch,
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


source_root_path = pathlib.Path(source_root).resolve(strict=True)


def logical_repo_path(path):
    resolved = pathlib.Path(path).resolve(strict=True)
    try:
        relative = resolved.relative_to(source_root_path)
    except ValueError:
        fail(f"repository input escapes source root: {resolved}")
    if not relative.parts:
        fail(f"repository input has no logical role: {resolved}")
    return relative.as_posix()


def identity(path, *, require_build_identity=False, repository_input=False):
    resolved = pathlib.Path(path).resolve(strict=True)
    before = resolved.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"cannot attest non-regular or empty file: {resolved}")
    digest = hashlib.sha256()
    needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
    found = [False, False]
    overlap = max(map(len, needles)) - 1
    tail = b""
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            if require_build_identity:
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
    if require_build_identity and not all(found):
        fail(f"built artifact does not embed source/challenge: {resolved}")
    recorded_path = logical_repo_path(resolved) if repository_input else str(resolved)
    return {"path": recorded_path, "sha256": digest.hexdigest(), "bytes": before.st_size}


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate source materialization envelope member {key!r}")
        result[key] = value
    return result


def load_source_materialization(path):
    supplied = pathlib.Path(path)
    expected = (
        source_root_path
        / "target"
        / "c84-source-materialization"
        / source_commit
        / challenge
        / "source-materialization-envelope.json"
    )
    if supplied != expected or expected.resolve(strict=True) != expected:
        fail("source materialization envelope path differs")
    before = expected.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > 16_777_216
        or before.st_nlink != 1
    ):
        fail("source materialization envelope is not a bounded single-link regular file")
    raw = expected.read_bytes()
    after = expected.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail("source materialization envelope changed while reading")
    try:
        root = json.loads(raw, object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode source materialization envelope: {error}")
    if not isinstance(root, dict) or set(root) != {
        "content", "content_sha256", "schema", "status", "version",
    }:
        fail("source materialization envelope fields are not closed")
    if (
        root["schema"] != "vibeos.c84.source-materialization-envelope"
        or type(root["version"]) is not int
        or root["version"] != 1
        or root["status"] != "closed"
    ):
        fail("source materialization envelope identity/status differs")
    content = root.get("content")
    if not isinstance(content, dict) or set(content) != {
        "bundles", "challenge", "clone_git_admin", "command", "frozen", "git",
        "independence", "materialization", "patch", "snapshot", "source",
        "source_commit", "submodules", "timestamps_utc",
    }:
        fail("source materialization content fields are not closed")
    if content.get("source_commit") != source_commit or content.get("challenge") != challenge:
        fail("source materialization identity differs")
    canonical_content = json.dumps(
        content, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = root.get("content_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or hashlib.sha256(canonical_content).hexdigest() != digest
    ):
        fail("source materialization content address differs")
    canonical_root = json.dumps(
        root, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if raw != canonical_root:
        fail("source materialization envelope is not canonical JSON")
    return root


artifacts = {
    "kernel_elf": identity(kernel_elf, require_build_identity=True, repository_input=True),
    "kernel_binary": identity(kernel_bin, require_build_identity=True, repository_input=True),
}
source_materialization = load_source_materialization(source_materialization_envelope)
tools = {
    "build_script": identity(build_script, repository_input=True),
    "source_materializer_script": identity(source_materializer_script, repository_input=True),
    "jitterentropy_patch": identity(jitterentropy_patch, repository_input=True),
    "gitmodules": identity(gitmodules, repository_input=True),
    "firmware_manifest": identity(firmware_manifest, repository_input=True),
    "firmware_build_script": identity(firmware_build_script, repository_input=True),
    "firmware_linker_script": identity(firmware_linker_script, repository_input=True),
    "firmware_cargo_config": identity(firmware_cargo_config, repository_input=True),
    "kernel_manifest": identity(kernel_manifest, repository_input=True),
    "workspace_manifest": identity(workspace_manifest, repository_input=True),
    "cargo_lock": identity(cargo_lock, repository_input=True),
    "workload_manifest": identity(workload_manifest, repository_input=True),
    "transcript_schema": identity(transcript_schema, repository_input=True),
    "toolchain_contract": identity(toolchain_contract, repository_input=True),
}
toolchain = {
    "provenance": "build-runner-self-measured; package cross-platform live rehash unavailable",
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
    "VIBEOS_C84_CHALLENGE",
    "VIBEOS_C84_SOURCE_COMMIT",
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
        "VIBEOS_C84_CHALLENGE": challenge,
        "VIBEOS_C84_SOURCE_COMMIT": source_commit,
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
    "wasm-c84-ssh-managed-child-single-boot-collector",
]
objcopy_command = [
    toolchain["rust_objcopy"]["path"],
    "-O",
    "binary",
    artifacts["kernel_elf"]["path"],
    artifacts["kernel_binary"]["path"],
]
objcopy_allowed_keys = ["LC_ALL", "PATH", "TZ"]
objcopy_values = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}
if objcopy_os == "Darwin":
    objcopy_allowed_keys.insert(0, "DYLD_LIBRARY_PATH")
    objcopy_values["DYLD_LIBRARY_PATH"] = str(pathlib.Path(sysroot).resolve(strict=True) / "lib")
try:
    workload = json.loads(pathlib.Path(workload_manifest).read_text(encoding="utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode C8.4 workload manifest: {error}")
fixture = workload.get("fixture") if isinstance(workload, dict) else None
if not isinstance(fixture, dict):
    fail("C8.4 workload fixture is missing")
artifact = fixture.get("artifact")
input_fixture = fixture.get("input")
output_fixture = fixture.get("output")
if not all(isinstance(value, dict) for value in (artifact, input_fixture, output_fixture)):
    fail("C8.4 workload fixture hashes are missing")
run_fields = [
    "vibeos.c84.aot-decision.run-id.v1",
    source_commit,
    challenge,
    artifact.get("sha256"),
    input_fixture.get("sha256"),
    output_fixture.get("sha256"),
    tools["workload_manifest"]["sha256"],
    tools["transcript_schema"]["sha256"],
]
if not all(isinstance(value, str) and "\0" not in value for value in run_fields):
    fail("C8.4 run-id fields are malformed")
try:
    run_id = hashlib.sha256("\0".join(run_fields).encode("ascii")).hexdigest()
except UnicodeEncodeError as error:
    fail(f"C8.4 run-id field is not ASCII: {error}")
closed_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
timestamp_values = [build_started_utc, build_completed_utc, closed_utc]
parsed_timestamps = []
for name, value in zip(("build_started", "build_completed", "envelope_closed"), timestamp_values):
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"build timestamp {name} is not UTC")
    try:
        parsed_timestamps.append(datetime.datetime.fromisoformat(value[:-1] + "+00:00"))
    except ValueError as error:
        fail(f"build timestamp {name} is invalid: {error}")
if parsed_timestamps != sorted(parsed_timestamps):
    fail("build timestamps are reversed")
content = {
    "platform": "milkv-duo-cv1800b",
    "source_commit": source_commit,
    "challenge": challenge,
    "run_id": run_id,
    "source": {
        "root": ".",
        "head": source_commit,
        "materialization": source_materialization,
    },
    "command": command,
    "objcopy_command": objcopy_command,
    "objcopy_environment": {
        "mode": "env -i",
        "allowed_keys": objcopy_allowed_keys,
        "values": objcopy_values,
    },
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
canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
envelope = {
    "schema": "vibeos.c84.duo-wasm-aot-profile.build-envelope",
    "version": 2,
    "status": "closed",
    "content_sha256": hashlib.sha256(canonical).hexdigest(),
    "content": content,
}
with pathlib.Path(destination).open("x", encoding="utf-8") as output:
    json.dump(envelope, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  mv "$wasm_aot_profile_temp_envelope" "$wasm_aot_profile_build_envelope"
  verify_wasm_aot_profile_source
  python3 - "$wasm_aot_profile_build_envelope" \
    "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" \
    "$repo_root" <<'PY'
import datetime
import hashlib
import json
import pathlib
import stat
import sys

envelope_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
source_commit, challenge = sys.argv[2:4]
source_root_path = pathlib.Path(sys.argv[4]).resolve(strict=True)


def fail(message):
    raise SystemExit(f"build-milkv-duo.sh: C8.4 closure rehash failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_source_materialization(path):
    if path.resolve(strict=True) != path:
        fail("source materialization envelope path is not canonical")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > 16_777_216
        or before.st_nlink != 1
    ):
        fail("source materialization envelope is not a bounded single-link regular file")
    raw = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail("source materialization envelope changed while reading")
    try:
        root = json.loads(raw, object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode source materialization envelope: {error}")
    if not isinstance(root, dict) or set(root) != {
        "content", "content_sha256", "schema", "status", "version",
    }:
        fail("source materialization envelope fields are not closed")
    if (
        root["schema"] != "vibeos.c84.source-materialization-envelope"
        or type(root["version"]) is not int
        or root["version"] != 1
        or root["status"] != "closed"
    ):
        fail("source materialization envelope identity/status differs")
    materialization_content = root.get("content")
    if not isinstance(materialization_content, dict) or set(materialization_content) != {
        "bundles", "challenge", "clone_git_admin", "command", "frozen", "git",
        "independence", "materialization", "patch", "snapshot", "source",
        "source_commit", "submodules", "timestamps_utc",
    }:
        fail("source materialization content fields are not closed")
    if (
        materialization_content.get("source_commit") != source_commit
        or materialization_content.get("challenge") != challenge
    ):
        fail("source materialization identity differs")
    canonical_content = json.dumps(
        materialization_content, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = root.get("content_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or hashlib.sha256(canonical_content).hexdigest() != digest
    ):
        fail("source materialization content address differs")
    canonical_root = json.dumps(
        root, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if raw != canonical_root:
        fail("source materialization envelope is not canonical JSON")
    return root


before_envelope = envelope_path.stat()
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
    envelope["schema"] != "vibeos.c84.duo-wasm-aot-profile.build-envelope"
    or type(envelope["version"]) is not int
    or envelope["version"] != 2
    or envelope["status"] != "closed"
):
    fail("build envelope identity/status differs")
content = envelope.get("content")
if not isinstance(content, dict) or set(content) != {
    "platform", "source_commit", "challenge", "run_id", "source", "command",
    "objcopy_command", "objcopy_environment", "environment", "toolchain",
    "artifacts", "tools", "timestamps_utc",
}:
    fail("build content fields are not closed")
canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
if hashlib.sha256(canonical).hexdigest() != envelope["content_sha256"]:
    fail("content address differs")
if content.get("source_commit") != source_commit or content.get("challenge") != challenge:
    fail("build identity differs")
if content.get("platform") != "milkv-duo-cv1800b":
    fail("build platform differs")
source = content.get("source")
if not isinstance(source, dict) or set(source) != {
    "root", "head", "materialization",
}:
    fail("source fields are not closed")
if source["root"] != "." or source["head"] != source_commit:
    fail("superproject source attestation differs")
source_materialization_path = (
    source_root_path
    / "target"
    / "c84-source-materialization"
    / source_commit
    / challenge
    / "source-materialization-envelope.json"
)
if source["materialization"] != load_source_materialization(source_materialization_path):
    fail("embedded source materialization envelope differs from the live closure")
stage_root = (
    pathlib.PurePosixPath("target")
    / f".milkv-duo-wasm-aot-profile.stage.{source_commit}.{challenge}"
)
expected_repo_paths = {
    "artifacts.kernel_elf": str(stage_root / "vibeos-milkv-duo-wasm-aot-profile.elf"),
    "artifacts.kernel_binary": str(stage_root / "vibeos-milkv-duo.bin"),
    "tools.build_script": "scripts/build-milkv-duo.sh",
    "tools.source_materializer_script": "scripts/c84-source-materialization.py",
    "tools.jitterentropy_patch": "patches/jitterentropy-rs/0001-vibeos-qualification.patch",
    "tools.gitmodules": ".gitmodules",
    "tools.firmware_manifest": "firmware/milkv-duo/Cargo.toml",
    "tools.firmware_build_script": "firmware/milkv-duo/build.rs",
    "tools.firmware_linker_script": "firmware/milkv-duo/linker.ld",
    "tools.firmware_cargo_config": "firmware/.cargo/config.toml",
    "tools.kernel_manifest": "kernel/Cargo.toml",
    "tools.workspace_manifest": "Cargo.toml",
    "tools.cargo_lock": "Cargo.lock",
    "tools.workload_manifest": "benchmarks/wasm-aot-decision/workloads-v1.json",
    "tools.transcript_schema": "benchmarks/wasm-aot-decision/schema-v1.json",
    "tools.toolchain_contract": "rust-toolchain.toml",
}
artifacts = content.get("artifacts")
tools = content.get("tools")
if not isinstance(artifacts, dict) or set(artifacts) != {"kernel_elf", "kernel_binary"}:
    fail("artifacts fields are not closed")
expected_tool_names = {label.split(".", 1)[1] for label in expected_repo_paths if label.startswith("tools.")}
if not isinstance(tools, dict) or set(tools) != expected_tool_names:
    fail("tools fields are not closed")
records = [
    (label, artifacts[label.split(".", 1)[1]] if label.startswith("artifacts.") else tools[label.split(".", 1)[1]], True)
    for label in expected_repo_paths
]
toolchain = content.get("toolchain")
if not isinstance(toolchain, dict) or set(toolchain) != {
    "provenance", "channel", "rustc_verbose", "rustup", "cargo", "rustc",
    "rustdoc", "rust_objcopy", "linker",
}:
    fail("toolchain fields are not closed")
if toolchain["provenance"] != "build-runner-self-measured; package cross-platform live rehash unavailable":
    fail("toolchain provenance differs")
for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
    records.append((f"toolchain.{name}", toolchain.get(name), False))
snapshots = {}
for label, record, is_repo_input in records:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        fail(f"{label} identity is malformed")
    if (
        not isinstance(record["path"], str)
        or not isinstance(record["sha256"], str)
        or len(record["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in record["sha256"])
        or type(record["bytes"]) is not int
        or record["bytes"] <= 0
    ):
        fail(f"{label} identity values are malformed")
    if is_repo_input:
        if record["path"] != expected_repo_paths[label]:
            fail(f"{label} logical path differs")
        pure = pathlib.PurePosixPath(record["path"])
        if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
            fail(f"{label} logical path escapes the source root")
        path = (source_root_path / pathlib.Path(*pure.parts)).resolve(strict=True)
        try:
            path.relative_to(source_root_path)
        except ValueError:
            fail(f"{label} resolved outside the source root")
    else:
        if not pathlib.PurePath(record["path"]).is_absolute():
            fail(f"{label} build-runner path is not absolute")
        path = pathlib.Path(record["path"]).resolve(strict=True)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"{label} is not a non-empty regular file")
    snapshots[label] = (path, before)
needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
for label, record, _ in records:
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
                found = [seen or needle in window for seen, needle in zip(found, needles)]
                tail = window[-overlap:]
    if before.st_size != record["bytes"] or digest.hexdigest() != record["sha256"]:
        fail(f"{label} no longer matches the build envelope")
    if label.startswith("artifacts.") and not all(found):
        fail(f"{label} no longer embeds source/challenge")
workload_record = tools.get("workload_manifest") if isinstance(tools, dict) else None
schema_record = tools.get("transcript_schema") if isinstance(tools, dict) else None
if not isinstance(workload_record, dict) or not isinstance(schema_record, dict):
    fail("run-id contract records are missing")
try:
    workload = json.loads((source_root_path / workload_record["path"]).read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError) as error:
    fail(f"cannot decode run-id workload: {error}")
fixture = workload.get("fixture") if isinstance(workload, dict) else None
try:
    fields = [
        "vibeos.c84.aot-decision.run-id.v1",
        source_commit,
        challenge,
        fixture["artifact"]["sha256"],
        fixture["input"]["sha256"],
        fixture["output"]["sha256"],
        workload_record["sha256"],
        schema_record["sha256"],
    ]
except (KeyError, TypeError) as error:
    fail(f"run-id workload fields are missing: {error}")
expected_run_id = hashlib.sha256("\0".join(fields).encode("ascii")).hexdigest()
if content.get("run_id") != expected_run_id:
    fail("run id does not bind the C8.4 campaign")
timestamps = content.get("timestamps_utc")
if not isinstance(timestamps, dict) or set(timestamps) != {
    "build_started", "build_completed", "envelope_closed",
}:
    fail("build timestamp fields are not closed")
parsed_timestamps = []
for name in ("build_started", "build_completed", "envelope_closed"):
    value = timestamps[name]
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"build timestamp {name} is not UTC")
    try:
        parsed_timestamps.append(datetime.datetime.fromisoformat(value[:-1] + "+00:00"))
    except ValueError as error:
        fail(f"build timestamp {name} is invalid: {error}")
if parsed_timestamps != sorted(parsed_timestamps):
    fail("build timestamps are reversed")
for label, (path, before) in snapshots.items():
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"{label} changed during closure rehash")
after_envelope = envelope_path.stat()
if (
    before_envelope.st_dev,
    before_envelope.st_ino,
    before_envelope.st_size,
    before_envelope.st_mtime_ns,
) != (
    after_envelope.st_dev,
    after_envelope.st_ino,
    after_envelope.st_size,
    after_envelope.st_mtime_ns,
):
    fail("build envelope changed during closure rehash")
print("build-milkv-duo.sh C8.4 build closure rehash: PASS")
PY
  verify_wasm_aot_profile_source
  if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then
    echo "build-milkv-duo.sh: WebAssembly AOT profile publication path reappeared during the build" >&2
    exit 1
  fi
  python3 - "$wasm_aot_profile_stage_dir" "$wasm_aot_profile_publish_dir" "$repo_root/target" <<'PY'
import ctypes
import errno
import os
import pathlib
import platform
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
parent = pathlib.Path(sys.argv[3]).resolve(strict=True)
if source.is_symlink() or not source.is_dir():
    raise SystemExit("build-milkv-duo.sh: C8.4 publication source is not a fixed directory")
if destination.parent.resolve(strict=True) != parent or destination.name != "milkv-duo-wasm-aot-profile":
    raise SystemExit("build-milkv-duo.sh: C8.4 publication destination differs")
if stat.S_ISLNK(destination.parent.lstat().st_mode):
    raise SystemExit("build-milkv-duo.sh: C8.4 publication parent is a symlink")
if destination.exists() or destination.is_symlink():
    raise SystemExit("build-milkv-duo.sh: C8.4 publication destination already exists")
children = list(source.iterdir())
if {child.name for child in children} != {
    "vibeos-milkv-duo-wasm-aot-profile.elf", "vibeos-milkv-duo.bin", "build-envelope.json",
}:
    raise SystemExit("build-milkv-duo.sh: C8.4 staged publication entries are not closed")
for child in children:
    if child.is_symlink() or not child.is_file():
        raise SystemExit(f"build-milkv-duo.sh: C8.4 staged publication entry differs: {child}")
    descriptor = os.open(child, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
source_descriptor = os.open(source, os.O_RDONLY)
try:
    os.fsync(source_descriptor)
finally:
    os.close(source_descriptor)

system = platform.system()
libc = ctypes.CDLL(None, use_errno=True)
source_bytes = os.fsencode(source)
destination_bytes = os.fsencode(destination)
if system == "Linux" and hasattr(libc, "renameat2"):
    libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.renameat2.restype = ctypes.c_int
    result = libc.renameat2(-100, source_bytes, -100, destination_bytes, 1)
elif system == "Darwin" and hasattr(libc, "renamex_np"):
    libc.renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    libc.renamex_np.restype = ctypes.c_int
    result = libc.renamex_np(source_bytes, destination_bytes, 0x00000004)
else:
    raise SystemExit(f"build-milkv-duo.sh: atomic no-replace directory publication is unsupported on {system}")
if result != 0:
    error = ctypes.get_errno()
    if error in (errno.EEXIST, errno.ENOTEMPTY):
        raise SystemExit("build-milkv-duo.sh: C8.4 publication destination appeared concurrently")
    raise OSError(error, os.strerror(error), str(destination))
parent_descriptor = os.open(parent, os.O_RDONLY)
try:
    os.fsync(parent_descriptor)
finally:
    os.close(parent_descriptor)
PY
  wasm_aot_profile_stage_dir=
  output_dir=$wasm_aot_profile_publish_dir
  output_elf="$output_dir/vibeos-milkv-duo-wasm-aot-profile.elf"
  output_bin="$output_dir/vibeos-milkv-duo.bin"
  echo "Milk-V Duo ELF: $output_elf"
  echo "Milk-V Duo binary: $output_bin"
  echo "Milk-V Duo WebAssembly AOT profile build envelope: $output_dir/build-envelope.json"
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
