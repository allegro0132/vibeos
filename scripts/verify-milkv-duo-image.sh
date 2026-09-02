#!/usr/bin/env bash
# Verify the final Milk-V Duo SD image without mounting or modifying it.
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: $0 --selftest" >&2
  echo "       $0 [--diagnostic | --ssh-acceptance | --jitterentropy-probe | --jitterentropy-ssh-probe | --iperf3-server | --file-tree | --runtime-costs | --wasm-aot-profile] [--package-preflight] [--artifact-root=<absolute-path>] <duo-buildroot-sdk-root>" >&2
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


def verify_c84_package_phase(package_preflight, package_envelope_exists):
    if package_preflight:
        if package_envelope_exists:
            raise Violation("package-preflight unexpectedly found a package envelope")
    elif not package_envelope_exists:
        raise Violation("final C8.4 verification requires a package envelope")


def verify_c84_report_shape(report):
    expected_fields = {
        "schema", "version", "source_commit", "challenge",
        "source_materialization", "runtime_attestation", "artifacts", "tools",
    }
    expected_tools = {
        "sdk_mkimage", "sdk_dumpimage", "git_config", "source_materializer_script",
        "docker_runtime_script", "mdir", "mcopy", "cmp", "sha256sum", "fdtget",
        "python3", "tr",
    }
    if not isinstance(report, dict) or set(report) != expected_fields:
        raise Violation("image audit report fields are not closed")
    if not isinstance(report["tools"], dict) or set(report["tools"]) != expected_tools:
        raise Violation("image audit report tools are not closed")


def verify_c84_runtime_binding(report, live_runtime_attestation):
    verify_c84_report_shape(report)
    if report["runtime_attestation"] != live_runtime_attestation:
        raise Violation("image audit report runtime attestation differs")


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

    verify_c84_package_phase(True, False)
    try:
        verify_c84_package_phase(False, False)
    except Violation as error:
        if "requires a package envelope" not in str(error):
            raise RuntimeError(
                "selftest 'missing-final-package-envelope' failed for the wrong reason: "
                f"{error}"
            ) from error
    else:
        raise RuntimeError("selftest 'missing-final-package-envelope' was accepted")

    live_runtime_attestation = {"schema": "vibeos.c84.docker-runtime-attestation", "version": 1}
    report = {
        "schema": None, "version": None, "source_commit": None, "challenge": None,
        "source_materialization": None,
        "runtime_attestation": live_runtime_attestation,
        "artifacts": {},
        "tools": {
            name: None
            for name in (
                "sdk_mkimage", "sdk_dumpimage", "git_config", "source_materializer_script",
                "docker_runtime_script", "mdir", "mcopy", "cmp", "sha256sum", "fdtget",
                "python3", "tr",
            )
        },
    }
    verify_c84_runtime_binding(report, live_runtime_attestation)
    for label, mutation, expected_message in (
        (
            "legacy-report-without-source-materialization",
            lambda value: value.pop("source_materialization"),
            "report fields",
        ),
        (
            "legacy-report-without-source-tool",
            lambda value: value["tools"].pop("source_materializer_script"),
            "report tools",
        ),
        (
            "legacy-report-without-runtime-attestation",
            lambda value: value.pop("runtime_attestation"),
            "report fields",
        ),
        (
            "legacy-report-without-runtime-tool",
            lambda value: value["tools"].pop("docker_runtime_script"),
            "report tools",
        ),
    ):
        candidate = {**report, "tools": dict(report["tools"])}
        mutation(candidate)
        try:
            verify_c84_report_shape(candidate)
        except Violation as error:
            if expected_message not in str(error):
                raise RuntimeError(
                    f"selftest {label!r} failed for the wrong reason: {error}"
                ) from error
        else:
            raise RuntimeError(f"selftest {label!r} was accepted")

    swapped = {**report, "tools": dict(report["tools"])}
    swapped["runtime_attestation"] = {
        "schema": "vibeos.c84.docker-runtime-attestation", "version": 2,
    }
    try:
        verify_c84_runtime_binding(swapped, live_runtime_attestation)
    except Violation as error:
        if "runtime attestation differs" not in str(error):
            raise RuntimeError(
                "selftest 'swapped-runtime-attestation' failed for the wrong reason: "
                f"{error}"
            ) from error
    else:
        raise RuntimeError("selftest 'swapped-runtime-attestation' was accepted")

    print("verify-milkv-duo-image.sh raw data/provenance selftest: PASS (13 negative cases)")


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

verify_c84_provenance_selftest() {
  local selftest_source=$1
  if [[ "$selftest_source" != */* ]]; then
    selftest_source=$(command -v -- "$selftest_source")
  fi
  python3 - "$selftest_source" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1]).resolve(strict=True)
text = path.read_text(encoding="utf-8")
begin = "# C84_" + "PROVENANCE_VALIDATOR_BEGIN"
end = "# C84_" + "PROVENANCE_VALIDATOR_END"
if text.count(begin) != 1 or text.count(end) != 1:
    raise SystemExit("verify-milkv-duo-image.sh: provenance selftest markers differ")
program = text.split(begin, 1)[1].split(end, 1)[0]
sys.argv = [f"{path}:C84-provenance-validator", "--selftest"]
exec(compile(program, f"{path}:C84-provenance-validator", "exec"), {"__name__": "__main__"})
PY
}

c84_stability_tracker() {
  python3 -B - "$@" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys


SCHEMA = "vibeos.c84.image-verifier-stability-tracker"
VERSION = 2
PHASES = {
    "mark-structure": ("collecting", "structure_complete"),
    "mark-report": ("structure_complete", "report_complete"),
    "mark-gates": ("report_complete", "gates_complete"),
}


def fail(message):
    raise SystemExit(f"verify-milkv-duo-image.sh: C8.4 global stability tracker: {message}")


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields are not closed")
    return value


def stat_identity(value):
    return {
        "dev": value.st_dev,
        "ino": value.st_ino,
        "mode": value.st_mode,
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def observe(path_text):
    supplied = pathlib.Path(path_text)
    try:
        canonical = supplied.resolve(strict=True)
        before = canonical.stat()
    except OSError as error:
        fail(f"cannot resolve tracked input {supplied}: {error}")
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"tracked input is not a non-empty regular file: {canonical}")
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with canonical.open("rb") as stream:
            while chunk := stream.read(4 * 1024 * 1024):
                digest.update(chunk)
                byte_count += len(chunk)
        after = canonical.stat()
    except OSError as error:
        fail(f"cannot read tracked input {canonical}: {error}")
    before_identity = stat_identity(before)
    if before_identity != stat_identity(after) or byte_count != before.st_size:
        fail(f"tracked input changed while it was first read: {canonical}")
    return {
        "path": str(canonical),
        **before_identity,
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
    }


def observe_directory(path_text):
    supplied = pathlib.Path(path_text)
    try:
        canonical = supplied.resolve(strict=True)
        before_lstat = canonical.lstat()
        before = canonical.stat()
    except OSError as error:
        fail(f"cannot resolve tracked directory {supplied}: {error}")
    if stat.S_ISLNK(before_lstat.st_mode) or not stat.S_ISDIR(before.st_mode):
        fail(f"tracked directory is not a non-symlink directory: {canonical}")
    try:
        names = sorted(os.fsencode(entry.name) for entry in os.scandir(canonical))
        after = canonical.stat()
    except OSError as error:
        fail(f"cannot enumerate tracked directory {canonical}: {error}")
    before_identity = stat_identity(before)
    if before_identity != stat_identity(after):
        fail(f"tracked directory changed while it was first read: {canonical}")
    digest = hashlib.sha256()
    for name in names:
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
    return {
        "path": str(canonical),
        **before_identity,
        "entries": len(names),
        "entries_sha256": digest.hexdigest(),
    }


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def load_state(path):
    try:
        before_lstat = path.lstat()
        if stat.S_ISLNK(before_lstat.st_mode) or not stat.S_ISREG(before_lstat.st_mode):
            fail("tracker state is not a regular non-symlink file")
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
    except OSError as error:
        fail(f"cannot read tracker state: {error}")
    if stat_identity(before) != stat_identity(after):
        fail("tracker state changed while it was read")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode tracker state: {error}")
    value = exact(
        value,
        {"directories", "phase", "records", "schema", "version"},
        "tracker state",
    )
    if (
        value["schema"] != SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or value["phase"] not in {"collecting", "structure_complete", "report_complete", "gates_complete"}
        or not isinstance(value["records"], dict)
        or not isinstance(value["directories"], dict)
        or raw != canonical_bytes(value)
    ):
        fail("tracker state identity differs")
    return value


def store_state(path, value, *, exclusive=False):
    raw = canonical_bytes(value)
    if exclusive:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as error:
            fail(f"cannot initialize tracker state: {error}")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return
    temporary = path.with_name(path.name + ".next")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        fail(f"cannot update tracker state: {error}")


if len(sys.argv) < 3:
    fail("internal invocation differs")
command = sys.argv[1]
state_path = pathlib.Path(sys.argv[2])
if command == "init":
    if len(sys.argv) != 3:
        fail("init arguments differ")
    store_state(
        state_path,
        {
            "schema": SCHEMA,
            "version": VERSION,
            "phase": "collecting",
            "records": {},
            "directories": {},
        },
        exclusive=True,
    )
elif command == "add":
    if len(sys.argv) < 4:
        fail("add requires at least one input")
    state = load_state(state_path)
    if state["phase"] != "collecting":
        fail("inputs cannot be added after structural validation")
    for path_text in sys.argv[3:]:
        record = observe(path_text)
        previous = state["records"].get(record["path"])
        if previous is not None and previous != record:
            fail(f"tracked input differs from its first read: {record['path']}")
        state["records"][record["path"]] = record
    store_state(state_path, state)
elif command == "add-dir":
    if len(sys.argv) < 4:
        fail("add-dir requires at least one input")
    state = load_state(state_path)
    if state["phase"] != "collecting":
        fail("directories cannot be added after structural validation")
    for path_text in sys.argv[3:]:
        record = observe_directory(path_text)
        previous = state["directories"].get(record["path"])
        if previous is not None and previous != record:
            fail(f"tracked directory differs from its first read: {record['path']}")
        state["directories"][record["path"]] = record
    store_state(state_path, state)
elif command in PHASES:
    if len(sys.argv) != 3:
        fail(f"{command} arguments differ")
    state = load_state(state_path)
    expected, replacement = PHASES[command]
    if state["phase"] != expected:
        fail(f"{command} is not valid during phase {state['phase']}")
    if not state["records"]:
        fail("tracker has no inputs")
    if command == "mark-structure" and not state["directories"]:
        fail("tracker has no pinned structural directory")
    state["phase"] = replacement
    store_state(state_path, state)
elif command == "verify":
    if len(sys.argv) != 3:
        fail("verify arguments differ")
    state = load_state(state_path)
    if state["phase"] != "gates_complete":
        fail("final verification is not immediately after both external gates")
    record_fields = {
        "path", "dev", "ino", "mode", "nlink", "size", "mtime_ns", "ctime_ns",
        "bytes", "sha256",
    }
    directory_fields = {
        "path", "dev", "ino", "mode", "nlink", "size", "mtime_ns", "ctime_ns",
        "entries", "entries_sha256",
    }
    for canonical_path, expected in sorted(state["records"].items()):
        exact(expected, record_fields, f"record for {canonical_path}")
        if expected["path"] != canonical_path:
            fail(f"record key/path differs: {canonical_path}")
        observed = observe(canonical_path)
        if observed != expected:
            fail(f"tracked input changed before PASS: {canonical_path}")
    for canonical_path, expected in sorted(state["directories"].items()):
        exact(expected, directory_fields, f"directory record for {canonical_path}")
        if expected["path"] != canonical_path:
            fail(f"directory record key/path differs: {canonical_path}")
        observed = observe_directory(canonical_path)
        if observed != expected:
            fail(f"tracked directory changed before PASS: {canonical_path}")
else:
    fail(f"unknown command: {command}")
PY
}

verify_c84_stability_selftest() (
  local selftest_dir input_dir state_dir artifact tool state
  selftest_dir=$(mktemp -d)
  trap 'rm -rf -- "$selftest_dir"' EXIT
  input_dir="$selftest_dir/inputs"
  state_dir="$selftest_dir/state"
  mkdir -- "$input_dir" "$state_dir"
  artifact="$input_dir/artifact.bin"
  tool="$input_dir/tool.bin"

  prepare_case() {
    local case_name=$1
    state="$state_dir/$case_name.json"
    python3 - "$artifact" "$tool" <<'PY'
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(b"artifact-v1\n")
pathlib.Path(sys.argv[2]).write_bytes(b"tool-v1\n")
PY
    c84_stability_tracker init "$state"
    c84_stability_tracker add "$state" "$artifact" "$tool"
    c84_stability_tracker add-dir "$state" "$input_dir" "$input_dir/.."
    python3 - "$artifact" <<'PY'
import pathlib
import sys
if pathlib.Path(sys.argv[1]).read_bytes() != b"artifact-v1\n":
    raise SystemExit("structure fixture differs")
PY
    c84_stability_tracker mark-structure "$state"
  }

  expect_stability_rejection() {
    local label=$1
    if c84_stability_tracker verify "$state" >/dev/null 2>&1; then
      echo "verify-milkv-duo-image.sh: stability selftest '$label' was accepted" >&2
      return 1
    fi
  }

  prepare_case positive
  c84_stability_tracker mark-report "$state"
  c84_stability_tracker mark-gates "$state"
  c84_stability_tracker verify "$state"

  prepare_case structure-artifact-inode-swap
  python3 - "$artifact" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
replacement = path.with_name(path.name + ".replacement")
replacement.write_bytes(path.read_bytes())
os.replace(replacement, path)
PY
  c84_stability_tracker mark-report "$state"
  c84_stability_tracker mark-gates "$state"
  expect_stability_rejection structure-artifact-inode-swap

  prepare_case structure-tool-byte-mutation
  python3 - "$tool" <<'PY'
import pathlib
import sys
with pathlib.Path(sys.argv[1]).open("ab") as stream:
    stream.write(b"mutated")
PY
  c84_stability_tracker mark-report "$state"
  c84_stability_tracker mark-gates "$state"
  expect_stability_rejection structure-tool-byte-mutation

  prepare_case post-gate-artifact-mutation
  c84_stability_tracker mark-report "$state"
  python3 - "$artifact" "$tool" <<'PY'
import pathlib
import sys
# These reads model the two external source/runtime gates completing.
for name in sys.argv[1:]:
    pathlib.Path(name).read_bytes()
PY
  c84_stability_tracker mark-gates "$state"
  python3 - "$artifact" <<'PY'
import pathlib
import sys
with pathlib.Path(sys.argv[1]).open("r+b") as stream:
    stream.seek(0)
    stream.write(b"X")
PY
  expect_stability_rejection post-gate-artifact-mutation

  prepare_case structure-directory-swap-use-restore
  python3 - "$input_dir" <<'PY'
import os
import pathlib
import shutil
import sys

original = pathlib.Path(sys.argv[1])
saved = original.with_name(original.name + ".saved")
os.rename(original, saved)
original.mkdir()
(original / "artifact.bin").write_bytes(b"structurally-valid-substitute\n")
(original / "tool.bin").write_bytes(b"tool-substitute\n")
if (original / "artifact.bin").read_bytes() != b"structurally-valid-substitute\n":
    raise SystemExit("directory-swap fixture differs")
shutil.rmtree(original)
os.rename(saved, original)
PY
  c84_stability_tracker mark-report "$state"
  c84_stability_tracker mark-gates "$state"
  expect_stability_rejection structure-directory-swap-use-restore

  echo "verify-milkv-duo-image.sh C8.4 global stability selftest: PASS (4 TOCTOU negative cases)"
)

select_c84_runtime_attestations() {
  local admission_package_preflight=$1 admission_repo_root=$2
  c84_runtime_attestation="$admission_repo_root/target/milkv-duo-wasm-aot-profile/container-runtime-attestation.json"
  case "$admission_package_preflight" in
    true)
      c84_admission_runtime_attestation="$admission_repo_root/target/milkv-duo-wasm-aot-profile/container-runtime-attestation.json"
      c84_admission_runtime_mode=package
      ;;
    false)
      c84_admission_runtime_attestation="$admission_repo_root/target/milkv-duo-wasm-aot-profile/container-runtime-verifier-attestation.json"
      c84_admission_runtime_mode=verify
      ;;
    *)
      echo "verify-milkv-duo-image.sh: internal C8.4 package-preflight mode differs" >&2
      return 2
      ;;
  esac
  c84_runtime_gate_attestations=(
    "$c84_admission_runtime_attestation"
    "$c84_runtime_attestation"
  )
  c84_runtime_gate_modes=("$c84_admission_runtime_mode" package)
}

verify_c84_runtime_attestation_selection_selftest() {
  local fixture_root=/home/vibeos
  select_c84_runtime_attestations true "$fixture_root"
  [[ "$c84_admission_runtime_attestation" == \
      "$fixture_root/target/milkv-duo-wasm-aot-profile/container-runtime-attestation.json" &&
     "$c84_admission_runtime_mode" == package &&
     ${#c84_runtime_gate_attestations[@]} -eq 2 &&
     "${c84_runtime_gate_attestations[0]}" == "$c84_runtime_attestation" &&
     "${c84_runtime_gate_attestations[1]}" == "$c84_runtime_attestation" &&
     "${c84_runtime_gate_modes[0]}" == package &&
     "${c84_runtime_gate_modes[1]}" == package ]] || {
    echo "verify-milkv-duo-image.sh: package admission selection selftest failed" >&2
    return 1
  }
  select_c84_runtime_attestations false "$fixture_root"
  [[ "$c84_admission_runtime_attestation" == \
      "$fixture_root/target/milkv-duo-wasm-aot-profile/container-runtime-verifier-attestation.json" &&
     "$c84_admission_runtime_mode" == verify &&
     ${#c84_runtime_gate_attestations[@]} -eq 2 &&
     "${c84_runtime_gate_attestations[0]}" == "$c84_admission_runtime_attestation" &&
     "${c84_runtime_gate_attestations[1]}" == "$c84_runtime_attestation" &&
     "${c84_runtime_gate_modes[0]}" == verify &&
     "${c84_runtime_gate_modes[1]}" == package ]] || {
    echo "verify-milkv-duo-image.sh: verifier admission selection selftest failed" >&2
    return 1
  }
  if select_c84_runtime_attestations invalid "$fixture_root" >/dev/null 2>&1; then
    echo "verify-milkv-duo-image.sh: invalid admission selection selftest was accepted" >&2
    return 1
  fi
  echo "verify-milkv-duo-image.sh C8.4 runtime attestation gate selection selftest: PASS"
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
package_preflight=false
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
    --package-preflight) package_preflight=true ;;
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
  if ((mode_count != 0)) || [[ -n "$sdk_arg" || -n "$artifact_root_arg" || "$package_preflight" == true ]]; then
    echo "verify-milkv-duo-image.sh: --selftest does not accept an SDK root or image mode" >&2
    usage
    exit 2
  fi
  command -v python3 >/dev/null || {
    echo "verify-milkv-duo-image.sh: required tool is missing: python3" >&2
    exit 1
  }
  verify_raw_data_partition --selftest
  verify_c84_stability_selftest
  verify_c84_runtime_attestation_selection_selftest
  verify_c84_provenance_selftest "$0"
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
if [[ "$package_preflight" == true ]] &&
   { [[ "$wasm_aot_profile" != true ]] || [[ -z "$artifact_root_arg" ]]; }; then
  echo "verify-milkv-duo-image.sh: --package-preflight requires --wasm-aot-profile and --artifact-root" >&2
  usage
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
sdk_root=$(cd -- "$sdk_arg" && pwd -P)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
if [[ "$wasm_aot_profile" == true ]]; then
  for c84_git_environment_name in ${!GIT_@}; do
    unset "$c84_git_environment_name"
  done
  c84_docker_git_config=/etc/vibeos-c84.gitconfig
  c84_docker_git_config_template="$script_dir/c84-docker.gitconfig"
  c84_stability_state="$temp_dir/c84-global-stability.json"
  if [[ "$repo_root" != /home/vibeos || "$sdk_root" != /home/work ]]; then
    echo "verify-milkv-duo-image.sh: C8.4 requires source /home/vibeos and SDK /home/work inside the pinned container" >&2
    exit 2
  fi
  command -v python3 >/dev/null || {
    echo "verify-milkv-duo-image.sh: required C8.4 tool is missing: python3" >&2
    exit 1
  }
  c84_stability_tracker init "$c84_stability_state"
  c84_stability_tracker add "$c84_stability_state" \
    "$c84_docker_git_config_template" "$c84_docker_git_config" \
    "$(command -v python3)"
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
  wasm_aot_profile_container_digest_pin=${VIBEOS_C84_SDK_CONTAINER_DIGEST-}
  require_wasm_aot_profile_identity VIBEOS_C84_SOURCE_COMMIT \
    "$wasm_aot_profile_source_commit" 40 \
    0000000000000000000000000000000000000000 \
    1111111111111111111111111111111111111111
  require_wasm_aot_profile_identity VIBEOS_C84_CHALLENGE \
    "$wasm_aot_profile_challenge" 64 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    2222222222222222222222222222222222222222222222222222222222222222
  c84_source_materializer="$script_dir/c84-source-materialization.py"
  c84_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge/source-materialization-envelope.json"
  c84_docker_runtime="$script_dir/c84-docker-runtime.py"
  # The package attestation remains the evidence/report provenance root.  The
  # admission attestation instead belongs to whichever guest is executing this
  # verifier: package during preflight, verify during the independent pass.
  # Every gate fully verifies both roles; in preflight they intentionally name
  # the same package attestation.
  select_c84_runtime_attestations "$package_preflight" "$repo_root"
  verify_c84_frozen_source() {
    python3 -B "$c84_source_materializer" verify \
      --destination "$repo_root" \
      --source-commit "$wasm_aot_profile_source_commit" \
      --challenge "$wasm_aot_profile_challenge" \
      --container-mounted-read-only
  }
  verify_c84_runtime_attestations() {
    local gate_index
    if [[ ${#c84_runtime_gate_attestations[@]} -ne 2 ||
          ${#c84_runtime_gate_modes[@]} -ne 2 ]]; then
      echo "verify-milkv-duo-image.sh: internal C8.4 runtime attestation gate set differs" >&2
      return 2
    fi
    for gate_index in "${!c84_runtime_gate_attestations[@]}"; do
      python3 -B "$c84_docker_runtime" verify-attestation \
        --attestation "${c84_runtime_gate_attestations[$gate_index]}" \
        --source-root "$repo_root" \
        --source-commit "$wasm_aot_profile_source_commit" \
        --challenge "$wasm_aot_profile_challenge" \
        --expect-mode "${c84_runtime_gate_modes[$gate_index]}"
    done
  }
  c84_stability_tracker add "$c84_stability_state" \
    "$c84_source_envelope" "$c84_runtime_attestation" \
    "$c84_admission_runtime_attestation" \
    "$c84_source_materializer" "$c84_docker_runtime" \
    "$script_dir/package-milkv-duo-sdk.sh" \
    "$script_dir/verify-milkv-duo-image.sh" \
    "$script_dir/build-milkv-duo.sh" \
    "$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch" \
    "$repo_root/.gitmodules" \
    "$script_dir/milkv-duo.its" \
    "$script_dir/milkv-duo-genimage.cfg" \
    "$repo_root/benchmarks/wasm-aot-decision/workloads-v1.json" \
    "$repo_root/benchmarks/wasm-aot-decision/schema-v1.json" \
    "$repo_root/rust-toolchain.toml" \
    "$script_dir/verify-c84-aot-decision.py" \
    "$repo_root/firmware/milkv-duo/Cargo.toml" \
    "$repo_root/firmware/milkv-duo/build.rs" \
    "$repo_root/firmware/milkv-duo/linker.ld" \
    "$repo_root/firmware/.cargo/config.toml" \
    "$repo_root/kernel/Cargo.toml" \
    "$repo_root/Cargo.toml" \
    "$repo_root/Cargo.lock"
  verify_c84_runtime_attestations
  verify_c84_frozen_source
  if [[ "$wasm_aot_profile_container_digest_pin" != "$wasm_aot_profile_sdk_container_digest" ]]; then
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
  if ! sdk_status=$(git --no-optional-locks -c core.fsmonitor=false -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    echo "verify-milkv-duo-image.sh: cannot read WebAssembly AOT profile SDK status" >&2
    exit 1
  fi
  if [[ -n "$sdk_status" ]]; then
    echo "verify-milkv-duo-image.sh: WebAssembly AOT profile SDK checkout is not clean" >&2
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
if [[ "$wasm_aot_profile" == true ]]; then
  c84_package_envelope="$output_dir/package-envelope.json"
  if [[ "$package_preflight" == true ]]; then
    c84_stage_name=$(basename -- "$output_dir")
    if [[ $(cd -- "$output_dir/.." && pwd -P) != "$repo_root/target" ]] ||
       [[ ! "$c84_stage_name" =~ ^\.milkv-duo-wasm-aot-profile-package\.[[:alnum:]]{6,}$ ]]; then
      echo "verify-milkv-duo-image.sh: --package-preflight artifact root is not a fixed C8.4 package staging directory" >&2
      exit 2
    fi
    if [[ -e "$c84_package_envelope" || -L "$c84_package_envelope" ]]; then
      echo "verify-milkv-duo-image.sh: --package-preflight requires the package envelope to be absent" >&2
      exit 1
    fi
    c84_build_envelope="$repo_root/target/milkv-duo-wasm-aot-profile/build-envelope.json"
  else
    c84_build_envelope="$output_dir/build-envelope.json"
    if [[ ! -f "$c84_package_envelope" || -L "$c84_package_envelope" ]]; then
      echo "verify-milkv-duo-image.sh: final C8.4 verification requires a regular package-envelope.json" >&2
      exit 1
    fi
  fi
  if [[ ! -f "$c84_build_envelope" || -L "$c84_build_envelope" ]]; then
    echo "verify-milkv-duo-image.sh: C8.4 verification requires a regular build-envelope.json" >&2
    exit 1
  fi
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
mdir_tool=$(command -v mdir)
mcopy_tool=$(command -v mcopy)
cmp_tool=$(command -v cmp)
sha256sum_tool=$(command -v sha256sum)
fdtget_tool=$(command -v fdtget)
python3_tool=$(command -v python3)
tr_tool=$(command -v tr)
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
  c84_kernel_elf="$repo_root/target/milkv-duo-wasm-aot-profile/vibeos-milkv-duo-wasm-aot-profile.elf"
  c84_genimage="$sdk_root/buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage"
  if [[ ! -f "$c84_genimage" ]]; then
    c84_genimage="$sdk_root/buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/per-package/host-genimage/host/bin/genimage"
  fi
  c84_tracker_inputs=(
    "$image" "$expected_fit" "$expected_kernel" "$expected_its" "$packaged_dtb"
    "$expected_dtb" "$expected_fip" "$c84_kernel_elf" "$c84_build_envelope"
    "$mkimage" "$dumpimage" "$c84_genimage"
    "$mdir_tool" "$mcopy_tool" "$cmp_tool" "$sha256sum_tool" "$fdtget_tool"
    "$python3_tool" "$tr_tool"
    "$c84_source_envelope" "$c84_runtime_attestation"
    "$c84_admission_runtime_attestation"
    "$c84_docker_git_config" "$c84_docker_git_config_template"
    "$script_dir/package-milkv-duo-sdk.sh"
    "$script_dir/verify-milkv-duo-image.sh"
    "$script_dir/build-milkv-duo.sh"
    "$c84_source_materializer" "$c84_docker_runtime"
    "$repo_root/patches/jitterentropy-rs/0001-vibeos-qualification.patch"
    "$repo_root/.gitmodules"
    "$script_dir/milkv-duo.its"
    "$script_dir/milkv-duo-genimage.cfg"
    "$repo_root/benchmarks/wasm-aot-decision/workloads-v1.json"
    "$repo_root/benchmarks/wasm-aot-decision/schema-v1.json"
    "$repo_root/rust-toolchain.toml"
    "$script_dir/verify-c84-aot-decision.py"
    "$repo_root/firmware/milkv-duo/Cargo.toml"
    "$repo_root/firmware/milkv-duo/build.rs"
    "$repo_root/firmware/milkv-duo/linker.ld"
    "$repo_root/firmware/.cargo/config.toml"
    "$repo_root/kernel/Cargo.toml"
    "$repo_root/Cargo.toml"
    "$repo_root/Cargo.lock"
  )
  if [[ "$package_preflight" != true ]]; then
    c84_tracker_inputs+=("$c84_package_envelope" "$output_dir/image-verifier-audit.log")
  fi
  c84_stability_tracker add "$c84_stability_state" "${c84_tracker_inputs[@]}"
  # The nested target bind is intentionally writable during packaging.  Pin
  # its artifact directory as well as the files so a whole-directory
  # swap/use/restore cannot present one tree to structure checks and another
  # to the provenance closure before restoring the original file inodes.
  c84_stability_tracker add-dir \
    "$c84_stability_state" "$output_dir" "$output_dir/.."
  unset c84_tracker_inputs
  cmp -s "$expected_its" "$script_dir/milkv-duo.its" ||
    die "packaged FIT source differs from the repository recipe"
  cmp -s "$packaged_dtb" "$expected_dtb" ||
    die "packaged DTB differs from the SDK Linux DTB"
fi

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
if [[ "$wasm_aot_profile" == true ]]; then
  c84_stability_tracker add "$c84_stability_state" \
    "$temp_dir/fat-boot.sd" "$temp_dir/fat-fip.bin"
fi

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
if [[ "$wasm_aot_profile" == true ]]; then
  c84_stability_tracker add "$c84_stability_state" \
    "$temp_dir/kernel.bin" "$temp_dir/fdt.dtb"
fi
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
  c84_stability_tracker mark-structure "$c84_stability_state"
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
     ! sdk_status_after=$(git --no-optional-locks -c core.fsmonitor=false -C "$sdk_root" status --porcelain=v1 --untracked-files=all --ignore-submodules=none); then
    die "cannot recheck C8.4 SDK checkout"
  fi
  if [[ "$sdk_head_after" != "$wasm_aot_profile_sdk_commit" || -n "$sdk_status_after" ]]; then
    die "C8.4 SDK checkout changed during image verification"
  fi
  verify_c84_runtime_attestations >/dev/null
  python3 - \
    "$wasm_aot_profile_source_commit" "$wasm_aot_profile_challenge" \
    "$package_preflight" "$c84_source_envelope" "$c84_runtime_attestation" \
    "$c84_build_envelope" "$c84_package_envelope" "$sdk_root" \
    "$expected_kernel" "$expected_its" "$packaged_dtb" "$expected_dtb" \
    "$expected_fit" "$image" "$expected_fip" \
    "$mkimage" "$dumpimage" "$c84_docker_git_config" \
    "$c84_source_materializer" "$c84_docker_runtime" \
    "$mdir_tool" "$mcopy_tool" "$cmp_tool" "$sha256sum_tool" \
    "$fdtget_tool" "$python3_tool" "$tr_tool" <<'PY'
# C84_PROVENANCE_VALIDATOR_BEGIN
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile

artifact_names = (
    "kernel_binary", "fit_source", "packaged_dtb", "sdk_dtb",
    "fit_boot_sd", "full_sd_image", "sdk_fip",
)
tool_names = (
    "sdk_mkimage", "sdk_dumpimage", "git_config", "source_materializer_script",
    "docker_runtime_script", "mdir", "mcopy", "cmp", "sha256sum", "fdtget",
    "python3", "tr",
)
semantic_selftest = sys.argv[1:] == ["--selftest"]
if semantic_selftest:
    source_commit = "a" * 40
    challenge = "b" * 64
    package_preflight = "false"
    source_envelope_path = runtime_attestation_path = None
    build_envelope_path = package_envelope_path = sdk_root_path = None
    artifact_paths = []
    tool_paths = []
else:
    source_commit, challenge, package_preflight = sys.argv[1:4]
    source_envelope_path = pathlib.Path(sys.argv[4])
    runtime_attestation_path = pathlib.Path(sys.argv[5])
    build_envelope_path = pathlib.Path(sys.argv[6])
    package_envelope_path = pathlib.Path(sys.argv[7])
    sdk_root_path = pathlib.Path(sys.argv[8]).resolve(strict=True)
    artifact_paths = sys.argv[9:16]
    tool_paths = sys.argv[16:28]
    if len(artifact_paths) != len(artifact_names) or len(tool_paths) != len(tool_names):
        raise SystemExit("verify-milkv-duo-image.sh: canonical report arguments differ")
    if package_preflight not in {"true", "false"}:
        raise SystemExit("verify-milkv-duo-image.sh: package verification phase differs")


def fail(message):
    raise SystemExit(f"verify-milkv-duo-image.sh: C8.4 provenance closure failed: {message}")


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields are not closed")
    return value


snapshots = {}


def stable_regular(path, label, *, maximum=33_554_432, single_link=False):
    try:
        before_lstat = path.lstat()
        if stat.S_ISLNK(before_lstat.st_mode) or not stat.S_ISREG(before_lstat.st_mode):
            fail(f"{label} is not a regular non-symlink file")
        before = path.stat()
        if before.st_size <= 0 or before.st_size > maximum:
            fail(f"{label} size is outside its closed bound")
        if single_link and before.st_nlink != 1:
            fail(f"{label} is hardlinked")
        raw = path.read_bytes()
        after = path.stat()
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        fail(f"{label} changed while reading")
    if len(raw) != before.st_size:
        fail(f"{label} was truncated while reading")
    snapshots[label] = (path, before)
    return raw


def load_envelope(path, label, schema, version, *, canonical_root=False, maximum=None):
    if maximum is None:
        maximum = 16_777_216 if canonical_root else 33_554_432
    raw = stable_regular(
        path,
        label,
        maximum=maximum,
        single_link=canonical_root,
    )
    try:
        root = json.loads(raw, object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {label}: {error}")
    root = exact(
        root,
        {"content", "content_sha256", "schema", "status", "version"},
        label,
    )
    if (
        root["schema"] != schema
        or type(root["version"]) is not int
        or root["version"] != version
        or root["status"] != "closed"
    ):
        fail(f"{label} identity/status differs")
    content = root.get("content")
    digest = root.get("content_sha256")
    canonical_content = json.dumps(
        content, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if (
        not isinstance(content, dict)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or hashlib.sha256(canonical_content).hexdigest() != digest
    ):
        fail(f"{label} content address differs")
    if canonical_root:
        canonical = json.dumps(
            root, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        if raw != canonical:
            fail(f"{label} is not canonical JSON")
    return root


def validate_source_materialization(root):
    content = exact(
        root["content"],
        {
            "bundles", "challenge", "clone_git_admin", "command", "frozen", "git",
            "independence", "materialization", "patch", "snapshot", "source",
            "source_commit", "submodules", "timestamps_utc",
        },
        "source materialization content",
    )
    if content["source_commit"] != source_commit or content["challenge"] != challenge:
        fail("source materialization campaign identity differs")
    return root


def validate_runtime_attestation(root, live_source):
    content = exact(
        root["content"],
        {
            "capability", "challenge", "host_preinspect", "host_preinspect_identity",
            "mode", "source_commit", "source_materialization_content_sha256", "witness",
        },
        "runtime attestation content",
    )
    capability = "host Docker daemon inspect plus in-container namespace witness; software custody only"
    if (
        content["capability"] != capability
        or content["source_commit"] != source_commit
        or content["challenge"] != challenge
        or content["mode"] != "package"
        or content["source_materialization_content_sha256"] != live_source["content_sha256"]
    ):
        fail("runtime attestation identity differs")
    preinspect = exact(
        content["host_preinspect"],
        {"content", "content_sha256", "schema", "status", "version"},
        "host preinspect",
    )
    pre_content = exact(
        preinspect["content"],
        {
            "challenge", "container_preinspect", "contract", "image_inspect", "mode",
            "sdk_volume_inspect", "source_commit",
        },
        "host preinspect content",
    )
    canonical_pre_content = json.dumps(
        pre_content, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if (
        preinspect["schema"] != "vibeos.c84.docker-host-preinspect"
        or type(preinspect["version"]) is not int
        or preinspect["version"] != 1
        or preinspect["status"] != "closed"
        or pre_content["source_commit"] != source_commit
        or pre_content["challenge"] != challenge
        or pre_content["mode"] != "package"
        or not isinstance(preinspect["content_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", preinspect["content_sha256"]) is None
        or hashlib.sha256(canonical_pre_content).hexdigest() != preinspect["content_sha256"]
    ):
        fail("host preinspect identity/content address differs")
    pre_raw = json.dumps(preinspect, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if content["host_preinspect_identity"] != {
        "bytes": len(pre_raw), "sha256": hashlib.sha256(pre_raw).hexdigest(),
    }:
        fail("host preinspect file identity differs")
    image = pre_content["image_inspect"]
    contract = exact(
        pre_content["contract"],
        {
            "capability", "command", "create_argv", "environment", "gid",
            "image_digest", "image_reference", "mounts", "network", "platform",
            "supplementary_groups", "uid",
        },
        "runtime contract",
    )
    image_id = image.get("Id") if isinstance(image, dict) else None
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        or contract.get("capability") != capability
        or contract.get("image_digest") != "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679"
        or contract.get("platform") != "linux/amd64"
    ):
        fail("runtime image custody differs")
    mounts = contract["mounts"]
    if not isinstance(mounts, list) or len(mounts) != 5:
        fail("runtime mount contract differs")
    mount_map = {}
    for value in mounts:
        record = exact(
            value,
            {"destination", "kind", "read_only", "source"},
            "runtime mount record",
        )
        destination = record["destination"]
        if not isinstance(destination, str) or destination in mount_map:
            fail("runtime mount destinations differ")
        mount_map[destination] = record
    expected_destinations = {
        "/etc/vibeos-c84.gitconfig",
        "/home/vibeos",
        "/home/vibeos/target",
        "/home/work",
        "/run/vibeos-c84-host",
    }
    if set(mount_map) != expected_destinations:
        fail("runtime mount destinations differ")
    source_mount = mount_map["/home/vibeos"]
    host_source_text = source_mount["source"]
    if not isinstance(host_source_text, str):
        fail("runtime host source path is malformed")
    host_source_root = pathlib.PurePath(host_source_text)
    if (
        source_mount != {
            "destination": "/home/vibeos",
            "kind": "bind",
            "read_only": True,
            "source": host_source_text,
        }
        or not host_source_root.is_absolute()
        or str(host_source_root) != host_source_text
        or mount_map["/home/vibeos/target"]
        != {
            "destination": "/home/vibeos/target",
            "kind": "bind",
            "read_only": False,
            "source": str(host_source_root / "target"),
        }
        or mount_map["/etc/vibeos-c84.gitconfig"]
        != {
            "destination": "/etc/vibeos-c84.gitconfig",
            "kind": "bind",
            "read_only": True,
            "source": str(host_source_root / "scripts" / "c84-docker.gitconfig"),
        }
    ):
        fail("runtime host source bindings differ")
    return image_id, host_source_root


def identity_record(value, label, *, expected_path=None):
    record = exact(value, {"path", "sha256", "bytes"}, label)
    if (
        not isinstance(record["path"], str)
        or not isinstance(record["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or type(record["bytes"]) is not int
        or record["bytes"] <= 0
    ):
        fail(f"{label} identity differs")
    if expected_path is not None and record["path"] != expected_path:
        fail(
            f"{label} path differs: {record['path']!r} != {expected_path!r}"
        )
    return record


PASS_MARKER = (
    "PASS: C8.4 FAT boot + raw data MBR image, FIP, FIT metadata, "
    "kernel/DTB payloads, and CRC32 hashes are valid"
)
BUILD_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.build-envelope"
PACKAGE_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.package-envelope"
REPORT_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.image-audit-report"
FIXED_VERIFIER_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
BUILD_TOOL_LOGICAL_PATHS = {
    "build_script": "scripts/build-milkv-duo.sh",
    "source_materializer_script": "scripts/c84-source-materialization.py",
    "jitterentropy_patch": "patches/jitterentropy-rs/0001-vibeos-qualification.patch",
    "gitmodules": ".gitmodules",
    "firmware_manifest": "firmware/milkv-duo/Cargo.toml",
    "firmware_build_script": "firmware/milkv-duo/build.rs",
    "firmware_linker_script": "firmware/milkv-duo/linker.ld",
    "firmware_cargo_config": "firmware/.cargo/config.toml",
    "kernel_manifest": "kernel/Cargo.toml",
    "workspace_manifest": "Cargo.toml",
    "cargo_lock": "Cargo.lock",
    "workload_manifest": "benchmarks/wasm-aot-decision/workloads-v1.json",
    "transcript_schema": "benchmarks/wasm-aot-decision/schema-v1.json",
    "toolchain_contract": "rust-toolchain.toml",
}
PACKAGE_ARTIFACT_FILENAMES = {
    "kernel_elf": "vibeos-milkv-duo-wasm-aot-profile.elf",
    "kernel_binary": "vibeos-milkv-duo.bin",
    "packaged_fit_source": "milkv-duo.its",
    "packaged_dtb": "cv1800b_milkv_duo_sd.dtb",
    "fit_boot_sd": "boot.sd",
    "full_sd_image": "vibeos-milkv-duo-wasm-aot-profile-sd.img",
}
REPORT_ARTIFACT_ROLES = {
    "kernel_binary": "kernel_binary",
    "fit_source": "packaged_fit_source",
    "packaged_dtb": "packaged_dtb",
    "sdk_dtb": "sdk_dtb",
    "fit_boot_sd": "fit_boot_sd",
    "full_sd_image": "full_sd_image",
    "sdk_fip": "sdk_fip",
}
REPORT_TOOL_ROLES = {
    "sdk_mkimage": "sdk_mkimage",
    "sdk_dumpimage": "sdk_dumpimage",
    "git_config": "docker_git_config",
    "source_materializer_script": "source_materializer_script",
    "docker_runtime_script": "docker_runtime_script",
    "mdir": "verifier_mdir",
    "mcopy": "verifier_mcopy",
    "cmp": "verifier_cmp",
    "sha256sum": "verifier_sha256sum",
    "fdtget": "verifier_fdtget",
    "python3": "verifier_python3",
    "tr": "verifier_tr",
}


def contains_old_provenance(value):
    if isinstance(value, str):
        return (
            "operator-declared" in value
            or "runtime container identity not attested" in value
        )
    if isinstance(value, list):
        return any(contains_old_provenance(item) for item in value)
    if isinstance(value, dict):
        if set(value) & {"declared_container_digest", "container_digest_provenance"}:
            return True
        return any(contains_old_provenance(item) for item in value.values())
    return False


def validate_root_object(root, schema, version, label):
    root = exact(
        root,
        {"content", "content_sha256", "schema", "status", "version"},
        label,
    )
    content = root["content"]
    digest = root["content_sha256"]
    if (
        root["schema"] != schema
        or type(root["version"]) is not int
        or root["version"] != version
        or root["status"] != "closed"
        or not isinstance(content, dict)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest() != digest
    ):
        fail(f"{label} identity/content address differs")
    return root


def measurement_record(value, label):
    record = exact(value, {"sha256", "bytes"}, label)
    if (
        not isinstance(record["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or type(record["bytes"]) is not int
        or record["bytes"] <= 0
    ):
        fail(f"{label} measurement differs")
    return record


def measure_file(path, label, *, scan=False, reject_symlink=True):
    supplied = pathlib.Path(path)
    try:
        supplied_lstat = supplied.lstat()
        if reject_symlink and stat.S_ISLNK(supplied_lstat.st_mode):
            fail(f"{label} is a symlink")
        resolved = supplied.resolve(strict=True)
        before = resolved.stat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"{label} is not a non-empty regular file")
    digest = hashlib.sha256()
    needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
    found = [False, False]
    overlap = max(map(len, needles)) - 1
    tail = b""
    with resolved.open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            digest.update(chunk)
            if scan:
                window = tail + chunk
                found = [seen or needle in window for seen, needle in zip(found, needles)]
                tail = window[-overlap:]
    after = resolved.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        fail(f"{label} changed while hashing")
    if scan and not all(found):
        fail(f"{label} does not embed source/challenge")
    snapshots[f"measured {label}"] = (resolved, before)
    return {"sha256": digest.hexdigest(), "bytes": before.st_size}


def validate_live_identity(
    value,
    label,
    *,
    expected_path,
    live_path,
    scan=False,
    reject_symlink=True,
):
    record = identity_record(value, label, expected_path=str(expected_path))
    observed = measure_file(
        live_path,
        label,
        scan=scan,
        reject_symlink=reject_symlink,
    )
    if {"sha256": record["sha256"], "bytes": record["bytes"]} != observed:
        fail(f"{label} live bytes differ")
    return record


def validate_utc_chain(value, names, label):
    timestamps = exact(value, set(names), label)
    parsed = []
    for name in names:
        item = timestamps[name]
        if not isinstance(item, str) or not item.endswith("Z"):
            fail(f"{label}.{name} is not UTC")
        try:
            parsed.append(datetime.datetime.fromisoformat(item[:-1] + "+00:00"))
        except ValueError as error:
            fail(f"{label}.{name} is invalid: {error}")
    if parsed != sorted(parsed):
        fail(f"{label} values are reversed")
    return timestamps


def validate_build_deep(root, live_source, source_root, host_source_root):
    root = validate_root_object(root, BUILD_SCHEMA, 2, "build envelope")
    if contains_old_provenance(root):
        fail("build envelope contains old provenance")
    content = exact(
        root["content"],
        {
            "platform", "source_commit", "challenge", "run_id", "source", "command",
            "objcopy_command", "objcopy_environment", "environment", "toolchain",
            "artifacts", "tools", "timestamps_utc",
        },
        "build content",
    )
    if (
        content["platform"] != "milkv-duo-cv1800b"
        or content["source_commit"] != source_commit
        or content["challenge"] != challenge
    ):
        fail("build campaign identity differs")
    source = exact(content["source"], {"root", "head", "materialization"}, "build source")
    if source != {"root": ".", "head": source_commit, "materialization": live_source}:
        fail("build frozen-source proof differs")

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
        record = identity_record(toolchain[name], f"build toolchain.{name}")
        if not pathlib.PurePath(record["path"]).is_absolute():
            fail(f"build toolchain.{name} path is not absolute")
    contract_path = pathlib.Path(source_root) / BUILD_TOOL_LOGICAL_PATHS["toolchain_contract"]
    try:
        contract_text = contract_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot read toolchain contract: {error}")
    channel_match = re.search(r'^channel = "([^"]+)"$', contract_text, re.MULTILINE)
    rustc_match = re.search(r"^# rustc (.+)$", contract_text, re.MULTILINE)
    commit_match = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", contract_text, re.MULTILINE)
    verbose_lines = toolchain["rustc_verbose"].splitlines() if isinstance(toolchain["rustc_verbose"], str) else []
    verbose_fields = {
        key: value
        for line in verbose_lines[1:]
        if ": " in line
        for key, value in [line.split(": ", 1)]
    }
    if (
        channel_match is None
        or rustc_match is None
        or commit_match is None
        or toolchain["channel"] != channel_match.group(1)
        or not verbose_lines
        or verbose_lines[0] != f"rustc {rustc_match.group(1)}"
        or f"commit-hash: {commit_match.group(1)}" not in verbose_lines
        or not isinstance(verbose_fields.get("host"), str)
        or not verbose_fields["host"]
    ):
        fail("build toolchain pin differs")
    rustc_path = pathlib.PurePath(toolchain["rustc"]["path"])
    toolchain_bin = rustc_path.parent
    expected_tool_paths = {
        "cargo": toolchain_bin / "cargo",
        "rustc": toolchain_bin / "rustc",
        "rustdoc": toolchain_bin / "rustdoc",
        "rust_objcopy": (
            toolchain_bin.parent
            / "lib"
            / "rustlib"
            / verbose_fields["host"]
            / "bin"
            / "rust-objcopy"
        ),
    }
    if any(
        pathlib.PurePath(toolchain[name]["path"]) != expected
        for name, expected in expected_tool_paths.items()
    ):
        fail("build toolchain executable paths differ")
    expected_command = [
        toolchain["rustup"]["path"], "run", toolchain["channel"], "cargo", "build",
        "--release", "--locked", "--offline", "--no-default-features", "--features",
        "wasm-c84-ssh-managed-child-single-boot-collector",
    ]
    if content["command"] != expected_command:
        fail("build command differs")

    stage_root = (
        pathlib.PurePosixPath("target")
        / f".milkv-duo-wasm-aot-profile.stage.{source_commit}.{challenge}"
    )
    canonical_output = pathlib.Path(source_root) / "target" / "milkv-duo-wasm-aot-profile"
    artifact_specs = {
        "kernel_elf": (
            stage_root / "vibeos-milkv-duo-wasm-aot-profile.elf",
            canonical_output / "vibeos-milkv-duo-wasm-aot-profile.elf",
        ),
        "kernel_binary": (
            stage_root / "vibeos-milkv-duo.bin",
            canonical_output / "vibeos-milkv-duo.bin",
        ),
    }
    artifacts = exact(content["artifacts"], set(artifact_specs), "build artifacts")
    artifact_records = {}
    for name, (logical_path, live_path) in artifact_specs.items():
        artifact_records[name] = validate_live_identity(
            artifacts[name],
            f"build artifacts.{name}",
            expected_path=str(logical_path),
            live_path=live_path,
            scan=True,
        )
    expected_objcopy = [
        toolchain["rust_objcopy"]["path"], "-O", "binary",
        artifact_records["kernel_elf"]["path"],
        artifact_records["kernel_binary"]["path"],
    ]
    if content["objcopy_command"] != expected_objcopy:
        fail("build objcopy command differs")
    objcopy = exact(
        content["objcopy_environment"],
        {"mode", "allowed_keys", "values"},
        "build objcopy environment",
    )
    linux_objcopy = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}
    if objcopy["mode"] != "env -i":
        fail("build objcopy environment mode differs")
    if objcopy["allowed_keys"] == ["LC_ALL", "PATH", "TZ"]:
        if objcopy["values"] != linux_objcopy:
            fail("build objcopy environment values differ")
    elif objcopy["allowed_keys"] == ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"]:
        values = exact(
            objcopy["values"],
            {"DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"},
            "build Darwin objcopy values",
        )
        dyld = values["DYLD_LIBRARY_PATH"]
        if (
            values["LC_ALL"] != "C"
            or values["PATH"] != "/usr/bin:/bin"
            or values["TZ"] != "UTC"
            or not isinstance(dyld, str)
            or dyld
            != str(
                pathlib.PurePath(toolchain["rustc"]["path"]).parent.parent / "lib"
            )
        ):
            fail("build Darwin objcopy environment values differ")
    else:
        fail("build objcopy environment allowlist differs")

    expected_keys = [
        "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR",
        "HOME", "LC_ALL", "PATH", "RUSTC", "RUSTDOC", "RUSTUP_HOME",
        "SOURCE_DATE_EPOCH", "TMPDIR", "TZ", "VIBEOS_C84_CHALLENGE",
        "VIBEOS_C84_SOURCE_COMMIT",
    ]
    environment = exact(
        content["environment"],
        {"mode", "allowed_keys", "values", "cargo_home_isolation"},
        "build environment",
    )
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
        or not isinstance(values["RUSTUP_HOME"], str)
        or not pathlib.PurePath(values["RUSTUP_HOME"]).is_absolute()
    ):
        fail("build environment values differ")
    path_parts = values["PATH"].split(":") if isinstance(values["PATH"], str) else []
    if (
        len(path_parts) != 5
        or not pathlib.PurePath(path_parts[0]).is_absolute()
        or pathlib.PurePath(path_parts[0]).name != "closed-bin"
        or not pathlib.PurePath(path_parts[0]).parent.name.startswith("vibeos-c84-cargo-home.")
        or path_parts[1:] != ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    ):
        fail("build PATH differs")
    expected_target = (
        pathlib.PurePath(host_source_root)
        / "target"
        / "c84-milkv-build"
        / source_commit
        / challenge
    )
    target_path = pathlib.PurePath(values["CARGO_TARGET_DIR"])
    if target_path != expected_target:
        fail("build target directory differs")
    isolation = exact(
        environment["cargo_home_isolation"],
        {
            "ambient_config_loaded", "temporary", "cache_source",
            "registry_cache_symlinked", "git_cache_symlinked",
        },
        "build Cargo-home isolation",
    )
    if (
        isolation["ambient_config_loaded"] is not False
        or isolation["temporary"] is not True
        or not isinstance(isolation["cache_source"], str)
        or not pathlib.PurePath(isolation["cache_source"]).is_absolute()
        or type(isolation["registry_cache_symlinked"]) is not bool
        or type(isolation["git_cache_symlinked"]) is not bool
    ):
        fail("build Cargo-home isolation differs")

    tools = exact(content["tools"], set(BUILD_TOOL_LOGICAL_PATHS), "build tools")
    tool_records = {}
    source_root_path = pathlib.Path(source_root)
    for name, logical_path in BUILD_TOOL_LOGICAL_PATHS.items():
        tool_records[name] = validate_live_identity(
            tools[name],
            f"build tools.{name}",
            expected_path=logical_path,
            live_path=source_root_path / logical_path,
        )
    try:
        workload = json.loads(
            (source_root_path / BUILD_TOOL_LOGICAL_PATHS["workload_manifest"])
            .read_text(encoding="utf-8")
        )
        fixture = workload["fixture"]
        run_fields = [
            "vibeos.c84.aot-decision.run-id.v1", source_commit, challenge,
            fixture["artifact"]["sha256"], fixture["input"]["sha256"],
            fixture["output"]["sha256"], tool_records["workload_manifest"]["sha256"],
            tool_records["transcript_schema"]["sha256"],
        ]
        expected_run_id = hashlib.sha256("\0".join(run_fields).encode("ascii")).hexdigest()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, UnicodeEncodeError) as error:
        fail(f"cannot derive build run id: {error}")
    if content["run_id"] != expected_run_id:
        fail("build run id differs")
    validate_utc_chain(
        content["timestamps_utc"],
        ("build_started", "build_completed", "envelope_closed"),
        "build timestamps",
    )
    return content


def image_audit_transcript_has_failure(lines):
    return (
        re.search(
            r"\b(?:panic|fatal|fail|failed|failure)\b",
            "\n".join(lines[:-2]),
            re.IGNORECASE,
        )
        is not None
    )


def validate_package_deep(
    root,
    *,
    live_source,
    live_runtime,
    runtime_image_id,
    build_root,
    build_content,
    source_root,
    build_path,
    artifact_specs,
    tool_specs,
    audit_path,
):
    root = validate_root_object(root, PACKAGE_SCHEMA, 2, "package envelope")
    if contains_old_provenance(root):
        fail("package envelope contains old provenance")
    content = exact(
        root["content"],
        {
            "platform", "source_commit", "challenge", "run_id", "source", "sdk",
            "runtime_attestation", "build", "command", "environment", "artifacts",
            "verifier", "tools", "timestamps_utc",
        },
        "package content",
    )
    if (
        content["platform"] != "milkv-duo-cv1800b"
        or content["source_commit"] != source_commit
        or content["challenge"] != challenge
        or not isinstance(content["run_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", content["run_id"]) is None
        or content["run_id"] != build_content["run_id"]
    ):
        fail("package/build campaign run id differs")
    source = exact(content["source"], {"root", "head", "materialization"}, "package source")
    if source != {
        "root": str(pathlib.Path(source_root)),
        "head": source_commit,
        "materialization": live_source,
    }:
        fail("package frozen-source proof differs")
    if content["runtime_attestation"] != live_runtime:
        fail("package runtime attestation differs")
    sdk = exact(
        content["sdk"],
        {
            "commit", "commit_provenance", "image_digest", "image_id", "platform",
            "root", "runtime_provenance", "status_policy", "worktree_clean",
        },
        "package SDK",
    )
    if sdk != {
        "commit": "23eb84fecb29585dbb5728d6b7e2475ff273baac",
        "commit_provenance": "host-observed read-only SDK mount; in-container Git HEAD and clean worktree verified",
        "image_digest": "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679",
        "image_id": runtime_image_id,
        "platform": "linux/amd64",
        "root": "/home/work",
        "runtime_provenance": "host Docker daemon inspect plus in-container namespace witness; software custody only",
        "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
        "worktree_clean": True,
    }:
        fail("package SDK runtime custody differs")

    build = exact(content["build"], {"content_sha256", "envelope"}, "package build reference")
    build_path = pathlib.Path(build_path).resolve(strict=True)
    validate_live_identity(
        build["envelope"],
        "package build.envelope",
        expected_path=str(build_path),
        live_path=build_path,
    )
    if build["content_sha256"] != build_root["content_sha256"]:
        fail("package build reference differs")
    if content["command"] != [
        "scripts/package-milkv-duo-sdk.sh", "--wasm-aot-profile", "<sdk-root>"
    ]:
        fail("package command differs")

    environment = exact(
        content["environment"],
        {"fit_tools", "genimage", "image_verifier"},
        "package environment",
    )
    fit_environment = exact(
        environment["fit_tools"], {"mode", "allowed_keys", "values"},
        "package fit_tools environment",
    )
    if fit_environment != {
        "mode": "env -i",
        "allowed_keys": ["LC_ALL", "PATH", "TZ"],
        "values": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    }:
        fail("package fit_tools environment differs")
    genimage_path = pathlib.Path(tool_specs["sdk_genimage"][0]).resolve(strict=True)
    try:
        genimage_lib = (genimage_path.parent / ".." / "lib").resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve package genimage library: {error}")
    genimage_environment = exact(
        environment["genimage"], {"mode", "allowed_keys", "values"},
        "package genimage environment",
    )
    if genimage_environment != {
        "mode": "env -i",
        "allowed_keys": ["HOME", "LC_ALL", "LD_LIBRARY_PATH", "PATH", "TZ"],
        "values": {
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(genimage_lib),
            "PATH": f"{genimage_path.parent}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TZ": "UTC",
        },
    }:
        fail("package genimage environment differs")
    image_environment = exact(
        environment["image_verifier"], {"mode", "allowed_keys", "values"},
        "package image_verifier environment",
    )
    image_keys = [
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
        "GIT_OPTIONAL_LOCKS", "HOME", "LC_ALL", "PATH", "TZ",
        "VIBEOS_C84_CHALLENGE", "VIBEOS_C84_SDK_CONTAINER_DIGEST",
        "VIBEOS_C84_SOURCE_COMMIT",
    ]
    if image_environment != {
        "mode": "env -i",
        "allowed_keys": image_keys,
        "values": {
            "GIT_CONFIG_GLOBAL": "/etc/vibeos-c84.gitconfig",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "PATH": FIXED_VERIFIER_PATH,
            "TZ": "UTC",
            "VIBEOS_C84_CHALLENGE": challenge,
            "VIBEOS_C84_SDK_CONTAINER_DIGEST": sdk["image_digest"],
            "VIBEOS_C84_SOURCE_COMMIT": source_commit,
        },
    }:
        fail("package image_verifier environment differs")

    artifacts = exact(content["artifacts"], set(artifact_specs), "package artifacts")
    artifact_records = {}
    for name, (live_path, recorded_path) in artifact_specs.items():
        artifact_records[name] = validate_live_identity(
            artifacts[name],
            f"package artifacts.{name}",
            expected_path=recorded_path,
            live_path=live_path,
            scan=name in {
                "kernel_elf", "kernel_binary", "fit_boot_sd", "full_sd_image"
            },
            reject_symlink=name not in {"sdk_fip", "sdk_dtb"},
        )
    build_artifacts = exact(
        build_content["artifacts"], {"kernel_elf", "kernel_binary"},
        "build artifacts",
    )
    for name in ("kernel_elf", "kernel_binary"):
        if {
            "sha256": artifact_records[name]["sha256"],
            "bytes": artifact_records[name]["bytes"],
        } != {
            "sha256": build_artifacts[name]["sha256"],
            "bytes": build_artifacts[name]["bytes"],
        }:
            fail(f"package/build artifact {name} differs")

    tools = exact(content["tools"], set(tool_specs), "package tools")
    tool_records = {}
    for name, (live_path, recorded_path) in tool_specs.items():
        tool_records[name] = validate_live_identity(
            tools[name],
            f"package tools.{name}",
            expected_path=recorded_path,
            live_path=live_path,
            reject_symlink=False,
        )
    build_source_tool = build_content["tools"]["source_materializer_script"]
    if {
        "sha256": build_source_tool["sha256"], "bytes": build_source_tool["bytes"],
    } != {
        "sha256": tool_records["source_materializer_script"]["sha256"],
        "bytes": tool_records["source_materializer_script"]["bytes"],
    }:
        fail("package/build source materializer differs")

    verifier = exact(
        content["verifier"],
        {
            "status", "exit_code", "exact_pass_marker", "report", "report_sha256",
            "audit_log", "invocation",
        },
        "package verifier",
    )
    if (
        verifier["status"] != "PASS"
        or type(verifier["exit_code"]) is not int
        or verifier["exit_code"] != 0
        or verifier["exact_pass_marker"] != PASS_MARKER
        or verifier["invocation"] != [
            "scripts/verify-milkv-duo-image.sh", "--wasm-aot-profile",
            "--package-preflight", "--artifact-root=<staging-artifact-root>",
            "<sdk-root>",
        ]
    ):
        fail("package verifier attestation differs")
    report = exact(
        verifier["report"],
        {
            "schema", "version", "source_commit", "challenge",
            "source_materialization", "runtime_attestation", "artifacts", "tools",
        },
        "embedded image audit report",
    )
    if (
        report["schema"] != REPORT_SCHEMA
        or type(report["version"]) is not int
        or report["version"] != 2
        or report["source_commit"] != source_commit
        or report["challenge"] != challenge
        or report["source_materialization"] != live_source
        or report["runtime_attestation"] != live_runtime
    ):
        fail("embedded image audit report identity differs")
    canonical_report = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if (
        not isinstance(verifier["report_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", verifier["report_sha256"]) is None
        or hashlib.sha256(canonical_report.encode("utf-8")).hexdigest()
        != verifier["report_sha256"]
    ):
        fail("embedded image audit report content address differs")
    report_artifacts = exact(
        report["artifacts"], set(REPORT_ARTIFACT_ROLES),
        "embedded image audit artifacts",
    )
    report_tools = exact(
        report["tools"], set(REPORT_TOOL_ROLES),
        "embedded image audit tools",
    )
    for report_role, package_role in REPORT_ARTIFACT_ROLES.items():
        measurement = measurement_record(
            report_artifacts[report_role], f"embedded artifacts.{report_role}"
        )
        record = artifact_records[package_role]
        if measurement != {"sha256": record["sha256"], "bytes": record["bytes"]}:
            fail(f"embedded artifact {report_role} differs from package/live bytes")
    for report_role, package_role in REPORT_TOOL_ROLES.items():
        measurement = measurement_record(
            report_tools[report_role], f"embedded tools.{report_role}"
        )
        record = tool_records[package_role]
        if measurement != {"sha256": record["sha256"], "bytes": record["bytes"]}:
            fail(f"embedded tool {report_role} differs from package/live bytes")

    audit_path = pathlib.Path(audit_path).resolve(strict=True)
    audit_record = validate_live_identity(
        verifier["audit_log"],
        "package verifier.audit_log",
        expected_path=str(audit_path),
        live_path=audit_path,
    )
    audit_raw = stable_regular(
        audit_path, "published image verifier audit", maximum=67_108_864
    )
    if (
        audit_record["bytes"] != len(audit_raw)
        or audit_record["sha256"] != hashlib.sha256(audit_raw).hexdigest()
    ):
        fail("package verifier audit identity differs")
    try:
        audit_text = audit_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"image verifier audit is not UTF-8: {error}")
    audit_lines = audit_text.splitlines()
    if (
        not audit_text.endswith(PASS_MARKER + "\n")
        or len(audit_lines) < 2
        or audit_lines[-1] != PASS_MARKER
        or audit_lines[-2] != canonical_report
        or audit_text.count(PASS_MARKER) != 1
        or audit_text.count(f'"schema":"{REPORT_SCHEMA}"') != 1
        or image_audit_transcript_has_failure(audit_lines)
    ):
        fail("package verifier audit framing differs")
    try:
        audit_report = json.loads(
            audit_lines[-2],
            object_pairs_hook=reject_duplicate_members,
            parse_constant=lambda value: fail(f"non-finite audit JSON value {value}"),
        )
    except json.JSONDecodeError as error:
        fail(f"cannot decode image verifier audit report: {error}")
    if audit_report != report:
        fail("package embedded/audit report differs")
    validate_utc_chain(
        content["timestamps_utc"],
        ("packaging_started", "image_verified", "envelope_closed"),
        "package timestamps",
    )
    return content, report


def fixture_root(schema, content, *, version):
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": schema,
        "version": version,
        "status": "closed",
        "content_sha256": hashlib.sha256(canonical).hexdigest(),
        "content": content,
    }


def fixture_file_identity(path, recorded_path):
    data = pathlib.Path(path).read_bytes()
    return {
        "path": str(recorded_path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def run_semantic_selftest():
    global snapshots
    snapshots = {}
    if image_audit_transcript_has_failure(
        ["normal verifier output", '{"path":"/tmp/fail/source"}', PASS_MARKER]
    ):
        raise RuntimeError("structured image audit status word was treated as failure")
    if not image_audit_transcript_has_failure(
        ["fatal: verifier crashed", "{}", PASS_MARKER]
    ):
        raise RuntimeError("non-structured image audit failure was not detected")
    with tempfile.TemporaryDirectory(prefix="vibeos-c84-verifier-selftest.") as temporary:
        temporary_root = pathlib.Path(temporary)
        source_root = temporary_root / "home" / "vibeos"
        host_source_root = temporary_root / "host" / "frozen-vibeos"
        sdk_root = temporary_root / "home" / "work"
        canonical_output = source_root / "target" / "milkv-duo-wasm-aot-profile"
        canonical_output.mkdir(parents=True)
        sdk_root.mkdir(parents=True)

        def put(path, data):
            path = pathlib.Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return path.resolve(strict=True)

        workload = {
            "fixture": {
                "artifact": {"sha256": "1" * 64},
                "input": {"sha256": "2" * 64},
                "output": {"sha256": "3" * 64},
            }
        }
        for name, logical_path in BUILD_TOOL_LOGICAL_PATHS.items():
            path = source_root / logical_path
            if name == "workload_manifest":
                put(path, json.dumps(workload, sort_keys=True).encode("utf-8"))
            elif name == "toolchain_contract":
                put(
                    path,
                    (
                        '[toolchain]\nchannel = "nightly-fixture"\n'
                        '# rustc 1.86.0-nightly (fixture 2025-01-01)\n'
                        f'# rustc-commit: {"c" * 40}\n'
                    ).encode("utf-8"),
                )
            else:
                put(path, f"fixture build tool {name}\n".encode("utf-8"))

        build_elf = put(
            canonical_output / PACKAGE_ARTIFACT_FILENAMES["kernel_elf"],
            f"fixture ELF {source_commit} {challenge}\n".encode("ascii"),
        )
        build_binary = put(
            canonical_output / PACKAGE_ARTIFACT_FILENAMES["kernel_binary"],
            f"fixture BIN {source_commit} {challenge}\n".encode("ascii"),
        )
        live_source = fixture_root(
            "vibeos.c84.source-materialization-envelope",
            {"source_commit": source_commit, "challenge": challenge, "fixture": True},
            version=1,
        )
        live_runtime = fixture_root(
            "vibeos.c84.docker-runtime-attestation",
            {"source_commit": source_commit, "challenge": challenge, "fixture": True},
            version=1,
        )
        runtime_image_id = "sha256:" + "d" * 64
        stage_root = (
            pathlib.PurePosixPath("target")
            / f".milkv-duo-wasm-aot-profile.stage.{source_commit}.{challenge}"
        )
        build_artifacts = {
            "kernel_elf": fixture_file_identity(
                build_elf, stage_root / PACKAGE_ARTIFACT_FILENAMES["kernel_elf"]
            ),
            "kernel_binary": fixture_file_identity(
                build_binary, stage_root / PACKAGE_ARTIFACT_FILENAMES["kernel_binary"]
            ),
        }
        build_tools = {
            name: fixture_file_identity(source_root / logical_path, logical_path)
            for name, logical_path in BUILD_TOOL_LOGICAL_PATHS.items()
        }

        def synthetic_toolchain_record(name):
            data = f"synthetic toolchain {name}".encode("ascii")
            paths = {
                "rustup": "/opt/rustup/bin/rustup",
                "cargo": "/opt/vibeos-toolchain/bin/cargo",
                "rustc": "/opt/vibeos-toolchain/bin/rustc",
                "rustdoc": "/opt/vibeos-toolchain/bin/rustdoc",
                "rust_objcopy": "/opt/vibeos-toolchain/lib/rustlib/fixture-host/bin/rust-objcopy",
                "linker": "/usr/bin/ld.lld",
            }
            return {
                "path": paths[name],
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }

        toolchain = {
            "provenance": "build-runner-self-measured; package cross-platform live rehash unavailable",
            "channel": "nightly-fixture",
            "rustc_verbose": (
                "rustc 1.86.0-nightly (fixture 2025-01-01)\n"
                f"commit-hash: {'c' * 40}\nhost: fixture-host\n"
            ),
            **{
                name: synthetic_toolchain_record(name)
                for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker")
            },
        }
        build_keys = [
            "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR",
            "HOME", "LC_ALL", "PATH", "RUSTC", "RUSTDOC", "RUSTUP_HOME",
            "SOURCE_DATE_EPOCH", "TMPDIR", "TZ", "VIBEOS_C84_CHALLENGE",
            "VIBEOS_C84_SOURCE_COMMIT",
        ]
        isolated_bin = temporary_root / "vibeos-c84-cargo-home.fixture" / "closed-bin"
        build_environment = {
            "mode": "env -i",
            "allowed_keys": build_keys,
            "values": {
                "CARGO_HOME": "<isolated-cargo-home>",
                "CARGO_INCREMENTAL": "0",
                "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_DIR": str(
                    host_source_root
                    / "target"
                    / "c84-milkv-build"
                    / source_commit
                    / challenge
                ),
                "HOME": "<isolated-cargo-home>/home",
                "LC_ALL": "C",
                "PATH": f"{isolated_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
                "RUSTC": toolchain["rustc"]["path"],
                "RUSTDOC": toolchain["rustdoc"]["path"],
                "RUSTUP_HOME": "/opt/rustup",
                "SOURCE_DATE_EPOCH": "1740000000",
                "TMPDIR": "<isolated-cargo-home>/tmp",
                "TZ": "UTC",
                "VIBEOS_C84_CHALLENGE": challenge,
                "VIBEOS_C84_SOURCE_COMMIT": source_commit,
            },
            "cargo_home_isolation": {
                "ambient_config_loaded": False,
                "temporary": True,
                "cache_source": "/opt/cargo-cache",
                "registry_cache_symlinked": False,
                "git_cache_symlinked": False,
            },
        }
        fixture = workload["fixture"]
        run_fields = [
            "vibeos.c84.aot-decision.run-id.v1", source_commit, challenge,
            fixture["artifact"]["sha256"], fixture["input"]["sha256"],
            fixture["output"]["sha256"], build_tools["workload_manifest"]["sha256"],
            build_tools["transcript_schema"]["sha256"],
        ]
        run_id = hashlib.sha256("\0".join(run_fields).encode("ascii")).hexdigest()
        build_content = {
            "platform": "milkv-duo-cv1800b",
            "source_commit": source_commit,
            "challenge": challenge,
            "run_id": run_id,
            "source": {"root": ".", "head": source_commit, "materialization": live_source},
            "command": [
                toolchain["rustup"]["path"], "run", toolchain["channel"], "cargo", "build",
                "--release", "--locked", "--offline", "--no-default-features", "--features",
                "wasm-c84-ssh-managed-child-single-boot-collector",
            ],
            "objcopy_command": [
                toolchain["rust_objcopy"]["path"], "-O", "binary",
                build_artifacts["kernel_elf"]["path"],
                build_artifacts["kernel_binary"]["path"],
            ],
            "objcopy_environment": {
                "mode": "env -i",
                "allowed_keys": ["LC_ALL", "PATH", "TZ"],
                "values": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            },
            "environment": build_environment,
            "toolchain": toolchain,
            "artifacts": build_artifacts,
            "tools": build_tools,
            "timestamps_utc": {
                "build_started": "2025-01-01T00:00:00Z",
                "build_completed": "2025-01-01T00:01:00Z",
                "envelope_closed": "2025-01-01T00:02:00Z",
            },
        }
        build_root = fixture_root(BUILD_SCHEMA, build_content, version=2)
        build_path = canonical_output / "build-envelope.json"
        build_path.write_text(json.dumps(build_root, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        build_path = build_path.resolve(strict=True)
        validated_build = validate_build_deep(
            build_root, live_source, source_root, host_source_root
        )

        package_files = {
            "kernel_elf": build_elf,
            "kernel_binary": build_binary,
            "packaged_fit_source": put(canonical_output / "milkv-duo.its", b"fixture ITS\n"),
            "packaged_dtb": put(canonical_output / "cv1800b_milkv_duo_sd.dtb", b"fixture DTB\n"),
            "fit_boot_sd": put(
                canonical_output / "boot.sd",
                f"fixture FIT {source_commit} {challenge}\n".encode("ascii"),
            ),
            "full_sd_image": put(
                canonical_output / "vibeos-milkv-duo-wasm-aot-profile-sd.img",
                f"fixture IMG {source_commit} {challenge}\n".encode("ascii"),
            ),
            "sdk_fip": put(sdk_root / "install" / "soc" / "fip.bin", b"fixture FIP\n"),
            "sdk_dtb": put(sdk_root / "linux" / "sdk.dtb", b"fixture SDK DTB\n"),
        }
        artifact_specs = {
            name: (path, str(path)) for name, path in package_files.items()
        }

        package_tool_paths = {
            "package_script": source_root / "scripts" / "package-milkv-duo-sdk.sh",
            "image_verifier_script": source_root / "scripts" / "verify-milkv-duo-image.sh",
            "docker_git_config": source_root / "scripts" / "c84-docker.gitconfig",
            "build_script": source_root / "scripts" / "build-milkv-duo.sh",
            "source_materializer_script": source_root / "scripts" / "c84-source-materialization.py",
            "docker_runtime_script": source_root / "scripts" / "c84-docker-runtime.py",
            "jitterentropy_patch": source_root / "patches" / "jitterentropy-rs" / "0001-vibeos-qualification.patch",
            "gitmodules": source_root / ".gitmodules",
            "fit_source": source_root / "scripts" / "milkv-duo.its",
            "genimage_config": source_root / "scripts" / "milkv-duo-genimage.cfg",
            "workload_manifest": source_root / "benchmarks" / "wasm-aot-decision" / "workloads-v1.json",
            "transcript_schema": source_root / "benchmarks" / "wasm-aot-decision" / "schema-v1.json",
            "toolchain_contract": source_root / "rust-toolchain.toml",
            "evidence_checker": source_root / "scripts" / "verify-c84-aot-decision.py",
            "sdk_mkimage": sdk_root / "tools" / "mkimage",
            "sdk_dumpimage": sdk_root / "tools" / "dumpimage",
            "sdk_genimage": sdk_root / "host" / "bin" / "genimage",
            "verifier_mdir": temporary_root / "verifier-bin" / "mdir",
            "verifier_mcopy": temporary_root / "verifier-bin" / "mcopy",
            "verifier_cmp": temporary_root / "verifier-bin" / "cmp",
            "verifier_sha256sum": temporary_root / "verifier-bin" / "sha256sum",
            "verifier_fdtget": temporary_root / "verifier-bin" / "fdtget",
            "verifier_python3": temporary_root / "verifier-bin" / "python3",
            "verifier_tr": temporary_root / "verifier-bin" / "tr",
        }
        for name, path in package_tool_paths.items():
            if not path.exists():
                put(path, f"fixture package tool {name}\n".encode("utf-8"))
        (package_tool_paths["sdk_genimage"].parent / ".." / "lib").mkdir(parents=True)
        tool_specs = {
            name: (path.resolve(strict=True), str(path.resolve(strict=True)))
            for name, path in package_tool_paths.items()
        }
        package_artifacts = {
            name: fixture_file_identity(path, recorded_path)
            for name, (path, recorded_path) in artifact_specs.items()
        }
        package_tools = {
            name: fixture_file_identity(path, recorded_path)
            for name, (path, recorded_path) in tool_specs.items()
        }
        report = {
            "schema": REPORT_SCHEMA,
            "version": 2,
            "source_commit": source_commit,
            "challenge": challenge,
            "source_materialization": live_source,
            "runtime_attestation": live_runtime,
            "artifacts": {
                report_role: {
                    "sha256": package_artifacts[package_role]["sha256"],
                    "bytes": package_artifacts[package_role]["bytes"],
                }
                for report_role, package_role in REPORT_ARTIFACT_ROLES.items()
            },
            "tools": {
                report_role: {
                    "sha256": package_tools[package_role]["sha256"],
                    "bytes": package_tools[package_role]["bytes"],
                }
                for report_role, package_role in REPORT_TOOL_ROLES.items()
            },
        }
        canonical_report = json.dumps(report, sort_keys=True, separators=(",", ":"))
        audit_path = canonical_output / "image-verifier-audit.log"
        audit_path = put(
            audit_path,
            ("fixture provenance ready\n" + canonical_report + "\n" + PASS_MARKER + "\n")
            .encode("utf-8"),
        )
        genimage_path = pathlib.Path(tool_specs["sdk_genimage"][0])
        genimage_lib = (genimage_path.parent / ".." / "lib").resolve(strict=True)
        image_keys = [
            "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
            "GIT_OPTIONAL_LOCKS", "HOME", "LC_ALL", "PATH", "TZ",
            "VIBEOS_C84_CHALLENGE", "VIBEOS_C84_SDK_CONTAINER_DIGEST",
            "VIBEOS_C84_SOURCE_COMMIT",
        ]
        package_environment = {
            "fit_tools": {
                "mode": "env -i", "allowed_keys": ["LC_ALL", "PATH", "TZ"],
                "values": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            },
            "genimage": {
                "mode": "env -i",
                "allowed_keys": ["HOME", "LC_ALL", "LD_LIBRARY_PATH", "PATH", "TZ"],
                "values": {
                    "HOME": "/nonexistent", "LC_ALL": "C",
                    "LD_LIBRARY_PATH": str(genimage_lib),
                    "PATH": f"{genimage_path.parent}:/usr/bin:/bin:/usr/sbin:/sbin",
                    "TZ": "UTC",
                },
            },
            "image_verifier": {
                "mode": "env -i", "allowed_keys": image_keys,
                "values": {
                    "GIT_CONFIG_GLOBAL": "/etc/vibeos-c84.gitconfig",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0", "HOME": "/nonexistent", "LC_ALL": "C",
                    "PATH": FIXED_VERIFIER_PATH, "TZ": "UTC",
                    "VIBEOS_C84_CHALLENGE": challenge,
                    "VIBEOS_C84_SDK_CONTAINER_DIGEST": "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679",
                    "VIBEOS_C84_SOURCE_COMMIT": source_commit,
                },
            },
        }
        build_envelope_identity = fixture_file_identity(build_path, str(build_path))
        package_content = {
            "platform": "milkv-duo-cv1800b",
            "source_commit": source_commit,
            "challenge": challenge,
            "run_id": run_id,
            "source": {
                "root": str(source_root), "head": source_commit,
                "materialization": live_source,
            },
            "sdk": {
                "commit": "23eb84fecb29585dbb5728d6b7e2475ff273baac",
                "commit_provenance": "host-observed read-only SDK mount; in-container Git HEAD and clean worktree verified",
                "image_digest": "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679",
                "image_id": runtime_image_id,
                "platform": "linux/amd64", "root": "/home/work",
                "runtime_provenance": "host Docker daemon inspect plus in-container namespace witness; software custody only",
                "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
                "worktree_clean": True,
            },
            "runtime_attestation": live_runtime,
            "build": {
                "content_sha256": build_root["content_sha256"],
                "envelope": build_envelope_identity,
            },
            "command": ["scripts/package-milkv-duo-sdk.sh", "--wasm-aot-profile", "<sdk-root>"],
            "environment": package_environment,
            "artifacts": package_artifacts,
            "verifier": {
                "status": "PASS", "exit_code": 0, "exact_pass_marker": PASS_MARKER,
                "report": report,
                "report_sha256": hashlib.sha256(canonical_report.encode("utf-8")).hexdigest(),
                "audit_log": fixture_file_identity(audit_path, str(audit_path)),
                "invocation": [
                    "scripts/verify-milkv-duo-image.sh", "--wasm-aot-profile",
                    "--package-preflight", "--artifact-root=<staging-artifact-root>",
                    "<sdk-root>",
                ],
            },
            "tools": package_tools,
            "timestamps_utc": {
                "packaging_started": "2025-01-01T00:03:00Z",
                "image_verified": "2025-01-01T00:04:00Z",
                "envelope_closed": "2025-01-01T00:05:00Z",
            },
        }
        package_root = fixture_root(PACKAGE_SCHEMA, package_content, version=2)
        validate_package_deep(
            package_root,
            live_source=live_source,
            live_runtime=live_runtime,
            runtime_image_id=runtime_image_id,
            build_root=build_root,
            build_content=validated_build,
            source_root=source_root,
            build_path=build_path,
            artifact_specs=artifact_specs,
            tool_specs=tool_specs,
            audit_path=audit_path,
        )

        def readdress(root, schema, mutation):
            candidate_content = copy.deepcopy(root["content"])
            mutation(candidate_content)
            return fixture_root(schema, candidate_content, version=2)

        negative_cases = []

        def reject_package(label, mutation):
            candidate = readdress(package_root, PACKAGE_SCHEMA, mutation)
            try:
                validate_package_deep(
                    candidate,
                    live_source=live_source,
                    live_runtime=live_runtime,
                    runtime_image_id=runtime_image_id,
                    build_root=build_root,
                    build_content=validated_build,
                    source_root=source_root,
                    build_path=build_path,
                    artifact_specs=artifact_specs,
                    tool_specs=tool_specs,
                    audit_path=audit_path,
                )
            except SystemExit:
                negative_cases.append(label)
            else:
                raise RuntimeError(f"semantic selftest {label!r} was accepted")

        def reject_build(label, mutation):
            candidate = readdress(build_root, BUILD_SCHEMA, mutation)
            try:
                validate_build_deep(
                    candidate, live_source, source_root, host_source_root
                )
            except SystemExit:
                negative_cases.append(label)
            else:
                raise RuntimeError(f"semantic selftest {label!r} was accepted")

        reject_package(
            "forged-exact-pass-marker",
            lambda content: content["verifier"].__setitem__("exact_pass_marker", "PASS"),
        )
        reject_package(
            "curl-verifier-invocation",
            lambda content: content["verifier"].__setitem__("invocation", ["curl", "https://invalid"]),
        )
        reject_package(
            "package-extra-artifact",
            lambda content: content["artifacts"].__setitem__("extra", copy.deepcopy(content["artifacts"]["kernel_binary"])),
        )
        reject_package(
            "package-command",
            lambda content: content.__setitem__("command", ["sh", "-c", "true"]),
        )
        reject_package(
            "package-environment",
            lambda content: content["environment"]["image_verifier"]["values"].__setitem__("PATH", "/tmp"),
        )
        reject_package(
            "package-timestamp",
            lambda content: content["timestamps_utc"].__setitem__("envelope_closed", "2024-01-01T00:00:00Z"),
        )
        reject_build(
            "build-artifact",
            lambda content: content["artifacts"]["kernel_binary"].__setitem__("bytes", content["artifacts"]["kernel_binary"]["bytes"] + 1),
        )
        reject_build(
            "build-toolchain",
            lambda content: content["toolchain"].__setitem__("channel", "nightly-forged"),
        )
        reject_build(
            "build-run-id",
            lambda content: content.__setitem__("run_id", "e" * 64),
        )
        reject_build(
            "build-host-target-relocation",
            lambda content: content["environment"]["values"].__setitem__(
                "CARGO_TARGET_DIR",
                f"/forged/target/c84-milkv-build/{source_commit}/{challenge}",
            ),
        )

        def swap_tools(content):
            content["tools"]["sdk_mkimage"], content["tools"]["sdk_dumpimage"] = (
                content["tools"]["sdk_dumpimage"], content["tools"]["sdk_mkimage"]
            )

        reject_package("package-tool-record-swap", swap_tools)
        if len(negative_cases) != 11:
            raise RuntimeError("semantic selftest negative-case count differs")
    print(
        "verify-milkv-duo-image.sh C8.4 semantic selftest: "
        "PASS (11 re-addressed forgeries)"
    )


if semantic_selftest:
    run_semantic_selftest()
    raise SystemExit(0)


source_materializer_path = pathlib.Path(tool_paths[3]).resolve(strict=True)
source_root = source_materializer_path.parent.parent
expected_source_envelope = (
    source_root
    / "target"
    / "c84-source-materialization"
    / source_commit
    / challenge
    / "source-materialization-envelope.json"
)
if source_envelope_path != expected_source_envelope or source_envelope_path.resolve(strict=True) != source_envelope_path:
    fail("source materialization envelope path differs")
live_source = validate_source_materialization(
    load_envelope(
        source_envelope_path,
        "source materialization envelope",
        "vibeos.c84.source-materialization-envelope",
        1,
        canonical_root=True,
    )
)
docker_runtime_path = pathlib.Path(tool_paths[4]).resolve(strict=True)
if docker_runtime_path != source_root / "scripts" / "c84-docker-runtime.py":
    fail("Docker runtime tool path differs")
expected_runtime_attestation = (
    source_root
    / "target"
    / "milkv-duo-wasm-aot-profile"
    / "container-runtime-attestation.json"
)
if (
    runtime_attestation_path != expected_runtime_attestation
    or runtime_attestation_path.resolve(strict=True) != runtime_attestation_path
):
    fail("runtime attestation path differs")
live_runtime = load_envelope(
    runtime_attestation_path,
    "runtime attestation",
    "vibeos.c84.docker-runtime-attestation",
    1,
    canonical_root=True,
    maximum=67_108_864,
)
runtime_image_id, host_source_root = validate_runtime_attestation(
    live_runtime, live_source
)

build_root = load_envelope(
    build_envelope_path,
    "build envelope",
    "vibeos.c84.duo-wasm-aot-profile.build-envelope",
    2,
)
build_content_deep = validate_build_deep(
    build_root, live_source, source_root, host_source_root
)
build_content = exact(
    build_root["content"],
    {
        "platform", "source_commit", "challenge", "run_id", "source", "command",
        "objcopy_command", "objcopy_environment", "environment", "toolchain",
        "artifacts", "tools", "timestamps_utc",
    },
    "build content",
)
if (
    build_content["platform"] != "milkv-duo-cv1800b"
    or build_content["source_commit"] != source_commit
    or build_content["challenge"] != challenge
):
    fail("build campaign identity differs")
build_source = exact(build_content["source"], {"root", "head", "materialization"}, "build source")
if (
    build_source["root"] != "."
    or build_source["head"] != source_commit
    or build_source["materialization"] != live_source
):
    fail("build frozen-source proof differs")
expected_build_tools = {
    "build_script", "source_materializer_script", "jitterentropy_patch", "gitmodules",
    "firmware_manifest", "firmware_build_script", "firmware_linker_script",
    "firmware_cargo_config", "kernel_manifest", "workspace_manifest", "cargo_lock",
    "workload_manifest", "transcript_schema", "toolchain_contract",
}
build_tools = exact(build_content["tools"], expected_build_tools, "build tools")
build_source_tool = identity_record(
    build_tools["source_materializer_script"],
    "build tools.source_materializer_script",
    expected_path="scripts/c84-source-materialization.py",
)

report_artifact_live = {
    name: pathlib.Path(path).resolve(strict=True)
    for name, path in zip(artifact_names, artifact_paths)
}
report_tool_live = {
    name: pathlib.Path(path).resolve(strict=True)
    for name, path in zip(tool_names, tool_paths)
}
artifact_root = report_artifact_live["kernel_binary"].parent
canonical_artifact_root = source_root / "target" / "milkv-duo-wasm-aot-profile"
genimage_path = (
    sdk_root_path
    / "buildroot-2021.05"
    / "output"
    / "milkv-duo-sd_musl_riscv64"
    / "host"
    / "bin"
    / "genimage"
)
if not genimage_path.is_file():
    genimage_path = (
        sdk_root_path
        / "buildroot-2021.05"
        / "output"
        / "milkv-duo-sd_musl_riscv64"
        / "per-package"
        / "host-genimage"
        / "host"
        / "bin"
        / "genimage"
    )
genimage_path = genimage_path.resolve(strict=True)
package_artifact_live = {
    "kernel_elf": canonical_artifact_root / PACKAGE_ARTIFACT_FILENAMES["kernel_elf"],
    "kernel_binary": report_artifact_live["kernel_binary"],
    "packaged_fit_source": report_artifact_live["fit_source"],
    "packaged_dtb": report_artifact_live["packaged_dtb"],
    "fit_boot_sd": report_artifact_live["fit_boot_sd"],
    "full_sd_image": report_artifact_live["full_sd_image"],
    "sdk_fip": report_artifact_live["sdk_fip"],
    "sdk_dtb": report_artifact_live["sdk_dtb"],
}
package_artifact_specs = {
    name: (path, str(path.resolve(strict=True)))
    for name, path in package_artifact_live.items()
}
package_tool_live = {
    "package_script": source_root / "scripts" / "package-milkv-duo-sdk.sh",
    "image_verifier_script": source_root / "scripts" / "verify-milkv-duo-image.sh",
    "docker_git_config": source_root / "scripts" / "c84-docker.gitconfig",
    "build_script": source_root / "scripts" / "build-milkv-duo.sh",
    "source_materializer_script": source_root / "scripts" / "c84-source-materialization.py",
    "docker_runtime_script": source_root / "scripts" / "c84-docker-runtime.py",
    "jitterentropy_patch": source_root / "patches" / "jitterentropy-rs" / "0001-vibeos-qualification.patch",
    "gitmodules": source_root / ".gitmodules",
    "fit_source": source_root / "scripts" / "milkv-duo.its",
    "genimage_config": source_root / "scripts" / "milkv-duo-genimage.cfg",
    "workload_manifest": source_root / "benchmarks" / "wasm-aot-decision" / "workloads-v1.json",
    "transcript_schema": source_root / "benchmarks" / "wasm-aot-decision" / "schema-v1.json",
    "toolchain_contract": source_root / "rust-toolchain.toml",
    "evidence_checker": source_root / "scripts" / "verify-c84-aot-decision.py",
    "sdk_mkimage": report_tool_live["sdk_mkimage"],
    "sdk_dumpimage": report_tool_live["sdk_dumpimage"],
    "sdk_genimage": genimage_path,
    "verifier_mdir": report_tool_live["mdir"],
    "verifier_mcopy": report_tool_live["mcopy"],
    "verifier_cmp": report_tool_live["cmp"],
    "verifier_sha256sum": report_tool_live["sha256sum"],
    "verifier_fdtget": report_tool_live["fdtget"],
    "verifier_python3": report_tool_live["python3"],
    "verifier_tr": report_tool_live["tr"],
}
package_tool_specs = {
    name: (path, str(pathlib.Path(path).resolve(strict=True)))
    for name, path in package_tool_live.items()
}

package_root = None
package_source_tool = None
package_docker_tool = None
embedded_source_measurement = None
embedded_docker_measurement = None
deep_embedded_report = None
if package_preflight == "true":
    if os.path.lexists(package_envelope_path):
        fail("package-preflight unexpectedly found a package envelope")
else:
    if artifact_root != canonical_artifact_root:
        fail("normal package artifact root differs from the fixed target")
    package_root = load_envelope(
        package_envelope_path,
        "package envelope",
        "vibeos.c84.duo-wasm-aot-profile.package-envelope",
        2,
        maximum=67_108_864,
    )
    _, deep_embedded_report = validate_package_deep(
        package_root,
        live_source=live_source,
        live_runtime=live_runtime,
        runtime_image_id=runtime_image_id,
        build_root=build_root,
        build_content=build_content_deep,
        source_root=source_root,
        build_path=build_envelope_path,
        artifact_specs=package_artifact_specs,
        tool_specs=package_tool_specs,
        audit_path=artifact_root / "image-verifier-audit.log",
    )
    package_content = exact(
        package_root["content"],
        {
            "platform", "source_commit", "challenge", "run_id", "source", "sdk",
            "runtime_attestation", "build", "command", "environment", "artifacts",
            "verifier", "tools", "timestamps_utc",
        },
        "package content",
    )
    if (
        package_content["platform"] != "milkv-duo-cv1800b"
        or package_content["source_commit"] != source_commit
        or package_content["challenge"] != challenge
        or package_content["runtime_attestation"] != live_runtime
    ):
        fail("package campaign identity differs")
    package_source = exact(
        package_content["source"], {"root", "head", "materialization"}, "package source"
    )
    if (
        package_source["root"] != str(source_root)
        or package_source["head"] != source_commit
        or package_source["materialization"] != live_source
        or package_source["materialization"] != build_source["materialization"]
    ):
        fail("package frozen-source proof differs")
    build_reference = exact(
        package_content["build"], {"content_sha256", "envelope"}, "package build reference"
    )
    if build_reference["content_sha256"] != build_root["content_sha256"]:
        fail("package build reference differs")
    package_sdk = exact(
        package_content["sdk"],
        {
            "commit", "commit_provenance", "image_digest", "image_id", "platform",
            "root", "runtime_provenance", "status_policy", "worktree_clean",
        },
        "package SDK",
    )
    if package_sdk != {
        "commit": "23eb84fecb29585dbb5728d6b7e2475ff273baac",
        "commit_provenance": "host-observed read-only SDK mount; in-container Git HEAD and clean worktree verified",
        "image_digest": "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679",
        "image_id": runtime_image_id,
        "platform": "linux/amd64",
        "root": "/home/work",
        "runtime_provenance": "host Docker daemon inspect plus in-container namespace witness; software custody only",
        "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
        "worktree_clean": True,
    }:
        fail("package SDK runtime custody differs")
    expected_package_tools = {
        "package_script", "image_verifier_script", "docker_git_config", "build_script",
        "source_materializer_script", "docker_runtime_script", "jitterentropy_patch",
        "gitmodules", "fit_source", "genimage_config", "workload_manifest",
        "transcript_schema", "toolchain_contract", "evidence_checker", "sdk_mkimage",
        "sdk_dumpimage", "sdk_genimage", "verifier_mdir", "verifier_mcopy",
        "verifier_cmp", "verifier_sha256sum", "verifier_fdtget", "verifier_python3",
        "verifier_tr",
    }
    package_tools = exact(package_content["tools"], expected_package_tools, "package tools")
    package_source_tool = identity_record(
        package_tools["source_materializer_script"],
        "package tools.source_materializer_script",
        expected_path=str(source_materializer_path),
    )
    package_docker_tool = identity_record(
        package_tools["docker_runtime_script"],
        "package tools.docker_runtime_script",
        expected_path=str(docker_runtime_path),
    )
    verifier = exact(
        package_content["verifier"],
        {
            "status", "exit_code", "exact_pass_marker", "report", "report_sha256",
            "audit_log", "invocation",
        },
        "package verifier",
    )
    embedded_report = exact(
        verifier["report"],
        {
            "schema", "version", "source_commit", "challenge",
            "source_materialization", "runtime_attestation", "artifacts", "tools",
        },
        "embedded image audit report",
    )
    if (
        embedded_report["schema"] != "vibeos.c84.duo-wasm-aot-profile.image-audit-report"
        or type(embedded_report["version"]) is not int
        or embedded_report["version"] != 2
        or embedded_report["source_commit"] != source_commit
        or embedded_report["challenge"] != challenge
        or embedded_report["source_materialization"] != live_source
        or embedded_report["source_materialization"] != build_source["materialization"]
        or embedded_report["source_materialization"] != package_source["materialization"]
        or embedded_report["runtime_attestation"] != live_runtime
        or embedded_report["runtime_attestation"] != package_content["runtime_attestation"]
    ):
        fail("embedded image audit frozen-source proof differs")
    embedded_tools = exact(
        embedded_report["tools"], set(tool_names), "embedded image audit tools"
    )
    embedded_source_measurement = exact(
        embedded_tools["source_materializer_script"],
        {"sha256", "bytes"},
        "embedded image audit source materializer",
    )
    if (
        embedded_source_measurement
        != {"sha256": package_source_tool["sha256"], "bytes": package_source_tool["bytes"]}
    ):
        fail("embedded image audit source materializer differs")
    embedded_docker_measurement = exact(
        embedded_tools["docker_runtime_script"],
        {"sha256", "bytes"},
        "embedded image audit Docker runtime",
    )
    if (
        embedded_docker_measurement
        != {"sha256": package_docker_tool["sha256"], "bytes": package_docker_tool["bytes"]}
    ):
        fail("embedded image audit Docker runtime differs")
    canonical_embedded_report = json.dumps(
        embedded_report, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if (
        not isinstance(verifier["report_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", verifier["report_sha256"]) is None
        or hashlib.sha256(canonical_embedded_report).hexdigest() != verifier["report_sha256"]
    ):
        fail("embedded image audit report content address differs")


def identity(name):
    path = pathlib.Path(name).resolve(strict=True)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        fail(f"report input is not a non-empty regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        fail(f"report input changed while hashing: {path}")
    return {"sha256": digest.hexdigest(), "bytes": before.st_size}


artifacts = {name: identity(path) for name, path in zip(artifact_names, artifact_paths)}
tools = {name: identity(path) for name, path in zip(tool_names, tool_paths)}
source_tool_measurement = tools["source_materializer_script"]
docker_tool_measurement = tools["docker_runtime_script"]
for label, record in (
    ("build source materializer", build_source_tool),
    ("package source materializer", package_source_tool),
):
    if record is not None and {
        "sha256": record["sha256"], "bytes": record["bytes"],
    } != source_tool_measurement:
        fail(f"{label} identity differs from the live verifier tool")
if (
    embedded_source_measurement is not None
    and embedded_source_measurement != source_tool_measurement
):
    fail("embedded image audit source materializer differs from the live verifier tool")
if package_docker_tool is not None and {
    "sha256": package_docker_tool["sha256"],
    "bytes": package_docker_tool["bytes"],
} != docker_tool_measurement:
    fail("package Docker runtime identity differs from the live verifier tool")
if (
    embedded_docker_measurement is not None
    and embedded_docker_measurement != docker_tool_measurement
):
    fail("embedded image audit Docker runtime differs from the live verifier tool")

for label, (path, before) in snapshots.items():
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        fail(f"{label} changed during provenance closure")

report = {
    "schema": REPORT_SCHEMA,
    "version": 2,
    "source_commit": source_commit,
    "challenge": challenge,
    "source_materialization": live_source,
    "runtime_attestation": live_runtime,
    "artifacts": artifacts,
    "tools": tools,
}
if deep_embedded_report is not None and report != deep_embedded_report:
    fail("normal verifier live report differs from package embedded report")
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
# C84_PROVENANCE_VALIDATOR_END
PY
  c84_stability_tracker mark-report "$c84_stability_state"
  verify_c84_frozen_source >/dev/null
  verify_c84_runtime_attestations >/dev/null
  c84_stability_tracker mark-gates "$c84_stability_state"
  c84_stability_tracker verify "$c84_stability_state"
  echo "PASS: C8.4 FAT boot + raw data MBR image, FIP, FIT metadata, kernel/DTB payloads, and CRC32 hashes are valid"
else
  echo "PASS: FAT boot + raw data MBR image, FIP, FIT metadata, and payload CRC32 hashes are valid"
fi
