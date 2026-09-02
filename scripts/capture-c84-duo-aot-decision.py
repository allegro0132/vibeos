#!/usr/bin/env python3
"""Capture three physical Milk-V Duo C8.4 AOT-decision cold boots.

The collector is deliberately unable to flash, reset, auto-discover, or write
to a serial device.  It opens one explicitly named UART read-only, requires an
interactive ``COLD BOOT N`` acknowledgement before each boot, invokes the
independent single-boot verifier for every raw transcript, and publishes a
content-addressed capture envelope only after all three boots close.

``--selftest`` is host-only and never opens a serial device.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import select
import stat
import subprocess
import sys
import termios
import time
from dataclasses import dataclass
from typing import Any, NoReturn, Sequence


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = pathlib.Path(__file__).resolve()
C84_VERIFIER = ROOT / "scripts/verify-c84-aot-decision.py"
C84_EVIDENCE_VERIFIER = ROOT / "scripts/verify-c84-evidence.py"
C83_EVIDENCE_VERIFIER = ROOT / "scripts/verify-c83-evidence.py"
C84_SOURCE_MATERIALIZER = ROOT / "scripts/c84-source-materialization.py"
C84_DOCKER_RUNTIME = ROOT / "scripts/c84-docker-runtime.py"
C84_MANIFEST = ROOT / "benchmarks/wasm-aot-decision/workloads-v1.json"
C84_TRANSCRIPT_SCHEMA = ROOT / "benchmarks/wasm-aot-decision/schema-v1.json"
C84_EVIDENCE_SCHEMA = ROOT / "benchmarks/wasm-aot-decision/evidence-schema-v2.json"
DEFAULT_C83_ROOT = ROOT / "benchmarks/wasm-runtime"

TARGET_ROOT = ROOT / "target/milkv-duo-wasm-aot-profile"
CANONICAL_ARTIFACTS = {
    "kernel_elf": TARGET_ROOT / "vibeos-milkv-duo-wasm-aot-profile.elf",
    "kernel_binary": TARGET_ROOT / "vibeos-milkv-duo.bin",
    "fit_boot_sd": TARGET_ROOT / "boot.sd",
    "full_sd_image": TARGET_ROOT / "vibeos-milkv-duo-wasm-aot-profile-sd.img",
}
CANONICAL_BUILD_ENVELOPE = TARGET_ROOT / "build-envelope.json"
CANONICAL_PACKAGE_ENVELOPE = TARGET_ROOT / "package-envelope.json"
CANONICAL_IMAGE_AUDIT = TARGET_ROOT / "image-verifier-audit.log"
CANONICAL_PACKAGE_RUNTIME_ATTESTATION = (
    TARGET_ROOT / "container-runtime-attestation.json"
)
CANONICAL_VERIFIER_RUNTIME_ATTESTATION = (
    TARGET_ROOT / "container-runtime-verifier-attestation.json"
)
CANONICAL_CONTAINER_RUNTIME_CLOSURE = TARGET_ROOT / "container-runtime-closure.json"

PLATFORM = "milkv-duo-cv1800b"
WORKLOAD_ID = "ssh-case-filter-12k-v1"
BOOT_COUNT = 3
WARMUPS_PER_BOOT = 3
RETAINED_PER_BOOT = 21
RETAINED_TOTAL = BOOT_COUNT * RETAINED_PER_BOOT
BUDGET_TICKS = 2_500_000
UART_SETTINGS = "115200 8N1"
DEFAULT_TIMEOUT_SECONDS = 900.0
END_GUARD_SECONDS = 1.0
MAX_RAW_BYTES = 268_435_456
MAX_SUMMARY_BYTES = 1_048_576
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SDK_COMMIT = "23eb84fecb29585dbb5728d6b7e2475ff273baac"
SDK_CONTAINER_DIGEST = (
    "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679"
)
SDK_CONTAINER_REFERENCE = f"milkvtech/milkv-duo@{SDK_CONTAINER_DIGEST}"
SDK_CONTAINER_PLATFORM = "linux/amd64"
RUNTIME_SOURCE_ROOT = "/home/vibeos"
RUNTIME_SDK_ROOT = "/home/work"
RUNTIME_CAPABILITY = (
    "host Docker daemon inspect plus in-container namespace witness; "
    "software custody only"
)
SOURCE_MATERIALIZATION_SCHEMA = "vibeos.c84.source-materialization-envelope"
RUNTIME_ATTESTATION_SCHEMA = "vibeos.c84.docker-runtime-attestation"
RUNTIME_CLOSURE_SCHEMA = "vibeos.c84.docker-runtime-closure"
CAPTURE_ENVELOPE_SCHEMA = "vibeos.c84.duo-aot-decision.capture-envelope"
TEST_SOURCE = "1" * 40
TEST_CHALLENGE = "2" * 64
META_PREFIX = b"VIBE_WASM_AOT_META "
SAMPLE_PREFIX = b"VIBE_WASM_AOT_SAMPLE "
END_PREFIX = b"VIBE_WASM_AOT_END "
MARKER_PREFIX = b"VIBE_WASM_AOT_"
FAILURE_MARKERS = (b"panic", b"fatal", b"vibe_wasm_aot_failed")
STRICT_STATUS_POLICY = (
    "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none"
)
BUILD_ENVIRONMENT_KEYS = [
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
BUILD_TOOL_KEYS = {
    "build_script",
    "source_materializer_script",
    "jitterentropy_patch",
    "gitmodules",
    "firmware_manifest",
    "firmware_build_script",
    "firmware_linker_script",
    "firmware_cargo_config",
    "kernel_manifest",
    "workspace_manifest",
    "cargo_lock",
    "workload_manifest",
    "transcript_schema",
    "toolchain_contract",
}
PACKAGE_TOOL_KEYS = {
    "package_script",
    "image_verifier_script",
    "docker_git_config",
    "build_script",
    "source_materializer_script",
    "docker_runtime_script",
    "jitterentropy_patch",
    "gitmodules",
    "fit_source",
    "genimage_config",
    "workload_manifest",
    "transcript_schema",
    "toolchain_contract",
    "evidence_checker",
    "sdk_mkimage",
    "sdk_dumpimage",
    "sdk_genimage",
    "verifier_mdir",
    "verifier_mcopy",
    "verifier_cmp",
    "verifier_sha256sum",
    "verifier_fdtget",
    "verifier_python3",
    "verifier_tr",
}
C84_IMAGE_PASS = "PASS: C8.4 FAT boot + raw data MBR image, FIP, FIT metadata, kernel/DTB payloads, and CRC32 hashes are valid"
C84_IMAGE_REPORT_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.image-audit-report"
RUN_ID_DOMAIN = "vibeos.c84.aot-decision.run-id.v1"
RUN_ID_FIELDS = [
    "source_commit",
    "challenge",
    "artifact_sha256",
    "input_sha256",
    "output_sha256",
    "manifest_sha256",
    "transcript_schema_sha256",
]
IMAGE_REPORT_ARTIFACT_ROLES = {
    "kernel_binary": "kernel_binary",
    "fit_source": "packaged_fit_source",
    "packaged_dtb": "packaged_dtb",
    "sdk_dtb": "sdk_dtb",
    "fit_boot_sd": "fit_boot_sd",
    "full_sd_image": "full_sd_image",
    "sdk_fip": "sdk_fip",
}
IMAGE_REPORT_TOOL_ROLES = {
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
REPOSITORY_BUILD_TOOLS = {
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
REPOSITORY_PACKAGE_TOOLS = {
    "package_script": "scripts/package-milkv-duo-sdk.sh",
    "image_verifier_script": "scripts/verify-milkv-duo-image.sh",
    "docker_git_config": "scripts/c84-docker.gitconfig",
    "build_script": "scripts/build-milkv-duo.sh",
    "source_materializer_script": "scripts/c84-source-materialization.py",
    "docker_runtime_script": "scripts/c84-docker-runtime.py",
    "jitterentropy_patch": "patches/jitterentropy-rs/0001-vibeos-qualification.patch",
    "gitmodules": ".gitmodules",
    "fit_source": "scripts/milkv-duo.its",
    "genimage_config": "scripts/milkv-duo-genimage.cfg",
    "workload_manifest": "benchmarks/wasm-aot-decision/workloads-v1.json",
    "transcript_schema": "benchmarks/wasm-aot-decision/schema-v1.json",
    "toolchain_contract": "rust-toolchain.toml",
    "evidence_checker": "scripts/verify-c84-aot-decision.py",
}
C83_RELATIVE_FILES = tuple(
    sorted(
        (
            "README.md",
            "RESULTS.md",
            "schema-v1.json",
            "workloads-v1.json",
            "qemu/uart.log",
            "qemu/summary.json",
            "qemu/evidence.json",
            "duo/build-envelope.json",
            "duo/package-envelope.json",
            "duo/package-image-verifier-audit.log",
            "duo/capture-envelope.json",
            *(f"duo/boot-{index}.uart.log" for index in range(BOOT_COUNT)),
            *(f"duo/boot-{index}.summary.json" for index in range(BOOT_COUNT)),
        )
    )
)
RUNTIME_ARTIFACT_FILES = {
    "boot_sd": "boot.sd",
    "build_envelope": "build-envelope.json",
    "full_sd_image": "vibeos-milkv-duo-wasm-aot-profile-sd.img",
    "image_verifier_audit": "image-verifier-audit.log",
    "kernel_binary": "vibeos-milkv-duo.bin",
    "kernel_elf": "vibeos-milkv-duo-wasm-aot-profile.elf",
    "package_envelope": "package-envelope.json",
    "packaged_dtb": "cv1800b_milkv_duo_sd.dtb",
    "packaged_fit_source": "milkv-duo.its",
    "package_attestation": "container-runtime-attestation.json",
    "verifier_attestation": "container-runtime-verifier-attestation.json",
}
CAPTURE_FIXED_FILES = {
    "build-envelope.json",
    "package-envelope.json",
    "package-image-verifier-audit.log",
    "source-materialization-envelope.json",
    "container-runtime-attestation.json",
    "container-runtime-verifier-attestation.json",
    "container-runtime-closure.json",
    "capture-envelope.json",
}
CAPTURE_OUTPUT_FILES = CAPTURE_FIXED_FILES | {
    *(f"boot-{index}.uart.log" for index in range(BOOT_COUNT)),
    *(f"boot-{index}.summary.json" for index in range(BOOT_COUNT)),
}
_ACTIVE_CAPTURE_STAGE: pathlib.Path | None = None


class CaptureError(RuntimeError):
    """A physical capture or evidence precondition failed."""


def fail(message: str) -> NoReturn:
    raise CaptureError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )


def canonical_hex(value: Any, length: int, label: str) -> str:
    pattern = HEX40 if length == 40 else HEX64
    require(
        isinstance(value, str) and pattern.fullmatch(value) is not None,
        f"{label} is not canonical {length}-hex",
    )
    require(value != "0" * length, f"{label} uses the all-zero sentinel")
    return value


def canonical_source(value: Any, label: str = "source commit") -> str:
    source = canonical_hex(value, 40, label)
    require(source != TEST_SOURCE, f"{label} uses the documented test sentinel")
    return source


def canonical_challenge(value: Any, label: str = "challenge") -> str:
    challenge = canonical_hex(value, 64, label)
    require(challenge != TEST_CHALLENGE, f"{label} uses the documented test sentinel")
    return challenge


def canonical_sha(value: Any, label: str) -> str:
    return canonical_hex(value, 64, label)


def integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int = (1 << 64) - 1
) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label} is not an integer",
    )
    require(minimum <= value <= maximum, f"{label} is outside [{minimum}, {maximum}]")
    return value


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(
        set(value) == keys,
        f"{label} fields are not closed: {sorted(set(value) ^ keys)}",
    )
    return value


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON object contains duplicate member {key!r}")
        result[key] = value
    return result


def require_finite_json(value: Any, label: str) -> None:
    if isinstance(value, float):
        require(math.isfinite(value), f"{label} contains a non-finite number")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            require_finite_json(item, f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            require_finite_json(item, f"{label}.{key}")


def strict_json_bytes(raw: bytes, label: str) -> Any:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=lambda value: fail(
                f"{label} contains non-standard JSON constant {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {label}: {error}")
    require_finite_json(value, label)
    return value


def canonical_marker_stream_digest(raw: bytes, label: str) -> str:
    records: list[tuple[bytes, bytes]] = []
    for line in raw.splitlines():
        for kind, prefix in (
            (b"meta", META_PREFIX),
            (b"sample", SAMPLE_PREFIX),
            (b"end", END_PREFIX),
        ):
            if line.startswith(prefix):
                value = strict_json_bytes(
                    line[len(prefix) :], f"{label} {kind.decode()} record"
                )
                require(
                    isinstance(value, dict),
                    f"{label} {kind.decode()} record is not an object",
                )
                canonical = json.dumps(
                    value, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                records.append((kind, canonical))
                break
    require(
        [kind for kind, _canonical in records]
        == [b"meta", *([b"sample"] * 24), b"end"],
        f"{label} canonical marker stream is not META + 24 SAMPLE + END",
    )
    digest = hashlib.sha256()
    digest.update(b"vibeos.c84.canonical-marker-stream.v1\0")
    for kind, canonical in records:
        digest.update(kind)
        digest.update(b"\0")
        digest.update(str(len(canonical)).encode("ascii"))
        digest.update(b"\0")
        digest.update(canonical)
    return digest.hexdigest()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def campaign_run_id(
    source: str,
    challenge: str,
    manifest_raw: bytes,
    transcript_schema_raw: bytes,
    label: str,
) -> str:
    """Recompute the frozen campaign identity from exact contract bytes."""
    canonical_hex(source, 40, f"{label} source")
    canonical_hex(challenge, 64, f"{label} challenge")
    manifest = strict_json_bytes(manifest_raw, f"{label} manifest")
    require(isinstance(manifest, dict), f"{label} manifest is not an object")
    transcript = manifest.get("transcript")
    require(isinstance(transcript, dict), f"{label} transcript contract is missing")
    contract = exact(
        transcript.get("run_id"),
        {"domain", "algorithm", "encoding", "fields", "meaning"},
        f"{label} run-id contract",
    )
    require(
        contract
        == {
            "domain": RUN_ID_DOMAIN,
            "algorithm": "sha256",
            "encoding": "domain followed by fields as NUL-separated ASCII values with no trailing NUL",
            "fields": RUN_ID_FIELDS,
            "meaning": "shared campaign identity only; it does not prove a cold boot",
        },
        f"{label} run-id contract differs",
    )
    fixture = manifest.get("fixture")
    require(isinstance(fixture, dict), f"{label} fixture is missing")
    hashes: list[str] = []
    for name in ("artifact", "input", "output"):
        record = fixture.get(name)
        require(isinstance(record, dict), f"{label} fixture {name} is missing")
        hashes.append(canonical_sha(record.get("sha256"), f"{label} {name} hash"))
    fields = [
        RUN_ID_DOMAIN,
        source,
        challenge,
        *hashes,
        sha256_bytes(manifest_raw),
        sha256_bytes(transcript_schema_raw),
    ]
    require(
        all("\0" not in field and field.isascii() for field in fields),
        f"{label} run-id input is not NUL-free ASCII",
    )
    return sha256_bytes("\0".join(fields).encode("ascii"))


def require_run_id_binding(expected: str, **observed: Any) -> None:
    expected = canonical_sha(expected, "expected C8.4 run id")
    for label, value in observed.items():
        require(
            canonical_sha(value, f"C8.4 {label} run id") == expected,
            f"C8.4 {label} run id differs from the frozen campaign",
        )


def absolute_no_symlink_path(
    path: pathlib.Path,
    label: str,
    *,
    leaf_may_be_missing: bool = False,
) -> pathlib.Path:
    """Return a lexical absolute path after rejecting every symlink component."""
    absolute = pathlib.Path(os.path.abspath(os.fspath(path.expanduser())))
    parts = absolute.parts
    require(bool(parts) and absolute.is_absolute(), f"{label} is not absolute")
    current = pathlib.Path(parts[0])
    for position, part in enumerate(parts[1:], start=1):
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            require(
                leaf_may_be_missing and position == len(parts) - 1,
                f"{label} path component does not exist: {current}",
            )
            break
        except OSError as error:
            fail(f"cannot inspect {label} path component {current}: {error}")
        require(
            not stat.S_ISLNK(mode), f"{label} contains symlink component: {current}"
        )
    return absolute


def open_directory_chain(path: pathlib.Path, label: str) -> tuple[pathlib.Path, int]:
    absolute = pathlib.Path(os.path.abspath(os.fspath(path.expanduser())))
    require(absolute.is_absolute(), f"{label} is not absolute")
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        require(
            stat.S_ISDIR(os.fstat(descriptor).st_mode), f"{label} is not a directory"
        )
        return absolute, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def stable_regular_measure(
    path: pathlib.Path, label: str, *, maximum: int | None = None
) -> tuple[bytes, tuple[int, int]]:
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        absolute = pathlib.Path(os.path.abspath(os.fspath(path.expanduser())))
        _parent, parent_descriptor = open_directory_chain(
            absolute.parent, f"{label} parent"
        )
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode), f"{label} is not a regular file: {absolute}"
        )
        require(before.st_size > 0, f"{label} is empty: {absolute}")
        if maximum is not None:
            require(before.st_size <= maximum, f"{label} exceeds {maximum} bytes")
        chunks: list[bytes] = []
        consumed = 0
        while chunk := os.read(descriptor, 4 * 1024 * 1024):
            consumed += len(chunk)
            if maximum is not None:
                require(consumed <= maximum, f"{label} exceeds {maximum} bytes")
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = os.stat(
            absolute.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        _reopened, reopened_parent = open_directory_chain(
            absolute.parent, f"{label} parent recheck"
        )
        try:
            require(
                (os.fstat(parent_descriptor).st_dev, os.fstat(parent_descriptor).st_ino)
                == (os.fstat(reopened_parent).st_dev, os.fstat(reopened_parent).st_ino),
                f"{label} ancestor path changed while it was read",
            )
        finally:
            os.close(reopened_parent)
    except OSError as error:
        fail(f"cannot read {label} {path}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"{label} changed while it was read",
    )
    require(
        (after.st_dev, after.st_ino) == (path_after.st_dev, path_after.st_ino)
        and stat.S_ISREG(path_after.st_mode)
        and not stat.S_ISLNK(path_after.st_mode),
        f"{label} path changed while it was read",
    )
    return raw, (after.st_dev, after.st_ino)


def stable_regular_bytes(
    path: pathlib.Path, label: str, *, maximum: int | None = None
) -> bytes:
    return stable_regular_measure(path, label, maximum=maximum)[0]


def file_identity(path: pathlib.Path, label: str = "file") -> dict[str, Any]:
    raw = stable_regular_bytes(path, label)
    return {"sha256": sha256_bytes(raw), "bytes": len(raw)}


def inode_record(path: pathlib.Path, label: str) -> dict[str, int]:
    try:
        absolute = absolute_no_symlink_path(path, label)
        status = absolute.lstat()
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    require(stat.S_ISREG(status.st_mode), f"{label} is not regular")
    return {"device": status.st_dev, "inode": status.st_ino}


def identity_record(
    value: Any, label: str, *, file_key: str = "path"
) -> dict[str, Any]:
    record = exact(value, {file_key, "sha256", "bytes"}, label)
    require(
        isinstance(record[file_key], str) and bool(record[file_key]),
        f"{label}.{file_key} is empty",
    )
    canonical_sha(record["sha256"], f"{label}.sha256")
    integer(record["bytes"], f"{label}.bytes", minimum=1)
    return record


def canonical_absolute_recorded_path(value: Any, label: str) -> pathlib.PurePosixPath:
    require(isinstance(value, str) and bool(value), f"{label} is empty")
    require(
        "\0" not in value and not value.startswith("//"), f"{label} is not canonical"
    )
    path = pathlib.PurePosixPath(value)
    require(
        path.is_absolute()
        and len(path.parts) > 1
        and value == str(path)
        and "." not in path.parts
        and ".." not in path.parts,
        f"{label} is not a canonical absolute path",
    )
    return path


def same_identity(actual: dict[str, Any], recorded: dict[str, Any], label: str) -> None:
    require(actual["sha256"] == recorded["sha256"], f"{label} SHA-256 differs")
    require(actual["bytes"] == recorded["bytes"], f"{label} byte length differs")


def measurement_record(value: Any, label: str) -> dict[str, Any]:
    record = exact(value, {"sha256", "bytes"}, label)
    canonical_sha(record["sha256"], f"{label}.sha256")
    integer(record["bytes"], f"{label}.bytes", minimum=1)
    return record


def image_audit_transcript_has_failure(lines: list[str]) -> bool:
    return (
        re.search(
            r"\b(?:panic|fatal|fail|failed|failure)\b",
            "\n".join(lines[:-2]),
            re.IGNORECASE,
        )
        is not None
    )


def validate_image_audit(
    raw: bytes,
    *,
    source: str,
    challenge: str,
    source_materialization: dict[str, Any],
    runtime_attestation: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    tools: dict[str, dict[str, Any]],
    label: str,
) -> tuple[dict[str, Any], str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    lines = text.splitlines()
    require(
        raw.endswith((C84_IMAGE_PASS + "\n").encode("utf-8"))
        and len(lines) >= 2
        and lines[-1] == C84_IMAGE_PASS,
        f"{label} terminal PASS differs",
    )
    require(
        text.count(C84_IMAGE_PASS) == 1
        and text.count(f'"schema":"{C84_IMAGE_REPORT_SCHEMA}"') == 1,
        f"{label} report/PASS is not unique",
    )
    require(
        not image_audit_transcript_has_failure(lines),
        f"{label} transcript contains a failure token",
    )
    report_line = lines[-2]
    report = exact(
        strict_json_bytes(report_line.encode("utf-8"), f"{label} report"),
        {
            "schema",
            "version",
            "source_commit",
            "challenge",
            "source_materialization",
            "runtime_attestation",
            "artifacts",
            "tools",
        },
        f"{label} report",
    )
    require(
        report["schema"] == C84_IMAGE_REPORT_SCHEMA
        and type(report["version"]) is int
        and report["version"] == 2
        and report["source_commit"] == source
        and report["challenge"] == challenge,
        f"{label} report identity differs",
    )
    require(
        report["source_materialization"] == source_materialization,
        f"{label} source materialization differs",
    )
    require(
        report["runtime_attestation"] == runtime_attestation,
        f"{label} runtime attestation differs",
    )
    require(
        json.dumps(report, sort_keys=True, separators=(",", ":")) == report_line,
        f"{label} report is not canonical JSON",
    )
    report_artifacts = exact(
        report["artifacts"], set(IMAGE_REPORT_ARTIFACT_ROLES), f"{label} artifacts"
    )
    report_tools = exact(
        report["tools"], set(IMAGE_REPORT_TOOL_ROLES), f"{label} tools"
    )
    for report_role, envelope_role in IMAGE_REPORT_ARTIFACT_ROLES.items():
        measured = measurement_record(
            report_artifacts[report_role], f"{label} artifact {report_role}"
        )
        expected = identity_record(
            artifacts[envelope_role], f"{label} package artifact {envelope_role}"
        )
        same_identity(measured, expected, f"{label} artifact {report_role}")
    for report_role, envelope_role in IMAGE_REPORT_TOOL_ROLES.items():
        measured = measurement_record(
            report_tools[report_role], f"{label} tool {report_role}"
        )
        expected = identity_record(
            tools[envelope_role], f"{label} package tool {envelope_role}"
        )
        same_identity(measured, expected, f"{label} tool {report_role}")
    return report, sha256_bytes(report_line.encode("utf-8"))


def canonical_content_envelope(
    value: Any, schema: str, label: str, *, version: int = 1
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = exact(
        value, {"schema", "version", "status", "content_sha256", "content"}, label
    )
    require(
        root["schema"] == schema
        and type(root["version"]) is int
        and root["version"] == version
        and root["status"] == "closed",
        f"{label} identity/status differs",
    )
    canonical_sha(root["content_sha256"], f"{label}.content_sha256")
    require(isinstance(root["content"], dict), f"{label}.content is not an object")
    rendered = json.dumps(
        root["content"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    require(
        sha256_bytes(rendered) == root["content_sha256"],
        f"{label} content address differs",
    )
    return root, root["content"]


def make_content_envelope(
    schema: str, content: dict[str, Any], *, version: int = 1
) -> dict[str, Any]:
    require_finite_json(content, f"{schema} content")
    rendered = json.dumps(content, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "schema": schema,
        "version": version,
        "status": "closed",
        "content_sha256": sha256_bytes(rendered),
        "content": content,
    }


def run_checked(command: list[str], *, label: str, cwd: pathlib.Path = ROOT) -> str:
    environment = {
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as error:
        fail(f"cannot invoke {label}: {error}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        fail(f"{label} failed: {detail}")
    return completed.stdout


def canonical_root_file(
    path: pathlib.Path,
    *,
    schema: str,
    version: int,
    label: str,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    raw = stable_regular_bytes(path, label, maximum=64 * 1024 * 1024)
    root, _content = canonical_content_envelope(
        strict_json_bytes(raw, label), schema, label, version=version
    )
    canonical = (
        json.dumps(root, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    require(raw == canonical, f"{label} is not canonical JSON")
    return root, raw, {"sha256": sha256_bytes(raw), "bytes": len(raw)}


def source_materialization_path(source: str, challenge: str) -> pathlib.Path:
    return (
        ROOT
        / "target/c84-source-materialization"
        / source
        / challenge
        / "source-materialization-envelope.json"
    )


def runtime_file_record(
    value: Any,
    *,
    filename: str,
    identity: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    record = identity_record(value, label)
    require(record["path"] == filename, f"{label} path differs")
    same_identity(identity, record, label)
    return record


def validate_provenance_roots(
    *,
    source: str,
    challenge: str,
    source_root: dict[str, Any],
    package_attestation: dict[str, Any],
    verifier_attestation: dict[str, Any],
    closure_root: dict[str, Any],
    package_attestation_identity: dict[str, Any],
    verifier_attestation_identity: dict[str, Any],
) -> None:
    source_root, _ = canonical_content_envelope(
        source_root,
        SOURCE_MATERIALIZATION_SCHEMA,
        "C8.4 source materialization envelope",
        version=1,
    )
    package_attestation, _ = canonical_content_envelope(
        package_attestation,
        RUNTIME_ATTESTATION_SCHEMA,
        "C8.4 package runtime attestation",
        version=1,
    )
    verifier_attestation, _ = canonical_content_envelope(
        verifier_attestation,
        RUNTIME_ATTESTATION_SCHEMA,
        "C8.4 verifier runtime attestation",
        version=1,
    )
    closure_root, _ = canonical_content_envelope(
        closure_root,
        RUNTIME_CLOSURE_SCHEMA,
        "C8.4 container runtime closure",
        version=1,
    )
    source_content = exact(
        source_root["content"],
        {
            "bundles",
            "challenge",
            "clone_git_admin",
            "command",
            "frozen",
            "git",
            "independence",
            "materialization",
            "patch",
            "snapshot",
            "source",
            "source_commit",
            "submodules",
            "timestamps_utc",
        },
        "C8.4 source materialization content",
    )
    require(
        source_content["source_commit"] == source
        and source_content["challenge"] == challenge,
        "C8.4 source materialization campaign identity differs",
    )

    def attestation(value: dict[str, Any], mode: str) -> dict[str, Any]:
        content = exact(
            value["content"],
            {
                "capability",
                "challenge",
                "host_preinspect",
                "host_preinspect_identity",
                "mode",
                "source_commit",
                "source_materialization_content_sha256",
                "witness",
            },
            f"C8.4 {mode} runtime attestation content",
        )
        require(
            content["capability"] == RUNTIME_CAPABILITY
            and content["source_commit"] == source
            and content["challenge"] == challenge
            and content["mode"] == mode
            and content["source_materialization_content_sha256"]
            == source_root["content_sha256"],
            f"C8.4 {mode} runtime attestation identity differs",
        )
        require(
            isinstance(content["host_preinspect"], dict)
            and isinstance(content["witness"], dict),
            f"C8.4 {mode} runtime attestation witness is malformed",
        )
        measurement_record(
            content["host_preinspect_identity"],
            f"C8.4 {mode} host-preinspect identity",
        )
        return content

    attestation(package_attestation, "package")
    attestation(verifier_attestation, "verify")
    measurement_record(
        package_attestation_identity, "C8.4 package runtime-attestation file"
    )
    measurement_record(
        verifier_attestation_identity, "C8.4 verifier runtime-attestation file"
    )

    closure = exact(
        closure_root["content"],
        {
            "artifacts",
            "capability",
            "challenge",
            "image",
            "package",
            "platform",
            "runs",
            "sdk_mount",
            "source",
            "source_commit",
        },
        "C8.4 container runtime closure content",
    )
    require(
        closure["capability"] == RUNTIME_CAPABILITY
        and closure["source_commit"] == source
        and closure["challenge"] == challenge
        and closure["platform"] == SDK_CONTAINER_PLATFORM,
        "C8.4 container runtime closure campaign identity differs",
    )
    closure_source = exact(
        closure["source"],
        {"materialization_content_sha256", "root"},
        "C8.4 container runtime closure source",
    )
    require(
        closure_source
        == {
            "materialization_content_sha256": source_root["content_sha256"],
            "root": str(ROOT),
        },
        "C8.4 container runtime closure source differs",
    )
    image = exact(
        closure["image"],
        {
            "architecture",
            "descriptor",
            "id",
            "inspect",
            "os",
            "reference",
            "repo_digest",
        },
        "C8.4 container runtime closure image",
    )
    require(
        image["architecture"] == "amd64"
        and image["os"] == "linux"
        and image["reference"] == SDK_CONTAINER_REFERENCE
        and image["repo_digest"] == SDK_CONTAINER_REFERENCE
        and isinstance(image["id"], str)
        and CONTAINER_DIGEST.fullmatch(image["id"]) is not None
        and isinstance(image["inspect"], dict),
        "C8.4 container runtime closure image differs",
    )
    exact(
        closure["sdk_mount"],
        {"destination", "kind", "read_only", "source"},
        "C8.4 container runtime SDK mount",
    )
    closure_package = exact(
        closure["package"],
        {"build_envelope", "image_verifier_audit", "package_envelope"},
        "C8.4 container runtime package records",
    )
    for name, record in closure_package.items():
        identity_record(record, f"C8.4 container runtime package {name}")
    runs = exact(
        closure["runs"], {"package", "verifier"}, "C8.4 container runtime runs"
    )
    expected_runs = {
        "package": (package_attestation, package_attestation_identity),
        "verifier": (verifier_attestation, verifier_attestation_identity),
    }
    container_ids: list[str] = []
    for mode, (expected_root, expected_identity) in expected_runs.items():
        run = exact(
            runs[mode],
            {
                "attestation",
                "attestation_identity",
                "container_id",
                "container_postinspect",
                "container_preinspect",
                "host_preinspect",
                "host_preinspect_identity",
                "operations",
                "wait_exit_code",
            },
            f"C8.4 container runtime {mode} run",
        )
        require(
            run["attestation"] == expected_root
            and run["attestation_identity"] == expected_identity
            and type(run["wait_exit_code"]) is int
            and run["wait_exit_code"] == 0,
            f"C8.4 container runtime {mode} attestation/exit differs",
        )
        container_id = run["container_id"]
        require(
            isinstance(container_id, str)
            and re.fullmatch(r"[0-9a-f]{64}", container_id) is not None,
            f"C8.4 container runtime {mode} container id is malformed",
        )
        container_ids.append(container_id)
    require(
        len(set(container_ids)) == 2,
        "C8.4 package and verifier reused one runtime container",
    )
    closure_artifacts = exact(
        closure["artifacts"],
        set(RUNTIME_ARTIFACT_FILES),
        "C8.4 container runtime artifacts",
    )
    runtime_file_record(
        closure_artifacts["package_attestation"],
        filename=RUNTIME_ARTIFACT_FILES["package_attestation"],
        identity=package_attestation_identity,
        label="C8.4 closure package runtime attestation",
    )
    runtime_file_record(
        closure_artifacts["verifier_attestation"],
        filename=RUNTIME_ARTIFACT_FILES["verifier_attestation"],
        identity=verifier_attestation_identity,
        label="C8.4 closure verifier runtime attestation",
    )
    require(
        "operator-declared"
        not in json.dumps(closure_root, sort_keys=True, separators=(",", ":")),
        "C8.4 container runtime closure contains old operator-declared provenance",
    )


@dataclass(frozen=True)
class ProvenanceEvidence:
    source_path: pathlib.Path
    source_root: dict[str, Any]
    source_bytes: bytes
    source_identity: dict[str, Any]
    package_attestation_root: dict[str, Any]
    package_attestation_bytes: bytes
    package_attestation_identity: dict[str, Any]
    verifier_attestation_root: dict[str, Any]
    verifier_attestation_bytes: bytes
    verifier_attestation_identity: dict[str, Any]
    closure_root: dict[str, Any]
    closure_bytes: bytes
    closure_identity: dict[str, Any]


def validate_live_provenance(source: str, challenge: str) -> ProvenanceEvidence:
    source_path = source_materialization_path(source, challenge)
    run_checked(
        [
            sys.executable,
            "-I",
            "-B",
            str(C84_SOURCE_MATERIALIZER),
            "verify",
            "--destination",
            str(ROOT),
            "--source-commit",
            source,
            "--challenge",
            challenge,
        ],
        label="C8.4 frozen source materialization verifier",
    )
    run_checked(
        [
            sys.executable,
            "-I",
            "-B",
            str(C84_DOCKER_RUNTIME),
            "verify",
            "--closure",
            str(CANONICAL_CONTAINER_RUNTIME_CLOSURE),
            "--source-commit",
            source,
            "--challenge",
            challenge,
        ],
        label="C8.4 Docker runtime closure verifier",
    )
    source_root, source_raw, source_identity = canonical_root_file(
        source_path,
        schema=SOURCE_MATERIALIZATION_SCHEMA,
        version=1,
        label="C8.4 source materialization envelope",
    )
    package_root, package_raw, package_identity = canonical_root_file(
        CANONICAL_PACKAGE_RUNTIME_ATTESTATION,
        schema=RUNTIME_ATTESTATION_SCHEMA,
        version=1,
        label="C8.4 package runtime attestation",
    )
    verifier_root, verifier_raw, verifier_identity = canonical_root_file(
        CANONICAL_VERIFIER_RUNTIME_ATTESTATION,
        schema=RUNTIME_ATTESTATION_SCHEMA,
        version=1,
        label="C8.4 verifier runtime attestation",
    )
    closure_root, closure_raw, closure_identity = canonical_root_file(
        CANONICAL_CONTAINER_RUNTIME_CLOSURE,
        schema=RUNTIME_CLOSURE_SCHEMA,
        version=1,
        label="C8.4 container runtime closure",
    )
    validate_provenance_roots(
        source=source,
        challenge=challenge,
        source_root=source_root,
        package_attestation=package_root,
        verifier_attestation=verifier_root,
        closure_root=closure_root,
        package_attestation_identity=package_identity,
        verifier_attestation_identity=verifier_identity,
    )
    return ProvenanceEvidence(
        source_path=source_path,
        source_root=source_root,
        source_bytes=source_raw,
        source_identity=source_identity,
        package_attestation_root=package_root,
        package_attestation_bytes=package_raw,
        package_attestation_identity=package_identity,
        verifier_attestation_root=verifier_root,
        verifier_attestation_bytes=verifier_raw,
        verifier_attestation_identity=verifier_identity,
        closure_root=closure_root,
        closure_bytes=closure_raw,
        closure_identity=closure_identity,
    )


def frozen_git_bytes(arguments: list[str], label: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    try:
        completed = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.file.allow=only",
                "-C",
                str(ROOT),
                *arguments,
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot invoke frozen-source Git for {label}: {error}")
    require(
        completed.returncode == 0,
        f"frozen-source Git {label} failed: "
        f"{completed.stderr.decode(errors='replace').strip()}",
    )
    return completed.stdout


def validate_real_directory_tree(
    root: pathlib.Path, expected: Sequence[str], label: str
) -> dict[str, bytes]:
    expected_set = set(expected)
    require(len(expected_set) == len(expected), f"{label} expected paths repeat")
    expected_directories: set[str] = set()
    for relative in expected_set:
        pure = pathlib.PurePosixPath(relative)
        require(
            not pure.is_absolute() and ".." not in pure.parts and "." not in pure.parts,
            f"{label} expected path is unsafe: {relative!r}",
        )
        parent = pure.parent
        while parent != pathlib.PurePosixPath("."):
            expected_directories.add(str(parent))
            parent = parent.parent
    root, root_fd = open_directory_chain(root, f"{label} root")
    root_identity = (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino)
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    identities: set[tuple[int, int]] = set()
    result: dict[str, bytes] = {}

    def visit(directory_fd: int, prefix: str) -> None:
        try:
            names = os.listdir(directory_fd)
        except OSError as error:
            fail(f"cannot enumerate {label} {prefix or '.'}: {error}")
        require(len(names) == len(set(names)), f"{label} directory entries repeat")
        for name in sorted(names):
            require(
                name not in {"", ".", ".."} and "/" not in name,
                f"{label} contains unsafe directory entry {name!r}",
            )
            relative = f"{prefix}/{name}" if prefix else name
            try:
                status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                fail(f"cannot inspect {label} {relative}: {error}")
            if stat.S_ISDIR(status.st_mode):
                actual_directories.add(relative)
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_fd,
                    )
                except OSError as error:
                    fail(f"cannot open {label} directory {relative}: {error}")
                try:
                    opened = os.fstat(child_fd)
                    require(
                        (opened.st_dev, opened.st_ino)
                        == (status.st_dev, status.st_ino),
                        f"{label} directory changed before open: {relative}",
                    )
                    visit(child_fd, relative)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    require(
                        stat.S_ISDIR(after.st_mode)
                        and (after.st_dev, after.st_ino)
                        == (opened.st_dev, opened.st_ino),
                        f"{label} directory changed while read: {relative}",
                    )
                finally:
                    os.close(child_fd)
                continue
            require(
                stat.S_ISREG(status.st_mode),
                f"{label} contains symlink/special file {relative}",
            )
            actual_files.add(relative)
            try:
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
            except OSError as error:
                fail(f"cannot open {label} file {relative}: {error}")
            try:
                before = os.fstat(file_fd)
                require(
                    stat.S_ISREG(before.st_mode)
                    and (before.st_dev, before.st_ino)
                    == (status.st_dev, status.st_ino),
                    f"{label} file changed before open: {relative}",
                )
                require(
                    0 < before.st_size <= MAX_RAW_BYTES,
                    f"{label} file size is invalid: {relative}",
                )
                chunks: list[bytes] = []
                consumed = 0
                while chunk := os.read(file_fd, 4 * 1024 * 1024):
                    consumed += len(chunk)
                    require(
                        consumed <= MAX_RAW_BYTES,
                        f"{label} file exceeds limit: {relative}",
                    )
                    chunks.append(chunk)
                after = os.fstat(file_fd)
                named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                require(
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    and (after.st_dev, after.st_ino)
                    == (named_after.st_dev, named_after.st_ino),
                    f"{label} file changed while read: {relative}",
                )
                inode = (after.st_dev, after.st_ino)
                require(
                    inode not in identities,
                    f"{label} contains hardlink alias {relative}",
                )
                identities.add(inode)
                result[relative] = b"".join(chunks)
            finally:
                os.close(file_fd)

    try:
        visit(root_fd, "")
        _root_again, reopened_fd = open_directory_chain(root, f"{label} root recheck")
        try:
            require(
                (os.fstat(reopened_fd).st_dev, os.fstat(reopened_fd).st_ino)
                == root_identity,
                f"{label} root/ancestor path changed while read",
            )
        finally:
            os.close(reopened_fd)
    finally:
        os.close(root_fd)
    require(
        actual_files == expected_set,
        f"{label} file members differ: {sorted(actual_files ^ expected_set)}",
    )
    require(
        actual_directories == expected_directories,
        f"{label} directory members differ: {sorted(actual_directories ^ expected_directories)}",
    )
    return result


def canonical_tree_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(b"vibeos.c84.c83-precondition-tree.v1\0")
    for relative in sorted(files):
        encoded = relative.encode("utf-8")
        raw = files[relative]
        digest.update(encoded)
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    return digest.hexdigest()


def require_matching_c83_trees(
    external: dict[str, bytes], frozen: dict[str, bytes]
) -> None:
    require(
        external == frozen,
        "C8.3 evidence differs byte-for-byte from the frozen C8.4 source",
    )


def verify_c83_precondition(
    root: pathlib.Path,
    *,
    c84_source: str,
    c83_source: str,
    c83_challenge: str,
) -> dict[str, Any]:
    c84_source = canonical_source(c84_source, "C8.4 preparation commit")
    c83_source = canonical_source(c83_source, "expected C8.3 source")
    c83_challenge = canonical_challenge(c83_challenge, "expected C8.3 challenge")
    frozen_root = ROOT / "benchmarks/wasm-runtime"
    external = validate_real_directory_tree(root, C83_RELATIVE_FILES, "C8.3 evidence")
    frozen = validate_real_directory_tree(
        frozen_root, C83_RELATIVE_FILES, "frozen-source C8.3 evidence"
    )
    require_matching_c83_trees(external, frozen)
    head = frozen_git_bytes(["rev-parse", "HEAD"], "C8.4 source HEAD")
    require(
        head.decode().strip() == c84_source,
        "frozen C8.4 source HEAD differs from the supplied commit",
    )
    tree_oid = (
        frozen_git_bytes(
            ["rev-parse", "--verify", f"{c84_source}:benchmarks/wasm-runtime"],
            "C8.3 tree identity",
        )
        .decode()
        .strip()
    )
    require(
        re.fullmatch(r"[0-9a-f]{40,64}", tree_oid) is not None,
        "frozen-source C8.3 Git tree id is malformed",
    )
    verifier = C83_EVIDENCE_VERIFIER
    verifier_raw = stable_regular_bytes(verifier, "frozen-source C8.3 verifier")
    run_checked(
        [
            sys.executable,
            "-I",
            "-B",
            str(verifier),
            "--evidence-root",
            str(frozen_root),
            "--expect-source",
            c83_source,
            "--expect-challenge",
            c83_challenge,
        ],
        cwd=ROOT,
        label="frozen-source complete C8.3 evidence verifier",
    )
    external_closed = validate_real_directory_tree(
        root, C83_RELATIVE_FILES, "closed C8.3 evidence"
    )
    frozen_closed = validate_real_directory_tree(
        frozen_root, C83_RELATIVE_FILES, "closed frozen-source C8.3 evidence"
    )
    require(external_closed == external, "C8.3 evidence changed during verification")
    require(frozen_closed == frozen, "frozen C8.3 evidence changed during verification")
    require_matching_c83_trees(external_closed, frozen_closed)
    require(
        stable_regular_bytes(verifier, "closed frozen-source C8.3 verifier")
        == verifier_raw,
        "frozen C8.3 verifier changed during verification",
    )
    summary = strict_json_bytes(frozen["qemu/summary.json"], "C8.3 QEMU summary")
    require(isinstance(summary, dict), "C8.3 QEMU summary is not an object")
    require(summary.get("source_commit") == c83_source, "C8.3 summary source differs")
    require(summary.get("challenge") == c83_challenge, "C8.3 summary challenge differs")
    run_id = canonical_sha(summary.get("run_id"), "C8.3 run id")
    return {
        "status": "verified-complete",
        "source_commit": c83_source,
        "challenge": c83_challenge,
        "run_id": run_id,
        "tree_digest_algorithm": "sha256(domain-NUL,path-NUL,length-NUL,bytes)*",
        "tree_sha256": canonical_tree_digest(frozen),
        "git_tree_oid": tree_oid,
        "results": {
            "sha256": sha256_bytes(frozen["RESULTS.md"]),
            "bytes": len(frozen["RESULTS.md"]),
        },
        "verifier": {
            "path": "scripts/verify-c83-evidence.py",
            "sha256": sha256_bytes(verifier_raw),
            "bytes": len(verifier_raw),
        },
        "c84_preparation_commit": c84_source,
        "commit_tree_byte_match": True,
    }


def load_campaign_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_raw = stable_regular_bytes(
        C84_MANIFEST, "C8.4 manifest", maximum=1_048_576
    )
    schema_raw = stable_regular_bytes(
        C84_TRANSCRIPT_SCHEMA, "C8.4 transcript schema", maximum=1_048_576
    )
    manifest = strict_json_bytes(manifest_raw, "C8.4 manifest")
    schema = strict_json_bytes(schema_raw, "C8.4 transcript schema")
    require(
        isinstance(manifest, dict)
        and manifest.get("schema") == "vibeos.wasm-aot-decision.manifest",
        "C8.4 manifest identity differs",
    )
    require(
        manifest.get("suite_id") == "vibeos.c84.aot-decision",
        "C8.4 suite identity differs",
    )
    sampling = manifest.get("sampling")
    require(isinstance(sampling, dict), "C8.4 sampling contract is missing")
    require(
        (
            sampling.get("cold_boots"),
            sampling.get("warmup_per_boot"),
            sampling.get("retained_per_boot"),
            sampling.get("retained_total"),
        )
        == (BOOT_COUNT, WARMUPS_PER_BOOT, RETAINED_PER_BOOT, RETAINED_TOTAL),
        "C8.4 sampling contract differs",
    )
    budget = manifest.get("budget")
    require(
        isinstance(budget, dict) and budget.get("ticks") == BUDGET_TICKS,
        "C8.4 budget differs",
    )
    require(
        isinstance(schema, dict)
        and schema.get("$id")
        == "https://vibeos.invalid/schemas/wasm-aot-decision-v1.json",
        "C8.4 transcript schema identity differs",
    )
    run_checked(
        [sys.executable, "-I", "-B", str(C84_VERIFIER), "--check-manifest"],
        label="C8.4 preparation verifier",
    )
    return manifest, schema


def validate_timestamp_record(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    record = exact(value, keys, label)
    parsed: list[datetime.datetime] = []
    for key in keys:
        timestamp = record[key]
        require(
            isinstance(timestamp, str) and timestamp.endswith("Z"),
            f"{label}.{key} is not UTC",
        )
        try:
            parsed.append(datetime.datetime.fromisoformat(timestamp[:-1] + "+00:00"))
        except ValueError as error:
            fail(f"{label}.{key} is invalid: {error}")
    ordered = [
        record[key] for key in sorted(keys, key=lambda name: list(keys).index(name))
    ]
    del (
        ordered
    )  # The caller supplies semantic order below; parsing is still fail-closed here.
    return record


def validate_build_content(
    build: dict[str, Any],
    source: str,
    challenge: str,
    source_materialization: dict[str, Any],
) -> tuple[str, dict[str, dict[str, Any]]]:
    exact(
        build,
        {
            "platform",
            "source_commit",
            "challenge",
            "run_id",
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
        "C8.4 build content",
    )
    require(
        (build["platform"], build["source_commit"], build["challenge"])
        == (PLATFORM, source, challenge),
        "C8.4 build identity differs",
    )
    run_id = canonical_sha(build["run_id"], "C8.4 build run id")
    source_record = exact(
        build["source"],
        {"root", "head", "materialization"},
        "C8.4 build source",
    )
    require(
        source_record["root"] == "."
        and source_record["head"] == source
        and source_record["materialization"] == source_materialization,
        "C8.4 build source attestation differs",
    )

    toolchain = exact(
        build["toolchain"],
        {
            "channel",
            "rustc_verbose",
            "rustup",
            "cargo",
            "rustc",
            "rustdoc",
            "rust_objcopy",
            "linker",
            "provenance",
        },
        "C8.4 build toolchain",
    )
    require(
        isinstance(toolchain["channel"], str) and bool(toolchain["channel"]),
        "C8.4 toolchain channel is empty",
    )
    require(
        isinstance(toolchain["rustc_verbose"], str)
        and bool(toolchain["rustc_verbose"]),
        "C8.4 rustc pin is empty",
    )
    require(
        toolchain["provenance"]
        == "build-runner-self-measured; package cross-platform live rehash unavailable",
        "C8.4 toolchain provenance differs",
    )
    for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
        tool = identity_record(toolchain[name], f"C8.4 toolchain {name}")
        canonical_absolute_recorded_path(tool["path"], f"C8.4 toolchain {name} path")
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
        "wasm-c84-ssh-managed-child-single-boot-collector",
    ]
    require(build["command"] == expected_command, "C8.4 build command differs")
    artifacts_value = exact(
        build["artifacts"], {"kernel_elf", "kernel_binary"}, "C8.4 build artifacts"
    )
    artifacts = {
        key: identity_record(value, f"C8.4 build artifact {key}")
        for key, value in artifacts_value.items()
    }
    artifact_prefix = f"target/.milkv-duo-wasm-aot-profile.stage.{source}.{challenge}"
    require(
        artifacts["kernel_elf"]["path"]
        == f"{artifact_prefix}/vibeos-milkv-duo-wasm-aot-profile.elf",
        "C8.4 build ELF path differs",
    )
    require(
        artifacts["kernel_binary"]["path"] == f"{artifact_prefix}/vibeos-milkv-duo.bin",
        "C8.4 build binary path differs",
    )
    require(
        build["objcopy_command"]
        == [
            toolchain["rust_objcopy"]["path"],
            "-O",
            "binary",
            artifacts["kernel_elf"]["path"],
            artifacts["kernel_binary"]["path"],
        ],
        "C8.4 objcopy command differs",
    )
    objcopy = exact(
        build["objcopy_environment"],
        {"mode", "allowed_keys", "values"},
        "C8.4 objcopy environment",
    )
    require(
        objcopy["mode"] == "env -i"
        and objcopy["allowed_keys"]
        in (["LC_ALL", "PATH", "TZ"], ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"]),
        "C8.4 objcopy allowlist differs",
    )
    require(
        isinstance(objcopy["values"], dict)
        and set(objcopy["values"]) == set(objcopy["allowed_keys"]),
        "C8.4 objcopy values are not closed",
    )
    require(
        objcopy["values"].get("LC_ALL") == "C"
        and objcopy["values"].get("PATH") == "/usr/bin:/bin"
        and objcopy["values"].get("TZ") == "UTC",
        "C8.4 objcopy values differ",
    )
    environment = exact(
        build["environment"],
        {"mode", "allowed_keys", "values", "cargo_home_isolation"},
        "C8.4 build environment",
    )
    require(
        environment["mode"] == "env -i"
        and environment["allowed_keys"] == BUILD_ENVIRONMENT_KEYS,
        "C8.4 build environment allowlist differs",
    )
    values = exact(
        environment["values"],
        set(BUILD_ENVIRONMENT_KEYS),
        "C8.4 build environment values",
    )
    require(
        values["CARGO_HOME"] == "<isolated-cargo-home>"
        and values["HOME"] == "<isolated-cargo-home>/home"
        and values["TMPDIR"] == "<isolated-cargo-home>/tmp"
        and values["CARGO_INCREMENTAL"] == "0"
        and values["CARGO_NET_OFFLINE"] == "true"
        and values["LC_ALL"] == "C"
        and values["TZ"] == "UTC"
        and values["VIBEOS_C84_SOURCE_COMMIT"] == source
        and values["VIBEOS_C84_CHALLENGE"] == challenge
        and values["RUSTC"] == toolchain["rustc"]["path"]
        and values["RUSTDOC"] == toolchain["rustdoc"]["path"]
        and isinstance(values["SOURCE_DATE_EPOCH"], str)
        and values["SOURCE_DATE_EPOCH"].isdigit(),
        "C8.4 closed build environment values differ",
    )
    target_tail = pathlib.PurePath("target/c84-milkv-build") / source / challenge
    require(
        pathlib.PurePath(values["CARGO_TARGET_DIR"]).parts[-len(target_tail.parts) :]
        == target_tail.parts,
        "C8.4 target directory binding differs",
    )
    isolation = exact(
        environment["cargo_home_isolation"],
        {
            "ambient_config_loaded",
            "temporary",
            "cache_source",
            "registry_cache_symlinked",
            "git_cache_symlinked",
        },
        "C8.4 Cargo-home isolation",
    )
    require(
        isolation["ambient_config_loaded"] is False and isolation["temporary"] is True,
        "C8.4 Cargo home was not isolated",
    )
    require(
        type(isolation["registry_cache_symlinked"]) is bool
        and type(isolation["git_cache_symlinked"]) is bool
        and isinstance(isolation["cache_source"], str),
        "C8.4 Cargo cache attestation differs",
    )
    tools = exact(build["tools"], BUILD_TOOL_KEYS, "C8.4 build tools")
    for name, record in tools.items():
        measured = identity_record(record, f"C8.4 build tool {name}")
        require(
            measured["path"] == REPOSITORY_BUILD_TOOLS[name],
            f"C8.4 build tool {name} path differs",
        )
        same_identity(
            file_identity(ROOT / REPOSITORY_BUILD_TOOLS[name]),
            measured,
            f"C8.4 live build tool {name}",
        )
    timestamps = exact(
        build["timestamps_utc"],
        {"build_started", "build_completed", "envelope_closed"},
        "C8.4 build timestamps",
    )
    parsed = [
        datetime.datetime.fromisoformat(timestamps[name][:-1] + "+00:00")
        if isinstance(timestamps[name], str) and timestamps[name].endswith("Z")
        else fail(f"C8.4 build timestamp {name} is not UTC")
        for name in ("build_started", "build_completed", "envelope_closed")
    ]
    require(parsed == sorted(parsed), "C8.4 build timestamps are reversed")
    return run_id, artifacts


def validate_package_source(
    value: Any, source: str, source_materialization: dict[str, Any]
) -> dict[str, Any]:
    record = exact(
        value,
        {"root", "head", "materialization"},
        "C8.4 package source",
    )
    canonical_absolute_recorded_path(record["root"], "C8.4 package source root")
    require(
        record["root"] == RUNTIME_SOURCE_ROOT
        and record["head"] == source
        and record["materialization"] == source_materialization,
        "C8.4 package source attestation differs",
    )
    return record


def validate_package_environment(value: Any, source: str, challenge: str) -> None:
    environment = exact(
        value, {"fit_tools", "genimage", "image_verifier"}, "C8.4 package environment"
    )
    keysets = {
        "fit_tools": ["LC_ALL", "PATH", "TZ"],
        "genimage": ["HOME", "LC_ALL", "LD_LIBRARY_PATH", "PATH", "TZ"],
        "image_verifier": [
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_OPTIONAL_LOCKS",
            "HOME",
            "LC_ALL",
            "PATH",
            "TZ",
            "VIBEOS_C84_CHALLENGE",
            "VIBEOS_C84_SDK_CONTAINER_DIGEST",
            "VIBEOS_C84_SOURCE_COMMIT",
        ],
    }
    values: dict[str, dict[str, Any]] = {}
    for name, keys in keysets.items():
        record = exact(
            environment[name],
            {"mode", "allowed_keys", "values"},
            f"C8.4 package environment {name}",
        )
        require(
            record["mode"] == "env -i" and record["allowed_keys"] == keys,
            f"C8.4 package environment {name} allowlist differs",
        )
        values[name] = exact(
            record["values"], set(keys), f"C8.4 package environment {name} values"
        )
    require(
        values["fit_tools"] == {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
        "C8.4 FIT environment differs",
    )
    genimage = values["genimage"]
    require(
        genimage["HOME"] == "/nonexistent"
        and genimage["LC_ALL"] == "C"
        and genimage["TZ"] == "UTC"
        and isinstance(genimage["LD_LIBRARY_PATH"], str)
        and bool(genimage["LD_LIBRARY_PATH"])
        and isinstance(genimage["PATH"], str)
        and genimage["PATH"].endswith(":/usr/bin:/bin:/usr/sbin:/sbin"),
        "C8.4 genimage environment differs",
    )
    verifier = values["image_verifier"]
    require(
        verifier["GIT_CONFIG_GLOBAL"] == "/etc/vibeos-c84.gitconfig"
        and verifier["GIT_CONFIG_NOSYSTEM"] == "1"
        and verifier["GIT_NO_REPLACE_OBJECTS"] == "1"
        and verifier["GIT_OPTIONAL_LOCKS"] == "0"
        and verifier["HOME"] == "/nonexistent"
        and verifier["LC_ALL"] == "C"
        and verifier["TZ"] == "UTC"
        and verifier["VIBEOS_C84_SOURCE_COMMIT"] == source
        and verifier["VIBEOS_C84_CHALLENGE"] == challenge
        and verifier["VIBEOS_C84_SDK_CONTAINER_DIGEST"] == SDK_CONTAINER_DIGEST
        and verifier["PATH"] == "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "C8.4 image-verifier environment differs",
    )


def validate_package_recorded_paths(
    *,
    package_source: dict[str, Any],
    sdk: dict[str, Any],
    build_envelope: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    audit_log: dict[str, Any],
    tools: dict[str, Any],
) -> None:
    recorded_source_root = canonical_absolute_recorded_path(
        package_source["root"], "C8.4 package source root"
    )
    recorded_sdk_root = canonical_absolute_recorded_path(
        sdk["root"], "C8.4 package SDK root"
    )
    recorded_kernel_elf = canonical_absolute_recorded_path(
        artifacts["kernel_elf"]["path"], "C8.4 package kernel ELF path"
    )
    recorded_artifact_root = recorded_kernel_elf.parent
    require(
        recorded_artifact_root
        == recorded_source_root / "target/milkv-duo-wasm-aot-profile",
        "C8.4 package artifact root differs from the fixed source target",
    )
    require(
        build_envelope["path"] == str(recorded_artifact_root / "build-envelope.json"),
        "C8.4 package build-envelope path differs",
    )
    require(
        audit_log["path"] == str(recorded_artifact_root / "image-verifier-audit.log"),
        "C8.4 package audit-log path differs",
    )
    artifact_paths = {
        "kernel_elf": recorded_artifact_root / "vibeos-milkv-duo-wasm-aot-profile.elf",
        "kernel_binary": recorded_artifact_root / "vibeos-milkv-duo.bin",
        "packaged_fit_source": recorded_artifact_root / "milkv-duo.its",
        "packaged_dtb": recorded_artifact_root / "cv1800b_milkv_duo_sd.dtb",
        "fit_boot_sd": recorded_artifact_root / "boot.sd",
        "full_sd_image": recorded_artifact_root
        / "vibeos-milkv-duo-wasm-aot-profile-sd.img",
        "sdk_fip": recorded_sdk_root / "install/soc_cv1800b_milkv_duo_sd/fip.bin",
        "sdk_dtb": recorded_sdk_root
        / "linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb",
    }
    for role, expected in artifact_paths.items():
        require(
            artifacts[role]["path"] == str(expected),
            f"C8.4 package artifact {role} recorded path differs",
        )
    for role, relative in REPOSITORY_PACKAGE_TOOLS.items():
        record = identity_record(tools[role], f"C8.4 package tool {role}")
        require(
            record["path"] == str(recorded_source_root / relative),
            f"C8.4 package tool {role} recorded path differs",
        )
        same_identity(
            file_identity(ROOT / relative, f"live C8.4 package tool {role}"),
            record,
            f"C8.4 live package tool {role}",
        )
    sdk_tool_paths = {
        "sdk_mkimage": recorded_sdk_root
        / "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/mkimage",
        "sdk_dumpimage": recorded_sdk_root
        / "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/dumpimage",
    }
    for role, expected in sdk_tool_paths.items():
        require(
            tools[role]["path"] == str(expected),
            f"C8.4 package tool {role} recorded path differs",
        )
    genimage_paths = {
        recorded_sdk_root
        / "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage",
        recorded_sdk_root
        / "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/per-package/host-genimage/host/bin/genimage",
    }
    require(
        tools["sdk_genimage"]["path"] in {str(path) for path in genimage_paths},
        "C8.4 package tool sdk_genimage recorded path differs",
    )
    external_roles = (
        PACKAGE_TOOL_KEYS
        - set(REPOSITORY_PACKAGE_TOOLS)
        - {
            "sdk_mkimage",
            "sdk_dumpimage",
            "sdk_genimage",
        }
    )
    for role in external_roles:
        canonical_absolute_recorded_path(
            tools[role]["path"], f"C8.4 package tool {role} path"
        )


@dataclass(frozen=True)
class PackageEvidence:
    package_bytes: bytes
    build_bytes: bytes
    audit_bytes: bytes
    package_identity: dict[str, Any]
    build_identity: dict[str, Any]
    audit_identity: dict[str, Any]
    artifacts: dict[str, dict[str, Any]]
    package_content_sha256: str
    build_content_sha256: str
    run_id: str


def validate_package_evidence(
    source: str, challenge: str, provenance: ProvenanceEvidence
) -> PackageEvidence:
    package_raw = stable_regular_bytes(
        CANONICAL_PACKAGE_ENVELOPE, "C8.4 package envelope", maximum=16_777_216
    )
    build_raw = stable_regular_bytes(
        CANONICAL_BUILD_ENVELOPE, "C8.4 build envelope", maximum=16_777_216
    )
    audit_raw = stable_regular_bytes(
        CANONICAL_IMAGE_AUDIT, "C8.4 image verifier audit", maximum=16_777_216
    )
    package_root, package = canonical_content_envelope(
        strict_json_bytes(package_raw, "C8.4 package envelope"),
        "vibeos.c84.duo-wasm-aot-profile.package-envelope",
        "C8.4 package envelope",
        version=2,
    )
    build_root, build = canonical_content_envelope(
        strict_json_bytes(build_raw, "C8.4 build envelope"),
        "vibeos.c84.duo-wasm-aot-profile.build-envelope",
        "C8.4 build envelope",
        version=2,
    )
    run_id, build_artifacts = validate_build_content(
        build, source, challenge, provenance.source_root
    )
    expected_run_id = campaign_run_id(
        source,
        challenge,
        stable_regular_bytes(C84_MANIFEST, "C8.4 run-id manifest", maximum=1_048_576),
        stable_regular_bytes(
            C84_TRANSCRIPT_SCHEMA,
            "C8.4 run-id transcript schema",
            maximum=1_048_576,
        ),
        "C8.4 package",
    )
    require_run_id_binding(expected_run_id, build=run_id)

    exact(
        package,
        {
            "platform",
            "source_commit",
            "challenge",
            "run_id",
            "source",
            "runtime_attestation",
            "sdk",
            "build",
            "command",
            "environment",
            "artifacts",
            "verifier",
            "tools",
            "timestamps_utc",
        },
        "C8.4 package content",
    )
    require(
        (package["platform"], package["source_commit"], package["challenge"])
        == (PLATFORM, source, challenge),
        "C8.4 package identity differs",
    )
    require_run_id_binding(expected_run_id, build=run_id, package=package["run_id"])
    package_source = validate_package_source(
        package["source"], source, provenance.source_root
    )
    require(
        package["runtime_attestation"] == provenance.package_attestation_root,
        "C8.4 package runtime attestation differs from the live attestation",
    )
    sdk = exact(
        package["sdk"],
        {
            "root",
            "commit",
            "commit_provenance",
            "image_digest",
            "image_id",
            "platform",
            "runtime_provenance",
            "worktree_clean",
            "status_policy",
        },
        "C8.4 package SDK",
    )
    canonical_absolute_recorded_path(sdk["root"], "C8.4 SDK root")
    require(sdk["commit"] == SDK_COMMIT, f"C8.4 SDK commit must be {SDK_COMMIT}")
    require(
        sdk["image_digest"] == SDK_CONTAINER_DIGEST,
        f"C8.4 SDK container digest must be {SDK_CONTAINER_DIGEST}",
    )
    require(
        sdk["root"] == RUNTIME_SDK_ROOT
        and sdk["commit_provenance"]
        == "host-observed read-only SDK mount; in-container Git HEAD and clean worktree verified"
        and sdk["runtime_provenance"] == RUNTIME_CAPABILITY
        and sdk["image_id"] == provenance.closure_root["content"]["image"]["id"]
        and sdk["platform"] == SDK_CONTAINER_PLATFORM,
        "C8.4 SDK provenance differs",
    )
    require(
        sdk["worktree_clean"] is True and sdk["status_policy"] == STRICT_STATUS_POLICY,
        "C8.4 SDK was not clean",
    )
    require(
        package["command"]
        == ["scripts/package-milkv-duo-sdk.sh", "--wasm-aot-profile", "<sdk-root>"],
        "C8.4 package command differs",
    )
    validate_package_environment(package["environment"], source, challenge)
    build_ref = exact(
        package["build"], {"content_sha256", "envelope"}, "C8.4 package build reference"
    )
    require(
        build_ref["content_sha256"] == build_root["content_sha256"],
        "C8.4 package/build content address differs",
    )
    build_envelope_record = identity_record(
        build_ref["envelope"], "C8.4 packaged build envelope"
    )
    same_identity(
        file_identity(CANONICAL_BUILD_ENVELOPE),
        build_envelope_record,
        "C8.4 packaged build envelope",
    )
    artifacts_value = exact(
        package["artifacts"],
        set(CANONICAL_ARTIFACTS)
        | {"packaged_fit_source", "packaged_dtb", "sdk_fip", "sdk_dtb"},
        "C8.4 package artifacts",
    )
    artifacts = {
        key: identity_record(value, f"C8.4 package artifact {key}")
        for key, value in artifacts_value.items()
    }
    for key, path in CANONICAL_ARTIFACTS.items():
        local = file_identity(path, f"C8.4 canonical artifact {key}")
        same_identity(local, artifacts[key], f"C8.4 canonical artifact {key}")
    for key in ("kernel_elf", "kernel_binary"):
        same_identity(
            artifacts[key], build_artifacts[key], f"C8.4 build/package artifact {key}"
        )
    verifier = exact(
        package["verifier"],
        {
            "status",
            "exit_code",
            "exact_pass_marker",
            "report",
            "report_sha256",
            "audit_log",
            "invocation",
        },
        "C8.4 package image verifier",
    )
    require(
        verifier["status"] == "PASS"
        and type(verifier["exit_code"]) is int
        and verifier["exit_code"] == 0
        and verifier["exact_pass_marker"] == C84_IMAGE_PASS,
        "C8.4 package image verifier did not pass exactly",
    )
    require(
        verifier["invocation"]
        == [
            "scripts/verify-milkv-duo-image.sh",
            "--wasm-aot-profile",
            "--package-preflight",
            "--artifact-root=<staging-artifact-root>",
            "<sdk-root>",
        ],
        "C8.4 package image verifier invocation differs",
    )
    audit_record = identity_record(verifier["audit_log"], "C8.4 package image audit")
    same_identity(
        file_identity(CANONICAL_IMAGE_AUDIT), audit_record, "C8.4 package image audit"
    )
    tools = exact(package["tools"], PACKAGE_TOOL_KEYS, "C8.4 package tools")
    for name, record in tools.items():
        identity_record(record, f"C8.4 package tool {name}")
    validate_package_recorded_paths(
        package_source=package_source,
        sdk=sdk,
        build_envelope=build_envelope_record,
        artifacts=artifacts,
        audit_log=audit_record,
        tools=tools,
    )
    audit_report, audit_report_sha256 = validate_image_audit(
        audit_raw,
        source=source,
        challenge=challenge,
        source_materialization=provenance.source_root,
        runtime_attestation=provenance.package_attestation_root,
        artifacts=artifacts,
        tools=tools,
        label="C8.4 package image audit",
    )
    require(
        verifier["report"] == audit_report
        and verifier["report_sha256"] == audit_report_sha256,
        "C8.4 package verifier report binding differs",
    )
    timestamps = exact(
        package["timestamps_utc"],
        {"packaging_started", "image_verified", "envelope_closed"},
        "C8.4 package timestamps",
    )
    parsed = [
        datetime.datetime.fromisoformat(timestamps[name][:-1] + "+00:00")
        if isinstance(timestamps[name], str) and timestamps[name].endswith("Z")
        else fail(f"C8.4 package timestamp {name} is not UTC")
        for name in ("packaging_started", "image_verified", "envelope_closed")
    ]
    require(parsed == sorted(parsed), "C8.4 package timestamps are reversed")
    return PackageEvidence(
        package_bytes=package_raw,
        build_bytes=build_raw,
        audit_bytes=audit_raw,
        package_identity={
            "sha256": sha256_bytes(package_raw),
            "bytes": len(package_raw),
        },
        build_identity={"sha256": sha256_bytes(build_raw), "bytes": len(build_raw)},
        audit_identity={"sha256": sha256_bytes(audit_raw), "bytes": len(audit_raw)},
        artifacts=artifacts,
        package_content_sha256=package_root["content_sha256"],
        build_content_sha256=build_root["content_sha256"],
        run_id=run_id,
    )


def canonical_artifact_arguments(
    arguments: argparse.Namespace,
) -> dict[str, pathlib.Path]:
    supplied = {
        "kernel_binary": arguments.kernel,
        "fit_boot_sd": arguments.fit,
        "full_sd_image": arguments.image,
    }
    result: dict[str, pathlib.Path] = {}
    for key, supplied_path in supplied.items():
        require(supplied_path is not None, f"--{key.replace('_', '-')} is required")
        actual = absolute_no_symlink_path(supplied_path, f"C8.4 argument {key}")
        expected = absolute_no_symlink_path(
            CANONICAL_ARTIFACTS[key], f"canonical C8.4 {key}"
        )
        require(actual == expected, f"{key} must be canonical artifact {expected}")
        result[key] = actual
    require(arguments.package_envelope is not None, "--package-envelope is required")
    require(
        absolute_no_symlink_path(
            arguments.package_envelope, "C8.4 package-envelope argument"
        )
        == absolute_no_symlink_path(
            CANONICAL_PACKAGE_ENVELOPE, "canonical C8.4 package envelope"
        ),
        f"--package-envelope must be {CANONICAL_PACKAGE_ENVELOPE}",
    )
    return result


def lexical_serial_path(path: pathlib.Path) -> None:
    text = os.fspath(path.expanduser())
    require(
        pathlib.PurePath(text).is_absolute(), "UART path must be explicit and absolute"
    )
    require(
        "usbmodem" not in text.lower(),
        "monitor/control usbmodem devices are forbidden as a Duo UART",
    )


def validate_serial_path(path: pathlib.Path) -> tuple[str, str]:
    lexical_serial_path(path)
    requested = os.fspath(path.expanduser())
    try:
        resolved = absolute_no_symlink_path(path, "explicit UART")
        mode = resolved.lstat().st_mode
    except OSError as error:
        fail(f"cannot resolve explicit UART {path}: {error}")
    require(stat.S_ISCHR(mode), f"explicit UART is not a character device: {resolved}")
    require(
        "usbmodem" not in str(resolved).lower(),
        "resolved usbmodem monitor/control device is forbidden",
    )
    return requested, str(resolved)


def configure_read_only_uart(descriptor: int) -> None:
    attributes = termios.tcgetattr(descriptor)
    attributes[0] = 0
    attributes[1] = 0
    attributes[2] = termios.CLOCAL | termios.CREAD | termios.CS8
    attributes[3] = 0
    attributes[4] = termios.B115200
    attributes[5] = termios.B115200
    attributes[6][termios.VMIN] = 0
    attributes[6][termios.VTIME] = 1
    termios.tcsetattr(descriptor, termios.TCSANOW, attributes)


@dataclass(frozen=True)
class StreamIdentity:
    source_commit: str
    challenge: str
    run_id: str


class TranscriptStream:
    def __init__(self, source: str, challenge: str) -> None:
        self.source = source
        self.challenge = challenge
        self.pending = bytearray()
        self.metadata: dict[str, Any] | None = None
        self.ending: dict[str, Any] | None = None
        self.samples = 0
        self.closed_at: float | None = None

    @staticmethod
    def _record(line: bytes, prefix: bytes, label: str) -> dict[str, Any]:
        require(line.startswith(prefix), f"malformed C8.4 {label} marker")
        value = strict_json_bytes(line[len(prefix) :], f"C8.4 streamed {label}")
        require(isinstance(value, dict), f"C8.4 streamed {label} is not an object")
        return value

    def _line(self, line: bytes, now: float) -> None:
        lowered = line.lower()
        for marker in FAILURE_MARKERS:
            require(
                marker not in lowered,
                f"UART contains terminal failure marker {marker.decode()!r}",
            )
        if line.startswith(MARKER_PREFIX):
            require(self.ending is None, "C8.4 marker appeared after END")
        if line.startswith(META_PREFIX):
            require(
                self.metadata is None and self.samples == 0,
                "duplicate or late C8.4 META",
            )
            value = self._record(line, META_PREFIX, "metadata")
            require(
                value.get("source_commit") == self.source,
                "stream metadata source differs",
            )
            require(
                value.get("challenge") == self.challenge,
                "stream metadata challenge differs",
            )
            canonical_sha(value.get("run_id"), "stream run id")
            self.metadata = value
        elif line.startswith(SAMPLE_PREFIX):
            require(self.metadata is not None, "C8.4 SAMPLE appeared before META")
            self._record(line, SAMPLE_PREFIX, "sample")
            self.samples += 1
            require(self.samples <= 24, "C8.4 stream contains too many samples")
        elif line.startswith(END_PREFIX):
            require(self.metadata is not None, "C8.4 END appeared before META")
            require(self.samples == 24, "C8.4 END appeared before exactly 24 samples")
            value = self._record(line, END_PREFIX, "end")
            require(
                value.get("run_id") == self.metadata.get("run_id"),
                "stream END run id differs",
            )
            require(
                value.get("challenge") == self.challenge, "stream END challenge differs"
            )
            self.ending = value
            self.closed_at = now

    def feed(self, chunk: bytes, now: float) -> None:
        require(
            self.ending is None or now <= (self.closed_at or now) + END_GUARD_SECONDS,
            "bytes arrived after END guard",
        )
        self.pending.extend(chunk)
        while b"\n" in self.pending:
            line, _, remainder = self.pending.partition(b"\n")
            self.pending = bytearray(remainder)
            self._line(line.rstrip(b"\r"), now)

    def finish(self) -> StreamIdentity:
        if self.pending:
            self._line(bytes(self.pending).rstrip(b"\r"), time.monotonic())
            self.pending.clear()
        require(self.metadata is not None, "capture ended without C8.4 META")
        require(self.ending is not None, "capture ended without C8.4 END")
        require(self.samples == 24, "capture did not contain exactly 24 C8.4 samples")
        return StreamIdentity(
            source_commit=self.source,
            challenge=self.challenge,
            run_id=canonical_sha(self.metadata.get("run_id"), "captured run id"),
        )


def confirm_cold_boot(boot_index: int) -> str:
    expected = f"COLD BOOT {boot_index + 1}"
    print(
        "Power the Milk-V Duo fully OFF. This collector never flashes, resets, or writes serial."
    )
    response = input(f"Type {expected!r} only after verifying the board is OFF: ")
    require(response == expected, f"operator confirmation must be exactly {expected!r}")
    return utc_now()


def capture_one_boot(
    *,
    port: pathlib.Path,
    raw_path: pathlib.Path,
    source: str,
    challenge: str,
    timeout_seconds: float,
) -> tuple[StreamIdentity, dict[str, str]]:
    started_utc = utc_now()
    parser = TranscriptStream(source, challenge)
    total = 0
    first_byte_utc: str | None = None
    deadline = time.monotonic() + timeout_seconds
    descriptor = os.open(
        port,
        os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        _raw_parent, raw_parent_fd = open_directory_chain(
            raw_path.parent, "raw capture parent"
        )
    except BaseException:
        os.close(descriptor)
        raise
    raw_descriptor: int | None = None
    try:
        configure_read_only_uart(descriptor)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
        raw_descriptor = os.open(
            raw_path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=raw_parent_fd,
        )
        with os.fdopen(raw_descriptor, "wb") as output:
            raw_descriptor = None
            while True:
                now = time.monotonic()
                require(now < deadline, "physical UART capture timed out")
                if (
                    parser.closed_at is not None
                    and now - parser.closed_at >= END_GUARD_SECONDS
                ):
                    break
                wait_ms = max(1, min(250, math.ceil((deadline - now) * 1000)))
                events = poller.poll(wait_ms)
                for _fd, event in events:
                    require(
                        not (event & select.POLLNVAL), "UART descriptor became invalid"
                    )
                    if event & select.POLLIN:
                        chunk = os.read(descriptor, 65_536)
                        if not chunk:
                            continue
                        if first_byte_utc is None:
                            first_byte_utc = utc_now()
                        total += len(chunk)
                        require(
                            total <= MAX_RAW_BYTES,
                            "raw transcript exceeds its 256 MiB bound",
                        )
                        output.write(chunk)
                        parser.feed(chunk, time.monotonic())
                    if event & (select.POLLERR | select.POLLHUP):
                        require(
                            parser.ending is not None, "UART closed before verified END"
                        )
            output.flush()
            os.fsync(output.fileno())
        os.fsync(raw_parent_fd)
    finally:
        if raw_descriptor is not None:
            os.close(raw_descriptor)
        os.close(raw_parent_fd)
        os.close(descriptor)
    require(first_byte_utc is not None, "physical UART produced no bytes")
    identity = parser.finish()
    return identity, {
        "capture_started_utc": started_utc,
        "first_byte_utc": first_byte_utc,
        "completion_marker_closed_utc": utc_now(),
    }


def invoke_single_boot_verifier(
    *,
    raw: pathlib.Path,
    summary: pathlib.Path,
    source: str,
    challenge: str,
    boot_index: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, tuple[int, int]]:
    run_checked(
        [
            sys.executable,
            "-I",
            "-B",
            str(C84_VERIFIER),
            "--transcript",
            str(raw),
            "--expect-source",
            source,
            "--expect-challenge",
            challenge,
            "--boot-index",
            str(boot_index),
            "--summary-out",
            str(summary),
        ],
        label=f"C8.4 single-boot verifier for boot {boot_index}",
    )
    raw_bytes, raw_inode = stable_regular_measure(
        raw, f"C8.4 raw boot {boot_index}", maximum=MAX_RAW_BYTES
    )
    raw_identity = {"sha256": sha256_bytes(raw_bytes), "bytes": len(raw_bytes)}
    marker_stream_sha256 = canonical_marker_stream_digest(
        raw_bytes, f"C8.4 raw boot {boot_index}"
    )
    summary_raw = stable_regular_bytes(
        summary, f"C8.4 summary boot {boot_index}", maximum=MAX_SUMMARY_BYTES
    )
    summary_identity = {"sha256": sha256_bytes(summary_raw), "bytes": len(summary_raw)}
    value = strict_json_bytes(summary_raw, f"C8.4 summary boot {boot_index}")
    require(isinstance(value, dict), f"C8.4 summary boot {boot_index} is not an object")
    expected = {
        "schema": "vibeos.wasm-aot-decision.boot-summary",
        "scope": "single-boot-transcript-semantics-only-no-aot-decision",
        "physical_provenance": "unverified",
        "cold_boot_provenance": "unverified",
        "source_commit": source,
        "challenge": challenge,
        "platform": PLATFORM,
        "boot_index": boot_index,
        "required_cold_boots": BOOT_COUNT,
        "warmups": WARMUPS_PER_BOOT,
        "retained": RETAINED_PER_BOOT,
        "raw_transcript_sha256": raw_identity["sha256"],
        "raw_transcript_bytes": raw_identity["bytes"],
    }
    for key, wanted in expected.items():
        require(
            value.get(key) == wanted, f"C8.4 summary boot {boot_index} {key} differs"
        )
    integer(
        value.get("boot_index"),
        f"C8.4 summary boot {boot_index} index",
        minimum=boot_index,
        maximum=boot_index,
    )
    canonical_sha(value.get("run_id"), f"C8.4 summary boot {boot_index} run id")
    retained = value.get("retained_samples")
    require(
        isinstance(retained, list) and len(retained) == RETAINED_PER_BOOT,
        f"C8.4 boot {boot_index} retained samples differ",
    )
    return value, raw_identity, summary_identity, marker_stream_sha256, raw_inode


def nearest_rank(values: Sequence[int], percentile: int) -> int:
    require(bool(values), "cannot summarize an empty distribution")
    ordered = sorted(values)
    return ordered[(percentile * len(ordered) + 99) // 100 - 1]


def distribution(values: Sequence[int]) -> dict[str, int]:
    require(bool(values), "cannot summarize an empty distribution")
    ordered = sorted(values)
    return {
        "samples": len(ordered),
        "min": ordered[0],
        "p50": nearest_rank(ordered, 50),
        "p95": nearest_rank(ordered, 95),
        "max": ordered[-1],
        "mean": sum(ordered) // len(ordered),
    }


def aggregate_summaries(
    summaries: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    require(len(summaries) == BOOT_COUNT, "C8.4 aggregate requires exactly three boots")
    run_ids = {summary.get("run_id") for summary in summaries}
    sources = {summary.get("source_commit") for summary in summaries}
    challenges = {summary.get("challenge") for summary in summaries}
    require(
        len(run_ids) == len(sources) == len(challenges) == 1,
        "C8.4 cross-boot campaign identity differs",
    )
    cross: list[dict[str, Any]] = []
    all_samples: list[dict[str, Any]] = []
    for index, summary in enumerate(summaries):
        require(
            integer(
                summary.get("boot_index"),
                f"C8.4 boot summary {index} index",
                minimum=index,
                maximum=index,
            )
            == index,
            f"C8.4 boot summary order differs at {index}",
        )
        retained = summary.get("retained_samples")
        require(
            isinstance(retained, list) and len(retained) == RETAINED_PER_BOOT,
            f"C8.4 boot {index} retained count differs",
        )
        totals = [
            integer(sample.get("total_ticks"), f"boot {index} total ticks", minimum=1)
            for sample in retained
        ]
        p50 = nearest_rank(totals, 50)
        p95 = nearest_rank(totals, 95)
        require(p95 * 100 <= p50 * 150, f"C8.4 boot {index} stability exceeds 1.50")
        cross.append(
            {"boot_index": index, "p50_total_ticks": p50, "p95_total_ticks": p95}
        )
        all_samples.extend(retained)
    totals = [
        integer(sample.get("total_ticks"), "pooled total ticks", minimum=1)
        for sample in all_samples
    ]
    interpretation = [
        integer(sample.get("interpretation_ticks"), "pooled interpretation ticks")
        for sample in all_samples
    ]
    non_interpretation = [
        integer(
            sample.get("non_interpretation_ticks"), "pooled non-interpretation ticks"
        )
        for sample in all_samples
    ]
    for total, interp, non_interp in zip(totals, interpretation, non_interpretation):
        require(
            interp <= total and non_interp == total - interp,
            "C8.4 retained attribution arithmetic differs",
        )
    require(len(totals) == RETAINED_TOTAL, "C8.4 decision population is not 63")
    total_stats = distribution(totals)
    interpretation_stats = distribution(interpretation)
    non_interpretation_stats = distribution(non_interpretation)
    budget_miss = total_stats["p95"] > BUDGET_TICKS
    interpretation_attributable = non_interpretation_stats["p95"] <= BUDGET_TICKS
    eligible = budget_miss and interpretation_attributable
    pooled = {
        "scope": "capture-preview-final-evidence-verifier-required",
        "retained_samples": RETAINED_TOTAL,
        "budget_ticks": BUDGET_TICKS,
        "total_ticks": total_stats,
        "interpretation_ticks": interpretation_stats,
        "non_interpretation_ticks": non_interpretation_stats,
        "predicates": {
            "budget_miss": budget_miss,
            "interpretation_attribution": interpretation_attributable,
        },
        "candidate_outcome": (
            "aot-eligible-for-c85-design-review" if eligible else "aot-not-justified"
        ),
        "aot_authorized": False,
        "native_code_accepted": False,
    }
    return cross, pooled


def require_distinct_boot_files(boots: Sequence[dict[str, Any]]) -> None:
    require(
        len(boots) == BOOT_COUNT,
        "capture does not contain exactly three boot file records",
    )
    raw_hashes: list[str] = []
    raw_inodes: list[tuple[int, int]] = []
    summary_hashes: list[str] = []
    marker_stream_hashes: list[str] = []
    for index, boot in enumerate(boots):
        require(
            integer(
                boot.get("boot_index"),
                f"boot {index} file record index",
                minimum=index,
                maximum=index,
            )
            == index,
            f"boot file record order differs at {index}",
        )
        raw = boot.get("raw_log")
        summary = boot.get("summary")
        inode = boot.get("raw_capture_inode")
        marker_stream = boot.get("record_stream_sha256")
        require(
            isinstance(raw, dict)
            and isinstance(summary, dict)
            and isinstance(inode, dict),
            f"boot {index} file evidence is malformed",
        )
        raw_hashes.append(canonical_sha(raw.get("sha256"), f"boot {index} raw hash"))
        summary_hashes.append(
            canonical_sha(summary.get("sha256"), f"boot {index} summary hash")
        )
        marker_stream_hashes.append(
            canonical_sha(marker_stream, f"boot {index} canonical marker stream hash")
        )
        raw_inodes.append(
            (
                integer(inode.get("device"), f"boot {index} raw device"),
                integer(inode.get("inode"), f"boot {index} raw inode", minimum=1),
            )
        )
    require(
        len(set(raw_hashes)) == BOOT_COUNT,
        "raw transcript hashes are not distinct; replay is forbidden",
    )
    require(
        len(set(raw_inodes)) == BOOT_COUNT,
        "raw transcript inodes are not distinct; alias/replay is forbidden",
    )
    require(
        len(set(summary_hashes)) == BOOT_COUNT, "boot summary hashes are not distinct"
    )
    require(
        len(set(marker_stream_hashes)) == BOOT_COUNT,
        "canonical marker record streams are not distinct; noise-only replay is forbidden",
    )


def write_bytes_exclusive(path: pathlib.Path, raw: bytes) -> dict[str, Any]:
    _parent, directory_fd = open_directory_chain(path.parent, "capture file parent")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory_fd)
    except FileExistsError:
        fail(f"refusing to clobber existing output {path}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)
    return {"sha256": sha256_bytes(raw), "bytes": len(raw)}


def write_json_exclusive_atomic(path: pathlib.Path, value: Any) -> dict[str, Any]:
    rendered = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _parent, directory_fd = open_directory_chain(
        path.parent, "capture JSON output parent"
    )
    temporary = f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            fail(f"refusing to clobber existing output {path}")
        os.unlink(temporary, dir_fd=directory_fd)
        temporary = ""
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)
    return {"sha256": sha256_bytes(rendered), "bytes": len(rendered)}


def create_capture_stage(final: pathlib.Path) -> pathlib.Path:
    parent, parent_fd = open_directory_chain(final.parent, "capture output parent")
    try:
        for _attempt in range(32):
            name = f".{final.name}.capture.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            os.fsync(parent_fd)
            return parent / name
        fail("cannot allocate a unique sibling capture staging directory")
    finally:
        os.close(parent_fd)


def cleanup_capture_stage(stage: pathlib.Path) -> None:
    parent, parent_fd = open_directory_chain(stage.parent, "capture staging parent")
    require(stage.parent == parent, "capture staging parent changed")
    require(
        stage.name.startswith(".")
        and ".capture." in stage.name
        and stage.name.endswith(".tmp"),
        "refusing to clean a non-staging capture path",
    )
    stage_fd: int | None = None
    try:
        try:
            stage_fd = os.open(
                stage.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return
        for name in os.listdir(stage_fd):
            status = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            require(
                not stat.S_ISDIR(status.st_mode),
                f"capture staging contains unexpected directory {name!r}",
            )
            os.unlink(name, dir_fd=stage_fd)
        os.close(stage_fd)
        stage_fd = None
        os.rmdir(stage.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(parent_fd)


def atomic_publish_directory(stage: pathlib.Path, final: pathlib.Path) -> None:
    stage = pathlib.Path(os.path.abspath(os.fspath(stage)))
    final = pathlib.Path(os.path.abspath(os.fspath(final)))
    require(
        stage.parent == final.parent,
        "capture staging directory is not a sibling of final output",
    )
    _parent, parent_fd = open_directory_chain(
        stage.parent, "capture publication parent"
    )
    stage_fd = os.open(
        stage.name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    try:
        os.fsync(stage_fd)
        library = ctypes.CDLL(None, use_errno=True)
        old = os.fsencode(stage.name)
        new = os.fsencode(final.name)
        if sys.platform == "darwin" and hasattr(library, "renameatx_np"):
            result = library.renameatx_np(
                ctypes.c_int(parent_fd),
                ctypes.c_char_p(old),
                ctypes.c_int(parent_fd),
                ctypes.c_char_p(new),
                ctypes.c_uint(0x00000004),
            )
        elif hasattr(library, "renameat2"):
            result = library.renameat2(
                ctypes.c_int(parent_fd),
                ctypes.c_char_p(old),
                ctypes.c_int(parent_fd),
                ctypes.c_char_p(new),
                ctypes.c_uint(1),
            )
        else:
            fail("host has no atomic no-replace directory rename primitive")
        if result != 0:
            error = ctypes.get_errno()
            fail(
                f"cannot atomically publish capture output without replacement: {os.strerror(error)}"
            )
        published = os.stat(final.name, dir_fd=parent_fd, follow_symlinks=False)
        original = os.fstat(stage_fd)
        require(
            (published.st_dev, published.st_ino) == (original.st_dev, original.st_ino),
            "capture publication inode differs from the verified staging directory",
        )
        os.fsync(parent_fd)
    finally:
        os.close(stage_fd)
        os.close(parent_fd)


def validate_capture_output_tree(root: pathlib.Path) -> None:
    try:
        root_info = root.lstat()
        entries = list(root.iterdir())
    except OSError as error:
        fail(f"cannot inspect C8.4 capture output tree {root}: {error}")
    require(
        stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode),
        "C8.4 capture output root is not a fixed directory",
    )
    require(
        {entry.name for entry in entries} == CAPTURE_OUTPUT_FILES,
        "C8.4 capture output file set is not closed",
    )
    for entry in entries:
        info = entry.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_nlink == 1,
            f"C8.4 capture output entry is not a single-link regular file: {entry}",
        )


def output_directory(path: pathlib.Path) -> pathlib.Path:
    absolute = absolute_no_symlink_path(
        path, "capture output", leaf_may_be_missing=True
    )
    require(
        not absolute.exists() and not absolute.is_symlink(),
        f"capture output already exists: {absolute}",
    )
    repo = absolute_no_symlink_path(ROOT, "repository root")
    try:
        absolute.relative_to(repo)
    except ValueError:
        pass
    else:
        fail(f"capture output must be outside the frozen source tree: {absolute}")
    return absolute


def positive_timeout(value: Any) -> float:
    require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        "timeout must be numeric",
    )
    result = float(value)
    require(
        math.isfinite(result) and result > END_GUARD_SECONDS,
        "timeout must exceed END guard",
    )
    return result


def run_capture(arguments: argparse.Namespace) -> pathlib.Path:
    global _ACTIVE_CAPTURE_STAGE
    source = canonical_source(arguments.source_commit, "C8.4 source commit")
    challenge = canonical_challenge(arguments.challenge, "C8.4 challenge")
    provenance = validate_live_provenance(source, challenge)
    require(
        sys.stdin.isatty(),
        "physical cold-boot confirmations require an interactive terminal",
    )
    c83_source = canonical_source(arguments.expect_c83_source, "expected C8.3 source")
    c83_challenge = canonical_challenge(
        arguments.expect_c83_challenge, "expected C8.3 challenge"
    )
    require(
        arguments.port is not None and arguments.output_dir is not None,
        "--port and --output-dir are required",
    )
    timeout = positive_timeout(arguments.timeout_seconds)
    final_output = output_directory(arguments.output_dir)
    canonical_artifact_arguments(arguments)
    load_campaign_contract()
    requested_port, resolved_port = validate_serial_path(arguments.port)
    c83_root = absolute_no_symlink_path(
        arguments.c83_evidence_root, "C8.3 evidence root"
    )
    c83_precondition = verify_c83_precondition(
        c83_root,
        c84_source=source,
        c83_source=c83_source,
        c83_challenge=c83_challenge,
    )
    package = validate_package_evidence(source, challenge, provenance)
    tool_identities = {
        "capture_script": file_identity(SCRIPT_PATH),
        "single_boot_verifier": file_identity(C84_VERIFIER),
        "final_evidence_verifier": file_identity(C84_EVIDENCE_VERIFIER),
        "c83_evidence_verifier": file_identity(C83_EVIDENCE_VERIFIER),
        "source_materializer_script": file_identity(C84_SOURCE_MATERIALIZER),
        "docker_runtime_script": file_identity(C84_DOCKER_RUNTIME),
        "manifest": file_identity(C84_MANIFEST),
        "transcript_schema": file_identity(C84_TRANSCRIPT_SCHEMA),
        "evidence_schema": file_identity(C84_EVIDENCE_SCHEMA),
    }
    artifacts = {
        key: file_identity(path, f"C8.4 artifact {key}")
        for key, path in CANONICAL_ARTIFACTS.items()
    }
    started_utc = utc_now()
    output = create_capture_stage(final_output)
    _ACTIVE_CAPTURE_STAGE = output
    copied_build = write_bytes_exclusive(
        output / "build-envelope.json", package.build_bytes
    )
    copied_package = write_bytes_exclusive(
        output / "package-envelope.json", package.package_bytes
    )
    copied_audit = write_bytes_exclusive(
        output / "package-image-verifier-audit.log", package.audit_bytes
    )
    copied_source = write_bytes_exclusive(
        output / "source-materialization-envelope.json", provenance.source_bytes
    )
    copied_package_attestation = write_bytes_exclusive(
        output / "container-runtime-attestation.json",
        provenance.package_attestation_bytes,
    )
    copied_verifier_attestation = write_bytes_exclusive(
        output / "container-runtime-verifier-attestation.json",
        provenance.verifier_attestation_bytes,
    )
    copied_runtime_closure = write_bytes_exclusive(
        output / "container-runtime-closure.json", provenance.closure_bytes
    )
    copied_custody = {
        "build-envelope.json": copied_build,
        "package-envelope.json": copied_package,
        "package-image-verifier-audit.log": copied_audit,
        "source-materialization-envelope.json": copied_source,
        "container-runtime-attestation.json": copied_package_attestation,
        "container-runtime-verifier-attestation.json": copied_verifier_attestation,
        "container-runtime-closure.json": copied_runtime_closure,
    }
    boots: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    run_id: str | None = None
    for boot_index in range(BOOT_COUNT):
        confirmed_utc = confirm_cold_boot(boot_index)
        raw_path = output / f"boot-{boot_index}.uart.log"
        summary_path = output / f"boot-{boot_index}.summary.json"
        stream_identity, timing = capture_one_boot(
            port=pathlib.Path(resolved_port),
            raw_path=raw_path,
            source=source,
            challenge=challenge,
            timeout_seconds=timeout,
        )
        if run_id is None:
            run_id = stream_identity.run_id
        require_run_id_binding(
            package.run_id,
            stream=stream_identity.run_id,
            capture=run_id,
        )
        summary, raw_identity, summary_identity, marker_stream_sha256, raw_inode = (
            invoke_single_boot_verifier(
                raw=raw_path,
                summary=summary_path,
                source=source,
                challenge=challenge,
                boot_index=boot_index,
            )
        )
        require(
            summary["run_id"] == run_id, f"boot {boot_index} summary run id differs"
        )
        summaries.append(summary)
        boots.append(
            {
                "boot_index": boot_index,
                "operator_confirmation": f"COLD BOOT {boot_index + 1}",
                "operator_confirmed_utc": confirmed_utc,
                **timing,
                "verified_utc": utc_now(),
                "run_id": run_id,
                "raw_log": {"file": raw_path.name, **raw_identity},
                "raw_capture_inode": {"device": raw_inode[0], "inode": raw_inode[1]},
                "record_stream_sha256": marker_stream_sha256,
                "summary": {"file": summary_path.name, **summary_identity},
            }
        )
        if boot_index + 1 < BOOT_COUNT:
            print(
                f"Boot {boot_index + 1} verified. Fully power the board OFF before continuing."
            )
    require(run_id is not None, "capture has no run id")
    require_distinct_boot_files(boots)
    cross, pooled = aggregate_summaries(summaries)
    provenance_closed = validate_live_provenance(source, challenge)
    require(
        provenance_closed == provenance,
        "source materialization or container runtime custody changed during capture",
    )
    package_closed = validate_package_evidence(source, challenge, provenance_closed)
    require(
        package_closed == package,
        "package evidence or artifacts changed during capture",
    )
    c83_closed = verify_c83_precondition(
        c83_root,
        c84_source=source,
        c83_source=c83_source,
        c83_challenge=c83_challenge,
    )
    require(c83_closed == c83_precondition, "C8.3 precondition changed during capture")
    for key, path in CANONICAL_ARTIFACTS.items():
        require(
            file_identity(path) == artifacts[key],
            f"C8.4 artifact {key} changed during capture",
        )
    for filename, expected in copied_custody.items():
        same_identity(
            file_identity(output / filename, f"copied C8.4 custody file {filename}"),
            expected,
            f"copied C8.4 custody file {filename}",
        )
    for key, path in {
        "capture_script": SCRIPT_PATH,
        "single_boot_verifier": C84_VERIFIER,
        "final_evidence_verifier": C84_EVIDENCE_VERIFIER,
        "c83_evidence_verifier": C83_EVIDENCE_VERIFIER,
        "source_materializer_script": C84_SOURCE_MATERIALIZER,
        "docker_runtime_script": C84_DOCKER_RUNTIME,
        "manifest": C84_MANIFEST,
        "transcript_schema": C84_TRANSCRIPT_SCHEMA,
        "evidence_schema": C84_EVIDENCE_SCHEMA,
    }.items():
        require(
            file_identity(path) == tool_identities[key],
            f"C8.4 evidence input {key} changed during capture",
        )
    content = {
        "platform": PLATFORM,
        "source_commit": source,
        "git_head": source,
        "challenge": challenge,
        "run_id": run_id,
        "workload_id": WORKLOAD_ID,
        "c83_precondition": c83_precondition,
        "artifacts": artifacts,
        "artifact_custody": {
            "build_envelope": {
                "file": "build-envelope.json",
                "content_sha256": package.build_content_sha256,
                **copied_build,
            },
            "package_envelope": {
                "file": "package-envelope.json",
                "content_sha256": package.package_content_sha256,
                **copied_package,
            },
            "package_image_verifier_audit": {
                "file": "package-image-verifier-audit.log",
                **copied_audit,
            },
            "source_materialization_envelope": {
                "file": "source-materialization-envelope.json",
                "content_sha256": provenance.source_root["content_sha256"],
                **copied_source,
            },
            "package_runtime_attestation": {
                "file": "container-runtime-attestation.json",
                "content_sha256": provenance.package_attestation_root["content_sha256"],
                **copied_package_attestation,
            },
            "verifier_runtime_attestation": {
                "file": "container-runtime-verifier-attestation.json",
                "content_sha256": provenance.verifier_attestation_root[
                    "content_sha256"
                ],
                **copied_verifier_attestation,
            },
            "container_runtime_closure": {
                "file": "container-runtime-closure.json",
                "content_sha256": provenance.closure_root["content_sha256"],
                **copied_runtime_closure,
            },
        },
        "provenance": {
            "source_materialization": provenance.source_root,
            "container_runtime": provenance.closure_root,
        },
        "capture": {
            "started_utc": started_utc,
            "completed_utc": utc_now(),
            "fresh_cold_boots": BOOT_COUNT,
            "retained_samples": RETAINED_TOTAL,
            "timeout_seconds_per_boot": timeout,
            "end_uniqueness_guard_seconds": END_GUARD_SECONDS,
            "power_and_flash_control": "manual operator only; collector performs no serial writes, reset, auto-discovery, or flash",
            "serial": {
                "access": "read-only",
                "requested_port": requested_port,
                "resolved_port": resolved_port,
                "settings": UART_SETTINGS,
                "usbmodem_forbidden": True,
            },
            "boots": boots,
            "cross_boot_stability": cross,
            "pooled_preview": pooled,
        },
        "evidence_tools": tool_identities,
    }
    envelope = make_content_envelope(CAPTURE_ENVELOPE_SCHEMA, content, version=2)
    envelope_identity = write_json_exclusive_atomic(
        output / "capture-envelope.json", envelope
    )
    validate_capture_output_tree(output)
    for filename, expected in copied_custody.items():
        same_identity(
            file_identity(output / filename, f"copied C8.4 custody file {filename}"),
            expected,
            f"copied C8.4 custody file {filename}",
        )
    require(
        validate_live_provenance(source, challenge) == provenance,
        "source materialization or container runtime custody changed before publication",
    )
    for filename, expected in copied_custody.items():
        same_identity(
            file_identity(output / filename, f"copied C8.4 custody file {filename}"),
            expected,
            f"copied C8.4 custody file {filename}",
        )
    atomic_publish_directory(output, final_output)
    validate_capture_output_tree(final_output)
    for filename, expected in copied_custody.items():
        same_identity(
            file_identity(
                final_output / filename, f"published C8.4 custody file {filename}"
            ),
            expected,
            f"published C8.4 custody file {filename}",
        )
    _ACTIVE_CAPTURE_STAGE = None
    print(
        f"PASS C8.4 physical capture boots=3 retained=63 source={source} challenge={challenge} "
        f"run_id={run_id} envelope_sha256={envelope_identity['sha256']}"
    )
    return final_output / "capture-envelope.json"


def synthetic_summary(
    boot_index: int, *, base: int = 2_400_000, run_id: str = "a" * 64
) -> dict[str, Any]:
    retained = []
    for index in range(RETAINED_PER_BOOT):
        total = base + index * 1_000
        interpretation = 200_000
        retained.append(
            {
                "sample_index": index + WARMUPS_PER_BOOT,
                "total_ticks": total,
                "interpretation_ticks": interpretation,
                "non_interpretation_ticks": total - interpretation,
            }
        )
    return {
        "source_commit": "a" * 40,
        "challenge": "b" * 64,
        "run_id": run_id,
        "boot_index": boot_index,
        "retained_samples": retained,
    }


def synthetic_stream_lines() -> bytes:
    meta = {"source_commit": "a" * 40, "challenge": "b" * 64, "run_id": "c" * 64}
    sample = {"placeholder": True}
    ending = {"challenge": "b" * 64, "run_id": "c" * 64}
    lines = [META_PREFIX + json.dumps(meta, separators=(",", ":")).encode()]
    lines.extend(
        SAMPLE_PREFIX + json.dumps(sample, separators=(",", ":")).encode()
        for _ in range(24)
    )
    lines.append(END_PREFIX + json.dumps(ending, separators=(",", ":")).encode())
    return b"\n".join(lines) + b"\n"


def selftest() -> None:
    require(
        not image_audit_transcript_has_failure(
            ["normal verifier output", '{"path":"/tmp/fail/source"}', C84_IMAGE_PASS]
        ),
        "structured image audit status word was treated as transcript failure",
    )
    require(
        image_audit_transcript_has_failure(
            ["fatal: verifier crashed", "{}", C84_IMAGE_PASS]
        ),
        "non-structured image audit failure was not detected",
    )
    good = synthetic_stream_lines()
    parser = TranscriptStream("a" * 40, "b" * 64)
    midpoint = len(good) // 2
    parser.feed(good[:midpoint], 10.0)
    parser.feed(good[midpoint:], 10.1)
    require(parser.finish().run_id == "c" * 64, "stream selftest baseline differs")
    stream_mutations: list[tuple[str, bytes]] = []
    lines = good.splitlines(keepends=True)
    stream_mutations.extend(
        [
            ("missing-meta", b"".join(lines[1:])),
            ("duplicate-meta", lines[0] + good),
            ("sample-before-meta", lines[1] + good),
            ("missing-sample", b"".join(lines[:10] + lines[11:])),
            ("duplicate-end", good + lines[-1]),
            ("failure-marker", b"panic\n" + good),
            (
                "wrong-source",
                good.replace(b'"a' + b"a" * 39 + b'"', b'"d' + b"d" * 39 + b'"', 1),
            ),
            (
                "wrong-challenge",
                good.replace(b'"b' + b"b" * 63 + b'"', b'"e' + b"e" * 63 + b'"', 1),
            ),
            (
                "duplicate-json",
                good.replace(
                    b'{"source_commit"',
                    b'{"run_id":"' + b"c" * 64 + b'","source_commit"',
                    1,
                ),
            ),
            ("marker-after-end", good + SAMPLE_PREFIX + b"{}\n"),
        ]
    )
    rejected = 0
    for label, raw in stream_mutations:
        candidate = TranscriptStream("a" * 40, "b" * 64)
        try:
            candidate.feed(raw, 20.0)
            candidate.finish()
        except CaptureError:
            rejected += 1
        else:
            fail(f"selftest accepted stream mutation {label}")
    require(
        rejected == len(stream_mutations), "stream mutation rejection count differs"
    )

    require(
        nearest_rank(list(range(1, 64)), 50) == 32,
        "63-sample p50 is not nearest-rank index 31",
    )
    require(
        nearest_rank(list(range(1, 64)), 95) == 60,
        "63-sample p95 is not nearest-rank index 59",
    )

    summaries = [synthetic_summary(index) for index in range(BOOT_COUNT)]
    cross, pooled = aggregate_summaries(summaries)
    require(
        len(cross) == BOOT_COUNT and pooled["retained_samples"] == RETAINED_TOTAL,
        "aggregate baseline differs",
    )
    require(
        pooled["candidate_outcome"] == "aot-not-justified",
        "under-budget baseline decision differs",
    )
    eligible = [synthetic_summary(index, base=2_600_000) for index in range(BOOT_COUNT)]
    for summary in eligible:
        for sample in summary["retained_samples"]:
            sample["interpretation_ticks"] = 300_000
            sample["non_interpretation_ticks"] = sample["total_ticks"] - 300_000
    _, eligible_pooled = aggregate_summaries(eligible)
    require(
        eligible_pooled["candidate_outcome"] == "aot-eligible-for-c85-design-review",
        "dual-threshold eligible decision differs",
    )
    boundary = [
        synthetic_summary(index, base=BUDGET_TICKS - 19_000)
        for index in range(BOOT_COUNT)
    ]
    _, boundary_pooled = aggregate_summaries(boundary)
    require(
        boundary_pooled["total_ticks"]["p95"] == BUDGET_TICKS,
        "budget boundary fixture differs",
    )
    require(
        boundary_pooled["predicates"]
        == {"budget_miss": False, "interpretation_attribution": True},
        "strict budget boundary comparison differs",
    )
    percentile_fixture = [
        synthetic_summary(index, base=2_000_000) for index in range(BOOT_COUNT)
    ]
    ordered_n: list[int] = []
    ordered_t: list[int] = []
    ordered_i: list[int] = []
    for boot in percentile_fixture:
        for position, sample in enumerate(boot["retained_samples"]):
            # Anti-correlate interpretation and non-interpretation so p95(T)-p95(I)
            # cannot masquerade as p95(T-I).
            sample["interpretation_ticks"] = 900_000 if position < 11 else 10_000
            sample["non_interpretation_ticks"] = (
                sample["total_ticks"] - sample["interpretation_ticks"]
            )
            ordered_t.append(sample["total_ticks"])
            ordered_i.append(sample["interpretation_ticks"])
            ordered_n.append(sample["non_interpretation_ticks"])
    _, percentile_pooled = aggregate_summaries(percentile_fixture)
    require(
        percentile_pooled["non_interpretation_ticks"]["p95"]
        == nearest_rank(ordered_n, 95),
        "non-interpretation percentile was not computed per sample",
    )
    require(
        nearest_rank(ordered_n, 95)
        != nearest_rank(ordered_t, 95) - nearest_rank(ordered_i, 95),
        "percentile anti-subtraction fixture is ineffective",
    )
    aggregate_rejected = 0
    mutations = []
    wrong_identity = json.loads(json.dumps(summaries))
    wrong_identity[2]["run_id"] = "d" * 64
    mutations.append(("identity", wrong_identity))
    wrong_index = json.loads(json.dumps(summaries))
    wrong_index[1]["boot_index"] = 0
    mutations.append(("boot-index", wrong_index))
    missing = json.loads(json.dumps(summaries))
    missing[0]["retained_samples"].pop()
    mutations.append(("retained", missing))
    arithmetic = json.loads(json.dumps(summaries))
    arithmetic[0]["retained_samples"][0]["non_interpretation_ticks"] += 1
    mutations.append(("attribution-arithmetic", arithmetic))
    for label, value in mutations:
        try:
            aggregate_summaries(value)
        except CaptureError:
            aggregate_rejected += 1
        else:
            fail(f"selftest accepted aggregate mutation {label}")
    require(aggregate_rejected == len(mutations), "aggregate rejection count differs")

    boot_files = [
        {
            "boot_index": index,
            "raw_log": {
                "sha256": f"{index + 3:x}" * 64,
                "bytes": 1,
                "file": f"boot-{index}.uart.log",
            },
            "raw_capture_inode": {"device": 1, "inode": index + 10},
            "record_stream_sha256": f"{index + 9:x}" * 64,
            "summary": {
                "sha256": f"{index + 6:x}" * 64,
                "bytes": 1,
                "file": f"boot-{index}.summary.json",
            },
        }
        for index in range(BOOT_COUNT)
    ]
    require_distinct_boot_files(boot_files)
    replay_rejected = 0
    for mutate in ("hash", "inode", "summary", "swap"):
        candidate = json.loads(json.dumps(boot_files))
        if mutate == "hash":
            candidate[2]["raw_log"]["sha256"] = candidate[0]["raw_log"]["sha256"]
        elif mutate == "inode":
            candidate[2]["raw_capture_inode"] = candidate[0]["raw_capture_inode"]
        elif mutate == "summary":
            candidate[2]["summary"]["sha256"] = candidate[0]["summary"]["sha256"]
        else:
            candidate[1], candidate[2] = candidate[2], candidate[1]
        try:
            require_distinct_boot_files(candidate)
        except CaptureError:
            replay_rejected += 1
        else:
            fail(f"selftest accepted boot replay/swap mutation {mutate}")
    require(replay_rejected == 4, "boot replay rejection count differs")

    marker_digest = canonical_marker_stream_digest(good, "semantic replay baseline")
    require(
        canonical_marker_stream_digest(b"noise one\n" + good, "noise replay one")
        == marker_digest
        and canonical_marker_stream_digest(
            b"different harmless noise\n" + good, "noise replay two"
        )
        == marker_digest,
        "semantic replay fixture did not preserve the marker stream",
    )
    semantic_replay = json.loads(json.dumps(boot_files))
    for index, record in enumerate(semantic_replay):
        record["raw_log"]["sha256"] = sha256_bytes(
            f"noise-{index}".encode("ascii") + good
        )
        record["record_stream_sha256"] = marker_digest
    try:
        require_distinct_boot_files(semantic_replay)
    except CaptureError:
        pass
    else:
        fail("selftest accepted noise-only canonical marker-stream replay")

    lexical_rejected = 0
    for value in (
        pathlib.Path("relative-uart"),
        pathlib.Path("/dev/cu.usbmodem01"),
        pathlib.Path("/DEV/USBMODEM-control"),
    ):
        try:
            lexical_serial_path(value)
        except CaptureError:
            lexical_rejected += 1
        else:
            fail(f"selftest accepted unsafe UART {value}")
    require(lexical_rejected == 3, "UART rejection count differs")

    content = {"answer": 42}
    envelope = make_content_envelope("vibeos.test", content)
    canonical_content_envelope(envelope, "vibeos.test", "selftest envelope")
    corrupted = json.loads(json.dumps(envelope))
    corrupted["content"]["answer"] = 43
    try:
        canonical_content_envelope(
            corrupted, "vibeos.test", "corrupt selftest envelope"
        )
    except CaptureError:
        pass
    else:
        fail("selftest accepted corrupt content address")
    boolean_version = make_content_envelope("vibeos.test", {"answer": 42})
    boolean_version["version"] = True
    try:
        canonical_content_envelope(
            boolean_version, "vibeos.test", "boolean-version selftest envelope"
        )
    except CaptureError:
        pass
    else:
        fail("selftest accepted boolean content-envelope version")
    v2_envelope = make_content_envelope("vibeos.test-v2", {"answer": 42}, version=2)
    canonical_content_envelope(
        v2_envelope, "vibeos.test-v2", "v2 selftest envelope", version=2
    )
    try:
        canonical_content_envelope(
            v2_envelope, "vibeos.test-v2", "v2-as-v1 selftest envelope"
        )
    except CaptureError:
        pass
    else:
        fail("selftest accepted a v2 content envelope as v1")
    try:
        strict_json_bytes(b'{"value":1e999}', "infinite-number selftest JSON")
    except CaptureError:
        pass
    else:
        fail("selftest accepted a non-finite JSON number")
    files = {"a": b"one", "b/c": b"two"}
    require(
        canonical_tree_digest(files)
        == canonical_tree_digest(dict(reversed(list(files.items())))),
        "tree digest depends on insertion order",
    )
    changed = dict(files)
    changed["b/c"] = b"three"
    require(
        canonical_tree_digest(files) != canonical_tree_digest(changed),
        "tree digest ignored changed bytes",
    )

    provenance_source = "a" * 40
    provenance_challenge = "b" * 64
    source_root = make_content_envelope(
        SOURCE_MATERIALIZATION_SCHEMA,
        {
            "bundles": [],
            "challenge": provenance_challenge,
            "clone_git_admin": {},
            "command": [],
            "frozen": {},
            "git": {"path": "/opt/failure-tools/git"},
            "independence": {},
            "materialization": {},
            "patch": {},
            "snapshot": {},
            "source": {},
            "source_commit": provenance_source,
            "submodules": [],
            "timestamps_utc": {},
        },
    )

    def synthetic_attestation(mode: str, marker: str) -> dict[str, Any]:
        return make_content_envelope(
            RUNTIME_ATTESTATION_SCHEMA,
            {
                "capability": RUNTIME_CAPABILITY,
                "challenge": provenance_challenge,
                "host_preinspect": {"marker": marker},
                "host_preinspect_identity": {"sha256": marker * 64, "bytes": 1},
                "mode": mode,
                "source_commit": provenance_source,
                "source_materialization_content_sha256": source_root["content_sha256"],
                "witness": {"marker": marker},
            },
        )

    package_attestation = synthetic_attestation("package", "c")
    verifier_attestation = synthetic_attestation("verify", "d")

    def root_file_identity(root: dict[str, Any]) -> dict[str, Any]:
        raw = (
            json.dumps(root, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        return {"sha256": sha256_bytes(raw), "bytes": len(raw)}

    package_attestation_identity = root_file_identity(package_attestation)
    verifier_attestation_identity = root_file_identity(verifier_attestation)

    def runtime_record(filename: str, marker: str) -> dict[str, Any]:
        return {"path": filename, "sha256": marker * 64, "bytes": 1}

    runtime_artifacts = {
        role: runtime_record(filename, f"{index + 1:x}")
        for index, (role, filename) in enumerate(RUNTIME_ARTIFACT_FILES.items())
    }
    runtime_artifacts["package_attestation"] = {
        "path": RUNTIME_ARTIFACT_FILES["package_attestation"],
        **package_attestation_identity,
    }
    runtime_artifacts["verifier_attestation"] = {
        "path": RUNTIME_ARTIFACT_FILES["verifier_attestation"],
        **verifier_attestation_identity,
    }

    def synthetic_run(
        mode: str,
        container_id: str,
        root: dict[str, Any],
        identity: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "attestation": root,
            "attestation_identity": identity,
            "container_id": container_id,
            "container_postinspect": {},
            "container_preinspect": {},
            "host_preinspect": {},
            "host_preinspect_identity": {"sha256": "e" * 64, "bytes": 1},
            "operations": {},
            "wait_exit_code": 0,
        }

    closure_root = make_content_envelope(
        RUNTIME_CLOSURE_SCHEMA,
        {
            "artifacts": runtime_artifacts,
            "capability": RUNTIME_CAPABILITY,
            "challenge": provenance_challenge,
            "image": {
                "architecture": "amd64",
                "descriptor": {},
                "id": "sha256:" + "9" * 64,
                "inspect": {},
                "os": "linux",
                "reference": SDK_CONTAINER_REFERENCE,
                "repo_digest": SDK_CONTAINER_REFERENCE,
            },
            "package": {
                "build_envelope": runtime_record("build-envelope.json", "5"),
                "image_verifier_audit": runtime_record("image-verifier-audit.log", "6"),
                "package_envelope": runtime_record("package-envelope.json", "7"),
            },
            "platform": SDK_CONTAINER_PLATFORM,
            "runs": {
                "package": synthetic_run(
                    "package",
                    "a" * 64,
                    package_attestation,
                    package_attestation_identity,
                ),
                "verifier": synthetic_run(
                    "verify",
                    "b" * 64,
                    verifier_attestation,
                    verifier_attestation_identity,
                ),
            },
            "sdk_mount": {
                "destination": RUNTIME_SDK_ROOT,
                "kind": "volume",
                "read_only": True,
                "source": "synthetic-sdk",
            },
            "source": {
                "materialization_content_sha256": source_root["content_sha256"],
                "root": str(ROOT),
            },
            "source_commit": provenance_source,
        },
    )
    provenance_arguments = {
        "source": provenance_source,
        "challenge": provenance_challenge,
        "source_root": source_root,
        "package_attestation": package_attestation,
        "verifier_attestation": verifier_attestation,
        "closure_root": closure_root,
        "package_attestation_identity": package_attestation_identity,
        "verifier_attestation_identity": verifier_attestation_identity,
    }
    validate_provenance_roots(**provenance_arguments)
    provenance_rejected = 0
    provenance_mutations: list[tuple[str, dict[str, Any]]] = []
    wrong_source = json.loads(json.dumps(source_root))
    wrong_source["content"]["challenge"] = "f" * 64
    wrong_source = make_content_envelope(
        SOURCE_MATERIALIZATION_SCHEMA, wrong_source["content"]
    )
    provenance_mutations.append(("source campaign", {"source_root": wrong_source}))
    wrong_package = json.loads(json.dumps(package_attestation))
    wrong_package["content"]["mode"] = "verify"
    wrong_package = make_content_envelope(
        RUNTIME_ATTESTATION_SCHEMA, wrong_package["content"]
    )
    provenance_mutations.append(
        ("package attestation mode", {"package_attestation": wrong_package})
    )
    reused = json.loads(json.dumps(closure_root))
    reused["content"]["runs"]["verifier"]["container_id"] = "a" * 64
    reused = make_content_envelope(RUNTIME_CLOSURE_SCHEMA, reused["content"])
    provenance_mutations.append(("reused container", {"closure_root": reused}))
    swapped = json.loads(json.dumps(closure_root))
    swapped["content"]["runs"]["verifier"]["attestation"] = package_attestation
    swapped = make_content_envelope(RUNTIME_CLOSURE_SCHEMA, swapped["content"])
    provenance_mutations.append(("swapped attestation", {"closure_root": swapped}))
    old_runtime = json.loads(json.dumps(closure_root))
    old_runtime["content"]["capability"] = (
        "operator-declared; runtime container identity not attested"
    )
    old_runtime = make_content_envelope(RUNTIME_CLOSURE_SCHEMA, old_runtime["content"])
    provenance_mutations.append(("old runtime proof", {"closure_root": old_runtime}))
    for label, changes in provenance_mutations:
        try:
            validate_provenance_roots(**{**provenance_arguments, **changes})
        except CaptureError:
            provenance_rejected += 1
        else:
            fail(f"selftest accepted provenance mutation {label}")
    require(
        provenance_rejected == len(provenance_mutations),
        "provenance mutation rejection count differs",
    )

    recorded_source_root = pathlib.PurePosixPath("/producer/vibeos")
    recorded_sdk_root = pathlib.PurePosixPath("/producer/sdk")
    recorded_artifact_root = recorded_source_root / "target/milkv-duo-wasm-aot-profile"
    package_source_paths = {"root": str(recorded_source_root)}
    sdk_paths = {"root": str(recorded_sdk_root)}
    artifact_names = {
        "kernel_elf": "vibeos-milkv-duo-wasm-aot-profile.elf",
        "kernel_binary": "vibeos-milkv-duo.bin",
        "packaged_fit_source": "milkv-duo.its",
        "packaged_dtb": "cv1800b_milkv_duo_sd.dtb",
        "fit_boot_sd": "boot.sd",
        "full_sd_image": "vibeos-milkv-duo-wasm-aot-profile-sd.img",
    }
    recorded_artifacts = {
        role: {
            "path": str(recorded_artifact_root / name),
            "sha256": "a" * 64,
            "bytes": 1,
        }
        for role, name in artifact_names.items()
    }
    recorded_artifacts.update(
        {
            "sdk_fip": {
                "path": str(
                    recorded_sdk_root / "install/soc_cv1800b_milkv_duo_sd/fip.bin"
                ),
                "sha256": "b" * 64,
                "bytes": 1,
            },
            "sdk_dtb": {
                "path": str(
                    recorded_sdk_root
                    / "linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb"
                ),
                "sha256": "c" * 64,
                "bytes": 1,
            },
        }
    )
    recorded_tools = {
        role: {"path": f"/usr/bin/{role}", "sha256": "d" * 64, "bytes": 1}
        for role in PACKAGE_TOOL_KEYS
    }
    for role, relative in REPOSITORY_PACKAGE_TOOLS.items():
        recorded_tools[role] = {
            "path": str(recorded_source_root / relative),
            **file_identity(ROOT / relative, f"selftest package tool {role}"),
        }
    recorded_tools["sdk_mkimage"]["path"] = str(
        recorded_sdk_root / "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/mkimage"
    )
    recorded_tools["sdk_dumpimage"]["path"] = str(
        recorded_sdk_root / "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/dumpimage"
    )
    recorded_tools["sdk_genimage"]["path"] = str(
        recorded_sdk_root
        / "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage"
    )
    build_envelope_path = {
        "path": str(recorded_artifact_root / "build-envelope.json"),
        "sha256": "e" * 64,
        "bytes": 1,
    }
    audit_log_path = {
        "path": str(recorded_artifact_root / "image-verifier-audit.log"),
        "sha256": "f" * 64,
        "bytes": 1,
    }
    validate_package_recorded_paths(
        package_source=package_source_paths,
        sdk=sdk_paths,
        build_envelope=build_envelope_path,
        artifacts=recorded_artifacts,
        audit_log=audit_log_path,
        tools=recorded_tools,
    )
    path_rejected = 0
    arbitrary_root = pathlib.PurePosixPath("/producer/arbitrary-artifacts")
    moved_artifacts = {
        role: dict(record) for role, record in recorded_artifacts.items()
    }
    for role, name in artifact_names.items():
        moved_artifacts[role]["path"] = str(arbitrary_root / name)
    for label, changes in (
        (
            "arbitrary artifact root",
            {
                "artifacts": moved_artifacts,
                "build_envelope": {
                    **build_envelope_path,
                    "path": str(arbitrary_root / "build-envelope.json"),
                },
                "audit_log": {
                    **audit_log_path,
                    "path": str(arbitrary_root / "image-verifier-audit.log"),
                },
            },
        ),
        (
            "forged repository tool path",
            {
                "tools": {
                    **recorded_tools,
                    "package_script": {
                        **recorded_tools["package_script"],
                        "path": str(recorded_source_root / "scripts/forged.sh"),
                    },
                }
            },
        ),
        (
            "noncanonical external tool path",
            {
                "tools": {
                    **recorded_tools,
                    "verifier_cmp": {
                        **recorded_tools["verifier_cmp"],
                        "path": "/usr/bin/../bin/cmp",
                    },
                }
            },
        ),
    ):
        arguments = {
            "package_source": package_source_paths,
            "sdk": sdk_paths,
            "build_envelope": build_envelope_path,
            "artifacts": recorded_artifacts,
            "audit_log": audit_log_path,
            "tools": recorded_tools,
            **changes,
        }
        try:
            validate_package_recorded_paths(**arguments)
        except CaptureError:
            path_rejected += 1
        else:
            fail(f"selftest accepted {label}")
    require(path_rejected == 3, "package path-closure rejection count differs")

    import ast
    import tempfile

    module = ast.parse(
        stable_regular_bytes(SCRIPT_PATH, "capture selftest source").decode("utf-8")
    )
    definitions = {
        node.name for node in module.body if isinstance(node, ast.FunctionDef)
    }
    forbidden_definitions = {
        "committed_c83_files",
        "materialize_commit_snapshot",
        "parse_ls_tree_records",
        "resolve_full_commit",
    }
    require(
        definitions.isdisjoint(forbidden_definitions),
        "formal C8.3 gate retains a legacy Git-object snapshot helper",
    )
    formal_c83 = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "verify_c83_precondition"
    )

    def call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    formal_calls = {
        name
        for node in ast.walk(formal_c83)
        if isinstance(node, ast.Call) and (name := call_name(node)) is not None
    }
    require(
        formal_calls.isdisjoint(
            forbidden_definitions | {"TemporaryDirectory", "mkdtemp"}
        ),
        "formal C8.3 gate retains a temporary/Git-object snapshot call",
    )
    git_calls = [
        node
        for node in ast.walk(formal_c83)
        if isinstance(node, ast.Call) and call_name(node) == "frozen_git_bytes"
    ]
    command_signatures: set[tuple[str, ...]] = set()
    for call in git_calls:
        require(
            bool(call.args) and isinstance(call.args[0], ast.List),
            "formal C8.3 frozen Git command is not a closed list",
        )
        signature: list[str] = []
        for item in call.args[0].elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                signature.append(item.value)
            elif isinstance(item, ast.JoinedStr):
                signature.append("<formatted>")
            else:
                fail("formal C8.3 frozen Git command contains a dynamic argument")
        command_signatures.add(tuple(signature))
    require(
        command_signatures
        == {
            ("rev-parse", "HEAD"),
            ("rev-parse", "--verify", "<formatted>"),
        },
        "formal C8.3 gate uses a Git command beyond HEAD/tree identity",
    )

    trusted_temp = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-capture-selftest-", dir=trusted_temp
    ) as name:
        root = pathlib.Path(name)
        frozen_c83_fixture = root / "frozen-c83"
        external_c83_fixture = root / "external-c83"
        for relative in C83_RELATIVE_FILES:
            raw = f"synthetic C8.3 {relative}\n".encode("utf-8")
            for fixture in (frozen_c83_fixture, external_c83_fixture):
                destination = fixture.joinpath(*pathlib.PurePosixPath(relative).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                write_bytes_exclusive(destination, raw)
        frozen_c83_files = validate_real_directory_tree(
            frozen_c83_fixture, C83_RELATIVE_FILES, "selftest frozen C8.3 tree"
        )
        external_c83_files = validate_real_directory_tree(
            external_c83_fixture, C83_RELATIVE_FILES, "selftest external C8.3 tree"
        )
        require_matching_c83_trees(external_c83_files, frozen_c83_files)
        (external_c83_fixture / "README.md").write_bytes(b"external mismatch\n")
        try:
            require_matching_c83_trees(
                validate_real_directory_tree(
                    external_c83_fixture,
                    C83_RELATIVE_FILES,
                    "mismatched external C8.3 tree",
                ),
                frozen_c83_files,
            )
        except CaptureError:
            pass
        else:
            fail("selftest accepted an external C8.3 byte mismatch")
        output = root / "capture"
        require(output_directory(output) == output, "outside output path rejected")
        output.mkdir()
        try:
            output_directory(output)
        except CaptureError:
            pass
        else:
            fail("selftest accepted existing output directory")
        canonical_source_path = root / "canonical-source-envelope.json"
        canonical_source_raw = (
            json.dumps(source_root, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            + b"\n"
        )
        write_bytes_exclusive(canonical_source_path, canonical_source_raw)
        loaded_source, loaded_raw, _loaded_identity = canonical_root_file(
            canonical_source_path,
            schema=SOURCE_MATERIALIZATION_SCHEMA,
            version=1,
            label="canonical source selftest",
        )
        require(
            loaded_source == source_root and loaded_raw == canonical_source_raw,
            "canonical source-envelope loader baseline differs",
        )
        noncanonical_source_path = root / "noncanonical-source-envelope.json"
        write_bytes_exclusive(
            noncanonical_source_path,
            (json.dumps(source_root, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        try:
            canonical_root_file(
                noncanonical_source_path,
                schema=SOURCE_MATERIALIZATION_SCHEMA,
                version=1,
                label="noncanonical source selftest",
            )
        except CaptureError:
            pass
        else:
            fail("selftest accepted a noncanonical source materialization root")
        target = root / "atomic.json"
        write_json_exclusive_atomic(target, {"ok": True})
        try:
            write_json_exclusive_atomic(target, {"ok": False})
        except CaptureError:
            pass
        else:
            fail("selftest clobbered an existing output")
        symlink = root / "symlink.json"
        symlink.symlink_to(target)
        try:
            write_json_exclusive_atomic(symlink, {"ok": False})
        except CaptureError:
            pass
        else:
            fail("selftest replaced a symlink output")
        final = root / "published"
        stage = create_capture_stage(final)
        write_bytes_exclusive(stage / "proof", b"closed")
        atomic_publish_directory(stage, final)
        require(
            (final / "proof").read_bytes() == b"closed",
            "atomic capture publication differs",
        )
        blocked_final = root / "blocked"
        blocked_final.mkdir()
        blocked_stage = create_capture_stage(blocked_final)
        try:
            atomic_publish_directory(blocked_stage, blocked_final)
        except CaptureError:
            cleanup_capture_stage(blocked_stage)
        else:
            fail("selftest replaced an existing final capture directory")
        closed_tree = root / "closed-capture-tree"
        closed_tree.mkdir()
        for filename in sorted(CAPTURE_OUTPUT_FILES):
            write_bytes_exclusive(closed_tree / filename, b"synthetic\n")
        validate_capture_output_tree(closed_tree)
        write_bytes_exclusive(closed_tree / "unexpected", b"rogue\n")
        try:
            validate_capture_output_tree(closed_tree)
        except CaptureError:
            pass
        else:
            fail("selftest accepted an extra capture output file")
    print(
        "capture-c84-duo-aot-decision.py selftest: PASS "
        f"({rejected} stream, {aggregate_rejected} aggregate, {replay_rejected} replay/swap, "
        f"{provenance_rejected} provenance, 3 UART, 3 package-path, "
        "C8.3 call-graph/mismatch, percentile/content/tree/no-clobber gates)"
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--selftest", action="store_true")
    value.add_argument("--port", type=pathlib.Path)
    value.add_argument("--output-dir", type=pathlib.Path)
    value.add_argument("--source-commit")
    value.add_argument("--challenge")
    value.add_argument("--expect-c83-source")
    value.add_argument("--expect-c83-challenge")
    value.add_argument(
        "--c83-evidence-root", type=pathlib.Path, default=DEFAULT_C83_ROOT
    )
    value.add_argument("--kernel", type=pathlib.Path)
    value.add_argument("--fit", type=pathlib.Path)
    value.add_argument("--image", type=pathlib.Path)
    value.add_argument("--package-envelope", type=pathlib.Path)
    value.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return value


def main() -> int:
    global _ACTIVE_CAPTURE_STAGE
    arguments = parser().parse_args()
    try:
        operational = (
            arguments.port,
            arguments.output_dir,
            arguments.source_commit,
            arguments.challenge,
            arguments.expect_c83_source,
            arguments.expect_c83_challenge,
            arguments.kernel,
            arguments.fit,
            arguments.image,
            arguments.package_envelope,
        )
        if arguments.selftest:
            require(
                not any(value is not None for value in operational),
                "--selftest does not accept physical capture arguments",
            )
            require(
                arguments.c83_evidence_root == DEFAULT_C83_ROOT,
                "--selftest does not accept --c83-evidence-root",
            )
            require(
                arguments.timeout_seconds == DEFAULT_TIMEOUT_SECONDS,
                "--selftest does not accept --timeout-seconds",
            )
            selftest()
            return 0
        require(
            all(value is not None for value in operational),
            "formal capture requires every identity, artifact, output, and UART argument",
        )
        run_capture(arguments)
        return 0
    except (CaptureError, OSError, UnicodeDecodeError, ValueError) as error:
        print(f"FAIL capture-c84-duo-aot-decision: {error}", file=sys.stderr)
        return 1
    finally:
        if _ACTIVE_CAPTURE_STAGE is not None:
            cleanup_capture_stage(_ACTIVE_CAPTURE_STAGE)
            _ACTIVE_CAPTURE_STAGE = None


if __name__ == "__main__":
    raise SystemExit(main())
