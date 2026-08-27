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
C84_MANIFEST = ROOT / "benchmarks/wasm-aot-decision/workloads-v1.json"
C84_TRANSCRIPT_SCHEMA = ROOT / "benchmarks/wasm-aot-decision/schema-v1.json"
C84_EVIDENCE_SCHEMA = ROOT / "benchmarks/wasm-aot-decision/evidence-schema-v1.json"
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
BUILD_STATUS_POLICY = (
    "git status --porcelain=v1 --untracked-files=all --ignore-submodules=all"
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
    "prepare_jitterentropy_script",
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
    "prepare_jitterentropy_script",
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
JITTERENTROPY_HEAD = "c5bd2e17194fe3a04d17f74027bb67622579405f"
SUNSET_HEAD = "f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e"
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
    "prepare_jitterentropy_script": "scripts/prepare-jitterentropy-rs.sh",
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
    "prepare_jitterentropy_script": "scripts/prepare-jitterentropy-rs.sh",
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


def validate_image_audit(
    raw: bytes,
    *,
    source: str,
    challenge: str,
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
        re.search(r"\b(?:panic|fatal|fail|failed|failure)\b", text, re.IGNORECASE)
        is None,
        f"{label} contains a failure token",
    )
    report_line = lines[-2]
    report = exact(
        strict_json_bytes(report_line.encode("utf-8"), f"{label} report"),
        {"schema", "version", "source_commit", "challenge", "artifacts", "tools"},
        f"{label} report",
    )
    require(
        report["schema"] == C84_IMAGE_REPORT_SCHEMA
        and type(report["version"]) is int
        and report["version"] == 1
        and report["source_commit"] == source
        and report["challenge"] == challenge,
        f"{label} report identity differs",
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
    value: Any, schema: str, label: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = exact(
        value, {"schema", "version", "status", "content_sha256", "content"}, label
    )
    require(
        root["schema"] == schema
        and type(root["version"]) is int
        and root["version"] == 1
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


def make_content_envelope(schema: str, content: dict[str, Any]) -> dict[str, Any]:
    require_finite_json(content, f"{schema} content")
    rendered = json.dumps(content, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "schema": schema,
        "version": 1,
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


def git_bytes(arguments: list[str], label: str) -> bytes:
    environment = {
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(ROOT), *arguments],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot invoke Git for {label}: {error}")
    require(
        completed.returncode == 0,
        f"Git {label} failed: {completed.stderr.decode(errors='replace').strip()}",
    )
    return completed.stdout


def git_head() -> str:
    return canonical_source(
        git_bytes(["rev-parse", "HEAD"], "HEAD").decode().strip(), "Git HEAD"
    )


def resolve_full_commit(value: str, label: str) -> str:
    commit = canonical_source(value, label)
    resolved = (
        git_bytes(["rev-parse", "--verify", f"{commit}^{{commit}}"], label)
        .decode()
        .strip()
    )
    require(
        resolved == commit,
        f"{label} does not resolve to the exact supplied full commit",
    )
    return commit


def git_status() -> str:
    return git_bytes(
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "status",
    ).decode()


def git_preflight(source: str) -> str:
    head = git_head()
    require(head == source, f"source commit must equal current HEAD {head}")
    status = git_status()
    require(
        not status,
        f"formal physical capture requires a clean worktree:\n{status[:2000]}",
    )
    return head


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


def parse_ls_tree_records(
    raw: bytes, expected_paths: set[str], label: str
) -> dict[str, tuple[str, str]]:
    records: dict[str, tuple[str, str]] = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            header, path_raw = encoded.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = header.split(b" ", 2)
            path = path_raw.decode("utf-8")
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
            fail(f"cannot parse {label} ls-tree record: {error}")
        require(path not in records, f"{label} contains duplicate Git path {path}")
        require(path in expected_paths, f"{label} contains unexpected Git path {path}")
        require(
            mode in {"100644", "100755"} and kind == "blob",
            f"{label} contains non-regular Git entry {path}: {mode} {kind}",
        )
        require(
            re.fullmatch(r"[0-9a-f]{40,64}", oid) is not None,
            f"{label} blob id is malformed for {path}",
        )
        records[path] = (mode, oid)
    require(
        set(records) == expected_paths,
        f"{label} Git members differ: {sorted(set(records) ^ expected_paths)}",
    )
    return records


def committed_c83_files(c84_source: str) -> tuple[dict[str, bytes], str]:
    c84_source = resolve_full_commit(c84_source, "C8.4 preparation commit")
    prefix = "benchmarks/wasm-runtime/"
    expected_paths = {prefix + relative for relative in C83_RELATIVE_FILES}
    records = parse_ls_tree_records(
        git_bytes(
            [
                "ls-tree",
                "-rz",
                "--full-tree",
                c84_source,
                "--",
                "benchmarks/wasm-runtime",
            ],
            "C8.3 tree listing",
        ),
        expected_paths,
        "C8.3 tree listing",
    )
    tree_oid = (
        git_bytes(
            ["rev-parse", "--verify", f"{c84_source}:benchmarks/wasm-runtime"],
            "C8.3 Git tree identity",
        )
        .decode()
        .strip()
    )
    require(
        re.fullmatch(r"[0-9a-f]{40,64}", tree_oid) is not None,
        "C8.3 Git tree id is malformed",
    )
    result: dict[str, bytes] = {}
    for relative in C83_RELATIVE_FILES:
        _mode, oid = records[prefix + relative]
        result[relative] = git_bytes(
            ["cat-file", "blob", oid], f"C8.3 committed blob {relative}"
        )
    return result, tree_oid


def materialize_commit_snapshot(c84_source: str, destination: pathlib.Path) -> None:
    import io
    import tarfile

    archive = git_bytes(
        ["archive", "--format=tar", c84_source], "C8.4 preparation archive"
    )
    root = destination.resolve(strict=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            path = pathlib.PurePosixPath(member.name)
            require(
                not path.is_absolute() and ".." not in path.parts,
                f"Git archive contains unsafe path {member.name!r}",
            )
            target = root.joinpath(*path.parts)
            require(
                target == root or root in target.parents,
                f"Git archive path escapes snapshot: {member.name!r}",
            )
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            require(
                member.isreg(),
                f"Git archive contains non-regular entry {member.name!r}",
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            require(
                source is not None, f"cannot read Git archive member {member.name!r}"
            )
            raw = source.read()
            with target.open("xb") as output:
                output.write(raw)
            target.chmod(member.mode & 0o777)


def verify_c83_precondition(
    root: pathlib.Path,
    *,
    c84_source: str,
    c83_source: str,
    c83_challenge: str,
) -> dict[str, Any]:
    c83_source = canonical_source(c83_source, "expected C8.3 source")
    c83_challenge = canonical_challenge(c83_challenge, "expected C8.3 challenge")
    current = validate_real_directory_tree(root, C83_RELATIVE_FILES, "C8.3 evidence")
    committed, tree_oid = committed_c83_files(c84_source)
    for relative in C83_RELATIVE_FILES:
        require(
            current[relative] == committed[relative],
            f"C8.3 {relative} differs from C8.4 preparation commit",
        )
    import tempfile

    trusted_temp = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-c83-snapshot-", dir=trusted_temp
    ) as name:
        snapshot = pathlib.Path(name)
        materialize_commit_snapshot(c84_source, snapshot)
        snapshot_verifier = snapshot / "scripts/verify-c83-evidence.py"
        committed_verifier = stable_regular_bytes(
            snapshot_verifier, "snapshot C8.3 evidence verifier"
        )
        run_checked(
            [
                sys.executable,
                "-I",
                "-B",
                str(snapshot_verifier),
                "--evidence-root",
                str(snapshot / "benchmarks/wasm-runtime"),
                "--expect-source",
                c83_source,
                "--expect-challenge",
                c83_challenge,
            ],
            cwd=snapshot,
            label="independent immutable-snapshot C8.3 evidence verifier",
        )
    summary = strict_json_bytes(current["qemu/summary.json"], "C8.3 QEMU summary")
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
        "tree_sha256": canonical_tree_digest(current),
        "git_tree_oid": tree_oid,
        "results": {
            "sha256": sha256_bytes(current["RESULTS.md"]),
            "bytes": len(current["RESULTS.md"]),
        },
        "verifier": {
            "path": "scripts/verify-c83-evidence.py",
            "sha256": sha256_bytes(committed_verifier),
            "bytes": len(committed_verifier),
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


def validate_source_attestation(value: Any, source: str, label: str) -> dict[str, Any]:
    record = exact(value, {"root", "head", "worktree_clean", "status_policy"}, label)
    require(
        isinstance(record["root"], str)
        and pathlib.PurePath(record["root"]).is_absolute(),
        f"{label}.root is not absolute",
    )
    require(
        record["head"] == source and record["worktree_clean"] is True,
        f"{label} is not clean/exact",
    )
    require(
        record["status_policy"] == STRICT_STATUS_POLICY,
        f"{label} status policy differs",
    )
    return record


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
    build: dict[str, Any], source: str, challenge: str
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
        {
            "root",
            "head",
            "superproject_clean",
            "status_policy",
            "jitterentropy",
            "sunset",
        },
        "C8.4 build source",
    )
    require(
        source_record["root"] == "."
        and source_record["head"] == source
        and source_record["superproject_clean"] is True
        and source_record["status_policy"] == BUILD_STATUS_POLICY,
        "C8.4 build source attestation differs",
    )
    jitter = exact(
        source_record["jitterentropy"],
        {
            "path",
            "head",
            "patch_sha256",
            "patch_bytes",
            "observed_diff_sha256",
            "observed_diff_bytes",
            "policy",
        },
        "C8.4 build jitterentropy source",
    )
    require(
        jitter["path"] == "vendor/jitterentropy-rs"
        and jitter["head"] == JITTERENTROPY_HEAD,
        "C8.4 jitterentropy path/head differs",
    )
    canonical_sha(jitter["patch_sha256"], "C8.4 jitterentropy patch")
    canonical_sha(jitter["observed_diff_sha256"], "C8.4 jitterentropy observed diff")
    integer(jitter["patch_bytes"], "C8.4 jitterentropy patch bytes", minimum=1)
    integer(jitter["observed_diff_bytes"], "C8.4 jitterentropy diff bytes", minimum=1)
    require(
        jitter["patch_sha256"] == jitter["observed_diff_sha256"]
        and jitter["patch_bytes"] == jitter["observed_diff_bytes"],
        "C8.4 jitterentropy reviewed delta differs",
    )
    require(
        jitter["policy"]
        == "exact recorded patch verified by prepare-jitterentropy-rs.sh",
        "C8.4 jitterentropy policy differs",
    )
    sunset = exact(
        source_record["sunset"],
        {"path", "head", "worktree_clean", "status_policy"},
        "C8.4 build sunset source",
    )
    require(
        sunset["path"] == "vendor/sunset"
        and sunset["head"] == SUNSET_HEAD
        and sunset["worktree_clean"] is True
        and sunset["status_policy"] == STRICT_STATUS_POLICY,
        "C8.4 sunset attestation differs",
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


def validate_package_source(value: Any, source: str) -> dict[str, Any]:
    record = exact(
        value,
        {
            "root",
            "head",
            "superproject_clean",
            "status_policy",
            "jitterentropy",
            "sunset",
        },
        "C8.4 package source",
    )
    canonical_absolute_recorded_path(record["root"], "C8.4 package source root")
    require(
        record["head"] == source
        and record["superproject_clean"] is True
        and record["status_policy"] == BUILD_STATUS_POLICY,
        "C8.4 package source attestation differs",
    )
    jitter = exact(
        record["jitterentropy"],
        {
            "path",
            "head",
            "patch_sha256",
            "patch_bytes",
            "observed_diff_sha256",
            "observed_diff_bytes",
            "policy",
        },
        "C8.4 package jitterentropy source",
    )
    canonical_absolute_recorded_path(jitter["path"], "C8.4 package jitterentropy path")
    require(
        jitter["head"] == JITTERENTROPY_HEAD, "C8.4 package jitterentropy head differs"
    )
    canonical_sha(jitter["patch_sha256"], "C8.4 package jitterentropy patch")
    canonical_sha(jitter["observed_diff_sha256"], "C8.4 package jitterentropy diff")
    integer(jitter["patch_bytes"], "C8.4 package jitterentropy patch bytes", minimum=1)
    integer(
        jitter["observed_diff_bytes"],
        "C8.4 package jitterentropy diff bytes",
        minimum=1,
    )
    require(
        jitter["patch_sha256"] == jitter["observed_diff_sha256"]
        and jitter["patch_bytes"] == jitter["observed_diff_bytes"]
        and jitter["policy"]
        == "exact recorded patch verified by prepare-jitterentropy-rs.sh",
        "C8.4 package reviewed delta differs",
    )
    sunset = exact(
        record["sunset"],
        {"path", "head", "worktree_clean", "status_policy"},
        "C8.4 package sunset source",
    )
    canonical_absolute_recorded_path(sunset["path"], "C8.4 package sunset path")
    require(
        sunset["head"] == SUNSET_HEAD
        and sunset["worktree_clean"] is True
        and sunset["status_policy"] == STRICT_STATUS_POLICY,
        "C8.4 package sunset attestation differs",
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
    require(
        package_source["jitterentropy"]["path"]
        == str(recorded_source_root / "vendor/jitterentropy-rs")
        and package_source["sunset"]["path"]
        == str(recorded_source_root / "vendor/sunset"),
        "C8.4 package submodule paths are not closed under the source root",
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


def validate_package_evidence(source: str, challenge: str) -> PackageEvidence:
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
    )
    build_root, build = canonical_content_envelope(
        strict_json_bytes(build_raw, "C8.4 build envelope"),
        "vibeos.c84.duo-wasm-aot-profile.build-envelope",
        "C8.4 build envelope",
    )
    run_id, build_artifacts = validate_build_content(build, source, challenge)
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
    package_source = validate_package_source(package["source"], source)
    sdk = exact(
        package["sdk"],
        {
            "root",
            "commit",
            "commit_provenance",
            "declared_container_digest",
            "container_digest_provenance",
            "worktree_clean",
            "status_policy",
        },
        "C8.4 package SDK",
    )
    canonical_absolute_recorded_path(sdk["root"], "C8.4 SDK root")
    require(sdk["commit"] == SDK_COMMIT, f"C8.4 SDK commit must be {SDK_COMMIT}")
    require(
        sdk["declared_container_digest"] == SDK_CONTAINER_DIGEST,
        f"C8.4 SDK container digest must be {SDK_CONTAINER_DIGEST}",
    )
    require(
        sdk["commit_provenance"]
        == "operator-declared; local checkout HEAD equality verified"
        and sdk["container_digest_provenance"]
        == "operator-declared; runtime container identity not attested",
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
        artifacts=artifacts,
        tools=tools,
        label="C8.4 package image audit",
    )
    require(
        verifier["report"] == audit_report
        and verifier["report_sha256"] == audit_report_sha256,
        "C8.4 package verifier report binding differs",
    )
    require(
        package_source["jitterentropy"]["patch_sha256"]
        == tools["jitterentropy_patch"]["sha256"]
        and package_source["jitterentropy"]["patch_bytes"]
        == tools["jitterentropy_patch"]["bytes"],
        "C8.4 package source/tool patch binding differs",
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
        fail(f"capture output must be outside the clean checkout: {absolute}")
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
    require(
        sys.stdin.isatty(),
        "physical cold-boot confirmations require an interactive terminal",
    )
    source = canonical_source(arguments.source_commit, "C8.4 source commit")
    challenge = canonical_challenge(arguments.challenge, "C8.4 challenge")
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
    head = git_preflight(source)
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
    package = validate_package_evidence(source, challenge)
    tool_identities = {
        "capture_script": file_identity(SCRIPT_PATH),
        "single_boot_verifier": file_identity(C84_VERIFIER),
        "final_evidence_verifier": file_identity(C84_EVIDENCE_VERIFIER),
        "c83_evidence_verifier": file_identity(C83_EVIDENCE_VERIFIER),
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
    package_closed = validate_package_evidence(source, challenge)
    require(
        package_closed == package,
        "package evidence or artifacts changed during capture",
    )
    require(git_preflight(source) == head, "C8.4 source changed during capture")
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
    for key, path in {
        "capture_script": SCRIPT_PATH,
        "single_boot_verifier": C84_VERIFIER,
        "final_evidence_verifier": C84_EVIDENCE_VERIFIER,
        "c83_evidence_verifier": C83_EVIDENCE_VERIFIER,
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
        "git_head": head,
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
    envelope = make_content_envelope(
        "vibeos.c84.duo-aot-decision.capture-envelope", content
    )
    envelope_identity = write_json_exclusive_atomic(
        output / "capture-envelope.json", envelope
    )
    atomic_publish_directory(output, final_output)
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

    recorded_source_root = pathlib.PurePosixPath("/producer/vibeos")
    recorded_sdk_root = pathlib.PurePosixPath("/producer/sdk")
    recorded_artifact_root = recorded_source_root / "target/milkv-duo-wasm-aot-profile"
    package_source_paths = {
        "root": str(recorded_source_root),
        "jitterentropy": {
            "path": str(recorded_source_root / "vendor/jitterentropy-rs")
        },
        "sunset": {"path": str(recorded_source_root / "vendor/sunset")},
    }
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

    import tempfile

    trusted_temp = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-capture-selftest-", dir=trusted_temp
    ) as name:
        root = pathlib.Path(name)
        output = root / "capture"
        require(output_directory(output) == output, "outside output path rejected")
        output.mkdir()
        try:
            output_directory(output)
        except CaptureError:
            pass
        else:
            fail("selftest accepted existing output directory")
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
    print(
        "capture-c84-duo-aot-decision.py selftest: PASS "
        f"({rejected} stream, {aggregate_rejected} aggregate, {replay_rejected} replay/swap, "
        "3 UART, 3 package-path, percentile/content/tree/no-clobber gates)"
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
