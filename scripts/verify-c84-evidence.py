#!/usr/bin/env python3
"""Verify and close the complete three-cold-boot C8.4 evidence tree.

The verifier does not trust the current checkout as the preparation source. It
resolves an explicit full C8.4 commit with replacement objects disabled,
materializes an immutable archive, proves that the complete checked-in C8.3
tree is byte-identical to that commit, and runs that commit's C8.3 verifier over
the snapshot. It then reruns the C8.4 single-boot verifier for three distinct
raw transcripts and derives the dual-threshold decision from all 63 retained
samples. QEMU input is forbidden.

``DECISION.json`` is no-clobber by default and is written only after every gate
passes. No failure is converted into an ``aot-not-justified`` outcome.
"""

from __future__ import annotations

import argparse
import datetime
import errno
import hashlib
import io
import json
import math
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any, NoReturn, Sequence


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = pathlib.Path(__file__).resolve()
C84_BENCHMARK_ROOT = ROOT / "benchmarks/wasm-aot-decision"
C83_BENCHMARK_ROOT = ROOT / "benchmarks/wasm-runtime"
C84_MANIFEST = C84_BENCHMARK_ROOT / "workloads-v1.json"
C84_TRANSCRIPT_SCHEMA = C84_BENCHMARK_ROOT / "schema-v1.json"
C84_EVIDENCE_SCHEMA = C84_BENCHMARK_ROOT / "evidence-schema-v1.json"
C84_README = C84_BENCHMARK_ROOT / "README.md"
C84_CAPTURE = ROOT / "scripts/capture-c84-duo-aot-decision.py"
C84_SINGLE_BOOT_VERIFIER = ROOT / "scripts/verify-c84-aot-decision.py"
C83_EVIDENCE_VERIFIER = ROOT / "scripts/verify-c83-evidence.py"
DOCKER_GIT_CONFIG_TEMPLATE = ROOT / "scripts/c84-docker.gitconfig"
DOCKER_GIT_CONFIG_RUNTIME = pathlib.Path("/etc/vibeos-c84.gitconfig")
DOCKER_GIT_CONFIG_BYTES = (
    b"[safe]\n"
    b"\tdirectory = /home/vibeos\n"
    b"\tdirectory = /home/vibeos/vendor/jitterentropy-rs\n"
    b"\tdirectory = /home/vibeos/vendor/sunset\n"
    b"\tdirectory = /home/work\n"
)

PLATFORM = "milkv-duo-cv1800b"
WORKLOAD_ID = "ssh-case-filter-12k-v1"
BOOT_COUNT = 3
WARMUPS_PER_BOOT = 3
RETAINED_PER_BOOT = 21
RETAINED_TOTAL = 63
BUDGET_TICKS = 2_500_000
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_OID = re.compile(r"[0-9a-f]{40,64}\Z")
TEST_SOURCE = "1" * 40
TEST_CHALLENGE = "2" * 64
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
META_PREFIX = b"VIBE_WASM_AOT_META "
SAMPLE_PREFIX = b"VIBE_WASM_AOT_SAMPLE "
END_PREFIX = b"VIBE_WASM_AOT_END "
MAX_RAW_BYTES = 268_435_456
MAX_SUMMARY_BYTES = 1_048_576
MAX_ENVELOPE_BYTES = 16_777_216
SDK_COMMIT = "23eb84fecb29585dbb5728d6b7e2475ff273baac"
SDK_CONTAINER_DIGEST = (
    "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679"
)
C84_PREPARATION_FILES = (
    "README.md",
    "schema-v1.json",
    "workloads-v1.json",
    "evidence-schema-v1.json",
)
C84_DUO_FILES = tuple(
    sorted(
        (
            "build-envelope.json",
            "package-envelope.json",
            "package-image-verifier-audit.log",
            "capture-envelope.json",
            *(f"boot-{index}.uart.log" for index in range(BOOT_COUNT)),
            *(f"boot-{index}.summary.json" for index in range(BOOT_COUNT)),
        )
    )
)
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


class EvidenceError(RuntimeError):
    """The C8.4 physical evidence boundary is not closed."""


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


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


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(
        set(value) == keys,
        f"{label} fields are not closed: {sorted(set(value) ^ keys)}",
    )
    return value


def integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int = (1 << 64) - 1
) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label} is not an integer",
    )
    require(minimum <= value <= maximum, f"{label} is outside [{minimum}, {maximum}]")
    return value


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


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def campaign_run_id(
    source: str,
    challenge: str,
    manifest_raw: bytes,
    transcript_schema_raw: bytes,
    label: str,
) -> str:
    """Recompute the frozen campaign identity from immutable contract bytes."""
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
        require(stat.S_ISREG(before.st_mode), f"{label} is not a real regular file")
        require(before.st_size > 0, f"{label} is empty")
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


def file_identity(
    path: pathlib.Path, label: str = "file", *, maximum: int | None = None
) -> dict[str, Any]:
    raw = stable_regular_bytes(path, label, maximum=maximum)
    return {"sha256": sha256_bytes(raw), "bytes": len(raw)}


def identity_record(
    value: Any, label: str, *, file_key: str | None = None
) -> dict[str, Any]:
    keys = {"sha256", "bytes"} if file_key is None else {file_key, "sha256", "bytes"}
    record = exact(value, keys, label)
    if file_key is not None:
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


def same_identity(actual: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    require(actual["sha256"] == expected["sha256"], f"{label} SHA-256 differs")
    require(actual["bytes"] == expected["bytes"], f"{label} bytes differ")


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
        measured = identity_record(
            report_artifacts[report_role], f"{label} artifact {report_role}"
        )
        expected = identity_record(
            artifacts[envelope_role],
            f"{label} package artifact {envelope_role}",
            file_key="path",
        )
        same_identity(measured, expected, f"{label} artifact {report_role}")
    for report_role, envelope_role in IMAGE_REPORT_TOOL_ROLES.items():
        measured = identity_record(
            report_tools[report_role], f"{label} tool {report_role}"
        )
        expected = identity_record(
            tools[envelope_role],
            f"{label} package tool {envelope_role}",
            file_key="path",
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


def utc(value: Any, label: str) -> datetime.datetime:
    require(
        isinstance(value, str) and value.endswith("Z"), f"{label} is not canonical UTC"
    )
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"{label} is invalid: {error}")
    require(parsed.utcoffset() == datetime.timedelta(0), f"{label} is not UTC")
    return parsed


def run_checked(command: list[str], *, cwd: pathlib.Path, label: str) -> str:
    environment = {
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
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
    require(
        completed.returncode == 0,
        f"{label} failed: {(completed.stderr or completed.stdout).strip()}",
    )
    return completed.stdout


def docker_git_config_path() -> pathlib.Path:
    template = stable_regular_bytes(
        DOCKER_GIT_CONFIG_TEMPLATE,
        "committed C8.4 Docker Git config",
        maximum=4096,
    )
    require(
        template == DOCKER_GIT_CONFIG_BYTES,
        "committed C8.4 Docker Git config bytes differ from the closed allowlist",
    )
    if not DOCKER_GIT_CONFIG_RUNTIME.exists():
        require(
            ROOT != pathlib.Path("/home/vibeos"),
            "formal C8.4 verification is missing /etc/vibeos-c84.gitconfig",
        )
        return DOCKER_GIT_CONFIG_TEMPLATE
    runtime = stable_regular_bytes(
        DOCKER_GIT_CONFIG_RUNTIME,
        "mounted C8.4 Docker Git config",
        maximum=4096,
    )
    require(
        runtime == DOCKER_GIT_CONFIG_BYTES,
        "mounted C8.4 Docker Git config bytes differ from the closed allowlist",
    )
    try:
        descriptor = os.open(
            DOCKER_GIT_CONFIG_RUNTIME,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        require(
            error.errno in (errno.EACCES, errno.EROFS),
            f"cannot prove mounted C8.4 Docker Git config is read-only: {error}",
        )
    else:
        os.close(descriptor)
        fail("mounted C8.4 Docker Git config is writable")
    return DOCKER_GIT_CONFIG_RUNTIME


def git_bytes(arguments: list[str], label: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": str(docker_git_config_path()),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
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


def resolve_full_commit(value: Any, label: str) -> str:
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
            f"{label} contains symlink/gitlink/non-blob {path}: {mode} {kind}",
        )
        require(
            HEX_OID.fullmatch(oid) is not None,
            f"{label} has malformed blob oid for {path}",
        )
        records[path] = (mode, oid)
    require(
        set(records) == expected_paths,
        f"{label} members differ: {sorted(set(records) ^ expected_paths)}",
    )
    return records


def committed_files(
    commit: str, prefix: str, relatives: Sequence[str], label: str
) -> tuple[dict[str, bytes], str]:
    commit = resolve_full_commit(commit, "C8.4 preparation commit")
    expected = {prefix + relative for relative in relatives}
    records = parse_ls_tree_records(
        git_bytes(
            ["ls-tree", "-rz", "--full-tree", commit, "--", prefix.rstrip("/")], label
        ),
        expected,
        label,
    )
    tree_oid = (
        git_bytes(
            ["rev-parse", "--verify", f"{commit}:{prefix.rstrip('/')}"],
            f"{label} tree oid",
        )
        .decode()
        .strip()
    )
    require(HEX_OID.fullmatch(tree_oid) is not None, f"{label} tree oid is malformed")
    result: dict[str, bytes] = {}
    for relative in relatives:
        _mode, oid = records[prefix + relative]
        result[relative] = git_bytes(
            ["cat-file", "blob", oid], f"{label} blob {relative}"
        )
    return result, tree_oid


def materialize_commit(commit: str, destination: pathlib.Path) -> None:
    commit = resolve_full_commit(commit, "C8.4 preparation commit")
    archive = git_bytes(["archive", "--format=tar", commit], "C8.4 preparation archive")
    root = destination.resolve(strict=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            pure = pathlib.PurePosixPath(member.name)
            require(
                not pure.is_absolute() and ".." not in pure.parts,
                f"Git archive contains unsafe path {member.name!r}",
            )
            target = root.joinpath(*pure.parts)
            require(
                target == root or root in target.parents,
                f"Git archive member escapes snapshot {member.name!r}",
            )
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            require(
                member.isreg(),
                f"Git archive contains non-regular member {member.name!r}",
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            require(
                source is not None, f"cannot extract Git archive member {member.name!r}"
            )
            with target.open("xb") as output:
                output.write(source.read())
            target.chmod(member.mode & 0o777)


def canonical_tree_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(b"vibeos.c84.c83-precondition-tree.v1\0")
    for relative in sorted(files):
        raw = files[relative]
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    return digest.hexdigest()


def read_exact_regular_tree(
    root: pathlib.Path, relatives: Sequence[str], label: str
) -> dict[str, bytes]:
    expected = set(relatives)
    require(len(expected) == len(relatives), f"{label} expected paths are duplicated")
    expected_directories: set[str] = set()
    for relative in expected:
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
    identities: set[tuple[int, int]] = set()
    result: dict[str, bytes] = {}
    actual_files: set[str] = set()
    actual_directories: set[str] = set()

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
        actual_files == expected,
        f"{label} file members differ: {sorted(actual_files ^ expected)}",
    )
    require(
        actual_directories == expected_directories,
        f"{label} directory members differ: {sorted(actual_directories ^ expected_directories)}",
    )
    return result


def c83_precondition(
    *,
    current_root: pathlib.Path,
    snapshot: pathlib.Path,
    c84_source: str,
    c83_source: str,
    c83_challenge: str,
) -> dict[str, Any]:
    c83_source = canonical_source(c83_source, "expected C8.3 source")
    c83_challenge = canonical_challenge(c83_challenge, "expected C8.3 challenge")
    current = read_exact_regular_tree(
        current_root, C83_RELATIVE_FILES, "current C8.3 evidence"
    )
    committed, tree_oid = committed_files(
        c84_source,
        "benchmarks/wasm-runtime/",
        C83_RELATIVE_FILES,
        "C8.3 preparation tree",
    )
    require(
        current == committed,
        "current C8.3 evidence tree differs byte-for-byte from C8.4 preparation commit",
    )
    snapshot_root = snapshot / "benchmarks/wasm-runtime"
    snapshot_files = read_exact_regular_tree(
        snapshot_root, C83_RELATIVE_FILES, "snapshot C8.3 evidence"
    )
    require(
        snapshot_files == committed, "materialized C8.3 snapshot differs from Git blobs"
    )
    verifier = snapshot / "scripts/verify-c83-evidence.py"
    verifier_raw = stable_regular_bytes(verifier, "snapshot C8.3 verifier")
    run_checked(
        [
            sys.executable,
            "-I",
            "-B",
            str(verifier),
            "--evidence-root",
            str(snapshot_root),
            "--expect-source",
            c83_source,
            "--expect-challenge",
            c83_challenge,
        ],
        cwd=snapshot,
        label="immutable-snapshot complete C8.3 verifier",
    )
    qemu_summary = strict_json_bytes(
        snapshot_files["qemu/summary.json"], "snapshot C8.3 QEMU summary"
    )
    require(
        isinstance(qemu_summary, dict), "snapshot C8.3 QEMU summary is not an object"
    )
    require(qemu_summary.get("source_commit") == c83_source, "C8.3 source differs")
    require(qemu_summary.get("challenge") == c83_challenge, "C8.3 challenge differs")
    run_id = canonical_sha(qemu_summary.get("run_id"), "C8.3 run id")
    return {
        "status": "verified-complete",
        "source_commit": c83_source,
        "challenge": c83_challenge,
        "run_id": run_id,
        "tree_digest_algorithm": "sha256(domain-NUL,path-NUL,length-NUL,bytes)*",
        "tree_sha256": canonical_tree_digest(snapshot_files),
        "git_tree_oid": tree_oid,
        "results": {
            "sha256": sha256_bytes(snapshot_files["RESULTS.md"]),
            "bytes": len(snapshot_files["RESULTS.md"]),
        },
        "verifier": {
            "path": "scripts/verify-c83-evidence.py",
            "sha256": sha256_bytes(verifier_raw),
            "bytes": len(verifier_raw),
        },
        "c84_preparation_commit": c84_source,
        "commit_tree_byte_match": True,
    }


@dataclass(frozen=True)
class EvidenceTree:
    root: pathlib.Path
    files: dict[str, bytes]
    decision_present: bool


def validate_c84_tree(root: pathlib.Path, *, decision_required: bool) -> EvidenceTree:
    root = pathlib.Path(os.path.abspath(os.fspath(root.expanduser())))
    try:
        mode = root.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect C8.4 evidence root: {error}")
    require(
        stat.S_ISDIR(mode) and not stat.S_ISLNK(mode),
        "C8.4 evidence root is not a real directory",
    )
    required_top = set(C84_PREPARATION_FILES) | {"duo"}
    allowed_top = required_top | {"DECISION.json"}
    actual_top = {entry.name for entry in root.iterdir()}
    if decision_required:
        require(
            actual_top == allowed_top,
            f"C8.4 evidence root entries differ: {sorted(actual_top ^ allowed_top)}",
        )
    else:
        require(
            required_top <= actual_top <= allowed_top,
            f"C8.4 evidence root entries differ: {sorted(actual_top ^ allowed_top)}",
        )
    duo = root / "duo"
    require(
        stat.S_ISDIR(duo.lstat().st_mode) and not stat.S_ISLNK(duo.lstat().st_mode),
        "C8.4 duo evidence is not a real directory",
    )
    duo_actual = {entry.name for entry in duo.iterdir()}
    require(
        duo_actual == set(C84_DUO_FILES),
        f"C8.4 duo entries differ: {sorted(duo_actual ^ set(C84_DUO_FILES))}",
    )
    relatives = [*C84_PREPARATION_FILES, *(f"duo/{name}" for name in C84_DUO_FILES)]
    if "DECISION.json" in actual_top:
        relatives.append("DECISION.json")
    files = read_exact_regular_tree(root, relatives, "C8.4 evidence")
    # QEMU has no role in the C8.4 decision tree, including disguised case variants.
    require(
        all(
            "qemu" not in part.lower()
            for relative in relatives
            for part in pathlib.PurePosixPath(relative).parts
        ),
        "QEMU input is forbidden in C8.4 evidence",
    )
    return EvidenceTree(
        root=root, files=files, decision_present="DECISION.json" in actual_top
    )


def validate_preparation(
    tree: EvidenceTree,
    *,
    snapshot: pathlib.Path,
    c84_source: str,
) -> dict[str, Any]:
    committed, _tree_oid = committed_files(
        c84_source,
        "benchmarks/wasm-aot-decision/",
        C84_PREPARATION_FILES,
        "C8.4 preparation contracts",
    )
    for relative in C84_PREPARATION_FILES:
        current = tree.files[relative]
        require(
            current == committed[relative],
            f"C8.4 {relative} differs from preparation commit",
        )
        snapshot_raw = stable_regular_bytes(
            snapshot / "benchmarks/wasm-aot-decision" / relative,
            f"snapshot C8.4 {relative}",
        )
        require(
            snapshot_raw == committed[relative],
            f"snapshot C8.4 {relative} differs from Git blob",
        )
    manifest = strict_json_bytes(
        committed["workloads-v1.json"], "C8.4 workload manifest"
    )
    transcript_schema = strict_json_bytes(
        committed["schema-v1.json"], "C8.4 transcript schema"
    )
    evidence_schema = strict_json_bytes(
        committed["evidence-schema-v1.json"], "C8.4 evidence schema"
    )
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
    require(
        isinstance(sampling, dict)
        and (
            sampling.get("cold_boots"),
            sampling.get("warmup_per_boot"),
            sampling.get("retained_per_boot"),
            sampling.get("retained_total"),
        )
        == (BOOT_COUNT, WARMUPS_PER_BOOT, RETAINED_PER_BOOT, RETAINED_TOTAL),
        "C8.4 sampling contract differs",
    )
    require(
        isinstance(manifest.get("budget"), dict)
        and manifest["budget"].get("ticks") == BUDGET_TICKS,
        "C8.4 budget differs",
    )
    require(
        isinstance(transcript_schema, dict)
        and transcript_schema.get("$id")
        == "https://vibeos.invalid/schemas/wasm-aot-decision-v1.json",
        "C8.4 transcript schema identity differs",
    )
    require(
        isinstance(evidence_schema, dict)
        and evidence_schema.get("$id")
        == "https://vibeos.invalid/schemas/wasm-aot-decision-evidence-v1.json",
        "C8.4 evidence schema identity differs",
    )
    critical = {
        "capture_script": "scripts/capture-c84-duo-aot-decision.py",
        "single_boot_verifier": "scripts/verify-c84-aot-decision.py",
        "final_evidence_verifier": "scripts/verify-c84-evidence.py",
        "c83_evidence_verifier": "scripts/verify-c83-evidence.py",
        "manifest": "benchmarks/wasm-aot-decision/workloads-v1.json",
        "transcript_schema": "benchmarks/wasm-aot-decision/schema-v1.json",
        "evidence_schema": "benchmarks/wasm-aot-decision/evidence-schema-v1.json",
    }
    identities: dict[str, dict[str, Any]] = {}
    for key, relative in critical.items():
        raw = stable_regular_bytes(snapshot / relative, f"snapshot {key}")
        # The evidence commit may add only evidence; executable closure inputs
        # must still be byte-identical to the preparation commit.
        current_path = ROOT / relative
        current_raw = stable_regular_bytes(current_path, f"current {key}")
        require(
            current_raw == raw, f"current {key} differs from C8.4 preparation commit"
        )
        identities[key] = {"sha256": sha256_bytes(raw), "bytes": len(raw)}
    return {
        "commit": c84_source,
        "contracts": {
            "README.md": {
                "sha256": sha256_bytes(committed["README.md"]),
                "bytes": len(committed["README.md"]),
            },
            "schema-v1.json": {
                "sha256": sha256_bytes(committed["schema-v1.json"]),
                "bytes": len(committed["schema-v1.json"]),
            },
            "workloads-v1.json": {
                "sha256": sha256_bytes(committed["workloads-v1.json"]),
                "bytes": len(committed["workloads-v1.json"]),
            },
            "evidence-schema-v1.json": {
                "sha256": sha256_bytes(committed["evidence-schema-v1.json"]),
                "bytes": len(committed["evidence-schema-v1.json"]),
            },
        },
        "tools": identities,
    }


@dataclass(frozen=True)
class PackageClosure:
    build_root: dict[str, Any]
    build_content: dict[str, Any]
    package_root: dict[str, Any]
    package_content: dict[str, Any]
    build_identity: dict[str, Any]
    package_identity: dict[str, Any]
    audit_identity: dict[str, Any]
    run_id: str


def explicit_existing_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    expanded = pathlib.Path(os.path.expanduser(os.fspath(path)))
    require(expanded.is_absolute(), f"{label} must be an explicit absolute path")
    absolute, descriptor = open_directory_chain(expanded, label)
    try:
        require(
            stat.S_ISDIR(os.fstat(descriptor).st_mode), f"{label} is not a directory"
        )
    finally:
        os.close(descriptor)
    return absolute


def bind_recorded_identity(
    record: dict[str, Any], actual_path: pathlib.Path, label: str
) -> dict[str, Any]:
    actual = file_identity(actual_path, f"live {label}")
    expected = identity_record(record, f"recorded {label}", file_key="path")
    same_identity(actual, expected, label)
    return actual


def bind_recorded_path(
    record: dict[str, Any],
    actual_path: pathlib.Path,
    label: str,
    *,
    recorded_path: str,
) -> dict[str, Any]:
    expected = identity_record(record, f"recorded {label}", file_key="path")
    require(expected["path"] == recorded_path, f"{label} recorded path differs")
    return bind_recorded_identity(record, actual_path, label)


def require_exact_flat_regular_directory(
    root: pathlib.Path, names: set[str], label: str
) -> None:
    _root, directory_fd = open_directory_chain(root, label)
    root_identity = (os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino)
    try:
        actual = set(os.listdir(directory_fd))
        require(actual == names, f"{label} entries differ: {sorted(actual ^ names)}")
        inodes: set[tuple[int, int]] = set()
        for name in sorted(actual):
            status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(
                stat.S_ISREG(status.st_mode) and status.st_size > 0,
                f"{label} entry is not a non-empty regular file: {name}",
            )
            inode = (status.st_dev, status.st_ino)
            require(inode not in inodes, f"{label} contains hardlink alias {name}")
            inodes.add(inode)
        _again, reopened_fd = open_directory_chain(root, f"{label} recheck")
        try:
            require(
                (os.fstat(reopened_fd).st_dev, os.fstat(reopened_fd).st_ino)
                == root_identity,
                f"{label} ancestor path changed while inspected",
            )
        finally:
            os.close(reopened_fd)
    finally:
        os.close(directory_fd)


def sdk_git_bytes(sdk_root: pathlib.Path, arguments: list[str], label: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": str(docker_git_config_path()),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(sdk_root), *arguments],
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


def validate_live_sdk(sdk_root: pathlib.Path) -> None:
    top = sdk_git_bytes(sdk_root, ["rev-parse", "--show-toplevel"], "C8.4 SDK root")
    head = sdk_git_bytes(sdk_root, ["rev-parse", "HEAD"], "C8.4 SDK HEAD")
    status = sdk_git_bytes(
        sdk_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "C8.4 SDK status",
    )
    require(
        pathlib.Path(top.decode().strip()) == sdk_root,
        "--sdk-root does not name the SDK Git root",
    )
    require(head.decode().strip() == SDK_COMMIT, f"SDK HEAD is not {SDK_COMMIT}")
    require(not status, "SDK checkout is not clean")


def package_live_paths(
    artifact_root: pathlib.Path, sdk_root: pathlib.Path
) -> tuple[dict[str, pathlib.Path], dict[str, pathlib.Path]]:
    artifacts = {
        "kernel_elf": artifact_root / "vibeos-milkv-duo-wasm-aot-profile.elf",
        "kernel_binary": artifact_root / "vibeos-milkv-duo.bin",
        "packaged_fit_source": artifact_root / "milkv-duo.its",
        "packaged_dtb": artifact_root / "cv1800b_milkv_duo_sd.dtb",
        "fit_boot_sd": artifact_root / "boot.sd",
        "full_sd_image": artifact_root / "vibeos-milkv-duo-wasm-aot-profile-sd.img",
        "sdk_fip": sdk_root / "install/soc_cv1800b_milkv_duo_sd/fip.bin",
        "sdk_dtb": sdk_root
        / "linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb",
    }
    sdk_tools = {
        "sdk_mkimage": sdk_root
        / "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/mkimage",
        "sdk_dumpimage": sdk_root
        / "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/dumpimage",
    }
    primary_genimage = (
        sdk_root
        / "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage"
    )
    fallback_genimage = (
        sdk_root
        / "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/per-package/host-genimage/host/bin/genimage"
    )
    try:
        require(
            os.access(primary_genimage, os.X_OK),
            "primary SDK genimage is not executable",
        )
        stable_regular_bytes(primary_genimage, "primary SDK genimage")
    except EvidenceError:
        sdk_tools["sdk_genimage"] = fallback_genimage
    else:
        sdk_tools["sdk_genimage"] = primary_genimage
    return artifacts, sdk_tools


def bind_package_live_state(
    *,
    build: dict[str, Any],
    package: dict[str, Any],
    snapshot: pathlib.Path,
    artifact_root: pathlib.Path,
    sdk_root: pathlib.Path,
) -> tuple[dict[str, pathlib.Path], dict[str, pathlib.Path]]:
    expected_artifact_root = explicit_existing_directory(
        ROOT / "target/milkv-duo-wasm-aot-profile", "canonical C8.4 target root"
    )
    require(
        artifact_root == expected_artifact_root,
        f"--artifact-root must be {expected_artifact_root}",
    )
    require_exact_flat_regular_directory(
        artifact_root,
        {
            "vibeos-milkv-duo-wasm-aot-profile.elf",
            "vibeos-milkv-duo.bin",
            "milkv-duo.its",
            "cv1800b_milkv_duo_sd.dtb",
            "boot.sd",
            "vibeos-milkv-duo-wasm-aot-profile-sd.img",
            "build-envelope.json",
            "package-envelope.json",
            "image-verifier-audit.log",
        },
        "published C8.4 artifact root",
    )
    validate_live_sdk(sdk_root)
    artifact_paths, sdk_tool_paths = package_live_paths(artifact_root, sdk_root)
    build_tools = exact(build["tools"], BUILD_TOOL_KEYS, "C8.4 build tools")
    package_tools = exact(package["tools"], PACKAGE_TOOL_KEYS, "C8.4 package tools")
    package_source = package["source"]
    recorded_source_root = canonical_absolute_recorded_path(
        package_source["root"], "C8.4 package source root"
    )
    recorded_sdk_root = canonical_absolute_recorded_path(
        package["sdk"]["root"], "C8.4 package SDK root"
    )
    package_artifacts = exact(
        package["artifacts"],
        set(artifact_paths),
        "C8.4 package artifacts",
    )
    recorded_kernel_elf = canonical_absolute_recorded_path(
        package_artifacts["kernel_elf"]["path"],
        "C8.4 package kernel ELF path",
    )
    recorded_artifact_root = recorded_kernel_elf.parent
    require(
        recorded_source_root.is_absolute()
        and package_source["jitterentropy"]["path"]
        == str(recorded_source_root / "vendor/jitterentropy-rs")
        and package_source["sunset"]["path"]
        == str(recorded_source_root / "vendor/sunset"),
        "C8.4 package source paths are not closed under the recorded root",
    )
    require(
        recorded_artifact_root
        == recorded_source_root / "target/milkv-duo-wasm-aot-profile",
        "C8.4 package artifact root differs from the fixed source target",
    )
    require(
        package["build"]["envelope"]["path"]
        == str(recorded_artifact_root / "build-envelope.json"),
        "C8.4 packaged build-envelope path escapes the recorded artifact root",
    )
    require(
        package["verifier"]["audit_log"]["path"]
        == str(recorded_artifact_root / "image-verifier-audit.log"),
        "C8.4 package audit-log path escapes the recorded artifact root",
    )
    for role, relative in REPOSITORY_BUILD_TOOLS.items():
        bind_recorded_path(
            build_tools[role],
            snapshot / relative,
            f"build tool {role}",
            recorded_path=relative,
        )
    for role, relative in REPOSITORY_PACKAGE_TOOLS.items():
        bind_recorded_path(
            package_tools[role],
            snapshot / relative,
            f"package tool {role}",
            recorded_path=str(recorded_source_root / relative),
        )
    sdk_tool_relatives = {
        "sdk_mkimage": "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/mkimage",
        "sdk_dumpimage": "u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/dumpimage",
    }
    for role, relative in sdk_tool_relatives.items():
        bind_recorded_path(
            package_tools[role],
            sdk_tool_paths[role],
            f"package tool {role}",
            recorded_path=str(recorded_sdk_root / relative),
        )
    genimage_relatives = {
        "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage",
        "buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/per-package/host-genimage/host/bin/genimage",
    }
    genimage_record = identity_record(
        package_tools["sdk_genimage"],
        "recorded package tool sdk_genimage",
        file_key="path",
    )
    require(
        genimage_record["path"]
        in {str(recorded_sdk_root / relative) for relative in genimage_relatives},
        "package tool sdk_genimage recorded path differs",
    )
    bind_recorded_identity(
        package_tools["sdk_genimage"],
        sdk_tool_paths["sdk_genimage"],
        "package tool sdk_genimage",
    )
    verifier_path = package["environment"]["image_verifier"]["values"]["PATH"]
    require(
        isinstance(verifier_path, str) and bool(verifier_path),
        "C8.4 verifier PATH is empty",
    )
    for binary, role in {
        "mdir": "verifier_mdir",
        "mcopy": "verifier_mcopy",
        "cmp": "verifier_cmp",
        "sha256sum": "verifier_sha256sum",
        "fdtget": "verifier_fdtget",
        "python3": "verifier_python3",
        "tr": "verifier_tr",
    }.items():
        found = shutil.which(binary, path=verifier_path)
        require(found is not None, f"live verifier tool {binary} is missing")
        actual = pathlib.Path(found).resolve(strict=True)
        recorded = identity_record(
            package_tools[role], f"recorded package tool {role}", file_key="path"
        )
        canonical_absolute_recorded_path(
            recorded["path"], f"package tool {role} recorded path"
        )
        bind_recorded_identity(package_tools[role], actual, f"package tool {role}")
    recorded_artifact_paths = {
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
    build_artifacts = exact(
        build["artifacts"], {"kernel_elf", "kernel_binary"}, "C8.4 build artifacts"
    )
    for role, path in artifact_paths.items():
        bind_recorded_path(
            package_artifacts[role],
            path,
            f"package artifact {role}",
            recorded_path=str(recorded_artifact_paths[role]),
        )
    for role in ("kernel_elf", "kernel_binary"):
        bind_recorded_identity(
            build_artifacts[role], artifact_paths[role], f"build artifact {role}"
        )
    return artifact_paths, sdk_tool_paths


def rerun_immutable_image_verifier(
    *,
    snapshot: pathlib.Path,
    artifact_root: pathlib.Path,
    sdk_root: pathlib.Path,
    source: str,
    challenge: str,
    package: dict[str, Any],
) -> dict[str, Any]:
    immutable_path = snapshot / "scripts/verify-milkv-duo-image.sh"
    immutable_raw = stable_regular_bytes(
        immutable_path, "immutable C8.4 image verifier", maximum=4_194_304
    )
    current_raw = stable_regular_bytes(
        ROOT / "scripts/verify-milkv-duo-image.sh",
        "current C8.4 image verifier",
        maximum=4_194_304,
    )
    require(
        current_raw == immutable_raw,
        "current image verifier differs from immutable C8.4 preparation bytes",
    )
    try:
        script = immutable_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"immutable C8.4 image verifier is not UTF-8: {error}")
    values = package["environment"]["image_verifier"]["values"]
    environment = {
        "GIT_CONFIG_GLOBAL": str(docker_git_config_path()),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": values["PATH"],
        "TZ": "UTC",
        "VIBEOS_C84_CHALLENGE": challenge,
        "VIBEOS_C84_SDK_CONTAINER_DIGEST": SDK_CONTAINER_DIGEST,
        "VIBEOS_C84_SOURCE_COMMIT": source,
    }
    try:
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                script,
                str(ROOT / "scripts/verify-milkv-duo-image.sh"),
                "--wasm-aot-profile",
                f"--artifact-root={artifact_root}",
                str(sdk_root),
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"cannot rerun immutable C8.4 image verifier: {error}")
    require(
        completed.returncode == 0,
        "immutable C8.4 image verifier failed: "
        + completed.stdout.decode(errors="replace")[-4000:],
    )
    report, report_sha256 = validate_image_audit(
        completed.stdout,
        source=source,
        challenge=challenge,
        artifacts=package["artifacts"],
        tools=package["tools"],
        label="immutable live C8.4 image verifier audit",
    )
    verifier = package["verifier"]
    require(
        report == verifier["report"] and report_sha256 == verifier["report_sha256"],
        "immutable live image audit differs from the package verifier report",
    )
    return report


def validate_source_attestation(value: Any, source: str, label: str) -> dict[str, Any]:
    record = exact(value, {"root", "head", "worktree_clean", "status_policy"}, label)
    canonical_absolute_recorded_path(record["root"], f"{label}.root")
    require(
        record["head"] == source and record["worktree_clean"] is True,
        f"{label} is not clean/exact",
    )
    require(
        record["status_policy"] == STRICT_STATUS_POLICY,
        f"{label} status policy differs",
    )
    return record


def ordered_timestamps(value: Any, names: Sequence[str], label: str) -> None:
    record = exact(value, set(names), label)
    parsed = [utc(record[name], f"{label}.{name}") for name in names]
    require(parsed == sorted(parsed), f"{label} timestamps are reversed")


def validate_closed_build(
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
        "C8.4 build campaign differs",
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
        "C8.4 jitterentropy source",
    )
    require(
        jitter["path"] == "vendor/jitterentropy-rs"
        and jitter["head"] == JITTERENTROPY_HEAD,
        "C8.4 jitterentropy path/head differs",
    )
    canonical_sha(jitter["patch_sha256"], "C8.4 jitterentropy patch hash")
    canonical_sha(jitter["observed_diff_sha256"], "C8.4 jitterentropy diff hash")
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
        "C8.4 sunset source",
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
        tool = identity_record(
            toolchain[name], f"C8.4 toolchain {name}", file_key="path"
        )
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
    require(
        build["command"] == expected_command,
        "C8.4 closed offline build command differs",
    )
    artifacts_value = exact(
        build["artifacts"], {"kernel_elf", "kernel_binary"}, "C8.4 build artifacts"
    )
    artifacts = {
        key: identity_record(value, f"C8.4 build artifact {key}", file_key="path")
        for key, value in artifacts_value.items()
    }
    artifact_prefix = f"target/.milkv-duo-wasm-aot-profile.stage.{source}.{challenge}"
    require(
        artifacts["kernel_elf"]["path"]
        == f"{artifact_prefix}/vibeos-milkv-duo-wasm-aot-profile.elf",
        "C8.4 ELF name differs",
    )
    require(
        artifacts["kernel_binary"]["path"] == f"{artifact_prefix}/vibeos-milkv-duo.bin",
        "C8.4 binary name differs",
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
    expected_tail = pathlib.PurePath("target/c84-milkv-build") / source / challenge
    require(
        pathlib.PurePath(values["CARGO_TARGET_DIR"]).parts[-len(expected_tail.parts) :]
        == expected_tail.parts,
        "C8.4 build target binding differs",
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
        measured = identity_record(record, f"C8.4 build tool {name}", file_key="path")
        require(
            measured["path"] == REPOSITORY_BUILD_TOOLS[name],
            f"C8.4 build tool {name} path differs",
        )
    ordered_timestamps(
        build["timestamps_utc"],
        ("build_started", "build_completed", "envelope_closed"),
        "C8.4 build",
    )
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
        "C8.4 package jitterentropy",
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
        "C8.4 package sunset",
    )
    canonical_absolute_recorded_path(sunset["path"], "C8.4 package sunset path")
    require(
        sunset["head"] == SUNSET_HEAD
        and sunset["worktree_clean"] is True
        and sunset["status_policy"] == STRICT_STATUS_POLICY,
        "C8.4 package sunset state differs",
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


def validate_package_closure(
    duo: pathlib.Path,
    *,
    expected_build: bytes,
    expected_package: bytes,
    expected_audit: bytes,
    snapshot: pathlib.Path,
    artifact_root: pathlib.Path,
    sdk_root: pathlib.Path,
    source: str,
    challenge: str,
    expected_run_id: str,
) -> PackageClosure:
    build_path = duo / "build-envelope.json"
    package_path = duo / "package-envelope.json"
    audit_path = duo / "package-image-verifier-audit.log"
    build_raw = stable_regular_bytes(
        build_path, "C8.4 build envelope", maximum=MAX_ENVELOPE_BYTES
    )
    package_raw = stable_regular_bytes(
        package_path, "C8.4 package envelope", maximum=MAX_ENVELOPE_BYTES
    )
    audit_raw = stable_regular_bytes(
        audit_path, "C8.4 image verifier audit", maximum=MAX_ENVELOPE_BYTES
    )
    require(
        (build_raw, package_raw, audit_raw)
        == (expected_build, expected_package, expected_audit),
        "C8.4 package custody files differ from the exact evidence-tree snapshot",
    )
    for name, expected in (
        ("build-envelope.json", build_raw),
        ("package-envelope.json", package_raw),
        ("image-verifier-audit.log", audit_raw),
    ):
        live = stable_regular_bytes(
            artifact_root / name,
            f"published C8.4 {name}",
            maximum=MAX_ENVELOPE_BYTES,
        )
        require(
            live == expected,
            f"published C8.4 {name} differs from the captured evidence copy",
        )
    build_root, build = canonical_content_envelope(
        strict_json_bytes(build_raw, "C8.4 build envelope"),
        "vibeos.c84.duo-wasm-aot-profile.build-envelope",
        "C8.4 build envelope",
    )
    package_root, package = canonical_content_envelope(
        strict_json_bytes(package_raw, "C8.4 package envelope"),
        "vibeos.c84.duo-wasm-aot-profile.package-envelope",
        "C8.4 package envelope",
    )
    run_id, build_artifacts = validate_closed_build(build, source, challenge)
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
        "C8.4 package campaign differs",
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
        f"C8.4 SDK digest must be {SDK_CONTAINER_DIGEST}",
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
        "C8.4 package/build content hash differs",
    )
    same_identity(
        {"sha256": sha256_bytes(build_raw), "bytes": len(build_raw)},
        identity_record(
            build_ref["envelope"], "C8.4 packaged build envelope", file_key="path"
        ),
        "C8.4 packaged build envelope",
    )
    package_artifacts_value = exact(
        package["artifacts"],
        {
            "kernel_elf",
            "kernel_binary",
            "packaged_fit_source",
            "packaged_dtb",
            "fit_boot_sd",
            "full_sd_image",
            "sdk_fip",
            "sdk_dtb",
        },
        "C8.4 package artifacts",
    )
    package_artifacts = {
        key: identity_record(value, f"C8.4 package artifact {key}", file_key="path")
        for key, value in package_artifacts_value.items()
    }
    for key in ("kernel_elf", "kernel_binary"):
        same_identity(
            package_artifacts[key], build_artifacts[key], f"C8.4 build/package {key}"
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
        "C8.4 image verifier",
    )
    require(
        verifier["status"] == "PASS"
        and type(verifier["exit_code"]) is int
        and verifier["exit_code"] == 0
        and verifier["exact_pass_marker"] == C84_IMAGE_PASS,
        "C8.4 image verifier status differs",
    )
    require(
        verifier["invocation"]
        == [
            "scripts/verify-milkv-duo-image.sh",
            "--wasm-aot-profile",
            "--artifact-root=<staging-artifact-root>",
            "<sdk-root>",
        ],
        "C8.4 image verifier invocation differs",
    )
    same_identity(
        {"sha256": sha256_bytes(audit_raw), "bytes": len(audit_raw)},
        identity_record(
            verifier["audit_log"], "C8.4 image verifier audit", file_key="path"
        ),
        "C8.4 image verifier audit",
    )
    tools = exact(package["tools"], PACKAGE_TOOL_KEYS, "C8.4 package tools")
    for name, record in tools.items():
        identity_record(record, f"C8.4 package tool {name}", file_key="path")
    audit_report, audit_report_sha256 = validate_image_audit(
        audit_raw,
        source=source,
        challenge=challenge,
        artifacts=package_artifacts,
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
    ordered_timestamps(
        package["timestamps_utc"],
        ("packaging_started", "image_verified", "envelope_closed"),
        "C8.4 package",
    )
    bind_package_live_state(
        build=build,
        package=package,
        snapshot=snapshot,
        artifact_root=artifact_root,
        sdk_root=sdk_root,
    )
    rerun_immutable_image_verifier(
        snapshot=snapshot,
        artifact_root=artifact_root,
        sdk_root=sdk_root,
        source=source,
        challenge=challenge,
        package=package,
    )
    bind_package_live_state(
        build=build,
        package=package,
        snapshot=snapshot,
        artifact_root=artifact_root,
        sdk_root=sdk_root,
    )
    for name, expected in (
        ("build-envelope.json", build_raw),
        ("package-envelope.json", package_raw),
        ("image-verifier-audit.log", audit_raw),
    ):
        require(
            stable_regular_bytes(
                artifact_root / name,
                f"published C8.4 {name} final recheck",
                maximum=MAX_ENVELOPE_BYTES,
            )
            == expected,
            f"published C8.4 {name} changed during final closure",
        )
    validate_live_sdk(sdk_root)
    return PackageClosure(
        build_root=build_root,
        build_content=build,
        package_root=package_root,
        package_content=package,
        build_identity={"sha256": sha256_bytes(build_raw), "bytes": len(build_raw)},
        package_identity={
            "sha256": sha256_bytes(package_raw),
            "bytes": len(package_raw),
        },
        audit_identity={"sha256": sha256_bytes(audit_raw), "bytes": len(audit_raw)},
        run_id=run_id,
    )


@dataclass(frozen=True)
class VerifiedBoot:
    index: int
    summary: dict[str, Any]
    raw_identity: dict[str, Any]
    summary_identity: dict[str, Any]
    inode: tuple[int, int]
    record_stream_sha256: str


def verify_boot(
    duo: pathlib.Path,
    *,
    snapshot: pathlib.Path,
    source: str,
    challenge: str,
    boot_index: int,
    expected_raw: bytes,
    expected_summary: bytes,
) -> VerifiedBoot:
    raw_path = duo / f"boot-{boot_index}.uart.log"
    summary_path = duo / f"boot-{boot_index}.summary.json"
    raw_bytes, raw_inode = stable_regular_measure(
        raw_path, f"C8.4 boot {boot_index} raw", maximum=MAX_RAW_BYTES
    )
    require(
        raw_bytes == expected_raw,
        f"C8.4 boot {boot_index} raw differs from the exact evidence-tree read",
    )
    raw_identity = {"sha256": sha256_bytes(raw_bytes), "bytes": len(raw_bytes)}
    record_stream_sha256 = canonical_marker_stream_digest(
        raw_bytes, f"C8.4 boot {boot_index} raw"
    )
    summary_raw, summary_inode = stable_regular_measure(
        summary_path, f"C8.4 boot {boot_index} summary", maximum=MAX_SUMMARY_BYTES
    )
    require(
        summary_raw == expected_summary,
        f"C8.4 boot {boot_index} summary differs from the exact evidence-tree read",
    )
    summary_identity = {"sha256": sha256_bytes(summary_raw), "bytes": len(summary_raw)}
    verifier = snapshot / "scripts/verify-c84-aot-decision.py"
    run_checked(
        [
            sys.executable,
            "-I",
            "-B",
            str(verifier),
            "--transcript",
            str(raw_path),
            "--expect-source",
            source,
            "--expect-challenge",
            challenge,
            "--boot-index",
            str(boot_index),
            "--summary-in",
            str(summary_path),
        ],
        cwd=snapshot,
        label=f"immutable-snapshot C8.4 verifier boot {boot_index}",
    )
    raw_after, raw_inode_after = stable_regular_measure(
        raw_path,
        f"C8.4 boot {boot_index} raw post-verification",
        maximum=MAX_RAW_BYTES,
    )
    summary_after, summary_inode_after = stable_regular_measure(
        summary_path,
        f"C8.4 boot {boot_index} summary post-verification",
        maximum=MAX_SUMMARY_BYTES,
    )
    require(
        raw_after == raw_bytes and raw_inode_after == raw_inode,
        f"C8.4 boot {boot_index} raw changed during verification",
    )
    require(
        summary_after == summary_raw and summary_inode_after == summary_inode,
        f"C8.4 boot {boot_index} summary changed during verification",
    )
    summary = strict_json_bytes(summary_raw, f"C8.4 boot {boot_index} summary")
    require(
        isinstance(summary, dict), f"C8.4 boot {boot_index} summary is not an object"
    )
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
            summary.get(key) == wanted, f"C8.4 boot {boot_index} summary {key} differs"
        )
    integer(
        summary.get("boot_index"),
        f"C8.4 boot {boot_index} summary boot index",
        minimum=boot_index,
        maximum=boot_index,
    )
    canonical_sha(summary.get("run_id"), f"C8.4 boot {boot_index} run id")
    retained = summary.get("retained_samples")
    require(
        isinstance(retained, list) and len(retained) == RETAINED_PER_BOOT,
        f"C8.4 boot {boot_index} retained sample count differs",
    )
    return VerifiedBoot(
        index=boot_index,
        summary=summary,
        raw_identity=raw_identity,
        summary_identity=summary_identity,
        inode=raw_inode,
        record_stream_sha256=record_stream_sha256,
    )


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


def aggregate_boots(
    boots: Sequence[VerifiedBoot],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    require(len(boots) == BOOT_COUNT, "C8.4 aggregate requires exactly three boots")
    require(
        [boot.index for boot in boots] == [0, 1, 2],
        "C8.4 boot indexes are missing, duplicated, or swapped",
    )
    require(
        len({boot.inode for boot in boots}) == BOOT_COUNT,
        "C8.4 raw files share an inode/hardlink",
    )
    require(
        len({boot.raw_identity["sha256"] for boot in boots}) == BOOT_COUNT,
        "C8.4 raw transcript hash replay detected",
    )
    require(
        len({boot.summary_identity["sha256"] for boot in boots}) == BOOT_COUNT,
        "C8.4 summary hash replay detected",
    )
    require(
        len({boot.record_stream_sha256 for boot in boots}) == BOOT_COUNT,
        "C8.4 canonical marker-stream semantic replay detected",
    )
    run_ids = {boot.summary.get("run_id") for boot in boots}
    sources = {boot.summary.get("source_commit") for boot in boots}
    challenges = {boot.summary.get("challenge") for boot in boots}
    require(
        len(run_ids) == len(sources) == len(challenges) == 1,
        "C8.4 boot campaign identities differ",
    )
    cross: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []
    for boot in boots:
        samples = boot.summary["retained_samples"]
        require(
            [sample.get("sample_index") for sample in samples] == list(range(3, 24)),
            f"C8.4 boot {boot.index} retained coordinates differ",
        )
        totals = [
            integer(
                sample.get("total_ticks"), f"boot {boot.index} total ticks", minimum=1
            )
            for sample in samples
        ]
        p50 = nearest_rank(totals, 50)
        p95 = nearest_rank(totals, 95)
        require(
            p95 * 100 <= p50 * 150,
            f"C8.4 boot {boot.index} retained stability exceeds 1.50",
        )
        cross.append(
            {"boot_index": boot.index, "p50_total_ticks": p50, "p95_total_ticks": p95}
        )
        retained.extend(samples)
    require(
        len(retained) == RETAINED_TOTAL, "C8.4 global retained population is not 63"
    )
    totals: list[int] = []
    interpretation: list[int] = []
    non_interpretation: list[int] = []
    for position, sample in enumerate(retained):
        total = integer(
            sample.get("total_ticks"), f"global sample {position} total", minimum=1
        )
        interp = integer(
            sample.get("interpretation_ticks"),
            f"global sample {position} interpretation",
        )
        non_interp = integer(
            sample.get("non_interpretation_ticks"),
            f"global sample {position} non-interpretation",
        )
        require(
            interp <= total and non_interp == total - interp,
            f"global sample {position} N != T-I",
        )
        totals.append(total)
        interpretation.append(interp)
        non_interpretation.append(non_interp)
    total_stats = distribution(totals)
    interpretation_stats = distribution(interpretation)
    non_interpretation_stats = distribution(non_interpretation)
    budget_miss = total_stats["p95"] > BUDGET_TICKS
    attribution = non_interpretation_stats["p95"] <= BUDGET_TICKS
    candidate = budget_miss and attribution
    aggregate = {
        "retained_samples": RETAINED_TOTAL,
        "budget_ticks": BUDGET_TICKS,
        "total_ticks": total_stats,
        "interpretation_ticks": interpretation_stats,
        "non_interpretation_ticks": non_interpretation_stats,
        "predicates": {
            "budget_miss": budget_miss,
            "interpretation_attribution": attribution,
        },
        "candidate_outcome": "aot-eligible-for-c85-design-review"
        if candidate
        else "aot-not-justified",
        "aot_authorized": False,
        "native_code_accepted": False,
    }
    return cross, aggregate


def validate_capture_envelope(
    tree: EvidenceTree,
    *,
    source: str,
    challenge: str,
    c83: dict[str, Any],
    preparation: dict[str, Any],
    package: PackageClosure,
    boots: Sequence[VerifiedBoot],
    cross: list[dict[str, Any]],
    aggregate: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = tree.files["duo/capture-envelope.json"]
    root, content = canonical_content_envelope(
        strict_json_bytes(raw, "C8.4 capture envelope"),
        "vibeos.c84.duo-aot-decision.capture-envelope",
        "C8.4 capture envelope",
    )
    exact(
        content,
        {
            "platform",
            "source_commit",
            "git_head",
            "challenge",
            "run_id",
            "workload_id",
            "c83_precondition",
            "artifacts",
            "artifact_custody",
            "capture",
            "evidence_tools",
        },
        "C8.4 capture content",
    )
    run_id = canonical_sha(content["run_id"], "C8.4 capture run id")
    require_run_id_binding(package.run_id, capture=run_id)
    require(
        (
            content["platform"],
            content["source_commit"],
            content["git_head"],
            content["challenge"],
            content["workload_id"],
        )
        == (PLATFORM, source, source, challenge, WORKLOAD_ID),
        "C8.4 capture campaign identity differs",
    )
    require(
        content["c83_precondition"] == c83,
        "C8.4 capture C8.3 precondition binding differs",
    )
    require(
        content["evidence_tools"] == preparation["tools"],
        "C8.4 capture tool closure differs from preparation commit",
    )

    artifact_records = exact(
        content["artifacts"],
        {"kernel_elf", "kernel_binary", "fit_boot_sd", "full_sd_image"},
        "C8.4 captured artifacts",
    )
    package_artifacts = package.package_content["artifacts"]
    for key, record_value in artifact_records.items():
        record = identity_record(record_value, f"C8.4 captured artifact {key}")
        same_identity(
            record, package_artifacts[key], f"C8.4 captured/package artifact {key}"
        )

    custody = exact(
        content["artifact_custody"],
        {"build_envelope", "package_envelope", "package_image_verifier_audit"},
        "C8.4 artifact custody",
    )
    custody_expectations = {
        "build_envelope": (
            "build-envelope.json",
            package.build_identity,
            package.build_root["content_sha256"],
        ),
        "package_envelope": (
            "package-envelope.json",
            package.package_identity,
            package.package_root["content_sha256"],
        ),
    }
    for key, (filename, identity, content_hash) in custody_expectations.items():
        record = exact(
            custody[key],
            {"file", "content_sha256", "sha256", "bytes"},
            f"C8.4 custody {key}",
        )
        require(
            record["file"] == filename and record["content_sha256"] == content_hash,
            f"C8.4 custody {key} binding differs",
        )
        same_identity(record, identity, f"C8.4 custody {key}")
    audit_record = identity_record(
        custody["package_image_verifier_audit"],
        "C8.4 custody image audit",
        file_key="file",
    )
    require(
        audit_record["file"] == "package-image-verifier-audit.log",
        "C8.4 custody audit filename differs",
    )
    same_identity(audit_record, package.audit_identity, "C8.4 custody image audit")

    capture = exact(
        content["capture"],
        {
            "started_utc",
            "completed_utc",
            "fresh_cold_boots",
            "retained_samples",
            "timeout_seconds_per_boot",
            "end_uniqueness_guard_seconds",
            "power_and_flash_control",
            "serial",
            "boots",
            "cross_boot_stability",
            "pooled_preview",
        },
        "C8.4 capture record",
    )
    started = utc(capture["started_utc"], "C8.4 capture start")
    completed = utc(capture["completed_utc"], "C8.4 capture completion")
    require(started <= completed, "C8.4 capture timestamps are reversed")
    require(
        capture["fresh_cold_boots"] == BOOT_COUNT
        and capture["retained_samples"] == RETAINED_TOTAL,
        "C8.4 capture population differs",
    )
    timeout = capture["timeout_seconds_per_boot"]
    require(
        isinstance(timeout, (int, float))
        and not isinstance(timeout, bool)
        and math.isfinite(float(timeout))
        and float(timeout) > 1.0,
        "C8.4 capture timeout is invalid",
    )
    require(
        isinstance(capture["end_uniqueness_guard_seconds"], (int, float))
        and not isinstance(capture["end_uniqueness_guard_seconds"], bool)
        and float(capture["end_uniqueness_guard_seconds"]) == 1.0,
        "C8.4 END uniqueness guard differs",
    )
    require(
        capture["power_and_flash_control"]
        == "manual operator only; collector performs no serial writes, reset, auto-discovery, or flash",
        "C8.4 capture control policy differs",
    )
    serial = exact(
        capture["serial"],
        {"access", "requested_port", "resolved_port", "settings", "usbmodem_forbidden"},
        "C8.4 serial record",
    )
    require(
        serial["access"] == "read-only"
        and serial["settings"] == "115200 8N1"
        and serial["usbmodem_forbidden"] is True,
        "C8.4 serial policy differs",
    )
    for key in ("requested_port", "resolved_port"):
        require(
            isinstance(serial[key], str)
            and pathlib.PurePath(serial[key]).is_absolute()
            and "usbmodem" not in serial[key].lower(),
            f"C8.4 serial {key} is unsafe",
        )

    boot_records = capture["boots"]
    require(
        isinstance(boot_records, list) and len(boot_records) == BOOT_COUNT,
        "C8.4 capture boot records differ",
    )
    recorded_inodes: set[tuple[int, int]] = set()
    last_time = started
    for index, (record_value, verified) in enumerate(zip(boot_records, boots)):
        record = exact(
            record_value,
            {
                "boot_index",
                "operator_confirmation",
                "operator_confirmed_utc",
                "capture_started_utc",
                "first_byte_utc",
                "completion_marker_closed_utc",
                "verified_utc",
                "run_id",
                "raw_log",
                "raw_capture_inode",
                "record_stream_sha256",
                "summary",
            },
            f"C8.4 capture boot {index}",
        )
        require(
            integer(
                record["boot_index"],
                f"C8.4 capture boot {index} index",
                minimum=index,
                maximum=index,
            )
            == index
            and record["operator_confirmation"] == f"COLD BOOT {index + 1}",
            f"C8.4 boot {index} cold-boot confirmation differs",
        )
        require(
            record["run_id"] == run_id == verified.summary["run_id"],
            f"C8.4 boot {index} run id differs",
        )
        times = [
            utc(record[name], f"C8.4 boot {index} {name}")
            for name in (
                "operator_confirmed_utc",
                "capture_started_utc",
                "first_byte_utc",
                "completion_marker_closed_utc",
                "verified_utc",
            )
        ]
        require(
            times == sorted(times) and last_time <= times[0] and times[-1] <= completed,
            f"C8.4 boot {index} timestamps are reversed/overlapping",
        )
        last_time = times[-1]
        raw_record = identity_record(
            record["raw_log"], f"C8.4 boot {index} raw custody", file_key="file"
        )
        summary_record = identity_record(
            record["summary"], f"C8.4 boot {index} summary custody", file_key="file"
        )
        require(
            raw_record["file"] == f"boot-{index}.uart.log"
            and summary_record["file"] == f"boot-{index}.summary.json",
            f"C8.4 boot {index} filename differs",
        )
        same_identity(
            raw_record, verified.raw_identity, f"C8.4 boot {index} raw custody"
        )
        same_identity(
            summary_record,
            verified.summary_identity,
            f"C8.4 boot {index} summary custody",
        )
        inode = exact(
            record["raw_capture_inode"],
            {"device", "inode"},
            f"C8.4 boot {index} capture inode",
        )
        pair = (
            integer(inode["device"], f"C8.4 boot {index} capture device"),
            integer(inode["inode"], f"C8.4 boot {index} capture inode", minimum=1),
        )
        require(
            pair not in recorded_inodes, "C8.4 capture-time raw inode replay detected"
        )
        require_inode_binding(pair, verified.inode, f"C8.4 boot {index}")
        require(
            record["record_stream_sha256"] == verified.record_stream_sha256,
            f"C8.4 boot {index} canonical marker-stream digest differs",
        )
        recorded_inodes.add(pair)
    require(
        capture["cross_boot_stability"] == cross,
        "C8.4 recorded boot stability differs from independent calculation",
    )
    preview = {"scope": "capture-preview-final-evidence-verifier-required", **aggregate}
    require(
        capture["pooled_preview"] == preview,
        "C8.4 pooled preview differs from per-sample global calculation",
    )
    return root, content


def require_inode_binding(
    recorded: tuple[int, int], verified: tuple[int, int], label: str
) -> None:
    require(
        recorded == verified,
        f"{label} recorded raw inode does not equal the verified file inode",
    )


def render_decision(
    *,
    source: str,
    challenge: str,
    c83: dict[str, Any],
    preparation: dict[str, Any],
    package: PackageClosure,
    capture_root: dict[str, Any],
    capture_content: dict[str, Any],
    boots: Sequence[VerifiedBoot],
    aggregate: dict[str, Any],
    tree: EvidenceTree,
) -> dict[str, Any]:
    candidate = (
        aggregate["predicates"]["budget_miss"]
        and aggregate["predicates"]["interpretation_attribution"]
    )
    content = {
        "suite_id": "vibeos.c84.aot-decision",
        "workload_revision": 1,
        "source_commit": source,
        "challenge": challenge,
        "run_id": capture_content["run_id"],
        "platform": PLATFORM,
        "workload_id": WORKLOAD_ID,
        "evidence_scope": "three-distinct-physical-cold-boots",
        "c83_precondition": c83,
        "c84_preparation": preparation,
        "capture_evidence": {
            "capture_envelope": {
                "file": "duo/capture-envelope.json",
                "content_sha256": capture_root["content_sha256"],
                "sha256": sha256_bytes(tree.files["duo/capture-envelope.json"]),
                "bytes": len(tree.files["duo/capture-envelope.json"]),
            },
            "build_envelope": {
                "file": "duo/build-envelope.json",
                "content_sha256": package.build_root["content_sha256"],
                **package.build_identity,
            },
            "package_envelope": {
                "file": "duo/package-envelope.json",
                "content_sha256": package.package_root["content_sha256"],
                **package.package_identity,
            },
            "package_image_verifier_audit": {
                "file": "duo/package-image-verifier-audit.log",
                **package.audit_identity,
            },
        },
        "population": {
            "cold_boots": BOOT_COUNT,
            "warmups_per_boot": WARMUPS_PER_BOOT,
            "retained_per_boot": RETAINED_PER_BOOT,
            "retained_samples": RETAINED_TOTAL,
            "raw_transcript_sha256": [boot.raw_identity["sha256"] for boot in boots],
            "record_stream_sha256": [boot.record_stream_sha256 for boot in boots],
            "boot_summary_sha256": [boot.summary_identity["sha256"] for boot in boots],
            "qemu_inputs": 0,
        },
        "statistics": {
            "total_ticks": aggregate["total_ticks"],
            "interpretation_ticks": aggregate["interpretation_ticks"],
            "non_interpretation_ticks": aggregate["non_interpretation_ticks"],
        },
        "decision": {
            "budget_ticks": BUDGET_TICKS,
            "budget_miss": aggregate["predicates"]["budget_miss"],
            "interpretation_attribution": aggregate["predicates"][
                "interpretation_attribution"
            ],
            "candidate_for_c85_design_review": candidate,
            "outcome": "aot-eligible-for-c85-design-review"
            if candidate
            else "aot-not-justified",
            "aot_authorized": False,
            "native_code_accepted": False,
        },
        "limitations": [
            "This closes only the bounded C8.4 decision and does not authorize AOT or native-code admission.",
            "Physical cold-boot provenance is operator-attested; UART bytes are independently reverified.",
            "Any C8.3, preparation, custody, transcript, or population failure prevents DECISION.json creation.",
        ],
    }
    return make_content_envelope("vibeos.c84.aot-decision.evidence", content)


def write_json_no_clobber(path: pathlib.Path, value: Any) -> None:
    path = absolute_no_symlink_path(
        path, "C8.4 decision output", leaf_may_be_missing=True
    )
    rendered = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _parent, directory_fd = open_directory_chain(
        path.parent, "C8.4 decision output parent"
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
            fail(f"refusing to clobber existing decision {path}")
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


def verify_evidence(
    *,
    evidence_root: pathlib.Path,
    c83_root: pathlib.Path,
    artifact_root: pathlib.Path,
    sdk_root: pathlib.Path,
    c84_source: str,
    c84_challenge: str,
    c83_source: str,
    c83_challenge: str,
    write_decision: bool,
) -> dict[str, Any]:
    c84_source = resolve_full_commit(c84_source, "expected C8.4 preparation commit")
    c84_challenge = canonical_challenge(c84_challenge, "expected C8.4 challenge")
    artifact_root = explicit_existing_directory(artifact_root, "C8.4 artifact root")
    sdk_root = explicit_existing_directory(sdk_root, "C8.4 SDK root")
    tree = validate_c84_tree(evidence_root, decision_required=not write_decision)
    require(
        not write_decision or not tree.decision_present,
        "--write-decision is no-clobber and requires DECISION.json to be absent",
    )
    trusted_temp = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-source-snapshot-", dir=trusted_temp
    ) as name:
        snapshot = pathlib.Path(name)
        materialize_commit(c84_source, snapshot)
        preparation = validate_preparation(
            tree, snapshot=snapshot, c84_source=c84_source
        )
        c83 = c83_precondition(
            current_root=c83_root,
            snapshot=snapshot,
            c84_source=c84_source,
            c83_source=c83_source,
            c83_challenge=c83_challenge,
        )
        expected_run_id = campaign_run_id(
            c84_source,
            c84_challenge,
            stable_regular_bytes(
                snapshot / "benchmarks/wasm-aot-decision/workloads-v1.json",
                "immutable C8.4 run-id manifest",
                maximum=1_048_576,
            ),
            stable_regular_bytes(
                snapshot / "benchmarks/wasm-aot-decision/schema-v1.json",
                "immutable C8.4 run-id transcript schema",
                maximum=1_048_576,
            ),
            "immutable C8.4 campaign",
        )
        package = validate_package_closure(
            tree.root / "duo",
            expected_build=tree.files["duo/build-envelope.json"],
            expected_package=tree.files["duo/package-envelope.json"],
            expected_audit=tree.files["duo/package-image-verifier-audit.log"],
            snapshot=snapshot,
            artifact_root=artifact_root,
            sdk_root=sdk_root,
            source=c84_source,
            challenge=c84_challenge,
            expected_run_id=expected_run_id,
        )
        boots = [
            verify_boot(
                tree.root / "duo",
                snapshot=snapshot,
                source=c84_source,
                challenge=c84_challenge,
                boot_index=index,
                expected_raw=tree.files[f"duo/boot-{index}.uart.log"],
                expected_summary=tree.files[f"duo/boot-{index}.summary.json"],
            )
            for index in range(BOOT_COUNT)
        ]
        cross, aggregate = aggregate_boots(boots)
        capture_root, capture_content = validate_capture_envelope(
            tree,
            source=c84_source,
            challenge=c84_challenge,
            c83=c83,
            preparation=preparation,
            package=package,
            boots=boots,
            cross=cross,
            aggregate=aggregate,
        )
        require_run_id_binding(
            expected_run_id,
            package=package.run_id,
            capture=capture_content["run_id"],
            **{f"boot_{boot.index}": boot.summary["run_id"] for boot in boots},
        )
        expected = render_decision(
            source=c84_source,
            challenge=c84_challenge,
            c83=c83,
            preparation=preparation,
            package=package,
            capture_root=capture_root,
            capture_content=capture_content,
            boots=boots,
            aggregate=aggregate,
            tree=tree,
        )
    decision_path = tree.root / "DECISION.json"
    if write_decision:
        write_json_no_clobber(decision_path, expected)
        closed = validate_c84_tree(tree.root, decision_required=True)
        observed_raw = closed.files["DECISION.json"]
    else:
        observed_raw = tree.files["DECISION.json"]
    observed = strict_json_bytes(observed_raw, "C8.4 DECISION.json")
    canonical_content_envelope(
        observed, "vibeos.c84.aot-decision.evidence", "C8.4 DECISION.json"
    )
    require(
        observed == expected,
        "C8.4 DECISION.json differs from independent reconstruction",
    )
    return expected


def synthetic_boot(index: int, *, base: int = 2_400_000) -> VerifiedBoot:
    samples: list[dict[str, int]] = []
    for position in range(RETAINED_PER_BOOT):
        total = base + position * 1_000
        interpretation = 200_000
        samples.append(
            {
                "sample_index": position + WARMUPS_PER_BOOT,
                "total_ticks": total,
                "interpretation_ticks": interpretation,
                "non_interpretation_ticks": total - interpretation,
            }
        )
    return VerifiedBoot(
        index=index,
        summary={
            "source_commit": "a" * 40,
            "challenge": "b" * 64,
            "run_id": "c" * 64,
            "boot_index": index,
            "retained_samples": samples,
        },
        raw_identity={"sha256": f"{index + 3:x}" * 64, "bytes": index + 1},
        summary_identity={"sha256": f"{index + 6:x}" * 64, "bytes": index + 1},
        inode=(1, index + 10),
        record_stream_sha256=f"{index + 9:x}" * 64,
    )


def expect_rejected(label: str, action: Any) -> None:
    try:
        action()
    except (EvidenceError, OSError, ValueError):
        return
    fail(f"selftest accepted hostile case {label}")


def selftest() -> None:
    require(
        nearest_rank(list(range(1, 64)), 50) == 32,
        "nearest-rank p50 is not global index 31",
    )
    require(
        nearest_rank(list(range(1, 64)), 95) == 60,
        "nearest-rank p95 is not global index 59",
    )
    boots = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    _cross, baseline = aggregate_boots(boots)
    require(
        baseline["retained_samples"] == 63
        and baseline["candidate_outcome"] == "aot-not-justified",
        "aggregate baseline differs",
    )

    boundary = [
        synthetic_boot(index, base=BUDGET_TICKS - 19_000) for index in range(BOOT_COUNT)
    ]
    _, boundary_result = aggregate_boots(boundary)
    require(
        boundary_result["total_ticks"]["p95"] == BUDGET_TICKS,
        "threshold-boundary fixture differs",
    )
    require(
        boundary_result["predicates"]
        == {"budget_miss": False, "interpretation_attribution": True},
        "threshold boundary is not strict/inclusive as specified",
    )
    eligible = [synthetic_boot(index, base=2_600_000) for index in range(BOOT_COUNT)]
    for boot in eligible:
        for sample in boot.summary["retained_samples"]:
            sample["interpretation_ticks"] = 300_000
            sample["non_interpretation_ticks"] = (
                sample["total_ticks"] - sample["interpretation_ticks"]
            )
    _, eligible_result = aggregate_boots(eligible)
    require(
        eligible_result["predicates"]
        == {"budget_miss": True, "interpretation_attribution": True},
        "dual-threshold candidate differs",
    )
    require(
        eligible_result["aot_authorized"] is False
        and eligible_result["native_code_accepted"] is False,
        "candidate authorized native code",
    )

    percentile = [synthetic_boot(index, base=2_000_000) for index in range(BOOT_COUNT)]
    totals: list[int] = []
    interpretations: list[int] = []
    non_interpretations: list[int] = []
    for boot in percentile:
        for position, sample in enumerate(boot.summary["retained_samples"]):
            sample["interpretation_ticks"] = 900_000 if position < 11 else 10_000
            sample["non_interpretation_ticks"] = (
                sample["total_ticks"] - sample["interpretation_ticks"]
            )
            totals.append(sample["total_ticks"])
            interpretations.append(sample["interpretation_ticks"])
            non_interpretations.append(sample["non_interpretation_ticks"])
    _, percentile_result = aggregate_boots(percentile)
    require(
        percentile_result["non_interpretation_ticks"]["p95"]
        == nearest_rank(non_interpretations, 95),
        "N percentile was not computed per sample",
    )
    require(
        nearest_rank(non_interpretations, 95)
        != nearest_rank(totals, 95) - nearest_rank(interpretations, 95),
        "anti-percentile-subtraction fixture is ineffective",
    )

    replay_hash = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    replay_hash[2] = dataclass_replace(
        replay_hash[2], raw_identity=replay_hash[0].raw_identity
    )
    expect_rejected("raw hash replay", lambda: aggregate_boots(replay_hash))
    replay_inode = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    replay_inode[2] = dataclass_replace(replay_inode[2], inode=replay_inode[0].inode)
    expect_rejected("raw inode replay", lambda: aggregate_boots(replay_inode))
    semantic_replay = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    semantic_replay[2] = dataclass_replace(
        semantic_replay[2],
        record_stream_sha256=semantic_replay[0].record_stream_sha256,
    )
    expect_rejected(
        "noise-only marker semantic replay", lambda: aggregate_boots(semantic_replay)
    )
    expect_rejected(
        "recorded inode mismatch",
        lambda: require_inode_binding((1, 10), (1, 11), "selftest boot"),
    )
    swapped = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    swapped[1], swapped[2] = swapped[2], swapped[1]
    expect_rejected("boot swap", lambda: aggregate_boots(swapped))
    off_by_one = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    off_by_one[0].summary["retained_samples"][0]["sample_index"] = 2
    expect_rejected("retained off-by-one", lambda: aggregate_boots(off_by_one))
    short = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    short[0].summary["retained_samples"].pop()
    expect_rejected("62 retained", lambda: aggregate_boots(short))
    arithmetic = [synthetic_boot(index) for index in range(BOOT_COUNT)]
    arithmetic[0].summary["retained_samples"][0]["non_interpretation_ticks"] += 1
    expect_rejected("N != T-I", lambda: aggregate_boots(arithmetic))

    expect_rejected(
        "duplicate JSON",
        lambda: strict_json_bytes(b'{"a":1,"a":2}', "duplicate selftest JSON"),
    )
    expect_rejected(
        "non-finite JSON",
        lambda: strict_json_bytes(b'{"value":1e999}', "non-finite selftest JSON"),
    )
    oid = "d" * 40
    parse_ls_tree_records(f"100644 blob {oid}\ta\0".encode(), {"a"}, "selftest tree")
    expect_rejected(
        "Git symlink",
        lambda: parse_ls_tree_records(
            f"120000 blob {oid}\ta\0".encode(), {"a"}, "selftest tree"
        ),
    )
    expect_rejected(
        "Git gitlink",
        lambda: parse_ls_tree_records(
            f"160000 commit {oid}\ta\0".encode(), {"a"}, "selftest tree"
        ),
    )
    expect_rejected(
        "Git extra",
        lambda: parse_ls_tree_records(
            f"100644 blob {oid}\ta\0100644 blob {oid}\tb\0".encode(),
            {"a"},
            "selftest tree",
        ),
    )

    envelope = make_content_envelope("vibeos.test", {"answer": 42})
    canonical_content_envelope(envelope, "vibeos.test", "selftest envelope")
    boolean_version = make_content_envelope("vibeos.test", {"answer": 42})
    boolean_version["version"] = True
    expect_rejected(
        "boolean envelope version",
        lambda: canonical_content_envelope(
            boolean_version, "vibeos.test", "selftest envelope"
        ),
    )
    envelope["content"]["answer"] = 43
    expect_rejected(
        "content address",
        lambda: canonical_content_envelope(
            envelope, "vibeos.test", "selftest envelope"
        ),
    )

    manifest_raw = stable_regular_bytes(
        C84_MANIFEST, "selftest run-id manifest", maximum=1_048_576
    )
    transcript_schema_raw = stable_regular_bytes(
        C84_TRANSCRIPT_SCHEMA,
        "selftest run-id transcript schema",
        maximum=1_048_576,
    )
    expected_run_id = campaign_run_id(
        "a" * 40,
        "b" * 64,
        manifest_raw,
        transcript_schema_raw,
        "selftest campaign",
    )
    require_run_id_binding(
        expected_run_id, build=expected_run_id, package=expected_run_id
    )
    expect_rejected(
        "run-id disconnect",
        lambda: require_run_id_binding(expected_run_id, capture="d" * 64),
    )

    audit_artifacts: dict[str, dict[str, Any]] = {}
    for role in set(IMAGE_REPORT_ARTIFACT_ROLES.values()):
        audit_artifacts[role] = {
            "path": f"/recorded/{role}",
            "sha256": sha256_bytes(f"artifact:{role}".encode("ascii")),
            "bytes": len(role) + 1,
        }
    audit_tools: dict[str, dict[str, Any]] = {}
    for role in set(IMAGE_REPORT_TOOL_ROLES.values()):
        audit_tools[role] = {
            "path": f"/recorded/{role}",
            "sha256": sha256_bytes(f"tool:{role}".encode("ascii")),
            "bytes": len(role) + 1,
        }
    audit_report = {
        "schema": C84_IMAGE_REPORT_SCHEMA,
        "version": 1,
        "source_commit": "a" * 40,
        "challenge": "b" * 64,
        "artifacts": {
            report_role: {
                key: audit_artifacts[envelope_role][key] for key in ("sha256", "bytes")
            }
            for report_role, envelope_role in IMAGE_REPORT_ARTIFACT_ROLES.items()
        },
        "tools": {
            report_role: {
                key: audit_tools[envelope_role][key] for key in ("sha256", "bytes")
            }
            for report_role, envelope_role in IMAGE_REPORT_TOOL_ROLES.items()
        },
    }
    canonical_audit_line = json.dumps(
        audit_report, sort_keys=True, separators=(",", ":")
    )
    audit_raw = (canonical_audit_line + "\n" + C84_IMAGE_PASS + "\n").encode()
    validate_image_audit(
        audit_raw,
        source="a" * 40,
        challenge="b" * 64,
        artifacts=audit_artifacts,
        tools=audit_tools,
        label="selftest image audit",
    )
    expect_rejected(
        "noncanonical image audit",
        lambda: validate_image_audit(
            (json.dumps(audit_report) + "\n" + C84_IMAGE_PASS + "\n").encode(),
            source="a" * 40,
            challenge="b" * 64,
            artifacts=audit_artifacts,
            tools=audit_tools,
            label="noncanonical selftest image audit",
        ),
    )
    bool_audit = json.loads(json.dumps(audit_report))
    bool_audit["artifacts"]["kernel_binary"]["bytes"] = True
    bool_audit_line = json.dumps(bool_audit, sort_keys=True, separators=(",", ":"))
    expect_rejected(
        "boolean image audit bytes",
        lambda: validate_image_audit(
            (bool_audit_line + "\n" + C84_IMAGE_PASS + "\n").encode(),
            source="a" * 40,
            challenge="b" * 64,
            artifacts=audit_artifacts,
            tools=audit_tools,
            label="boolean selftest image audit",
        ),
    )
    expect_rejected(
        "output after image audit PASS",
        lambda: validate_image_audit(
            audit_raw + b"extra\n",
            source="a" * 40,
            challenge="b" * 64,
            artifacts=audit_artifacts,
            tools=audit_tools,
            label="post-PASS selftest image audit",
        ),
    )

    trusted_temp = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-evidence-selftest-", dir=trusted_temp
    ) as name:
        root = pathlib.Path(name)
        evidence = root / "evidence"
        duo = evidence / "duo"
        duo.mkdir(parents=True)
        for relative in C84_PREPARATION_FILES:
            (evidence / relative).write_bytes(b"x")
        for relative in C84_DUO_FILES:
            (duo / relative).write_bytes(b"x")
        validate_c84_tree(evidence, decision_required=False)
        injected = evidence / "QEMU"
        injected.mkdir()
        expect_rejected(
            "QEMU injection",
            lambda: validate_c84_tree(evidence, decision_required=False),
        )
        injected.rmdir()
        decision = evidence / "DECISION.json"
        write_json_no_clobber(decision, {"closed": True})
        expect_rejected(
            "decision no-clobber",
            lambda: write_json_no_clobber(decision, {"closed": False}),
        )
        decision.unlink()
        decision.symlink_to(evidence / "README.md")
        expect_rejected(
            "decision symlink",
            lambda: write_json_no_clobber(decision, {"closed": False}),
        )
        decision.unlink()
        linked = root / "linked-evidence"
        linked.symlink_to(evidence, target_is_directory=True)
        expect_rejected(
            "ancestor symlink",
            lambda: stable_regular_bytes(linked / "README.md", "linked input"),
        )
        hard_root = root / "hard"
        hard_root.mkdir()
        (hard_root / "a").write_bytes(b"same")
        os.link(hard_root / "a", hard_root / "b")
        expect_rejected(
            "hardlink evidence",
            lambda: read_exact_regular_tree(hard_root, ("a", "b"), "hardlink tree"),
        )
        live = root / "live-artifact"
        live.write_bytes(b"published artifact")
        recorded_live = {
            "path": "/producer/live-artifact",
            **file_identity(live, "selftest live artifact"),
        }
        bind_recorded_path(
            recorded_live,
            live,
            "selftest live artifact",
            recorded_path="/producer/live-artifact",
        )
        forged_path = dict(recorded_live)
        forged_path["path"] = "/forged/envelope/path"
        expect_rejected(
            "forged package path",
            lambda: bind_recorded_path(
                forged_path,
                live,
                "forged selftest package path",
                recorded_path="/producer/live-artifact",
            ),
        )
        relative_path = dict(recorded_live)
        relative_path["path"] = "relative/forged/path"
        expect_rejected(
            "relative package path",
            lambda: bind_recorded_path(
                relative_path,
                live,
                "relative selftest package path",
                recorded_path="/producer/live-artifact",
            ),
        )
        live.write_bytes(b"mutated published artifact")
        expect_rejected(
            "artifact mutation",
            lambda: bind_recorded_path(
                recorded_live,
                live,
                "mutated selftest live artifact",
                recorded_path="/producer/live-artifact",
            ),
        )
        expect_rejected(
            "nonexistent package artifact",
            lambda: bind_recorded_path(
                recorded_live,
                root / "missing-artifact",
                "missing selftest artifact",
                recorded_path="/producer/live-artifact",
            ),
        )
        wrong_tool = dict(recorded_live)
        wrong_tool["sha256"] = "e" * 64
        expect_rejected(
            "package tool mismatch",
            lambda: bind_recorded_path(
                wrong_tool,
                live,
                "selftest package tool",
                recorded_path="/producer/live-artifact",
            ),
        )
        linked_root = root / "linked-root"
        linked_root.symlink_to(hard_root, target_is_directory=True)
        expect_rejected(
            "explicit root symlink",
            lambda: explicit_existing_directory(linked_root, "selftest explicit root"),
        )
    print(
        "verify-c84-evidence.py selftest: PASS (nearest-rank, dual-threshold, replay/swap, QEMU, symlink/hardlink, duplicate/content gates)"
    )


def dataclass_replace(value: VerifiedBoot, **changes: Any) -> VerifiedBoot:
    fields = {
        "index": value.index,
        "summary": value.summary,
        "raw_identity": value.raw_identity,
        "summary_identity": value.summary_identity,
        "inode": value.inode,
        "record_stream_sha256": value.record_stream_sha256,
    }
    fields.update(changes)
    return VerifiedBoot(**fields)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--selftest", action="store_true")
    value.add_argument("--evidence-root", type=pathlib.Path, default=C84_BENCHMARK_ROOT)
    value.add_argument(
        "--c83-evidence-root", type=pathlib.Path, default=C83_BENCHMARK_ROOT
    )
    value.add_argument("--expect-c84-source")
    value.add_argument("--expect-c84-challenge")
    value.add_argument("--expect-c83-source")
    value.add_argument("--expect-c83-challenge")
    value.add_argument("--artifact-root", type=pathlib.Path)
    value.add_argument("--sdk-root", type=pathlib.Path)
    value.add_argument("--write-decision", action="store_true")
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        identities = (
            arguments.expect_c84_source,
            arguments.expect_c84_challenge,
            arguments.expect_c83_source,
            arguments.expect_c83_challenge,
        )
        if arguments.selftest:
            require(
                not any(identities)
                and arguments.artifact_root is None
                and arguments.sdk_root is None
                and not arguments.write_decision,
                "--selftest does not accept formal identity/output arguments",
            )
            require(
                arguments.evidence_root == C84_BENCHMARK_ROOT
                and arguments.c83_evidence_root == C83_BENCHMARK_ROOT,
                "--selftest does not accept evidence roots",
            )
            selftest()
            return 0
        require(
            all(identities)
            and arguments.artifact_root is not None
            and arguments.sdk_root is not None,
            "formal C8.4 closure requires explicit C8.4/C8.3 identity pins plus --artifact-root and --sdk-root",
        )
        decision = verify_evidence(
            evidence_root=arguments.evidence_root,
            c83_root=arguments.c83_evidence_root,
            artifact_root=arguments.artifact_root,
            sdk_root=arguments.sdk_root,
            c84_source=arguments.expect_c84_source,
            c84_challenge=arguments.expect_c84_challenge,
            c83_source=arguments.expect_c83_source,
            c83_challenge=arguments.expect_c83_challenge,
            write_decision=arguments.write_decision,
        )
        content = decision["content"]
        print(
            "PASS C8.4 evidence "
            f"source={content['source_commit']} challenge={content['challenge']} "
            f"run_id={content['run_id']} outcome={content['decision']['outcome']} "
            "aot_authorized=false native_code_accepted=false"
        )
        return 0
    except (EvidenceError, OSError, UnicodeDecodeError, ValueError) as error:
        print(f"FAIL verify-c84-evidence: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
