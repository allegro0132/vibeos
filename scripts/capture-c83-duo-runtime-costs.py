#!/usr/bin/env python3
"""Capture and close the physical Milk-V Duo C8.3 runtime-cost evidence.

This script only observes an explicitly named UART.  It never flashes an
image, writes to the serial port, resets the board, or guesses a device.  The
operator must confirm three separate cold boots while the UART is armed.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import pathlib
import pty
import re
import select
import stat
import subprocess
import sys
import tempfile
import termios
import time
from dataclasses import dataclass
from typing import Any, Sequence


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = pathlib.Path(__file__).resolve()
VERIFIER_PATH = ROOT / "scripts/verify-c83-runtime-costs.py"
IMAGE_VERIFIER_PATH = ROOT / "scripts/verify-milkv-duo-image.sh"
EVIDENCE_CHECKER_PATH = ROOT / "scripts/verify-c83-evidence.py"
MANIFEST_PATH = ROOT / "benchmarks/wasm-runtime/workloads-v1.json"
TOOLCHAIN_PATH = ROOT / "rust-toolchain.toml"
CANONICAL_ARTIFACT_PATHS = {
    "kernel_binary": ROOT / "target/milkv-duo-runtime-costs/vibeos-milkv-duo.bin",
    "fit_boot_sd": ROOT / "target/milkv-duo-runtime-costs/boot.sd",
    "full_sd_image": ROOT / "target/milkv-duo-runtime-costs/vibeos-milkv-duo-runtime-costs-sd.img",
}
CANONICAL_PACKAGE_ENVELOPE = ROOT / "target/milkv-duo-runtime-costs/package-envelope.json"
CANONICAL_PACKAGE_AUDIT = ROOT / "target/milkv-duo-runtime-costs/image-verifier-audit.log"
CANONICAL_BUILD_ENVELOPE = ROOT / "target/milkv-duo-runtime-costs/build-envelope.json"
CANONICAL_KERNEL_ELF = ROOT / "target/milkv-duo-runtime-costs/vibeos-milkv-duo-runtime-costs.elf"
CANONICAL_OUTPUT_DTB = ROOT / "target/milkv-duo-runtime-costs/cv1800b_milkv_duo_sd.dtb"

PLATFORM = "milkv-duo-cv1800b"
BOOT_COUNT = 3
UART_CONTRACT = "115200 8N1"
DEFAULT_TIMEOUT_SECONDS = 900.0
END_GUARD_SECONDS = 1.0
META_PREFIX = b"VIBE_WASM_COST_META "
SAMPLE_PREFIX = b"VIBE_WASM_COST_SAMPLE "
END_PREFIX = b"VIBE_WASM_COST_END "
FAILURE_MARKERS = (
    b"vibe_wasm_cost_failed",
    b"panicked at",
    b"panic",
    b"fatal",
)
BOARD_KEYS = {
    "board",
    "cpu",
    "fresh_boots",
    "hart_count",
    "ram_bytes",
    "sdk_commit",
    "sdk_container_digest",
    "target",
    "timebase_hz",
    "uart",
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class CaptureError(RuntimeError):
    """A preflight, capture, verification, or closure condition failed."""


@dataclass(frozen=True)
class PackageEvidence:
    content: dict[str, Any]
    envelope_bytes: bytes
    audit_bytes: bytes
    build_envelope_bytes: bytes
    envelope_identity: dict[str, Any]
    audit_identity: dict[str, Any]
    build_envelope_identity: dict[str, Any]
    local_artifacts: dict[str, dict[str, Any]]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError(message)


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(set(value) == keys, f"{label} fields are not closed")
    return value


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        require(key not in value, f"JSON object contains duplicate member {key!r}")
        value[key] = member
    return value


def strict_json_loads(raw: str | bytes, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CaptureError(f"cannot decode {label}: {error}") from error


def canonical_hex(value: str, length: int, label: str) -> str:
    pattern = HEX40 if length == 40 else HEX64
    require(pattern.fullmatch(value) is not None, f"{label} must be {length} lowercase hexadecimal characters")
    require(any(character != "0" for character in value), f"{label} must not use the all-zero sentinel")
    return value


def canonical_source_commit(value: str) -> str:
    result = canonical_hex(value, 40, "source commit")
    require(result != "1" * 40, "source commit must not use the documented test-only sentinel")
    return result


def canonical_challenge(value: str) -> str:
    result = canonical_hex(value, 64, "challenge")
    require(result != "2" * 64, "challenge must not use the documented test-only sentinel")
    return result


def validate_timeout_seconds(value: float) -> float:
    require(
        math.isfinite(value) and value > END_GUARD_SECONDS,
        "--timeout-seconds must be finite and exceed the end guard",
    )
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hash_file(path: pathlib.Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    before = resolved.stat()
    require(stat.S_ISREG(before.st_mode), f"required path is not a regular file: {resolved}")
    require(before.st_size > 0, f"required file is empty: {resolved}")
    digest = hashlib.sha256()
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    after = resolved.stat()
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"file changed while it was hashed: {resolved}",
    )
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


def hash_and_scan(path: pathlib.Path, needles: dict[str, bytes]) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    before = resolved.stat()
    require(stat.S_ISREG(before.st_mode), f"artifact is not a regular file: {resolved}")
    require(before.st_size > 0, f"artifact is empty: {resolved}")
    require(all(needles.values()), "artifact scan received an empty identity")
    overlap = max(len(needle) for needle in needles.values()) - 1
    found = {name: False for name in needles}
    digest = hashlib.sha256()
    tail = b""
    with resolved.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
            window = tail + chunk
            for name, needle in needles.items():
                if not found[name] and needle in window:
                    found[name] = True
            tail = window[-overlap:] if overlap else b""
    after = resolved.stat()
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"artifact changed while it was hashed: {resolved}",
    )
    missing = [name for name, present in found.items() if not present]
    require(not missing, f"artifact {resolved} does not embed the built identity: {', '.join(missing)}")
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


def load_board_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        manifest = strict_json_loads(MANIFEST_PATH.read_bytes(), "C8.3 workload manifest")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CaptureError(f"cannot load C8.3 workload manifest: {error}") from error
    require(isinstance(manifest, dict), "C8.3 workload manifest is not an object")
    platforms = manifest.get("platforms")
    require(isinstance(platforms, dict), "C8.3 workload manifest has no platform map")
    board = platforms.get(PLATFORM)
    require(isinstance(board, dict), f"C8.3 workload manifest has no {PLATFORM} contract")
    require(set(board) == BOARD_KEYS, f"{PLATFORM} board contract fields are not closed")
    require(board["board"] == "Milk-V Duo CV1800B", "physical board contract differs")
    require(board["cpu"] == "C906B", "physical CPU contract differs")
    require(board["fresh_boots"] == BOOT_COUNT, "physical boot-count contract differs")
    require(board["hart_count"] == 1, "physical hart-count contract differs")
    require(board["ram_bytes"] == 60 * 1024 * 1024, "physical RAM contract differs")
    require(board["timebase_hz"] == 25_000_000, "physical timebase contract differs")
    require(board["uart"] == UART_CONTRACT, "physical UART contract differs")
    require(board["target"] == "riscv64imac-unknown-none-elf", "physical target contract differs")
    return manifest, board


def validate_sdk_identity(board: dict[str, Any], sdk_commit: str, container_digest: str) -> None:
    canonical_hex(sdk_commit, 40, "SDK commit")
    require(
        CONTAINER_DIGEST.fullmatch(container_digest) is not None
        and container_digest != "sha256:" + "0" * 64,
        "SDK container digest must be a nonzero canonical sha256 digest",
    )
    require(sdk_commit == board["sdk_commit"], "SDK commit differs from the checked-in Duo contract")
    require(
        container_digest == board["sdk_container_digest"],
        "SDK container digest differs from the checked-in Duo contract",
    )


def validate_clean_prep(source_commit: str, head: str, porcelain: str) -> None:
    canonical_source_commit(source_commit)
    require(HEX40.fullmatch(head) is not None, "git HEAD is not a canonical commit id")
    require(source_commit == head, f"prep source {source_commit} does not equal HEAD {head}")
    require(not porcelain, "physical capture requires a completely clean prep-source worktree")


def git_preflight(source_commit: str) -> str:
    try:
        head_result = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        status_result = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(ROOT),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise CaptureError(f"cannot inspect the prep-source git state: {error}") from error
    head = head_result.stdout.strip()
    validate_clean_prep(source_commit, head, status_result.stdout)
    return head


def toolchain_identity() -> dict[str, Any]:
    try:
        raw = TOOLCHAIN_PATH.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CaptureError(f"cannot read the pinned toolchain contract: {error}") from error
    channel_match = re.search(r'^channel = "([^"]+)"$', text, re.MULTILINE)
    rustc_match = re.search(r"^# rustc (.+)$", text, re.MULTILINE)
    commit_match = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", text, re.MULTILINE)
    require(channel_match is not None, "rust-toolchain.toml has no exact channel")
    require(rustc_match is not None, "rust-toolchain.toml has no rustc identity comment")
    require(commit_match is not None, "rust-toolchain.toml has no rustc commit identity")
    return {
        "channel": channel_match.group(1),
        "rustc": rustc_match.group(1),
        "rustc_commit": commit_match.group(1),
        "rust_toolchain_toml_sha256": sha256_bytes(raw),
        "rust_toolchain_toml_bytes": len(raw),
    }


def validate_output_path(output_dir: pathlib.Path) -> pathlib.Path:
    resolved = output_dir.expanduser().resolve(strict=False)
    require(not resolved.exists(), f"output directory already exists; refusing to overwrite: {resolved}")
    return resolved


def is_within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_capture_output_location(output_dir: pathlib.Path, forbidden_roots: Sequence[pathlib.Path]) -> None:
    for root in forbidden_roots:
        require(
            not is_within(output_dir, root),
            f"capture output must be outside the clean Git checkout {root}: {output_dir}",
        )


def validate_canonical_artifact_paths(
    kernel: pathlib.Path,
    fit: pathlib.Path,
    image: pathlib.Path,
) -> dict[str, pathlib.Path]:
    supplied = {"kernel_binary": kernel, "fit_boot_sd": fit, "full_sd_image": image}
    resolved: dict[str, pathlib.Path] = {}
    for role, expected_path in CANONICAL_ARTIFACT_PATHS.items():
        actual = supplied[role].expanduser().resolve(strict=True)
        expected = expected_path.resolve(strict=True)
        require(actual == expected, f"{role} must be the canonical runtime-cost artifact {expected}")
        resolved[role] = actual
    return resolved


def validate_identity_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(value, {"path", "sha256", "bytes"}, label)
    require(isinstance(record["path"], str) and bool(record["path"]), f"{label}.path is empty")
    canonical_hex(record["sha256"], 64, f"{label}.sha256")
    require(
        isinstance(record["bytes"], int) and not isinstance(record["bytes"], bool) and record["bytes"] > 0,
        f"{label}.bytes is invalid",
    )
    return record


def require_identity_match(local: dict[str, Any], packaged: dict[str, Any], label: str) -> None:
    require(local["sha256"] == packaged["sha256"], f"{label} hash differs from package envelope")
    require(local["bytes"] == packaged["bytes"], f"{label} size differs from package envelope")


def validate_utc(value: Any, label: str) -> None:
    require(isinstance(value, str) and value.endswith("Z"), f"{label} is not UTC")
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CaptureError(f"{label} is not an ISO-8601 timestamp") from error
    require(parsed.tzinfo is not None, f"{label} has no timezone")


def validate_package_root(value: Any) -> dict[str, Any]:
    root = exact_keys(
        value,
        {"schema", "version", "status", "content_sha256", "content"},
        "package envelope",
    )
    require(
        root["schema"] == "vibeos.c83.duo-runtime-costs.package-envelope"
        and root["version"] == 1
        and root["status"] == "closed",
        "package envelope identity/status differs",
    )
    canonical_hex(root["content_sha256"], 64, "package content hash")
    require(isinstance(root["content"], dict), "package content is not an object")
    canonical_content = json.dumps(root["content"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    require(sha256_bytes(canonical_content) == root["content_sha256"], "package content hash differs")
    return root["content"]


def validate_build_root(value: Any) -> dict[str, Any]:
    root = exact_keys(
        value,
        {"schema", "version", "status", "content_sha256", "content"},
        "build envelope",
    )
    require(
        root["schema"] == "vibeos.c83.duo-runtime-costs.build-envelope"
        and root["version"] == 1
        and root["status"] == "closed",
        "build envelope identity/status differs",
    )
    canonical_hex(root["content_sha256"], 64, "build content hash")
    require(isinstance(root["content"], dict), "build content is not an object")
    canonical_content = json.dumps(root["content"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    require(sha256_bytes(canonical_content) == root["content_sha256"], "build content hash differs")
    return root["content"]


def validate_build_envelope(
    *,
    source_commit: str,
    challenge: str,
    packaged_artifacts: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    build_path = CANONICAL_BUILD_ENVELOPE.resolve(strict=True)
    try:
        build_bytes = build_path.read_bytes()
        build_root = strict_json_loads(build_bytes, "build envelope")
    except OSError as error:
        raise CaptureError(f"cannot read the build envelope: {error}") from error
    content = exact_keys(
        validate_build_root(build_root),
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
    require(content["platform"] == PLATFORM, "build platform differs")
    require(content["source_commit"] == source_commit, "build source commit differs")
    require(content["challenge"] == challenge, "build challenge differs")
    source = exact_keys(content["source"], {"root", "head", "worktree_clean", "status_policy"}, "build source")
    require(isinstance(source["root"], str) and bool(source["root"]), "build source root is empty")
    require(source["head"] == source_commit and source["worktree_clean"] is True, "build source was not clean/exact")
    require(
        source["status_policy"]
        == "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
        "build source cleanliness policy differs",
    )

    toolchain = exact_keys(
        content["toolchain"],
        {"channel", "rustc_verbose", "rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"},
        "build toolchain",
    )
    for name in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
        validate_identity_record(toolchain[name], f"build toolchain {name}")
    contract = toolchain_identity()
    require(toolchain["channel"] == contract["channel"], "build toolchain channel differs")
    verbose_lines = toolchain["rustc_verbose"].splitlines() if isinstance(toolchain["rustc_verbose"], str) else []
    require(bool(verbose_lines) and verbose_lines[0] == f"rustc {contract['rustc']}", "build rustc identity differs")
    require(
        f"commit-hash: {contract['rustc_commit']}" in verbose_lines,
        "build rustc commit differs",
    )
    require(
        content["command"]
        == [
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
        ],
        "build command differs from the closed runtime-cost command",
    )

    artifacts = exact_keys(content["artifacts"], {"kernel_elf", "kernel_binary"}, "build artifacts")
    build_artifacts = {
        role: validate_identity_record(record, f"build artifact {role}")
        for role, record in artifacts.items()
    }
    for role in ("kernel_elf", "kernel_binary"):
        require_identity_match(build_artifacts[role], packaged_artifacts[role], f"build/package {role}")
    require(
        content["objcopy_command"]
        == [
            toolchain["rust_objcopy"]["path"],
            "-O",
            "binary",
            build_artifacts["kernel_elf"]["path"],
            build_artifacts["kernel_binary"]["path"],
        ],
        "build objcopy command differs",
    )
    objcopy_environment = exact_keys(
        content["objcopy_environment"],
        {"mode", "allowed_keys", "values"},
        "build objcopy environment",
    )
    require(objcopy_environment["mode"] == "env -i", "build objcopy did not use an empty environment")
    objcopy_keys = objcopy_environment["allowed_keys"]
    objcopy_values = objcopy_environment["values"]
    if objcopy_keys == ["LC_ALL", "PATH", "TZ"]:
        require(
            objcopy_values == {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            "build objcopy environment values differ",
        )
    elif objcopy_keys == ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"]:
        expected_lib = str(pathlib.Path(toolchain["rust_objcopy"]["path"]).parents[3])
        require(
            objcopy_values
            == {
                "DYLD_LIBRARY_PATH": expected_lib,
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TZ": "UTC",
            },
            "build Darwin objcopy environment values differ",
        )
    else:
        raise CaptureError("build objcopy environment allowlist differs")

    environment = exact_keys(
        content["environment"],
        {"mode", "allowed_keys", "values", "cargo_home_isolation"},
        "build environment",
    )
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
    require(environment["mode"] == "env -i", "build did not use an empty environment")
    require(environment["allowed_keys"] == expected_keys, "build environment allowlist differs")
    values = exact_keys(environment["values"], set(expected_keys), "build environment values")
    require(values["CARGO_HOME"] == "<isolated-cargo-home>", "build Cargo home was not isolated")
    require(values["HOME"] == "<isolated-cargo-home>/home", "build home was not isolated")
    require(values["TMPDIR"] == "<isolated-cargo-home>/tmp", "build temp directory was not isolated")
    require(values["CARGO_INCREMENTAL"] == "0", "incremental runtime-cost build was enabled")
    require(values["CARGO_NET_OFFLINE"] == "true", "runtime-cost build was not offline")
    require(values["LC_ALL"] == "C" and values["TZ"] == "UTC", "build locale/timezone differs")
    require(values["VIBEOS_C83_SOURCE_COMMIT"] == source_commit, "build environment source differs")
    require(values["VIBEOS_C83_CHALLENGE"] == challenge, "build environment challenge differs")
    require(values["RUSTC"] == toolchain["rustc"]["path"], "build RUSTC differs")
    require(values["RUSTDOC"] == toolchain["rustdoc"]["path"], "build RUSTDOC differs")
    path_parts = values["PATH"].split(":") if isinstance(values["PATH"], str) else []
    require(
        len(path_parts) == 5
        and pathlib.PurePath(path_parts[0]).name == "closed-bin"
        and pathlib.PurePath(path_parts[0]).parent.name.startswith("vibeos-c83-cargo-home.")
        and path_parts[1:] == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
        "build PATH is not the isolated linker path plus fixed system paths",
    )
    require(isinstance(values["RUSTUP_HOME"], str) and bool(values["RUSTUP_HOME"]), "build RUSTUP_HOME is empty")
    require(
        isinstance(values["SOURCE_DATE_EPOCH"], str) and values["SOURCE_DATE_EPOCH"].isdigit(),
        "build SOURCE_DATE_EPOCH is invalid",
    )
    target_suffix = pathlib.PurePath("target/c83-milkv-build") / source_commit / challenge
    target_parts = pathlib.PurePath(values["CARGO_TARGET_DIR"]).parts
    require(
        tuple(target_parts[-len(target_suffix.parts) :]) == target_suffix.parts,
        "build target directory differs",
    )
    isolation = exact_keys(
        environment["cargo_home_isolation"],
        {"ambient_config_loaded", "temporary", "cache_source", "registry_cache_symlinked", "git_cache_symlinked"},
        "build Cargo-home isolation",
    )
    require(isolation["ambient_config_loaded"] is False, "build loaded ambient Cargo configuration")
    require(isolation["temporary"] is True, "build Cargo home was not temporary")
    require(isinstance(isolation["cache_source"], str) and bool(isolation["cache_source"]), "build cache source is empty")
    require(
        isinstance(isolation["registry_cache_symlinked"], bool)
        and isinstance(isolation["git_cache_symlinked"], bool),
        "build cache-link attestations are not boolean",
    )

    expected_tools = {
        "build_script": ROOT / "scripts/build-milkv-duo.sh",
        "firmware_manifest": ROOT / "firmware/milkv-duo/Cargo.toml",
        "firmware_build_script": ROOT / "firmware/milkv-duo/build.rs",
        "firmware_linker_script": ROOT / "firmware/milkv-duo/linker.ld",
        "firmware_cargo_config": ROOT / "firmware/.cargo/config.toml",
        "kernel_manifest": ROOT / "kernel/Cargo.toml",
        "workspace_manifest": ROOT / "Cargo.toml",
        "cargo_lock": ROOT / "Cargo.lock",
        "workload_manifest": MANIFEST_PATH,
        "toolchain_contract": TOOLCHAIN_PATH,
    }
    tools = exact_keys(content["tools"], set(expected_tools), "build tools")
    for name, path in expected_tools.items():
        recorded = validate_identity_record(tools[name], f"build tool {name}")
        require_identity_match(hash_file(path), recorded, f"build tool {name}")

    timestamps = exact_keys(
        content["timestamps_utc"],
        {"build_started", "build_completed", "envelope_closed"},
        "build timestamps",
    )
    for label, value in timestamps.items():
        validate_utc(value, f"build timestamp {label}")
    return content, build_bytes, hash_file(build_path)


def validate_package_envelope(
    package_path: pathlib.Path,
    *,
    source_commit: str,
    challenge: str,
    board: dict[str, Any],
    canonical_artifacts: dict[str, pathlib.Path],
) -> PackageEvidence:
    actual_package = package_path.expanduser().resolve(strict=True)
    expected_package = CANONICAL_PACKAGE_ENVELOPE.resolve(strict=True)
    require(actual_package == expected_package, f"--package-envelope must be {expected_package}")
    actual_audit = CANONICAL_PACKAGE_AUDIT.resolve(strict=True)
    try:
        envelope_bytes = actual_package.read_bytes()
        audit_bytes = actual_audit.read_bytes()
        envelope = strict_json_loads(envelope_bytes, "package evidence")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CaptureError(f"cannot read the package evidence: {error}") from error
    content = exact_keys(
        validate_package_root(envelope),
        {
            "platform",
            "source_commit",
            "challenge",
            "source",
            "sdk",
            "build",
            "artifacts",
            "verifier",
            "tools",
            "timestamps_utc",
        },
        "package content",
    )
    require(content["platform"] == PLATFORM, "package platform differs")
    require(content["source_commit"] == source_commit, "package source commit differs")
    require(content["challenge"] == challenge, "package challenge differs")

    source = exact_keys(content["source"], {"root", "head", "worktree_clean", "status_policy"}, "package source")
    require(source["head"] == source_commit and source["worktree_clean"] is True, "package source was not clean/exact")
    require(isinstance(source["root"], str) and bool(source["root"]), "package source root is empty")
    require(
        source["status_policy"]
        == "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
        "package source cleanliness policy differs",
    )
    sdk = exact_keys(
        content["sdk"],
        {"root", "commit", "declared_container_digest", "worktree_clean", "status_policy"},
        "package SDK",
    )
    require(isinstance(sdk["root"], str) and bool(sdk["root"]), "package SDK root is empty")
    require(sdk["worktree_clean"] is True, "package SDK checkout was not clean")
    require(
        sdk["status_policy"]
        == "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
        "package SDK cleanliness policy differs",
    )
    validate_sdk_identity(board, sdk["commit"], sdk["declared_container_digest"])

    artifacts = exact_keys(
        content["artifacts"],
        {"kernel_elf", "kernel_binary", "fit_boot_sd", "full_sd_image", "sdk_fip", "sdk_dtb"},
        "package artifacts",
    )
    packaged_artifacts = {
        role: validate_identity_record(record, f"package artifact {role}")
        for role, record in artifacts.items()
    }
    package_build = exact_keys(content["build"], {"content_sha256", "envelope"}, "package build evidence")
    canonical_hex(package_build["content_sha256"], 64, "packaged build content hash")
    packaged_build_identity = validate_identity_record(package_build["envelope"], "packaged build envelope")
    build_content, build_envelope_bytes, build_envelope_identity = validate_build_envelope(
        source_commit=source_commit,
        challenge=challenge,
        packaged_artifacts=packaged_artifacts,
    )
    build_content_hash = sha256_bytes(
        json.dumps(build_content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    require(build_content_hash == package_build["content_sha256"], "package/build content hash differs")
    require_identity_match(build_envelope_identity, packaged_build_identity, "package/build envelope")
    identities = {"source_commit": source_commit.encode("ascii"), "challenge": challenge.encode("ascii")}
    local_artifacts = {
        role: hash_and_scan(path, identities) for role, path in canonical_artifacts.items()
    }
    local_elf = hash_and_scan(CANONICAL_KERNEL_ELF, identities)
    require_identity_match(local_elf, packaged_artifacts["kernel_elf"], "kernel ELF")
    for role, local in local_artifacts.items():
        require_identity_match(local, packaged_artifacts[role], role)
    local_dtb = hash_file(CANONICAL_OUTPUT_DTB)
    require_identity_match(local_dtb, packaged_artifacts["sdk_dtb"], "packaged DTB")

    verifier = exact_keys(content["verifier"], {"status", "audit_log", "invocation"}, "package verifier")
    require(verifier["status"] == "PASS", "package image verifier did not pass")
    require(
        verifier["invocation"]
        == ["scripts/verify-milkv-duo-image.sh", "--runtime-costs", "<sdk-root>"],
        "package image verifier invocation differs",
    )
    packaged_audit = validate_identity_record(verifier["audit_log"], "package verifier audit")
    audit_identity = hash_file(actual_audit)
    require_identity_match(audit_identity, packaged_audit, "package verifier audit")
    require(b"PASS: FAT boot + raw data MBR image" in audit_bytes, "package audit has no terminal PASS")

    tools = exact_keys(
        content["tools"],
        {
            "package_script",
            "image_verifier_script",
            "build_script",
            "fit_source",
            "genimage_config",
            "workload_manifest",
            "toolchain_contract",
            "evidence_checker",
            "sdk_mkimage",
            "sdk_dumpimage",
            "sdk_genimage",
        },
        "package tools",
    )
    packaged_tools = {role: validate_identity_record(record, f"package tool {role}") for role, record in tools.items()}
    local_tools = {
        "package_script": ROOT / "scripts/package-milkv-duo-sdk.sh",
        "image_verifier_script": IMAGE_VERIFIER_PATH,
        "build_script": ROOT / "scripts/build-milkv-duo.sh",
        "fit_source": ROOT / "scripts/milkv-duo.its",
        "genimage_config": ROOT / "scripts/milkv-duo-genimage.cfg",
        "workload_manifest": MANIFEST_PATH,
        "toolchain_contract": TOOLCHAIN_PATH,
        "evidence_checker": EVIDENCE_CHECKER_PATH,
    }
    for role, path in local_tools.items():
        require_identity_match(hash_file(path), packaged_tools[role], f"package tool {role}")

    timestamps = exact_keys(
        content["timestamps_utc"],
        {"packaging_started", "image_verified", "envelope_closed"},
        "package timestamps",
    )
    for label, value in timestamps.items():
        validate_utc(value, f"package timestamp {label}")
    return PackageEvidence(
        content=content,
        envelope_bytes=envelope_bytes,
        audit_bytes=audit_bytes,
        build_envelope_bytes=build_envelope_bytes,
        envelope_identity=hash_file(actual_package),
        audit_identity=audit_identity,
        build_envelope_identity=build_envelope_identity,
        local_artifacts=local_artifacts,
    )


def validate_serial_port(port: pathlib.Path) -> tuple[str, str]:
    requested = str(port.expanduser().absolute())
    try:
        resolved = port.expanduser().resolve(strict=True)
        mode = resolved.stat().st_mode
    except OSError as error:
        raise CaptureError(f"cannot resolve explicit serial port {port}: {error}") from error
    require(stat.S_ISCHR(mode), f"explicit serial port is not a character device: {resolved}")
    return requested, str(resolved)


def configure_uart(fd: int) -> None:
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    termios.tcflush(fd, termios.TCIFLUSH)


def decode_record(line: bytes, prefix: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = strict_json_loads(line[len(prefix) :], f"UART {label} record")
    except CaptureError as error:
        raise CaptureError(f"malformed {label} record on UART: {error}") from error
    require(isinstance(decoded, dict), f"UART {label} record is not an object")
    return decoded


@dataclass(frozen=True)
class BootIdentity:
    source_commit: str
    challenge: str
    run_id: str


class CaptureMonitor:
    """Incrementally reject terminal and identity failures while retaining raw bytes."""

    def __init__(self, source_commit: str, challenge: str) -> None:
        self.source_commit = source_commit
        self.challenge = challenge
        self.line_buffer = bytearray()
        self.hazard_tail = b""
        self.metadata: dict[str, Any] | None = None
        self.ending: dict[str, Any] | None = None
        self.sample_count = 0
        self.end_monotonic: float | None = None

    def feed(self, chunk: bytes, now: float) -> None:
        lowered = (self.hazard_tail + chunk).lower()
        for marker in FAILURE_MARKERS:
            require(marker not in lowered, f"UART transcript contains failure marker {marker.decode('ascii')!r}")
        self.hazard_tail = lowered[-64:]
        self.line_buffer.extend(chunk)
        while b"\n" in self.line_buffer:
            raw_line, _, remainder = self.line_buffer.partition(b"\n")
            self.line_buffer = bytearray(remainder)
            self._line(raw_line.rstrip(b"\r"), now)

    def _line(self, line: bytes, now: float) -> None:
        if b"VIBE_WASM_COST_META" in line:
            require(line.startswith(META_PREFIX), "malformed C8.3 metadata marker line")
            require(self.metadata is None, "duplicate C8.3 metadata record")
            require(self.ending is None, "C8.3 metadata appeared after the end record")
            metadata = decode_record(line, META_PREFIX, "metadata")
            for key in ("source_commit", "challenge", "run_id", "platform"):
                require(isinstance(metadata.get(key), str), f"UART metadata has no string {key}")
            require(metadata["source_commit"] == self.source_commit, "UART source commit differs from prep source")
            require(metadata["challenge"] == self.challenge, "UART challenge differs from the built-image challenge")
            require(metadata["platform"] == PLATFORM, "UART metadata is not the physical Duo platform")
            canonical_hex(metadata["run_id"], 64, "UART run id")
            self.metadata = metadata
        elif b"VIBE_WASM_COST_SAMPLE" in line:
            require(line.startswith(SAMPLE_PREFIX), "malformed C8.3 sample marker line")
            require(self.metadata is not None, "C8.3 sample appeared before metadata")
            require(self.ending is None, "C8.3 sample appeared after the end record")
            self.sample_count += 1
        elif b"VIBE_WASM_COST_END" in line:
            require(line.startswith(END_PREFIX), "malformed C8.3 end marker line")
            require(self.metadata is not None, "C8.3 end record appeared before metadata")
            require(self.ending is None, "duplicate C8.3 end record")
            ending = decode_record(line, END_PREFIX, "end")
            require(ending.get("challenge") == self.challenge, "end challenge differs from built-image challenge")
            require(ending.get("run_id") == self.metadata["run_id"], "end run id differs from metadata")
            self.ending = ending
            self.end_monotonic = now

    def complete(self, now: float) -> bool:
        return self.end_monotonic is not None and now - self.end_monotonic >= END_GUARD_SECONDS

    def identity(self) -> BootIdentity:
        require(self.metadata is not None, "capture ended without C8.3 metadata")
        require(self.ending is not None, "capture ended without a C8.3 end record")
        return BootIdentity(
            source_commit=self.metadata["source_commit"],
            challenge=self.metadata["challenge"],
            run_id=self.metadata["run_id"],
        )


def confirm_cold_boot(boot_index: int) -> str:
    expected = f"COLD BOOT {boot_index + 1}"
    print()
    print(f"Physical boot {boot_index + 1}/{BOOT_COUNT} requires manual action.")
    print("Power the Milk-V Duo fully OFF. Do not flash or reset it through this script.")
    try:
        response = input(f"With the board OFF and the measured SD image inserted, type {expected!r}: ").strip()
    except EOFError as error:
        raise CaptureError("cold-boot confirmation input ended unexpectedly") from error
    require(response == expected, f"cold-boot confirmation did not exactly match {expected!r}")
    return utc_now()


def capture_boot(
    *,
    port: pathlib.Path,
    raw_path: pathlib.Path,
    source_commit: str,
    challenge: str,
    timeout_seconds: float,
) -> tuple[BootIdentity, dict[str, str]]:
    monitor = CaptureMonitor(source_commit, challenge)
    first_byte_utc: str | None = None
    completion_utc: str | None = None
    fd = os.open(port, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        configure_uart(fd)
        capture_started_utc = utc_now()
        started = time.monotonic()
        deadline = started + timeout_seconds
        print(f"UART armed on {port} at {UART_CONTRACT}; apply board power now.")
        with raw_path.open("xb") as raw_log:
            while True:
                now = time.monotonic()
                if monitor.complete(now):
                    readable, _, _ = select.select([fd], [], [], 0)
                    if readable:
                        chunk = os.read(fd, 65536)
                        if chunk:
                            if first_byte_utc is None:
                                first_byte_utc = utc_now()
                            raw_log.write(chunk)
                            raw_log.flush()
                            sys.stdout.buffer.write(chunk)
                            sys.stdout.buffer.flush()
                            monitor.feed(chunk, time.monotonic())
                            continue
                    completion_utc = utc_now()
                    raw_log.flush()
                    os.fsync(raw_log.fileno())
                    break
                require(now < deadline, f"UART capture timed out after {timeout_seconds:g} seconds")
                wait_seconds = min(1.0, deadline - now)
                if monitor.end_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, END_GUARD_SECONDS - (now - monitor.end_monotonic)),
                    )
                readable, _, _ = select.select([fd], [], [], wait_seconds)
                if not readable:
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    continue
                if first_byte_utc is None:
                    first_byte_utc = utc_now()
                raw_log.write(chunk)
                raw_log.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                monitor.feed(chunk, time.monotonic())
    finally:
        os.close(fd)
    require(first_byte_utc is not None, "UART capture contained no bytes")
    require(completion_utc is not None, "UART capture did not close")
    return monitor.identity(), {
        "capture_started_utc": capture_started_utc,
        "first_byte_utc": first_byte_utc,
        "completion_marker_closed_utc": completion_utc,
    }


def invoke_verifier(
    *,
    raw_path: pathlib.Path,
    summary_path: pathlib.Path,
    source_commit: str,
    challenge: str,
    run_id: str,
    boot_index: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    require(not summary_path.exists(), f"summary path already exists: {summary_path}")
    command = [
        sys.executable,
        "-I",
        "-B",
        str(VERIFIER_PATH),
        "--transcript",
        str(raw_path),
        "--platform",
        PLATFORM,
        "--expect-source",
        source_commit,
        "--publication",
        "--boot-index",
        str(boot_index),
        "--summary-out",
        str(summary_path),
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    require(result.returncode == 0, f"independent verifier rejected physical boot {boot_index}")
    try:
        summary = strict_json_loads(summary_path.read_bytes(), f"verifier summary for boot {boot_index}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CaptureError(f"cannot read verifier summary for boot {boot_index}: {error}") from error
    require(isinstance(summary, dict), f"boot {boot_index} verifier summary is not an object")
    raw_identity = hash_file(raw_path)
    require(summary.get("platform") == PLATFORM, f"boot {boot_index} summary platform differs")
    require(summary.get("source_commit") == source_commit, f"boot {boot_index} summary source differs")
    require(summary.get("challenge") == challenge, f"boot {boot_index} summary challenge differs")
    require(summary.get("run_id") == run_id, f"boot {boot_index} summary run id differs")
    require(summary.get("boot_index") == boot_index, f"boot {boot_index} summary index differs")
    require(
        summary.get("raw_transcript_sha256") == raw_identity["sha256"],
        f"boot {boot_index} summary raw hash differs",
    )
    require(
        summary.get("raw_transcript_bytes") == raw_identity["bytes"],
        f"boot {boot_index} summary raw size differs",
    )
    return summary, raw_identity, hash_file(summary_path)


def write_json_exclusive(path: pathlib.Path, value: Any) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("xb") as destination:
        destination.write(encoded)
        destination.flush()
        os.fsync(destination.fileno())


def write_bytes_exclusive(path: pathlib.Path, value: bytes) -> None:
    with path.open("xb") as destination:
        destination.write(value)
        destination.flush()
        os.fsync(destination.fileno())


def required_path(value: pathlib.Path | None, flag: str) -> pathlib.Path:
    require(value is not None, f"{flag} is required for a physical capture")
    return value


def required_text(value: str | None, flag: str) -> str:
    require(value is not None and bool(value), f"{flag} is required for a physical capture")
    return value


def cross_boot_stability(summaries: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    require(len(summaries) == BOOT_COUNT, "cross-boot gate requires exactly three verifier summaries")
    per_boot: list[dict[str, dict[str, Any]]] = []
    metric_order: list[tuple[str, str, int]] | None = None
    for boot_index, summary in enumerate(summaries):
        metrics = summary.get("metrics")
        require(isinstance(metrics, list) and metrics, f"boot {boot_index} summary has no metrics")
        values: dict[str, dict[str, Any]] = {}
        order: list[tuple[str, str, int]] = []
        for metric in metrics:
            require(isinstance(metric, dict), f"boot {boot_index} summary metric is not an object")
            workload_id = metric.get("workload_id")
            category = metric.get("category")
            distribution = metric.get("batch_ticks")
            batch_operations = metric.get("batch_operations")
            require(isinstance(workload_id, str) and workload_id, f"boot {boot_index} metric has no workload id")
            require(workload_id not in values, f"boot {boot_index} duplicates workload {workload_id}")
            require(isinstance(category, str) and category, f"boot {boot_index} workload {workload_id} has no category")
            require(isinstance(distribution, dict), f"boot {boot_index} workload {workload_id} has no batch ticks")
            require(
                isinstance(batch_operations, int)
                and not isinstance(batch_operations, bool)
                and batch_operations > 0,
                f"boot {boot_index} workload {workload_id} has invalid batch operations",
            )
            p50 = distribution.get("p50")
            require(
                isinstance(p50, int) and not isinstance(p50, bool) and p50 > 0,
                f"boot {boot_index} workload {workload_id} has invalid p50 batch ticks",
            )
            exact_fuel: tuple[int, int] | None = None
            if category in {"host-call", "fuel"}:
                fuel = metric.get("fuel_consumed_per_sample")
                poll = metric.get("poll_quanta_per_sample")
                require(
                    isinstance(fuel, int) and not isinstance(fuel, bool) and fuel >= 0,
                    f"boot {boot_index} workload {workload_id} has invalid fuel/sample",
                )
                require(
                    isinstance(poll, int) and not isinstance(poll, bool) and poll >= 0,
                    f"boot {boot_index} workload {workload_id} has invalid poll quanta/sample",
                )
                exact_fuel = (fuel, poll)
            order.append((workload_id, category, batch_operations))
            values[workload_id] = {
                "category": category,
                "batch_operations": batch_operations,
                "p50": p50,
                "fuel_poll": exact_fuel,
            }
        if metric_order is None:
            metric_order = order
        require(order == metric_order, f"boot {boot_index} workload/category/batch order differs")
        per_boot.append(values)
    require(metric_order is not None, "cross-boot gate found no workloads")
    result: list[dict[str, Any]] = []
    for workload_id, category, ordered_batch in metric_order:
        batch_values = [values[workload_id]["batch_operations"] for values in per_boot]
        require(len(set(batch_values)) == 1, f"cross-boot batch operations differ for {workload_id}")
        boot_values = [values[workload_id]["p50"] for values in per_boot]
        minimum = min(boot_values)
        maximum = max(boot_values)
        require(
            maximum * 100 <= minimum * 150,
            f"cross-boot p50 stability gate failed for {workload_id}: {maximum}/{minimum} > 1.50",
        )
        record: dict[str, Any] = {
            "workload_id": workload_id,
            "category": category,
            "batch_operations": ordered_batch,
            "boot_p50_batch_ticks": boot_values,
            "minimum": minimum,
            "maximum": maximum,
            "ratio_numerator": maximum,
            "ratio_denominator": minimum,
            "ratio_limit": "1.50",
        }
        if category in {"host-call", "fuel"}:
            fuel_poll_values = [values[workload_id]["fuel_poll"] for values in per_boot]
            require(
                len(set(fuel_poll_values)) == 1,
                f"cross-boot fuel/poll invariant differs for {workload_id}",
            )
            fuel, poll = fuel_poll_values[0]
            record["boot_fuel_consumed_per_sample"] = [value[0] for value in fuel_poll_values]
            record["boot_poll_quanta_per_sample"] = [value[1] for value in fuel_poll_values]
            record["fuel_consumed_per_sample"] = fuel
            record["poll_quanta_per_sample"] = poll
        result.append(record)
    return result


def run_capture(arguments: argparse.Namespace) -> pathlib.Path:
    timeout_seconds = validate_timeout_seconds(arguments.timeout_seconds)
    source_commit = canonical_source_commit(required_text(arguments.source_commit, "--source-commit"))
    challenge = canonical_challenge(required_text(arguments.challenge, "--challenge"))
    port = required_path(arguments.port, "--port")
    output_dir = validate_output_path(required_path(arguments.output_dir, "--output-dir"))
    kernel = required_path(arguments.kernel, "--kernel")
    fit = required_path(arguments.fit, "--fit")
    image = required_path(arguments.image, "--image")
    package_envelope = required_path(arguments.package_envelope, "--package-envelope")
    require(sys.stdin.isatty(), "physical cold-boot confirmations require an interactive terminal")

    manifest, board = load_board_contract()
    canonical_artifacts = validate_canonical_artifact_paths(kernel, fit, image)
    validate_capture_output_location(output_dir, (ROOT.resolve(strict=True),))
    head = git_preflight(source_commit)
    requested_port, resolved_port = validate_serial_port(port)
    package_evidence = validate_package_envelope(
        package_envelope,
        source_commit=source_commit,
        challenge=challenge,
        board=board,
        canonical_artifacts=canonical_artifacts,
    )
    toolchain = toolchain_identity()
    script_identity = hash_file(SCRIPT_PATH)
    verifier_identity = hash_file(VERIFIER_PATH)
    image_verifier_identity = hash_file(IMAGE_VERIFIER_PATH)
    evidence_checker_identity = hash_file(EVIDENCE_CHECKER_PATH)
    manifest_identity = hash_file(MANIFEST_PATH)
    artifacts = package_evidence.local_artifacts
    artifacts_preflight_utc = utc_now()

    output_dir.mkdir(parents=True, exist_ok=False)
    copied_package_path = output_dir / "package-envelope.json"
    copied_package_audit_path = output_dir / "package-image-verifier-audit.log"
    copied_build_path = output_dir / "build-envelope.json"
    write_bytes_exclusive(copied_package_path, package_evidence.envelope_bytes)
    write_bytes_exclusive(copied_package_audit_path, package_evidence.audit_bytes)
    write_bytes_exclusive(copied_build_path, package_evidence.build_envelope_bytes)
    copied_package_identity = hash_file(copied_package_path)
    copied_package_audit_identity = hash_file(copied_package_audit_path)
    copied_build_identity = hash_file(copied_build_path)
    require_identity_match(copied_package_identity, package_evidence.envelope_identity, "copied package envelope")
    require_identity_match(
        copied_package_audit_identity,
        package_evidence.audit_identity,
        "copied package image audit",
    )
    require_identity_match(copied_build_identity, package_evidence.build_envelope_identity, "copied build envelope")
    capture_started_utc = utc_now()
    boots: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    expected_run_id: str | None = None
    for boot_index in range(BOOT_COUNT):
        operator_confirmed_utc = confirm_cold_boot(boot_index)
        raw_path = output_dir / f"boot-{boot_index}.uart.log"
        summary_path = output_dir / f"boot-{boot_index}.summary.json"
        identity, times = capture_boot(
            port=pathlib.Path(resolved_port),
            raw_path=raw_path,
            source_commit=source_commit,
            challenge=challenge,
            timeout_seconds=timeout_seconds,
        )
        require(identity.source_commit == source_commit, f"boot {boot_index} source identity differs")
        require(identity.challenge == challenge, f"boot {boot_index} challenge identity differs")
        if expected_run_id is None:
            expected_run_id = identity.run_id
        require(identity.run_id == expected_run_id, f"boot {boot_index} run id differs across cold boots")
        summary, raw_identity, summary_identity = invoke_verifier(
            raw_path=raw_path,
            summary_path=summary_path,
            source_commit=source_commit,
            challenge=challenge,
            run_id=identity.run_id,
            boot_index=boot_index,
        )
        summaries.append(summary)
        verified_utc = utc_now()
        boots.append(
            {
                "boot_index": boot_index,
                "operator_confirmation": f"COLD BOOT {boot_index + 1}",
                "operator_confirmed_utc": operator_confirmed_utc,
                **times,
                "verified_utc": verified_utc,
                "run_id": identity.run_id,
                "challenge": identity.challenge,
                "raw_log": {
                    "file": raw_path.name,
                    "sha256": raw_identity["sha256"],
                    "bytes": raw_identity["bytes"],
                },
                "summary": {
                    "file": summary_path.name,
                    "sha256": summary_identity["sha256"],
                    "bytes": summary_identity["bytes"],
                },
            }
        )
        if boot_index + 1 < BOOT_COUNT:
            print(f"Boot {boot_index + 1} verified. Fully power the board OFF before the next prompt.")

    require(len(boots) == BOOT_COUNT, "capture did not contain exactly three verified cold boots")
    require(expected_run_id is not None, "capture has no run id")
    require(len({boot["run_id"] for boot in boots}) == 1, "closed boots do not share one run id")
    require(len({boot["challenge"] for boot in boots}) == 1, "closed boots do not share one challenge")
    cross_boot = cross_boot_stability(summaries)
    closed_package = validate_package_envelope(
        package_envelope,
        source_commit=source_commit,
        challenge=challenge,
        board=board,
        canonical_artifacts=canonical_artifacts,
    )
    require_identity_match(
        closed_package.envelope_identity,
        package_evidence.envelope_identity,
        "package envelope at closure",
    )
    require_identity_match(
        closed_package.audit_identity,
        package_evidence.audit_identity,
        "package image audit at closure",
    )
    require_identity_match(
        closed_package.build_envelope_identity,
        package_evidence.build_envelope_identity,
        "build envelope at closure",
    )
    require(closed_package.local_artifacts == artifacts, "measured artifacts changed before closure")
    require_identity_match(
        hash_file(copied_package_path),
        copied_package_identity,
        "copied package envelope at closure",
    )
    require_identity_match(
        hash_file(copied_package_audit_path),
        copied_package_audit_identity,
        "copied package image audit at closure",
    )
    require_identity_match(
        hash_file(copied_build_path),
        copied_build_identity,
        "copied build envelope at closure",
    )
    for boot in boots:
        require_identity_match(
            hash_file(output_dir / boot["raw_log"]["file"]),
            boot["raw_log"],
            f"boot {boot['boot_index']} raw log at closure",
        )
        require_identity_match(
            hash_file(output_dir / boot["summary"]["file"]),
            boot["summary"],
            f"boot {boot['boot_index']} summary at closure",
        )
    artifacts_closed_utc = utc_now()
    require(git_preflight(source_commit) == head, "VibeOS Git HEAD changed during capture")
    require(toolchain_identity() == toolchain, "toolchain contract changed during capture")
    require(hash_file(SCRIPT_PATH) == script_identity, "capture script changed during capture")
    require(hash_file(VERIFIER_PATH) == verifier_identity, "runtime-cost verifier changed during capture")
    require(hash_file(IMAGE_VERIFIER_PATH) == image_verifier_identity, "image verifier changed during capture")
    require(hash_file(EVIDENCE_CHECKER_PATH) == evidence_checker_identity, "evidence checker changed during capture")
    require(hash_file(MANIFEST_PATH) == manifest_identity, "workload manifest changed during capture")
    closure_attested_utc = utc_now()
    capture_completed_utc = utc_now()
    envelope = {
        "schema": "vibeos.c83.duo-runtime-costs.capture-envelope",
        "version": 1,
        "status": "closed",
        "platform": PLATFORM,
        "source_commit": source_commit,
        "git_head": head,
        "challenge": challenge,
        "run_id": expected_run_id,
        "board_contract": board,
        "sdk": package_evidence.content["sdk"],
        "toolchain": toolchain,
        "artifacts": artifacts,
        "artifact_custody": {
            "identity_scanned_before_capture_utc": artifacts_preflight_utc,
            "identity_and_hashes_rechecked_at_closure_utc": artifacts_closed_utc,
            "package_evidence": {
                "content_sha256": sha256_bytes(
                    json.dumps(package_evidence.content, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ),
                "envelope": {
                    "file": copied_package_path.name,
                    "sha256": copied_package_identity["sha256"],
                    "bytes": copied_package_identity["bytes"],
                },
                "image_verifier_audit": {
                    "file": copied_package_audit_path.name,
                    "sha256": copied_package_audit_identity["sha256"],
                    "bytes": copied_package_audit_identity["bytes"],
                },
                "build_envelope": {
                    "file": copied_build_path.name,
                    "sha256": copied_build_identity["sha256"],
                    "bytes": copied_build_identity["bytes"],
                    "content_sha256": package_evidence.content["build"]["content_sha256"],
                },
            },
        },
        "capture": {
            "started_utc": capture_started_utc,
            "completed_utc": capture_completed_utc,
            "fresh_cold_boots": BOOT_COUNT,
            "timeout_seconds_per_boot": timeout_seconds,
            "end_uniqueness_guard_seconds": END_GUARD_SECONDS,
            "power_and_flash_control": "manual operator only; collector performs no serial writes, reset, or flash",
            "serial": {
                "access": "read-only",
                "requested_port": requested_port,
                "resolved_port": resolved_port,
                "settings": UART_CONTRACT,
            },
            "boots": boots,
            "cross_boot_p50_stability": cross_boot,
            "source_tools_package_and_artifacts_rechecked_utc": closure_attested_utc,
        },
        "evidence_tools": {
            "capture_script": script_identity,
            "independent_verifier": verifier_identity,
            "independent_image_verifier": image_verifier_identity,
            "workload_manifest": manifest_identity,
            "evidence_checker": evidence_checker_identity,
        },
        "manifest_identity": {
            "schema": manifest.get("schema"),
            "version": manifest.get("version"),
            "suite_id": manifest.get("suite_id"),
            "workload_revision": manifest.get("workload_revision"),
        },
    }
    envelope_path = output_dir / "capture-envelope.json"
    write_json_exclusive(envelope_path, envelope)
    print(f"PASS: closed three-boot physical Duo capture envelope: {envelope_path}")
    return envelope_path


def synthetic_lines(source: str, challenge: str, run_id: str) -> bytes:
    metadata = {
        "source_commit": source,
        "challenge": challenge,
        "run_id": run_id,
        "platform": PLATFORM,
    }
    ending = {"challenge": challenge, "run_id": run_id}
    return (
        b"boot banner\r\n"
        + META_PREFIX
        + json.dumps(metadata, separators=(",", ":")).encode()
        + b"\r\n"
        + SAMPLE_PREFIX
        + b"{}\r\n"
        + END_PREFIX
        + json.dumps(ending, separators=(",", ":")).encode()
        + b"\r\n"
    )


def selftest() -> None:
    source = "4" * 40
    challenge = "5" * 64
    run_id = "6" * 64
    good = synthetic_lines(source, challenge, run_id)
    monitor = CaptureMonitor(source, challenge)
    cursor = 0
    now = 10.0
    for width in (1, 2, 5, 11, 23, 47, 97, len(good)):
        chunk = good[cursor : cursor + width]
        if not chunk:
            break
        cursor += len(chunk)
        monitor.feed(chunk, now)
        now += 0.01
    if cursor < len(good):
        monitor.feed(good[cursor:], now)
    require(monitor.identity() == BootIdentity(source, challenge, run_id), "split-stream parser identity differs")
    require(monitor.complete((monitor.end_monotonic or 0) + END_GUARD_SECONDS), "end guard did not close")

    stable_summaries = [
        {
            "metrics": [
                {
                    "workload_id": "workload-a",
                    "category": "composition",
                    "batch_operations": 4096,
                    "batch_ticks": {"p50": p50},
                },
                {
                    "workload_id": "workload-host",
                    "category": "host-call",
                    "batch_operations": 64,
                    "batch_ticks": {"p50": host_p50},
                    "fuel_consumed_per_sample": 50,
                    "poll_quanta_per_sample": 2,
                },
            ]
        }
        for p50, host_p50 in ((100, 200), (120, 220), (150, 250))
    ]
    stable_cross_boot = cross_boot_stability(stable_summaries)
    require(
        stable_cross_boot[0]["boot_p50_batch_ticks"] == [100, 120, 150],
        "cross-boot selftest values differ",
    )
    drifted_summaries = [
        *stable_summaries[:2],
        {
            "metrics": [
                {
                    "workload_id": "workload-a",
                    "category": "composition",
                    "batch_operations": 4096,
                    "batch_ticks": {"p50": 1000},
                },
                {
                    "workload_id": "workload-host",
                    "category": "host-call",
                    "batch_operations": 64,
                    "batch_ticks": {"p50": 250},
                    "fuel_consumed_per_sample": 50,
                    "poll_quanta_per_sample": 2,
                },
            ]
        },
    ]
    require(
        all((value + 4095) // 4096 == 1 for value in (100, 120, 1000)),
        "cross-boot drift fixture does not exercise ticks/op ceil collapse",
    )
    cross_boot_rejected = 0
    try:
        cross_boot_stability(drifted_summaries)
    except CaptureError:
        cross_boot_rejected += 1
    else:
        raise CaptureError("selftest accepted 10x cross-boot drift")

    fuel_drift_summaries = [
        *stable_summaries[:2],
        {
            "metrics": [
                stable_summaries[2]["metrics"][0],
                {
                    **stable_summaries[2]["metrics"][1],
                    "fuel_consumed_per_sample": 51,
                },
            ]
        },
    ]
    try:
        cross_boot_stability(fuel_drift_summaries)
    except CaptureError:
        cross_boot_rejected += 1
    else:
        raise CaptureError("selftest accepted cross-boot fuel drift")
    order_drift_summaries = [
        *stable_summaries[:2],
        {"metrics": list(reversed(stable_summaries[2]["metrics"]))},
    ]
    try:
        cross_boot_stability(order_drift_summaries)
    except CaptureError:
        cross_boot_rejected += 1
    else:
        raise CaptureError("selftest accepted cross-boot metric-order drift")

    mutations = {
        "duplicate-meta": good.replace(META_PREFIX, META_PREFIX, 1).replace(
            SAMPLE_PREFIX, META_PREFIX + json.dumps({"source_commit": source, "challenge": challenge, "run_id": run_id, "platform": PLATFORM}).encode() + b"\n" + SAMPLE_PREFIX, 1
        ),
        "duplicate-end": good + good[good.index(END_PREFIX) :],
        "fatal": good.replace(b"boot banner", b"[!] fatal trap"),
        "panic": good.replace(b"boot banner", b"panicked at runtime"),
        "wrong-challenge": good.replace(challenge.encode(), ("7" * 64).encode(), 1),
        "wrong-source": good.replace(source.encode(), ("8" * 40).encode(), 1),
        "sample-before-meta": SAMPLE_PREFIX + b"{}\n" + good,
        "sample-after-end": good + SAMPLE_PREFIX + b"{}\n",
        "malformed-meta": good.replace(b'{"source_commit"', b"{broken", 1),
        "malformed-end-marker": good.replace(END_PREFIX, b"prefix VIBE_WASM_COST_END ", 1),
        "missing-end-timeout": good[: good.index(END_PREFIX)],
    }
    rejected = 0
    for name, candidate in mutations.items():
        candidate_monitor = CaptureMonitor(source, challenge)
        try:
            candidate_monitor.feed(candidate, 20.0)
            candidate_monitor.identity()
        except CaptureError:
            rejected += 1
        else:
            raise CaptureError(f"selftest mutation was accepted: {name}")

    preflight_rejected = 0
    preflight_cases = (
        lambda: validate_clean_prep(source, "6" * 40, ""),
        lambda: validate_clean_prep(source, source, " M tracked\n"),
        lambda: canonical_hex("0" * 64, 64, "challenge"),
        lambda: canonical_hex("A" * 40, 40, "source commit"),
        lambda: canonical_source_commit("1" * 40),
        lambda: canonical_challenge("2" * 64),
        lambda: validate_timeout_seconds(float("nan")),
        lambda: validate_timeout_seconds(float("inf")),
        lambda: validate_timeout_seconds(END_GUARD_SECONDS),
    )
    validate_clean_prep(source, source, "")
    require(validate_timeout_seconds(2.0) == 2.0, "valid timeout changed")
    for case in preflight_cases:
        try:
            case()
        except CaptureError:
            preflight_rejected += 1
        else:
            raise CaptureError("selftest preflight mutation was accepted")
    try:
        strict_json_loads('{"member":1,"member":2}', "duplicate-member selftest")
    except CaptureError:
        preflight_rejected += 1
    else:
        raise CaptureError("selftest accepted a duplicate JSON member")

    _, board = load_board_contract()
    validate_sdk_identity(board, board["sdk_commit"], board["sdk_container_digest"])
    package_content = {"probe": 1}
    package_content_hash = sha256_bytes(
        json.dumps(package_content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    package_root = {
        "schema": "vibeos.c83.duo-runtime-costs.package-envelope",
        "version": 1,
        "status": "closed",
        "content_sha256": package_content_hash,
        "content": package_content,
    }
    require(validate_package_root(package_root) == package_content, "valid package content address changed")
    package_mutations = (
        {**package_root, "content": {"probe": 2}},
        {**package_root, "status": "open"},
        {**package_root, "extra": 1},
    )
    for candidate in package_mutations:
        try:
            validate_package_root(candidate)
        except CaptureError:
            preflight_rejected += 1
        else:
            raise CaptureError("selftest package-envelope mutation was accepted")
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        artifact = root / "artifact.bin"
        artifact.write_bytes(b"prefix" + source.encode() + b"middle" + challenge.encode() + b"suffix")
        identity = hash_and_scan(artifact, {"source_commit": source.encode(), "challenge": challenge.encode()})
        require(identity["bytes"] == artifact.stat().st_size, "artifact preflight size differs")
        missing = root / "missing.bin"
        missing.write_bytes(source.encode())
        try:
            hash_and_scan(missing, {"source_commit": source.encode(), "challenge": challenge.encode()})
        except CaptureError:
            preflight_rejected += 1
        else:
            raise CaptureError("selftest accepted an artifact without the challenge")
        available = root / "new-output"
        validate_output_path(available)
        checkout = root / "checkout"
        checkout.mkdir()
        validate_capture_output_location(available, (checkout,))
        try:
            validate_capture_output_location(checkout / "evidence", (checkout,))
        except CaptureError:
            preflight_rejected += 1
        else:
            raise CaptureError("selftest accepted capture output inside a clean checkout")
        available.mkdir()
        try:
            validate_output_path(available)
        except CaptureError:
            preflight_rejected += 1
        else:
            raise CaptureError("selftest accepted an existing output directory")

    toolchain = toolchain_identity()
    require(toolchain["channel"].startswith("nightly-"), "toolchain selftest did not find a pinned nightly")
    master_fd, inherited_slave_fd = pty.openpty()
    slave_name = os.ttyname(inherited_slave_fd)
    os.close(inherited_slave_fd)
    readonly_fd = os.open(slave_name, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        configure_uart(readonly_fd)
    finally:
        os.close(readonly_fd)
        os.close(master_fd)
    print(
        "capture-c83-duo-runtime-costs.py selftest: PASS "
        f"({rejected} stream mutations, {preflight_rejected} preflight mutations, "
        f"{cross_boot_rejected} cross-boot drift rejected)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="exercise parsing and preflight without a serial device")
    parser.add_argument("--port", type=pathlib.Path, help="explicit UART character device; never auto-discovered")
    parser.add_argument("--output-dir", type=pathlib.Path, help="new directory for all three boots and the envelope")
    parser.add_argument("--source-commit", help="clean prep commit embedded in the measured image")
    parser.add_argument("--challenge", help="nonzero 64-hex challenge embedded in the measured image")
    parser.add_argument("--kernel", type=pathlib.Path, help="measured runtime-cost kernel binary")
    parser.add_argument("--fit", type=pathlib.Path, help="measured boot.sd FIT")
    parser.add_argument("--image", type=pathlib.Path, help="measured full SD image")
    parser.add_argument(
        "--package-envelope",
        type=pathlib.Path,
        help="closed package envelope emitted inside the pinned SDK container",
    )
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.selftest:
            operational = (
                arguments.port,
                arguments.output_dir,
                arguments.source_commit,
                arguments.challenge,
                arguments.kernel,
                arguments.fit,
                arguments.image,
                arguments.package_envelope,
            )
            require(not any(value is not None for value in operational), "--selftest does not accept capture arguments")
            require(arguments.timeout_seconds == DEFAULT_TIMEOUT_SECONDS, "--selftest does not accept --timeout-seconds")
            selftest()
            return 0
        run_capture(arguments)
        return 0
    except (CaptureError, OSError, ValueError) as error:
        print(f"FAIL capture-c83-duo-runtime-costs: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
