#!/usr/bin/env python3
"""Offline closure verifier and deterministic report generator for C8.3.

The runtime transcript verifier deliberately knows nothing about collection
custody.  This second, preparation-owned gate closes the checked-in evidence
tree: it reruns the publication verifier for every raw/summary pair, validates
the QEMU and Duo provenance envelopes and all copied hash references, recomputes
the physical cross-boot gate from raw batch ticks, and derives RESULTS.md only
from retained raw samples that passed those checks.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Callable, NoReturn, Sequence


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = pathlib.Path(__file__).resolve()
BENCHMARK_ROOT = ROOT / "benchmarks/wasm-runtime"
MANIFEST_PATH = BENCHMARK_ROOT / "workloads-v1.json"
SCHEMA_PATH = BENCHMARK_ROOT / "schema-v1.json"
README_PATH = BENCHMARK_ROOT / "README.md"
RUNTIME_VERIFIER = ROOT / "scripts/verify-c83-runtime-costs.py"
QEMU_RUNNER = ROOT / "scripts/qemu-c83-runtime-costs.py"
DUO_BUILD_SCRIPT = ROOT / "scripts/build-milkv-duo.sh"
DUO_PACKAGE_SCRIPT = ROOT / "scripts/package-milkv-duo-sdk.sh"
DUO_CAPTURE_SCRIPT = ROOT / "scripts/capture-c83-duo-runtime-costs.py"
DUO_IMAGE_VERIFIER = ROOT / "scripts/verify-milkv-duo-image.sh"
TOOLCHAIN_PATH = ROOT / "rust-toolchain.toml"

QEMU_PLATFORM = "qemu-virt"
DUO_PLATFORM = "milkv-duo-cv1800b"
BOOT_COUNT = 3
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ISO_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T.+Z\Z")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
META_PREFIX = "VIBE_WASM_COST_META "
SAMPLE_PREFIX = "VIBE_WASM_COST_SAMPLE "
QEMU_GIT_STATUS_COMMAND = [
    "git", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none",
]
QEMU_GIT_DIFF_COMMAND = [
    "git", "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv",
    "--ignore-submodules=none", "HEAD", "--",
]
STRICT_DUO_STATUS_POLICY = (
    "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none"
)
QEMU_BUILD_ALLOWED_NAMES = sorted(
    [
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TERM_COLOR",
        "HOME",
        "LANG",
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
)

TOP_FILES = {"README.md", "schema-v1.json", "workloads-v1.json", "RESULTS.md"}
QEMU_FILES = {"uart.log", "summary.json", "evidence.json"}
DUO_FILES = {
    "build-envelope.json",
    "package-envelope.json",
    "package-image-verifier-audit.log",
    "capture-envelope.json",
    *(f"boot-{index}.uart.log" for index in range(BOOT_COUNT)),
    *(f"boot-{index}.summary.json" for index in range(BOOT_COUNT)),
}


class EvidenceError(RuntimeError):
    """The checked-in publication boundary is not closed."""


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        require(key not in value, f"JSON object contains duplicate member {key!r}")
        value[key] = member
    return value


def strict_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=lambda value: fail(
                f"{label} contains non-standard JSON constant {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {label}: {error}")


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return strict_json_bytes(path.read_bytes(), label)
    except OSError as error:
        fail(f"cannot read {label} {path}: {error}")


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(set(value) == keys, f"{label} fields are not closed: {sorted(set(value) ^ keys)}")
    return value


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} is not an integer")
    require(value >= minimum, f"{label} is below {minimum}")
    return value


def canonical_hex(value: Any, length: int, label: str) -> str:
    pattern = HEX40 if length == 40 else HEX64
    require(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{label} is not canonical {length}-hex")
    require(value != "0" * length, f"{label} uses the all-zero sentinel")
    return value


def canonical_source(value: Any, label: str = "source commit") -> str:
    source = canonical_hex(value, 40, label)
    require(source != "1" * 40, f"{label} uses the test-only sentinel")
    return source


def canonical_challenge(value: Any, label: str = "challenge") -> str:
    challenge = canonical_hex(value, 64, label)
    require(challenge != "2" * 64, f"{label} uses the test-only sentinel")
    return challenge


def canonical_sha(value: Any, label: str) -> str:
    return canonical_hex(value, 64, label)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_identity(path: pathlib.Path, *, include_path: bool = False) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat()
        require(stat.S_ISREG(before.st_mode), f"identity input is not regular: {resolved}")
        require(before.st_size > 0, f"identity input is empty: {resolved}")
        raw = resolved.read_bytes()
        after = resolved.stat()
    except OSError as error:
        fail(f"cannot hash {path}: {error}")
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"file changed while hashing: {resolved}",
    )
    result: dict[str, Any] = {"sha256": sha256_bytes(raw), "bytes": len(raw)}
    if include_path:
        result["path"] = str(resolved)
    return result


def identity_record(value: Any, label: str, *, key: str = "path") -> dict[str, Any]:
    record = exact(value, {key, "sha256", "bytes"}, label)
    require(isinstance(record[key], str) and bool(record[key]), f"{label}.{key} is empty")
    canonical_sha(record["sha256"], f"{label}.sha256")
    integer(record["bytes"], f"{label}.bytes", minimum=1)
    return record


def bare_identity(value: Any, label: str) -> dict[str, Any]:
    record = exact(value, {"sha256", "bytes"}, label)
    canonical_sha(record["sha256"], f"{label}.sha256")
    integer(record["bytes"], f"{label}.bytes", minimum=1)
    return record


def require_identity(actual: dict[str, Any], recorded: dict[str, Any], label: str) -> None:
    require(actual["sha256"] == recorded["sha256"], f"{label} hash differs")
    require(actual["bytes"] == recorded["bytes"], f"{label} size differs")


def validate_utc(value: Any, label: str) -> datetime.datetime:
    require(isinstance(value, str) and ISO_UTC.fullmatch(value) is not None, f"{label} is not UTC")
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"{label} is not ISO-8601: {error}")
    require(parsed.utcoffset() == datetime.timedelta(0), f"{label} is not UTC")
    return parsed


def validate_timestamp_map(value: Any, keys: Sequence[str], label: str) -> None:
    timestamps = exact(value, set(keys), label)
    parsed = [validate_utc(timestamps[key], f"{label}.{key}") for key in keys]
    require(parsed == sorted(parsed), f"{label} is not chronological")


def validate_regular_tree(root: pathlib.Path, *, results_required: bool) -> None:
    try:
        root_lstat = root.lstat()
    except OSError as error:
        fail(f"cannot inspect evidence root {root}: {error}")
    require(stat.S_ISDIR(root_lstat.st_mode) and not stat.S_ISLNK(root_lstat.st_mode), "evidence root must be a real directory")
    expected_top = (set(TOP_FILES) | {"qemu", "duo"})
    actual_top = {entry.name for entry in root.iterdir()}
    if results_required:
        require(actual_top == expected_top, f"evidence root entries differ: {sorted(actual_top ^ expected_top)}")
    else:
        required_top = expected_top - {"RESULTS.md"}
        require(required_top <= actual_top <= expected_top, f"evidence root entries differ: {sorted(actual_top ^ expected_top)}")
    for directory, expected in ((root / "qemu", QEMU_FILES), (root / "duo", DUO_FILES)):
        mode = directory.lstat().st_mode
        require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), f"{directory} is not a real directory")
        actual = {entry.name for entry in directory.iterdir()}
        require(actual == expected, f"{directory.name} entries differ: {sorted(actual ^ expected)}")
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), f"evidence tree contains symlink: {path}")
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), f"evidence tree contains special file: {path}")


def load_manifest(root: pathlib.Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = load_json(root / "workloads-v1.json", "workload manifest")
    schema = load_json(root / "schema-v1.json", "transcript schema")
    reference_manifest = MANIFEST_PATH.read_bytes()
    reference_schema = SCHEMA_PATH.read_bytes()
    require((root / "workloads-v1.json").read_bytes() == reference_manifest, "evidence manifest bytes differ from preparation contract")
    require((root / "schema-v1.json").read_bytes() == reference_schema, "evidence schema bytes differ from preparation contract")
    require((root / "README.md").read_bytes() == README_PATH.read_bytes(), "evidence README bytes differ from preparation contract")
    exact(
        manifest,
        {"schema", "version", "suite_id", "workload_revision", "scope", "fixtures", "platforms", "sampling", "statistics", "workloads", "publication_gates"},
        "workload manifest",
    )
    require(manifest["schema"] == "vibeos.wasm-runtime-costs.manifest" and manifest["version"] == 1, "manifest identity differs")
    require(manifest["suite_id"] == "vibeos.c83.runtime-costs", "manifest suite differs")
    require(isinstance(schema, dict) and schema.get("$id") == "https://vibeos.invalid/schemas/wasm-runtime-costs-v1.json", "schema identity differs")
    return manifest, schema


def invoke_publication_verifier(raw: pathlib.Path, summary: pathlib.Path, platform: str, source: str, boot_index: int) -> None:
    command = [
        sys.executable,
        "-I",
        "-B",
        str(RUNTIME_VERIFIER),
        "--check-manifest",
        "--transcript",
        str(raw),
        "--platform",
        platform,
        "--expect-source",
        source,
        "--publication",
        "--boot-index",
        str(boot_index),
        "--summary-in",
        str(summary),
    ]
    environment = {"LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        completed = subprocess.run(command, cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        fail(f"cannot run publication verifier for {raw}: {error}")
    require(completed.returncode == 0, f"publication verifier rejected {raw.name}: {(completed.stderr or completed.stdout).strip()}")


def parse_retained_samples(path: pathlib.Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot parse verified transcript {path}: {error}")
    metadata: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    for line in text.splitlines():
        if line.startswith(META_PREFIX):
            value = strict_json_bytes(line[len(META_PREFIX):].encode(), f"{path.name} metadata")
            require(isinstance(value, dict), f"{path.name} metadata is not an object")
            metadata.append(value)
        elif line.startswith(SAMPLE_PREFIX):
            value = strict_json_bytes(line[len(SAMPLE_PREFIX):].encode(), f"{path.name} sample")
            require(isinstance(value, dict), f"{path.name} sample is not an object")
            if value.get("warmup") is False:
                samples.append(value)
    require(len(metadata) == 1 and samples, f"verified transcript {path.name} has no unique metadata/retained samples")
    return metadata[0], samples


def nearest_rank(values: Sequence[int], percentile: int) -> int:
    require(bool(values), "cannot summarize empty distribution")
    ordered = sorted(values)
    return ordered[((percentile * len(ordered) + 99) // 100) - 1]


def distribution(values: Sequence[int]) -> dict[str, int]:
    require(bool(values), "cannot summarize empty distribution")
    ordered = sorted(values)
    return {
        "samples": len(ordered),
        "min": ordered[0],
        "p50": nearest_rank(ordered, 50),
        "p95": nearest_rank(ordered, 95),
        "max": ordered[-1],
        "mean": sum(ordered) // len(ordered),
    }


def samples_by_workload(samples: Sequence[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    expected = [workload["id"] for workload in manifest["workloads"]]
    groups = {workload_id: [] for workload_id in expected}
    for sample in samples:
        workload_id = sample.get("workload_id")
        require(workload_id in groups, f"retained sample names unknown workload {workload_id!r}")
        groups[workload_id].append(sample)
    require(all(groups.values()), "retained sample matrix is incomplete")
    return groups


@dataclass(frozen=True)
class VerifiedPair:
    metadata: dict[str, Any]
    samples: list[dict[str, Any]]
    summary: dict[str, Any]
    raw_identity: dict[str, Any]
    summary_identity: dict[str, Any]


def verify_pair(raw: pathlib.Path, summary: pathlib.Path, platform: str, source: str, challenge: str, boot_index: int) -> VerifiedPair:
    invoke_publication_verifier(raw, summary, platform, source, boot_index)
    summary_value = load_json(summary, f"{platform} summary {boot_index}")
    require(isinstance(summary_value, dict), f"{platform} summary is not an object")
    metadata, samples = parse_retained_samples(raw)
    expected = {
        "platform": platform,
        "source_commit": source,
        "challenge": challenge,
        "boot_index": boot_index,
    }
    for key, value in expected.items():
        require(summary_value.get(key) == value, f"{platform} boot {boot_index} summary {key} differs")
    require(metadata.get("run_id") == summary_value.get("run_id"), f"{platform} boot {boot_index} run id differs")
    raw_identity = file_identity(raw)
    summary_identity = file_identity(summary)
    require(summary_value.get("raw_transcript_sha256") == raw_identity["sha256"], f"{platform} boot {boot_index} raw hash differs")
    require(summary_value.get("raw_transcript_bytes") == raw_identity["bytes"], f"{platform} boot {boot_index} raw size differs")
    return VerifiedPair(metadata, samples, summary_value, raw_identity, summary_identity)


def validate_source_attestation(value: Any, source: str, label: str) -> dict[str, Any]:
    record = exact(value, {"root", "head", "worktree_clean", "status_policy"}, label)
    require(isinstance(record["root"], str) and pathlib.PurePath(record["root"]).is_absolute(), f"{label}.root is not absolute")
    require(record["head"] == source and record["worktree_clean"] is True, f"{label} is not clean/exact")
    require(record["status_policy"] == STRICT_DUO_STATUS_POLICY, f"{label} status policy differs")
    return record


def validate_tool_identity(record: Any, current: pathlib.Path, label: str) -> dict[str, Any]:
    parsed = identity_record(record, label)
    require_identity(file_identity(current), parsed, label)
    return parsed


def validate_qemu_envelope(path: pathlib.Path, pair: VerifiedPair, source: str, challenge: str) -> dict[str, Any]:
    envelope = exact(
        load_json(path, "QEMU evidence envelope"),
        {
            "schema", "version", "suite_id", "mode", "source_commit", "challenge", "run_id",
            "started_at_utc", "ended_at_utc", "repository", "runner", "verifier",
            "evidence_checker", "toolchain", "kernel_elf", "qemu", "bios", "transcript", "summary",
        },
        "QEMU evidence envelope",
    )
    require(envelope["schema"] == "vibeos.wasm-runtime-cost.qemu-environment" and envelope["version"] == 1, "QEMU envelope identity differs")
    require(envelope["suite_id"] == "vibeos.c83.runtime-costs" and envelope["mode"] == "formal-publication", "QEMU envelope mode differs")
    require(envelope["source_commit"] == source and envelope["challenge"] == challenge, "QEMU envelope source/challenge differs")
    require(envelope["run_id"] == pair.summary["run_id"], "QEMU envelope run id differs")
    started = validate_utc(envelope["started_at_utc"], "QEMU start")
    ended = validate_utc(envelope["ended_at_utc"], "QEMU end")
    require(started <= ended, "QEMU interval is reversed")

    repository = exact(envelope["repository"], {"before", "after"}, "QEMU repository")
    for phase in ("before", "after"):
        attestation = exact(
            repository[phase],
            {"head", "clean", "status_command", "diff_command", "status_porcelain_v1_z_sha256", "tracked_diff_head_binary_sha256"},
            f"QEMU repository {phase}",
        )
        require(attestation["head"] == source and attestation["clean"] is True, f"QEMU repository {phase} was not clean/exact")
        require(attestation["status_command"] == QEMU_GIT_STATUS_COMMAND, f"QEMU repository {phase} status policy did not expose submodules")
        require(attestation["diff_command"] == QEMU_GIT_DIFF_COMMAND, f"QEMU repository {phase} diff policy did not expose submodules")
        require(attestation["status_porcelain_v1_z_sha256"] == EMPTY_SHA256, f"QEMU repository {phase} status was nonempty")
        require(attestation["tracked_diff_head_binary_sha256"] == EMPTY_SHA256, f"QEMU repository {phase} diff was nonempty")
    require(repository["before"] == repository["after"], "QEMU repository changed during capture")

    runner = identity_record(envelope["runner"], "QEMU runner")
    require(runner["path"] == "scripts/qemu-c83-runtime-costs.py", "QEMU runner path differs")
    require_identity(file_identity(QEMU_RUNNER), runner, "QEMU runner")
    verifier = exact(envelope["verifier"], {"path", "sha256", "bytes", "publication_gate"}, "QEMU verifier")
    require(verifier["path"] == "scripts/verify-c83-runtime-costs.py" and verifier["publication_gate"] is True, "QEMU verifier contract differs")
    require_identity(file_identity(RUNTIME_VERIFIER), verifier, "QEMU verifier")
    checker = identity_record(envelope["evidence_checker"], "QEMU evidence checker")
    require(checker["path"] == "scripts/verify-c83-evidence.py", "QEMU evidence checker path differs")
    require_identity(file_identity(SCRIPT_PATH), checker, "QEMU evidence checker")

    toolchain = exact(
        envelope["toolchain"],
        {"channel", "pinned_rustc_commit", "rustc_vv", "cargo_version", "rustup", "cargo", "rustc", "rustdoc", "linker", "cargo_command", "build_environment_policy"},
        "QEMU toolchain",
    )
    contract = parsed_toolchain_contract()
    canonical_source(toolchain["pinned_rustc_commit"], "QEMU pinned rustc commit")
    require(toolchain["channel"] == contract["channel"], "QEMU toolchain channel differs from the checked-in pin")
    require(toolchain["pinned_rustc_commit"] == contract["rustc_commit"], "QEMU rustc commit differs from the checked-in pin")
    rustc_lines = toolchain["rustc_vv"].splitlines() if isinstance(toolchain["rustc_vv"], str) else []
    require(bool(rustc_lines) and rustc_lines[0] == f"rustc {contract['rustc']}", "QEMU rustc version differs")
    require(f"commit-hash: {toolchain['pinned_rustc_commit']}" in rustc_lines, "QEMU rustc verbose identity differs")
    require(isinstance(toolchain["cargo_version"], str) and toolchain["cargo_version"].startswith("cargo "), "QEMU Cargo identity differs")
    for key in ("rustup", "cargo", "rustc", "rustdoc", "linker"):
        tool = identity_record(toolchain[key], f"QEMU tool {key}")
        require(pathlib.PurePath(tool["path"]).is_absolute(), f"QEMU tool {key} path is not absolute")
    require(pathlib.PurePath(toolchain["linker"]["path"]).name == "ld.lld", "QEMU linker identity differs")
    expected_cargo = [toolchain["rustup"]["path"], "run", toolchain["channel"], "cargo", "build", "--release", "--locked", "--offline", "--no-default-features", "--features", "wasm-c83-runtime-costs"]
    require(toolchain["cargo_command"] == expected_cargo, "QEMU build command differs")
    policy = exact(toolchain["build_environment_policy"], {"ambient_variables", "cargo_home", "cargo_net_offline", "path_entries", "allowed_names", "normalized_values"}, "QEMU build environment")
    require(policy["ambient_variables"] == "denied-by-default" and policy["cargo_net_offline"] is True, "QEMU build environment is not closed/offline")
    require(policy["cargo_home"] == "ephemeral-config-free registry/git cache links only", "QEMU Cargo-home policy differs")
    require(policy["allowed_names"] == QEMU_BUILD_ALLOWED_NAMES, "QEMU build environment allowlist differs")
    expected_path = []
    for entry in (
        str(pathlib.PurePath(toolchain["linker"]["path"]).parent),
        str(pathlib.PurePath(toolchain["rustup"]["path"]).parent),
        "/usr/bin",
        "/bin",
    ):
        if entry not in expected_path:
            expected_path.append(entry)
    require(policy["path_entries"] == expected_path, "QEMU build PATH is not the recorded minimal allowlist")
    values = exact(policy["normalized_values"], set(QEMU_BUILD_ALLOWED_NAMES), "QEMU normalized build environment")
    require(values["CARGO_HOME"] == "<temporary-root>/cargo-home", "QEMU Cargo home was not isolated")
    require(values["HOME"] == "<temporary-root>/home" and values["TMPDIR"] == "<temporary-root>/tmp", "QEMU HOME/TMPDIR were not isolated")
    require(values["CARGO_INCREMENTAL"] == "0" and values["CARGO_NET_OFFLINE"] == "true", "QEMU build was incremental or online")
    require(values["CARGO_TERM_COLOR"] == "never" and values["LANG"] == "C" and values["LC_ALL"] == "C" and values["TZ"] == "UTC", "QEMU build locale/timezone differs")
    require(values["PATH"] == os.pathsep.join(expected_path), "QEMU normalized build PATH differs")
    require(values["RUSTC"] == toolchain["rustc"]["path"] and values["RUSTDOC"] == toolchain["rustdoc"]["path"], "QEMU normalized compiler paths differ")
    require(isinstance(values["RUSTUP_HOME"], str) and pathlib.PurePath(values["RUSTUP_HOME"]).is_absolute(), "QEMU RUSTUP_HOME is not absolute")
    require(isinstance(values["SOURCE_DATE_EPOCH"], str) and values["SOURCE_DATE_EPOCH"].isdigit() and int(values["SOURCE_DATE_EPOCH"]) > 0, "QEMU SOURCE_DATE_EPOCH differs")
    require(values["VIBEOS_C83_SOURCE_COMMIT"] == source and values["VIBEOS_C83_CHALLENGE"] == challenge, "QEMU normalized build identity differs")

    kernel = identity_record(envelope["kernel_elf"], "QEMU kernel ELF")
    require(kernel["path"] == "target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt", "QEMU kernel path differs")
    qemu = exact(envelope["qemu"], {"resolved_executable", "version", "argv", "sha256", "bytes"}, "QEMU executable")
    canonical_sha(qemu["sha256"], "QEMU executable hash")
    integer(qemu["bytes"], "QEMU executable size", minimum=1)
    require(isinstance(qemu["resolved_executable"], str) and pathlib.PurePath(qemu["resolved_executable"]).is_absolute(), "QEMU executable path is not absolute")
    require(isinstance(qemu["version"], str) and qemu["version"].startswith("QEMU emulator version "), "QEMU version differs")
    bios = exact(envelope["bios"], {"name", "resolved_path", "sha256", "bytes"}, "QEMU BIOS")
    require(bios["name"] == "opensbi-riscv64-generic-fw_dynamic.bin", "QEMU BIOS name differs")
    require(isinstance(bios["resolved_path"], str) and pathlib.PurePath(bios["resolved_path"]).is_absolute(), "QEMU BIOS path is not absolute")
    require(pathlib.PurePath(bios["resolved_path"]).name == bios["name"], "QEMU BIOS basename differs")
    canonical_sha(bios["sha256"], "QEMU BIOS hash")
    integer(bios["bytes"], "QEMU BIOS size", minimum=1)
    expected_argv = [
        qemu["resolved_executable"], "-machine", "virt", "-cpu", "rv64", "-smp", "1", "-m", "128M",
        "-accel", "tcg,thread=single", "-icount", "shift=0,align=off,sleep=off", "-nographic",
        "-bios", bios["resolved_path"], "-kernel", str(pathlib.Path(kernel["path"]).resolve()),
    ]
    # Historical collection records an absolute checkout-specific kernel path.
    require(isinstance(qemu["argv"], list) and len(qemu["argv"]) == len(expected_argv), "QEMU argv shape differs")
    require(qemu["argv"][:-1] == expected_argv[:-1], "QEMU fixed argv or explicit BIOS differs")
    kernel_suffix = pathlib.PurePath(kernel["path"]).parts
    require(pathlib.PurePath(qemu["argv"][-1]).is_absolute() and pathlib.PurePath(qemu["argv"][-1]).parts[-len(kernel_suffix):] == kernel_suffix, "QEMU kernel argv differs")
    require(bare_identity(envelope["transcript"], "QEMU transcript") == pair.raw_identity, "QEMU transcript reference differs")
    require(bare_identity(envelope["summary"], "QEMU summary") == pair.summary_identity, "QEMU summary reference differs")
    return envelope


def validate_content_addressed(value: Any, schema: str, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    root = exact(value, {"schema", "version", "status", "content_sha256", "content"}, label)
    require(root["schema"] == schema and root["version"] == 1 and root["status"] == "closed", f"{label} identity/status differs")
    canonical_sha(root["content_sha256"], f"{label} content hash")
    require(isinstance(root["content"], dict), f"{label} content is not an object")
    canonical = json.dumps(root["content"], sort_keys=True, separators=(",", ":")).encode()
    require(sha256_bytes(canonical) == root["content_sha256"], f"{label} content address differs")
    return root, root["content"]


def validate_build_envelope(path: pathlib.Path, source: str, challenge: str) -> tuple[dict[str, Any], dict[str, Any]]:
    root, content = validate_content_addressed(load_json(path, "Duo build envelope"), "vibeos.c83.duo-runtime-costs.build-envelope", "Duo build envelope")
    exact(
        content,
        {"platform", "source_commit", "challenge", "source", "command", "objcopy_command", "objcopy_environment", "environment", "toolchain", "artifacts", "tools", "timestamps_utc"},
        "Duo build content",
    )
    require(content["platform"] == DUO_PLATFORM and content["source_commit"] == source and content["challenge"] == challenge, "Duo build identity differs")
    validate_source_attestation(content["source"], source, "Duo build source")
    toolchain = exact(content["toolchain"], {"channel", "rustc_verbose", "rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"}, "Duo build toolchain")
    for key in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
        identity_record(toolchain[key], f"Duo build toolchain {key}")
    contract = parsed_toolchain_contract()
    require(toolchain["channel"] == contract["channel"], "Duo build channel differs from the checked-in pin")
    verbose_lines = toolchain["rustc_verbose"].splitlines() if isinstance(toolchain["rustc_verbose"], str) else []
    require(bool(verbose_lines) and verbose_lines[0] == f"rustc {contract['rustc']}", "Duo build rustc version differs")
    require(f"commit-hash: {contract['rustc_commit']}" in verbose_lines, "Duo build rustc commit differs")
    expected_command = [toolchain["rustup"]["path"], "run", toolchain["channel"], "cargo", "build", "--release", "--locked", "--offline", "--no-default-features", "--features", "wasm-c83-runtime-costs"]
    require(content["command"] == expected_command, "Duo build command differs")
    artifacts = exact(content["artifacts"], {"kernel_elf", "kernel_binary"}, "Duo build artifacts")
    for key, record in artifacts.items():
        identity_record(record, f"Duo build artifact {key}")
    require(content["objcopy_command"] == [toolchain["rust_objcopy"]["path"], "-O", "binary", artifacts["kernel_elf"]["path"], artifacts["kernel_binary"]["path"]], "Duo objcopy command differs")
    objcopy_environment = exact(content["objcopy_environment"], {"mode", "allowed_keys", "values"}, "Duo objcopy environment")
    require(objcopy_environment["mode"] == "env -i", "Duo objcopy did not use env -i")
    allowed_objcopy = objcopy_environment["allowed_keys"]
    require(allowed_objcopy in (["LC_ALL", "PATH", "TZ"], ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"]), "Duo objcopy allowlist differs")
    values_objcopy = exact(objcopy_environment["values"], set(allowed_objcopy), "Duo objcopy values")
    require(values_objcopy["LC_ALL"] == "C" and values_objcopy["PATH"] == "/usr/bin:/bin" and values_objcopy["TZ"] == "UTC", "Duo objcopy locale/path differs")

    environment = exact(content["environment"], {"mode", "allowed_keys", "values", "cargo_home_isolation"}, "Duo build environment")
    expected_keys = ["CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "HOME", "LC_ALL", "PATH", "RUSTC", "RUSTDOC", "RUSTUP_HOME", "SOURCE_DATE_EPOCH", "TMPDIR", "TZ", "VIBEOS_C83_CHALLENGE", "VIBEOS_C83_SOURCE_COMMIT"]
    require(environment["mode"] == "env -i" and environment["allowed_keys"] == expected_keys, "Duo build environment allowlist differs")
    values = exact(environment["values"], set(expected_keys), "Duo build environment values")
    require(values["CARGO_HOME"] == "<isolated-cargo-home>" and values["HOME"] == "<isolated-cargo-home>/home" and values["TMPDIR"] == "<isolated-cargo-home>/tmp", "Duo build home isolation differs")
    require(values["CARGO_INCREMENTAL"] == "0" and values["CARGO_NET_OFFLINE"] == "true", "Duo build was incremental or online")
    require(values["LC_ALL"] == "C" and values["TZ"] == "UTC", "Duo build locale differs")
    require(values["VIBEOS_C83_SOURCE_COMMIT"] == source and values["VIBEOS_C83_CHALLENGE"] == challenge, "Duo build environment identity differs")
    require(values["RUSTC"] == toolchain["rustc"]["path"] and values["RUSTDOC"] == toolchain["rustdoc"]["path"], "Duo build compiler path differs")
    require(isinstance(values["PATH"], str) and bool(values["PATH"]), "Duo build PATH is empty")
    require(isinstance(values["RUSTUP_HOME"], str) and pathlib.PurePath(values["RUSTUP_HOME"]).is_absolute(), "Duo build RUSTUP_HOME differs")
    require(isinstance(values["SOURCE_DATE_EPOCH"], str) and values["SOURCE_DATE_EPOCH"].isdigit(), "Duo SOURCE_DATE_EPOCH differs")
    target_suffix = pathlib.PurePath("target/c83-milkv-build") / source / challenge
    require(pathlib.PurePath(values["CARGO_TARGET_DIR"]).parts[-len(target_suffix.parts):] == target_suffix.parts, "Duo build target directory differs")
    isolation = exact(environment["cargo_home_isolation"], {"ambient_config_loaded", "temporary", "cache_source", "registry_cache_symlinked", "git_cache_symlinked"}, "Duo Cargo-home isolation")
    require(isolation["ambient_config_loaded"] is False and isolation["temporary"] is True, "Duo Cargo-home isolation differs")
    require(isinstance(isolation["cache_source"], str) and pathlib.PurePath(isolation["cache_source"]).is_absolute(), "Duo Cargo cache source differs")
    require(isinstance(isolation["registry_cache_symlinked"], bool) and isinstance(isolation["git_cache_symlinked"], bool), "Duo cache link attestations differ")

    expected_tools = {
        "build_script": DUO_BUILD_SCRIPT,
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
    tools = exact(content["tools"], set(expected_tools), "Duo build tools")
    for key, current in expected_tools.items():
        validate_tool_identity(tools[key], current, f"Duo build tool {key}")
    validate_timestamp_map(content["timestamps_utc"], ["build_started", "build_completed", "envelope_closed"], "Duo build timestamps")
    return root, content


def validate_package_envelope(path: pathlib.Path, build_path: pathlib.Path, audit_path: pathlib.Path, manifest: dict[str, Any], source: str, challenge: str, build_root: dict[str, Any], build_content: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    root, content = validate_content_addressed(load_json(path, "Duo package envelope"), "vibeos.c83.duo-runtime-costs.package-envelope", "Duo package envelope")
    exact(content, {"platform", "source_commit", "challenge", "source", "sdk", "build", "artifacts", "verifier", "tools", "timestamps_utc"}, "Duo package content")
    require(content["platform"] == DUO_PLATFORM and content["source_commit"] == source and content["challenge"] == challenge, "Duo package identity differs")
    validate_source_attestation(content["source"], source, "Duo package source")
    sdk = exact(content["sdk"], {"root", "commit", "declared_container_digest", "worktree_clean", "status_policy"}, "Duo package SDK")
    board = manifest["platforms"][DUO_PLATFORM]
    require(isinstance(sdk["root"], str) and pathlib.PurePath(sdk["root"]).is_absolute(), "Duo SDK root is not absolute")
    require(sdk["commit"] == board["sdk_commit"] and sdk["declared_container_digest"] == board["sdk_container_digest"], "Duo SDK identity differs")
    require(sdk["worktree_clean"] is True and sdk["status_policy"] == STRICT_DUO_STATUS_POLICY, "Duo SDK source was not clean")
    require(CONTAINER_DIGEST.fullmatch(sdk["declared_container_digest"]) is not None, "Duo SDK container digest is malformed")

    build = exact(content["build"], {"content_sha256", "envelope"}, "Duo package build reference")
    require(build["content_sha256"] == build_root["content_sha256"], "Duo package build content reference differs")
    require_identity(file_identity(build_path), identity_record(build["envelope"], "Duo packaged build envelope"), "Duo packaged build envelope")
    package_artifacts = exact(content["artifacts"], {"kernel_elf", "kernel_binary", "fit_boot_sd", "full_sd_image", "sdk_fip", "sdk_dtb"}, "Duo package artifacts")
    for key, record in package_artifacts.items():
        identity_record(record, f"Duo package artifact {key}")
    for key in ("kernel_elf", "kernel_binary"):
        require_identity(package_artifacts[key], build_content["artifacts"][key], f"Duo build/package {key}")
    verifier = exact(content["verifier"], {"status", "audit_log", "invocation"}, "Duo image verifier")
    require(verifier["status"] == "PASS" and verifier["invocation"] == ["scripts/verify-milkv-duo-image.sh", "--runtime-costs", "<sdk-root>"], "Duo image verifier contract differs")
    require_identity(file_identity(audit_path), identity_record(verifier["audit_log"], "Duo image verifier audit"), "Duo image verifier audit")
    audit = audit_path.read_bytes()
    require(b"PASS: FAT boot + raw data MBR image" in audit, "Duo image verifier audit lacks terminal PASS")
    lowered = audit.lower()
    require(b"panic" not in lowered and b"fatal" not in lowered and b"fail:" not in lowered, "Duo image verifier audit contains a failure marker")

    expected_source_tools = {
        "package_script": DUO_PACKAGE_SCRIPT,
        "image_verifier_script": DUO_IMAGE_VERIFIER,
        "build_script": DUO_BUILD_SCRIPT,
        "fit_source": ROOT / "scripts/milkv-duo.its",
        "genimage_config": ROOT / "scripts/milkv-duo-genimage.cfg",
        "workload_manifest": MANIFEST_PATH,
        "toolchain_contract": TOOLCHAIN_PATH,
        "evidence_checker": SCRIPT_PATH,
    }
    expected_tool_keys = set(expected_source_tools) | {"sdk_mkimage", "sdk_dumpimage", "sdk_genimage"}
    tools = exact(content["tools"], expected_tool_keys, "Duo package tools")
    for key, current in expected_source_tools.items():
        validate_tool_identity(tools[key], current, f"Duo package tool {key}")
    for key in ("sdk_mkimage", "sdk_dumpimage", "sdk_genimage"):
        identity_record(tools[key], f"Duo SDK tool {key}")
    validate_timestamp_map(content["timestamps_utc"], ["packaging_started", "image_verified", "envelope_closed"], "Duo package timestamps")
    return root, content


def parsed_toolchain_contract() -> dict[str, Any]:
    raw = TOOLCHAIN_PATH.read_bytes()
    text = raw.decode()
    channel = re.search(r'^channel = "([^"]+)"$', text, re.MULTILINE)
    rustc = re.search(r"^# rustc (.+)$", text, re.MULTILINE)
    commit = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", text, re.MULTILINE)
    require(channel is not None and rustc is not None and commit is not None, "toolchain contract cannot be parsed")
    return {"channel": channel.group(1), "rustc": rustc.group(1), "rustc_commit": commit.group(1), "rust_toolchain_toml_sha256": sha256_bytes(raw), "rust_toolchain_toml_bytes": len(raw)}


def validate_toolchain_contract(value: Any) -> dict[str, Any]:
    toolchain = exact(value, {"channel", "rustc", "rustc_commit", "rust_toolchain_toml_sha256", "rust_toolchain_toml_bytes"}, "Duo capture toolchain")
    require(toolchain == parsed_toolchain_contract(), "Duo capture toolchain differs")
    return toolchain


def validate_capture_envelope(path: pathlib.Path, duo_dir: pathlib.Path, pairs: Sequence[VerifiedPair], manifest: dict[str, Any], source: str, challenge: str, build_root: dict[str, Any], package_root: dict[str, Any], package_content: dict[str, Any]) -> dict[str, Any]:
    envelope = exact(
        load_json(path, "Duo capture envelope"),
        {"schema", "version", "status", "platform", "source_commit", "git_head", "challenge", "run_id", "board_contract", "sdk", "toolchain", "artifacts", "artifact_custody", "capture", "evidence_tools", "manifest_identity"},
        "Duo capture envelope",
    )
    require(envelope["schema"] == "vibeos.c83.duo-runtime-costs.capture-envelope" and envelope["version"] == 1 and envelope["status"] == "closed", "Duo capture identity/status differs")
    run_id = pairs[0].summary["run_id"]
    require(envelope["platform"] == DUO_PLATFORM and envelope["source_commit"] == source and envelope["git_head"] == source, "Duo capture source/platform differs")
    require(envelope["challenge"] == challenge and envelope["run_id"] == run_id, "Duo capture challenge/run id differs")
    require(envelope["board_contract"] == manifest["platforms"][DUO_PLATFORM], "Duo board contract differs")
    require(envelope["sdk"] == package_content["sdk"], "Duo capture SDK evidence differs")
    validate_toolchain_contract(envelope["toolchain"])

    capture_artifacts = exact(envelope["artifacts"], {"kernel_binary", "fit_boot_sd", "full_sd_image"}, "Duo capture artifacts")
    for key, record in capture_artifacts.items():
        identity_record(record, f"Duo capture artifact {key}")
        require_identity(record, package_content["artifacts"][key], f"Duo capture/package {key}")
    custody = exact(envelope["artifact_custody"], {"identity_scanned_before_capture_utc", "identity_and_hashes_rechecked_at_closure_utc", "package_evidence"}, "Duo artifact custody")
    before = validate_utc(custody["identity_scanned_before_capture_utc"], "Duo artifact preflight")
    closed = validate_utc(custody["identity_and_hashes_rechecked_at_closure_utc"], "Duo artifact closure")
    require(before <= closed, "Duo artifact custody interval is reversed")
    evidence = exact(custody["package_evidence"], {"content_sha256", "envelope", "image_verifier_audit", "build_envelope"}, "Duo package custody")
    require(evidence["content_sha256"] == package_root["content_sha256"], "Duo capture package content hash differs")
    refs = {
        "envelope": duo_dir / "package-envelope.json",
        "image_verifier_audit": duo_dir / "package-image-verifier-audit.log",
    }
    for key, referenced in refs.items():
        record = identity_record(evidence[key], f"Duo custody {key}", key="file")
        require(record["file"] == referenced.name, f"Duo custody {key} filename differs")
        require_identity(file_identity(referenced), record, f"Duo custody {key}")
    build_ref = exact(evidence["build_envelope"], {"file", "sha256", "bytes", "content_sha256"}, "Duo custody build envelope")
    require(build_ref["file"] == "build-envelope.json" and build_ref["content_sha256"] == build_root["content_sha256"], "Duo custody build content differs")
    require_identity(file_identity(duo_dir / "build-envelope.json"), build_ref, "Duo custody build envelope")

    capture = exact(envelope["capture"], {"started_utc", "completed_utc", "fresh_cold_boots", "timeout_seconds_per_boot", "end_uniqueness_guard_seconds", "power_and_flash_control", "serial", "boots", "cross_boot_p50_stability", "source_tools_package_and_artifacts_rechecked_utc"}, "Duo capture")
    started = validate_utc(capture["started_utc"], "Duo capture start")
    completed = validate_utc(capture["completed_utc"], "Duo capture end")
    rechecked = validate_utc(capture["source_tools_package_and_artifacts_rechecked_utc"], "Duo capture closure")
    require(started <= rechecked <= completed, "Duo capture timestamps are reversed")
    require(capture["fresh_cold_boots"] == BOOT_COUNT, "Duo capture boot count differs")
    require(isinstance(capture["timeout_seconds_per_boot"], (int, float)) and not isinstance(capture["timeout_seconds_per_boot"], bool) and math.isfinite(capture["timeout_seconds_per_boot"]) and capture["timeout_seconds_per_boot"] > 1.0, "Duo capture timeout differs")
    require(capture["end_uniqueness_guard_seconds"] == 1.0, "Duo END guard differs")
    require(capture["power_and_flash_control"] == "manual operator only; collector performs no serial writes, reset, or flash", "Duo manual custody statement differs")
    serial = exact(capture["serial"], {"access", "requested_port", "resolved_port", "settings"}, "Duo capture serial")
    require(serial["access"] == "read-only" and serial["settings"] == "115200 8N1", "Duo UART contract differs")
    require(all(isinstance(serial[key], str) and serial[key].startswith("/") for key in ("requested_port", "resolved_port")), "Duo UART path is not explicit/absolute")

    boots = capture["boots"]
    require(isinstance(boots, list) and len(boots) == BOOT_COUNT, "Duo capture does not contain three boots")
    for index, (boot, pair) in enumerate(zip(boots, pairs)):
        boot = exact(boot, {"boot_index", "operator_confirmation", "operator_confirmed_utc", "capture_started_utc", "first_byte_utc", "completion_marker_closed_utc", "verified_utc", "run_id", "challenge", "raw_log", "summary"}, f"Duo boot {index}")
        require(boot["boot_index"] == index and boot["operator_confirmation"] == f"COLD BOOT {index + 1}", f"Duo boot {index} operator confirmation differs")
        times = [validate_utc(boot[key], f"Duo boot {index} {key}") for key in ("operator_confirmed_utc", "capture_started_utc", "first_byte_utc", "completion_marker_closed_utc", "verified_utc")]
        require(times == sorted(times), f"Duo boot {index} timestamps are reversed")
        require(boot["run_id"] == run_id and boot["challenge"] == challenge, f"Duo boot {index} identity differs")
        raw_ref = identity_record(boot["raw_log"], f"Duo boot {index} raw", key="file")
        summary_ref = identity_record(boot["summary"], f"Duo boot {index} summary", key="file")
        require(raw_ref["file"] == f"boot-{index}.uart.log" and summary_ref["file"] == f"boot-{index}.summary.json", f"Duo boot {index} filename differs")
        require_identity(pair.raw_identity, raw_ref, f"Duo boot {index} raw")
        require_identity(pair.summary_identity, summary_ref, f"Duo boot {index} summary")

    recomputed = recompute_cross_boot(pairs, manifest)
    require(capture["cross_boot_p50_stability"] == recomputed, "Duo cross-boot p50 records differ from raw retained batch ticks")
    tools = exact(envelope["evidence_tools"], {"capture_script", "independent_verifier", "independent_image_verifier", "workload_manifest", "evidence_checker"}, "Duo evidence tools")
    current_tools = {
        "capture_script": DUO_CAPTURE_SCRIPT,
        "independent_verifier": RUNTIME_VERIFIER,
        "independent_image_verifier": DUO_IMAGE_VERIFIER,
        "workload_manifest": MANIFEST_PATH,
        "evidence_checker": SCRIPT_PATH,
    }
    for key, current in current_tools.items():
        validate_tool_identity(tools[key], current, f"Duo evidence tool {key}")
    manifest_identity = exact(envelope["manifest_identity"], {"schema", "version", "suite_id", "workload_revision"}, "Duo manifest identity")
    require(manifest_identity == {key: manifest[key] for key in ("schema", "version", "suite_id", "workload_revision")}, "Duo manifest identity differs")
    return envelope


def recompute_cross_boot(pairs: Sequence[VerifiedPair], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    require(len(pairs) == BOOT_COUNT, "cross-boot calculation requires three boots")
    grouped = [samples_by_workload(pair.samples, manifest) for pair in pairs]
    result: list[dict[str, Any]] = []
    for workload in manifest["workloads"]:
        workload_id = workload["id"]
        boot_p50 = [nearest_rank([integer(sample["ticks"], f"{workload_id} ticks", minimum=1) for sample in group[workload_id]], 50) for group in grouped]
        minimum = min(boot_p50)
        maximum = max(boot_p50)
        require(maximum * 100 <= minimum * 150, f"Duo cross-boot p50 stability failed for {workload_id}: {maximum}/{minimum} > 1.50")
        record: dict[str, Any] = {
            "workload_id": workload_id,
            "category": workload["category"],
            "batch_operations": workload["batch"],
            "boot_p50_batch_ticks": boot_p50,
            "minimum": minimum,
            "maximum": maximum,
            "ratio_numerator": maximum,
            "ratio_denominator": minimum,
            "ratio_limit": "1.50",
        }
        if workload["category"] in {"host-call", "fuel"}:
            fuels = [integer(group[workload_id][0]["fuel_consumed"], f"{workload_id} fuel") for group in grouped]
            polls = [integer(group[workload_id][0]["poll_quanta"], f"{workload_id} polls") for group in grouped]
            require(len(set(fuels)) == 1 and len(set(polls)) == 1, f"Duo cross-boot fuel/poll invariant differs for {workload_id}")
            record.update({
                "boot_fuel_consumed_per_sample": fuels,
                "boot_poll_quanta_per_sample": polls,
                "fuel_consumed_per_sample": fuels[0],
                "poll_quanta_per_sample": polls[0],
            })
        result.append(record)
    return result


def pooled_statistics(pairs: Sequence[VerifiedPair], manifest: dict[str, Any]) -> dict[str, dict[str, dict[str, int]]]:
    all_samples: list[dict[str, Any]] = []
    for pair in pairs:
        all_samples.extend(pair.samples)
    groups = samples_by_workload(all_samples, manifest)
    result: dict[str, dict[str, dict[str, int]]] = {}
    for workload in manifest["workloads"]:
        records = groups[workload["id"]]
        ticks_per_operation = [(record["ticks"] + record["operations"] - 1) // record["operations"] for record in records]
        heap_delta = [record["heap_peak"] - record["heap_before"] for record in records]
        result[workload["id"]] = {
            "ticks_per_operation": distribution(ticks_per_operation),
            "heap_peak_delta_bytes": distribution(heap_delta),
        }
    return result


def render_results(manifest: dict[str, Any], source: str, challenge: str, run_id: str, qemu_pair: VerifiedPair, duo_pairs: Sequence[VerifiedPair], qemu_envelope: dict[str, Any], build_root: dict[str, Any], package_root: dict[str, Any], duo_dir: pathlib.Path) -> str:
    qemu = pooled_statistics([qemu_pair], manifest)
    duo = pooled_statistics(duo_pairs, manifest)
    lines = [
        "# C8.3 WebAssembly runtime costs",
        "",
        "This report is deterministically derived from one verified fixed-QEMU boot and the pooled retained samples from three independently verified physical Milk-V Duo cold boots. Percentiles use nearest rank after per-sample `ceil(batch_ticks / operations)`. QEMU `icount` uses the 10 MHz guest timebase and the Duo uses a 25 MHz physical `rdtime` timebase; these ticks must not be divided to claim a cross-platform speed ratio.",
        "",
        f"- Preparation source: `{source}`",
        f"- Challenge: `{challenge}`",
        f"- Run ID: `{run_id}`",
        f"- Manifest SHA-256: `{file_identity(MANIFEST_PATH)['sha256']}`",
        f"- Transcript schema SHA-256: `{file_identity(SCHEMA_PATH)['sha256']}`",
        f"- Offline checker SHA-256: `{file_identity(SCRIPT_PATH)['sha256']}`",
        "",
        "| Category | Workload | Operations/batch | QEMU min | QEMU p50 | QEMU p95 | Duo pooled min | Duo pooled p50 | Duo pooled p95 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for workload in manifest["workloads"]:
        q = qemu[workload["id"]]["ticks_per_operation"]
        d = duo[workload["id"]]["ticks_per_operation"]
        lines.append(f"| {workload['category']} | `{workload['id']}` | {workload['batch']} | {q['min']} | {q['p50']} | {q['p95']} | {d['min']} | {d['p50']} | {d['p95']} |")
    memory = next(workload for workload in manifest["workloads"] if workload["category"] == "memory")
    q_heap = qemu[memory["id"]]["heap_peak_delta_bytes"]["p50"]
    d_heap = duo[memory["id"]]["heap_peak_delta_bytes"]["p50"]
    lines.extend([
        "",
        "## Scoped memory cost",
        "",
        f"The exact scoped allocator heap-peak delta p50 for `{memory['id']}` is **{q_heap} bytes** on QEMU and **{d_heap} bytes** across the pooled three Duo cold boots. Full per-workload heap distributions remain in the independently derived summaries.",
        "",
        "## Evidence provenance",
        "",
        f"- QEMU executable: `{qemu_envelope['qemu']['sha256']}` ({qemu_envelope['qemu']['version'].splitlines()[0]})",
        f"- Explicit OpenSBI BIOS `{qemu_envelope['bios']['name']}`: `{qemu_envelope['bios']['sha256']}`",
        f"- Duo build envelope content: `{build_root['content_sha256']}`",
        f"- Duo package envelope content: `{package_root['content_sha256']}`",
        f"- Duo package image-verifier audit: `{file_identity(duo_dir / 'package-image-verifier-audit.log')['sha256']}`",
        "",
    ])
    return "\n".join(lines)


@dataclass(frozen=True)
class VerificationResult:
    source: str
    challenge: str
    run_id: str
    results: str


def verify_evidence(root: pathlib.Path, source: str, challenge: str, *, results_required: bool = True) -> VerificationResult:
    root = pathlib.Path(os.path.abspath(os.fspath(root.expanduser())))
    source = canonical_source(source, "expected source commit")
    challenge = canonical_challenge(challenge, "expected challenge")
    validate_regular_tree(root, results_required=results_required)
    manifest, _schema = load_manifest(root)
    qemu_dir = root / "qemu"
    duo_dir = root / "duo"
    qemu_pair = verify_pair(qemu_dir / "uart.log", qemu_dir / "summary.json", QEMU_PLATFORM, source, challenge, 0)
    duo_pairs = [verify_pair(duo_dir / f"boot-{index}.uart.log", duo_dir / f"boot-{index}.summary.json", DUO_PLATFORM, source, challenge, index) for index in range(BOOT_COUNT)]
    run_ids = {qemu_pair.summary["run_id"], *(pair.summary["run_id"] for pair in duo_pairs)}
    require(len(run_ids) == 1, "QEMU and Duo evidence do not share one run id")
    run_id = next(iter(run_ids))
    qemu_envelope = validate_qemu_envelope(qemu_dir / "evidence.json", qemu_pair, source, challenge)
    build_root, build_content = validate_build_envelope(duo_dir / "build-envelope.json", source, challenge)
    package_root, package_content = validate_package_envelope(duo_dir / "package-envelope.json", duo_dir / "build-envelope.json", duo_dir / "package-image-verifier-audit.log", manifest, source, challenge, build_root, build_content)
    validate_capture_envelope(duo_dir / "capture-envelope.json", duo_dir, duo_pairs, manifest, source, challenge, build_root, package_root, package_content)
    results = render_results(manifest, source, challenge, run_id, qemu_pair, duo_pairs, qemu_envelope, build_root, package_root, duo_dir)
    if results_required:
        try:
            checked = (root / "RESULTS.md").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            fail(f"cannot read RESULTS.md: {error}")
        require(checked == results, "RESULTS.md differs from deterministic verified rendering")
    return VerificationResult(source, challenge, run_id, results)


def write_atomic(path: pathlib.Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def canonical_envelope(schema: str, content: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": schema,
        "version": 1,
        "status": "closed",
        "content_sha256": sha256_bytes(canonical),
        "content": content,
    }


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_runtime_verifier_module() -> Any:
    spec = importlib.util.spec_from_file_location("c83_runtime_verifier_selftest", RUNTIME_VERIFIER)
    require(spec is not None and spec.loader is not None, "cannot load runtime verifier for selftest")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_duo_transcript(module: Any, manifest: dict[str, Any], boot_index: int) -> bytes:
    metadata, samples, ending = module.decoded_synthetic(manifest)
    metadata["platform"] = DUO_PLATFORM
    metadata["timebase_hz"] = manifest["platforms"][DUO_PLATFORM]["timebase_hz"]
    for sample in samples:
        sample["ticks"] = 30_000 + sample["sample_index"] + boot_index * 100
    ending["accumulator"] = module.accumulator(samples)
    return module.encode_synthetic(metadata, samples, ending)


def make_synthetic_evidence(root: pathlib.Path) -> tuple[str, str]:
    module = load_runtime_verifier_module()
    manifest = module.load_manifest(MANIFEST_PATH)
    source = "a" * 40
    challenge = "b" * 64
    pinned = parsed_toolchain_contract()
    qemu_dir = root / "qemu"
    duo_dir = root / "duo"
    qemu_dir.mkdir(parents=True)
    duo_dir.mkdir()
    shutil.copyfile(README_PATH, root / "README.md")
    shutil.copyfile(MANIFEST_PATH, root / "workloads-v1.json")
    shutil.copyfile(SCHEMA_PATH, root / "schema-v1.json")

    qemu_raw = module.synthetic_transcript(manifest)
    (qemu_dir / "uart.log").write_bytes(qemu_raw)
    qemu_verified = module.verify_transcript_bytes(qemu_raw, platform=QEMU_PLATFORM, manifest=manifest, expect_source=source, publication=True)
    qemu_summary = module.derive_summary(qemu_verified, manifest, boot_index=0)
    write_json(qemu_dir / "summary.json", qemu_summary)

    duo_pairs: list[VerifiedPair] = []
    for index in range(BOOT_COUNT):
        raw = synthetic_duo_transcript(module, manifest, index)
        raw_path = duo_dir / f"boot-{index}.uart.log"
        summary_path = duo_dir / f"boot-{index}.summary.json"
        raw_path.write_bytes(raw)
        verified = module.verify_transcript_bytes(raw, platform=DUO_PLATFORM, manifest=manifest, expect_source=source, publication=True)
        write_json(summary_path, module.derive_summary(verified, manifest, boot_index=index))
        metadata, retained = parse_retained_samples(raw_path)
        duo_pairs.append(VerifiedPair(metadata, retained, load_json(summary_path, "synthetic Duo summary"), file_identity(raw_path), file_identity(summary_path)))

    def recorded(path: pathlib.Path) -> dict[str, Any]:
        return {"path": str(path.resolve()), **file_identity(path)}

    def fake(path: str, digit: str, size: int = 4096) -> dict[str, Any]:
        return {"path": path, "sha256": digit * 64, "bytes": size}

    empty_repository = {
        "head": source,
        "clean": True,
        "status_command": QEMU_GIT_STATUS_COMMAND,
        "diff_command": QEMU_GIT_DIFF_COMMAND,
        "status_porcelain_v1_z_sha256": EMPTY_SHA256,
        "tracked_diff_head_binary_sha256": EMPTY_SHA256,
    }
    qemu_executable = "/opt/qemu/bin/qemu-system-riscv64"
    bios_path = "/opt/qemu/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin"
    kernel_path = "target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt"
    qemu_envelope = {
        "schema": "vibeos.wasm-runtime-cost.qemu-environment",
        "version": 1,
        "suite_id": "vibeos.c83.runtime-costs",
        "mode": "formal-publication",
        "source_commit": source,
        "challenge": challenge,
        "run_id": qemu_summary["run_id"],
        "started_at_utc": "2026-01-01T00:00:00Z",
        "ended_at_utc": "2026-01-01T00:01:00Z",
        "repository": {"before": empty_repository, "after": dict(empty_repository)},
        "runner": {"path": "scripts/qemu-c83-runtime-costs.py", **file_identity(QEMU_RUNNER)},
        "verifier": {"path": "scripts/verify-c83-runtime-costs.py", **file_identity(RUNTIME_VERIFIER), "publication_gate": True},
        "evidence_checker": {"path": "scripts/verify-c83-evidence.py", **file_identity(SCRIPT_PATH)},
        "toolchain": {
            "channel": pinned["channel"],
            "pinned_rustc_commit": pinned["rustc_commit"],
            "rustc_vv": f"rustc {pinned['rustc']}\ncommit-hash: {pinned['rustc_commit']}",
            "cargo_version": "cargo 1.99.0-nightly",
            "rustup": fake("/tools/bin/rustup", "1"),
            "cargo": fake("/toolchain/bin/cargo", "2"),
            "rustc": fake("/toolchain/bin/rustc", "3"),
            "rustdoc": fake("/toolchain/bin/rustdoc", "4"),
            "linker": fake("/llvm/bin/ld.lld", "5"),
            "cargo_command": ["/tools/bin/rustup", "run", pinned["channel"], "cargo", "build", "--release", "--locked", "--offline", "--no-default-features", "--features", "wasm-c83-runtime-costs"],
            "build_environment_policy": {
                "ambient_variables": "denied-by-default",
                "cargo_home": "ephemeral-config-free registry/git cache links only",
                "cargo_net_offline": True,
                "path_entries": ["/llvm/bin", "/tools/bin", "/usr/bin", "/bin"],
                "allowed_names": QEMU_BUILD_ALLOWED_NAMES,
                "normalized_values": {
                    "CARGO_HOME": "<temporary-root>/cargo-home",
                    "CARGO_INCREMENTAL": "0",
                    "CARGO_NET_OFFLINE": "true",
                    "CARGO_TERM_COLOR": "never",
                    "HOME": "<temporary-root>/home",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/llvm/bin:/tools/bin:/usr/bin:/bin",
                    "RUSTC": "/toolchain/bin/rustc",
                    "RUSTDOC": "/toolchain/bin/rustdoc",
                    "RUSTUP_HOME": "/rustup",
                    "SOURCE_DATE_EPOCH": "1767225600",
                    "TMPDIR": "<temporary-root>/tmp",
                    "TZ": "UTC",
                    "VIBEOS_C83_CHALLENGE": challenge,
                    "VIBEOS_C83_SOURCE_COMMIT": source,
                },
            },
        },
        "kernel_elf": fake(kernel_path, "5"),
        "qemu": {
            "resolved_executable": qemu_executable,
            "version": "QEMU emulator version 11.0.0",
            "argv": [qemu_executable, "-machine", "virt", "-cpu", "rv64", "-smp", "1", "-m", "128M", "-accel", "tcg,thread=single", "-icount", "shift=0,align=off,sleep=off", "-nographic", "-bios", bios_path, "-kernel", "/checkout/" + kernel_path],
            "sha256": "3" * 64,
            "bytes": 1_000_000,
        },
        "bios": {"name": pathlib.PurePath(bios_path).name, "resolved_path": bios_path, "sha256": "4" * 64, "bytes": 200_000},
        "transcript": file_identity(qemu_dir / "uart.log"),
        "summary": file_identity(qemu_dir / "summary.json"),
    }
    write_json(qemu_dir / "evidence.json", qemu_envelope)

    toolchain = {
        "channel": pinned["channel"],
        "rustc_verbose": f"rustc {pinned['rustc']}\ncommit-hash: {pinned['rustc_commit']}",
        "rustup": fake("/toolchain/bin/rustup", "3"),
        "cargo": fake("/toolchain/bin/cargo", "4"),
        "rustc": fake("/toolchain/bin/rustc", "5"),
        "rustdoc": fake("/toolchain/bin/rustdoc", "6"),
        "rust_objcopy": fake("/toolchain/bin/rust-objcopy", "7"),
        "linker": fake("/sdk/bin/riscv64-unknown-elf-ld", "8"),
    }
    build_artifacts = {
        "kernel_elf": fake("/checkout/target/milkv-duo-runtime-costs/vibeos-milkv-duo-runtime-costs.elf", "a", 2_000_000),
        "kernel_binary": fake("/checkout/target/milkv-duo-runtime-costs/vibeos-milkv-duo.bin", "b", 1_000_000),
    }
    build_tools = {
        "build_script": DUO_BUILD_SCRIPT,
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
    allowed_keys = ["CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "HOME", "LC_ALL", "PATH", "RUSTC", "RUSTDOC", "RUSTUP_HOME", "SOURCE_DATE_EPOCH", "TMPDIR", "TZ", "VIBEOS_C83_CHALLENGE", "VIBEOS_C83_SOURCE_COMMIT"]
    build_content = {
        "platform": DUO_PLATFORM,
        "source_commit": source,
        "challenge": challenge,
        "source": {"root": "/checkout", "head": source, "worktree_clean": True, "status_policy": STRICT_DUO_STATUS_POLICY},
        "command": [toolchain["rustup"]["path"], "run", toolchain["channel"], "cargo", "build", "--release", "--locked", "--offline", "--no-default-features", "--features", "wasm-c83-runtime-costs"],
        "objcopy_command": [toolchain["rust_objcopy"]["path"], "-O", "binary", build_artifacts["kernel_elf"]["path"], build_artifacts["kernel_binary"]["path"]],
        "objcopy_environment": {"mode": "env -i", "allowed_keys": ["LC_ALL", "PATH", "TZ"], "values": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}},
        "environment": {
            "mode": "env -i",
            "allowed_keys": allowed_keys,
            "values": {
                "CARGO_HOME": "<isolated-cargo-home>", "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_DIR": f"/checkout/target/c83-milkv-build/{source}/{challenge}", "HOME": "<isolated-cargo-home>/home",
                "LC_ALL": "C", "PATH": "/usr/bin:/bin", "RUSTC": toolchain["rustc"]["path"], "RUSTDOC": toolchain["rustdoc"]["path"],
                "RUSTUP_HOME": "/toolchain", "SOURCE_DATE_EPOCH": "1767225600", "TMPDIR": "<isolated-cargo-home>/tmp", "TZ": "UTC",
                "VIBEOS_C83_CHALLENGE": challenge, "VIBEOS_C83_SOURCE_COMMIT": source,
            },
            "cargo_home_isolation": {"ambient_config_loaded": False, "temporary": True, "cache_source": "/cache/cargo", "registry_cache_symlinked": True, "git_cache_symlinked": True},
        },
        "toolchain": toolchain,
        "artifacts": build_artifacts,
        "tools": {key: recorded(value) for key, value in build_tools.items()},
        "timestamps_utc": {"build_started": "2026-01-01T00:00:00Z", "build_completed": "2026-01-01T00:01:00Z", "envelope_closed": "2026-01-01T00:02:00Z"},
    }
    build_root = canonical_envelope("vibeos.c83.duo-runtime-costs.build-envelope", build_content)
    write_json(duo_dir / "build-envelope.json", build_root)
    audit_path = duo_dir / "package-image-verifier-audit.log"
    audit_path.write_text("PASS: FAT boot + raw data MBR image\n", encoding="utf-8")
    package_artifacts = {
        **build_artifacts,
        "fit_boot_sd": fake("/checkout/target/milkv-duo-runtime-costs/boot.sd", "c", 4_000_000),
        "full_sd_image": fake("/checkout/target/milkv-duo-runtime-costs/vibeos-milkv-duo-runtime-costs-sd.img", "d", 8_000_000),
        "sdk_fip": fake("/sdk/fip.bin", "e", 500_000),
        "sdk_dtb": fake("/sdk/cv1800b_milkv_duo_sd.dtb", "f", 50_000),
    }
    package_source_tools = {
        "package_script": DUO_PACKAGE_SCRIPT,
        "image_verifier_script": DUO_IMAGE_VERIFIER,
        "build_script": DUO_BUILD_SCRIPT,
        "fit_source": ROOT / "scripts/milkv-duo.its",
        "genimage_config": ROOT / "scripts/milkv-duo-genimage.cfg",
        "workload_manifest": MANIFEST_PATH,
        "toolchain_contract": TOOLCHAIN_PATH,
        "evidence_checker": SCRIPT_PATH,
    }
    package_content = {
        "platform": DUO_PLATFORM,
        "source_commit": source,
        "challenge": challenge,
        "source": {"root": "/checkout", "head": source, "worktree_clean": True, "status_policy": STRICT_DUO_STATUS_POLICY},
        "sdk": {"root": "/sdk", "commit": manifest["platforms"][DUO_PLATFORM]["sdk_commit"], "declared_container_digest": manifest["platforms"][DUO_PLATFORM]["sdk_container_digest"], "worktree_clean": True, "status_policy": STRICT_DUO_STATUS_POLICY},
        "build": {"content_sha256": build_root["content_sha256"], "envelope": recorded(duo_dir / "build-envelope.json")},
        "artifacts": package_artifacts,
        "verifier": {"status": "PASS", "audit_log": recorded(audit_path), "invocation": ["scripts/verify-milkv-duo-image.sh", "--runtime-costs", "<sdk-root>"]},
        "tools": {
            **{key: recorded(value) for key, value in package_source_tools.items()},
            "sdk_mkimage": fake("/sdk/bin/mkimage", "1"),
            "sdk_dumpimage": fake("/sdk/bin/dumpimage", "2"),
            "sdk_genimage": fake("/sdk/bin/genimage", "3"),
        },
        "timestamps_utc": {"packaging_started": "2026-01-01T00:03:00Z", "image_verified": "2026-01-01T00:04:00Z", "envelope_closed": "2026-01-01T00:05:00Z"},
    }
    package_root = canonical_envelope("vibeos.c83.duo-runtime-costs.package-envelope", package_content)
    write_json(duo_dir / "package-envelope.json", package_root)

    toolchain_raw = TOOLCHAIN_PATH.read_bytes()
    toolchain_text = toolchain_raw.decode()
    channel = re.search(r'^channel = "([^"]+)"$', toolchain_text, re.MULTILINE)
    rustc = re.search(r"^# rustc (.+)$", toolchain_text, re.MULTILINE)
    rustc_commit = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", toolchain_text, re.MULTILINE)
    assert channel is not None and rustc is not None and rustc_commit is not None
    boots: list[dict[str, Any]] = []
    for index, pair in enumerate(duo_pairs):
        minute = index * 5 + 10
        boots.append({
            "boot_index": index,
            "operator_confirmation": f"COLD BOOT {index + 1}",
            "operator_confirmed_utc": f"2026-01-01T00:{minute:02d}:00Z",
            "capture_started_utc": f"2026-01-01T00:{minute + 1:02d}:00Z",
            "first_byte_utc": f"2026-01-01T00:{minute + 2:02d}:00Z",
            "completion_marker_closed_utc": f"2026-01-01T00:{minute + 3:02d}:00Z",
            "verified_utc": f"2026-01-01T00:{minute + 4:02d}:00Z",
            "run_id": qemu_summary["run_id"],
            "challenge": challenge,
            "raw_log": {"file": f"boot-{index}.uart.log", **pair.raw_identity},
            "summary": {"file": f"boot-{index}.summary.json", **pair.summary_identity},
        })
    capture_envelope = {
        "schema": "vibeos.c83.duo-runtime-costs.capture-envelope",
        "version": 1,
        "status": "closed",
        "platform": DUO_PLATFORM,
        "source_commit": source,
        "git_head": source,
        "challenge": challenge,
        "run_id": qemu_summary["run_id"],
        "board_contract": manifest["platforms"][DUO_PLATFORM],
        "sdk": package_content["sdk"],
        "toolchain": {"channel": channel.group(1), "rustc": rustc.group(1), "rustc_commit": rustc_commit.group(1), "rust_toolchain_toml_sha256": sha256_bytes(toolchain_raw), "rust_toolchain_toml_bytes": len(toolchain_raw)},
        "artifacts": {key: package_artifacts[key] for key in ("kernel_binary", "fit_boot_sd", "full_sd_image")},
        "artifact_custody": {
            "identity_scanned_before_capture_utc": "2026-01-01T00:06:00Z",
            "identity_and_hashes_rechecked_at_closure_utc": "2026-01-01T00:58:00Z",
            "package_evidence": {
                "content_sha256": package_root["content_sha256"],
                "envelope": {"file": "package-envelope.json", **file_identity(duo_dir / "package-envelope.json")},
                "image_verifier_audit": {"file": audit_path.name, **file_identity(audit_path)},
                "build_envelope": {"file": "build-envelope.json", **file_identity(duo_dir / "build-envelope.json"), "content_sha256": build_root["content_sha256"]},
            },
        },
        "capture": {
            "started_utc": "2026-01-01T00:07:00Z",
            "completed_utc": "2026-01-01T00:59:00Z",
            "fresh_cold_boots": 3,
            "timeout_seconds_per_boot": 900.0,
            "end_uniqueness_guard_seconds": 1.0,
            "power_and_flash_control": "manual operator only; collector performs no serial writes, reset, or flash",
            "serial": {"access": "read-only", "requested_port": "/dev/cu.DUO", "resolved_port": "/dev/cu.DUO", "settings": "115200 8N1"},
            "boots": boots,
            "cross_boot_p50_stability": recompute_cross_boot(duo_pairs, manifest),
            "source_tools_package_and_artifacts_rechecked_utc": "2026-01-01T00:58:30Z",
        },
        "evidence_tools": {
            "capture_script": recorded(DUO_CAPTURE_SCRIPT),
            "independent_verifier": recorded(RUNTIME_VERIFIER),
            "independent_image_verifier": recorded(DUO_IMAGE_VERIFIER),
            "workload_manifest": recorded(MANIFEST_PATH),
            "evidence_checker": recorded(SCRIPT_PATH),
        },
        "manifest_identity": {key: manifest[key] for key in ("schema", "version", "suite_id", "workload_revision")},
    }
    write_json(duo_dir / "capture-envelope.json", capture_envelope)
    result = verify_evidence(root, source, challenge, results_required=False)
    (root / "RESULTS.md").write_text(result.results, encoding="utf-8")
    return source, challenge


def selftest() -> None:
    rejected = 0
    good = b'{"a":1,"b":{"c":2}}'
    require(strict_json_bytes(good, "selftest") == {"a": 1, "b": {"c": 2}}, "strict JSON baseline differs")
    for label, candidate in (
        ("duplicate-root", b'{"a":1,"a":2}'),
        ("duplicate-nested", b'{"a":{"c":1,"c":2}}'),
    ):
        try:
            strict_json_bytes(candidate, label)
        except EvidenceError:
            rejected += 1
        else:
            fail(f"selftest accepted {label}")

    values = [100, 101, 102, 103, 104]
    require(distribution(values) == {"samples": 5, "min": 100, "p50": 102, "p95": 104, "max": 104, "mean": 102}, "nearest-rank selftest differs")
    for label, action in (
        ("zero-sha", lambda: canonical_sha("0" * 64, "selftest hash")),
        ("test-source", lambda: canonical_source("1" * 40, "selftest source")),
        ("test-challenge", lambda: canonical_challenge("2" * 64, "selftest challenge")),
        ("bool-integer", lambda: integer(True, "selftest integer")),
    ):
        try:
            action()
        except EvidenceError:
            rejected += 1
        else:
            fail(f"selftest accepted {label}")

    with tempfile.TemporaryDirectory(prefix="vibeos-c83-evidence-selftest-", dir="/tmp") as name:
        base = pathlib.Path(name) / "base"
        source, challenge = make_synthetic_evidence(base)
        verify_evidence(base, source, challenge)

        mutations: list[tuple[str, Callable[[pathlib.Path], None]]] = []
        mutations.append(("extra-tree-member", lambda root: (root / "unexpected").write_bytes(b"x")))
        mutations.append(("changed-results", lambda root: (root / "RESULTS.md").write_text("not derived\n", encoding="utf-8")))
        mutations.append(("changed-qemu-raw", lambda root: (root / "qemu/uart.log").write_bytes((root / "qemu/uart.log").read_bytes() + b"late fatal\n")))
        mutations.append(("changed-duo-summary", lambda root: (root / "duo/boot-1.summary.json").write_text("{}\n", encoding="utf-8")))
        mutations.append(("changed-package-audit", lambda root: (root / "duo/package-image-verifier-audit.log").write_bytes((root / "duo/package-image-verifier-audit.log").read_bytes() + b"fatal\n")))

        def mutate_json(relative: str, action: Callable[[dict[str, Any]], None]) -> Callable[[pathlib.Path], None]:
            def apply(root: pathlib.Path) -> None:
                path = root / relative
                value = strict_json_bytes(path.read_bytes(), f"selftest {relative}")
                assert isinstance(value, dict)
                action(value)
                write_json(path, value)
            return apply

        mutations.extend([
            ("qemu-dirty-source", mutate_json("qemu/evidence.json", lambda value: value["repository"]["after"].update(clean=False))),
            ("qemu-bios-argv", mutate_json("qemu/evidence.json", lambda value: value["qemu"]["argv"].__setitem__(-3, "/other/bios.bin"))),
            ("qemu-checker-hash", mutate_json("qemu/evidence.json", lambda value: value["evidence_checker"].update(sha256="9" * 64))),
            ("qemu-toolchain-pin", mutate_json("qemu/evidence.json", lambda value: value["toolchain"].update(pinned_rustc_commit="9" * 40))),
            ("qemu-build-allowlist", mutate_json("qemu/evidence.json", lambda value: value["toolchain"]["build_environment_policy"]["allowed_names"].pop())),
            ("qemu-rustup-identity", mutate_json("qemu/evidence.json", lambda value: value["toolchain"]["rustup"].update(path="rustup"))),
            ("qemu-build-path", mutate_json("qemu/evidence.json", lambda value: value["toolchain"]["build_environment_policy"]["path_entries"].append("/ambient/bin"))),
            ("qemu-ambient-home", mutate_json("qemu/evidence.json", lambda value: value["toolchain"]["build_environment_policy"]["normalized_values"].update(HOME="/Users/operator"))),
            ("qemu-incremental-build", mutate_json("qemu/evidence.json", lambda value: value["toolchain"]["build_environment_policy"]["normalized_values"].update(CARGO_INCREMENTAL="1"))),
            ("build-extra-field", mutate_json("duo/build-envelope.json", lambda value: value["content"].update(extra=True))),
            ("package-build-reference", mutate_json("duo/package-envelope.json", lambda value: value["content"]["build"].update(content_sha256="9" * 64))),
            ("capture-cross-boot", mutate_json("duo/capture-envelope.json", lambda value: value["capture"]["cross_boot_p50_stability"][0]["boot_p50_batch_ticks"].__setitem__(0, 1))),
            ("capture-source", mutate_json("duo/capture-envelope.json", lambda value: value.update(source_commit="c" * 40))),
        ])

        for index, (label, mutation) in enumerate(mutations):
            candidate = pathlib.Path(name) / f"mutation-{index}"
            shutil.copytree(base, candidate)
            mutation(candidate)
            try:
                verify_evidence(candidate, source, challenge)
            except EvidenceError:
                rejected += 1
            else:
                fail(f"selftest accepted {label}")

        symlink = pathlib.Path(name) / "symlink"
        shutil.copytree(base, symlink)
        (symlink / "qemu/uart.log").unlink()
        os.symlink(symlink / "README.md", symlink / "qemu/uart.log")
        try:
            verify_evidence(symlink, source, challenge)
        except EvidenceError:
            rejected += 1
        else:
            fail("selftest accepted evidence symlink")

        duplicate = pathlib.Path(name) / "duplicate"
        shutil.copytree(base, duplicate)
        envelope_path = duplicate / "qemu/evidence.json"
        raw = envelope_path.read_bytes()
        envelope_path.write_bytes(raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1))
        try:
            verify_evidence(duplicate, source, challenge)
        except EvidenceError:
            rejected += 1
        else:
            fail("selftest accepted duplicate envelope member")

    require(rejected == 26, f"selftest rejection count differs: {rejected}")
    print(f"verify-c83-evidence.py selftest: PASS ({rejected} mutations rejected)")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline verify and deterministically render the complete C8.3 publication evidence.")
    parser.add_argument("--evidence-root", type=pathlib.Path, default=BENCHMARK_ROOT)
    parser.add_argument("--expect-source", help="preparation commit bound into both platform captures")
    parser.add_argument("--expect-challenge", help="fresh 256-bit challenge bound into both platform captures")
    parser.add_argument("--write-results", action="store_true", help="atomically create or replace RESULTS.md after all other evidence passes")
    parser.add_argument("--selftest", action="store_true")
    return parser


def main() -> int:
    arguments = argument_parser().parse_args()
    try:
        if arguments.selftest:
            selftest()
            require(arguments.expect_source is None and arguments.expect_challenge is None and not arguments.write_results, "--selftest cannot be combined with publication options")
            return 0
        require(arguments.expect_source is not None, "--expect-source is required")
        require(arguments.expect_challenge is not None, "--expect-challenge is required")
        result = verify_evidence(arguments.evidence_root, arguments.expect_source, arguments.expect_challenge, results_required=not arguments.write_results)
        if arguments.write_results:
            write_atomic(arguments.evidence_root.resolve(strict=True) / "RESULTS.md", result.results)
            # Re-scan and exact-check the just-written report so write mode has
            # the same closed-tree postcondition as verification mode.
            verify_evidence(arguments.evidence_root, result.source, result.challenge, results_required=True)
        print(f"PASS C8.3 evidence source={result.source} challenge={result.challenge} run_id={result.run_id}")
        return 0
    except (EvidenceError, OSError, UnicodeDecodeError) as error:
        print(f"FAIL verify-c83-evidence: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
