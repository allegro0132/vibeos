#!/usr/bin/env python3
"""Host-observed Docker custody for the formal C8.4 package.

The public launcher creates two independent, networkless containers from one
content-pinned linux/amd64 image.  A private guest command closes the namespace
that it actually observes before packaging or independently verifying the
image.  The resulting canonical, content-addressed records are software
custody evidence only: they do not attest physical hardware or a cold boot.

Only the Python standard library and the local Docker CLI are used.  The
``--selftest`` path uses synthetic inspect/mountinfo data and never invokes
Docker, a network, a device, or a physical board.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn, Sequence


IMAGE_REFERENCE = (
    "milkvtech/milkv-duo@"
    "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679"
)
SCRIPT_PATH = pathlib.Path(__file__).resolve()
IMAGE_DIGEST = "sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679"
SDK_COMMIT = "23eb84fecb29585dbb5728d6b7e2475ff273baac"
PLATFORM = "linux/amd64"
CONTAINER_SOURCE = pathlib.PurePosixPath("/home/vibeos")
CONTAINER_TARGET = pathlib.PurePosixPath("/home/vibeos/target")
CONTAINER_SDK = pathlib.PurePosixPath("/home/work")
CONTAINER_GIT_CONFIG = pathlib.PurePosixPath("/etc/vibeos-c84.gitconfig")
CONTAINER_PREINSPECT = pathlib.PurePosixPath("/run/vibeos-c84-host")
ARTIFACT_RELATIVE = pathlib.PurePosixPath("target/milkv-duo-wasm-aot-profile")
PACKAGE_ATTESTATION = "container-runtime-attestation.json"
VERIFIER_ATTESTATION = "container-runtime-verifier-attestation.json"
CLOSURE_FILENAME = "container-runtime-closure.json"
HOST_PREINSPECT_FILENAME = "host-preinspect.json"
SOURCE_ENVELOPE_ROOT = pathlib.PurePosixPath("target/c84-source-materialization")
ATTESTATION_SCHEMA = "vibeos.c84.docker-runtime-attestation"
PREINSPECT_SCHEMA = "vibeos.c84.docker-host-preinspect"
CLOSURE_SCHEMA = "vibeos.c84.docker-runtime-closure"
SOURCE_SCHEMA = "vibeos.c84.source-materialization-envelope"
PACKAGE_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.package-envelope"
BUILD_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.build-envelope"
IMAGE_AUDIT_SCHEMA = "vibeos.c84.duo-wasm-aot-profile.image-audit-report"
VERSION = 1
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
VOLUME_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
CAPABILITY = (
    "host Docker daemon inspect plus in-container namespace witness; "
    "software custody only"
)
RUNTIME_PROVENANCE = CAPABILITY
IMAGE_VERIFIER_PASS = (
    "PASS: C8.4 FAT boot + raw data MBR image, FIP, FIT metadata, "
    "kernel/DTB payloads, and CRC32 hashes are valid"
)
RUNTIME_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
FIXED_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": str(CONTAINER_GIT_CONFIG),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "HOME": "/nonexistent",
    "LC_ALL": "C",
    "PATH": RUNTIME_PATH,
    "TZ": "UTC",
    "VIBEOS_C84_SDK_CONTAINER_DIGEST": IMAGE_DIGEST,
}
FORMAL_ARTIFACTS = {
    "boot_sd": "boot.sd",
    "build_envelope": "build-envelope.json",
    "full_sd_image": "vibeos-milkv-duo-wasm-aot-profile-sd.img",
    "image_verifier_audit": "image-verifier-audit.log",
    "kernel_binary": "vibeos-milkv-duo.bin",
    "kernel_elf": "vibeos-milkv-duo-wasm-aot-profile.elf",
    "package_envelope": "package-envelope.json",
    "packaged_dtb": "cv1800b_milkv_duo_sd.dtb",
    "packaged_fit_source": "milkv-duo.its",
    "package_attestation": PACKAGE_ATTESTATION,
    "verifier_attestation": VERIFIER_ATTESTATION,
}
SOURCE_CONTENT_KEYS = {
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
}
BUILD_TOOL_PATHS = {
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
PACKAGE_SOURCE_TOOL_PATHS = {
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
PACKAGE_SDK_TOOL_PATHS = {
    "sdk_mkimage": "/home/work/u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/mkimage",
    "sdk_dumpimage": "/home/work/u-boot-2021.10/build/cv1800b_milkv_duo_sd/tools/dumpimage",
}
PACKAGE_GENIMAGE_PATHS = {
    "/home/work/buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/host/bin/genimage",
    "/home/work/buildroot-2021.05/output/milkv-duo-sd_musl_riscv64/per-package/host-genimage/host/bin/genimage",
}
PACKAGE_VERIFIER_TOOL_BASENAMES = {
    # The pinned image exposes mdir/mcopy as symlinks to the single canonical
    # mtools multicall binary.  Package custody records resolved targets.
    "verifier_mdir": {"mtools"},
    "verifier_mcopy": {"mtools"},
    "verifier_cmp": {"cmp"},
    "verifier_sha256sum": {"sha256sum"},
    "verifier_fdtget": {"fdtget"},
    "verifier_python3": {
        "python3",
        "python3.8",
        "python3.9",
        "python3.10",
        "python3.11",
        "python3.12",
    },
    "verifier_tr": {"tr"},
}
PACKAGE_ARTIFACT_PATHS = {
    "kernel_elf": str(
        CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["kernel_elf"]
    ),
    "kernel_binary": str(
        CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["kernel_binary"]
    ),
    "packaged_fit_source": str(
        CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["packaged_fit_source"]
    ),
    "packaged_dtb": str(
        CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["packaged_dtb"]
    ),
    "fit_boot_sd": str(
        CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["boot_sd"]
    ),
    "full_sd_image": str(
        CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["full_sd_image"]
    ),
    "sdk_fip": "/home/work/install/soc_cv1800b_milkv_duo_sd/fip.bin",
    "sdk_dtb": "/home/work/linux_5.10/build/cv1800b_milkv_duo_sd/arch/riscv/boot/dts/cvitek/cv1800b_milkv_duo_sd.dtb",
}


class RuntimeClosureError(RuntimeError):
    """The C8.4 Docker software-custody boundary is not closed."""


def fail(message: str) -> NoReturn:
    raise RuntimeClosureError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_commit(value: str, label: str = "source commit") -> str:
    require(HEX40.fullmatch(value) is not None, f"{label} must be 40 lowercase hex")
    require(value not in {"0" * 40, "1" * 40}, f"{label} uses a forbidden sentinel")
    return value


def canonical_challenge(value: str, label: str = "challenge") -> str:
    require(HEX64.fullmatch(value) is not None, f"{label} must be 64 lowercase hex")
    require(value not in {"0" * 64, "2" * 64}, f"{label} uses a forbidden sentinel")
    return value


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> NoReturn:
    fail(f"non-finite JSON number {value!r}")


def strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {label}: {error}")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        fail(f"cannot canonicalize JSON: {error}")


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(set(value) == keys, f"{label} fields are not closed")
    return value


def content_addressed_root(
    schema: str, content: dict[str, Any], *, version: int = VERSION
) -> dict[str, Any]:
    return {
        "content": content,
        "content_sha256": hashlib.sha256(canonical_json(content)).hexdigest(),
        "schema": schema,
        "status": "closed",
        "version": version,
    }


def validate_content_addressed_root(
    root: Any, schema: str, label: str, *, version: int = VERSION
) -> dict[str, Any]:
    root = exact(
        root,
        {"content", "content_sha256", "schema", "status", "version"},
        label,
    )
    require(
        root["schema"] == schema
        and type(root["version"]) is int
        and root["version"] == version
        and root["status"] == "closed",
        f"{label} identity/status differs",
    )
    require(isinstance(root["content"], dict), f"{label} content is not an object")
    require(
        isinstance(root["content_sha256"], str)
        and HEX64.fullmatch(root["content_sha256"]) is not None
        and hashlib.sha256(canonical_json(root["content"])).hexdigest()
        == root["content_sha256"],
        f"{label} content address differs",
    )
    return root


def path_without_symlink(path: pathlib.Path, label: str) -> pathlib.Path:
    require(path.is_absolute(), f"{label} must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label} {path}: {error}")
    require(resolved == path, f"{label} is not canonical: {path}")
    current = pathlib.Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            require(
                not stat.S_ISLNK(current.lstat().st_mode), f"{label} crosses a symlink"
            )
    except OSError as error:
        fail(f"cannot inspect {label} {current}: {error}")
    return resolved


def docker_cli_invocation_path(candidate: pathlib.Path) -> str:
    """Validate a Docker CLI path without destroying its argv[0] dispatch name.

    Docker-compatible desktop runtimes may expose ``docker`` as a symlink to a
    multi-call executable.  Executing the resolved target changes argv[0] to
    e.g. ``docker-tools`` and makes the otherwise valid CLI reject the call.
    Keep the absolute ``docker`` entry point while still proving its target is
    a regular executable.
    """

    require(candidate.is_absolute(), "Docker CLI path is not absolute")
    require(candidate.name == "docker", "Docker CLI entry point is not named docker")
    try:
        candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved_stat = resolved.stat()
    except OSError as error:
        fail(f"cannot inspect Docker CLI {candidate}: {error}")
    require(
        stat.S_ISREG(resolved_stat.st_mode),
        f"Docker CLI target is not a regular file: {resolved}",
    )
    require(os.access(candidate, os.X_OK), f"Docker CLI is not executable: {candidate}")
    return str(candidate)


def stable_regular_bytes(
    path: pathlib.Path,
    label: str,
    *,
    maximum: int = MAX_JSON_BYTES,
    single_link: bool = True,
) -> bytes:
    try:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file: {path}")
        require(not stat.S_ISLNK(before.st_mode), f"{label} is a symlink: {path}")
        require(
            not single_link or before.st_nlink == 1, f"{label} is hardlinked: {path}"
        )
        require(0 < before.st_size <= maximum, f"{label} has an invalid byte count")
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        fail(f"cannot read {label} {path}: {error}")
    require(
        (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        f"{label} changed while read",
    )
    require(len(raw) == before.st_size, f"{label} was truncated while read")
    return raw


def snapshot_file(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        before = path.lstat()
        require(
            stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode),
            f"{label} is not a regular non-symlink file: {path}",
        )
        require(
            before.st_nlink == 1 and before.st_size > 0,
            f"{label} is hardlinked or empty",
        )
        digest = hashlib.sha256()
        observed = 0
        with path.open("rb") as source:
            while chunk := source.read(4 * 1024 * 1024):
                digest.update(chunk)
                observed += len(chunk)
        after = path.lstat()
    except OSError as error:
        fail(f"cannot hash {label} {path}: {error}")
    require(
        (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        f"{label} changed while hashed",
    )
    require(observed == before.st_size, f"{label} was truncated while hashed")
    return {
        "bytes": observed,
        "device": before.st_dev,
        "inode": before.st_ino,
        "links": before.st_nlink,
        "mode": before.st_mode,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": digest.hexdigest(),
    }


class StabilityTracker:
    """Pin every live file used by offline closure validation until PASS."""

    def __init__(self) -> None:
        self._snapshots: dict[pathlib.Path, tuple[str, dict[str, Any]]] = {}

    def observe(self, path: pathlib.Path, label: str) -> dict[str, Any]:
        require(path.is_absolute(), f"{label} path is not absolute")
        observed = snapshot_file(path, label)
        previous = self._snapshots.get(path)
        if previous is None:
            self._snapshots[path] = (label, observed)
        else:
            require(previous[1] == observed, f"{label} changed between validations")
        return {"bytes": observed["bytes"], "sha256": observed["sha256"]}

    def recheck(self) -> None:
        for path, (label, expected) in self._snapshots.items():
            require(
                snapshot_file(path, label) == expected,
                f"{label} changed before terminal closure PASS",
            )


def file_identity(
    path: pathlib.Path, label: str, *, tracker: StabilityTracker | None = None
) -> dict[str, Any]:
    if tracker is not None:
        return tracker.observe(path, label)
    snapshot = snapshot_file(path, label)
    return {"bytes": snapshot["bytes"], "sha256": snapshot["sha256"]}


def identity_record(value: Any, label: str) -> dict[str, Any]:
    value = exact(value, {"bytes", "sha256"}, label)
    require(
        type(value["bytes"]) is int
        and value["bytes"] > 0
        and isinstance(value["sha256"], str)
        and HEX64.fullmatch(value["sha256"]) is not None,
        f"{label} is malformed",
    )
    return value


def file_record(
    value: Any, label: str, *, expected_path: str | None = None
) -> dict[str, Any]:
    value = exact(value, {"bytes", "path", "sha256"}, label)
    identity_record({"bytes": value["bytes"], "sha256": value["sha256"]}, label)
    require(
        isinstance(value["path"], str) and value["path"] != "",
        f"{label} path is malformed",
    )
    if expected_path is not None:
        require(value["path"] == expected_path, f"{label} path differs")
    return value


def measurement_record(value: Any, label: str) -> dict[str, Any]:
    return identity_record(value, label)


def read_canonical_root(
    path: pathlib.Path,
    schema: str,
    label: str,
    *,
    version: int = VERSION,
    maximum: int = MAX_JSON_BYTES,
    tracker: StabilityTracker | None = None,
) -> tuple[dict[str, Any], bytes]:
    raw = stable_regular_bytes(path, label, maximum=maximum)
    if tracker is not None:
        tracker.observe(path, label)
    root = validate_content_addressed_root(
        strict_json(raw, label), schema, label, version=version
    )
    require(raw == canonical_json(root) + b"\n", f"{label} is not canonical JSON")
    return root, raw


def write_no_clobber(path: pathlib.Path, root: dict[str, Any], label: str) -> None:
    raw = canonical_json(root) + b"\n"
    require(len(raw) <= MAX_JSON_BYTES, f"{label} exceeds the byte bound")
    try:
        parent_lstat = path.parent.lstat()
        require(
            stat.S_ISDIR(parent_lstat.st_mode)
            and not stat.S_ISLNK(parent_lstat.st_mode),
            f"{label} parent is not a fixed directory",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o444)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, f"short write for {label}")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        fail(f"refusing to replace existing {label}: {path}")
    except OSError as error:
        fail(f"cannot publish {label} {path}: {error}")
    observed = stable_regular_bytes(path, label)
    require(observed == raw, f"published {label} differs")


def strict_environment(source_commit: str, challenge: str) -> dict[str, str]:
    result = dict(FIXED_ENVIRONMENT)
    result["VIBEOS_C84_CHALLENGE"] = challenge
    result["VIBEOS_C84_SOURCE_COMMIT"] = source_commit
    return result


def environment_list(value: Any, label: str) -> dict[str, str]:
    require(isinstance(value, list), f"{label} is not an array")
    result: dict[str, str] = {}
    for item in value:
        require(isinstance(item, str) and "=" in item, f"{label} entry is malformed")
        key, item_value = item.split("=", 1)
        require(key and key not in result, f"{label} has a duplicate key {key!r}")
        result[key] = item_value
    return result


def mount_contract(
    source: pathlib.Path,
    target: pathlib.Path,
    git_config: pathlib.Path,
    host_directory: pathlib.Path,
    sdk_root: pathlib.Path | None,
    sdk_volume: str | None,
) -> list[dict[str, Any]]:
    sdk = (
        {
            "destination": str(CONTAINER_SDK),
            "kind": "bind",
            "source": str(sdk_root),
            "read_only": True,
        }
        if sdk_root is not None
        else {
            "destination": str(CONTAINER_SDK),
            "kind": "volume",
            "source": sdk_volume,
            "read_only": True,
        }
    )
    return [
        {
            "destination": str(CONTAINER_SOURCE),
            "kind": "bind",
            "source": str(source),
            "read_only": True,
        },
        {
            "destination": str(CONTAINER_TARGET),
            "kind": "bind",
            "source": str(target),
            "read_only": False,
        },
        sdk,
        {
            "destination": str(CONTAINER_GIT_CONFIG),
            "kind": "bind",
            "source": str(git_config),
            "read_only": True,
        },
        {
            "destination": str(CONTAINER_PREINSPECT),
            "kind": "bind",
            "source": str(host_directory),
            "read_only": True,
        },
    ]


def validate_image_inspect(image: Any) -> dict[str, Any]:
    require(isinstance(image, dict), "image inspect value is not an object")
    image_id = image.get("Id")
    require(
        isinstance(image_id, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None,
        "image inspect Id is malformed",
    )
    repo_digests = image.get("RepoDigests")
    require(
        isinstance(repo_digests, list)
        and all(isinstance(item, str) for item in repo_digests)
        and len(repo_digests) == len(set(repo_digests))
        and IMAGE_REFERENCE in repo_digests,
        "image inspect RepoDigests do not bind the pinned reference",
    )
    descriptor = image.get("Descriptor")
    require(isinstance(descriptor, dict), "image inspect Descriptor is missing")
    require(descriptor.get("digest") == IMAGE_DIGEST, "image Descriptor digest differs")
    require(image.get("Os") == "linux", "image OS differs")
    require(image.get("Architecture") == "amd64", "image architecture differs")
    config = image.get("Config")
    require(isinstance(config, dict), "image Config is missing")
    inherited = environment_list(config.get("Env") or [], "image Config.Env")
    require(
        set(inherited).issubset(FIXED_ENVIRONMENT),
        "image has an environment key outside the runtime allowlist",
    )
    return image


def mount_spec_map(container: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    mounts = container.get("Mounts")
    require(isinstance(mounts, list), f"{label} Mounts is not an array")
    result: dict[str, dict[str, Any]] = {}
    for record in mounts:
        require(isinstance(record, dict), f"{label} mount is not an object")
        destination = record.get("Destination")
        require(
            isinstance(destination, str) and destination not in result,
            f"{label} mount destination is malformed",
        )
        result[destination] = record
    return result


def validate_mounts(
    container: dict[str, Any], contract_mounts: Any, label: str
) -> None:
    require(isinstance(contract_mounts, list), "mount contract is not an array")
    require(
        all(isinstance(item, dict) for item in contract_mounts),
        "mount contract contains a non-object",
    )
    expected = {item.get("destination"): item for item in contract_mounts}
    require(
        None not in expected and len(expected) == len(contract_mounts),
        "mount contract destinations differ",
    )
    observed = mount_spec_map(container, label)
    require(set(observed) == set(expected), f"{label} mount destinations differ")
    for destination, wanted in expected.items():
        wanted = exact(
            wanted,
            {"destination", "kind", "read_only", "source"},
            f"mount contract {destination}",
        )
        record = observed[destination]
        require(
            record.get("Type") == wanted["kind"],
            f"{label} mount type differs for {destination}",
        )
        require(
            record.get("RW") is (not wanted["read_only"]),
            f"{label} mount access differs for {destination}",
        )
        if wanted["kind"] == "bind":
            require(
                record.get("Propagation", "rprivate") == "rprivate",
                f"{label} mount propagation differs for {destination}",
            )
            require(
                record.get("Source") == wanted["source"],
                f"{label} mount source differs for {destination}",
            )
        else:
            require(
                record.get("Propagation", "") in ("", "rprivate"),
                f"{label} volume propagation differs for {destination}",
            )
            require(
                record.get("Name") == wanted["source"],
                f"{label} volume name differs for {destination}",
            )


def validate_mount_contract_shape(contract_mounts: Any) -> dict[str, dict[str, Any]]:
    require(isinstance(contract_mounts, list), "mount contract is not an array")
    result: dict[str, dict[str, Any]] = {}
    for value in contract_mounts:
        record = exact(
            value,
            {"destination", "kind", "read_only", "source"},
            "mount contract record",
        )
        destination = record["destination"]
        require(
            isinstance(destination, str) and destination not in result,
            "mount contract destination is malformed/duplicate",
        )
        require(
            record["kind"] in {"bind", "volume"} and type(record["read_only"]) is bool,
            f"mount contract values differ for {destination}",
        )
        require(
            isinstance(record["source"], str) and record["source"],
            f"mount contract source differs for {destination}",
        )
        result[destination] = record
    expected_destinations = {
        str(CONTAINER_SOURCE),
        str(CONTAINER_TARGET),
        str(CONTAINER_SDK),
        str(CONTAINER_GIT_CONFIG),
        str(CONTAINER_PREINSPECT),
    }
    require(
        set(result) == expected_destinations,
        "mount contract destinations are not exact",
    )
    for destination in (
        str(CONTAINER_SOURCE),
        str(CONTAINER_GIT_CONFIG),
        str(CONTAINER_PREINSPECT),
    ):
        require(
            result[destination]["kind"] == "bind"
            and result[destination]["read_only"] is True,
            f"mount contract access differs for {destination}",
        )
    require(
        result[str(CONTAINER_TARGET)]["kind"] == "bind"
        and result[str(CONTAINER_TARGET)]["read_only"] is False,
        "nested target mount contract differs",
    )
    require(
        result[str(CONTAINER_SDK)]["kind"] in {"bind", "volume"}
        and result[str(CONTAINER_SDK)]["read_only"] is True,
        "SDK mount contract differs",
    )
    source_path = pathlib.PurePath(result[str(CONTAINER_SOURCE)]["source"])
    target_path = pathlib.PurePath(result[str(CONTAINER_TARGET)]["source"])
    config_path = pathlib.PurePath(result[str(CONTAINER_GIT_CONFIG)]["source"])
    require(
        source_path.is_absolute() and target_path == source_path / "target",
        "nested target host source differs",
    )
    require(
        config_path == source_path / "scripts/c84-docker.gitconfig",
        "Git-config host source differs",
    )
    preinspect_path = pathlib.PurePath(result[str(CONTAINER_PREINSPECT)]["source"])
    require(preinspect_path.is_absolute(), "host-preinspect source is not absolute")
    sdk_source = result[str(CONTAINER_SDK)]["source"]
    if result[str(CONTAINER_SDK)]["kind"] == "bind":
        require(
            pathlib.PurePath(sdk_source).is_absolute(),
            "SDK bind source is not absolute",
        )
    else:
        require(
            VOLUME_NAME.fullmatch(sdk_source) is not None,
            "SDK volume source is malformed",
        )
    return result


def validate_hostconfig_mounts(
    host: dict[str, Any], contract_mounts: list[dict[str, Any]], label: str
) -> None:
    raw = host.get("Mounts")
    require(isinstance(raw, list), f"{label} HostConfig.Mounts is not an array")
    require(
        len(raw) == len(contract_mounts), f"{label} HostConfig.Mounts count differs"
    )
    observed: dict[str, dict[str, Any]] = {}
    for record in raw:
        require(isinstance(record, dict), f"{label} HostConfig mount is not an object")
        target = record.get("Target")
        require(
            isinstance(target, str) and target not in observed,
            f"{label} HostConfig mount target differs",
        )
        observed[target] = record
    expected = {record["destination"]: record for record in contract_mounts}
    require(set(observed) == set(expected), f"{label} HostConfig mount targets differ")
    for target, wanted in expected.items():
        record = observed[target]
        require(
            record.get("Type") == wanted["kind"]
            and record.get("Source") == wanted["source"],
            f"{label} HostConfig mount source/type differs for {target}",
        )
        # Docker's HostConfig JSON uses an omitempty boolean: writable mounts
        # may omit ReadOnly instead of serializing false.  Normalize only that
        # absence; explicit null/non-boolean values remain rejected.
        observed_read_only = record.get("ReadOnly", False)
        require(
            type(observed_read_only) is bool
            and observed_read_only is wanted["read_only"],
            f"{label} HostConfig mount access differs for {target}",
        )
        if wanted["kind"] == "bind":
            options = record.get("BindOptions") or {}
            require(
                isinstance(options, dict)
                and options.get("Propagation", "rprivate") == "rprivate",
                f"{label} bind propagation differs for {target}",
            )
        else:
            options = record.get("VolumeOptions") or {}
            require(
                isinstance(options, dict) and options.get("NoCopy") is True,
                f"{label} volume no-copy policy differs for {target}",
            )


def validate_network_settings(value: Any, label: str) -> None:
    require(isinstance(value, dict), f"{label} NetworkSettings is not an object")
    ports = value.get("Ports")
    require(ports in (None, {}), f"{label} publishes ports")
    networks = value.get("Networks")
    require(isinstance(networks, dict), f"{label} Networks is not an object")
    require(set(networks).issubset({"none"}), f"{label} has an unexpected network")
    for network in networks.values():
        require(isinstance(network, dict), f"{label} network record is malformed")
        for key in (
            "Gateway",
            "IPAddress",
            "GlobalIPv6Address",
            "IPv6Gateway",
            "MacAddress",
        ):
            require(
                network.get(key) in (None, ""), f"{label} network {key} is populated"
            )


def validate_container_inspect(
    container: Any,
    contract: dict[str, Any],
    image: dict[str, Any],
    label: str,
    *,
    phase: str,
    expected_id: str | None = None,
) -> dict[str, Any]:
    require(isinstance(container, dict), f"{label} inspect is not an object")
    identifier = container.get("Id")
    require(
        isinstance(identifier, str) and CONTAINER_ID.fullmatch(identifier) is not None,
        f"{label} Id is malformed",
    )
    if expected_id is not None:
        require(identifier == expected_id, f"{label} Id differs")
    require(container.get("Image") == image["Id"], f"{label} image Id differs")
    config = container.get("Config")
    host = container.get("HostConfig")
    require(
        isinstance(config, dict) and isinstance(host, dict),
        f"{label} config is missing",
    )
    require(config.get("Image") == IMAGE_REFERENCE, f"{label} image reference differs")
    require(
        config.get("User") == f"{contract['uid']}:{contract['gid']}",
        f"{label} user differs",
    )
    require(
        config.get("WorkingDir") == str(CONTAINER_SOURCE), f"{label} workdir differs"
    )
    require(config.get("Entrypoint") == ["python3"], f"{label} entrypoint differs")
    require(config.get("Cmd") == contract["command"], f"{label} command differs")
    require(
        environment_list(config.get("Env"), f"{label} Config.Env")
        == contract["environment"],
        f"{label} environment differs",
    )
    require(host.get("Privileged") is False, f"{label} is privileged")
    require(host.get("CapAdd") in (None, []), f"{label} adds capabilities")
    require(host.get("CapDrop") == ["ALL"], f"{label} does not drop all capabilities")
    require(host.get("Devices") in (None, []), f"{label} has devices")
    require(host.get("DeviceRequests") in (None, []), f"{label} has device requests")
    # A real Docker launch with --user uid:gid leaves GroupAdd empty, while the
    # Linux process-status witness below reports that primary gid as Groups: gid.
    require(host.get("GroupAdd") in (None, []), f"{label} adds supplementary groups")
    require(host.get("NetworkMode") == "none", f"{label} network mode differs")
    require(host.get("PidMode") == "", f"{label} PID namespace mode differs")
    require(host.get("IpcMode") == "private", f"{label} IPC namespace mode differs")
    require(host.get("UTSMode") == "", f"{label} UTS namespace mode differs")
    require(host.get("UsernsMode") == "", f"{label} user namespace mode differs")
    restart = exact(
        host.get("RestartPolicy"),
        {"MaximumRetryCount", "Name"},
        f"{label} restart policy",
    )
    require(
        restart["Name"] in {"", "no"}
        and type(restart["MaximumRetryCount"]) is int
        and restart["MaximumRetryCount"] == 0,
        f"{label} restart policy differs",
    )
    for key in ("Dns", "DnsOptions", "DnsSearch", "ExtraHosts"):
        require(host.get(key) in (None, []), f"{label} {key} is not empty")
    require(host.get("AutoRemove") is False, f"{label} auto-remove policy differs")
    require(
        host.get("Init") is None or host.get("Init") is False,
        f"{label} init policy differs",
    )
    require(host.get("PortBindings") in (None, {}), f"{label} binds ports")
    require(host.get("PublishAllPorts") is False, f"{label} publishes all ports")
    require(host.get("Binds") in (None, []), f"{label} uses unclosed legacy binds")
    require(host.get("Links") in (None, []), f"{label} has links")
    require(host.get("VolumesFrom") in (None, []), f"{label} inherits volumes")
    require(host.get("ReadonlyRootfs") is False, f"{label} rootfs policy differs")
    security = host.get("SecurityOpt") or []
    require(
        security in (["no-new-privileges:true"], ["no-new-privileges"]),
        f"{label} no-new-privileges policy differs",
    )
    validate_hostconfig_mounts(host, contract["mounts"], label)
    validate_mounts(container, contract["mounts"], label)
    validate_network_settings(container.get("NetworkSettings"), label)
    state = container.get("State")
    require(isinstance(state, dict), f"{label} State is missing")
    require(phase in {"created", "exited"}, f"{label} validation phase is malformed")
    require(state.get("Dead") is False, f"{label} is dead")
    require(state.get("Paused") is False, f"{label} is paused")
    require(state.get("Restarting") is False, f"{label} is restarting")
    require(state.get("Error") == "", f"{label} state error is populated")
    require(
        type(state.get("Pid")) is int and state["Pid"] == 0,
        f"{label} state PID differs",
    )
    require(state.get("OOMKilled") is False, f"{label} was OOM-killed")
    require(
        type(state.get("ExitCode")) is int and state["ExitCode"] == 0,
        f"{label} exit code differs",
    )
    if phase == "created":
        require(
            state.get("Status") == "created"
            and state.get("Running") is False
            and state["ExitCode"] == 0,
            f"{label} pre-start state differs",
        )
    else:
        require(
            state.get("Status") == "exited"
            and state.get("Running") is False
            and state["ExitCode"] == 0,
            f"{label} terminal state differs",
        )
    return container


def host_preinspect_content(
    *,
    mode: str,
    source_commit: str,
    challenge: str,
    uid: int,
    gid: int,
    image: dict[str, Any],
    container: dict[str, Any],
    mounts: list[dict[str, Any]],
    sdk_volume_inspect: dict[str, Any] | None,
    create_argv: list[str],
) -> dict[str, Any]:
    command = [
        "scripts/c84-docker-runtime.py",
        "guest-package",
        "--host-preinspect",
        str(CONTAINER_PREINSPECT / HOST_PREINSPECT_FILENAME),
        "--source-commit",
        source_commit,
        "--challenge",
        challenge,
        "--mode",
        mode,
    ]
    contract = {
        "capability": CAPABILITY,
        "command": command,
        "create_argv": create_argv,
        "environment": strict_environment(source_commit, challenge),
        "gid": gid,
        "image_digest": IMAGE_DIGEST,
        "image_reference": IMAGE_REFERENCE,
        "mounts": mounts,
        "network": {
            "interfaces": ["lo"],
            "ipv4_routes": [],
            "ipv6_policy": "loopback-only",
        },
        "platform": PLATFORM,
        # Docker GroupAdd remains empty.  Linux reports this primary gid in the
        # process-status Groups witness for the pinned --user uid:gid launch.
        "supplementary_groups": [gid],
        "uid": uid,
    }
    return {
        "challenge": challenge,
        "container_preinspect": container,
        "contract": contract,
        "image_inspect": image,
        "mode": mode,
        "sdk_volume_inspect": sdk_volume_inspect,
        "source_commit": source_commit,
    }


def validate_host_preinspect(
    root: Any,
    *,
    source_commit: str,
    challenge: str,
    expect_mode: str,
) -> dict[str, Any]:
    root = validate_content_addressed_root(root, PREINSPECT_SCHEMA, "host preinspect")
    content = exact(
        root["content"],
        {
            "challenge",
            "container_preinspect",
            "contract",
            "image_inspect",
            "mode",
            "sdk_volume_inspect",
            "source_commit",
        },
        "host preinspect content",
    )
    require(
        content["source_commit"] == source_commit
        and content["challenge"] == challenge
        and content["mode"] == expect_mode,
        "host preinspect campaign identity differs",
    )
    image = validate_image_inspect(content["image_inspect"])
    contract = exact(
        content["contract"],
        {
            "capability",
            "command",
            "create_argv",
            "environment",
            "gid",
            "image_digest",
            "image_reference",
            "mounts",
            "network",
            "platform",
            "supplementary_groups",
            "uid",
        },
        "host contract",
    )
    require(contract["capability"] == CAPABILITY, "host contract capability differs")
    require(
        contract["image_reference"] == IMAGE_REFERENCE
        and contract["image_digest"] == IMAGE_DIGEST,
        "host contract image differs",
    )
    require(contract["platform"] == PLATFORM, "host contract platform differs")
    require(
        type(contract["uid"]) is int and contract["uid"] > 0,
        "host contract uid is malformed/root",
    )
    require(
        type(contract["gid"]) is int and contract["gid"] > 0,
        "host contract gid is malformed/root",
    )
    require(
        contract["supplementary_groups"] == [contract["gid"]],
        "host contract status groups differ",
    )
    require(
        contract["environment"] == strict_environment(source_commit, challenge),
        "host contract environment differs",
    )
    contract_mount_map = validate_mount_contract_shape(contract["mounts"])
    sdk_contract = contract_mount_map[str(CONTAINER_SDK)]
    if sdk_contract["kind"] == "volume":
        validate_volume_inspect(content["sdk_volume_inspect"], sdk_contract["source"])
    else:
        require(
            content["sdk_volume_inspect"] is None,
            "bind-mounted SDK unexpectedly has a volume inspect",
        )
    expected_command = [
        "scripts/c84-docker-runtime.py",
        "guest-package",
        "--host-preinspect",
        str(CONTAINER_PREINSPECT / HOST_PREINSPECT_FILENAME),
        "--source-commit",
        source_commit,
        "--challenge",
        challenge,
        "--mode",
        expect_mode,
    ]
    require(contract["command"] == expected_command, "host contract command differs")
    require(
        isinstance(contract["create_argv"], list)
        and all(isinstance(item, str) and item for item in contract["create_argv"]),
        "host create argv is malformed",
    )
    require(
        contract["create_argv"]
        == docker_create_arguments(
            uid=contract["uid"],
            gid=contract["gid"],
            mounts=contract["mounts"],
            source_commit=source_commit,
            challenge=challenge,
            mode=expect_mode,
        ),
        "host create argv differs from the closed launcher",
    )
    network = exact(
        contract["network"],
        {"interfaces", "ipv4_routes", "ipv6_policy"},
        "host network contract",
    )
    require(
        network
        == {"interfaces": ["lo"], "ipv4_routes": [], "ipv6_policy": "loopback-only"},
        "host network contract differs",
    )
    validate_container_inspect(
        content["container_preinspect"],
        contract,
        image,
        "container preinspect",
        phase="created",
    )
    return root


def decode_mount_field(value: str) -> str:
    """Decode the only escaping admitted by proc(5) mountinfo."""
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            output.append(value[index])
            index += 1
            continue
        require(index + 3 < len(value), "truncated mountinfo escape")
        digits = value[index + 1 : index + 4]
        require(
            re.fullmatch(r"[0-7]{3}", digits) is not None, "invalid mountinfo escape"
        )
        output.append(chr(int(digits, 8)))
        index += 4
    decoded = "".join(output)
    require("\x00" not in decoded, "mountinfo field contains NUL")
    return decoded


def comma_options(value: str, label: str) -> list[str]:
    options = value.split(",")
    require(options and all(options), f"{label} contains an empty option")
    require(len(options) == len(set(options)), f"{label} contains duplicate options")
    return options


def parse_mountinfo(raw: str) -> list[dict[str, Any]]:
    require(raw.endswith("\n"), "mountinfo lacks a terminal newline")
    result: list[dict[str, Any]] = []
    identifiers: set[int] = set()
    for number, line in enumerate(raw.splitlines(), 1):
        left, separator, right = line.partition(" - ")
        require(separator != "", f"mountinfo line {number} lacks a separator")
        before = left.split(" ")
        after = right.split(" ")
        require(
            len(before) >= 6 and len(after) == 3,
            f"mountinfo line {number} is malformed",
        )
        try:
            mount_id = int(before[0], 10)
            parent_id = int(before[1], 10)
        except ValueError:
            fail(f"mountinfo line {number} has a non-numeric id")
        require(
            mount_id > 0 and parent_id > 0 and mount_id not in identifiers,
            f"mountinfo line {number} id differs",
        )
        identifiers.add(mount_id)
        require(
            re.fullmatch(r"[0-9]+:[0-9]+", before[2]) is not None,
            f"mountinfo line {number} device differs",
        )
        entry = {
            "filesystem_type": decode_mount_field(after[0]),
            "major_minor": before[2],
            "mount_id": mount_id,
            "mount_options": comma_options(
                before[5], f"mountinfo line {number} mount options"
            ),
            "mount_point": decode_mount_field(before[4]),
            "mount_source": decode_mount_field(after[1]),
            "optional_fields": [decode_mount_field(item) for item in before[6:]],
            "parent_id": parent_id,
            "root": decode_mount_field(before[3]),
            "super_options": comma_options(
                after[2], f"mountinfo line {number} super options"
            ),
        }
        require(
            entry["mount_point"].startswith("/"),
            f"mountinfo line {number} mount point is not absolute",
        )
        result.append(entry)
    require(result, "mountinfo is empty")
    return result


def parse_status(raw: str) -> dict[str, Any]:
    require(raw.endswith("\n"), "status lacks a terminal newline")
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        require(
            separator != "" and key not in fields,
            "status contains a malformed/duplicate field",
        )
        fields[key] = value.strip()
    expected = (
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
    )
    require(all(key in fields for key in expected), "status lacks a custody field")
    result: dict[str, Any] = {}
    for key in ("Uid", "Gid"):
        parts = fields[key].split()
        require(len(parts) == 4, f"status {key} differs")
        try:
            result[key.lower()] = [int(item, 10) for item in parts]
        except ValueError:
            fail(f"status {key} is malformed")
    try:
        result["groups"] = [int(item, 10) for item in fields["Groups"].split()]
    except ValueError:
        fail("status Groups is malformed")
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        require(
            re.fullmatch(r"[0-9A-Fa-f]{16}", fields[key]) is not None,
            f"status {key} is malformed",
        )
        result[key.lower()] = fields[key].lower()
    require(fields["NoNewPrivs"] in {"0", "1"}, "status NoNewPrivs is malformed")
    result["no_new_privs"] = int(fields["NoNewPrivs"])
    return result


def parse_ipv4_routes(raw: str) -> list[dict[str, str]]:
    require(raw.endswith("\n"), "IPv4 route table lacks a terminal newline")
    lines = raw.splitlines()
    require(lines, "IPv4 route table is empty")
    header = lines[0].split()
    expected = [
        "Iface",
        "Destination",
        "Gateway",
        "Flags",
        "RefCnt",
        "Use",
        "Metric",
        "Mask",
        "MTU",
        "Window",
        "IRTT",
    ]
    require(header == expected, "IPv4 route header differs")
    records: list[dict[str, str]] = []
    for line in lines[1:]:
        parts = line.split()
        require(len(parts) == len(expected), "IPv4 route row is malformed")
        records.append(dict(zip(expected, parts)))
    return records


def parse_ipv6_routes(raw: str) -> list[dict[str, str]]:
    require(
        raw.endswith("\n") or raw == "", "IPv6 route table lacks a terminal newline"
    )
    keys = [
        "destination",
        "destination_prefix",
        "source",
        "source_prefix",
        "next_hop",
        "metric",
        "reference",
        "use",
        "flags",
        "interface",
    ]
    records: list[dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split()
        require(len(parts) == 10, "IPv6 route row is malformed")
        require(
            re.fullmatch(r"[0-9A-Fa-f]{32}", parts[0]) is not None,
            "IPv6 destination is malformed",
        )
        require(
            re.fullmatch(r"[0-9A-Fa-f]{2}", parts[1]) is not None,
            "IPv6 destination prefix is malformed",
        )
        require(
            re.fullmatch(r"[0-9A-Fa-f]{32}", parts[2]) is not None,
            "IPv6 source is malformed",
        )
        require(
            re.fullmatch(r"[0-9A-Fa-f]{2}", parts[3]) is not None,
            "IPv6 source prefix is malformed",
        )
        require(
            re.fullmatch(r"[0-9A-Fa-f]{32}", parts[4]) is not None,
            "IPv6 next hop is malformed",
        )
        require(
            all(
                re.fullmatch(r"[0-9A-Fa-f]{8}", item) is not None for item in parts[5:9]
            ),
            "IPv6 counters are malformed",
        )
        records.append(
            dict(zip(keys, [item.lower() for item in parts[:9]] + [parts[9]]))
        )
    return records


def bounded_proc_text(path: pathlib.Path, label: str) -> str:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_TEXT_BYTES + 1)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    require(len(raw) <= MAX_TEXT_BYTES, f"{label} exceeds its byte bound")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")


def relevant_mounts(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    destinations = {
        str(CONTAINER_SOURCE),
        str(CONTAINER_TARGET),
        str(CONTAINER_SDK),
        str(CONTAINER_GIT_CONFIG),
        str(CONTAINER_PREINSPECT),
    }
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        point = entry["mount_point"]
        if point in destinations:
            require(point not in result, f"duplicate guest mountpoint {point}")
            result[point] = entry
        elif (
            point.startswith(str(CONTAINER_SOURCE) + "/")
            or point.startswith(str(CONTAINER_PREINSPECT) + "/")
            or point.startswith(str(CONTAINER_SDK) + "/")
        ):
            fail(f"unexpected nested custody mount {point}")
    require(set(result) == destinations, "guest custody mountpoints differ")
    return result


def validate_witness(witness: Any, preinspect: dict[str, Any]) -> dict[str, Any]:
    witness = exact(
        witness,
        {
            "credentials",
            "environment",
            "hostname",
            "interfaces",
            "ipv4_route_raw",
            "ipv4_routes",
            "ipv6_route_raw",
            "ipv6_routes",
            "mountinfo",
            "mountinfo_raw",
            "preinspect_entries",
            "status_raw",
        },
        "guest witness",
    )
    require(
        isinstance(witness["mountinfo_raw"], str),
        "witness mountinfo raw value is malformed",
    )
    reparsed_mounts = parse_mountinfo(witness["mountinfo_raw"])
    require(
        witness["mountinfo"] == reparsed_mounts,
        "witness parsed mountinfo differs from raw bytes",
    )
    observed = relevant_mounts(reparsed_mounts)
    for destination in (
        str(CONTAINER_SOURCE),
        str(CONTAINER_SDK),
        str(CONTAINER_GIT_CONFIG),
        str(CONTAINER_PREINSPECT),
    ):
        require(
            "ro" in observed[destination]["mount_options"]
            and "rw" not in observed[destination]["mount_options"],
            f"guest mount is not read-only: {destination}",
        )
    target = observed[str(CONTAINER_TARGET)]
    require(
        "rw" in target["mount_options"] and "ro" not in target["mount_options"],
        "guest target mount is not writable",
    )
    require(
        isinstance(witness["status_raw"], str), "witness status raw value is malformed"
    )
    credentials = parse_status(witness["status_raw"])
    require(
        witness["credentials"] == credentials,
        "witness parsed credentials differ from status",
    )
    contract = preinspect["content"]["contract"]
    uid = contract["uid"]
    gid = contract["gid"]
    require(
        credentials["uid"] == [uid] * 4 and credentials["gid"] == [gid] * 4,
        "guest uid/gid differs",
    )
    require(
        credentials["groups"] == contract["supplementary_groups"] == [gid],
        "guest status groups differ",
    )
    require(
        all(
            credentials[key] == "0000000000000000"
            for key in ("capinh", "capprm", "capeff", "capbnd", "capamb")
        ),
        "guest capabilities are nonzero",
    )
    require(credentials["no_new_privs"] == 1, "guest no-new-privileges is not set")
    container = preinspect["content"]["container_preinspect"]
    expected_hostname = container["Config"]["Hostname"]
    require(
        isinstance(expected_hostname, str)
        and expected_hostname == container["Id"][:12]
        and witness["hostname"] == expected_hostname,
        "guest hostname differs from the created container",
    )
    expected_environment = dict(contract["environment"])
    expected_environment["HOSTNAME"] = expected_hostname
    require(
        witness["environment"] == expected_environment,
        "guest process environment differs",
    )
    require(
        witness["preinspect_entries"] == [HOST_PREINSPECT_FILENAME],
        "guest host-preinspect directory entries differ",
    )
    require(witness["interfaces"] == ["lo"], "guest network interfaces differ")
    require(
        isinstance(witness["ipv4_route_raw"], str),
        "witness IPv4 raw value is malformed",
    )
    ipv4 = parse_ipv4_routes(witness["ipv4_route_raw"])
    require(witness["ipv4_routes"] == ipv4 and ipv4 == [], "guest has an IPv4 route")
    require(
        isinstance(witness["ipv6_route_raw"], str),
        "witness IPv6 raw value is malformed",
    )
    ipv6 = parse_ipv6_routes(witness["ipv6_route_raw"])
    require(
        witness["ipv6_routes"] == ipv6,
        "witness parsed IPv6 routes differ from raw bytes",
    )
    require(
        all(record["interface"] == "lo" for record in ipv6),
        "guest has a non-loopback IPv6 route",
    )
    return witness


def observe_guest_witness() -> dict[str, Any]:
    mountinfo_raw = bounded_proc_text(
        pathlib.Path("/proc/self/mountinfo"), "guest mountinfo"
    )
    status_raw = bounded_proc_text(pathlib.Path("/proc/self/status"), "guest status")
    ipv4_raw = bounded_proc_text(pathlib.Path("/proc/net/route"), "guest IPv4 routes")
    ipv6_raw = bounded_proc_text(
        pathlib.Path("/proc/net/ipv6_route"), "guest IPv6 routes"
    )
    try:
        interfaces = sorted(entry.name for entry in os.scandir("/sys/class/net"))
        preinspect_entries = sorted(
            entry.name for entry in os.scandir(CONTAINER_PREINSPECT)
        )
    except OSError as error:
        fail(f"cannot enumerate guest interface/preinspect entries: {error}")
    return {
        "credentials": parse_status(status_raw),
        "environment": dict(os.environ),
        "hostname": socket.gethostname(),
        "interfaces": interfaces,
        "ipv4_route_raw": ipv4_raw,
        "ipv4_routes": parse_ipv4_routes(ipv4_raw),
        "ipv6_route_raw": ipv6_raw,
        "ipv6_routes": parse_ipv6_routes(ipv6_raw),
        "mountinfo": parse_mountinfo(mountinfo_raw),
        "mountinfo_raw": mountinfo_raw,
        "preinspect_entries": preinspect_entries,
        "status_raw": status_raw,
    }


def source_envelope_path(
    source_root: pathlib.Path, source_commit: str, challenge: str
) -> pathlib.Path:
    return (
        source_root
        / pathlib.Path(*SOURCE_ENVELOPE_ROOT.parts)
        / source_commit
        / challenge
        / "source-materialization-envelope.json"
    )


def load_source_envelope(
    source_root: pathlib.Path,
    source_commit: str,
    challenge: str,
    *,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    path = source_envelope_path(source_root, source_commit, challenge)
    root, _ = read_canonical_root(
        path,
        SOURCE_SCHEMA,
        "source materialization envelope",
        tracker=tracker,
    )
    content = exact(
        root["content"], SOURCE_CONTENT_KEYS, "source materialization content"
    )
    require(
        content.get("source_commit") == source_commit
        and content.get("challenge") == challenge,
        "source materialization campaign identity differs",
    )
    require(
        not contains_old_provenance(root),
        "source materialization contains operator-declared provenance",
    )
    return root


def validate_attestation_root(
    root: Any,
    *,
    source_root: pathlib.Path,
    source_commit: str,
    challenge: str,
    expect_mode: str,
    expected_file_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = validate_content_addressed_root(
        root, ATTESTATION_SCHEMA, "runtime attestation"
    )
    content = exact(
        root["content"],
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
        "runtime attestation content",
    )
    require(
        content["capability"] == CAPABILITY
        and content["source_commit"] == source_commit
        and content["challenge"] == challenge
        and content["mode"] == expect_mode,
        "runtime attestation identity differs",
    )
    preinspect = validate_host_preinspect(
        content["host_preinspect"],
        source_commit=source_commit,
        challenge=challenge,
        expect_mode=expect_mode,
    )
    pre_identity = identity_record(
        content["host_preinspect_identity"], "host preinspect identity"
    )
    pre_raw = canonical_json(preinspect) + b"\n"
    require(
        pre_identity
        == {"bytes": len(pre_raw), "sha256": hashlib.sha256(pre_raw).hexdigest()},
        "host preinspect identity differs",
    )
    if expected_file_identity is not None:
        identity_record(expected_file_identity, "runtime attestation file identity")
    source_envelope = load_source_envelope(source_root, source_commit, challenge)
    require(
        content["source_materialization_content_sha256"]
        == source_envelope["content_sha256"],
        "attestation source materialization differs",
    )
    validate_witness(content["witness"], preinspect)
    require(
        "operator-declared" not in canonical_json(root).decode("utf-8"),
        "runtime attestation contains operator-declared provenance",
    )
    return root


def read_attestation(
    path: pathlib.Path,
    *,
    source_root: pathlib.Path,
    source_commit: str,
    challenge: str,
    expect_mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    root, raw = read_canonical_root(path, ATTESTATION_SCHEMA, "runtime attestation")
    identity = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    validate_attestation_root(
        root,
        source_root=source_root,
        source_commit=source_commit,
        challenge=challenge,
        expect_mode=expect_mode,
        expected_file_identity=identity,
    )
    return root, identity


def guest_package(
    host_preinspect: pathlib.Path,
    source_commit: str,
    challenge: str,
    mode: str,
) -> NoReturn:
    require(
        host_preinspect
        == pathlib.Path(CONTAINER_PREINSPECT / HOST_PREINSPECT_FILENAME),
        "guest host-preinspect path differs",
    )
    pre_root, pre_raw = read_canonical_root(
        host_preinspect, PREINSPECT_SCHEMA, "host preinspect"
    )
    validate_host_preinspect(
        pre_root, source_commit=source_commit, challenge=challenge, expect_mode=mode
    )
    witness = observe_guest_witness()
    validate_witness(witness, pre_root)
    source_root = pathlib.Path(CONTAINER_SOURCE)
    source_envelope = load_source_envelope(source_root, source_commit, challenge)
    content = {
        "capability": CAPABILITY,
        "challenge": challenge,
        "host_preinspect": pre_root,
        "host_preinspect_identity": {
            "bytes": len(pre_raw),
            "sha256": hashlib.sha256(pre_raw).hexdigest(),
        },
        "mode": mode,
        "source_commit": source_commit,
        "source_materialization_content_sha256": source_envelope["content_sha256"],
        "witness": witness,
    }
    root = content_addressed_root(ATTESTATION_SCHEMA, content)
    artifact_root = source_root / pathlib.Path(*ARTIFACT_RELATIVE.parts)
    destination = artifact_root / (
        PACKAGE_ATTESTATION if mode == "package" else VERIFIER_ATTESTATION
    )
    write_no_clobber(destination, root, f"{mode} runtime attestation")
    environment = strict_environment(source_commit, challenge)
    if mode == "package":
        executable = source_root / "scripts/package-milkv-duo-sdk.sh"
        arguments = [str(executable), "--wasm-aot-profile", str(CONTAINER_SDK)]
    else:
        executable = source_root / "scripts/verify-milkv-duo-image.sh"
        arguments = [
            str(executable),
            "--wasm-aot-profile",
            f"--artifact-root={artifact_root}",
            str(CONTAINER_SDK),
        ]
    raw_executable = stable_regular_bytes(
        executable, f"{mode} executable", maximum=MAX_TEXT_BYTES
    )
    require(raw_executable.startswith(b"#!"), f"{mode} executable lacks a shebang")
    try:
        os.execve(str(executable), arguments, environment)
    except OSError as error:
        fail(f"cannot exec {mode} executable: {error}")


def verify_attestation_command(
    attestation: pathlib.Path,
    source_root: pathlib.Path,
    source_commit: str,
    challenge: str,
    expect_mode: str,
) -> None:
    source_root = path_without_symlink(source_root, "source root")
    require(source_root.is_dir(), "source root is not a directory")
    expected = (
        source_root
        / pathlib.Path(*ARTIFACT_RELATIVE.parts)
        / (PACKAGE_ATTESTATION if expect_mode == "package" else VERIFIER_ATTESTATION)
    )
    supplied = (
        attestation if attestation.is_absolute() else pathlib.Path.cwd() / attestation
    )
    supplied = path_without_symlink(supplied, "runtime attestation")
    require(
        supplied == expected,
        "runtime attestation path differs from the fixed artifact path",
    )
    read_attestation(
        expected,
        source_root=source_root,
        source_commit=source_commit,
        challenge=challenge,
        expect_mode=expect_mode,
    )


def docker_output(
    docker: str,
    arguments: Sequence[str],
    label: str,
    *,
    check: bool = True,
    inherit_output: bool = False,
) -> bytes:
    try:
        if inherit_output:
            completed = subprocess.run([docker, *arguments], check=False)
            output = b""
        else:
            completed = subprocess.run(
                [docker, *arguments],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output = completed.stdout
            require(
                len(output) <= MAX_JSON_BYTES, f"{label} output exceeds its byte bound"
            )
        if check and completed.returncode != 0:
            detail = ""
            if not inherit_output:
                detail = completed.stderr[:4096].decode("utf-8", "replace").strip()
            fail(f"{label} failed with exit {completed.returncode}: {detail}")
        return output
    except OSError as error:
        fail(f"cannot run {label}: {error}")


def docker_json(docker: str, arguments: Sequence[str], label: str) -> dict[str, Any]:
    raw = docker_output(docker, [*arguments, "--format", "{{json .}}"], label)
    require(
        raw.endswith(b"\n") and raw.count(b"\n") == 1,
        f"{label} did not emit one JSON object",
    )
    value = strict_json(raw, label)
    require(isinstance(value, dict), f"{label} did not emit an object")
    return value


def mount_argument(record: dict[str, Any]) -> str:
    source = record["source"]
    require(isinstance(source, str) and source, "mount source is malformed")
    require(
        not any(character in source for character in ",\n\r"),
        "mount source contains a forbidden delimiter",
    )
    parts = [f"type={record['kind']}", f"src={source}", f"dst={record['destination']}"]
    if record["read_only"]:
        parts.append("readonly")
    if record["kind"] == "bind":
        parts.append("bind-propagation=rprivate")
    else:
        parts.append("volume-nocopy")
    return ",".join(parts)


def docker_create_arguments(
    *,
    uid: int,
    gid: int,
    mounts: list[dict[str, Any]],
    source_commit: str,
    challenge: str,
    mode: str,
) -> list[str]:
    command = [
        "scripts/c84-docker-runtime.py",
        "guest-package",
        "--host-preinspect",
        str(CONTAINER_PREINSPECT / HOST_PREINSPECT_FILENAME),
        "--source-commit",
        source_commit,
        "--challenge",
        challenge,
        "--mode",
        mode,
    ]
    arguments = [
        "create",
        "--pull",
        "never",
        "--platform",
        PLATFORM,
        "--network",
        "none",
        "--user",
        f"{uid}:{gid}",
        "--workdir",
        str(CONTAINER_SOURCE),
        "--entrypoint",
        "python3",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
    ]
    for key, value in sorted(strict_environment(source_commit, challenge).items()):
        arguments.extend(["--env", f"{key}={value}"])
    for record in mounts:
        arguments.extend(["--mount", mount_argument(record)])
    arguments.extend([IMAGE_REFERENCE, *command])
    return arguments


def validate_volume_inspect(value: Any, name: str) -> dict[str, Any]:
    require(isinstance(value, dict), "SDK volume inspect is not an object")
    require(value.get("Name") == name, "SDK volume name differs")
    require(value.get("Driver") == "local", "SDK volume driver is not local")
    require(value.get("Scope") == "local", "SDK volume scope is not local")
    require(
        "Options" in value and value["Options"] in (None, {}),
        "SDK volume has local-driver mount options",
    )
    require(
        "Labels" in value and value["Labels"] in (None, {}),
        "SDK volume has labels outside the closed contract",
    )
    require(
        isinstance(value.get("Mountpoint"), str)
        and value["Mountpoint"].startswith("/"),
        "SDK volume mountpoint is malformed",
    )
    return value


def check_host_source(
    source: pathlib.Path, source_commit: str, challenge: str
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, dict[str, Any]]:
    source = path_without_symlink(source, "source")
    require(source.is_dir(), "source is not a directory")
    target = path_without_symlink(source / "target", "source target")
    artifact_root = path_without_symlink(
        source / pathlib.Path(*ARTIFACT_RELATIVE.parts), "artifact root"
    )
    require(
        target.is_dir() and artifact_root.is_dir(),
        "source target/artifact root is not a directory",
    )
    git_config = path_without_symlink(
        source / "scripts/c84-docker.gitconfig", "Docker Git config"
    )
    expected_config = (
        b"[safe]\n"
        b"\tdirectory = /home/vibeos\n"
        b"\tdirectory = /home/vibeos/vendor/jitterentropy-rs\n"
        b"\tdirectory = /home/vibeos/vendor/sunset\n"
        b"\tdirectory = /home/work\n"
    )
    require(
        stable_regular_bytes(git_config, "Docker Git config", maximum=4096)
        == expected_config,
        "Docker Git config bytes differ",
    )
    mounted_runtime = path_without_symlink(
        source / "scripts/c84-docker-runtime.py", "mounted runtime script"
    )
    require(
        stable_regular_bytes(
            mounted_runtime, "mounted runtime script", maximum=MAX_TEXT_BYTES
        )
        == stable_regular_bytes(
            SCRIPT_PATH, "launcher runtime script", maximum=MAX_TEXT_BYTES
        ),
        "launcher and mounted runtime script bytes differ",
    )
    source_envelope = verify_source_materialization(source, source_commit, challenge)
    return source, target, git_config, source_envelope


def run_container(
    *,
    docker: str,
    mode: str,
    source: pathlib.Path,
    target: pathlib.Path,
    git_config: pathlib.Path,
    sdk_root: pathlib.Path | None,
    sdk_volume: str | None,
    sdk_volume_inspect: dict[str, Any] | None,
    source_commit: str,
    challenge: str,
    uid: int,
    gid: int,
) -> dict[str, Any]:
    container_id: str | None = None
    with tempfile.TemporaryDirectory(prefix=f"vibeos-c84-{mode}-") as temporary_text:
        host_directory = pathlib.Path(temporary_text).resolve(strict=True)
        mounts = mount_contract(
            source, target, git_config, host_directory, sdk_root, sdk_volume
        )
        create_argv = docker_create_arguments(
            uid=uid,
            gid=gid,
            mounts=mounts,
            source_commit=source_commit,
            challenge=challenge,
            mode=mode,
        )
        try:
            raw_id = docker_output(docker, create_argv, f"Docker create ({mode})")
            try:
                identifier_text = raw_id.decode("ascii")
            except UnicodeDecodeError:
                fail(f"Docker create ({mode}) returned a non-ASCII id")
            require(
                identifier_text.endswith("\n") and identifier_text.count("\n") == 1,
                f"Docker create ({mode}) id output differs",
            )
            container_id = identifier_text.strip()
            require(
                CONTAINER_ID.fullmatch(container_id) is not None,
                f"Docker create ({mode}) returned a malformed id",
            )
            pre = docker_json(
                docker, ["inspect", container_id], f"Docker preinspect ({mode})"
            )
            image = validate_image_inspect(
                docker_json(
                    docker,
                    ["image", "inspect", IMAGE_REFERENCE],
                    f"Docker image inspect ({mode})",
                )
            )
            content = host_preinspect_content(
                mode=mode,
                source_commit=source_commit,
                challenge=challenge,
                uid=uid,
                gid=gid,
                image=image,
                container=pre,
                mounts=mounts,
                sdk_volume_inspect=sdk_volume_inspect,
                create_argv=create_argv,
            )
            pre_root = content_addressed_root(PREINSPECT_SCHEMA, content)
            validate_host_preinspect(
                pre_root,
                source_commit=source_commit,
                challenge=challenge,
                expect_mode=mode,
            )
            pre_path = host_directory / HOST_PREINSPECT_FILENAME
            write_no_clobber(pre_path, pre_root, f"{mode} host preinspect")
            pre_identity = file_identity(pre_path, f"{mode} host preinspect")
            try:
                start_completed = subprocess.run(
                    [docker, "start", "--attach", container_id], check=False
                )
            except OSError as error:
                fail(f"cannot run Docker start ({mode}): {error}")
            require(
                start_completed.returncode == 0,
                f"Docker start ({mode}) failed with exit {start_completed.returncode}",
            )
            wait_raw = docker_output(
                docker, ["wait", container_id], f"Docker wait ({mode})"
            )
            try:
                wait_text = wait_raw.decode("ascii")
            except UnicodeDecodeError:
                fail(f"Docker wait ({mode}) returned non-ASCII output")
            require(wait_text == "0\n", f"Docker wait ({mode}) exit code differs")
            post = docker_json(
                docker, ["inspect", container_id], f"Docker postinspect ({mode})"
            )
            contract = pre_root["content"]["contract"]
            validate_container_inspect(
                post,
                contract,
                image,
                f"container postinspect ({mode})",
                phase="exited",
                expected_id=container_id,
            )
            require(
                pre_root["content"]["container_preinspect"] == pre,
                f"{mode} preinspect changed before recording",
            )
            attestation_path = (
                source
                / pathlib.Path(*ARTIFACT_RELATIVE.parts)
                / (PACKAGE_ATTESTATION if mode == "package" else VERIFIER_ATTESTATION)
            )
            attestation, attestation_identity = read_attestation(
                attestation_path,
                source_root=source,
                source_commit=source_commit,
                challenge=challenge,
                expect_mode=mode,
            )
            require(
                attestation["content"]["host_preinspect"] == pre_root,
                f"{mode} guest did not bind the host preinspect",
            )
            require(
                attestation["content"]["host_preinspect_identity"] == pre_identity,
                f"{mode} guest host-preinspect identity differs",
            )
            return {
                "attestation": attestation,
                "attestation_identity": attestation_identity,
                "container_id": container_id,
                "container_postinspect": post,
                "container_preinspect": pre,
                "host_preinspect": pre_root,
                "host_preinspect_identity": pre_identity,
                "operations": {
                    "create": create_argv,
                    "postinspect": ["inspect", container_id],
                    "preinspect": ["inspect", container_id],
                    "start": ["start", "--attach", container_id],
                    "wait": ["wait", container_id],
                },
                "wait_exit_code": 0,
            }
        finally:
            if container_id is not None:
                docker_output(
                    docker,
                    ["rm", "--force", container_id],
                    f"Docker cleanup ({mode})",
                    check=False,
                )


def path_identity(
    path: pathlib.Path,
    relative: str,
    label: str,
    *,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    identity = file_identity(path, label, tracker=tracker)
    return {"bytes": identity["bytes"], "path": relative, "sha256": identity["sha256"]}


def validate_path_identity(
    value: Any,
    path: pathlib.Path,
    relative: str,
    label: str,
    *,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    value = exact(value, {"bytes", "path", "sha256"}, label)
    require(value["path"] == relative, f"{label} path differs")
    identity_record({"bytes": value["bytes"], "sha256": value["sha256"]}, label)
    require(
        value == path_identity(path, relative, label, tracker=tracker),
        f"{label} live bytes differ",
    )
    return value


def read_semantic_envelope(
    path: pathlib.Path,
    schema: str,
    version: int,
    label: str,
    *,
    tracker: StabilityTracker | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = stable_regular_bytes(path, label, maximum=MAX_JSON_BYTES)
    if tracker is not None:
        tracker.observe(path, label)
    root = validate_content_addressed_root(
        strict_json(raw, label), schema, label, version=version
    )
    return root, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def contains_old_provenance(value: Any) -> bool:
    if isinstance(value, str):
        return (
            "operator-declared" in value
            or "runtime container identity not attested" in value
        )
    if isinstance(value, list):
        return any(contains_old_provenance(item) for item in value)
    if isinstance(value, dict):
        forbidden_keys = {"declared_container_digest", "container_digest_provenance"}
        return bool(set(value) & forbidden_keys) or any(
            contains_old_provenance(item) for item in value.values()
        )
    return False


def verify_source_materialization(
    source_root: pathlib.Path,
    source_commit: str,
    challenge: str,
    *,
    expected_root: dict[str, Any] | None = None,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    source_root = path_without_symlink(source_root, "source materialization root")
    before = load_source_envelope(
        source_root, source_commit, challenge, tracker=tracker
    )
    if expected_root is not None:
        require(before == expected_root, "source materialization root changed")
    materializer = path_without_symlink(
        source_root / "scripts/c84-source-materialization.py", "source materializer"
    )
    stable_regular_bytes(materializer, "source materializer", maximum=MAX_TEXT_BYTES)
    if tracker is not None:
        tracker.observe(materializer, "source materializer")
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(materializer),
                "verify",
                "--destination",
                str(source_root),
                "--source-commit",
                source_commit,
                "--challenge",
                challenge,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot run source materialization verifier: {error}")
    require(
        completed.returncode == 0,
        "source materialization verification failed: "
        + completed.stderr[:4096].decode("utf-8", "replace").strip(),
    )
    if tracker is not None:
        tracker.observe(materializer, "source materializer")
    after = load_source_envelope(source_root, source_commit, challenge, tracker=tracker)
    require(after == before, "source materialization changed during full verification")
    return after


def validate_utc_timestamps(value: Any, names: Sequence[str], label: str) -> None:
    value = exact(value, set(names), label)
    parsed: list[datetime.datetime] = []
    for name in names:
        timestamp = value[name]
        require(
            isinstance(timestamp, str) and timestamp.endswith("Z"),
            f"{label} {name} is not UTC",
        )
        try:
            parsed.append(datetime.datetime.fromisoformat(timestamp[:-1] + "+00:00"))
        except ValueError as error:
            fail(f"{label} {name} is invalid: {error}")
    require(parsed == sorted(parsed), f"{label} values are reversed")


def match_file_record(
    record: dict[str, Any],
    path: pathlib.Path,
    label: str,
    *,
    tracker: StabilityTracker | None,
) -> None:
    require(
        {"bytes": record["bytes"], "sha256": record["sha256"]}
        == file_identity(path, label, tracker=tracker),
        f"{label} live identity differs",
    )


def require_campaign_bytes(
    path: pathlib.Path,
    source_commit: str,
    challenge: str,
    label: str,
    *,
    tracker: StabilityTracker | None,
) -> None:
    needles = (source_commit.encode("ascii"), challenge.encode("ascii"))
    found = [False, False]
    overlap = max(map(len, needles)) - 1
    tail = b""
    try:
        before = path.lstat()
        require(
            stat.S_ISREG(before.st_mode)
            and not stat.S_ISLNK(before.st_mode)
            and before.st_nlink == 1
            and before.st_size > 0,
            f"{label} is not a single-link regular file",
        )
        with path.open("rb") as source:
            while chunk := source.read(4 * 1024 * 1024):
                window = tail + chunk
                found = [
                    seen or needle in window
                    for seen, needle in zip(found, needles, strict=True)
                ]
                tail = window[-overlap:]
        after = path.lstat()
    except OSError as error:
        fail(f"cannot scan {label}: {error}")
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"{label} changed while scanning",
    )
    require(all(found), f"{label} does not embed source/challenge")
    if tracker is not None:
        tracker.observe(path, label)


def validate_build_envelope(
    root: dict[str, Any],
    source_envelope: dict[str, Any],
    source_commit: str,
    challenge: str,
    *,
    source_root: pathlib.Path,
    artifact_root: pathlib.Path,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    root = validate_content_addressed_root(
        root, BUILD_SCHEMA, "build envelope", version=2
    )
    content = exact(
        root["content"],
        {
            "artifacts",
            "challenge",
            "command",
            "environment",
            "objcopy_command",
            "objcopy_environment",
            "platform",
            "run_id",
            "source",
            "source_commit",
            "timestamps_utc",
            "toolchain",
            "tools",
        },
        "build content",
    )
    require(
        content["platform"] == "milkv-duo-cv1800b"
        and content["source_commit"] == source_commit
        and content["challenge"] == challenge,
        "build campaign identity differs",
    )
    source = exact(
        content["source"], {"head", "materialization", "root"}, "build source"
    )
    require(
        source
        == {
            "head": source_commit,
            "materialization": source_envelope,
            "root": ".",
        },
        "build frozen-source proof differs",
    )

    expected_stage = pathlib.PurePosixPath(
        f"target/.milkv-duo-wasm-aot-profile.stage.{source_commit}.{challenge}"
    )
    expected_artifact_paths = {
        "kernel_elf": str(expected_stage / FORMAL_ARTIFACTS["kernel_elf"]),
        "kernel_binary": str(expected_stage / FORMAL_ARTIFACTS["kernel_binary"]),
    }
    artifacts = exact(
        content["artifacts"], set(expected_artifact_paths), "build artifacts"
    )
    artifact_records: dict[str, dict[str, Any]] = {}
    for role, logical_path in expected_artifact_paths.items():
        record = file_record(
            artifacts[role], f"build artifact {role}", expected_path=logical_path
        )
        live_path = artifact_root / FORMAL_ARTIFACTS[role]
        match_file_record(record, live_path, f"build artifact {role}", tracker=tracker)
        require_campaign_bytes(
            live_path,
            source_commit,
            challenge,
            f"build artifact {role}",
            tracker=tracker,
        )
        artifact_records[role] = record

    tools = exact(content["tools"], set(BUILD_TOOL_PATHS), "build tools")
    tool_records: dict[str, dict[str, Any]] = {}
    for role, logical_path in BUILD_TOOL_PATHS.items():
        record = file_record(
            tools[role], f"build tool {role}", expected_path=logical_path
        )
        match_file_record(
            record,
            source_root / pathlib.Path(*pathlib.PurePosixPath(logical_path).parts),
            f"build tool {role}",
            tracker=tracker,
        )
        tool_records[role] = record
    toolchain = exact(
        content["toolchain"],
        {
            "cargo",
            "channel",
            "linker",
            "provenance",
            "rust_objcopy",
            "rustc",
            "rustc_verbose",
            "rustdoc",
            "rustup",
        },
        "build toolchain",
    )
    require(
        toolchain["provenance"]
        == "build-runner-self-measured; package cross-platform live rehash unavailable",
        "build toolchain provenance differs",
    )
    for role in ("rustup", "cargo", "rustc", "rustdoc", "rust_objcopy", "linker"):
        record = file_record(toolchain[role], f"build toolchain {role}")
        require(
            pathlib.PurePath(record["path"]).is_absolute(),
            f"build toolchain {role} path is not absolute",
        )
    contract_raw = stable_regular_bytes(
        source_root / BUILD_TOOL_PATHS["toolchain_contract"],
        "toolchain contract",
        maximum=1_048_576,
    )
    try:
        contract_text = contract_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"toolchain contract is not UTF-8: {error}")
    channel_match = re.search(r'^channel = "([^"]+)"$', contract_text, re.MULTILINE)
    rustc_match = re.search(r"^# rustc (.+)$", contract_text, re.MULTILINE)
    commit_match = re.search(
        r"^# rustc-commit: ([0-9a-f]{40})$", contract_text, re.MULTILINE
    )
    require(
        channel_match is not None
        and rustc_match is not None
        and commit_match is not None,
        "toolchain contract is incomplete",
    )
    verbose_lines = (
        toolchain["rustc_verbose"].splitlines()
        if isinstance(toolchain["rustc_verbose"], str)
        else []
    )
    verbose_fields = {
        key: value
        for line in verbose_lines[1:]
        if ": " in line
        for key, value in [line.split(": ", 1)]
    }
    require(
        toolchain["channel"] == channel_match.group(1)
        and bool(verbose_lines)
        and verbose_lines[0] == f"rustc {rustc_match.group(1)}"
        and f"commit-hash: {commit_match.group(1)}" in verbose_lines
        and isinstance(verbose_fields.get("host"), str)
        and bool(verbose_fields["host"]),
        "build toolchain pin differs",
    )
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
    require(
        all(
            pathlib.PurePath(toolchain[role]["path"]) == expected
            for role, expected in expected_tool_paths.items()
        ),
        "build toolchain executable paths differ",
    )
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
    require(content["command"] == expected_command, "build command differs")
    require(
        content["objcopy_command"]
        == [
            toolchain["rust_objcopy"]["path"],
            "-O",
            "binary",
            artifact_records["kernel_elf"]["path"],
            artifact_records["kernel_binary"]["path"],
        ],
        "build objcopy command differs",
    )
    objcopy = exact(
        content["objcopy_environment"],
        {"allowed_keys", "mode", "values"},
        "build objcopy environment",
    )
    require(
        objcopy["mode"] == "env -i"
        and objcopy["allowed_keys"]
        in (["LC_ALL", "PATH", "TZ"], ["DYLD_LIBRARY_PATH", "LC_ALL", "PATH", "TZ"]),
        "build objcopy environment allowlist differs",
    )
    objcopy_values = exact(
        objcopy["values"], set(objcopy["allowed_keys"]), "build objcopy values"
    )
    require(
        objcopy_values.get("LC_ALL") == "C"
        and objcopy_values.get("PATH") == "/usr/bin:/bin"
        and objcopy_values.get("TZ") == "UTC",
        "build objcopy environment values differ",
    )
    if "DYLD_LIBRARY_PATH" in objcopy_values:
        require(
            isinstance(objcopy_values["DYLD_LIBRARY_PATH"], str)
            and objcopy_values["DYLD_LIBRARY_PATH"]
            == str(pathlib.PurePath(toolchain["rustc"]["path"]).parent.parent / "lib"),
            "build objcopy DYLD_LIBRARY_PATH differs",
        )

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
    environment = exact(
        content["environment"],
        {"allowed_keys", "cargo_home_isolation", "mode", "values"},
        "build environment",
    )
    require(
        environment["mode"] == "env -i" and environment["allowed_keys"] == allowed_keys,
        "build environment allowlist differs",
    )
    values = exact(environment["values"], set(allowed_keys), "build environment values")
    require(
        values["CARGO_HOME"] == "<isolated-cargo-home>"
        and values["HOME"] == "<isolated-cargo-home>/home"
        and values["TMPDIR"] == "<isolated-cargo-home>/tmp"
        and values["CARGO_INCREMENTAL"] == "0"
        and values["CARGO_NET_OFFLINE"] == "true"
        and values["LC_ALL"] == "C"
        and values["TZ"] == "UTC"
        and values["VIBEOS_C84_SOURCE_COMMIT"] == source_commit
        and values["VIBEOS_C84_CHALLENGE"] == challenge
        and values["RUSTC"] == toolchain["rustc"]["path"]
        and values["RUSTDOC"] == toolchain["rustdoc"]["path"]
        and isinstance(values["SOURCE_DATE_EPOCH"], str)
        and values["SOURCE_DATE_EPOCH"].isdigit()
        and isinstance(values["RUSTUP_HOME"], str)
        and pathlib.PurePath(values["RUSTUP_HOME"]).is_absolute(),
        "build environment values differ",
    )
    path_parts = values["PATH"].split(":") if isinstance(values["PATH"], str) else []
    require(
        len(path_parts) == 5
        and pathlib.PurePath(path_parts[0]).is_absolute()
        and pathlib.PurePath(path_parts[0]).name == "closed-bin"
        and pathlib.PurePath(path_parts[0]).parent.name.startswith(
            "vibeos-c84-cargo-home."
        )
        and path_parts[1:] == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
        "build PATH differs",
    )
    # The AOT kernel is built on the independently materialized host tree before
    # Docker is launched.  The runtime contract later binds that exact host
    # source at CONTAINER_SOURCE, so the recorded Cargo target must retain the
    # host path rather than being rewritten to the container destination.
    expected_target = (
        pathlib.PurePath(source_root)
        / "target"
        / "c84-milkv-build"
        / source_commit
        / challenge
    )
    target_path = pathlib.PurePath(values["CARGO_TARGET_DIR"])
    require(
        target_path == expected_target,
        "build target directory differs",
    )
    isolation = exact(
        environment["cargo_home_isolation"],
        {
            "ambient_config_loaded",
            "cache_source",
            "git_cache_symlinked",
            "registry_cache_symlinked",
            "temporary",
        },
        "build cargo-home isolation",
    )
    require(
        isolation["ambient_config_loaded"] is False
        and isolation["temporary"] is True
        and type(isolation["registry_cache_symlinked"]) is bool
        and type(isolation["git_cache_symlinked"]) is bool
        and isinstance(isolation["cache_source"], str)
        and pathlib.PurePath(isolation["cache_source"]).is_absolute(),
        "build cargo-home isolation differs",
    )

    workload_raw = stable_regular_bytes(
        source_root / BUILD_TOOL_PATHS["workload_manifest"],
        "run-id workload manifest",
        maximum=MAX_TEXT_BYTES,
    )
    try:
        workload = strict_json(workload_raw, "run-id workload manifest")
        fixture = workload["fixture"]
        fields = [
            "vibeos.c84.aot-decision.run-id.v1",
            source_commit,
            challenge,
            fixture["artifact"]["sha256"],
            fixture["input"]["sha256"],
            fixture["output"]["sha256"],
            tool_records["workload_manifest"]["sha256"],
            tool_records["transcript_schema"]["sha256"],
        ]
    except (KeyError, TypeError) as error:
        fail(f"run-id workload fields are missing: {error}")
    require(
        all(isinstance(item, str) and "\0" not in item for item in fields),
        "run-id fields are malformed",
    )
    try:
        expected_run_id = hashlib.sha256("\0".join(fields).encode("ascii")).hexdigest()
    except UnicodeEncodeError as error:
        fail(f"run-id field is not ASCII: {error}")
    require(content["run_id"] == expected_run_id, "build run id differs")
    validate_utc_timestamps(
        content["timestamps_utc"],
        ("build_started", "build_completed", "envelope_closed"),
        "build timestamps",
    )
    require(
        not contains_old_provenance(root),
        "build envelope contains old operator-declared provenance",
    )
    return root


def validate_package_envelope(
    root: dict[str, Any],
    *,
    package_attestation: dict[str, Any],
    source_envelope: dict[str, Any],
    build_root: dict[str, Any],
    build_identity: dict[str, Any],
    image_id: str,
    source_commit: str,
    challenge: str,
    source_root: pathlib.Path,
    artifact_root: pathlib.Path,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    root = validate_content_addressed_root(
        root, PACKAGE_SCHEMA, "package envelope", version=2
    )
    content = exact(
        root["content"],
        {
            "artifacts",
            "build",
            "challenge",
            "command",
            "environment",
            "platform",
            "run_id",
            "runtime_attestation",
            "sdk",
            "source",
            "source_commit",
            "timestamps_utc",
            "tools",
            "verifier",
        },
        "package content",
    )
    require(
        content["platform"] == "milkv-duo-cv1800b"
        and content["source_commit"] == source_commit
        and content["challenge"] == challenge,
        "package campaign identity differs",
    )
    require(
        isinstance(content["run_id"], str)
        and HEX64.fullmatch(content["run_id"]) is not None
        and content["run_id"] == build_root["content"]["run_id"],
        "package/build run id differs",
    )
    require(
        content["runtime_attestation"] == package_attestation,
        "package envelope runtime attestation differs",
    )
    source = exact(
        content["source"], {"head", "materialization", "root"}, "package source"
    )
    require(
        source
        == {
            "head": source_commit,
            "materialization": source_envelope,
            "root": str(CONTAINER_SOURCE),
        },
        "package frozen-source proof differs",
    )
    sdk = exact(
        content.get("sdk"),
        {
            "commit",
            "commit_provenance",
            "image_digest",
            "image_id",
            "platform",
            "root",
            "runtime_provenance",
            "status_policy",
            "worktree_clean",
        },
        "package SDK",
    )
    require(
        sdk
        == {
            "commit": SDK_COMMIT,
            "commit_provenance": "host-observed read-only SDK mount; in-container Git HEAD and clean worktree verified",
            "image_digest": IMAGE_DIGEST,
            "image_id": image_id,
            "platform": PLATFORM,
            "root": str(CONTAINER_SDK),
            "runtime_provenance": RUNTIME_PROVENANCE,
            "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
            "worktree_clean": True,
        },
        "package SDK custody differs",
    )
    build = exact(
        content.get("build"), {"content_sha256", "envelope"}, "package build reference"
    )
    require(
        build["content_sha256"] == build_root["content_sha256"],
        "package build content reference differs",
    )
    envelope_record = file_record(
        build["envelope"],
        "package build envelope",
        expected_path=str(
            CONTAINER_SOURCE / ARTIFACT_RELATIVE / FORMAL_ARTIFACTS["build_envelope"]
        ),
    )
    require(
        {"bytes": envelope_record["bytes"], "sha256": envelope_record["sha256"]}
        == build_identity,
        "package build envelope live identity differs",
    )

    require(
        content["command"]
        == ["scripts/package-milkv-duo-sdk.sh", "--wasm-aot-profile", "<sdk-root>"],
        "package command differs",
    )
    environment = exact(
        content["environment"],
        {"fit_tools", "genimage", "image_verifier"},
        "package environment",
    )
    environment_keys = {
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
    environment_values: dict[str, dict[str, Any]] = {}
    for name, keys in environment_keys.items():
        record = exact(
            environment[name],
            {"allowed_keys", "mode", "values"},
            f"package environment {name}",
        )
        require(
            record["mode"] == "env -i" and record["allowed_keys"] == keys,
            f"package environment {name} allowlist differs",
        )
        environment_values[name] = exact(
            record["values"], set(keys), f"package environment {name} values"
        )
    require(
        environment_values["fit_tools"]
        == {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
        "package FIT environment differs",
    )

    artifacts = exact(
        content["artifacts"], set(PACKAGE_ARTIFACT_PATHS), "package artifacts"
    )
    artifact_records: dict[str, dict[str, Any]] = {}
    live_artifact_roles = {
        "kernel_elf": "kernel_elf",
        "kernel_binary": "kernel_binary",
        "packaged_fit_source": "packaged_fit_source",
        "packaged_dtb": "packaged_dtb",
        "fit_boot_sd": "boot_sd",
        "full_sd_image": "full_sd_image",
    }
    for role, logical_path in PACKAGE_ARTIFACT_PATHS.items():
        record = file_record(
            artifacts[role], f"package artifact {role}", expected_path=logical_path
        )
        artifact_records[role] = record
        formal_role = live_artifact_roles.get(role)
        if formal_role is not None:
            live_path = artifact_root / FORMAL_ARTIFACTS[formal_role]
            match_file_record(
                record, live_path, f"package artifact {role}", tracker=tracker
            )
            if role in {
                "kernel_elf",
                "kernel_binary",
                "fit_boot_sd",
                "full_sd_image",
            }:
                require_campaign_bytes(
                    live_path,
                    source_commit,
                    challenge,
                    f"package artifact {role}",
                    tracker=tracker,
                )
    build_artifacts = build_root["content"]["artifacts"]
    for role in ("kernel_elf", "kernel_binary"):
        require(
            {
                "bytes": artifact_records[role]["bytes"],
                "sha256": artifact_records[role]["sha256"],
            }
            == {
                "bytes": build_artifacts[role]["bytes"],
                "sha256": build_artifacts[role]["sha256"],
            },
            f"package/build artifact {role} differs",
        )

    expected_tool_roles = (
        set(PACKAGE_SOURCE_TOOL_PATHS)
        | set(PACKAGE_SDK_TOOL_PATHS)
        | set(PACKAGE_VERIFIER_TOOL_BASENAMES)
        | {"sdk_genimage"}
    )
    tools = exact(content["tools"], expected_tool_roles, "package tools")
    tool_records: dict[str, dict[str, Any]] = {}
    for role, relative in PACKAGE_SOURCE_TOOL_PATHS.items():
        logical_path = str(CONTAINER_SOURCE / pathlib.PurePosixPath(relative))
        record = file_record(
            tools[role], f"package tool {role}", expected_path=logical_path
        )
        live_path = source_root / pathlib.Path(*pathlib.PurePosixPath(relative).parts)
        match_file_record(record, live_path, f"package tool {role}", tracker=tracker)
        if role == "docker_runtime_script":
            require(
                {"bytes": record["bytes"], "sha256": record["sha256"]}
                == file_identity(
                    SCRIPT_PATH, "executing Docker runtime", tracker=tracker
                ),
                "package Docker runtime differs from executing verifier",
            )
        tool_records[role] = record
    for role, logical_path in PACKAGE_SDK_TOOL_PATHS.items():
        tool_records[role] = file_record(
            tools[role], f"package tool {role}", expected_path=logical_path
        )
    genimage_record = file_record(tools["sdk_genimage"], "package tool sdk_genimage")
    require(
        genimage_record["path"] in PACKAGE_GENIMAGE_PATHS,
        "package SDK genimage path differs",
    )
    tool_records["sdk_genimage"] = genimage_record
    allowed_tool_parents = set(RUNTIME_PATH.split(":"))
    for role, basenames in PACKAGE_VERIFIER_TOOL_BASENAMES.items():
        record = file_record(tools[role], f"package tool {role}")
        pure = pathlib.PurePosixPath(record["path"])
        basename_ok = pure.name in basenames
        if role == "verifier_python3":
            basename_ok = re.fullmatch(r"python3(?:\.[0-9]+)?", pure.name) is not None
        require(
            pure.is_absolute()
            and str(pure.parent) in allowed_tool_parents
            and basename_ok,
            f"package verifier tool {role} path differs",
        )
        tool_records[role] = record
    require(
        tool_records["verifier_mdir"] == tool_records["verifier_mcopy"],
        "package mdir/mcopy canonical mtools identity differs",
    )

    gen_values = environment_values["genimage"]
    genimage_path = pathlib.PurePosixPath(genimage_record["path"])
    require(
        gen_values
        == {
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(genimage_path.parent.parent / "lib"),
            "PATH": f"{genimage_path.parent}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TZ": "UTC",
        },
        "package genimage environment differs",
    )
    require(
        environment_values["image_verifier"]
        == {
            "GIT_CONFIG_GLOBAL": str(CONTAINER_GIT_CONFIG),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "PATH": RUNTIME_PATH,
            "TZ": "UTC",
            "VIBEOS_C84_CHALLENGE": challenge,
            "VIBEOS_C84_SDK_CONTAINER_DIGEST": IMAGE_DIGEST,
            "VIBEOS_C84_SOURCE_COMMIT": source_commit,
        },
        "package image-verifier environment differs",
    )

    verifier = exact(
        content["verifier"],
        {
            "audit_log",
            "exact_pass_marker",
            "exit_code",
            "invocation",
            "report",
            "report_sha256",
            "status",
        },
        "package verifier",
    )
    require(
        verifier["status"] == "PASS"
        and type(verifier["exit_code"]) is int
        and verifier["exit_code"] == 0
        and verifier["exact_pass_marker"] == IMAGE_VERIFIER_PASS
        and verifier["invocation"]
        == [
            "scripts/verify-milkv-duo-image.sh",
            "--wasm-aot-profile",
            "--package-preflight",
            "--artifact-root=<staging-artifact-root>",
            "<sdk-root>",
        ],
        "package verifier contract differs",
    )
    file_record(
        verifier["audit_log"],
        "package verifier audit",
        expected_path=str(
            CONTAINER_SOURCE
            / ARTIFACT_RELATIVE
            / FORMAL_ARTIFACTS["image_verifier_audit"]
        ),
    )
    report = exact(
        verifier["report"],
        {
            "artifacts",
            "challenge",
            "runtime_attestation",
            "schema",
            "source_commit",
            "source_materialization",
            "tools",
            "version",
        },
        "package image audit report",
    )
    require(
        report["schema"] == IMAGE_AUDIT_SCHEMA
        and type(report["version"]) is int
        and report["version"] == 2
        and report["source_commit"] == source_commit
        and report["challenge"] == challenge
        and report["source_materialization"] == source_envelope
        and report["runtime_attestation"] == package_attestation,
        "package image audit report identity differs",
    )
    audit_artifact_roles = {
        "fit_boot_sd",
        "fit_source",
        "full_sd_image",
        "kernel_binary",
        "packaged_dtb",
        "sdk_dtb",
        "sdk_fip",
    }
    audit_tool_roles = {
        "cmp",
        "docker_runtime_script",
        "fdtget",
        "git_config",
        "mcopy",
        "mdir",
        "python3",
        "sha256sum",
        "source_materializer_script",
        "sdk_dumpimage",
        "sdk_mkimage",
        "tr",
    }
    report_artifacts = exact(
        report["artifacts"], audit_artifact_roles, "package image audit artifacts"
    )
    report_tools = exact(report["tools"], audit_tool_roles, "package image audit tools")
    for role, record in report_artifacts.items():
        measurement_record(record, f"package image audit artifact {role}")
    for role, record in report_tools.items():
        measurement_record(record, f"package image audit tool {role}")
    report_raw = canonical_json(report)
    require(
        isinstance(verifier["report_sha256"], str)
        and HEX64.fullmatch(verifier["report_sha256"]) is not None
        and verifier["report_sha256"] == hashlib.sha256(report_raw).hexdigest(),
        "package image audit report address differs",
    )
    validate_utc_timestamps(
        content["timestamps_utc"],
        ("packaging_started", "image_verified", "envelope_closed"),
        "package timestamps",
    )
    require(
        not contains_old_provenance(root),
        "package envelope contains old operator-declared provenance",
    )
    return root


def image_audit_transcript_has_failure(lines: list[str]) -> bool:
    return (
        re.search(
            r"\b(?:panic|fatal|fail|failed|failure)\b",
            "\n".join(lines[:-2]),
            re.IGNORECASE,
        )
        is not None
    )


def package_records(
    artifact_root: pathlib.Path,
    package_attestation: dict[str, Any],
    source_envelope: dict[str, Any],
    image_id: str,
    source_commit: str,
    challenge: str,
    *,
    source_root: pathlib.Path,
    tracker: StabilityTracker | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    build_path = artifact_root / FORMAL_ARTIFACTS["build_envelope"]
    package_path = artifact_root / FORMAL_ARTIFACTS["package_envelope"]
    audit_path = artifact_root / FORMAL_ARTIFACTS["image_verifier_audit"]
    build_root, build_identity = read_semantic_envelope(
        build_path, BUILD_SCHEMA, 2, "build envelope", tracker=tracker
    )
    validate_build_envelope(
        build_root,
        source_envelope,
        source_commit,
        challenge,
        source_root=source_root,
        artifact_root=artifact_root,
        tracker=tracker,
    )
    package_root, package_identity = read_semantic_envelope(
        package_path, PACKAGE_SCHEMA, 2, "package envelope", tracker=tracker
    )
    validate_package_envelope(
        package_root,
        package_attestation=package_attestation,
        source_envelope=source_envelope,
        build_root=build_root,
        build_identity=build_identity,
        image_id=image_id,
        source_commit=source_commit,
        challenge=challenge,
        source_root=source_root,
        artifact_root=artifact_root,
        tracker=tracker,
    )
    build_reference = package_root["content"]["build"]["envelope"]
    require(
        build_reference["bytes"] == build_identity["bytes"]
        and build_reference["sha256"] == build_identity["sha256"]
        and build_reference["path"]
        == str(CONTAINER_SOURCE / ARTIFACT_RELATIVE / build_path.name),
        "package build envelope file identity differs",
    )
    audit_identity = file_identity(audit_path, "image verifier audit", tracker=tracker)
    audit_raw = stable_regular_bytes(
        audit_path, "image verifier audit", maximum=MAX_JSON_BYTES
    )
    try:
        audit_text = audit_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"image verifier audit is not UTF-8: {error}")
    verifier = package_root["content"]["verifier"]
    lines = audit_text.splitlines()
    require(
        audit_text.endswith(IMAGE_VERIFIER_PASS + "\n")
        and len(lines) >= 2
        and lines[-1] == IMAGE_VERIFIER_PASS
        and audit_text.count(IMAGE_VERIFIER_PASS) == 1
        and audit_text.count(f'"schema":"{IMAGE_AUDIT_SCHEMA}"') == 1
        and not image_audit_transcript_has_failure(lines),
        "image verifier audit terminal/report framing differs",
    )
    report_line = lines[-2]
    report = strict_json(report_line.encode("utf-8"), "image verifier audit report")
    report = exact(
        report,
        {
            "artifacts",
            "challenge",
            "runtime_attestation",
            "schema",
            "source_commit",
            "source_materialization",
            "tools",
            "version",
        },
        "image verifier audit report",
    )
    require(
        report["schema"] == IMAGE_AUDIT_SCHEMA
        and type(report["version"]) is int
        and report["version"] == 2
        and report["source_commit"] == source_commit
        and report["challenge"] == challenge,
        "image verifier audit report identity differs",
    )
    require(
        canonical_json(report).decode("utf-8") == report_line,
        "image verifier audit report is not canonical JSON",
    )
    require(
        report["source_materialization"] == source_envelope,
        "image verifier audit source materialization differs",
    )
    require(
        report["runtime_attestation"] == package_attestation,
        "image verifier audit runtime attestation differs",
    )
    require(
        verifier["report"] == report,
        "package embedded image verifier report differs",
    )
    require(
        verifier["report_sha256"]
        == hashlib.sha256(report_line.encode("utf-8")).hexdigest(),
        "package image verifier report content address differs",
    )
    audit_record = verifier["audit_log"]
    require(
        audit_record["bytes"] == audit_identity["bytes"]
        and audit_record["sha256"] == audit_identity["sha256"]
        and audit_record["path"]
        == str(CONTAINER_SOURCE / ARTIFACT_RELATIVE / audit_path.name),
        "package image verifier audit identity differs",
    )
    published = package_root["content"]["artifacts"]
    role_to_name = {
        "kernel_elf": FORMAL_ARTIFACTS["kernel_elf"],
        "kernel_binary": FORMAL_ARTIFACTS["kernel_binary"],
        "packaged_fit_source": FORMAL_ARTIFACTS["packaged_fit_source"],
        "packaged_dtb": FORMAL_ARTIFACTS["packaged_dtb"],
        "fit_boot_sd": FORMAL_ARTIFACTS["boot_sd"],
        "full_sd_image": FORMAL_ARTIFACTS["full_sd_image"],
    }
    for role, filename in role_to_name.items():
        record = published.get(role)
        identity = file_identity(
            artifact_root / filename, f"package artifact {role}", tracker=tracker
        )
        require(
            record["bytes"] == identity["bytes"]
            and record["sha256"] == identity["sha256"]
            and record["path"] == PACKAGE_ARTIFACT_PATHS[role],
            f"package artifact {role} identity differs",
        )
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
    report_artifacts = exact(
        report["artifacts"], set(report_artifact_roles), "image audit artifacts"
    )
    package_tools = package_root["content"]["tools"]
    report_tools = exact(report["tools"], set(report_tool_roles), "image audit tools")
    for report_role, package_role in report_artifact_roles.items():
        record = published.get(package_role)
        require(isinstance(record, dict), f"package artifact {package_role} is missing")
        expected = identity_record(
            {"bytes": record.get("bytes"), "sha256": record.get("sha256")},
            f"package artifact {package_role}",
        )
        require(
            measurement_record(
                report_artifacts[report_role], f"image audit artifact {report_role}"
            )
            == expected,
            f"image audit artifact {report_role} differs",
        )
    for report_role, package_role in report_tool_roles.items():
        record = package_tools.get(package_role)
        require(isinstance(record, dict), f"package tool {package_role} is missing")
        expected = identity_record(
            {"bytes": record.get("bytes"), "sha256": record.get("sha256")},
            f"package tool {package_role}",
        )
        require(
            measurement_record(
                report_tools[report_role], f"image audit tool {report_role}"
            )
            == expected,
            f"image audit tool {report_role} differs",
        )
    return (
        {
            "bytes": build_identity["bytes"],
            "path": FORMAL_ARTIFACTS["build_envelope"],
            "sha256": build_identity["sha256"],
        },
        {
            "bytes": package_identity["bytes"],
            "path": FORMAL_ARTIFACTS["package_envelope"],
            "sha256": package_identity["sha256"],
        },
        {
            "bytes": audit_identity["bytes"],
            "path": FORMAL_ARTIFACTS["image_verifier_audit"],
            "sha256": audit_identity["sha256"],
        },
    )


def validate_run_record(
    value: Any,
    *,
    source_root: pathlib.Path,
    source_commit: str,
    challenge: str,
    mode: str,
    image: dict[str, Any],
) -> dict[str, Any]:
    value = exact(
        value,
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
        f"{mode} run",
    )
    container_id = value["container_id"]
    require(
        isinstance(container_id, str)
        and CONTAINER_ID.fullmatch(container_id) is not None,
        f"{mode} container id is malformed",
    )
    pre_root = validate_host_preinspect(
        value["host_preinspect"],
        source_commit=source_commit,
        challenge=challenge,
        expect_mode=mode,
    )
    require(
        pre_root["content"]["image_inspect"] == image,
        f"{mode} run image inspect differs",
    )
    require(
        value["container_preinspect"] == pre_root["content"]["container_preinspect"],
        f"{mode} run preinspect differs",
    )
    pre_raw = canonical_json(pre_root) + b"\n"
    require(
        value["host_preinspect_identity"]
        == {"bytes": len(pre_raw), "sha256": hashlib.sha256(pre_raw).hexdigest()},
        f"{mode} host preinspect identity differs",
    )
    contract = pre_root["content"]["contract"]
    validate_container_inspect(
        value["container_preinspect"],
        contract,
        image,
        f"{mode} preinspect",
        phase="created",
        expected_id=container_id,
    )
    validate_container_inspect(
        value["container_postinspect"],
        contract,
        image,
        f"{mode} postinspect",
        phase="exited",
        expected_id=container_id,
    )
    require(
        type(value["wait_exit_code"]) is int and value["wait_exit_code"] == 0,
        f"{mode} wait exit differs",
    )
    attestation = validate_attestation_root(
        value["attestation"],
        source_root=source_root,
        source_commit=source_commit,
        challenge=challenge,
        expect_mode=mode,
    )
    require(
        attestation["content"]["host_preinspect"] == pre_root,
        f"{mode} attestation host preinspect differs",
    )
    attestation_raw = canonical_json(attestation) + b"\n"
    require(
        value["attestation_identity"]
        == {
            "bytes": len(attestation_raw),
            "sha256": hashlib.sha256(attestation_raw).hexdigest(),
        },
        f"{mode} attestation identity differs",
    )
    operations = exact(
        value["operations"],
        {"create", "postinspect", "preinspect", "start", "wait"},
        f"{mode} operations",
    )
    require(
        operations["create"] == contract["create_argv"],
        f"{mode} create operation differs",
    )
    require(
        operations["preinspect"] == ["inspect", container_id]
        and operations["postinspect"] == ["inspect", container_id],
        f"{mode} inspect operations differ",
    )
    require(
        operations["start"] == ["start", "--attach", container_id]
        and operations["wait"] == ["wait", container_id],
        f"{mode} start/wait operations differ",
    )
    return value


def image_closure_record(image: dict[str, Any]) -> dict[str, Any]:
    return {
        "architecture": image["Architecture"],
        "descriptor": image["Descriptor"],
        "id": image["Id"],
        "inspect": image,
        "os": image["Os"],
        "repo_digest": IMAGE_REFERENCE,
        "reference": IMAGE_REFERENCE,
    }


def validate_closure_root(
    root: Any,
    *,
    closure_path: pathlib.Path,
    source_commit: str,
    challenge: str,
    tracker: StabilityTracker | None = None,
) -> dict[str, Any]:
    root = validate_content_addressed_root(root, CLOSURE_SCHEMA, "runtime closure")
    content = exact(
        root["content"],
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
        "runtime closure content",
    )
    require(
        content["capability"] == CAPABILITY
        and content["source_commit"] == source_commit
        and content["challenge"] == challenge
        and content["platform"] == PLATFORM,
        "runtime closure campaign identity differs",
    )
    artifact_root = path_without_symlink(closure_path.parent, "closure artifact root")
    require(closure_path.name == CLOSURE_FILENAME, "runtime closure filename differs")
    inferred_source = artifact_root.parent.parent
    inferred_source = path_without_symlink(inferred_source, "closure source root")
    require(
        artifact_root
        == path_without_symlink(
            inferred_source / pathlib.Path(*ARTIFACT_RELATIVE.parts),
            "formal closure artifact root",
        ),
        "runtime closure artifact root differs",
    )
    source = exact(
        content["source"], {"materialization_content_sha256", "root"}, "closure source"
    )
    require(source["root"] == str(inferred_source), "closure source root differs")
    source_envelope = verify_source_materialization(
        inferred_source,
        source_commit,
        challenge,
        tracker=tracker,
    )
    require(
        source["materialization_content_sha256"] == source_envelope["content_sha256"],
        "closure source materialization differs",
    )
    image_record = exact(
        content["image"],
        {
            "architecture",
            "descriptor",
            "id",
            "inspect",
            "os",
            "reference",
            "repo_digest",
        },
        "closure image",
    )
    image = validate_image_inspect(image_record["inspect"])
    require(
        image_record == image_closure_record(image), "closure image binding differs"
    )
    runs = exact(content["runs"], {"package", "verifier"}, "closure runs")
    package_run = validate_run_record(
        runs["package"],
        source_root=inferred_source,
        source_commit=source_commit,
        challenge=challenge,
        mode="package",
        image=image,
    )
    verifier_run = validate_run_record(
        runs["verifier"],
        source_root=inferred_source,
        source_commit=source_commit,
        challenge=challenge,
        mode="verify",
        image=image,
    )
    require(
        package_run["container_id"] != verifier_run["container_id"],
        "package and verifier reused one container",
    )
    package_contract = package_run["host_preinspect"]["content"]["contract"]
    verifier_contract = verifier_run["host_preinspect"]["content"]["contract"]
    require(
        (
            package_contract["uid"],
            package_contract["gid"],
            package_contract["supplementary_groups"],
        )
        == (
            verifier_contract["uid"],
            verifier_contract["gid"],
            verifier_contract["supplementary_groups"],
        ),
        "package/verifier credentials differ",
    )
    require(
        package_run["host_preinspect"]["content"]["sdk_volume_inspect"]
        == verifier_run["host_preinspect"]["content"]["sdk_volume_inspect"],
        "package/verifier SDK volume inspect differs",
    )
    sdk_mount = exact(
        content["sdk_mount"],
        {"destination", "kind", "read_only", "source"},
        "closure SDK mount",
    )
    require(
        sdk_mount["destination"] == str(CONTAINER_SDK)
        and sdk_mount["read_only"] is True
        and sdk_mount["kind"] in {"bind", "volume"},
        "closure SDK mount differs",
    )
    for run in (package_run, verifier_run):
        contract_mounts = run["host_preinspect"]["content"]["contract"]["mounts"]
        mount_map = validate_mount_contract_shape(contract_mounts)
        require(
            mount_map[str(CONTAINER_SOURCE)]["source"] == str(inferred_source)
            and mount_map[str(CONTAINER_TARGET)]["source"]
            == str(inferred_source / "target")
            and mount_map[str(CONTAINER_GIT_CONFIG)]["source"]
            == str(inferred_source / "scripts/c84-docker.gitconfig"),
            "container source/target/Git-config host bindings differ from closure source",
        )
        observed_sdk = next(
            item
            for item in contract_mounts
            if item["destination"] == str(CONTAINER_SDK)
        )
        require(observed_sdk == sdk_mount, "container SDK mounts differ")
    package = exact(
        content["package"],
        {"build_envelope", "image_verifier_audit", "package_envelope"},
        "closure package records",
    )
    expected_build, expected_package, expected_audit = package_records(
        artifact_root,
        package_run["attestation"],
        source_envelope,
        image["Id"],
        source_commit,
        challenge,
        source_root=inferred_source,
        tracker=tracker,
    )
    require(
        package
        == {
            "build_envelope": expected_build,
            "image_verifier_audit": expected_audit,
            "package_envelope": expected_package,
        },
        "closure package identities differ",
    )
    build_root, _ = read_semantic_envelope(
        artifact_root / FORMAL_ARTIFACTS["build_envelope"],
        BUILD_SCHEMA,
        2,
        "build envelope",
        tracker=tracker,
    )
    package_root, _ = read_semantic_envelope(
        artifact_root / FORMAL_ARTIFACTS["package_envelope"],
        PACKAGE_SCHEMA,
        2,
        "package envelope",
        tracker=tracker,
    )
    validate_path_identity(
        package["build_envelope"],
        artifact_root / FORMAL_ARTIFACTS["build_envelope"],
        FORMAL_ARTIFACTS["build_envelope"],
        "closure build envelope",
        tracker=tracker,
    )
    validate_path_identity(
        package["package_envelope"],
        artifact_root / FORMAL_ARTIFACTS["package_envelope"],
        FORMAL_ARTIFACTS["package_envelope"],
        "closure package envelope",
        tracker=tracker,
    )
    validate_path_identity(
        package["image_verifier_audit"],
        artifact_root / FORMAL_ARTIFACTS["image_verifier_audit"],
        FORMAL_ARTIFACTS["image_verifier_audit"],
        "closure image verifier audit",
        tracker=tracker,
    )
    artifacts = content["artifacts"]
    require(
        isinstance(artifacts, dict) and set(artifacts) == set(FORMAL_ARTIFACTS),
        "closure artifact roles differ",
    )
    for role, filename in FORMAL_ARTIFACTS.items():
        validate_path_identity(
            artifacts[role],
            artifact_root / filename,
            filename,
            f"closure artifact {role}",
            tracker=tracker,
        )
    require(
        package_run["attestation"] == package_root["content"]["runtime_attestation"],
        "closure/package embedded runtime attestation differs",
    )
    package_attestation_path = artifact_root / PACKAGE_ATTESTATION
    verifier_attestation_path = artifact_root / VERIFIER_ATTESTATION
    require(
        package_run["attestation_identity"]
        == file_identity(
            package_attestation_path, "package attestation", tracker=tracker
        ),
        "package attestation live identity differs",
    )
    require(
        verifier_run["attestation_identity"]
        == file_identity(
            verifier_attestation_path, "verifier attestation", tracker=tracker
        ),
        "verifier attestation live identity differs",
    )
    require(
        not contains_old_provenance(root),
        "runtime closure contains old operator-declared provenance",
    )
    return root


def verify_closure_command(
    closure: pathlib.Path,
    source_commit: str,
    challenge: str,
    *,
    _before_terminal: Any | None = None,
) -> None:
    if not closure.is_absolute():
        closure = pathlib.Path.cwd() / closure
    closure = path_without_symlink(closure, "runtime closure")
    tracker = StabilityTracker()
    root, raw = read_canonical_root(
        closure, CLOSURE_SCHEMA, "runtime closure", tracker=tracker
    )
    validate_closure_root(
        root,
        closure_path=closure,
        source_commit=source_commit,
        challenge=challenge,
        tracker=tracker,
    )
    if _before_terminal is not None:
        _before_terminal()
    source_root = closure.parent.parent.parent
    verify_source_materialization(
        source_root,
        source_commit,
        challenge,
        tracker=tracker,
    )
    tracker.recheck()
    terminal_root, terminal_raw = read_canonical_root(
        closure, CLOSURE_SCHEMA, "runtime closure", tracker=tracker
    )
    require(
        terminal_root == root and terminal_raw == raw,
        "runtime closure changed before terminal PASS",
    )


def launch_package(
    *,
    source: pathlib.Path,
    source_commit: str,
    challenge: str,
    sdk_root: pathlib.Path | None,
    sdk_volume: str | None,
) -> None:
    source, target, git_config, source_envelope = check_host_source(
        source, source_commit, challenge
    )
    artifact_root = source / pathlib.Path(*ARTIFACT_RELATIVE.parts)
    for filename in (PACKAGE_ATTESTATION, VERIFIER_ATTESTATION, CLOSURE_FILENAME):
        require(
            not os.path.lexists(artifact_root / filename),
            f"refusing to launch over existing runtime output: {artifact_root / filename}",
        )
    uid = os.getuid()
    gid = os.getgid()
    require(uid > 0 and gid > 0, "formal Docker custody refuses a root uid/gid")
    docker = shutil.which("docker")
    require(docker is not None, "required Docker CLI is missing")
    docker = docker_cli_invocation_path(pathlib.Path(docker))
    initial_image = validate_image_inspect(
        docker_json(
            docker, ["image", "inspect", IMAGE_REFERENCE], "Docker image inspect"
        )
    )
    sdk_volume_inspect: dict[str, Any] | None = None
    if sdk_root is not None:
        sdk_root = path_without_symlink(sdk_root, "SDK root")
        require(sdk_root.is_dir(), "SDK root is not a directory")
    else:
        require(
            isinstance(sdk_volume, str)
            and VOLUME_NAME.fullmatch(sdk_volume) is not None,
            "SDK volume name is malformed",
        )
        sdk_volume_inspect = validate_volume_inspect(
            docker_json(
                docker, ["volume", "inspect", sdk_volume], "Docker SDK volume inspect"
            ),
            sdk_volume,
        )
    package_run = run_container(
        docker=docker,
        mode="package",
        source=source,
        target=target,
        git_config=git_config,
        sdk_root=sdk_root,
        sdk_volume=sdk_volume,
        sdk_volume_inspect=sdk_volume_inspect,
        source_commit=source_commit,
        challenge=challenge,
        uid=uid,
        gid=gid,
    )
    require(
        package_run["host_preinspect"]["content"]["image_inspect"] == initial_image,
        "package image inspect changed after host preflight",
    )
    verifier_run = run_container(
        docker=docker,
        mode="verify",
        source=source,
        target=target,
        git_config=git_config,
        sdk_root=sdk_root,
        sdk_volume=sdk_volume,
        sdk_volume_inspect=sdk_volume_inspect,
        source_commit=source_commit,
        challenge=challenge,
        uid=uid,
        gid=gid,
    )
    require(
        verifier_run["host_preinspect"]["content"]["image_inspect"] == initial_image,
        "verifier image inspect changed after host preflight",
    )
    require(
        package_run["container_id"] != verifier_run["container_id"],
        "Docker reused one container for package and verifier",
    )
    require(
        verify_source_materialization(
            source,
            source_commit,
            challenge,
            expected_root=source_envelope,
        )
        == source_envelope,
        "source materialization changed across container runs",
    )
    build_record, package_record, audit_record = package_records(
        artifact_root,
        package_run["attestation"],
        source_envelope,
        initial_image["Id"],
        source_commit,
        challenge,
        source_root=source,
    )
    artifacts = {
        role: path_identity(
            artifact_root / filename, filename, f"closure artifact {role}"
        )
        for role, filename in FORMAL_ARTIFACTS.items()
    }
    package_mounts = package_run["host_preinspect"]["content"]["contract"]["mounts"]
    sdk_mount = next(
        item for item in package_mounts if item["destination"] == str(CONTAINER_SDK)
    )
    closure_content = {
        "artifacts": artifacts,
        "capability": CAPABILITY,
        "challenge": challenge,
        "image": image_closure_record(initial_image),
        "package": {
            "build_envelope": build_record,
            "image_verifier_audit": audit_record,
            "package_envelope": package_record,
        },
        "platform": PLATFORM,
        "runs": {"package": package_run, "verifier": verifier_run},
        "sdk_mount": sdk_mount,
        "source": {
            "materialization_content_sha256": source_envelope["content_sha256"],
            "root": str(source),
        },
        "source_commit": source_commit,
    }
    closure_root = content_addressed_root(CLOSURE_SCHEMA, closure_content)
    closure_path = artifact_root / CLOSURE_FILENAME
    write_no_clobber(closure_path, closure_root, "runtime closure")
    verify_closure_command(closure_path, source_commit, challenge)
    print(
        "C8.4 Docker runtime closure: PASS "
        f"source={source_commit} challenge={challenge} "
        f"image={initial_image['Id']} package={package_run['container_id']} "
        f"verifier={verifier_run['container_id']} closure={closure_path}"
    )


def expect_failure(label: str, operation: Any) -> None:
    try:
        operation()
    except RuntimeClosureError:
        return
    fail(f"selftest accepted mutation: {label}")


def synthetic_image() -> dict[str, Any]:
    return {
        "Architecture": "amd64",
        "Config": {"Env": [f"PATH={RUNTIME_PATH}"]},
        "Descriptor": {
            "digest": IMAGE_DIGEST,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "size": 1234,
        },
        "Id": "sha256:" + "9" * 64,
        "Os": "linux",
        "RepoDigests": [IMAGE_REFERENCE],
    }


def synthetic_container(
    identifier: str,
    image: dict[str, Any],
    contract_mounts: list[dict[str, Any]],
    source_commit: str,
    challenge: str,
    mode: str,
    uid: int,
    gid: int,
    *,
    terminal: bool,
) -> dict[str, Any]:
    mounts: list[dict[str, Any]] = []
    host_mounts: list[dict[str, Any]] = []
    for wanted in contract_mounts:
        record: dict[str, Any] = {
            "Destination": wanted["destination"],
            "Mode": "ro" if wanted["read_only"] else "",
            "Propagation": "rprivate",
            "RW": not wanted["read_only"],
            "Source": wanted["source"]
            if wanted["kind"] == "bind"
            else "/var/lib/docker/volumes/test/_data",
            "Type": wanted["kind"],
        }
        if wanted["kind"] == "volume":
            record["Name"] = wanted["source"]
        mounts.append(record)
        host_record: dict[str, Any] = {
            "Source": wanted["source"],
            "Target": wanted["destination"],
            "Type": wanted["kind"],
        }
        if wanted["read_only"]:
            host_record["ReadOnly"] = True
        if wanted["kind"] == "bind":
            host_record["BindOptions"] = {"Propagation": "rprivate"}
        else:
            host_record["VolumeOptions"] = {"NoCopy": True}
        host_mounts.append(host_record)
    command = [
        "scripts/c84-docker-runtime.py",
        "guest-package",
        "--host-preinspect",
        str(CONTAINER_PREINSPECT / HOST_PREINSPECT_FILENAME),
        "--source-commit",
        source_commit,
        "--challenge",
        challenge,
        "--mode",
        mode,
    ]
    return {
        "Config": {
            "Cmd": command,
            "Entrypoint": ["python3"],
            "Env": [
                f"{key}={value}"
                for key, value in strict_environment(source_commit, challenge).items()
            ],
            "Hostname": identifier[:12],
            "Image": IMAGE_REFERENCE,
            "User": f"{uid}:{gid}",
            "WorkingDir": str(CONTAINER_SOURCE),
        },
        "HostConfig": {
            "AutoRemove": False,
            "Binds": None,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "DeviceRequests": None,
            "Devices": [],
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": None,
            "GroupAdd": None,
            "Init": None,
            "IpcMode": "private",
            "Links": None,
            "Mounts": host_mounts,
            "NetworkMode": "none",
            "PidMode": "",
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": False,
            "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
            "SecurityOpt": ["no-new-privileges:true"],
            "UTSMode": "",
            "UsernsMode": "",
            "VolumesFrom": None,
        },
        "Id": identifier,
        "Image": image["Id"],
        "Mounts": mounts,
        "NetworkSettings": {"Networks": {}, "Ports": {}},
        "State": {
            "Dead": False,
            "Error": "",
            "ExitCode": 0,
            "OOMKilled": False,
            "Paused": False,
            "Pid": 0,
            "Restarting": False,
            "Running": False,
            "Status": "exited" if terminal else "created",
        },
    }


def synthetic_witness(uid: int, gid: int, hostname: str) -> dict[str, Any]:
    header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    status = (
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
        f"Groups:\t{gid}\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000000\n"
        "CapEff:\t0000000000000000\n"
        "CapBnd:\t0000000000000000\n"
        "CapAmb:\t0000000000000000\n"
        "NoNewPrivs:\t1\n"
    )
    mountinfo = (
        "1 1 0:1 / / rw,relatime - overlay overlay rw\n"
        "2 1 0:2 / /home/vibeos ro,nosuid - bind /synthetic/source ro\n"
        "3 2 0:3 / /home/vibeos/target rw,nosuid - bind /synthetic/target rw\n"
        "4 1 0:4 / /home/work ro,nosuid - bind /synthetic/sdk ro\n"
        "5 1 0:5 / /etc/vibeos-c84.gitconfig ro,nosuid - bind /synthetic/config ro\n"
        "6 1 0:6 / /run/vibeos-c84-host ro,nosuid - bind /synthetic/preinspect ro\n"
    )
    return {
        "credentials": parse_status(status),
        "environment": {**strict_environment("3" * 40, "4" * 64), "HOSTNAME": hostname},
        "hostname": hostname,
        "interfaces": ["lo"],
        "ipv4_route_raw": header,
        "ipv4_routes": [],
        "ipv6_route_raw": "",
        "ipv6_routes": [],
        "mountinfo": parse_mountinfo(mountinfo),
        "mountinfo_raw": mountinfo,
        "preinspect_entries": [HOST_PREINSPECT_FILENAME],
        "status_raw": status,
    }


def run_selftest() -> None:
    require(
        not image_audit_transcript_has_failure(
            [
                "normal verifier output",
                '{"path":"/tmp/fail/source"}',
                IMAGE_VERIFIER_PASS,
            ]
        ),
        "structured image audit status word was treated as transcript failure",
    )
    require(
        image_audit_transcript_has_failure(
            ["fatal: verifier crashed", "{}", IMAGE_VERIFIER_PASS]
        ),
        "non-structured image audit failure was not detected",
    )
    source_commit = "3" * 40
    challenge = "4" * 64
    uid = 1000
    gid = 1000
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-runtime-selftest-"
    ) as temporary_text:
        temporary_root = pathlib.Path(temporary_text).resolve(strict=True)
        docker_tools = temporary_root / "docker-tools"
        docker_tools.write_bytes(b"#!/bin/sh\nexit 0\n")
        docker_tools.chmod(0o755)
        docker_entry = temporary_root / "docker"
        docker_entry.symlink_to(docker_tools.name)
        require(
            docker_cli_invocation_path(docker_entry) == str(docker_entry),
            "Docker multi-call symlink lost its docker argv[0] entry point",
        )
        expect_failure(
            "resolved Docker multi-call target",
            lambda: docker_cli_invocation_path(docker_entry.resolve(strict=True)),
        )

        source = temporary_root / "source"
        artifact_root = source / pathlib.Path(*ARTIFACT_RELATIVE.parts)
        artifact_root.mkdir(parents=True)
        source_inputs = set(BUILD_TOOL_PATHS.values()) | set(
            PACKAGE_SOURCE_TOOL_PATHS.values()
        )
        for relative in sorted(source_inputs):
            path = source / pathlib.Path(*pathlib.PurePosixPath(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"producer-shaped selftest input {relative}\n", encoding="utf-8"
            )
        workload_path = source / BUILD_TOOL_PATHS["workload_manifest"]
        workload_path.write_text(
            json.dumps(
                {
                    "fixture": {
                        "artifact": {"sha256": "1" * 64},
                        "input": {"sha256": "2" * 64},
                        "output": {"sha256": "3" * 64},
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        toolchain_path = source / BUILD_TOOL_PATHS["toolchain_contract"]
        toolchain_path.write_text(
            "# rustc 1.99.0-nightly (aaaaaaaaa 2026-01-01)\n"
            "# rustc-commit: "
            + "a" * 40
            + '\n[toolchain]\nchannel = "nightly-selftest"\n',
            encoding="utf-8",
        )
        runtime_copy = source / PACKAGE_SOURCE_TOOL_PATHS["docker_runtime_script"]
        runtime_copy.write_bytes(
            stable_regular_bytes(
                SCRIPT_PATH, "selftest runtime source", maximum=MAX_TEXT_BYTES
            )
        )
        materializer_path = source / BUILD_TOOL_PATHS["source_materializer_script"]
        materializer_path.write_text(
            """#!/usr/bin/env python3
import argparse, json, pathlib
p = argparse.ArgumentParser()
p.add_argument('operation')
p.add_argument('--destination', required=True)
p.add_argument('--source-commit', required=True)
p.add_argument('--challenge', required=True)
o = p.parse_args()
assert o.operation == 'verify'
root = pathlib.Path(o.destination)
path = root / 'target/c84-source-materialization' / o.source_commit / o.challenge / 'source-materialization-envelope.json'
value = json.loads(path.read_text(encoding='utf-8'))
assert set(value['content']) == {'bundles','challenge','clone_git_admin','command','frozen','git','independence','materialization','patch','snapshot','source','source_commit','submodules','timestamps_utc'}
assert value['content']['source_commit'] == o.source_commit
assert value['content']['challenge'] == o.challenge
(root / 'target/.runtime-source-verifier-ran').write_text('PASS\\n', encoding='utf-8')
print('synthetic frozen materialization verify: PASS')
""",
            encoding="utf-8",
        )
        materializer_path.chmod(0o555)
        source_path = source_envelope_path(source, source_commit, challenge)
        source_path.parent.mkdir(parents=True)
        source_root = content_addressed_root(
            SOURCE_SCHEMA,
            {
                "bundles": [
                    {
                        "bytes": 1,
                        "head": source_commit,
                        "role": "superproject",
                        "sha256": "1" * 64,
                    }
                ],
                "challenge": challenge,
                "clone_git_admin": {
                    "ordinary_refs_remotes_reflogs_hooks_removed": True
                },
                "command": [
                    "scripts/c84-source-materialization.py",
                    "materialize",
                    "--source",
                    "<operator-source>",
                    "--destination",
                    "<new-destination>",
                    "--source-commit",
                    source_commit,
                    "--challenge",
                    challenge,
                ],
                "frozen": {
                    "source_except_target_current_credential_writable": False,
                    "target_current_credential_writable": True,
                },
                "git": {
                    "bytes": 1,
                    "path": "/opt/failure-tools/git",
                    "sha256": "2" * 64,
                    "version": "git version 2.selftest",
                },
                "independence": {"object_stores_disjoint": True},
                "materialization": {
                    "atomic_destination_publish": "renameat2(RENAME_NOREPLACE)",
                    "destination_was_absent": True,
                    "local_bundles_only": True,
                    "method": "local Git bundles into independent standalone repositories",
                    "network_allowed": False,
                    "ordinary_refs_remotes_reflogs_hooks_removed": True,
                    "replacement_graft_alternate_shallow_promisor_allowed": False,
                },
                "patch": {
                    "applied_diff_bytes": 1,
                    "applied_diff_sha256": "3" * 64,
                    "base_submodule_commit": "4" * 40,
                    "path": "patches/jitterentropy-rs/0001-vibeos-qualification.patch",
                    "policy": "exact git diff --unified=0 --binary; applied before source freeze",
                },
                "snapshot": {"files": 1, "sha256": "4" * 64},
                "source": {
                    "head": source_commit,
                    "object_format": "sha1",
                    "submodule_heads": {},
                    "tree": "5" * 40,
                },
                "source_commit": source_commit,
                "submodules": [],
                "timestamps_utc": {
                    "materialization_started": "2026-01-01T00:00:00Z",
                    "materialization_completed": "2026-01-01T00:00:01Z",
                },
            },
        )
        write_no_clobber(source_path, source_root, "synthetic source envelope")
        image = synthetic_image()
        validate_image_inspect(image)
        mounts = mount_contract(
            source,
            source / "target",
            source / "scripts/c84-docker.gitconfig",
            pathlib.Path(temporary_text).resolve(strict=True) / "host-preinspect",
            pathlib.Path(temporary_text).resolve(strict=True) / "sdk",
            None,
        )

        def make_run(mode: str, identifier: str) -> dict[str, Any]:
            create = docker_create_arguments(
                uid=uid,
                gid=gid,
                mounts=mounts,
                source_commit=source_commit,
                challenge=challenge,
                mode=mode,
            )
            pre_container = synthetic_container(
                identifier,
                image,
                mounts,
                source_commit,
                challenge,
                mode,
                uid,
                gid,
                terminal=False,
            )
            pre_content = host_preinspect_content(
                mode=mode,
                source_commit=source_commit,
                challenge=challenge,
                uid=uid,
                gid=gid,
                image=image,
                container=pre_container,
                mounts=mounts,
                sdk_volume_inspect=None,
                create_argv=create,
            )
            pre_root = content_addressed_root(PREINSPECT_SCHEMA, pre_content)
            validate_host_preinspect(
                pre_root,
                source_commit=source_commit,
                challenge=challenge,
                expect_mode=mode,
            )
            witness = synthetic_witness(uid, gid, identifier[:12])
            validate_witness(witness, pre_root)
            attestation = content_addressed_root(
                ATTESTATION_SCHEMA,
                {
                    "capability": CAPABILITY,
                    "challenge": challenge,
                    "host_preinspect": pre_root,
                    "host_preinspect_identity": {
                        "bytes": len(canonical_json(pre_root) + b"\n"),
                        "sha256": hashlib.sha256(
                            canonical_json(pre_root) + b"\n"
                        ).hexdigest(),
                    },
                    "mode": mode,
                    "source_commit": source_commit,
                    "source_materialization_content_sha256": source_root[
                        "content_sha256"
                    ],
                    "witness": witness,
                },
            )
            attestation_raw = canonical_json(attestation) + b"\n"
            return {
                "attestation": attestation,
                "attestation_identity": {
                    "bytes": len(attestation_raw),
                    "sha256": hashlib.sha256(attestation_raw).hexdigest(),
                },
                "container_id": identifier,
                "container_postinspect": synthetic_container(
                    identifier,
                    image,
                    mounts,
                    source_commit,
                    challenge,
                    mode,
                    uid,
                    gid,
                    terminal=True,
                ),
                "container_preinspect": pre_container,
                "host_preinspect": pre_root,
                "host_preinspect_identity": {
                    "bytes": len(canonical_json(pre_root) + b"\n"),
                    "sha256": hashlib.sha256(
                        canonical_json(pre_root) + b"\n"
                    ).hexdigest(),
                },
                "operations": {
                    "create": create,
                    "postinspect": ["inspect", identifier],
                    "preinspect": ["inspect", identifier],
                    "start": ["start", "--attach", identifier],
                    "wait": ["wait", identifier],
                },
                "wait_exit_code": 0,
            }

        package_run = make_run("package", "a" * 64)
        verifier_run = make_run("verify", "b" * 64)
        write_no_clobber(
            artifact_root / PACKAGE_ATTESTATION,
            package_run["attestation"],
            "synthetic package attestation",
        )
        write_no_clobber(
            artifact_root / VERIFIER_ATTESTATION,
            verifier_run["attestation"],
            "synthetic verifier attestation",
        )
        for role, filename in FORMAL_ARTIFACTS.items():
            path = artifact_root / filename
            if path.exists():
                continue
            if role not in {
                "build_envelope",
                "package_envelope",
                "image_verifier_audit",
            }:
                payload = f"synthetic {role}\n"
                if role in {
                    "kernel_elf",
                    "kernel_binary",
                    "boot_sd",
                    "full_sd_image",
                }:
                    payload += f"source={source_commit}\nchallenge={challenge}\n"
                path.write_bytes(payload.encode("ascii"))
        stage_root = pathlib.PurePosixPath(
            f"target/.milkv-duo-wasm-aot-profile.stage.{source_commit}.{challenge}"
        )
        build_artifacts: dict[str, dict[str, Any]] = {}
        for role in ("kernel_elf", "kernel_binary"):
            identity = file_identity(
                artifact_root / FORMAL_ARTIFACTS[role],
                f"producer-shaped build artifact {role}",
            )
            build_artifacts[role] = {
                **identity,
                "path": str(stage_root / FORMAL_ARTIFACTS[role]),
            }
        build_tools: dict[str, dict[str, Any]] = {}
        for role, relative in BUILD_TOOL_PATHS.items():
            identity = file_identity(
                source / pathlib.Path(*pathlib.PurePosixPath(relative).parts),
                f"producer-shaped build tool {role}",
            )
            build_tools[role] = {**identity, "path": relative}
        external_measurement = {"bytes": 1, "sha256": "6" * 64}
        synthetic_host = "x86_64-unknown-linux-gnu"
        synthetic_toolchain_bin = pathlib.PurePosixPath("/synthetic/toolchain/bin")
        toolchain = {
            "provenance": "build-runner-self-measured; package cross-platform live rehash unavailable",
            "channel": "nightly-selftest",
            "rustc_verbose": "rustc 1.99.0-nightly (aaaaaaaaa 2026-01-01)\ncommit-hash: "
            + "a" * 40
            + f"\nhost: {synthetic_host}",
            "rustup": {**external_measurement, "path": "/synthetic/bin/rustup"},
            "cargo": {
                **external_measurement,
                "path": str(synthetic_toolchain_bin / "cargo"),
            },
            "rustc": {
                **external_measurement,
                "path": str(synthetic_toolchain_bin / "rustc"),
            },
            "rustdoc": {
                **external_measurement,
                "path": str(synthetic_toolchain_bin / "rustdoc"),
            },
            "rust_objcopy": {
                **external_measurement,
                "path": str(
                    synthetic_toolchain_bin.parent
                    / "lib"
                    / "rustlib"
                    / synthetic_host
                    / "bin"
                    / "rust-objcopy"
                ),
            },
            "linker": {**external_measurement, "path": "/synthetic/bin/ld.lld"},
        }
        workload = strict_json(
            stable_regular_bytes(workload_path, "selftest workload"),
            "selftest workload",
        )
        run_fields = [
            "vibeos.c84.aot-decision.run-id.v1",
            source_commit,
            challenge,
            workload["fixture"]["artifact"]["sha256"],
            workload["fixture"]["input"]["sha256"],
            workload["fixture"]["output"]["sha256"],
            build_tools["workload_manifest"]["sha256"],
            build_tools["transcript_schema"]["sha256"],
        ]
        run_id = hashlib.sha256("\0".join(run_fields).encode("ascii")).hexdigest()
        build_allowed_keys = [
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
        build_environment_values = {
            "CARGO_HOME": "<isolated-cargo-home>",
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(
                source / "target" / "c84-milkv-build" / source_commit / challenge
            ),
            "HOME": "<isolated-cargo-home>/home",
            "LC_ALL": "C",
            "PATH": "/tmp/vibeos-c84-cargo-home.selftest/closed-bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "RUSTC": toolchain["rustc"]["path"],
            "RUSTDOC": toolchain["rustdoc"]["path"],
            "RUSTUP_HOME": "/synthetic/rustup-home",
            "SOURCE_DATE_EPOCH": "1",
            "TMPDIR": "<isolated-cargo-home>/tmp",
            "TZ": "UTC",
            "VIBEOS_C84_CHALLENGE": challenge,
            "VIBEOS_C84_SOURCE_COMMIT": source_commit,
        }
        build_content = {
            "artifacts": build_artifacts,
            "challenge": challenge,
            "command": [
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
            ],
            "environment": {
                "mode": "env -i",
                "allowed_keys": build_allowed_keys,
                "values": build_environment_values,
                "cargo_home_isolation": {
                    "ambient_config_loaded": False,
                    "temporary": True,
                    "cache_source": "/synthetic/cache",
                    "registry_cache_symlinked": False,
                    "git_cache_symlinked": False,
                },
            },
            "objcopy_command": [
                toolchain["rust_objcopy"]["path"],
                "-O",
                "binary",
                build_artifacts["kernel_elf"]["path"],
                build_artifacts["kernel_binary"]["path"],
            ],
            "objcopy_environment": {
                "mode": "env -i",
                "allowed_keys": ["LC_ALL", "PATH", "TZ"],
                "values": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            },
            "platform": "milkv-duo-cv1800b",
            "run_id": run_id,
            "source": {
                "head": source_commit,
                "materialization": source_root,
                "root": ".",
            },
            "source_commit": source_commit,
            "timestamps_utc": {
                "build_started": "2026-01-01T00:00:00Z",
                "build_completed": "2026-01-01T00:00:01Z",
                "envelope_closed": "2026-01-01T00:00:02Z",
            },
            "toolchain": toolchain,
            "tools": build_tools,
        }
        build_root = content_addressed_root(BUILD_SCHEMA, build_content, version=2)
        write_no_clobber(
            artifact_root / FORMAL_ARTIFACTS["build_envelope"],
            build_root,
            "synthetic build envelope",
        )
        build_identity = file_identity(
            artifact_root / FORMAL_ARTIFACTS["build_envelope"],
            "synthetic build envelope",
        )
        published_roles = {
            "kernel_elf": FORMAL_ARTIFACTS["kernel_elf"],
            "kernel_binary": FORMAL_ARTIFACTS["kernel_binary"],
            "packaged_fit_source": FORMAL_ARTIFACTS["packaged_fit_source"],
            "packaged_dtb": FORMAL_ARTIFACTS["packaged_dtb"],
            "fit_boot_sd": FORMAL_ARTIFACTS["boot_sd"],
            "full_sd_image": FORMAL_ARTIFACTS["full_sd_image"],
        }
        published = {}
        for role, filename in published_roles.items():
            identity = file_identity(
                artifact_root / filename, f"synthetic package artifact {role}"
            )
            published[role] = {
                "bytes": identity["bytes"],
                "path": str(CONTAINER_SOURCE / ARTIFACT_RELATIVE / filename),
                "sha256": identity["sha256"],
            }
        synthetic_sdk = b"synthetic SDK measurement\n"
        sdk_measurement = {
            "bytes": len(synthetic_sdk),
            "sha256": hashlib.sha256(synthetic_sdk).hexdigest(),
        }
        for role in ("sdk_dtb", "sdk_fip"):
            published[role] = {
                **sdk_measurement,
                "path": PACKAGE_ARTIFACT_PATHS[role],
            }
        package_tools: dict[str, dict[str, Any]] = {}
        for role, relative in PACKAGE_SOURCE_TOOL_PATHS.items():
            identity = file_identity(
                source / pathlib.Path(*pathlib.PurePosixPath(relative).parts),
                f"producer-shaped package tool {role}",
            )
            package_tools[role] = {
                **identity,
                "path": str(CONTAINER_SOURCE / pathlib.PurePosixPath(relative)),
            }
        for role, logical_path in PACKAGE_SDK_TOOL_PATHS.items():
            package_tools[role] = {**sdk_measurement, "path": logical_path}
        package_tools["sdk_genimage"] = {
            **sdk_measurement,
            "path": sorted(PACKAGE_GENIMAGE_PATHS)[0],
        }
        verifier_paths = {
            "verifier_mdir": "/usr/bin/mtools",
            "verifier_mcopy": "/usr/bin/mtools",
            "verifier_cmp": "/usr/bin/cmp",
            "verifier_sha256sum": "/usr/bin/sha256sum",
            "verifier_fdtget": "/usr/bin/fdtget",
            "verifier_python3": "/usr/bin/python3.11",
            "verifier_tr": "/usr/bin/tr",
        }
        for role, logical_path in verifier_paths.items():
            package_tools[role] = {**sdk_measurement, "path": logical_path}
        audit_artifact_mapping = {
            "kernel_binary": "kernel_binary",
            "fit_source": "packaged_fit_source",
            "packaged_dtb": "packaged_dtb",
            "sdk_dtb": "sdk_dtb",
            "fit_boot_sd": "fit_boot_sd",
            "full_sd_image": "full_sd_image",
            "sdk_fip": "sdk_fip",
        }
        audit_tool_mapping = {
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
        audit_report = {
            "artifacts": {
                report_role: {
                    "bytes": published[package_role]["bytes"],
                    "sha256": published[package_role]["sha256"],
                }
                for report_role, package_role in audit_artifact_mapping.items()
            },
            "challenge": challenge,
            "runtime_attestation": package_run["attestation"],
            "schema": IMAGE_AUDIT_SCHEMA,
            "source_commit": source_commit,
            "source_materialization": source_root,
            "tools": {
                report_role: {
                    "bytes": package_tools[package_role]["bytes"],
                    "sha256": package_tools[package_role]["sha256"],
                }
                for report_role, package_role in audit_tool_mapping.items()
            },
            "version": 2,
        }
        audit_report_raw = canonical_json(audit_report)
        (artifact_root / FORMAL_ARTIFACTS["image_verifier_audit"]).write_bytes(
            audit_report_raw + b"\n" + IMAGE_VERIFIER_PASS.encode("ascii") + b"\n"
        )
        audit_identity = file_identity(
            artifact_root / FORMAL_ARTIFACTS["image_verifier_audit"], "synthetic audit"
        )
        package_root = content_addressed_root(
            PACKAGE_SCHEMA,
            {
                "artifacts": published,
                "build": {
                    "content_sha256": build_root["content_sha256"],
                    "envelope": {
                        "bytes": build_identity["bytes"],
                        "path": str(
                            CONTAINER_SOURCE / ARTIFACT_RELATIVE / "build-envelope.json"
                        ),
                        "sha256": build_identity["sha256"],
                    },
                },
                "challenge": challenge,
                "command": [
                    "scripts/package-milkv-duo-sdk.sh",
                    "--wasm-aot-profile",
                    "<sdk-root>",
                ],
                "environment": {
                    "fit_tools": {
                        "mode": "env -i",
                        "allowed_keys": ["LC_ALL", "PATH", "TZ"],
                        "values": {
                            "LC_ALL": "C",
                            "PATH": "/usr/bin:/bin",
                            "TZ": "UTC",
                        },
                    },
                    "genimage": {
                        "mode": "env -i",
                        "allowed_keys": [
                            "HOME",
                            "LC_ALL",
                            "LD_LIBRARY_PATH",
                            "PATH",
                            "TZ",
                        ],
                        "values": {
                            "HOME": "/nonexistent",
                            "LC_ALL": "C",
                            "LD_LIBRARY_PATH": str(
                                pathlib.PurePosixPath(
                                    package_tools["sdk_genimage"]["path"]
                                ).parent.parent
                                / "lib"
                            ),
                            "PATH": f"{pathlib.PurePosixPath(package_tools['sdk_genimage']['path']).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
                            "TZ": "UTC",
                        },
                    },
                    "image_verifier": {
                        "mode": "env -i",
                        "allowed_keys": [
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
                        "values": {
                            "GIT_CONFIG_GLOBAL": str(CONTAINER_GIT_CONFIG),
                            "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_NO_REPLACE_OBJECTS": "1",
                            "GIT_OPTIONAL_LOCKS": "0",
                            "HOME": "/nonexistent",
                            "LC_ALL": "C",
                            "PATH": RUNTIME_PATH,
                            "TZ": "UTC",
                            "VIBEOS_C84_CHALLENGE": challenge,
                            "VIBEOS_C84_SDK_CONTAINER_DIGEST": IMAGE_DIGEST,
                            "VIBEOS_C84_SOURCE_COMMIT": source_commit,
                        },
                    },
                },
                "platform": "milkv-duo-cv1800b",
                "run_id": run_id,
                "runtime_attestation": package_run["attestation"],
                "sdk": {
                    "commit": SDK_COMMIT,
                    "commit_provenance": "host-observed read-only SDK mount; in-container Git HEAD and clean worktree verified",
                    "image_digest": IMAGE_DIGEST,
                    "image_id": image["Id"],
                    "platform": PLATFORM,
                    "root": str(CONTAINER_SDK),
                    "runtime_provenance": RUNTIME_PROVENANCE,
                    "status_policy": "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
                    "worktree_clean": True,
                },
                "source": {
                    "head": source_commit,
                    "materialization": source_root,
                    "root": str(CONTAINER_SOURCE),
                },
                "source_commit": source_commit,
                "timestamps_utc": {
                    "packaging_started": "2026-01-01T00:00:03Z",
                    "image_verified": "2026-01-01T00:00:04Z",
                    "envelope_closed": "2026-01-01T00:00:05Z",
                },
                "tools": package_tools,
                "verifier": {
                    "audit_log": {
                        "bytes": audit_identity["bytes"],
                        "path": str(
                            CONTAINER_SOURCE
                            / ARTIFACT_RELATIVE
                            / "image-verifier-audit.log"
                        ),
                        "sha256": audit_identity["sha256"],
                    },
                    "exact_pass_marker": IMAGE_VERIFIER_PASS,
                    "exit_code": 0,
                    "invocation": [
                        "scripts/verify-milkv-duo-image.sh",
                        "--wasm-aot-profile",
                        "--package-preflight",
                        "--artifact-root=<staging-artifact-root>",
                        "<sdk-root>",
                    ],
                    "report": audit_report,
                    "report_sha256": hashlib.sha256(audit_report_raw).hexdigest(),
                    "status": "PASS",
                },
            },
            version=2,
        )
        write_no_clobber(
            artifact_root / FORMAL_ARTIFACTS["package_envelope"],
            package_root,
            "synthetic package envelope",
        )
        package_record = path_identity(
            artifact_root / FORMAL_ARTIFACTS["package_envelope"],
            FORMAL_ARTIFACTS["package_envelope"],
            "synthetic package envelope",
        )
        build_record = path_identity(
            artifact_root / FORMAL_ARTIFACTS["build_envelope"],
            FORMAL_ARTIFACTS["build_envelope"],
            "synthetic build envelope",
        )
        audit_record = path_identity(
            artifact_root / FORMAL_ARTIFACTS["image_verifier_audit"],
            FORMAL_ARTIFACTS["image_verifier_audit"],
            "synthetic audit",
        )
        artifacts = {
            role: path_identity(
                artifact_root / filename, filename, f"synthetic artifact {role}"
            )
            for role, filename in FORMAL_ARTIFACTS.items()
        }
        sdk_mount = next(
            item for item in mounts if item["destination"] == str(CONTAINER_SDK)
        )
        closure = content_addressed_root(
            CLOSURE_SCHEMA,
            {
                "artifacts": artifacts,
                "capability": CAPABILITY,
                "challenge": challenge,
                "image": image_closure_record(image),
                "package": {
                    "build_envelope": build_record,
                    "image_verifier_audit": audit_record,
                    "package_envelope": package_record,
                },
                "platform": PLATFORM,
                "runs": {"package": package_run, "verifier": verifier_run},
                "sdk_mount": sdk_mount,
                "source": {
                    "materialization_content_sha256": source_root["content_sha256"],
                    "root": str(source),
                },
                "source_commit": source_commit,
            },
        )
        closure_path = artifact_root / CLOSURE_FILENAME
        write_no_clobber(closure_path, closure, "synthetic runtime closure")
        verify_closure_command(closure_path, source_commit, challenge)
        require(
            (source / "target/.runtime-source-verifier-ran").read_text(encoding="utf-8")
            == "PASS\n",
            "selftest frozen source verifier was not executed",
        )

        alternate_artifact_root = source / "alternate" / "artifact-root"
        alternate_artifact_root.mkdir(parents=True)
        expect_failure(
            "non-formal artifact root",
            lambda: validate_closure_root(
                closure,
                closure_path=alternate_artifact_root / CLOSURE_FILENAME,
                source_commit=source_commit,
                challenge=challenge,
            ),
        )

        closure_raw = stable_regular_bytes(closure_path, "selftest closure")

        def replace_closure_inode() -> None:
            replacement = closure_path.parent / ".closure-replacement.tmp"
            replacement.write_bytes(closure_raw)
            replacement.chmod(0o444)
            os.replace(replacement, closure_path)

        expect_failure(
            "closure inode replacement after validation",
            lambda: verify_closure_command(
                closure_path,
                source_commit,
                challenge,
                _before_terminal=replace_closure_inode,
            ),
        )
        raced_artifact = artifact_root / FORMAL_ARTIFACTS["kernel_elf"]
        raced_original = raced_artifact.read_bytes()

        def change_validated_artifact() -> None:
            raced_artifact.write_bytes(raced_original + b"terminal race\n")

        try:
            expect_failure(
                "artifact change after final semantic hash",
                lambda: verify_closure_command(
                    closure_path,
                    source_commit,
                    challenge,
                    _before_terminal=change_validated_artifact,
                ),
            )
        finally:
            raced_artifact.write_bytes(raced_original)

        build_path = artifact_root / FORMAL_ARTIFACTS["build_envelope"]
        package_path = artifact_root / FORMAL_ARTIFACTS["package_envelope"]
        original_build_raw = canonical_json(build_root) + b"\n"
        original_package_raw = canonical_json(package_root) + b"\n"

        def replace_selftest_envelope(path: pathlib.Path, raw: bytes) -> None:
            path.chmod(0o644)
            path.write_bytes(raw)
            path.chmod(0o444)

        def integrated_build_mutation(label: str, mutation: Any) -> None:
            attacked_build_content = copy.deepcopy(build_root["content"])
            mutation(attacked_build_content)
            attacked_build = content_addressed_root(
                BUILD_SCHEMA, attacked_build_content, version=2
            )
            try:
                replace_selftest_envelope(
                    build_path, canonical_json(attacked_build) + b"\n"
                )
                attacked_build_identity = file_identity(
                    build_path, f"{label} build envelope"
                )

                attacked_package_content = copy.deepcopy(package_root["content"])
                attacked_package_content["build"] = {
                    "content_sha256": attacked_build["content_sha256"],
                    "envelope": {
                        **attacked_build_identity,
                        "path": str(
                            CONTAINER_SOURCE / ARTIFACT_RELATIVE / build_path.name
                        ),
                    },
                }
                attacked_package = content_addressed_root(
                    PACKAGE_SCHEMA, attacked_package_content, version=2
                )
                replace_selftest_envelope(
                    package_path, canonical_json(attacked_package) + b"\n"
                )
                attacked_package_identity = file_identity(
                    package_path, f"{label} package envelope"
                )

                attacked_closure_content = copy.deepcopy(closure["content"])
                attacked_build_record = {
                    **attacked_build_identity,
                    "path": FORMAL_ARTIFACTS["build_envelope"],
                }
                attacked_package_record = {
                    **attacked_package_identity,
                    "path": FORMAL_ARTIFACTS["package_envelope"],
                }
                attacked_closure_content["package"]["build_envelope"] = (
                    attacked_build_record
                )
                attacked_closure_content["package"]["package_envelope"] = (
                    attacked_package_record
                )
                attacked_closure_content["artifacts"]["build_envelope"] = (
                    attacked_build_record
                )
                attacked_closure_content["artifacts"]["package_envelope"] = (
                    attacked_package_record
                )
                attacked_closure = content_addressed_root(
                    CLOSURE_SCHEMA, attacked_closure_content
                )
                replace_selftest_envelope(
                    closure_path, canonical_json(attacked_closure) + b"\n"
                )
                expect_failure(
                    label,
                    lambda: verify_closure_command(
                        closure_path, source_commit, challenge
                    ),
                )
            finally:
                replace_selftest_envelope(build_path, original_build_raw)
                replace_selftest_envelope(package_path, original_package_raw)
                replace_selftest_envelope(closure_path, closure_raw)

        for label, mutation in (
            (
                "integrated relative build PATH",
                lambda value: value["environment"]["values"].__setitem__(
                    "PATH",
                    "relative/vibeos-c84-cargo-home.attack/closed-bin:/usr/bin:/bin:/usr/sbin:/sbin",
                ),
            ),
            (
                "integrated relocated CARGO_TARGET_DIR",
                lambda value: value["environment"]["values"].__setitem__(
                    "CARGO_TARGET_DIR",
                    f"/forged/target/c84-milkv-build/{source_commit}/{challenge}",
                ),
            ),
            (
                "integrated unrelated toolchain cargo path",
                lambda value: value["toolchain"]["cargo"].__setitem__(
                    "path", "/forged/toolchain/bin/cargo"
                ),
            ),
        ):
            integrated_build_mutation(label, mutation)

        volume_inspect = {
            "Driver": "local",
            "Labels": None,
            "Mountpoint": "/var/lib/docker/volumes/vibeos-c84-sdk/_data",
            "Name": "vibeos-c84-sdk",
            "Options": None,
            "Scope": "local",
        }
        validate_volume_inspect(volume_inspect, "vibeos-c84-sdk")
        empty_volume_metadata = copy.deepcopy(volume_inspect)
        empty_volume_metadata["Labels"] = {}
        empty_volume_metadata["Options"] = {}
        validate_volume_inspect(empty_volume_metadata, "vibeos-c84-sdk")

        def mutate_volume(label: str, mutation: Any) -> None:
            attacked = copy.deepcopy(volume_inspect)
            mutation(attacked)
            expect_failure(
                label,
                lambda: validate_volume_inspect(attacked, "vibeos-c84-sdk"),
            )

        mutate_volume(
            "NFS-backed local volume",
            lambda value: value.__setitem__(
                "Options",
                {"device": ":/exports/sdk", "o": "addr=192.0.2.1", "type": "nfs"},
            ),
        )
        mutate_volume(
            "global volume", lambda value: value.__setitem__("Scope", "global")
        )
        mutate_volume(
            "labeled volume",
            lambda value: value.__setitem__("Labels", {"unclosed": "true"}),
        )
        mutate_volume("missing volume options", lambda value: value.pop("Options"))

        def mutate_closure(label: str, mutation: Any) -> None:
            attacked_content = copy.deepcopy(closure["content"])
            mutation(attacked_content)
            attacked_root = content_addressed_root(CLOSURE_SCHEMA, attacked_content)
            expect_failure(
                label,
                lambda: validate_closure_root(
                    attacked_root,
                    closure_path=closure_path,
                    source_commit=source_commit,
                    challenge=challenge,
                ),
            )

        mutate_closure(
            "capability",
            lambda value: value.__setitem__("capability", "hardware attested"),
        )
        mutate_closure(
            "wrong image id",
            lambda value: value["image"].__setitem__("id", "sha256:" + "8" * 64),
        )
        mutate_closure(
            "same container",
            lambda value: value["runs"]["verifier"].__setitem__(
                "container_id", "a" * 64
            ),
        )
        mutate_closure(
            "nonzero exit",
            lambda value: value["runs"]["package"].__setitem__("wait_exit_code", 7),
        )
        mutate_closure(
            "boolean exit",
            lambda value: value["runs"]["package"].__setitem__("wait_exit_code", False),
        )
        mutate_closure(
            "artifact digest",
            lambda value: value["artifacts"]["kernel_binary"].__setitem__(
                "sha256", "0" * 64
            ),
        )
        mutate_closure(
            "rw SDK", lambda value: value["sdk_mount"].__setitem__("read_only", False)
        )

        def root_credentials(value: dict[str, Any]) -> None:
            run = value["runs"]["package"]
            root_create = docker_create_arguments(
                uid=0,
                gid=0,
                mounts=mounts,
                source_commit=source_commit,
                challenge=challenge,
                mode="package",
            )
            root_container = synthetic_container(
                "a" * 64,
                image,
                mounts,
                source_commit,
                challenge,
                "package",
                0,
                0,
                terminal=False,
            )
            root_preinspect = content_addressed_root(
                PREINSPECT_SCHEMA,
                host_preinspect_content(
                    mode="package",
                    source_commit=source_commit,
                    challenge=challenge,
                    uid=0,
                    gid=0,
                    image=image,
                    container=root_container,
                    mounts=mounts,
                    sdk_volume_inspect=None,
                    create_argv=root_create,
                ),
            )
            run["host_preinspect"] = root_preinspect
            run["container_preinspect"] = root_container

        mutate_closure("root credential closure", root_credentials)

        def mutate_preinspect(label: str, mutation: Any) -> None:
            attacked_content = copy.deepcopy(package_run["host_preinspect"]["content"])
            mutation(attacked_content)
            attacked_root = content_addressed_root(PREINSPECT_SCHEMA, attacked_content)
            expect_failure(
                label,
                lambda: validate_host_preinspect(
                    attacked_root,
                    source_commit=source_commit,
                    challenge=challenge,
                    expect_mode="package",
                ),
            )

        mutate_preinspect(
            "boolean uid",
            lambda value: value["contract"].__setitem__("uid", True),
        )
        mutate_preinspect(
            "zero gid",
            lambda value: value["contract"].__setitem__("gid", 0),
        )
        mutate_preinspect(
            "boolean gid",
            lambda value: value["contract"].__setitem__("gid", True),
        )

        attacked_container = copy.deepcopy(package_run["container_preinspect"])
        attacked_container["HostConfig"]["Privileged"] = True
        expect_failure(
            "privileged",
            lambda: validate_container_inspect(
                attacked_container,
                package_run["host_preinspect"]["content"]["contract"],
                image,
                "attacked",
                phase="created",
            ),
        )

        alternate_defaults = copy.deepcopy(package_run["container_preinspect"])
        alternate_defaults["HostConfig"]["RestartPolicy"]["Name"] = ""
        alternate_defaults["HostConfig"]["Init"] = False
        validate_container_inspect(
            alternate_defaults,
            package_run["host_preinspect"]["content"]["contract"],
            image,
            "alternate defaults",
            phase="created",
        )
        for label, mutate in (
            (
                "added capability",
                lambda value: value["HostConfig"].__setitem__("CapAdd", ["SYS_ADMIN"]),
            ),
            (
                "device",
                lambda value: value["HostConfig"].__setitem__(
                    "Devices", [{"PathOnHost": "/dev/null"}]
                ),
            ),
            (
                "network",
                lambda value: value["HostConfig"].__setitem__("NetworkMode", "bridge"),
            ),
            (
                "host PID namespace",
                lambda value: value["HostConfig"].__setitem__("PidMode", "host"),
            ),
            (
                "host IPC namespace",
                lambda value: value["HostConfig"].__setitem__("IpcMode", "host"),
            ),
            (
                "host UTS namespace",
                lambda value: value["HostConfig"].__setitem__("UTSMode", "host"),
            ),
            (
                "host user namespace",
                lambda value: value["HostConfig"].__setitem__("UsernsMode", "host"),
            ),
            (
                "restart always",
                lambda value: value["HostConfig"]["RestartPolicy"].__setitem__(
                    "Name", "always"
                ),
            ),
            (
                "restart retry",
                lambda value: value["HostConfig"]["RestartPolicy"].__setitem__(
                    "MaximumRetryCount", 1
                ),
            ),
            (
                "DNS server",
                lambda value: value["HostConfig"].__setitem__("Dns", ["192.0.2.53"]),
            ),
            (
                "DNS option",
                lambda value: value["HostConfig"].__setitem__("DnsOptions", ["use-vc"]),
            ),
            (
                "DNS search",
                lambda value: value["HostConfig"].__setitem__(
                    "DnsSearch", ["example.invalid"]
                ),
            ),
            (
                "extra host",
                lambda value: value["HostConfig"].__setitem__(
                    "ExtraHosts", ["escape:192.0.2.1"]
                ),
            ),
            (
                "auto remove",
                lambda value: value["HostConfig"].__setitem__("AutoRemove", True),
            ),
            (
                "init process",
                lambda value: value["HostConfig"].__setitem__("Init", True),
            ),
            (
                "GroupAdd",
                lambda value: value["HostConfig"].__setitem__("GroupAdd", [str(gid)]),
            ),
            (
                "writable target marked read-only",
                lambda value: next(
                    record
                    for record in value["HostConfig"]["Mounts"]
                    if record["Target"] == str(CONTAINER_TARGET)
                ).__setitem__("ReadOnly", True),
            ),
            (
                "writable target null access",
                lambda value: next(
                    record
                    for record in value["HostConfig"]["Mounts"]
                    if record["Target"] == str(CONTAINER_TARGET)
                ).__setitem__("ReadOnly", None),
            ),
            (
                "read-only source access omitted",
                lambda value: next(
                    record
                    for record in value["HostConfig"]["Mounts"]
                    if record["Target"] == str(CONTAINER_SOURCE)
                ).pop("ReadOnly"),
            ),
            (
                "extra environment",
                lambda value: value["Config"]["Env"].append("EVIL=1"),
            ),
            ("dead state", lambda value: value["State"].__setitem__("Dead", True)),
            ("paused state", lambda value: value["State"].__setitem__("Paused", True)),
            (
                "restarting state",
                lambda value: value["State"].__setitem__("Restarting", True),
            ),
            ("state error", lambda value: value["State"].__setitem__("Error", "boom")),
            ("live PID", lambda value: value["State"].__setitem__("Pid", 123)),
            ("boolean PID", lambda value: value["State"].__setitem__("Pid", False)),
            ("OOM killed", lambda value: value["State"].__setitem__("OOMKilled", True)),
            (
                "string OOM state",
                lambda value: value["State"].__setitem__("OOMKilled", "false"),
            ),
            (
                "nonzero state exit",
                lambda value: value["State"].__setitem__("ExitCode", 1),
            ),
            (
                "boolean state exit",
                lambda value: value["State"].__setitem__("ExitCode", False),
            ),
        ):
            attacked = copy.deepcopy(package_run["container_preinspect"])
            mutate(attacked)
            expect_failure(
                label,
                lambda attacked=attacked: validate_container_inspect(
                    attacked,
                    package_run["host_preinspect"]["content"]["contract"],
                    image,
                    "attacked",
                    phase="created",
                ),
            )
        for destination in (
            str(CONTAINER_SOURCE),
            str(CONTAINER_SDK),
            str(CONTAINER_GIT_CONFIG),
            str(CONTAINER_PREINSPECT),
        ):
            attacked = copy.deepcopy(package_run["container_preinspect"])
            record = next(
                item
                for item in attacked["Mounts"]
                if item["Destination"] == destination
            )
            record["RW"] = True
            expect_failure(
                f"rw mount {destination}",
                lambda attacked=attacked: validate_container_inspect(
                    attacked,
                    package_run["host_preinspect"]["content"]["contract"],
                    image,
                    "attacked",
                    phase="created",
                ),
            )
        attacked_witness = copy.deepcopy(
            package_run["attestation"]["content"]["witness"]
        )
        attacked_witness["interfaces"] = ["eth0", "lo"]
        expect_failure(
            "guest interface",
            lambda: validate_witness(attacked_witness, package_run["host_preinspect"]),
        )
        attacked_witness = copy.deepcopy(
            package_run["attestation"]["content"]["witness"]
        )
        attacked_witness["hostname"] = "forged"
        expect_failure(
            "guest hostname",
            lambda: validate_witness(attacked_witness, package_run["host_preinspect"]),
        )
        attacked_witness = copy.deepcopy(
            package_run["attestation"]["content"]["witness"]
        )
        attacked_witness["status_raw"] = attacked_witness["status_raw"].replace(
            f"Groups:\t{gid}\n", "Groups:\t\n"
        )
        attacked_witness["credentials"] = parse_status(attacked_witness["status_raw"])
        expect_failure(
            "missing probed primary group",
            lambda: validate_witness(attacked_witness, package_run["host_preinspect"]),
        )

        source_raw = stable_regular_bytes(source_path, "selftest source envelope")
        attacked_source_content = copy.deepcopy(source_root["content"])
        attacked_source_content["git"]["declared_container_digest"] = IMAGE_DIGEST
        attacked_source = content_addressed_root(SOURCE_SCHEMA, attacked_source_content)
        try:
            source_path.chmod(0o644)
            source_path.write_bytes(canonical_json(attacked_source) + b"\n")
            source_path.chmod(0o444)
            expect_failure(
                "source old declared-container provenance",
                lambda: load_source_envelope(source, source_commit, challenge),
            )
        finally:
            source_path.chmod(0o644)
            source_path.write_bytes(source_raw)
            source_path.chmod(0o444)

        def mutate_build(label: str, mutation: Any) -> None:
            attacked_content = copy.deepcopy(build_root["content"])
            mutation(attacked_content)
            attacked_root = content_addressed_root(
                BUILD_SCHEMA, attacked_content, version=2
            )
            expect_failure(
                label,
                lambda: validate_build_envelope(
                    attacked_root,
                    source_root,
                    source_commit,
                    challenge,
                    source_root=source,
                    artifact_root=artifact_root,
                ),
            )

        mutate_build(
            "build extra content field",
            lambda value: value.__setitem__("unclosed", True),
        )
        mutate_build(
            "build source field removed",
            lambda value: value["source"].pop("materialization"),
        )
        mutate_build(
            "build forged command",
            lambda value: value.__setitem__("command", ["curl", "example.invalid"]),
        )
        mutate_build(
            "build extra artifact role",
            lambda value: value["artifacts"].__setitem__(
                "unclosed", copy.deepcopy(value["artifacts"]["kernel_binary"])
            ),
        )
        mutate_build(
            "build forged artifact path",
            lambda value: value["artifacts"]["kernel_binary"].__setitem__(
                "path", "/evil/vibeos-milkv-duo.bin"
            ),
        )
        mutate_build(
            "build extra tool role",
            lambda value: value["tools"].__setitem__(
                "unclosed", copy.deepcopy(value["tools"]["build_script"])
            ),
        )
        mutate_build(
            "build forged environment",
            lambda value: value["environment"]["values"].__setitem__(
                "CARGO_NET_OFFLINE", "false"
            ),
        )
        mutate_build(
            "build forged derived run id",
            lambda value: value.__setitem__("run_id", "0" * 64),
        )
        mutate_build(
            "build empty timestamps",
            lambda value: value.__setitem__("timestamps_utc", {}),
        )

        def mutate_package(label: str, mutation: Any) -> None:
            attacked_content = copy.deepcopy(package_root["content"])
            mutation(attacked_content)
            attacked_root = content_addressed_root(
                PACKAGE_SCHEMA, attacked_content, version=2
            )
            expect_failure(
                label,
                lambda: validate_package_envelope(
                    attacked_root,
                    package_attestation=package_run["attestation"],
                    source_envelope=source_root,
                    build_root=build_root,
                    build_identity=build_identity,
                    image_id=image["Id"],
                    source_commit=source_commit,
                    challenge=challenge,
                    source_root=source,
                    artifact_root=artifact_root,
                ),
            )

        mutate_package(
            "package extra content field",
            lambda value: value.__setitem__("unclosed", True),
        )
        mutate_package(
            "package source root",
            lambda value: value["source"].__setitem__("root", "."),
        )
        mutate_package(
            "package missing runtime attestation",
            lambda value: value.pop("runtime_attestation"),
        )
        mutate_package(
            "package extra artifact role",
            lambda value: value["artifacts"].__setitem__(
                "unclosed", copy.deepcopy(value["artifacts"]["kernel_binary"])
            ),
        )
        mutate_package(
            "package forged artifact path",
            lambda value: value["artifacts"]["kernel_binary"].__setitem__(
                "path", "/evil/vibeos-milkv-duo.bin"
            ),
        )
        mutate_package(
            "package extra tool role",
            lambda value: value["tools"].__setitem__(
                "unclosed", copy.deepcopy(value["tools"]["package_script"])
            ),
        )
        mutate_package(
            "package forged command",
            lambda value: value.__setitem__("command", ["curl"]),
        )
        mutate_package(
            "package forged build path",
            lambda value: value["build"]["envelope"].__setitem__(
                "path", "/evil/build-envelope.json"
            ),
        )
        mutate_package(
            "package boolean verifier exit",
            lambda value: value["verifier"].__setitem__("exit_code", False),
        )
        mutate_package(
            "package forged verifier marker",
            lambda value: value["verifier"].__setitem__("exact_pass_marker", "forged"),
        )
        mutate_package(
            "package forged verifier invocation",
            lambda value: value["verifier"].__setitem__("invocation", ["curl"]),
        )
        mutate_package(
            "package forged environment",
            lambda value: value["environment"]["image_verifier"]["values"].__setitem__(
                "PATH", "/evil"
            ),
        )
        mutate_package(
            "package empty timestamps",
            lambda value: value.__setitem__("timestamps_utc", {}),
        )
        expect_failure(
            "duplicate JSON", lambda: strict_json(b'{"x":1,"x":2}', "duplicate fixture")
        )
        expect_failure(
            "nonfinite JSON", lambda: strict_json(b'{"x":NaN}', "nonfinite fixture")
        )
        expect_failure("malformed mountinfo", lambda: parse_mountinfo("1 1 broken\n"))
        expect_failure(
            "no-clobber",
            lambda: write_no_clobber(closure_path, closure, "replacement closure"),
        )
        old = {
            "container_digest_provenance": "operator-declared; runtime container identity not attested"
        }
        require(
            contains_old_provenance(old), "selftest old provenance detector is inert"
        )
        create = package_run["operations"]["create"]
        require(
            create[:5] == ["create", "--pull", "never", "--platform", PLATFORM]
            and ["--network", "none"] == create[5:7]
            and "--cap-drop" in create
            and "--security-opt" in create
            and IMAGE_REFERENCE in create,
            "selftest Docker create command is not closed",
        )
        print("c84-docker-runtime.py selftest: PASS")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run Docker/network/device-free synthetic mutation tests",
    )
    subparsers = parser.add_subparsers(dest="operation")
    launch = subparsers.add_parser(
        "launch-package", help="run package then an independent verifier container"
    )
    launch.add_argument("--source", type=pathlib.Path, required=True)
    launch.add_argument("--source-commit", required=True)
    launch.add_argument("--challenge", required=True)
    sdk = launch.add_mutually_exclusive_group(required=True)
    sdk.add_argument("--sdk-root", type=pathlib.Path)
    sdk.add_argument("--sdk-volume")
    guest = subparsers.add_parser(
        "guest-package", help="private in-container entrypoint"
    )
    guest.add_argument("--host-preinspect", type=pathlib.Path, required=True)
    guest.add_argument("--source-commit", required=True)
    guest.add_argument("--challenge", required=True)
    guest.add_argument("--mode", choices=("package", "verify"), required=True)
    attestation = subparsers.add_parser(
        "verify-attestation", help="semantically verify a live runtime attestation"
    )
    attestation.add_argument("--attestation", type=pathlib.Path, required=True)
    attestation.add_argument("--source-root", type=pathlib.Path, required=True)
    attestation.add_argument("--source-commit", required=True)
    attestation.add_argument("--challenge", required=True)
    attestation.add_argument(
        "--expect-mode", choices=("package", "verify"), required=True
    )
    verify = subparsers.add_parser(
        "verify", help="offline semantic verification of a published closure"
    )
    verify.add_argument("--closure", type=pathlib.Path, required=True)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--challenge", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(arguments)
    if options.selftest:
        require(
            options.operation is None, "--selftest does not accept a formal operation"
        )
        run_selftest()
        return 0
    require(options.operation is not None, "a formal operation is required")
    source_commit = canonical_commit(options.source_commit)
    challenge = canonical_challenge(options.challenge)
    if options.operation == "launch-package":
        launch_package(
            source=options.source,
            source_commit=source_commit,
            challenge=challenge,
            sdk_root=options.sdk_root,
            sdk_volume=options.sdk_volume,
        )
    elif options.operation == "guest-package":
        guest_package(options.host_preinspect, source_commit, challenge, options.mode)
    elif options.operation == "verify-attestation":
        verify_attestation_command(
            options.attestation,
            options.source_root,
            source_commit,
            challenge,
            options.expect_mode,
        )
        print(
            f"C8.4 Docker runtime attestation: PASS mode={options.expect_mode} source={source_commit} challenge={challenge}"
        )
    else:
        verify_closure_command(options.closure, source_commit, challenge)
        print(
            f"C8.4 Docker runtime closure verify: PASS source={source_commit} challenge={challenge} closure={options.closure}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeClosureError as error:
        print(f"c84-docker-runtime.py: {error}", file=sys.stderr)
        raise SystemExit(1) from error
