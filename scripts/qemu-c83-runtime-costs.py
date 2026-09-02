#!/usr/bin/env python3
"""Build, capture, and independently verify the fixed C8.3 QEMU baseline.

The default mode is a publication run: it requires a clean repository, binds
the current 40-hex HEAD and a fresh (or caller-supplied) 64-hex challenge into
the dedicated firmware image, boots the fixed single-hart QEMU/TCG contract,
and asks the independent verifier to apply its publication gates.

``--allow-dirty-smoke`` exists only for development.  It disables publication
gates and deliberately forbids exporting the transcript or summary, so a run
against uncommitted sources cannot later be mistaken for C8.3 evidence.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import NoReturn


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIRMWARE = ROOT / "firmware/qemu-virt"
KERNEL = ROOT / "target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt"
TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"
VERIFIER = ROOT / "scripts/verify-c83-runtime-costs.py"
EVIDENCE_CHECKER = ROOT / "scripts/verify-c83-evidence.py"

FEATURE = "wasm-c83-runtime-costs"
SOURCE_ENV = "VIBEOS_C83_SOURCE_COMMIT"
CHALLENGE_ENV = "VIBEOS_C83_CHALLENGE"
META_PREFIX = "VIBE_WASM_COST_META "
END_PREFIX = b"VIBE_WASM_COST_END "
FAILURE_MARKER = b"VIBE_WASM_COST_FAILED"

QEMU_MACHINE = "virt"
QEMU_CPU = "rv64"
QEMU_SMP = "1"
QEMU_MEMORY = "128M"
QEMU_ACCELERATOR = "tcg,thread=single"
QEMU_ICOUNT = "shift=0,align=off,sleep=off"
QEMU_BIOS_NAME = "opensbi-riscv64-generic-fw_dynamic.bin"

DEFAULT_TIMEOUT_SECONDS = 300.0
END_SETTLE_SECONDS = 0.25
MAX_TRANSCRIPT_BYTES = 32 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TEST_ONLY_SOURCE_COMMIT = "1" * 40
TEST_ONLY_CHALLENGE = "2" * 64
GIT_STATUS_COMMAND = [
    "git",
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--ignore-submodules=none",
]
GIT_STATUS_Z_COMMAND = [
    "git",
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
    "--ignore-submodules=none",
]
GIT_DIFF_COMMAND = [
    "git",
    "diff",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    "--ignore-submodules=none",
    "HEAD",
    "--",
]


class RunnerError(RuntimeError):
    """A closed C8.3 collection or verification step failed."""


def fail(message: str) -> NoReturn:
    raise RunnerError(message)


def reject_duplicate_json_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def strict_json_loads(value: str, label: str) -> object:
    try:
        return json.loads(value, object_pairs_hook=reject_duplicate_json_members)
    except json.JSONDecodeError as error:
        fail(f"invalid {label} JSON: {error}")


def positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not 1.0 <= parsed <= 3600.0:
        raise argparse.ArgumentTypeError("must be between 1 and 3600 seconds")
    return parsed


def boot_index(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return parsed


def canonical_hex(value: str, pattern: re.Pattern[str], length: int, label: str) -> str:
    if pattern.fullmatch(value) is None:
        fail(f"{label} must be canonical lowercase hexadecimal of length {length}")
    if not any(character != "0" for character in value):
        fail(f"{label} must not be the all-zero sentinel")
    return value


def run_text(command: list[str], *, cwd: pathlib.Path = ROOT) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot execute {command[0]}: {error}")
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        fail(f"{' '.join(command)} failed: {detail or f'exit {error.returncode}'}")
    return completed.stdout.strip()


def run_bytes(command: list[str], *, cwd: pathlib.Path = ROOT) -> bytes:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot execute {command[0]}: {error}")
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or b"").decode("utf-8", errors="replace")
        fail(
            f"{' '.join(command)} failed: {detail.strip() or f'exit {error.returncode}'}"
        )
    return completed.stdout


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_identity(path: pathlib.Path) -> dict[str, object]:
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat()
        if not resolved.is_file() or before.st_size <= 0:
            fail(f"identity input is not a nonempty regular file: {resolved}")
        value = resolved.read_bytes()
        after = resolved.stat()
    except OSError as error:
        fail(f"cannot read identity input {path}: {error}")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"identity input changed while hashing: {resolved}")
    if len(value) != before.st_size:
        fail(f"identity input size changed while reading: {resolved}")
    return {"sha256": sha256_bytes(value), "bytes": len(value)}


def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def git_head() -> str:
    head = run_text(["git", "rev-parse", "--verify", "HEAD"])
    return canonical_hex(head, HEX40, 40, "git HEAD")


def git_status() -> str:
    return run_text(GIT_STATUS_COMMAND)


def repository_attestation() -> dict[str, object]:
    status = run_bytes(GIT_STATUS_Z_COMMAND)
    diff = run_bytes(GIT_DIFF_COMMAND)
    return {
        "head": git_head(),
        "clean": not status and not diff,
        "status_command": GIT_STATUS_Z_COMMAND,
        "diff_command": GIT_DIFF_COMMAND,
        "status_porcelain_v1_z_sha256": sha256_bytes(status),
        "tracked_diff_head_binary_sha256": sha256_bytes(diff),
    }


def check_repository_state(source_commit: str, *, allow_dirty: bool) -> None:
    current = git_head()
    if current != source_commit:
        fail(f"repository HEAD changed during collection: {source_commit} -> {current}")
    dirty = git_status()
    if dirty and not allow_dirty:
        preview = "\n".join(dirty.splitlines()[:20])
        fail(f"formal publication requires a clean worktree:\n{preview}")


def toolchain_pin(toolchain_file: pathlib.Path | None = None) -> tuple[str, str]:
    selected = toolchain_file or TOOLCHAIN_FILE
    try:
        document = selected.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {selected}: {error}")
    channel = re.search(r'^channel = "([^"]+)"$', document, re.MULTILINE)
    commit = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", document, re.MULTILINE)
    if channel is None or commit is None:
        fail("rust-toolchain.toml must contain exact nightly channel and commit pins")
    return channel.group(1), commit.group(1)


def resolve_executable(name: str, label: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        fail(f"{label} was not found on PATH: {name}")
    path = pathlib.Path(resolved).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        fail(f"{label} is not an executable regular file: {path}")
    return str(path)


def linker_tool_record(path: str | pathlib.Path, label: str) -> dict[str, object]:
    """Bind both the selected ld.lld entry and the binary it resolves to."""
    invocation = pathlib.Path(os.path.abspath(os.fspath(path)))
    try:
        resolved = invocation.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label} entry {invocation}: {error}")
    if invocation.name != "ld.lld":
        fail(f"{label} entry is not named ld.lld: {invocation}")
    if not resolved.is_file() or not os.access(invocation, os.X_OK):
        fail(f"{label} is not an executable regular file: {invocation}")
    return {
        "invocation_path": str(invocation),
        "resolved_path": str(resolved),
        **file_identity(resolved),
    }


def resolve_linker(*, search_path: str | None = None) -> dict[str, object]:
    selected = shutil.which("ld.lld", path=search_path)
    if selected is None:
        fail("bare-metal linker was not found on PATH: ld.lld")
    return linker_tool_record(selected, "bare-metal linker")


def pinned_tool(rustup: str, channel: str, executable: str) -> str:
    resolved = run_text(
        [rustup, "which", "--toolchain", channel, executable]
    ).splitlines()
    if len(resolved) != 1:
        fail(f"rustup returned no pinned {executable} for {channel}")
    path = pathlib.Path(resolved[0]).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        fail(f"pinned {executable} is not an executable regular file: {path}")
    return str(path)


def tool_record(path: str) -> dict[str, object]:
    return {"path": path, **file_identity(pathlib.Path(path))}


def minimal_build_path(rustup: str, linker: str) -> list[str]:
    entries: list[str] = []
    for entry in (
        str(pathlib.Path(linker).parent),
        str(pathlib.Path(rustup).parent),
        "/usr/bin",
        "/bin",
    ):
        if entry not in entries:
            entries.append(entry)
    return entries


def ambient_cargo_home() -> pathlib.Path:
    configured = os.environ.get("CARGO_HOME")
    candidate = pathlib.Path(configured) if configured else pathlib.Path.home() / ".cargo"
    try:
        return candidate.expanduser().resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve the Cargo cache home {candidate}: {error}")


def link_offline_cargo_caches(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir(mode=0o700)
    for name in ("registry", "git"):
        cache = source / name
        if cache.exists():
            try:
                os.symlink(cache, destination / name, target_is_directory=True)
            except OSError as error:
                fail(f"cannot link the offline Cargo {name} cache: {error}")


def strict_tree_identity(path: pathlib.Path, label: str) -> dict[str, object]:
    """Hash one directory tree including names, types, modes, and file bytes."""

    try:
        requested = pathlib.Path(os.path.abspath(os.fspath(path)))
        requested_metadata = requested.lstat()
        if stat.S_ISLNK(requested_metadata.st_mode):
            fail(f"{label} root cannot itself be a symbolic link: {requested}")
        root = requested.resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as error:
        fail(f"cannot resolve {label} tree {path}: {error}")
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        fail(f"{label} root is not one regular directory: {root}")
    entries: list[tuple[bytes, str, pathlib.Path, os.stat_result]] = []
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        base = pathlib.Path(directory)
        for name in (*directory_names, *filenames):
            candidate = base / name
            try:
                metadata = candidate.lstat()
                relative = candidate.relative_to(root).as_posix()
                encoded = relative.encode("utf-8", errors="strict")
            except (OSError, UnicodeError, ValueError) as error:
                fail(f"cannot inventory {label} entry {candidate}: {error}")
            if stat.S_ISDIR(metadata.st_mode):
                kind = "d"
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    fail(f"{label} file has multiple links: {relative}")
                kind = "f"
            else:
                fail(f"{label} contains a link or special entry: {relative}")
            entries.append((encoded, kind, candidate, metadata))
    digest = hashlib.sha256()
    files = 0
    directories = 1
    byte_count = 0
    root_mode = stat.S_IMODE(root_metadata.st_mode)
    digest.update((f"d\0.\0{root_mode:04o}\0" + "0\0-\n").encode("ascii"))
    for _, kind, candidate, opened_metadata in sorted(entries, key=lambda item: item[0]):
        relative = candidate.relative_to(root).as_posix()
        mode = stat.S_IMODE(opened_metadata.st_mode)
        if kind == "d":
            directories += 1
            size = 0
            content_digest = "-"
        else:
            file_digest = hashlib.sha256()
            size = 0
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
            try:
                descriptor = os.open(candidate, flags)
                try:
                    before = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1
                        or before.st_dev != opened_metadata.st_dev
                        or before.st_ino != opened_metadata.st_ino
                    ):
                        fail(f"{label} file changed before hashing: {relative}")
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        file_digest.update(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as error:
                fail(f"cannot hash {label} file {relative}: {error}")
            if (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or size != after.st_size:
                fail(f"{label} file changed while hashing: {relative}")
            content_digest = file_digest.hexdigest()
            files += 1
            byte_count += size
        digest.update(
            (
                f"{kind}\0{relative}\0{mode:04o}\0{size}\0"
                f"{content_digest}\n"
            ).encode("utf-8")
        )
    return {
        "policy": "strict-tree-content-mode-v1",
        "sha256": digest.hexdigest(),
        "files": files,
        "directories": directories,
        "bytes": byte_count,
    }


def canonical_direct_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    """Resolve a directory while rejecting an alias at the supplied leaf."""

    try:
        requested = pathlib.Path(os.path.abspath(os.fspath(path)))
        metadata = requested.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} must be one direct non-link directory: {requested}")
        return requested.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label} {path}: {error}")


def private_cargo_home_identity(
    cargo_home: pathlib.Path, generated_config: dict[str, object]
) -> dict[str, object]:
    """Require the private Cargo home to contain exactly its immutable config."""

    try:
        requested = pathlib.Path(os.path.abspath(os.fspath(cargo_home)))
        requested_metadata = requested.lstat()
        if stat.S_ISLNK(requested_metadata.st_mode):
            fail(f"private Cargo home cannot itself be a symbolic link: {requested}")
        root = requested.resolve(strict=True)
        root_metadata = root.lstat()
        entries = tuple(root.iterdir())
    except OSError as error:
        fail(f"cannot inspect private Cargo home {cargo_home}: {error}")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail(f"private Cargo home is not a directory: {root}")
    if stat.S_IMODE(root_metadata.st_mode) != 0o700:
        fail("private Cargo home must have mode 0700")
    if [entry.name for entry in entries] != ["config.toml"]:
        fail("private Cargo home must contain exactly config.toml")
    config = entries[0]
    try:
        metadata = config.lstat()
    except OSError as error:
        fail(f"cannot inspect private Cargo configuration: {error}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        fail("private Cargo configuration must be one 0400 regular file")
    current = {"path": "<private-cargo-home>/config.toml", **file_identity(config)}
    if current != generated_config:
        fail("private Cargo configuration differs from its generated identity")
    return {
        "policy": "exact-private-cargo-home-config-only-v1",
        "root_mode": "0700",
        "entries": [
            {
                **current,
                "mode": "0400",
                "links": 1,
            }
        ],
    }


def read_direct_regular(path: pathlib.Path, label: str, expected_size: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != expected_size
            ):
                fail(f"{label} is not one exact-size regular file")
            chunks: list[bytes] = []
            remaining = expected_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    fail(f"{label} ended before its recorded size")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                fail(f"{label} exceeds its recorded size")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        fail(f"{label} changed while being read")
    return b"".join(chunks)


def remove_private_cargo_transient_outputs(cargo_home: pathlib.Path) -> dict[str, object]:
    """Validate, record, then remove Cargo outputs that were proven absent pre-build."""

    tag_raw = (
        b"Signature: 8a477f597d28d172789f06886806bc55\n"
        b"# This file is a cache directory tag created by cargo.\n"
        b"# For information about cache directory tags see "
        b"https://bford.info/cachedir/\n"
    )
    try:
        root = pathlib.Path(os.path.abspath(os.fspath(cargo_home))).resolve(strict=True)
        observed = {candidate.name: candidate for candidate in root.iterdir()}
        expected = {
            "config.toml",
            ".global-cache",
            ".package-cache",
            ".package-cache-mutate",
            "registry",
        }
        if set(observed) != expected:
            fail(
                "private Cargo home post-build entry set differs: "
                f"expected {sorted(expected)}, got {sorted(observed)}"
            )
        package_cache = observed[".package-cache"]
        package_metadata = package_cache.lstat()
        if (
            not stat.S_ISREG(package_metadata.st_mode)
            or package_metadata.st_nlink != 1
            or stat.S_IMODE(package_metadata.st_mode) != 0o600
            or package_metadata.st_size != 0
        ):
            fail("private Cargo .package-cache output differs")
        if read_direct_regular(package_cache, "private Cargo .package-cache", 0):
            fail("private Cargo .package-cache is not empty")
        package_cache_mutate = observed[".package-cache-mutate"]
        mutate_metadata = package_cache_mutate.lstat()
        if (
            not stat.S_ISREG(mutate_metadata.st_mode)
            or mutate_metadata.st_nlink != 1
            or stat.S_IMODE(mutate_metadata.st_mode) != 0o600
            or mutate_metadata.st_size != 0
        ):
            fail("private Cargo .package-cache-mutate output differs")
        if read_direct_regular(
            package_cache_mutate, "private Cargo .package-cache-mutate", 0
        ):
            fail("private Cargo .package-cache-mutate is not empty")
        global_cache = observed[".global-cache"]
        global_metadata = global_cache.lstat()
        if stat.S_IMODE(global_metadata.st_mode) != 0o600:
            fail("private Cargo .global-cache mode differs")
        global_raw = read_direct_regular(
            global_cache, "private Cargo .global-cache", 57_344
        )
        global_sha256 = hashlib.sha256(global_raw).hexdigest()
        if not (
            global_raw[:16] == b"SQLite format 3\0"
            and int.from_bytes(global_raw[16:18], "big") == 4096
            and global_raw[18:24] == b"\x01\x01\x00\x40\x20\x20"
            and int.from_bytes(global_raw[28:32], "big") == 14
            and global_raw[32:40] == b"\0" * 8
            and int.from_bytes(global_raw[44:48], "big") == 4
            and global_raw[48:56] == b"\0" * 8
            and int.from_bytes(global_raw[56:60], "big") == 1
            and int.from_bytes(global_raw[60:64], "big") == 7
            and int.from_bytes(global_raw[96:100], "big") == 3_053_002
        ):
            fail("private Cargo .global-cache SQLite header differs")
        if (
            global_sha256
            != "66d946720de0afd44c2d5748698b700ce812830bd8a3dedaa589831610948d9d"
        ):
            fail("private Cargo .global-cache deterministic identity differs")
        registry = observed["registry"]
        registry_metadata = registry.lstat()
        if (
            not stat.S_ISDIR(registry_metadata.st_mode)
            or stat.S_ISLNK(registry_metadata.st_mode)
            or stat.S_IMODE(registry_metadata.st_mode) != 0o700
        ):
            fail("private Cargo registry output directory differs")
        registry_entries = tuple(registry.iterdir())
        if [entry.name for entry in registry_entries] != ["CACHEDIR.TAG"]:
            fail("private Cargo registry output entry set differs")
        tag = registry_entries[0]
        tag_metadata = tag.lstat()
        if stat.S_IMODE(tag_metadata.st_mode) != 0o600:
            fail("private Cargo registry CACHEDIR.TAG mode differs")
        observed_tag = read_direct_regular(
            tag, "private Cargo registry CACHEDIR.TAG", len(tag_raw)
        )
        if observed_tag != tag_raw:
            fail("private Cargo registry CACHEDIR.TAG bytes differ")
        record = {
            "policy": "fresh-pinned-cargo-runtime-outputs-validated-recorded-removed-v1",
            "precondition": "private-home-config-only-before-cargo",
            "entries": [
                {
                    "path": "<private-cargo-home>/.global-cache",
                    "kind": "sqlite3-global-cache",
                    "mode": "0600",
                    "links": 1,
                    "sha256": global_sha256,
                    "bytes": len(global_raw),
                    "header": {
                        "magic": "SQLite format 3 NUL",
                        "page_size": 4096,
                        "write_version": 1,
                        "read_version": 1,
                        "database_pages": 14,
                        "schema_format": 4,
                        "encoding": 1,
                        "user_version": 7,
                        "sqlite_version": 3_053_002,
                    },
                },
                {
                    "path": "<private-cargo-home>/.package-cache",
                    "kind": "empty-advisory-lock",
                    "mode": "0600",
                    "links": 1,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "bytes": 0,
                },
                {
                    "path": "<private-cargo-home>/.package-cache-mutate",
                    "kind": "empty-advisory-lock",
                    "mode": "0600",
                    "links": 1,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "bytes": 0,
                },
                {
                    "path": "<private-cargo-home>/registry",
                    "kind": "directory",
                    "mode": "0700",
                    "entries": [
                        {
                            "path": "<private-cargo-home>/registry/CACHEDIR.TAG",
                            "kind": "cargo-cache-directory-tag",
                            "mode": "0600",
                            "links": 1,
                            "sha256": hashlib.sha256(tag_raw).hexdigest(),
                            "bytes": len(tag_raw),
                        }
                    ],
                },
            ],
        }
        # Nothing is removed until the complete exact output set has passed.
        tag.unlink()
        registry.rmdir()
        global_cache.unlink()
        package_cache.unlink()
        package_cache_mutate.unlink()
        descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot remove validated private Cargo transient outputs: {error}")
    return record


def root_cargo_config_absence() -> dict[str, object]:
    candidates = (pathlib.Path("/.cargo/config"), pathlib.Path("/.cargo/config.toml"))
    present = [str(path) for path in candidates if os.path.lexists(path)]
    if present:
        fail(f"Cargo filesystem-root configuration is present: {present}")
    return {
        "cwd": "/",
        "candidates": [str(path) for path in candidates],
        "all_absent": True,
    }


def generated_cargo_config(
    firmware_config: pathlib.Path, private_sources: pathlib.Path
) -> tuple[bytes, dict[str, object]]:
    try:
        metadata = firmware_config.lstat()
        raw = firmware_config.read_bytes()
    except OSError as error:
        fail(f"cannot read materialized firmware Cargo config: {error}")
    if not stat.S_ISREG(metadata.st_mode) or firmware_config.is_symlink():
        fail("materialized firmware Cargo config is not a regular file")
    if not raw.endswith(b"\n"):
        fail("materialized firmware Cargo config must end with one newline")
    try:
        private_text = str(private_sources).encode("utf-8", errors="strict")
    except UnicodeError as error:
        fail(f"private Cargo source path is not UTF-8: {error}")
    if any(byte < 0x20 or byte in (0x22, 0x5C, 0x7F) for byte in private_text):
        fail("private Cargo source path cannot be encoded as a literal TOML string")
    suffix = (
        b"\n[cache]\n"
        b'auto-clean-frequency = "never"\n\n'
        b"[source.crates-io]\n"
        b'replace-with = "vibeos-c84-private"\n\n'
        b"[source.vibeos-c84-private]\n"
        + b'directory = "'
        + private_text
        + b'"\n'
    )
    generated = raw + suffix
    return generated, {
        "path": "firmware/.cargo/config.toml",
        **file_identity(firmware_config),
    }


def build_kernel(
    source_commit: str,
    challenge: str,
    *,
    firmware: pathlib.Path | None = None,
    toolchain_file: pathlib.Path | None = None,
    cargo_target_dir: pathlib.Path | None = None,
    kernel_path: pathlib.Path | None = None,
    commit_timestamp: str | None = None,
    private_cargo_home: pathlib.Path | None = None,
    private_cargo_sources: pathlib.Path | None = None,
    private_crate_archives: pathlib.Path | None = None,
    private_cargo_record: dict[str, object] | None = None,
    expected_toolchain_tree: dict[str, object] | None = None,
    expected_rust_src: dict[str, object] | None = None,
    formal_rustup_home: pathlib.Path | None = None,
    formal_host_triple: str | None = None,
    formal_rustup_path: pathlib.Path | None = None,
) -> dict[str, object]:
    selected_firmware = firmware or FIRMWARE
    selected_kernel = kernel_path or KERNEL
    channel, expected_rustc = toolchain_pin(toolchain_file)
    formal_values = (
        private_cargo_home,
        private_cargo_sources,
        private_crate_archives,
        private_cargo_record,
        expected_toolchain_tree,
        expected_rust_src,
        formal_rustup_home,
        formal_host_triple,
        formal_rustup_path,
    )
    formal_private_build = any(value is not None for value in formal_values)
    if formal_private_build and not all(value is not None for value in formal_values):
        fail("formal private Cargo build options must be supplied together")
    if formal_private_build:
        assert expected_toolchain_tree is not None
        assert expected_rust_src is not None
        assert formal_rustup_home is not None
        assert formal_host_triple is not None
        assert formal_rustup_path is not None
        if re.fullmatch(r"[A-Za-z0-9_-]+", formal_host_triple) is None:
            fail("formal Rust host triple is not canonical")
        try:
            fixed_rustup_home = canonical_direct_directory(
                formal_rustup_home, "formal RUSTUP_HOME"
            )
            toolchain_root = (
                fixed_rustup_home
                / "toolchains"
                / f"{channel}-{formal_host_triple}"
            )
            toolchain_before = strict_tree_identity(
                toolchain_root, "pinned Rust toolchain"
            )
        except OSError as error:
            fail(f"cannot derive the formal Rust toolchain: {error}")
        if toolchain_before != expected_toolchain_tree:
            fail("pinned Rust toolchain tree differs from the frozen contract")
        toolchain_root = toolchain_root.resolve(strict=True)
        rust_src = toolchain_root / "lib/rustlib/src/rust/library"
        rust_src_before = strict_tree_identity(rust_src, "pinned rust-src library")
        if rust_src_before != expected_rust_src:
            fail("pinned rust-src library differs from the frozen contract")
        fixed_tools: dict[str, str] = {}
        for name in ("cargo", "rustc", "rustdoc"):
            candidate = toolchain_root / "bin" / name
            try:
                metadata = candidate.lstat()
            except OSError as error:
                fail(f"cannot inspect formal pinned {name}: {error}")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or not os.access(candidate, os.X_OK)
            ):
                fail(f"formal pinned {name} is not a direct executable file")
            fixed_tools[name] = str(candidate)
        cargo_path = fixed_tools["cargo"]
        rustc_path = fixed_tools["rustc"]
        rustdoc_path = fixed_tools["rustdoc"]
        try:
            rustup_candidate = pathlib.Path(
                os.path.abspath(os.fspath(formal_rustup_path))
            ).resolve(strict=True)
            rustup_metadata = rustup_candidate.lstat()
        except OSError as error:
            fail(f"cannot inspect statically recorded rustup: {error}")
        if (
            not stat.S_ISREG(rustup_metadata.st_mode)
            or stat.S_ISLNK(rustup_metadata.st_mode)
            or not os.access(rustup_candidate, os.X_OK)
        ):
            fail("statically recorded rustup is not an executable regular file")
        rustup_path = str(rustup_candidate)
    else:
        rustup_path = resolve_executable("rustup", "rustup")
        cargo_path = pinned_tool(rustup_path, channel, "cargo")
        rustc_path = pinned_tool(rustup_path, channel, "rustc")
        rustdoc_path = pinned_tool(rustup_path, channel, "rustdoc")
        toolchain_root = pathlib.Path(cargo_path).parent.parent.resolve(strict=True)
        toolchain_before = None
        rust_src = None
        rust_src_before = None
    linker = resolve_linker()
    linker_path = str(linker["invocation_path"])
    linker_resolved_path = str(linker["resolved_path"])
    tool_records = {
        "rustup": tool_record(rustup_path),
        "cargo": tool_record(cargo_path),
        "rustc": tool_record(rustc_path),
        "rustdoc": tool_record(rustdoc_path),
        "linker": linker,
    }
    # In formal mode the complete toolchain and rust-src trees were attested
    # before this first Rust-tool execution. Rustup is never executed there.
    version = run_text([rustc_path, "-Vv"])
    actual = re.search(r"^commit-hash: ([0-9a-f]{40})$", version, re.MULTILINE)
    if actual is None or actual.group(1) != expected_rustc:
        fail(
            "pinned rustc commit differs: "
            f"expected {expected_rustc}, got {actual.group(1) if actual else 'unavailable'}"
        )

    if formal_private_build:
        if cargo_target_dir is None:
            fail("formal private Cargo build requires a private target directory")
        selected_firmware = canonical_direct_directory(
            selected_firmware, "formal firmware root"
        )
        cargo_target_dir = canonical_direct_directory(
            cargo_target_dir, "formal Cargo target"
        )
        selected_kernel = pathlib.Path(
            os.path.abspath(os.fspath(selected_kernel))
        ).resolve(strict=False)
        try:
            selected_kernel.relative_to(cargo_target_dir)
        except ValueError:
            fail("formal kernel output must remain below the private target directory")
        manifest = (selected_firmware / "Cargo.toml").resolve(strict=True)
        firmware_config = (
            selected_firmware.parent / ".cargo/config.toml"
        ).resolve(strict=True)
        source_root = selected_firmware.parent.parent.resolve(strict=True)
        if not manifest.is_file() or not firmware_config.is_file():
            fail("formal private Cargo build is missing its materialized configuration")
        command = [
            cargo_path,
            "build",
            "--manifest-path",
            str(manifest),
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            FEATURE,
        ]
        normalized_command = [
            cargo_path,
            "build",
            "--manifest-path",
            "<materialized-source>/firmware/qemu-virt/Cargo.toml",
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            FEATURE,
        ]
    else:
        command = [
            rustup_path,
            "run",
            channel,
            "cargo",
            "build",
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            FEATURE,
        ]
        normalized_command = command
    print(f"C8.3: building dedicated {FEATURE} image", file=sys.stderr)
    # Cargo otherwise merges $CARGO_HOME/config.toml with the reviewed local
    # configuration. Use an ephemeral, config-free home that exposes only the
    # already-fetched registry/Git caches, and whitelist the complete build
    # environment. This closes ambient wrappers, rustflags, profile overrides,
    # source replacement, and target-directory overrides while retaining a
    # browser-free/offline build.
    source_cargo_home = None if formal_private_build else ambient_cargo_home()
    if formal_private_build:
        if commit_timestamp is None:
            fail("formal private Cargo build requires the attested commit timestamp")
        source_date_epoch = commit_timestamp
        rustup_home = None
    else:
        host_home = os.environ.get("HOME")
        if not host_home:
            fail("HOME is required for the sanitized Cargo build")
        rustup_home = str(
            pathlib.Path(
                os.environ.get(
                    "RUSTUP_HOME", str(pathlib.Path(host_home) / ".rustup")
                )
            ).expanduser().resolve(strict=True)
        )
        source_date_epoch = commit_timestamp or run_text(
            ["git", "show", "-s", "--format=%ct", source_commit]
        )
    if not source_date_epoch.isdigit() or int(source_date_epoch) <= 0:
        fail("preparation commit has no valid positive timestamp")
    path_entries = (
        [str(pathlib.Path(linker_path).parent), "/usr/bin", "/bin"]
        if formal_private_build
        else minimal_build_path(rustup_path, linker_path)
    )
    sanitized_linker = shutil.which("ld.lld", path=os.pathsep.join(path_entries))
    if (
        sanitized_linker is None
        or os.path.abspath(sanitized_linker) != linker_path
        or str(pathlib.Path(sanitized_linker).resolve(strict=True))
        != linker_resolved_path
    ):
        fail("sanitized build PATH does not resolve the recorded ld.lld first")
    temporary_root = pathlib.Path(os.environ.get("TMPDIR", "/tmp"))
    build_input_closure: dict[str, object] | None = None
    try:
        if formal_private_build:
            assert private_cargo_home is not None
            assert private_cargo_sources is not None
            assert private_crate_archives is not None
            assert private_cargo_record is not None
            assert expected_toolchain_tree is not None
            assert expected_rust_src is not None
            cargo_home = canonical_direct_directory(
                private_cargo_home, "private Cargo home"
            )
            private_sources = canonical_direct_directory(
                private_cargo_sources, "private Cargo sources"
            )
            private_archives = canonical_direct_directory(
                private_crate_archives, "private crate archives"
            )
            if stat.S_IMODE(cargo_home.lstat().st_mode) != 0o700:
                fail("private Cargo home must have mode 0700")
            if tuple(cargo_home.iterdir()):
                fail("private Cargo home must begin empty")
            expected_private_tree = private_cargo_record.get("tree")
            private_before = strict_tree_identity(
                private_sources, "private Cargo registry sources"
            )
            archives_before = strict_tree_identity(
                private_archives, "private crate archives"
            )
            if private_before != expected_private_tree:
                fail("private Cargo source tree differs from its lock attestation")
            for tool in (cargo_path, rustc_path, rustdoc_path):
                try:
                    pathlib.Path(tool).relative_to(toolchain_root)
                except ValueError:
                    fail("pinned Rust tools do not share one toolchain root")
            assert toolchain_before is not None
            assert rust_src is not None
            assert rust_src_before is not None
            root_config_before = root_cargo_config_absence()
            generated, firmware_config_record = generated_cargo_config(
                firmware_config, private_sources
            )
            generated_path = cargo_home / "config.toml"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(generated_path, flags, 0o400)
            try:
                view = memoryview(generated)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail("cannot write private Cargo configuration")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            generated_record = {
                "path": "<private-cargo-home>/config.toml",
                **file_identity(generated_path),
            }
            cargo_home_before = private_cargo_home_identity(
                cargo_home, generated_record
            )
            isolated_home = cargo_home.parent / "cargo-build-home"
            isolated_tmp = cargo_home.parent / "cargo-build-tmp"
            isolated_home.mkdir(mode=0o700)
            isolated_tmp.mkdir(mode=0o700)
            environment = {
                "__CARGO_TEST_LAST_USE_NOW": "1234567890",
                "CARGO_HOME": str(cargo_home),
                "CARGO_INCREMENTAL": "0",
                "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_DIR": str(cargo_target_dir),
                "CARGO_TERM_COLOR": "never",
                "HOME": str(isolated_home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.pathsep.join(path_entries),
                "RUSTC": rustc_path,
                "RUSTDOC": rustdoc_path,
                "SOURCE_DATE_EPOCH": source_date_epoch,
                "TMPDIR": str(isolated_tmp),
                "TZ": "UTC",
                SOURCE_ENV: source_commit,
                CHALLENGE_ENV: challenge,
            }
            normalized_environment = dict(environment)
            normalized_environment["CARGO_HOME"] = "<private-cargo-home>"
            normalized_environment["CARGO_TARGET_DIR"] = "<private-target>"
            normalized_environment["HOME"] = "<private-build-home>"
            normalized_environment["TMPDIR"] = "<private-build-tmp>"
            completed = subprocess.run(
                command,
                cwd="/",
                env=environment,
                stdin=subprocess.DEVNULL,
                check=False,
                umask=0o077,
            )
            root_config_after = root_cargo_config_absence()
            transient_outputs = remove_private_cargo_transient_outputs(cargo_home)
            cargo_home_after = private_cargo_home_identity(
                cargo_home, generated_record
            )
            private_after = strict_tree_identity(
                private_sources, "private Cargo registry sources"
            )
            archives_after = strict_tree_identity(
                private_archives, "private crate archives"
            )
            toolchain_after = strict_tree_identity(
                toolchain_root, "pinned Rust toolchain"
            )
            rust_src_after = strict_tree_identity(rust_src, "pinned rust-src library")
            if private_after != private_before:
                fail("private Cargo source tree changed during build")
            if archives_after != archives_before:
                fail("private crate archives changed during build")
            if toolchain_after != toolchain_before:
                fail("pinned Rust toolchain changed during build")
            if rust_src_after != rust_src_before:
                fail("pinned rust-src library changed during build")
            if file_identity(generated_path) != {
                "sha256": generated_record["sha256"],
                "bytes": generated_record["bytes"],
            }:
                fail("private Cargo configuration changed during build")
            build_input_closure = {
                "policy": "c84-private-build-input-closure-v1",
                "normalized_paths": {
                    "policy": "canonical-realpath-no-leaf-symlink-v1",
                    "source_root": str(source_root),
                    "manifest": str(manifest),
                    "cargo_home": str(cargo_home),
                    "private_crate_sources": str(private_sources),
                    "private_crate_archives": str(private_archives),
                    "cargo_target": str(cargo_target_dir),
                    "toolchain_root": str(toolchain_root),
                    "rust_src": str(rust_src),
                },
                "cargo_locks": private_cargo_record["cargo_locks"],
                "private_crate_sources": {
                    **{
                        key: value
                        for key, value in private_cargo_record.items()
                        if key not in {"cargo_locks", "tree"}
                    },
                    "before": private_before,
                    "after": private_after,
                },
                "private_crate_archives": {
                    "root": str(private_archives),
                    "before": archives_before,
                    "after": archives_after,
                },
                "cargo_configuration": {
                    "discovery_policy": "filesystem-root-plus-private-cargo-home-v1",
                    "root_before": root_config_before,
                    "root_after": root_config_after,
                    "materialized_firmware": firmware_config_record,
                    "generated": generated_record,
                    "private_home_before": cargo_home_before,
                    "private_home_after": cargo_home_after,
                    "cargo_subprocess_umask": "0077",
                    "transient_outputs": transient_outputs,
                },
                "toolchain_tree": {
                    "root": str(toolchain_root),
                    "before": toolchain_before,
                    "after": toolchain_after,
                },
                "rust_src": {
                    "root": str(rust_src),
                    "relative_path": "lib/rustlib/src/rust/library",
                    "before": rust_src_before,
                    "after": rust_src_after,
                    "cargo_toml": file_identity(rust_src / "Cargo.toml"),
                    "cargo_lock": file_identity(rust_src / "Cargo.lock"),
                },
            }
        else:
            with tempfile.TemporaryDirectory(
                prefix="vibeos-c83-cargo-home-", dir=temporary_root
            ) as temporary_name:
                cargo_home = pathlib.Path(temporary_name) / "cargo-home"
                isolated_home = pathlib.Path(temporary_name) / "home"
                isolated_tmp = pathlib.Path(temporary_name) / "tmp"
                assert source_cargo_home is not None
                link_offline_cargo_caches(source_cargo_home, cargo_home)
                isolated_home.mkdir(mode=0o700)
                isolated_tmp.mkdir(mode=0o700)
                environment = {
                    "CARGO_HOME": str(cargo_home),
                    "CARGO_INCREMENTAL": "0",
                    "CARGO_NET_OFFLINE": "true",
                    "CARGO_TERM_COLOR": "never",
                    "HOME": str(isolated_home),
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": os.pathsep.join(path_entries),
                    "RUSTC": rustc_path,
                    "RUSTDOC": rustdoc_path,
                    "RUSTUP_HOME": rustup_home,
                    "SOURCE_DATE_EPOCH": source_date_epoch,
                    "TMPDIR": str(isolated_tmp),
                    "TZ": "UTC",
                    SOURCE_ENV: source_commit,
                    CHALLENGE_ENV: challenge,
                }
                if cargo_target_dir is not None:
                    environment["CARGO_TARGET_DIR"] = str(cargo_target_dir)
                normalized_environment = dict(environment)
                normalized_environment["CARGO_HOME"] = "<temporary-root>/cargo-home"
                normalized_environment["HOME"] = "<temporary-root>/home"
                normalized_environment["TMPDIR"] = "<temporary-root>/tmp"
                if cargo_target_dir is not None:
                    normalized_environment["CARGO_TARGET_DIR"] = "<private-target>"
                completed = subprocess.run(
                    command,
                    cwd=selected_firmware,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    check=False,
                )
    except OSError as error:
        fail(f"cannot start sanitized pinned Cargo build: {error}")
    if completed.returncode != 0:
        fail(f"pinned Cargo build failed with exit {completed.returncode}")
    if not selected_kernel.is_file() or selected_kernel.stat().st_size == 0:
        fail(f"Cargo did not produce the expected kernel: {selected_kernel}")
    result = {
        "channel": channel,
        "pinned_rustc_commit": expected_rustc,
        "rustc_vv": version,
        "cargo_version": run_text([cargo_path, "-V"]),
        **tool_records,
        "cargo_command": normalized_command,
        "build_environment_policy": {
            "ambient_variables": "denied-by-default",
            "cargo_home": (
                "private-generated-config-directory-source-only"
                if formal_private_build
                else "ephemeral-config-free registry/git cache links only"
            ),
            "cargo_net_offline": True,
            "path_entries": path_entries,
            "allowed_names": sorted(environment),
            "normalized_values": normalized_environment,
        },
    }
    if build_input_closure is not None:
        result["build_input_closure"] = build_input_closure
    return result


def resolve_qemu(name: str) -> str:
    if os.sep in name:
        candidate = pathlib.Path(name)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            fail(f"QEMU binary is not executable: {candidate}")
        return str(candidate.resolve())
    resolved = shutil.which(name)
    if resolved is None:
        fail(f"QEMU binary was not found on PATH: {name}")
    return str(pathlib.Path(resolved).resolve())


def resolve_bios(qemu: str) -> pathlib.Path:
    search_output = run_text([qemu, "-L", "help"])
    candidates: set[pathlib.Path] = set()
    for line in search_output.splitlines():
        directory = pathlib.Path(line.strip())
        if directory.is_absolute():
            candidate = directory / QEMU_BIOS_NAME
            if candidate.is_file():
                candidates.add(candidate.resolve(strict=True))
    if len(candidates) != 1:
        rendered = ", ".join(str(path) for path in sorted(candidates)) or "none"
        fail(
            f"QEMU firmware search must resolve exactly one {QEMU_BIOS_NAME}; "
            f"found {rendered}"
        )
    return next(iter(candidates))


def qemu_command(qemu: str, bios: pathlib.Path) -> list[str]:
    # These values are intentionally constants, not command-line switches or
    # environment overrides: changing any one creates a different baseline.
    return [
        qemu,
        "-machine",
        QEMU_MACHINE,
        "-cpu",
        QEMU_CPU,
        "-smp",
        QEMU_SMP,
        "-m",
        QEMU_MEMORY,
        "-accel",
        QEMU_ACCELERATOR,
        "-icount",
        QEMU_ICOUNT,
        "-nographic",
        "-bios",
        str(bios),
        "-kernel",
        str(KERNEL),
    ]


def uart_tail(raw: bytes, lines: int = 100) -> str:
    decoded = raw.decode("utf-8", errors="replace").replace("\r", "\n")
    return "\n".join(decoded.splitlines()[-lines:])


def capture_failure(message: str, raw: bytes) -> NoReturn:
    tail = uart_tail(raw)
    suffix = f"\n--- QEMU UART tail ---\n{tail}" if tail else ""
    fail(message + suffix)


def complete_end_record(raw: bytes) -> bool:
    position = raw.find(END_PREFIX)
    if position < 0:
        return False
    return b"\n" in raw[position:] or b"\r" in raw[position:]


def transcript_failure(raw: bytes) -> str | None:
    lowered = raw.lower()
    if FAILURE_MARKER.lower() in lowered:
        return "guest emitted VIBE_WASM_COST_FAILED"
    if b"panic" in lowered:
        return "guest emitted panic output"
    if b"fatal" in lowered:
        return "guest emitted fatal output"
    return None


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2.0)


def capture_qemu(
    qemu: str, bios: pathlib.Path, timeout: float, transcript: pathlib.Path
) -> bytes:
    command = qemu_command(qemu, bios)
    print(
        "C8.3: booting fixed QEMU contract "
        f"machine={QEMU_MACHINE} cpu={QEMU_CPU} smp={QEMU_SMP} "
        f"memory={QEMU_MEMORY} accel={QEMU_ACCELERATOR} icount={QEMU_ICOUNT}",
        file=sys.stderr,
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except OSError as error:
        fail(f"cannot start QEMU: {error}")

    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    raw = bytearray()
    deadline = time.monotonic() + timeout
    end_seen_at: float | None = None
    try:
        with transcript.open("wb") as output:
            while True:
                chunk = b""
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    pass
                if chunk:
                    raw.extend(chunk)
                    output.write(chunk)
                    output.flush()
                    if len(raw) > MAX_TRANSCRIPT_BYTES:
                        capture_failure(
                            f"QEMU transcript exceeded {MAX_TRANSCRIPT_BYTES} bytes",
                            bytes(raw),
                        )

                snapshot = bytes(raw)
                failure = transcript_failure(snapshot)
                if failure is not None:
                    capture_failure(failure, snapshot)

                endings = snapshot.count(END_PREFIX)
                if endings > 1:
                    capture_failure(
                        f"guest emitted duplicate END markers ({endings})", snapshot
                    )
                now = time.monotonic()
                if endings == 1 and complete_end_record(snapshot):
                    if end_seen_at is None:
                        end_seen_at = now
                    if now - end_seen_at >= END_SETTLE_SECONDS:
                        return snapshot

                returncode = process.poll()
                if returncode is not None:
                    # The child can exit before its final pipe bytes become
                    # visible. Drain them once before classifying the result.
                    while True:
                        try:
                            remainder = os.read(descriptor, 65536)
                        except BlockingIOError:
                            break
                        if not remainder:
                            break
                        raw.extend(remainder)
                        output.write(remainder)
                    snapshot = bytes(raw)
                    failure = transcript_failure(snapshot)
                    if failure is not None:
                        capture_failure(failure, snapshot)
                    endings = snapshot.count(END_PREFIX)
                    if endings != 1 or not complete_end_record(snapshot):
                        capture_failure(
                            f"QEMU exited with {returncode} before one complete END record",
                            snapshot,
                        )
                    return snapshot

                if now >= deadline:
                    capture_failure(
                        f"QEMU timed out after {timeout:.1f}s waiting for one END record",
                        snapshot,
                    )
                time.sleep(0.01)
    finally:
        stop_process(process)


def verify_expected_challenge(raw: bytes, challenge: str) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"UART transcript is not UTF-8: {error}")
    records: list[dict[str, object]] = []
    for line in text.splitlines():
        position = line.find(META_PREFIX)
        if position < 0:
            continue
        if position != 0:
            fail("metadata marker must begin at UART column zero")
        decoded = strict_json_loads(
            line[len(META_PREFIX) :].strip(), "UART metadata"
        )
        if not isinstance(decoded, dict):
            fail("metadata record is not an object while checking challenge")
        records.append(decoded)
    if len(records) != 1:
        fail(
            f"expected one metadata record while checking challenge, found {len(records)}"
        )
    if records[0].get("challenge") != challenge:
        fail(
            "guest metadata challenge does not match the challenge bound at build time"
        )
    return records[0]


def invoke_verifier(
    transcript: pathlib.Path,
    summary: pathlib.Path,
    source_commit: str,
    boot: int,
    *,
    publication: bool,
) -> str:
    command = [
        sys.executable,
        "-I",
        "-B",
        str(VERIFIER),
        "--check-manifest",
        "--transcript",
        str(transcript),
        "--platform",
        "qemu-virt",
        "--expect-source",
        source_commit,
        "--boot-index",
        str(boot),
        "--summary-out",
        str(summary),
    ]
    if publication:
        command.append("--publication")
    environment = {"LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot invoke the independent C8.3 verifier: {error}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        fail(f"independent C8.3 verifier rejected the transcript: {detail}")
    if not summary.is_file() or summary.stat().st_size == 0:
        fail("independent verifier did not create its derived summary")
    return completed.stdout.strip()


def recheck_toolchain_tools(toolchain: dict[str, object]) -> None:
    for name in ("rustup", "cargo", "rustc", "rustdoc"):
        record = toolchain.get(name)
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            fail(f"recorded {name} identity is malformed at closure")
        path = record.get("path")
        if not isinstance(path, str):
            fail(f"recorded {name} path is malformed at closure")
        if file_identity(pathlib.Path(path)) != {
            "sha256": record.get("sha256"),
            "bytes": record.get("bytes"),
        }:
            fail(f"recorded {name} changed during build/capture")
    linker = toolchain.get("linker")
    if not isinstance(linker, dict) or set(linker) != {
        "invocation_path",
        "resolved_path",
        "sha256",
        "bytes",
    }:
        fail("recorded linker identity is malformed at closure")
    linker_path = linker.get("invocation_path")
    if not isinstance(linker_path, str):
        fail("recorded linker path is malformed at closure")
    if linker_tool_record(linker_path, "recorded bare-metal linker") != linker:
        fail("recorded linker changed during build/capture")


def read_summary_identity(
    summary: pathlib.Path,
    *,
    source_commit: str,
    challenge: str,
    run_id: object,
) -> dict[str, object]:
    try:
        decoded = strict_json_loads(
            summary.read_text(encoding="utf-8"), "derived summary"
        )
    except OSError as error:
        fail(f"cannot read independently derived summary identity: {error}")
    if not isinstance(decoded, dict):
        fail("independently derived summary is not a JSON object")
    expected = {
        "source_commit": source_commit,
        "challenge": challenge,
        "run_id": run_id,
        "platform": "qemu-virt",
    }
    for field, value in expected.items():
        if decoded.get(field) != value:
            fail(f"derived summary {field} does not match verified guest metadata")
    return decoded


def write_envelope(
    destination: pathlib.Path,
    *,
    source_commit: str,
    challenge: str,
    run_id: object,
    started_at: str,
    ended_at: str,
    repository_before: dict[str, object],
    repository_after: dict[str, object],
    toolchain: dict[str, object],
    qemu: str,
    qemu_version: str,
    qemu_identity: dict[str, object],
    bios: pathlib.Path,
    bios_identity: dict[str, object],
    kernel: dict[str, object],
    evidence_checker: dict[str, object],
    transcript: pathlib.Path,
    summary: pathlib.Path,
) -> None:
    transcript_identity = file_identity(transcript)
    summary_identity = file_identity(summary)
    envelope = {
        "schema": "vibeos.wasm-runtime-cost.qemu-environment",
        "version": 2,
        "suite_id": "vibeos.c83.runtime-costs",
        "mode": "formal-publication",
        "source_commit": source_commit,
        "challenge": challenge,
        "run_id": run_id,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "repository": {
            "before": repository_before,
            "after": repository_after,
        },
        "runner": {
            "path": "scripts/qemu-c83-runtime-costs.py",
            **file_identity(pathlib.Path(__file__).resolve()),
        },
        "verifier": {
            "path": "scripts/verify-c83-runtime-costs.py",
            **file_identity(VERIFIER),
            "publication_gate": True,
        },
        "evidence_checker": {
            "path": "scripts/verify-c83-evidence.py",
            **evidence_checker,
        },
        "toolchain": toolchain,
        "kernel_elf": {
            "path": "target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt",
            **kernel,
        },
        "qemu": {
            "resolved_executable": qemu,
            "version": qemu_version,
            "argv": qemu_command(qemu, bios),
            **qemu_identity,
        },
        "bios": {
            "name": QEMU_BIOS_NAME,
            "resolved_path": str(bios),
            **bios_identity,
        },
        "transcript": transcript_identity,
        "summary": summary_identity,
    }
    try:
        destination.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        fail(f"cannot write temporary environment envelope: {error}")


def output_key(path: pathlib.Path) -> str:
    return os.path.abspath(os.fspath(path))


def check_output_destinations(args: argparse.Namespace) -> None:
    destinations = [
        path
        for path in (args.transcript_out, args.summary_out, args.envelope_out)
        if path is not None
    ]
    if len({output_key(path) for path in destinations}) != len(destinations):
        fail("all explicitly requested output paths must name different files")
    for destination in destinations:
        if pathlib.Path(destination).is_dir():
            fail(f"output destination is a directory: {destination}")
        if os.path.lexists(destination) and not args.overwrite:
            fail(
                f"output already exists (pass --overwrite to replace it): {destination}"
            )


def copy_output(
    source: pathlib.Path, destination: pathlib.Path, *, overwrite: bool
) -> None:
    destination = pathlib.Path(os.path.abspath(os.fspath(destination)))
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not overwrite:
            with source.open("rb") as input_file, destination.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file)
            return

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = pathlib.Path(temporary_name)
        try:
            with (
                os.fdopen(descriptor, "wb") as output_file,
                source.open("rb") as input_file,
            ):
                shutil.copyfileobj(input_file, output_file)
                output_file.flush()
                os.fsync(output_file.fileno())
            os.replace(temporary, destination)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except FileExistsError:
        fail(f"output appeared during collection and was not replaced: {destination}")
    except OSError as error:
        fail(f"cannot copy verified output to {destination}: {error}")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect the fixed single-hart QEMU C8.3 runtime-cost baseline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source-commit",
        help="canonical 40-hex commit to bind (defaults to HEAD and must equal HEAD)",
    )
    parser.add_argument(
        "--challenge",
        help="canonical nonzero 64-hex challenge (generated randomly when omitted)",
    )
    parser.add_argument(
        "--allow-dirty-smoke",
        action="store_true",
        help=(
            "allow an uncommitted development build; disables publication checks "
            "and forbids output export"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=positive_timeout,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="whole-boot timeout",
    )
    parser.add_argument(
        "--qemu",
        default="qemu-system-riscv64",
        help="QEMU executable (machine options remain fixed)",
    )
    parser.add_argument(
        "--boot-index",
        type=boot_index,
        default=0,
        help="derived-summary boot index (formal fresh_boots=1 requires zero)",
    )
    parser.add_argument(
        "--transcript-out",
        type=pathlib.Path,
        help="copy the verified formal UART transcript to this file",
    )
    parser.add_argument(
        "--summary-out",
        type=pathlib.Path,
        help="copy the independently derived formal summary to this file",
    )
    parser.add_argument(
        "--envelope-out",
        type=pathlib.Path,
        help=(
            "copy the formal QEMU/toolchain/Git environment envelope to this file "
            "(required with transcript or summary output)"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace explicitly requested output files atomically",
    )
    return parser


def main() -> int:
    args = argument_parser().parse_args()
    try:
        if args.allow_dirty_smoke and (
            args.transcript_out is not None
            or args.summary_out is not None
            or args.envelope_out is not None
        ):
            fail(
                "--allow-dirty-smoke cannot export evidence files; "
                "commit the source and use formal mode to collect evidence"
            )
        exports = (
            args.transcript_out,
            args.summary_out,
            args.envelope_out,
        )
        if any(path is not None for path in exports) and not all(
            path is not None for path in exports
        ):
            fail(
                "formal evidence export is all-or-none: specify --transcript-out, "
                "--summary-out, and --envelope-out together"
            )
        if not args.allow_dirty_smoke and args.boot_index != 0:
            fail("formal fresh_boots=1 evidence requires --boot-index 0")
        check_output_destinations(args)

        head = git_head()
        source_commit = canonical_hex(
            args.source_commit or head, HEX40, 40, "source commit"
        )
        if source_commit != head:
            fail(f"source commit must equal current HEAD {head}, got {source_commit}")
        challenge = canonical_hex(
            args.challenge or secrets.token_hex(32), HEX64, 64, "challenge"
        )
        if not args.allow_dirty_smoke and source_commit == TEST_ONLY_SOURCE_COMMIT:
            fail("formal publication cannot use the documented test-only source sentinel")
        if not args.allow_dirty_smoke and challenge == TEST_ONLY_CHALLENGE:
            fail("formal publication cannot use the documented test-only challenge sentinel")
        check_repository_state(source_commit, allow_dirty=args.allow_dirty_smoke)
        started_at = utc_now()
        repository_before = repository_attestation()

        publication = not args.allow_dirty_smoke
        mode = "formal-publication" if publication else "DIRTY-SMOKE-NOT-PUBLICATION"
        if not publication:
            print(
                "WARNING: dirty smoke mode is not C8.3 publication evidence; "
                "publication gates and artifact export are disabled.",
                file=sys.stderr,
            )
        print(
            f"C8.3: mode={mode} source={source_commit} challenge={challenge}",
            file=sys.stderr,
        )

        toolchain = build_kernel(source_commit, challenge)
        check_repository_state(source_commit, allow_dirty=args.allow_dirty_smoke)
        qemu = resolve_qemu(args.qemu)
        qemu_version = run_text([qemu, "--version"])
        qemu_identity = file_identity(pathlib.Path(qemu))
        bios = resolve_bios(qemu)
        bios_identity = file_identity(bios)
        kernel_identity = file_identity(KERNEL)
        evidence_checker_identity = file_identity(EVIDENCE_CHECKER)

        # UART and derived files live outside the repository.  They disappear
        # unless a successful formal run explicitly requests an output copy.
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c83-qemu-", dir="/tmp"
        ) as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            transcript = temporary / "qemu-uart.log"
            summary = temporary / "qemu-summary.json"
            envelope = temporary / "qemu-environment.json"
            raw = capture_qemu(qemu, bios, args.timeout_seconds, transcript)
            metadata = verify_expected_challenge(raw, challenge)
            verifier_result = invoke_verifier(
                transcript,
                summary,
                source_commit,
                args.boot_index,
                publication=publication,
            )
            read_summary_identity(
                summary,
                source_commit=source_commit,
                challenge=challenge,
                run_id=metadata.get("run_id"),
            )
            check_repository_state(source_commit, allow_dirty=args.allow_dirty_smoke)
            if file_identity(KERNEL) != kernel_identity:
                fail("kernel ELF changed between build and verified capture")
            if file_identity(pathlib.Path(qemu)) != qemu_identity:
                fail("resolved QEMU executable changed during verified capture")
            if file_identity(bios) != bios_identity:
                fail("resolved OpenSBI BIOS changed during verified capture")
            if file_identity(EVIDENCE_CHECKER) != evidence_checker_identity:
                fail("offline C8.3 evidence checker changed during verified capture")
            recheck_toolchain_tools(toolchain)
            repository_after = repository_attestation()
            ended_at = utc_now()
            if publication:
                write_envelope(
                    envelope,
                    source_commit=source_commit,
                    challenge=challenge,
                    run_id=metadata.get("run_id"),
                    started_at=started_at,
                    ended_at=ended_at,
                    repository_before=repository_before,
                    repository_after=repository_after,
                    toolchain=toolchain,
                    qemu=qemu,
                    qemu_version=qemu_version,
                    qemu_identity=qemu_identity,
                    bios=bios,
                    bios_identity=bios_identity,
                    kernel=kernel_identity,
                    evidence_checker=evidence_checker_identity,
                    transcript=transcript,
                    summary=summary,
                )

            if args.transcript_out is not None:
                copy_output(transcript, args.transcript_out, overwrite=args.overwrite)
            if args.summary_out is not None:
                copy_output(summary, args.summary_out, overwrite=args.overwrite)
            if args.envelope_out is not None:
                copy_output(envelope, args.envelope_out, overwrite=args.overwrite)

        if verifier_result:
            print(verifier_result)
        digest = hashlib.sha256(raw).hexdigest()
        print(
            f"PASS qemu-c83-runtime-costs mode={mode} source={source_commit} "
            f"challenge={challenge} transcript_sha256={digest}"
        )
        return 0
    except RunnerError as error:
        print(f"FAIL qemu-c83-runtime-costs: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
