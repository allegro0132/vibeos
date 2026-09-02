#!/usr/bin/env python3
"""Build, capture, and verify the C8.8-F5 fixed-QEMU qualification image.

The default mode is a formal evidence run.  It requires a clean, stable Git
HEAD, builds the dedicated ``riscv64imac-unknown-none-elf`` image with a fresh
compile-time challenge, boots exactly the pinned QEMU 11.0.3/OpenSBI contract,
captures a bounded UART transcript, and delegates semantic acceptance to the
independent verifier.

``--allow-dirty-smoke`` is deliberately non-publishable: it may exercise an
uncommitted image, but it cannot export evidence and does not claim that the
formal verifier accepted a clean source identity.  This runner never boots or
claims a physical Milk-V target.

Kernel identity is measured by the host after the build and bound in the
environment envelope and QEMU ``-kernel`` argument.  It is intentionally not a
guest compile-time field: embedding an ELF's own SHA-256 in that ELF would ask
for an infeasible cryptographic fixed point.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import NoReturn

OutputToken = tuple[pathlib.Path, int, int]


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIRMWARE = ROOT / "firmware/qemu-virt"
TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"
CARGO_LOCK = ROOT / "Cargo.lock"
CARGO_CONFIG = ROOT / "firmware/.cargo/config.toml"
VERIFIER = ROOT / "scripts/verify-c88-f5-float-target.py"
ELF_AUDITOR = ROOT / "scripts/verify-c88-f5-riscv-elf.py"
PRODUCER = ROOT / "kernel/src/wasm_float_target.rs"
QUALIFICATION = ROOT / "acceptance/wasm-float-target/src/lib.rs"
QUALIFICATION_MANIFEST = (
    ROOT / "acceptance/wasm-float-target/artifacts/qualification-manifest.json"
)

TARGET = "riscv64imac-unknown-none-elf"
FEATURE = "wasm-c88-f5-float-qemu-acceptance"
KERNEL_RELATIVE = pathlib.Path(TARGET) / "release/vibeos-qemu-virt"
F5_RUSTFLAGS = (
    "-C",
    "linker=ld.lld",
    "-C",
    "linker-flavor=ld",
    "-C",
    "target-feature=+zicsr,+zifencei",
    "-C",
    "link-arg=--gc-sections",
    "-C",
    "force-frame-pointers=yes",
    "-Z",
    "fmt-debug=none",
)

SOURCE_COMMIT_ENV = "VIBEOS_C88_F5_SOURCE_COMMIT"
SOURCE_TREE_ENV = "VIBEOS_C88_F5_SOURCE_TREE"
CHALLENGE_ENV = "VIBEOS_C88_F5_CHALLENGE"
RUN_ID_ENV = "VIBEOS_C88_F5_RUN_ID"
MANIFEST_SHA256_ENV = "VIBEOS_C88_F5_MANIFEST_SHA256"
TRANSCRIPT_SCHEMA_SHA256_ENV = "VIBEOS_C88_F5_TRANSCRIPT_SCHEMA_SHA256"

SUITE_ID = "vibeos.c88.f5.float-target"
ENVIRONMENT_SCHEMA = "vibeos.c88.f5.float-target.environment"
RUN_ID_DOMAIN = b"vibeos.c88.f5.float-target.run.v1\0"
COMPONENT_SHA256 = "5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a"
QUALIFICATION_MANIFEST_SHA256 = (
    "39abd7d8bf25f2da2dfe76109e0811202ba05a9dbc17501ef7a6c2a905c81d76"
)
QUALIFICATION_MANIFEST_BYTES = 2_090

PLATFORM = {
    "id": "qemu-virt-rv64-tcg-icount-v1",
    "class": "emulator",
    "target": TARGET,
    "physical_provenance": "not-claimed",
}

QEMU_PATH = pathlib.Path("/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-riscv64")
QEMU_SHA256 = "ef5c714232320c22561daa0998546b73672e21a2801404714dfbd4982ac7b3c0"
QEMU_BYTES = 13_511_488
QEMU_VERSION = (
    "QEMU emulator version 11.0.3\n"
    "Copyright (c) 2003-2026 Fabrice Bellard and the QEMU Project developers"
)
BIOS_PATH = pathlib.Path(
    "/opt/homebrew/Cellar/qemu/11.0.3/share/qemu/"
    "opensbi-riscv64-generic-fw_dynamic.bin"
)
BIOS_SHA256 = "49bdf7b939bda11321132d1042bf99d7324fb190f1feef423171fed3573f8705"
BIOS_BYTES = 273_048

QEMU_MACHINE = "virt"
QEMU_CPU = "rv64"
QEMU_SMP = "1"
QEMU_MEMORY = "128M"
QEMU_ACCEL = "tcg,thread=single"
QEMU_ICOUNT = "shift=0,align=off,sleep=off"
EXPECTED_SEMANTIC_SHA256 = (
    "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1"
)

META_PREFIX = "VIBE_C88_F5_META "
END_PREFIX = "VIBE_C88_F5_END "
PASS_PREFIX = "VIBE_C88_F5_PASS "
FAIL_PREFIX = "VIBE_C88_F5_FAIL"
FAMILY_PREFIX = "VIBE_C88_F5_"
FATAL_MARKERS = ("panicked at", "panic", "fatal")

DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_UART_BYTES = 16 * 1024 * 1024
MAX_UART_LINES = 20_000
MAX_IDENTITY_BYTES = 256 * 1024 * 1024
MAX_CONTRACT_BYTES = 2 * 1024 * 1024
MAX_ELF_AUDIT_BYTES = 4 * 1024 * 1024
MAX_ENVIRONMENT_BYTES = 4 * 1024 * 1024
MAX_RUST_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_RUST_SOURCE_FILES = 20_000
MAX_RUST_SOURCE_BYTES = 256 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120.0
BUILD_COMMAND_TIMEOUT_SECONDS = 600.0
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
RUST_SOURCE_TREE_DOMAIN = b"vibeos.c88.f5.rust-source-tree.v1\0"
FORMAL_BRANCH = "codex/wasm"
FORMAL_REMOTE_REF = "refs/remotes/origin/codex/wasm"
FORMAL_TEMP_ROOT = pathlib.Path("/private/tmp")

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TOOLCHAIN_CHANNEL = re.compile(r'^\s*channel\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
TOOLCHAIN_COMMIT = re.compile(r"^# rustc-commit: ([0-9a-f]{40})$", re.MULTILINE)
RUSTC_COMMIT = re.compile(r"^commit-hash: ([0-9a-f]{40})$", re.MULTILINE)

GIT_STATUS_COMMAND = [
    "/usr/bin/git",
    "-c",
    "core.fsmonitor=false",
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
    "--ignore-submodules=none",
]


def git_environment() -> dict[str, str]:
    """Deny ambient repository/config overrides for formal source binding."""
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


class RunnerError(RuntimeError):
    """A fail-closed C8.8-F5 build, capture, or verification error."""


def fail(message: str) -> NoReturn:
    raise RunnerError(message)


def positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(parsed) or not 1.0 <= parsed <= 3600.0:
        raise argparse.ArgumentTypeError("must be between 1 and 3600 seconds")
    return parsed


def canonical_hex(value: str, pattern: re.Pattern[str], length: int, label: str) -> str:
    if pattern.fullmatch(value) is None:
        fail(f"{label} must be canonical lowercase hexadecimal of length {length}")
    if not any(character != "0" for character in value):
        fail(f"{label} must not be the all-zero sentinel")
    return value


def reject_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def reject_nonfinite_json(value: str) -> NoReturn:
    fail(f"non-finite JSON number {value!r}")


def strict_json_text(value: str, label: str) -> object:
    try:
        return json.loads(
            value,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_nonfinite_json,
        )
    except json.JSONDecodeError as error:
        fail(f"invalid {label} JSON: {error}")


def stop_process_group(process: subprocess.Popen[bytes], label: str) -> None:
    """Terminate one isolated subprocess group within a fixed grace period."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass
    # The session can outlive its leader when a descendant ignores SIGTERM.
    # Always address the original PGID again, even after wait() reaped the
    # leader, so a pipe-closing daemon cannot escape the command bound.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        fail(f"{label} process group did not terminate after SIGKILL")


def run_command(
    command: list[str],
    *,
    cwd: pathlib.Path | str = ROOT,
    environment: dict[str, str] | None = None,
    maximum_output: int = 1024 * 1024,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    if not command:
        fail("cannot execute an empty command")
    if maximum_output <= 0:
        fail("subprocess diagnostic bound must be positive")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        fail("subprocess timeout must be finite and positive")
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
    except OSError as error:
        fail(f"cannot execute {command[0]}: {error}")

    assert process.stdout is not None
    assert process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    streams = {
        process.stdout.fileno(): stdout,
        process.stderr.fileno(): stderr,
    }
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_process_group(process, command[0])
                fail(f"{command[0]} timed out after {timeout_seconds:.1f}s")
            events = selector.select(timeout=min(remaining, 0.1))
            for key, _ in events:
                descriptor = key.fd
                try:
                    chunk = os.read(descriptor, READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                except OSError as error:
                    stop_process_group(process, command[0])
                    fail(f"cannot read {command[0]} diagnostics: {error}")
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                streams[descriptor].extend(chunk)
                if len(stdout) + len(stderr) > maximum_output:
                    stop_process_group(process, command[0])
                    fail(
                        f"{command[0]} produced more than {maximum_output} "
                        "diagnostic bytes"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop_process_group(process, command[0])
            fail(f"{command[0]} timed out after {timeout_seconds:.1f}s")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            stop_process_group(process, command[0])
            fail(f"{command[0]} timed out after {timeout_seconds:.1f}s")
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        # This is intentionally unconditional: a successful leader may have
        # left a same-session descendant after closing the captured pipes.
        stop_process_group(process, command[0])
    return subprocess.CompletedProcess(
        command, returncode, bytes(stdout), bytes(stderr)
    )


def run_text(
    command: list[str],
    *,
    cwd: pathlib.Path | str = ROOT,
    environment: dict[str, str] | None = None,
    maximum_output: int = 1024 * 1024,
) -> str:
    completed = run_command(
        command,
        cwd=cwd,
        environment=environment,
        maximum_output=maximum_output,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        fail(
            f"{' '.join(command)} failed with exit {completed.returncode}: "
            f"{detail.strip() or 'no diagnostic'}"
        )
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        fail(f"{command[0]} output is not UTF-8: {error}")


def stable_file_bytes(
    path: pathlib.Path,
    label: str,
    *,
    maximum: int = MAX_IDENTITY_BYTES,
    allow_empty: bool = False,
) -> tuple[pathlib.Path, bytes]:
    requested = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = requested.lstat()
        resolved_path = requested.resolve(strict=True)
        if stat.S_ISLNK(before_path.st_mode):
            fail(f"{label} must not be a symbolic link: {requested}")
        if resolved_path != requested:
            fail(f"{label} path must not traverse symbolic links: {requested}")
        descriptor = os.open(requested, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                fail(f"{label} is not a direct regular file: {requested}")
            if before.st_nlink != 1:
                fail(f"{label} must have exactly one hard link: {requested}")
            minimum = 0 if allow_empty else 1
            if before.st_size < minimum or before.st_size > maximum:
                interval = "[0" if allow_empty else "(0"
                fail(f"{label} byte length is outside {interval}, {maximum}]")
            chunks: list[bytes] = []
            byte_count = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > maximum:
                    fail(f"{label} grew beyond {maximum} bytes while hashing")
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = requested.lstat()
    except OSError as error:
        fail(f"cannot read {label} {requested}: {error}")
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    initial_path_identity = (
        before_path.st_dev,
        before_path.st_ino,
        before_path.st_size,
        before_path.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    path_identity = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
    )
    if (
        before_identity != initial_path_identity
        or before_identity != after_identity
        or before_identity != path_identity
    ):
        fail(f"{label} changed while it was read: {requested}")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"{label} byte length changed while it was read: {requested}")
    return requested, raw


def file_identity(
    path: pathlib.Path, label: str, *, maximum: int = MAX_IDENTITY_BYTES
) -> dict[str, object]:
    direct, raw = stable_file_bytes(path, label, maximum=maximum)
    return {
        "path": str(direct),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def require_unchanged(
    path: pathlib.Path,
    label: str,
    expected: dict[str, object],
    *,
    maximum: int = MAX_IDENTITY_BYTES,
) -> None:
    actual = file_identity(path, label, maximum=maximum)
    if actual != expected:
        fail(f"{label} changed during the formal run")


def fixed_identity(
    path: pathlib.Path,
    label: str,
    *,
    expected_sha256: str,
    expected_bytes: int,
    executable: bool = False,
) -> dict[str, object]:
    identity = file_identity(path, label)
    if identity["sha256"] != expected_sha256 or identity["bytes"] != expected_bytes:
        fail(
            f"{label} differs from the pinned identity: expected "
            f"sha256={expected_sha256} bytes={expected_bytes}, got "
            f"sha256={identity['sha256']} bytes={identity['bytes']}"
        )
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable: {path}")
    return identity


def git_text(arguments: list[str]) -> str:
    return run_text(
        ["/usr/bin/git", "-c", "core.fsmonitor=false", *arguments],
        cwd=ROOT,
        environment=git_environment(),
    )


def git_identity() -> tuple[str, str]:
    repository = pathlib.Path(git_text(["rev-parse", "--show-toplevel"]))
    try:
        repository = repository.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve Git repository root: {error}")
    if repository != ROOT.resolve(strict=True):
        fail(f"runner repository root differs: {repository} != {ROOT}")
    commit = canonical_hex(
        git_text(["rev-parse", "--verify", "HEAD^{commit}"]),
        HEX40,
        40,
        "source commit",
    )
    tree = canonical_hex(
        git_text(["rev-parse", "--verify", "HEAD^{tree}"]),
        HEX40,
        40,
        "source tree",
    )
    return commit, tree


def repository_is_clean() -> bool:
    completed = run_command(GIT_STATUS_COMMAND, cwd=ROOT, environment=git_environment())
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"cannot inspect repository status: {detail or completed.returncode}")
    return completed.stdout == b""


def require_repository_state(
    source_commit: str, source_tree: str, *, clean: bool
) -> None:
    actual_commit, actual_tree = git_identity()
    if actual_commit != source_commit or actual_tree != source_tree:
        fail("Git HEAD or tree changed during the run")
    if clean and not repository_is_clean():
        fail("formal C8.8-F5 mode requires a clean HEAD (including untracked files)")


def require_pushed_formal_branch(source_commit: str) -> None:
    branch = git_text(["symbolic-ref", "--quiet", "--short", "HEAD"])
    if branch != FORMAL_BRANCH:
        fail(f"formal F5 evidence must run on {FORMAL_BRANCH}, got {branch!r}")
    remote_commit = canonical_hex(
        git_text(["rev-parse", "--verify", f"{FORMAL_REMOTE_REF}^{{commit}}"]),
        HEX40,
        40,
        "formal remote-tracking commit",
    )
    if remote_commit != source_commit:
        fail(
            f"formal F5 source must already be pushed to {FORMAL_REMOTE_REF}; "
            f"remote={remote_commit} source={source_commit}"
        )


def compute_run_id(
    source_commit: str,
    source_tree: str,
    challenge: str,
    manifest_sha256: str,
    transcript_schema_sha256: str,
) -> str:
    fields = (
        source_commit,
        source_tree,
        challenge,
        manifest_sha256,
        transcript_schema_sha256,
        COMPONENT_SHA256,
    )
    payload = RUN_ID_DOMAIN + b"\0".join(field.encode("ascii") for field in fields)
    return hashlib.sha256(payload).hexdigest()


def toolchain_pin() -> tuple[str, str]:
    _, raw = stable_file_bytes(
        TOOLCHAIN_FILE, "pinned Rust toolchain file", maximum=64 * 1024
    )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"rust-toolchain.toml is not UTF-8: {error}")
    channel = TOOLCHAIN_CHANNEL.search(text)
    commit = TOOLCHAIN_COMMIT.search(text)
    if channel is None or commit is None:
        fail("rust-toolchain.toml lacks exact channel and rustc commit pins")
    return channel.group(1), commit.group(1)


def resolve_executable(name: str, label: str) -> pathlib.Path:
    selected = shutil.which(name)
    if selected is None:
        fail(f"{label} was not found on PATH: {name}")
    try:
        path = pathlib.Path(selected).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label}: {error}")
    if not path.is_file() or not os.access(path, os.X_OK):
        fail(f"{label} is not an executable regular file: {path}")
    return path


def rustup_tool(rustup: pathlib.Path, channel: str, name: str) -> pathlib.Path:
    output = run_text(
        [str(rustup), "which", "--toolchain", channel, name], cwd=ROOT
    ).splitlines()
    if len(output) != 1:
        fail(f"rustup did not resolve one pinned {name} for {channel}")
    try:
        path = pathlib.Path(output[0]).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve pinned {name}: {error}")
    if not path.is_file() or not os.access(path, os.X_OK):
        fail(f"pinned {name} is not an executable regular file: {path}")
    return path


def ambient_cargo_home() -> pathlib.Path:
    configured = os.environ.get("CARGO_HOME")
    candidate = (
        pathlib.Path(configured).expanduser()
        if configured
        else pathlib.Path.home() / ".cargo"
    )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve the offline Cargo cache home {candidate}: {error}")
    if not resolved.is_dir():
        fail(f"offline Cargo cache home is not a directory: {resolved}")
    return resolved


def fixed_campaign_root() -> pathlib.Path:
    """Return the one direct temporary root permitted for an F5 campaign."""
    try:
        metadata = FORMAL_TEMP_ROOT.lstat()
        resolved = FORMAL_TEMP_ROOT.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect fixed campaign root {FORMAL_TEMP_ROOT}: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"fixed campaign root must be one direct directory: {FORMAL_TEMP_ROOT}")
    if resolved != FORMAL_TEMP_ROOT:
        fail(
            f"fixed campaign root must not traverse symbolic links: {FORMAL_TEMP_ROOT}"
        )
    return FORMAL_TEMP_ROOT


def require_no_ancestor_cargo_configs(invocation_directory: pathlib.Path) -> None:
    """Reject Cargo configuration merged from outside the reviewed cwd config."""
    try:
        direct = invocation_directory.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve Cargo invocation directory: {error}")
    if direct != invocation_directory:
        fail("Cargo invocation directory must be lexically direct")

    ancestor = direct.parent
    while True:
        for name in ("config", "config.toml"):
            candidate = ancestor / ".cargo" / name
            if os.path.lexists(candidate):
                fail(f"ambient ancestor Cargo config is forbidden: {candidate}")
        if ancestor.parent == ancestor:
            break
        ancestor = ancestor.parent


def rust_source_tree_identity(rustc: pathlib.Path) -> dict[str, object]:
    """Hash the complete rust-src library tree consumed by ``-Z build-std``."""
    sysroot_lines = run_text([str(rustc), "--print", "sysroot"], cwd=ROOT).splitlines()
    if len(sysroot_lines) != 1:
        fail("pinned rustc did not report exactly one sysroot")
    try:
        sysroot = pathlib.Path(sysroot_lines[0]).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve pinned rustc sysroot: {error}")
    expected_sysroot = rustc.parent.parent
    if sysroot != expected_sysroot:
        fail(f"pinned rustc sysroot differs from its toolchain: {sysroot}")
    root = sysroot / "lib/rustlib/src/rust/library"
    try:
        root_metadata = root.lstat()
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect pinned rust-src library tree: {error}")
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        fail("pinned rust-src library root must be one direct directory")
    if resolved_root != root:
        fail("pinned rust-src library root must not traverse symbolic links")

    files: list[tuple[str, pathlib.Path]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
        except OSError as error:
            fail(f"cannot enumerate pinned rust-src directory {directory}: {error}")
        for entry in entries:
            try:
                metadata = entry.lstat()
            except OSError as error:
                fail(f"cannot inspect pinned rust-src entry {entry}: {error}")
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"pinned rust-src tree contains a symbolic link: {entry}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(entry)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"pinned rust-src entry is not a direct regular file: {entry}")
            relative = entry.relative_to(root).as_posix()
            if any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in relative
            ):
                fail(f"pinned rust-src path contains a control character: {relative!r}")
            files.append((relative, entry))
            if len(files) > MAX_RUST_SOURCE_FILES:
                fail("pinned rust-src tree exceeds its file-count bound")
    files.sort(key=lambda item: item[0])
    if not files:
        fail("pinned rust-src tree contains no source files")

    digest = hashlib.sha256(RUST_SOURCE_TREE_DOMAIN)
    total_bytes = 0
    for relative, path in files:
        _, raw = stable_file_bytes(
            path,
            f"pinned rust-src file {relative}",
            maximum=MAX_RUST_SOURCE_FILE_BYTES,
            allow_empty=True,
        )
        total_bytes += len(raw)
        if total_bytes > MAX_RUST_SOURCE_BYTES:
            fail("pinned rust-src tree exceeds its byte bound")
        record = canonical_json_bytes(
            {
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        )
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return {
        "path": str(root),
        "files": len(files),
        "bytes": total_bytes,
        "tree_sha256": digest.hexdigest(),
    }


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def environment_json_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def cargo_lock_requirements() -> tuple[dict[str, object], list[dict[str, str]]]:
    direct, raw = stable_file_bytes(CARGO_LOCK, "Cargo.lock", maximum=4 * 1024 * 1024)
    try:
        decoded = raw.decode("utf-8", errors="strict")
        lock = tomllib.loads(decoded)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"Cargo.lock is not strict TOML: {error}")
    if lock.get("version") != 4 or not isinstance(lock.get("package"), list):
        fail("Cargo.lock must use version 4 and contain a package array")

    requirements: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, package in enumerate(lock["package"]):
        if not isinstance(package, dict):
            fail(f"Cargo.lock package {index} is not a table")
        source = package.get("source")
        if source is None:
            continue
        if not isinstance(source, str):
            fail(f"Cargo.lock package {index} has a non-string source")
        if source.startswith("git+"):
            fail("formal F5 build does not permit Git dependencies")
        if source != CRATES_IO_SOURCE:
            fail(f"formal F5 build has an unsupported package source: {source}")
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if not isinstance(name, str) or not name or "/" in name or "\\" in name:
            fail(f"Cargo.lock package {index} has an invalid registry name")
        if (
            not isinstance(version, str)
            or not version
            or "/" in version
            or "\\" in version
        ):
            fail(f"Cargo.lock package {index} has an invalid registry version")
        if not isinstance(checksum, str):
            fail(f"Cargo.lock package {name} {version} lacks a checksum")
        canonical_hex(checksum, HEX64, 64, f"Cargo.lock {name} {version} checksum")
        key = (name, version, source)
        if key in seen:
            fail(f"Cargo.lock repeats registry package {name} {version}")
        seen.add(key)
        requirements.append(
            {
                "name": name,
                "version": version,
                "source": source,
                "checksum": checksum,
                "filename": f"{name}-{version}.crate",
            }
        )
    requirements.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    if not requirements:
        fail("Cargo.lock contains no registry packages to close")
    identity = {
        "path": str(direct),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    return identity, requirements


def registry_archive_closure(
    cargo_home: pathlib.Path,
) -> tuple[dict[str, object], list[tuple[pathlib.Path, dict[str, object]]]]:
    cargo_lock, requirements = cargo_lock_requirements()
    cache_root = cargo_home / "registry/cache"
    try:
        cache_metadata = cache_root.lstat()
    except OSError as error:
        fail(f"cannot inspect offline Cargo registry cache: {error}")
    if stat.S_ISLNK(cache_metadata.st_mode) or not stat.S_ISDIR(cache_metadata.st_mode):
        fail("offline Cargo registry cache must be one direct directory")
    try:
        cache_directories = sorted(cache_root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        fail(f"cannot enumerate offline Cargo registry cache: {error}")
    if not cache_directories:
        fail("offline Cargo registry cache has no index directories")
    for directory in cache_directories:
        try:
            metadata = directory.lstat()
        except OSError as error:
            fail(f"cannot inspect offline Cargo cache directory {directory}: {error}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail(f"offline Cargo cache entry is not a direct directory: {directory}")

    records: list[dict[str, object]] = []
    tracked: list[tuple[pathlib.Path, dict[str, object]]] = []
    for requirement in requirements:
        matches = [
            directory / requirement["filename"]
            for directory in cache_directories
            if os.path.lexists(directory / requirement["filename"])
        ]
        if len(matches) != 1:
            fail(
                "offline Cargo cache must contain exactly one archive for "
                f"{requirement['name']} {requirement['version']}; found {len(matches)}"
            )
        path = matches[0]
        identity = file_identity(path, f"registry archive {requirement['filename']}")
        if identity["sha256"] != requirement["checksum"]:
            fail(
                f"registry archive {requirement['filename']} differs from "
                "the Cargo.lock checksum"
            )
        records.append(
            {
                **requirement,
                "sha256": identity["sha256"],
                "bytes": identity["bytes"],
            }
        )
        tracked.append((path, identity))
    return (
        {
            "cargo_lock": cargo_lock,
            "count": len(records),
            "records_sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
            "records": records,
        },
        tracked,
    )


def make_ephemeral_cargo_home(destination: pathlib.Path, source: pathlib.Path) -> None:
    destination.mkdir(mode=0o700)
    registry = destination / "registry"
    registry.mkdir(mode=0o700)
    for name in ("cache", "index"):
        cache = source / "registry" / name
        try:
            metadata = cache.lstat()
        except OSError as error:
            fail(f"cannot inspect offline Cargo registry {name}: {error}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail(f"offline Cargo registry {name} must be one direct directory")
        try:
            os.symlink(cache, registry / name, target_is_directory=True)
        except OSError as error:
            fail(f"cannot expose offline Cargo registry {name}: {error}")
    if os.path.lexists(destination / "git") or os.path.lexists(registry / "src"):
        fail("ephemeral Cargo home unexpectedly exposes mutable source trees")


def source_date_epoch(source_commit: str) -> str:
    value = git_text(["show", "-s", "--format=%ct", source_commit])
    if not value.isdigit() or int(value) <= 0:
        fail("source commit has no canonical positive timestamp")
    return value


def build_kernel(
    campaign: pathlib.Path,
    *,
    source_commit: str,
    source_tree: str,
    challenge: str,
    run_id: str,
    manifest_sha256: str,
    transcript_schema_sha256: str,
) -> tuple[
    pathlib.Path,
    dict[str, dict[str, object]],
    dict[str, object],
]:
    channel, expected_rustc_commit = toolchain_pin()
    rustup = resolve_executable("rustup", "rustup")
    rustup_identity = file_identity(rustup, "rustup")
    cargo = rustup_tool(rustup, channel, "cargo")
    rustc = rustup_tool(rustup, channel, "rustc")
    rustdoc = rustup_tool(rustup, channel, "rustdoc")
    linker = resolve_executable("ld.lld", "bare-metal linker")
    tools = {
        "rustup": rustup_identity,
        "cargo": file_identity(cargo, "pinned cargo"),
        "rustc": file_identity(rustc, "pinned rustc"),
        "rustdoc": file_identity(rustdoc, "pinned rustdoc"),
        "linker": file_identity(linker, "bare-metal linker"),
    }

    rustc_version = run_text([str(rustc), "-Vv"], cwd=ROOT)
    commit = RUSTC_COMMIT.search(rustc_version)
    if commit is None or commit.group(1) != expected_rustc_commit:
        fail(
            "pinned rustc commit differs: expected "
            f"{expected_rustc_commit}, got {commit.group(1) if commit else 'unknown'}"
        )

    target_directory = campaign / "target"
    cargo_home = campaign / "cargo-home"
    build_home = campaign / "build-home"
    build_tmp = campaign / "build-tmp"
    invocation_directory = campaign / "cargo-invocation"
    invocation_config_directory = invocation_directory / ".cargo"
    target_directory.mkdir(mode=0o700)
    build_home.mkdir(mode=0o700)
    build_tmp.mkdir(mode=0o700)
    invocation_directory.mkdir(mode=0o700)
    invocation_config_directory.mkdir(mode=0o700)
    offline_cargo_home = ambient_cargo_home()
    dependency_archives, tracked_archives = registry_archive_closure(offline_cargo_home)
    rust_source_identity = rust_source_tree_identity(rustc)
    dependency_archives["rust_source"] = rust_source_identity
    cargo_config_identity = file_identity(
        CARGO_CONFIG, "tracked bare-metal Cargo config", maximum=64 * 1024
    )
    dependency_archives["cargo_config"] = cargo_config_identity
    staged_cargo_config = invocation_config_directory / "config.toml"
    copy_exclusive(
        CARGO_CONFIG,
        staged_cargo_config,
        label="tracked bare-metal Cargo config",
        maximum=64 * 1024,
    )
    staged_config_identity = file_identity(
        staged_cargo_config, "staged bare-metal Cargo config", maximum=64 * 1024
    )
    if (
        staged_config_identity["sha256"] != cargo_config_identity["sha256"]
        or staged_config_identity["bytes"] != cargo_config_identity["bytes"]
    ):
        fail("staged bare-metal Cargo config differs from the tracked source")
    make_ephemeral_cargo_home(cargo_home, offline_cargo_home)

    path_entries: list[str] = []
    for entry in (
        str(linker.parent),
        str(rustup.parent),
        "/usr/bin",
        "/bin",
    ):
        if entry not in path_entries:
            path_entries.append(entry)
    path_value = os.pathsep.join(path_entries)
    selected_linker = shutil.which("ld.lld", path=path_value)
    if selected_linker is None:
        fail("sanitized build PATH no longer resolves ld.lld")
    if pathlib.Path(selected_linker).resolve(strict=True) != linker:
        fail("sanitized build PATH resolves a different ld.lld")

    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(F5_RUSTFLAGS),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target_directory),
        "CARGO_TERM_COLOR": "never",
        "HOME": str(build_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": path_value,
        "RUSTC": str(rustc),
        "RUSTDOC": str(rustdoc),
        "SOURCE_DATE_EPOCH": source_date_epoch(source_commit),
        "TMPDIR": str(build_tmp),
        "TZ": "UTC",
        SOURCE_COMMIT_ENV: source_commit,
        SOURCE_TREE_ENV: source_tree,
        CHALLENGE_ENV: challenge,
        RUN_ID_ENV: run_id,
        MANIFEST_SHA256_ENV: manifest_sha256,
        TRANSCRIPT_SCHEMA_SHA256_ENV: transcript_schema_sha256,
    }
    command = [
        str(cargo),
        "build",
        "--manifest-path",
        str(FIRMWARE / "Cargo.toml"),
        "--target",
        TARGET,
        "--release",
        "--locked",
        "--offline",
        "--no-default-features",
        "--features",
        FEATURE,
    ]
    print(
        f"C8.8-F5: building dedicated {FEATURE} image for {TARGET}",
        file=sys.stderr,
    )
    require_no_ancestor_cargo_configs(invocation_directory)
    if rust_source_tree_identity(rustc) != rust_source_identity:
        fail("pinned rust-src library tree changed during the build")
    completed = run_command(
        command,
        # Cargo configuration discovery is rooted at the invocation directory,
        # not at --manifest-path. The private directory contains only an exact
        # copy of the reviewed bare-metal target/build-std contract.
        cwd=invocation_directory,
        environment=environment,
        maximum_output=16 * 1024 * 1024,
        timeout_seconds=BUILD_COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        fail(
            f"pinned offline Cargo build failed with exit {completed.returncode}: "
            f"{detail[-16_384:].strip() or 'no diagnostic'}"
        )
    require_no_ancestor_cargo_configs(invocation_directory)
    if rust_source_tree_identity(rustc) != rust_source_identity:
        fail("pinned rust-src library tree changed during the build")

    kernel = target_directory / KERNEL_RELATIVE
    if not kernel.exists():
        fail(f"Cargo did not produce the expected kernel: {kernel}")
    cargo_lock_identity = dependency_archives["cargo_lock"]
    assert isinstance(cargo_lock_identity, dict)
    require_unchanged(
        CARGO_LOCK,
        "Cargo.lock",
        cargo_lock_identity,
        maximum=4 * 1024 * 1024,
    )
    require_unchanged(
        CARGO_CONFIG,
        "tracked bare-metal Cargo config",
        cargo_config_identity,
        maximum=64 * 1024,
    )
    require_unchanged(
        staged_cargo_config,
        "staged bare-metal Cargo config",
        staged_config_identity,
        maximum=64 * 1024,
    )
    for archive_path, archive_identity in tracked_archives:
        require_unchanged(
            archive_path,
            f"registry archive {archive_path.name}",
            archive_identity,
        )
    for tool_name, identity in tools.items():
        require_unchanged(
            pathlib.Path(str(identity["path"])),
            f"build tool {tool_name}",
            identity,
        )
    return kernel, tools, dependency_archives


def qemu_argv(kernel: pathlib.Path) -> list[str]:
    """Return the verifier-frozen QEMU argv, including exact order."""
    return [
        str(QEMU_PATH),
        "-no-user-config",
        "-machine",
        QEMU_MACHINE,
        "-cpu",
        QEMU_CPU,
        "-smp",
        QEMU_SMP,
        "-m",
        QEMU_MEMORY,
        "-accel",
        QEMU_ACCEL,
        "-icount",
        QEMU_ICOUNT,
        "-nographic",
        "-nic",
        "none",
        "-bios",
        str(BIOS_PATH),
        "-kernel",
        str(pathlib.Path(os.path.abspath(os.fspath(kernel)))),
    ]


def uart_tail(raw: bytes, lines: int = 80) -> str:
    decoded = raw.decode("utf-8", errors="replace").replace("\r", "\n")
    return "\n".join(decoded.splitlines()[-lines:])


def capture_failure(message: str, raw: bytes) -> NoReturn:
    tail = uart_tail(raw)
    suffix = f"\n--- fixed-QEMU UART tail ---\n{tail}" if tail else ""
    fail(message + suffix)


def transcript_failure(raw: bytes) -> str | None:
    lowered = raw.lower()
    if FAIL_PREFIX.lower().encode("ascii") in lowered:
        return "guest emitted explicit C8.8-F5 FAIL"
    for marker in FATAL_MARKERS:
        if marker.encode("ascii") in lowered:
            return f"guest emitted fatal marker {marker!r}"
    return None


def complete_line_count(raw: bytes, prefix: str) -> int:
    count = 0
    for line in raw.splitlines(keepends=True):
        if not line.endswith((b"\n", b"\r")):
            continue
        normalized = line.rstrip(b"\r\n")
        if normalized.startswith(prefix.encode("ascii")):
            count += 1
    return count


def capture_qemu(
    kernel: pathlib.Path,
    transcript: pathlib.Path,
    *,
    timeout: float,
    campaign: pathlib.Path,
) -> bytes:
    command = qemu_argv(kernel)
    qemu_home = campaign / "qemu-home"
    qemu_tmp = campaign / "qemu-tmp"
    qemu_xdg = campaign / "qemu-xdg"
    qemu_home.mkdir(mode=0o700)
    qemu_tmp.mkdir(mode=0o700)
    qemu_xdg.mkdir(mode=0o700)
    environment = {
        "HOME": str(qemu_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(qemu_tmp),
        "TZ": "UTC",
        "XDG_CONFIG_HOME": str(qemu_xdg),
    }
    print(
        "C8.8-F5: booting fixed QEMU 11.0.3 contract "
        f"machine={QEMU_MACHINE} cpu={QEMU_CPU} smp={QEMU_SMP} "
        f"memory={QEMU_MEMORY} accel={QEMU_ACCEL} icount={QEMU_ICOUNT}",
        file=sys.stderr,
    )
    try:
        process = subprocess.Popen(
            command,
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )
    except OSError as error:
        fail(f"cannot start pinned QEMU: {error}")

    try:
        if process.stdout is None:
            fail("pinned QEMU stdout pipe was not created")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        raw = bytearray()
        deadline = time.monotonic() + timeout
        with transcript.open("xb") as output:
            while True:
                drained = False
                while True:
                    try:
                        chunk = os.read(descriptor, READ_CHUNK_BYTES)
                    except BlockingIOError:
                        break
                    if not chunk:
                        break
                    drained = True
                    if len(raw) + len(chunk) > MAX_UART_BYTES:
                        capture_failure(
                            f"UART exceeded the {MAX_UART_BYTES}-byte bound", bytes(raw)
                        )
                    raw.extend(chunk)
                    output.write(chunk)

                snapshot = bytes(raw)
                failure = transcript_failure(snapshot)
                if failure is not None:
                    capture_failure(failure, snapshot)
                if len(snapshot.splitlines()) > MAX_UART_LINES:
                    capture_failure(
                        f"UART exceeded the {MAX_UART_LINES}-line bound", snapshot
                    )

                meta_count = complete_line_count(snapshot, META_PREFIX)
                end_count = complete_line_count(snapshot, END_PREFIX)
                pass_count = complete_line_count(snapshot, PASS_PREFIX)
                if meta_count > 1 or end_count > 1 or pass_count > 1:
                    capture_failure(
                        "guest emitted duplicate META, END, or PASS records", snapshot
                    )
                now = time.monotonic()
                if pass_count == 1 and (meta_count != 1 or end_count != 1):
                    capture_failure("PASS arrived before one META and END", snapshot)

                returncode = process.poll()
                if returncode is not None:
                    # Drain once more after exit so the final pipe bytes are not lost.
                    while True:
                        try:
                            chunk = os.read(descriptor, READ_CHUNK_BYTES)
                        except BlockingIOError:
                            break
                        if not chunk:
                            break
                        if len(raw) + len(chunk) > MAX_UART_BYTES:
                            capture_failure(
                                f"UART exceeded the {MAX_UART_BYTES}-byte bound",
                                bytes(raw),
                            )
                        raw.extend(chunk)
                        output.write(chunk)
                    snapshot = bytes(raw)
                    failure = transcript_failure(snapshot)
                    if failure is not None:
                        capture_failure(failure, snapshot)
                    if returncode != 0:
                        capture_failure(
                            f"QEMU exited with nonzero status {returncode}", snapshot
                        )
                    if complete_line_count(snapshot, PASS_PREFIX) != 1:
                        capture_failure(
                            f"QEMU exited with {returncode} before one complete PASS",
                            snapshot,
                        )
                    output.flush()
                    os.fsync(output.fileno())
                    return snapshot

                if now >= deadline:
                    capture_failure(
                        f"QEMU timed out after {timeout:.1f}s waiting for PASS",
                        snapshot,
                    )
                if not drained:
                    time.sleep(0.01)
    finally:
        stop_process_group(process, "QEMU")


def records_with_prefix(raw: bytes, prefix: str, label: str) -> list[dict[str, object]]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"UART transcript is not strict UTF-8: {error}")
    result: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if FAMILY_PREFIX in line and not line.startswith(FAMILY_PREFIX):
            fail(f"C8.8-F5 family text is not column-zero on line {line_number}")
        if not line.startswith(prefix):
            continue
        payload = line[len(prefix) :]
        if not payload or payload != payload.strip():
            fail(f"{label} payload has surrounding whitespace on line {line_number}")
        decoded = strict_json_text(payload, f"UART {label} line {line_number}")
        if not isinstance(decoded, dict):
            fail(f"UART {label} is not a JSON object on line {line_number}")
        result.append(decoded)
    return result


def transcript_bindings(
    raw: bytes,
    *,
    source_commit: str,
    source_tree: str,
    challenge: str,
    run_id: str,
    manifest_sha256: str,
    transcript_schema_sha256: str,
) -> str:
    metadata = records_with_prefix(raw, META_PREFIX, "META")
    endings = records_with_prefix(raw, END_PREFIX, "END")
    passings = records_with_prefix(raw, PASS_PREFIX, "PASS")
    if len(metadata) != 1 or len(endings) != 1 or len(passings) != 1:
        fail(
            "UART must contain exactly one complete META, END, and PASS before "
            "independent verification"
        )
    bindings = {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "challenge": challenge,
        "run_id": run_id,
        "manifest_sha256": manifest_sha256,
        "transcript_schema_sha256": transcript_schema_sha256,
    }
    for key, expected in bindings.items():
        if metadata[0].get(key) != expected:
            fail(f"guest META {key} differs from the runner-bound value")
    if "kernel_sha256" in metadata[0]:
        fail(
            "guest META must not self-bind kernel_sha256; kernel identity is "
            "host-measured in the environment envelope"
        )
    semantic = endings[0].get("semantic_sha256")
    if not isinstance(semantic, str):
        fail("END semantic_sha256 must be a string")
    canonical_hex(semantic, HEX64, 64, "END semantic_sha256")
    for label, terminal in (("END", endings[0]), ("PASS", passings[0])):
        if terminal.get("challenge") != challenge:
            fail(f"guest {label} challenge differs")
        if terminal.get("run_id") != run_id:
            fail(f"guest {label} run_id differs")
        if terminal.get("semantic_sha256") != semantic:
            fail(f"guest {label} semantic_sha256 differs")
    return str(semantic)


def qemu_version() -> str:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    actual = run_text([str(QEMU_PATH), "--version"], cwd="/", environment=environment)
    if actual != QEMU_VERSION:
        fail(f"pinned QEMU version text differs: {actual!r}")
    return actual


def write_bytes_exclusive(
    path: pathlib.Path,
    raw: bytes,
    *,
    label: str,
    registry: list[OutputToken] | None = None,
) -> OutputToken:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    token: OutputToken | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    fail(f"new {label} is not a direct singly-linked regular file")
                token = (path, metadata.st_dev, metadata.st_ino)
                if registry is not None:
                    # Register inside the O_EXCL writer, before the first data
                    # write, so even BaseException cannot fall into the caller
                    # gap between successful creation and token publication.
                    registry.append(token)
                view = memoryview(raw)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail(f"short write while creating {path}")
                    view = view[written:]
                os.fsync(descriptor)
            except BaseException:
                if token is None:
                    # Recover the identity from the still-open O_EXCL handle;
                    # this closes the signal/exception window immediately
                    # after os.open() and before the normal fstat assignment.
                    metadata = os.fstat(descriptor)
                    token = (path, metadata.st_dev, metadata.st_ino)
                    if registry is not None:
                        registry.append(token)
                raise
        finally:
            os.close(descriptor)
        final_metadata = path.lstat()
        if (
            final_metadata.st_dev != token[1]
            or final_metadata.st_ino != token[2]
            or not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_nlink != 1
        ):
            fail(f"new {label} path changed while it was created")
        return token
    except BaseException as error:
        rollback_error = None
        if token is not None:
            rollback_error = remove_new_output(token)
        if isinstance(error, OSError):
            suffix = f"; {rollback_error}" if rollback_error is not None else ""
            fail(f"cannot create {label} {path}: {error}{suffix}")
        if rollback_error is not None:
            try:
                error.add_note(rollback_error)
            except AttributeError:
                pass
        raise


def write_json_exclusive(
    path: pathlib.Path,
    value: dict[str, object],
    *,
    registry: list[OutputToken] | None = None,
) -> OutputToken:
    return write_bytes_exclusive(
        path,
        environment_json_bytes(value),
        label="environment envelope",
        registry=registry,
    )


def invoke_verifier(
    uart: pathlib.Path,
    environment_path: pathlib.Path,
    kernel: pathlib.Path,
    elf_audit: pathlib.Path,
    *,
    python_path: pathlib.Path,
) -> str:
    command = [
        str(python_path),
        "-I",
        "-B",
        str(VERIFIER),
        "--uart",
        str(uart),
        "--environment",
        str(environment_path),
        "--kernel",
        str(kernel),
        "--elf-audit",
        str(elf_audit),
    ]
    verifier_environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    completed = run_command(
        command,
        cwd=ROOT,
        environment=verifier_environment,
        maximum_output=2 * 1024 * 1024,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        fail(f"independent F5 verifier rejected the evidence: {detail.strip()}")
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        fail(f"independent verifier output is not UTF-8: {error}")


def invoke_elf_auditor(
    kernel: pathlib.Path,
    report_path: pathlib.Path,
    *,
    rustup_path: pathlib.Path,
    python_path: pathlib.Path,
) -> tuple[dict[str, object], dict[str, object]]:
    command = [
        str(python_path),
        "-I",
        "-B",
        str(ELF_AUDITOR),
        "--elf",
        str(kernel),
        "--output",
        str(report_path),
    ]
    audit_environment = {
        "HOME": str(pathlib.Path.home()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join((str(rustup_path.parent), "/usr/bin", "/bin")),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    completed = run_command(
        command,
        cwd=ROOT,
        environment=audit_environment,
        maximum_output=MAX_ELF_AUDIT_BYTES,
        timeout_seconds=BUILD_COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        if report_path.exists():
            _, raw_failure = stable_file_bytes(
                report_path,
                "failed final-ELF audit report",
                maximum=MAX_ELF_AUDIT_BYTES,
            )
            detail = raw_failure.decode("utf-8", errors="replace")
        fail(f"final RISC-V ELF auditor rejected the kernel: {detail.strip()}")
    if completed.stdout or completed.stderr:
        fail("successful final RISC-V ELF auditor emitted unexpected process output")

    _, raw = stable_file_bytes(
        report_path, "final RISC-V ELF audit report", maximum=MAX_ELF_AUDIT_BYTES
    )
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"final RISC-V ELF audit report is not UTF-8: {error}")
    value = strict_json_text(decoded, "final RISC-V ELF audit report")
    if not isinstance(value, dict):
        fail("final RISC-V ELF audit report must be one JSON object")
    canonical = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        fail("final RISC-V ELF audit report is not canonical JSON")
    if (
        value.get("schema") != "vibeos.c88.f5.riscv-final-elf.audit"
        or value.get("schema_version") != 1
        or value.get("mode") != "audit"
        or value.get("status") != "pass"
        or value.get("target") != TARGET
    ):
        fail("final RISC-V ELF audit report has the wrong success envelope")
    elf = value.get("elf")
    if not isinstance(elf, dict):
        fail("final RISC-V ELF audit report has no ELF object")
    kernel_identity = file_identity(kernel, "audited F5 kernel ELF")
    if (
        elf.get("sha256") != kernel_identity["sha256"]
        or elf.get("bytes") != kernel_identity["bytes"]
    ):
        fail("final RISC-V ELF audit report differs from the built kernel identity")
    return value, file_identity(
        report_path, "final RISC-V ELF audit report", maximum=MAX_ELF_AUDIT_BYTES
    )


def environment_envelope(
    *,
    source_commit: str,
    source_tree: str,
    kernel: dict[str, object],
    qemu: dict[str, object],
    bios: dict[str, object],
    uart: dict[str, object],
    manifest: dict[str, object],
    producer: dict[str, object],
    qualification: dict[str, object],
    runner: dict[str, object],
    verifier: dict[str, object],
    elf_auditor: dict[str, object],
    elf_audit_report: dict[str, object],
    elf_audit: dict[str, object],
    build_tools: dict[str, dict[str, object]],
    dependency_archives: dict[str, object],
    python: dict[str, object],
    challenge: str,
    run_id: str,
    manifest_sha256: str,
    transcript_schema_sha256: str,
    expected_semantic_sha256: str,
) -> dict[str, object]:
    qemu_record = {
        **qemu,
        "version": QEMU_VERSION,
        "argv": qemu_argv(pathlib.Path(str(kernel["path"]))),
    }
    return {
        "schema": ENVIRONMENT_SCHEMA,
        "version": 1,
        "suite_id": SUITE_ID,
        "mode": "formal-qemu",
        "source": {
            "commit": source_commit,
            "tree": source_tree,
            "clean": True,
            "branch": FORMAL_BRANCH,
            "remote_ref": FORMAL_REMOTE_REF,
            "remote_commit": source_commit,
        },
        "platform": dict(PLATFORM),
        "build": {
            "target": TARGET,
            "package": "vibeos-firmware-qemu-virt",
            "feature": FEATURE,
            "profile": "release",
            "no_default_features": True,
            "locked": True,
            "offline": True,
            "rustflags": list(F5_RUSTFLAGS),
        },
        "build_tools": build_tools,
        "dependency_archives": dependency_archives,
        "python": python,
        "kernel": kernel,
        "qemu": qemu_record,
        "bios": bios,
        "uart": uart,
        "manifest": manifest,
        "producer": producer,
        "qualification": qualification,
        "runner": runner,
        "verifier": verifier,
        "elf_auditor": elf_auditor,
        "elf_audit_report": elf_audit_report,
        "elf_audit": elf_audit,
        "challenge": challenge,
        "run_id": run_id,
        "manifest_sha256": manifest_sha256,
        "transcript_schema_sha256": transcript_schema_sha256,
        "expected_semantic_sha256": expected_semantic_sha256,
    }


def destination(path: pathlib.Path, label: str) -> pathlib.Path:
    selected = pathlib.Path(os.path.abspath(os.fspath(path)))
    try:
        selected.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        fail(f"formal {label} output must be outside the Git worktree")
    if os.path.lexists(selected):
        fail(f"formal {label} output already exists: {selected}")
    try:
        parent_metadata = selected.parent.lstat()
        resolved_parent = selected.parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect {label} output directory: {error}")
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        fail(f"{label} output parent must be one direct existing directory")
    if resolved_parent != selected.parent:
        fail(f"{label} output directory must not traverse symbolic-link ancestors")
    return selected


def copy_exclusive(
    source: pathlib.Path,
    target: pathlib.Path,
    *,
    label: str,
    maximum: int = MAX_IDENTITY_BYTES,
    registry: list[OutputToken] | None = None,
) -> OutputToken:
    _, raw = stable_file_bytes(source, label, maximum=maximum)
    return write_bytes_exclusive(
        target,
        raw,
        label=f"published {label}",
        registry=registry,
    )


def remove_new_output(token: OutputToken) -> str | None:
    path, expected_device, expected_inode = token
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_dev != expected_device
            or metadata.st_ino != expected_inode
        ):
            return f"refused to remove replaced or non-direct output {path}"
        path.unlink()
    except FileNotFoundError:
        return None
    except OSError as error:
        return f"cannot remove {path}: {error}"
    return None


def verify_qemu_contract() -> None:
    fake_kernel = pathlib.Path("/private/tmp/vibeos-c88-f5-selftest/kernel")
    expected = [
        str(QEMU_PATH),
        "-no-user-config",
        "-machine",
        "virt",
        "-cpu",
        "rv64",
        "-smp",
        "1",
        "-m",
        "128M",
        "-accel",
        "tcg,thread=single",
        "-icount",
        "shift=0,align=off,sleep=off",
        "-nographic",
        "-nic",
        "none",
        "-bios",
        str(BIOS_PATH),
        "-kernel",
        str(fake_kernel),
    ]
    if qemu_argv(fake_kernel) != expected:
        fail("selftest: QEMU argv differs from the verifier-frozen order")


def selftest() -> None:
    verify_qemu_contract()
    if git_environment().get("GIT_NO_REPLACE_OBJECTS") != "1":
        fail("selftest: Git replace objects are not disabled")
    if fixed_campaign_root() != FORMAL_TEMP_ROOT:
        fail("selftest: fixed campaign root differs")
    try:
        strict_json_text('{"a":1,"a":2}', "selftest duplicate")
    except RunnerError:
        pass
    else:
        fail("selftest: duplicate JSON member was accepted")
    try:
        strict_json_text('{"a":NaN}', "selftest nonfinite")
    except RunnerError:
        pass
    else:
        fail("selftest: non-finite JSON number was accepted")

    source_commit = "1" * 40
    source_tree = "2" * 40
    challenge = "3" * 64
    manifest = "4" * 64
    schema = "5" * 64
    run_id = compute_run_id(source_commit, source_tree, challenge, manifest, schema)
    canonical_hex(run_id, HEX64, 64, "selftest run_id")
    semantic = "6" * 64
    meta = {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "challenge": challenge,
        "run_id": run_id,
        "manifest_sha256": manifest,
        "transcript_schema_sha256": schema,
    }
    terminal = {
        "challenge": challenge,
        "run_id": run_id,
        "semantic_sha256": semantic,
    }
    raw = (
        META_PREFIX
        + json.dumps(meta, separators=(",", ":"), sort_keys=True)
        + "\n"
        + END_PREFIX
        + json.dumps(terminal, separators=(",", ":"), sort_keys=True)
        + "\n"
        + PASS_PREFIX
        + json.dumps(terminal, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    actual = transcript_bindings(
        raw,
        source_commit=source_commit,
        source_tree=source_tree,
        challenge=challenge,
        run_id=run_id,
        manifest_sha256=manifest,
        transcript_schema_sha256=schema,
    )
    if actual != semantic:
        fail("selftest: terminal semantic binding differs")
    if complete_line_count(raw, META_PREFIX) != 1:
        fail("selftest: complete-line counter differs")
    if transcript_failure(raw) is not None:
        fail("selftest: valid synthetic transcript was classified as fatal")
    if transcript_failure(raw + b"VIBE_C88_F5_FAIL reason=selftest\n") is None:
        fail("selftest: explicit FAIL marker was accepted")

    python = str(pathlib.Path(sys.executable).resolve(strict=True))
    completed = run_command(
        [
            python,
            "-I",
            "-B",
            "-c",
            "import sys;sys.stdout.buffer.write(b'out');sys.stderr.buffer.write(b'err')",
        ],
        maximum_output=16,
        timeout_seconds=5.0,
    )
    if (
        completed.returncode != 0
        or completed.stdout != b"out"
        or completed.stderr != b"err"
    ):
        fail("selftest: bounded subprocess capture differs")
    try:
        run_command(
            [python, "-I", "-B", "-c", "import sys;sys.stdout.write('x'*4096)"],
            maximum_output=32,
            timeout_seconds=5.0,
        )
    except RunnerError:
        pass
    else:
        fail("selftest: subprocess diagnostic cap was not enforced")
    try:
        run_command(
            [python, "-I", "-B", "-c", "import time;time.sleep(10)"],
            maximum_output=32,
            timeout_seconds=0.05,
        )
    except RunnerError:
        pass
    else:
        fail("selftest: subprocess timeout was not enforced")

    with tempfile.TemporaryDirectory(
        prefix="vibeos-c88-f5-output-selftest-", dir="/private/tmp"
    ) as temporary_name:
        directory = pathlib.Path(temporary_name)
        source = directory / "source"
        source.write_bytes(b"source-bytes")
        occupied = directory / "occupied"
        occupied.write_bytes(b"do-not-delete")
        try:
            copy_exclusive(source, occupied, label="selftest occupied output")
        except RunnerError:
            pass
        else:
            fail("selftest: O_EXCL accepted a pre-existing output")
        if occupied.read_bytes() != b"do-not-delete":
            fail("selftest: failed publication changed a pre-existing output")

        published = directory / "published"
        publication_registry: list[OutputToken] = []
        token = copy_exclusive(
            source,
            published,
            label="selftest output",
            registry=publication_registry,
        )
        if publication_registry != [token]:
            fail("selftest: successful publication was not registered in the writer")
        published.unlink()
        published.write_bytes(b"replacement")
        rollback_error = remove_new_output(token)
        if rollback_error is None or published.read_bytes() != b"replacement":
            fail("selftest: inode-bound rollback removed a replacement output")

        interrupted = directory / "interrupted"
        interrupted_registry: list[OutputToken] = []
        original_write = os.write

        def interrupt_write(_descriptor: int, _raw: bytes | memoryview) -> int:
            raise KeyboardInterrupt("selftest publication interruption")

        os.write = interrupt_write
        try:
            write_bytes_exclusive(
                interrupted,
                b"must-be-rolled-back",
                label="selftest interrupted output",
                registry=interrupted_registry,
            )
        except KeyboardInterrupt:
            pass
        else:
            fail("selftest: publication interruption was not propagated")
        finally:
            os.write = original_write
        if len(interrupted_registry) != 1 or os.path.lexists(interrupted):
            fail("selftest: BaseException left an unregistered or partial output")

        lingering_marker = directory / "lingering-child-survived"
        lingering_code = (
            "import os,signal,sys,time\n"
            "read_fd,write_fd=os.pipe()\n"
            "child=os.fork()\n"
            "if child == 0:\n"
            " os.close(read_fd)\n"
            " signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            " os.write(write_fd,b'1')\n"
            " os.close(write_fd);os.close(1);os.close(2)\n"
            " time.sleep(0.5)\n"
            " open(sys.argv[1],'xb').write(b'survived')\n"
            " time.sleep(10)\n"
            "else:\n"
            " os.close(write_fd);os.read(read_fd,1);os.close(read_fd)\n"
            " print(child,flush=True)\n"
        )
        lingering = run_command(
            [python, "-I", "-B", "-c", lingering_code, str(lingering_marker)],
            maximum_output=64,
            timeout_seconds=5.0,
        )
        if lingering.returncode != 0 or not lingering.stdout.strip().isdigit():
            fail("selftest: lingering-child fixture did not complete")
        time.sleep(0.75)
        if os.path.lexists(lingering_marker):
            fail("selftest: leader exit allowed a same-PGID descendant to survive")

        cargo_ancestor = directory / "cargo-ancestor"
        cargo_invocation = cargo_ancestor / "nested" / "invocation"
        cargo_invocation.mkdir(parents=True)
        ancestor_config_directory = cargo_ancestor / ".cargo"
        ancestor_config_directory.mkdir()
        ancestor_config = ancestor_config_directory / "config.toml"
        ancestor_config.write_bytes(b"[build]\nrustc-wrapper = 'forbidden'\n")
        try:
            require_no_ancestor_cargo_configs(cargo_invocation)
        except RunnerError:
            pass
        else:
            fail("selftest: ambient ancestor Cargo config was accepted")
    print("qemu-c88-f5-float-target.py selftest: PASS")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect fixed-QEMU C8.8-F5 exact-bit/fuel evidence.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--challenge",
        help="canonical nonzero 64-hex challenge (random when omitted)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=positive_timeout,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="bounded whole-boot timeout",
    )
    parser.add_argument(
        "--allow-dirty-smoke",
        action="store_true",
        help="allow development capture but disable verification/export evidence",
    )
    parser.add_argument(
        "--uart-out",
        type=pathlib.Path,
        help="copy the verified formal UART transcript to this absent file",
    )
    parser.add_argument(
        "--environment-out",
        type=pathlib.Path,
        help="copy the exact formal environment JSON to this absent file",
    )
    parser.add_argument(
        "--kernel-out",
        type=pathlib.Path,
        help="retain the exact audited and booted formal kernel at this absent file",
    )
    parser.add_argument(
        "--elf-audit-out",
        type=pathlib.Path,
        help="retain the exact formal final-ELF audit at this absent file",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="exercise parsers/contracts without building or running QEMU",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = argument_parser().parse_args(argv)
    created_outputs: list[OutputToken] = []
    try:
        if arguments.selftest:
            if (
                arguments.challenge is not None
                or arguments.allow_dirty_smoke
                or arguments.uart_out is not None
                or arguments.environment_out is not None
                or arguments.kernel_out is not None
                or arguments.elf_audit_out is not None
                or arguments.timeout_seconds != DEFAULT_TIMEOUT_SECONDS
            ):
                fail("--selftest does not accept collection options")
            selftest()
            return 0

        formal = not arguments.allow_dirty_smoke
        requested_outputs = (
            arguments.kernel_out,
            arguments.elf_audit_out,
            arguments.uart_out,
            arguments.environment_out,
        )
        if formal and not all(path is not None for path in requested_outputs):
            fail(
                "formal evidence requires all four absent destinations: "
                "--kernel-out, --elf-audit-out, --uart-out, and --environment-out"
            )
        if not formal and any(path is not None for path in requested_outputs):
            fail("--allow-dirty-smoke cannot export formal evidence")

        kernel_output = destination(arguments.kernel_out, "kernel") if formal else None
        elf_audit_output = (
            destination(arguments.elf_audit_out, "ELF audit") if formal else None
        )
        uart_output = destination(arguments.uart_out, "UART") if formal else None
        environment_output = (
            destination(arguments.environment_out, "environment") if formal else None
        )
        if formal:
            normalized_outputs = {
                kernel_output,
                elf_audit_output,
                uart_output,
                environment_output,
            }
            if None in normalized_outputs or len(normalized_outputs) != 4:
                fail("formal evidence outputs must name four different files")

        source_commit, source_tree = git_identity()
        require_repository_state(source_commit, source_tree, clean=formal)
        if formal:
            require_pushed_formal_branch(source_commit)
        challenge = canonical_hex(
            arguments.challenge or secrets.token_hex(32),
            HEX64,
            64,
            "challenge",
        )
        if formal and challenge == "3" * 64:
            fail("formal mode cannot use the documented selftest challenge sentinel")

        manifest_identity = fixed_identity(
            QUALIFICATION_MANIFEST,
            "qualification manifest",
            expected_sha256=QUALIFICATION_MANIFEST_SHA256,
            expected_bytes=QUALIFICATION_MANIFEST_BYTES,
        )
        verifier_identity = file_identity(
            VERIFIER, "independent verifier", maximum=MAX_CONTRACT_BYTES
        )
        elf_auditor_identity = file_identity(
            ELF_AUDITOR, "final RISC-V ELF auditor", maximum=MAX_CONTRACT_BYTES
        )
        producer_identity = file_identity(
            PRODUCER, "guest producer", maximum=MAX_CONTRACT_BYTES
        )
        qualification_identity = file_identity(
            QUALIFICATION, "shared qualification", maximum=MAX_CONTRACT_BYTES
        )
        runner_identity = file_identity(
            pathlib.Path(__file__), "running F5 runner", maximum=MAX_CONTRACT_BYTES
        )
        try:
            python_path = pathlib.Path(sys.executable).resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve the running Python interpreter: {error}")
        python_identity = file_identity(
            python_path, "Python interpreter", maximum=MAX_IDENTITY_BYTES
        )
        manifest_sha256 = str(manifest_identity["sha256"])
        transcript_schema_sha256 = str(verifier_identity["sha256"])
        run_id = compute_run_id(
            source_commit,
            source_tree,
            challenge,
            manifest_sha256,
            transcript_schema_sha256,
        )

        mode = "formal-qemu" if formal else "DIRTY-SMOKE-NOT-EVIDENCE"
        if not formal:
            print(
                "WARNING: dirty smoke mode is not C8.8-F5 evidence; independent "
                "formal verification and export are disabled.",
                file=sys.stderr,
            )
        print(
            f"C8.8-F5: mode={mode} source={source_commit} tree={source_tree} "
            f"challenge={challenge} run_id={run_id}",
            file=sys.stderr,
        )

        temporary_root = fixed_campaign_root()
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c88-f5-qemu-", dir=temporary_root
        ) as temporary_name:
            campaign = pathlib.Path(temporary_name)
            built_kernel, build_tools, dependency_archives = build_kernel(
                campaign,
                source_commit=source_commit,
                source_tree=source_tree,
                challenge=challenge,
                run_id=run_id,
                manifest_sha256=manifest_sha256,
                transcript_schema_sha256=transcript_schema_sha256,
            )
            require_repository_state(source_commit, source_tree, clean=formal)

            built_kernel_identity = file_identity(built_kernel, "built F5 kernel ELF")
            if formal:
                assert kernel_output is not None
                copy_exclusive(
                    built_kernel,
                    kernel_output,
                    label="built F5 kernel ELF",
                    registry=created_outputs,
                )
                kernel_path = kernel_output
                kernel_identity = file_identity(kernel_path, "published F5 kernel ELF")
                if (
                    kernel_identity["sha256"] != built_kernel_identity["sha256"]
                    or kernel_identity["bytes"] != built_kernel_identity["bytes"]
                ):
                    fail("published F5 kernel differs from the just-built ELF")
            else:
                kernel_path = built_kernel
                kernel_identity = built_kernel_identity
            staged_elf_audit_path = campaign / "riscv-final-elf-audit.json"
            rustup_path = pathlib.Path(str(build_tools["rustup"]["path"]))
            elf_audit, staged_elf_audit_identity = invoke_elf_auditor(
                kernel_path,
                staged_elf_audit_path,
                rustup_path=rustup_path,
                python_path=python_path,
            )
            if formal:
                assert elf_audit_output is not None
                copy_exclusive(
                    staged_elf_audit_path,
                    elf_audit_output,
                    label="final RISC-V ELF audit report",
                    maximum=MAX_ELF_AUDIT_BYTES,
                    registry=created_outputs,
                )
                elf_audit_path = elf_audit_output
                elf_audit_report_identity = file_identity(
                    elf_audit_path,
                    "published final RISC-V ELF audit report",
                    maximum=MAX_ELF_AUDIT_BYTES,
                )
                if (
                    elf_audit_report_identity["sha256"]
                    != staged_elf_audit_identity["sha256"]
                    or elf_audit_report_identity["bytes"]
                    != staged_elf_audit_identity["bytes"]
                ):
                    fail("published final-ELF audit differs from the verified report")
            else:
                elf_audit_path = staged_elf_audit_path
                elf_audit_report_identity = staged_elf_audit_identity
            require_unchanged(kernel_path, "F5 kernel ELF", kernel_identity)
            qemu_identity = fixed_identity(
                QEMU_PATH,
                "pinned QEMU 11.0.3",
                expected_sha256=QEMU_SHA256,
                expected_bytes=QEMU_BYTES,
                executable=True,
            )
            bios_identity = fixed_identity(
                BIOS_PATH,
                "pinned OpenSBI BIOS",
                expected_sha256=BIOS_SHA256,
                expected_bytes=BIOS_BYTES,
            )
            version = qemu_version()
            if version != QEMU_VERSION:
                fail("pinned QEMU version changed after validation")

            transcript = campaign / "qemu-uart.log"
            raw = capture_qemu(
                kernel_path,
                transcript,
                timeout=arguments.timeout_seconds,
                campaign=campaign,
            )
            semantic_sha256 = transcript_bindings(
                raw,
                source_commit=source_commit,
                source_tree=source_tree,
                challenge=challenge,
                run_id=run_id,
                manifest_sha256=manifest_sha256,
                transcript_schema_sha256=transcript_schema_sha256,
            )
            if semantic_sha256 != EXPECTED_SEMANTIC_SHA256:
                fail("guest semantic digest differs from the frozen host witness")

            require_repository_state(source_commit, source_tree, clean=formal)
            require_unchanged(kernel_path, "F5 kernel ELF", kernel_identity)
            require_unchanged(QEMU_PATH, "pinned QEMU 11.0.3", qemu_identity)
            require_unchanged(BIOS_PATH, "pinned OpenSBI BIOS", bios_identity)
            require_unchanged(
                QUALIFICATION_MANIFEST,
                "qualification manifest",
                manifest_identity,
                maximum=MAX_CONTRACT_BYTES,
            )
            require_unchanged(
                VERIFIER,
                "independent verifier",
                verifier_identity,
                maximum=MAX_CONTRACT_BYTES,
            )
            require_unchanged(
                ELF_AUDITOR,
                "final RISC-V ELF auditor",
                elf_auditor_identity,
                maximum=MAX_CONTRACT_BYTES,
            )
            require_unchanged(
                elf_audit_path,
                "final RISC-V ELF audit report",
                elf_audit_report_identity,
                maximum=MAX_ELF_AUDIT_BYTES,
            )
            require_unchanged(
                PRODUCER,
                "guest producer",
                producer_identity,
                maximum=MAX_CONTRACT_BYTES,
            )
            require_unchanged(
                QUALIFICATION,
                "shared qualification",
                qualification_identity,
                maximum=MAX_CONTRACT_BYTES,
            )
            require_unchanged(
                pathlib.Path(__file__),
                "running F5 runner",
                runner_identity,
                maximum=MAX_CONTRACT_BYTES,
            )
            for tool_name, identity in build_tools.items():
                require_unchanged(
                    pathlib.Path(str(identity["path"])),
                    f"build tool {tool_name}",
                    identity,
                )
            require_unchanged(
                python_path,
                "Python interpreter",
                python_identity,
            )

            if formal:
                assert uart_output is not None
                assert environment_output is not None
                copy_exclusive(
                    transcript,
                    uart_output,
                    label="captured F5 UART transcript",
                    maximum=MAX_UART_BYTES,
                    registry=created_outputs,
                )
                uart_identity = file_identity(
                    uart_output,
                    "published F5 UART transcript",
                    maximum=MAX_UART_BYTES,
                )
                if uart_identity["sha256"] != hashlib.sha256(
                    raw
                ).hexdigest() or uart_identity["bytes"] != len(raw):
                    fail("published UART differs from the captured transcript")
                envelope_value = environment_envelope(
                    source_commit=source_commit,
                    source_tree=source_tree,
                    kernel=kernel_identity,
                    qemu=qemu_identity,
                    bios=bios_identity,
                    uart=uart_identity,
                    manifest=manifest_identity,
                    producer=producer_identity,
                    qualification=qualification_identity,
                    runner=runner_identity,
                    verifier=verifier_identity,
                    elf_auditor=elf_auditor_identity,
                    elf_audit_report=elf_audit_report_identity,
                    elf_audit=elf_audit,
                    build_tools=build_tools,
                    dependency_archives=dependency_archives,
                    python=python_identity,
                    challenge=challenge,
                    run_id=run_id,
                    manifest_sha256=manifest_sha256,
                    transcript_schema_sha256=transcript_schema_sha256,
                    expected_semantic_sha256=semantic_sha256,
                )
                envelope_value["evidence_sha256"] = hashlib.sha256(
                    canonical_json_bytes(envelope_value)
                ).hexdigest()
                write_json_exclusive(
                    environment_output,
                    envelope_value,
                    registry=created_outputs,
                )
                expected_environment = environment_json_bytes(envelope_value)
                environment_identity = file_identity(
                    environment_output,
                    "published F5 environment envelope",
                    maximum=MAX_ENVIRONMENT_BYTES,
                )
                if environment_identity["sha256"] != hashlib.sha256(
                    expected_environment
                ).hexdigest() or environment_identity["bytes"] != len(
                    expected_environment
                ):
                    fail("published environment differs from its canonical envelope")
                verifier_result = invoke_verifier(
                    uart_output,
                    environment_output,
                    kernel_path,
                    elf_audit_path,
                    python_path=python_path,
                )
                require_repository_state(source_commit, source_tree, clean=True)
                require_pushed_formal_branch(source_commit)
                require_unchanged(
                    kernel_path, "published F5 kernel ELF", kernel_identity
                )
                require_unchanged(
                    elf_audit_path,
                    "published final RISC-V ELF audit report",
                    elf_audit_report_identity,
                    maximum=MAX_ELF_AUDIT_BYTES,
                )
                require_unchanged(
                    uart_output,
                    "published F5 UART transcript",
                    uart_identity,
                    maximum=MAX_UART_BYTES,
                )
                require_unchanged(
                    environment_output,
                    "published F5 environment envelope",
                    environment_identity,
                    maximum=MAX_ENVIRONMENT_BYTES,
                )
                require_unchanged(
                    python_path,
                    "Python interpreter",
                    python_identity,
                )
            else:
                verifier_result = (
                    "dirty smoke capture only; formal verifier not invoked"
                )

        print(verifier_result)
        print(
            f"PASS qemu-c88-f5-float-target mode={mode} source={source_commit} "
            f"tree={source_tree} challenge={challenge} run_id={run_id} "
            f"semantic_sha256={semantic_sha256} uart_sha256={hashlib.sha256(raw).hexdigest()} "
            "physical_provenance=not-claimed"
        )
        return 0
    except RunnerError as error:
        rollback_errors = [
            rollback_error
            for token in reversed(created_outputs)
            if (rollback_error := remove_new_output(token)) is not None
        ]
        print(f"FAIL qemu-c88-f5-float-target: {error}", file=sys.stderr)
        for rollback_error in rollback_errors:
            print(
                f"FAIL qemu-c88-f5-float-target rollback: {rollback_error}",
                file=sys.stderr,
            )
        return 1
    except BaseException:
        for token in reversed(created_outputs):
            rollback_error = remove_new_output(token)
            if rollback_error is not None:
                print(
                    f"FAIL qemu-c88-f5-float-target rollback: {rollback_error}",
                    file=sys.stderr,
                )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
