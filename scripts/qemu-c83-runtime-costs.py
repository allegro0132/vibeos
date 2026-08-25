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


def toolchain_pin() -> tuple[str, str]:
    try:
        document = TOOLCHAIN_FILE.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {TOOLCHAIN_FILE}: {error}")
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


def build_kernel(source_commit: str, challenge: str) -> dict[str, object]:
    channel, expected_rustc = toolchain_pin()
    rustup_path = resolve_executable("rustup", "rustup")
    cargo_path = pinned_tool(rustup_path, channel, "cargo")
    rustc_path = pinned_tool(rustup_path, channel, "rustc")
    rustdoc_path = pinned_tool(rustup_path, channel, "rustdoc")
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
    version = run_text([rustc_path, "-Vv"])
    actual = re.search(r"^commit-hash: ([0-9a-f]{40})$", version, re.MULTILINE)
    if actual is None or actual.group(1) != expected_rustc:
        fail(
            "pinned rustc commit differs: "
            f"expected {expected_rustc}, got {actual.group(1) if actual else 'unavailable'}"
        )

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
    print(f"C8.3: building dedicated {FEATURE} image", file=sys.stderr)
    # Cargo otherwise merges $CARGO_HOME/config.toml with the reviewed local
    # configuration. Use an ephemeral, config-free home that exposes only the
    # already-fetched registry/Git caches, and whitelist the complete build
    # environment. This closes ambient wrappers, rustflags, profile overrides,
    # source replacement, and target-directory overrides while retaining a
    # browser-free/offline build.
    source_cargo_home = ambient_cargo_home()
    host_home = os.environ.get("HOME")
    if not host_home:
        fail("HOME is required for the sanitized Cargo build")
    rustup_home = str(
        pathlib.Path(
            os.environ.get("RUSTUP_HOME", str(pathlib.Path(host_home) / ".rustup"))
        ).expanduser().resolve(strict=True)
    )
    source_date_epoch = run_text(
        ["git", "show", "-s", "--format=%ct", source_commit]
    )
    if not source_date_epoch.isdigit() or int(source_date_epoch) <= 0:
        fail("preparation commit has no valid positive timestamp")
    path_entries = minimal_build_path(rustup_path, linker_path)
    sanitized_linker = shutil.which("ld.lld", path=os.pathsep.join(path_entries))
    if (
        sanitized_linker is None
        or os.path.abspath(sanitized_linker) != linker_path
        or str(pathlib.Path(sanitized_linker).resolve(strict=True))
        != linker_resolved_path
    ):
        fail("sanitized build PATH does not resolve the recorded ld.lld first")
    temporary_root = pathlib.Path(os.environ.get("TMPDIR", "/tmp"))
    try:
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c83-cargo-home-", dir=temporary_root
        ) as temporary_name:
            cargo_home = pathlib.Path(temporary_name) / "cargo-home"
            isolated_home = pathlib.Path(temporary_name) / "home"
            isolated_tmp = pathlib.Path(temporary_name) / "tmp"
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
            normalized_environment = dict(environment)
            normalized_environment["CARGO_HOME"] = "<temporary-root>/cargo-home"
            normalized_environment["HOME"] = "<temporary-root>/home"
            normalized_environment["TMPDIR"] = "<temporary-root>/tmp"
            completed = subprocess.run(
                command, cwd=FIRMWARE, env=environment, check=False
            )
    except OSError as error:
        fail(f"cannot start sanitized pinned Cargo build: {error}")
    if completed.returncode != 0:
        fail(f"pinned Cargo build failed with exit {completed.returncode}")
    if not KERNEL.is_file() or KERNEL.stat().st_size == 0:
        fail(f"Cargo did not produce the expected kernel: {KERNEL}")
    return {
        "channel": channel,
        "pinned_rustc_commit": expected_rustc,
        "rustc_vv": version,
        "cargo_version": run_text([cargo_path, "-V"]),
        **tool_records,
        "cargo_command": command,
        "build_environment_policy": {
            "ambient_variables": "denied-by-default",
            "cargo_home": "ephemeral-config-free registry/git cache links only",
            "cargo_net_offline": True,
            "path_entries": path_entries,
            "allowed_names": sorted(environment),
            "normalized_values": normalized_environment,
        },
    }


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
