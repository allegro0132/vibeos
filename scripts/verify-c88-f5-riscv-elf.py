#!/usr/bin/env python3
"""Fail-closed audit of a final linked C8.8-F5 RISC-V kernel ELF.

This verifier does not build or boot the image.  It binds the repository-pinned
Rust nightly and its bundled LLVM readers, validates the final ELF structure
and RISC-V attributes, scans every executable section as raw variable-length
RISC-V instructions, cross-checks canonical executable coverage with
llvm-objdump, validates trusted direct-control-flow and code-symbol boundaries,
and requires a complete static llvm-nm view with no floating-point helpers.
Arbitrary-PC and hardware-NX claims are explicitly outside this qualification;
the self-test retains an all-LOAD halfword-window diagnostic for that stronger
threat model without using it as a PASS gate.

The report is canonical JSON.  ``--output`` is created with O_EXCL and is never
overwritten; when it is omitted the report is written to stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import tomllib
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Sequence


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"

SCHEMA = "vibeos.c88.f5.riscv-final-elf.audit"
SCHEMA_VERSION = 1
TOOLCHAIN = "nightly-2026-08-01"
TARGET = "riscv64imac-unknown-none-elf"
EXPECTED_HOST = "aarch64-apple-darwin"
EXPECTED_RUSTC_COMMIT = "ad3d0bc141a02cf446e384136d250a1f6950fed5"
EXPECTED_RUSTC_DATE = "2026-07-31"
EXPECTED_RUSTC_RELEASE = "1.99.0-nightly"
EXPECTED_LLVM_VERSION = "22.1.8"
EXPECTED_LLVM_BUILD = "22.1.8-rust-1.99.0-nightly"

# The formal F5 collector is pinned to the Apple-silicon host toolchain used by
# its fixed Homebrew QEMU envelope.  Version strings alone are not identities:
# bind every executable which interprets the qualification ELF.
EXPECTED_TOOL_IDENTITIES = {
    "rustc": {
        "bytes": 413_480,
        "sha256": "fa817099946eee0d4a4ed1d6593b05596f34f92181363e467c6253e84ce431af",
    },
    "llvm-readobj": {
        "bytes": 1_791_936,
        "sha256": "5c388043b0ce7698cbce64e9ca94c2d397bad0018b7a104c4da5a0b8348053a4",
    },
    "llvm-objdump": {
        "bytes": 943_328,
        "sha256": "82a155f861d4c87deaed3c85193a645f4556a60c4634ff13b09cde44fa5d6ec7",
    },
    "llvm-nm": {
        "bytes": 166_008,
        "sha256": "096bc03c2848d5d99d78e3e2c3671092c67cedafef9c8c46d9c1b54f63215d4a",
    },
}

EXPECTED_RISCV_ARCH = (
    "rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_" "zaamo1p0_zalrsc1p0_zca1p0"
)
EXPECTED_E_FLAGS = 0x1  # EF_RISCV_RVC with the soft-float ABI encoding.
EF_RISCV_FLOAT_ABI = 0x6

MAX_ELF_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 4096
MAX_PROGRAM_HEADERS = 256
MAX_TOOL_OUTPUT = 128 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 120
U64_SPACE = 1 << 64

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF_PROGRAM = struct.Struct("<IIQQQQQQ")

ET_EXEC = 2
EM_RISCV = 243
EV_CURRENT = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_RISCV_ATTRIBUTES = 0x70000003

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MERGE = 0x10
SHF_STRINGS = 0x20

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_RISCV_ATTRIBUTES = 0x70000003
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

FORBIDDEN_MAJOR_OPCODES = {
    0x07: "LOAD-FP/LOAD-V",
    0x27: "STORE-FP/STORE-V",
    0x43: "MADD-FP",
    0x47: "MSUB-FP",
    0x4B: "NMSUB-FP",
    0x4F: "NMADD-FP",
    0x53: "OP-FP",
    0x57: "OP-V",
}
FP_CSRS = {0x001: "fflags", 0x002: "frm", 0x003: "fcsr"}
ALLOWED_F_MNEMONICS = {"fence", "fence.i", "fence.tso"}
FORBIDDEN_DIRECTIVES = {
    ".byte",
    ".short",
    ".2byte",
    ".word",
    ".4byte",
    ".long",
    ".insn",
}

FP_FORMAT = r"(?:hf|bf|sf|df|xf|tf)"
FP_HELPER_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        rf"__(?:add|sub|mul|div|mod|neg){FP_FORMAT}3",
        rf"__fma{FP_FORMAT}4",
        rf"__(?:cmp|eq|ne|ge|gt|le|lt|unord){FP_FORMAT}2",
        rf"__powi{FP_FORMAT}2",
        rf"__(?:extend|trunc){FP_FORMAT}{FP_FORMAT}2",
        rf"__fix(?:uns)?{FP_FORMAT}(?:si|di|ti)",
        rf"__float(?:un)?(?:si|di|ti){FP_FORMAT}",
        r"__(?:mul|div)[sdxt]c3",
        r"__gnu_(?:f2h|h2f)_ieee",
        r"__aeabi_[fd](?:add|sub|mul|div|neg|cmp|cmpeq|cmplt|cmple|2iz|2lz|2uiz|2ulz)",
    )
)

LIBM_BASES = frozenset(
    "acos acosh asin asinh atan atan2 atanh cbrt ceil copysign cos cosh "
    "erf erfc exp exp2 expm1 fabs fdim floor fma fmax fmin fmod frexp "
    "hypot ilogb ldexp lgamma log log10 log1p log2 logb lrint llrint "
    "lround llround modf nan nearbyint nextafter nexttoward pow remainder "
    "remquo rint round roundeven scalbn scalbln sin sinh sqrt tan tanh "
    "tgamma trunc".split()
)
CLONE_SUFFIX = re.compile(
    r"(?:\.llvm\.[0-9A-Fa-f]+|\.constprop\.[0-9]+|\.isra\.[0-9]+|"
    r"\.part\.[0-9]+|\.cold(?:\.[0-9]+)?)$"
)

SECTION_NAME = re.compile(r"[A-Za-z0-9._+-]+\Z")
NM_DEFINED = re.compile(r"(.+) ([A-Za-z?]) ([0-9A-Fa-f]+) ([0-9A-Fa-f]+)\Z")
NM_UNDEFINED = re.compile(r"(.+) ([Uu?])(?: ([0-9A-Fa-f]+) ([0-9A-Fa-f]+))?\Z")
OBJDUMP_INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)(?:\s+.*)?$")
OBJDUMP_ADDRESS_LINE = re.compile(r"^\s*[0-9A-Fa-f]+:")


class AuditFailure(RuntimeError):
    """A deterministic fail-closed audit result."""

    def __init__(
        self, code: str, message: str, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


def fail(code: str, message: str, details: dict[str, Any] | None = None) -> NoReturn:
    raise AuditFailure(code, message, details)


@dataclass(frozen=True)
class FileBlob:
    path: Path
    data: bytes
    size: int
    sha256: str
    device: int
    inode: int
    mtime_ns: int


@dataclass(frozen=True)
class Toolchain:
    rustc: Path
    readobj: Path
    objdump: Path
    nm: Path
    identities: dict[str, dict[str, int | str]]


@dataclass(frozen=True)
class ElfHeaderRecord:
    elf_type: int
    machine: int
    version: int
    entry: int
    program_offset: int
    section_offset: int
    flags: int
    header_size: int
    program_entry_size: int
    program_count: int
    section_entry_size: int
    section_count: int
    shstr_index: int


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    section_type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class ProgramHeader:
    index: int
    segment_type: int
    flags: int
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    alignment: int


@dataclass(frozen=True)
class ElfImage:
    header: ElfHeaderRecord
    sections: tuple[Section, ...]
    programs: tuple[ProgramHeader, ...]


@dataclass(frozen=True)
class RawScan:
    section: Section
    lengths: array
    two_byte: int
    four_byte: int
    sha256: str
    forbidden: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class WindowScan:
    halfword_starts: int
    word_starts: int
    forbidden_count: int
    examples: tuple[dict[str, str], ...]


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def write_report(report: object, output: Path | None) -> None:
    encoded = canonical_json(report)
    if output is None:
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return

    requested = Path(os.path.abspath(os.fspath(output)))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(requested, flags, 0o600)
    except OSError as error:
        fail("output.exclusive", f"cannot exclusively create report: {error.strerror}")
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("output.write", "short write while emitting report")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def checked_region(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        fail(
            "elf.bounds",
            f"{label} is outside the ELF file",
            {"offset": offset, "size": size},
        )
    return data[offset : offset + size]


def read_stable_file(path: Path, label: str, maximum: int) -> FileBlob:
    requested = Path(os.path.abspath(os.fspath(path)))
    if any(character in os.fspath(requested) for character in "\r\n\t"):
        fail("file.path", f"{label} path contains a control character")
    try:
        before = requested.lstat()
    except OSError as error:
        fail("file.open", f"cannot stat {label}: {error.strerror}")
    if not stat.S_ISREG(before.st_mode):
        fail("file.type", f"{label} is not a regular file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(
            "file.size",
            f"{label} size is outside the allowed range",
            {"bytes": before.st_size, "maximum": maximum},
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(requested, flags)
    except OSError as error:
        fail("file.open", f"cannot open {label}: {error.strerror}")
    try:
        opened = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_opened = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if identity_before != identity_opened:
            fail("file.race", f"{label} changed while it was opened")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail("file.read", f"unexpected EOF while reading {label}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail("file.read", f"{label} grew while it was read")
        after = os.fstat(descriptor)
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_opened != identity_after:
            fail("file.race", f"{label} changed while it was read")
    finally:
        os.close(descriptor)

    data = b"".join(chunks)
    return FileBlob(
        path=requested,
        data=data,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        device=before.st_dev,
        inode=before.st_ino,
        mtime_ns=before.st_mtime_ns,
    )


def assert_file_unchanged(original: FileBlob, label: str) -> None:
    current = read_stable_file(original.path, label, original.size)
    if (
        current.size != original.size
        or current.sha256 != original.sha256
        or current.device != original.device
        or current.inode != original.inode
        or current.mtime_ns != original.mtime_ns
    ):
        fail("file.race", f"{label} changed during the audit")


def command_environment() -> dict[str, str]:
    home = os.environ.get("HOME")
    if not home or not os.path.isabs(home):
        fail("toolchain.environment", "HOME must be an absolute path for rustup")
    return {
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    """Bounded best-effort teardown for a tool and any descendants it spawned."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    # The group can outlive its leader when a descendant ignores SIGTERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        fail("tool.teardown", "tool process group resisted SIGKILL")


def run_command(
    command: Sequence[str | os.PathLike[str]],
    *,
    maximum_output: int,
    timeout_seconds: float = TOOL_TIMEOUT_SECONDS,
) -> bytes:
    rendered = [os.fspath(part) for part in command]
    if not rendered:
        fail("tool.exec", "cannot execute an empty command")
    if maximum_output < 0:
        fail("tool.output-limit", "tool output limit cannot be negative")
    if timeout_seconds <= 0:
        fail("tool.timeout", "tool timeout must be positive")
    try:
        process = subprocess.Popen(
            rendered,
            cwd="/",
            env=command_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        fail("tool.exec", f"cannot execute {Path(rendered[0]).name}: {error.strerror}")

    if process.stdout is None or process.stderr is None:
        stop_process_group(process)
        fail("tool.exec", f"cannot capture {Path(rendered[0]).name} output")

    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        for stream, destination in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)

        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                stop_process_group(process)
                fail(
                    "tool.timeout",
                    f"{Path(rendered[0]).name} exceeded the time limit",
                )
            events = selector.select(remaining_time)
            if not events:
                stop_process_group(process)
                fail(
                    "tool.timeout",
                    f"{Path(rendered[0]).name} exceeded the time limit",
                )
            for key, _mask in events:
                stream = key.fileobj
                destination = key.data
                total = len(stdout) + len(stderr)
                allowance = maximum_output - total
                try:
                    chunk = os.read(stream.fileno(), min(64 * 1024, allowance + 1))
                except BlockingIOError:
                    continue
                except OSError as error:
                    stop_process_group(process)
                    fail(
                        "tool.read",
                        f"cannot read {Path(rendered[0]).name} output: {error.strerror}",
                    )
                if not chunk:
                    selector.unregister(stream)
                    continue
                destination.extend(chunk)
                total = len(stdout) + len(stderr)
                if total > maximum_output:
                    stop_process_group(process)
                    fail(
                        "tool.output-limit",
                        f"{Path(rendered[0]).name} exceeded its output limit",
                        {"bytes": total, "maximum": maximum_output},
                    )

        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            stop_process_group(process)
            fail("tool.timeout", f"{Path(rendered[0]).name} exceeded the time limit")
        try:
            return_code = process.wait(timeout=remaining_time)
        except subprocess.TimeoutExpired:
            stop_process_group(process)
            fail("tool.timeout", f"{Path(rendered[0]).name} exceeded the time limit")
    except BaseException:
        if process.poll() is None:
            stop_process_group(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    if return_code != 0:
        fail(
            "tool.exit",
            f"{Path(rendered[0]).name} exited unsuccessfully",
            {"exit_code": return_code},
        )
    if stderr:
        fail(
            "tool.stderr",
            f"{Path(rendered[0]).name} emitted unexpected stderr",
            {"bytes": len(stderr)},
        )
    return bytes(stdout)


def strict_utf8(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail("tool.encoding", f"{label} output is not UTF-8: byte {error.start}")


def parse_key_values(text: str, label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in values:
            fail("tool.version", f"{label} repeated version key {key!r}")
        values[key] = value
    return values


def verify_identity(path: Path, name: str) -> dict[str, int | str]:
    expected = EXPECTED_TOOL_IDENTITIES[name]
    blob = read_stable_file(path, name, 16 * 1024 * 1024)
    observed = {"bytes": blob.size, "sha256": blob.sha256}
    if observed != expected:
        fail(
            "tool.identity",
            f"pinned {name} identity mismatch",
            {"expected": expected, "observed": observed},
        )
    if not os.access(blob.path, os.X_OK):
        fail("tool.permissions", f"pinned {name} is not executable")
    return observed


def locate_toolchain() -> Toolchain:
    try:
        raw_contract = TOOLCHAIN_FILE.read_bytes()
        contract = tomllib.loads(raw_contract.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail("toolchain.contract", f"cannot parse rust-toolchain.toml: {error}")
    expected_contract = {
        "toolchain": {
            "channel": TOOLCHAIN,
            "components": ["rust-src", "llvm-tools-preview"],
            "profile": "minimal",
        }
    }
    if contract != expected_contract:
        fail("toolchain.contract", "rust-toolchain.toml contract drifted")
    marker = f"# rustc-commit: {EXPECTED_RUSTC_COMMIT}\n".encode("ascii")
    if raw_contract.count(marker) != 1:
        fail("toolchain.contract", "rust-toolchain.toml lost its unique commit pin")

    rustup_name = shutil.which("rustup")
    if rustup_name is None:
        fail("toolchain.missing", "rustup is required")
    rustup = Path(rustup_name).resolve(strict=True)
    rustc_text = strict_utf8(
        run_command(
            [rustup, "which", "--toolchain", TOOLCHAIN, "rustc"],
            maximum_output=16 * 1024,
        ),
        "rustup which rustc",
    )
    if not rustc_text.endswith("\n") or rustc_text.count("\n") != 1:
        fail("toolchain.resolve", "rustup returned a non-canonical rustc path")
    rustc = Path(rustc_text[:-1]).resolve(strict=True)
    rustc_info = parse_key_values(
        strict_utf8(run_command([rustc, "-Vv"], maximum_output=64 * 1024), "rustc -Vv"),
        "rustc",
    )
    expected_info = {
        "binary": "rustc",
        "commit-hash": EXPECTED_RUSTC_COMMIT,
        "commit-date": EXPECTED_RUSTC_DATE,
        "host": EXPECTED_HOST,
        "release": EXPECTED_RUSTC_RELEASE,
        "LLVM version": EXPECTED_LLVM_VERSION,
    }
    if rustc_info != expected_info:
        fail(
            "toolchain.version",
            "pinned rustc verbose identity drifted",
            {"expected": expected_info, "observed": rustc_info},
        )

    sysroot_text = strict_utf8(
        run_command([rustc, "--print", "sysroot"], maximum_output=16 * 1024),
        "rustc sysroot",
    )
    if not sysroot_text.endswith("\n") or sysroot_text.count("\n") != 1:
        fail("toolchain.resolve", "rustc returned a non-canonical sysroot")
    sysroot = Path(sysroot_text[:-1]).resolve(strict=True)
    if rustc.parent.parent != sysroot:
        fail("toolchain.resolve", "rustc is outside its reported sysroot")
    llvm_directory = sysroot / "lib" / "rustlib" / EXPECTED_HOST / "bin"
    tools = {
        name: (llvm_directory / name).resolve(strict=True)
        for name in ("llvm-readobj", "llvm-objdump", "llvm-nm")
    }
    for name, path in tools.items():
        if path.parent != llvm_directory:
            fail("toolchain.resolve", f"{name} escaped the pinned LLVM directory")

    paths = {"rustc": rustc, **tools}
    identities = {name: verify_identity(path, name) for name, path in paths.items()}
    version_pattern = re.compile(
        rf"^  LLVM version {re.escape(EXPECTED_LLVM_BUILD)}$", re.MULTILINE
    )
    for name, path in tools.items():
        version = strict_utf8(
            run_command([path, "--version"], maximum_output=512 * 1024),
            f"{name} --version",
        )
        if len(version_pattern.findall(version)) != 1:
            fail("tool.version", f"pinned {name} LLVM build version drifted")

    return Toolchain(
        rustc=rustc,
        readobj=tools["llvm-readobj"],
        objdump=tools["llvm-objdump"],
        nm=tools["llvm-nm"],
        identities=identities,
    )


def parse_elf(data: bytes) -> ElfImage:
    if len(data) < ELF_HEADER.size:
        fail("elf.header", "ELF is shorter than an ELF64 header")
    unpacked = ELF_HEADER.unpack_from(data)
    ident = unpacked[0]
    if ident[:4] != b"\x7fELF":
        fail("elf.magic", "input does not have ELF magic")
    if ident[4] != ELFCLASS64 or ident[5] != ELFDATA2LSB or ident[6] != EV_CURRENT:
        fail("elf.ident", "ELF must be 64-bit, little-endian, and current-version")
    if ident[7] != 0 or ident[8] != 0 or any(ident[9:]):
        fail("elf.ident", "ELF OS/ABI identification is not the frozen SystemV form")

    header = ElfHeaderRecord(*unpacked[1:])
    if header.header_size != ELF_HEADER.size:
        fail("elf.header", "ELF header size is not 64 bytes")
    if header.program_entry_size != ELF_PROGRAM.size:
        fail("elf.header", "ELF program-header entry size is not 56 bytes")
    if header.section_entry_size != ELF_SECTION.size:
        fail("elf.header", "ELF section-header entry size is not 64 bytes")
    if not 0 < header.program_count <= MAX_PROGRAM_HEADERS:
        fail("elf.header", "ELF program-header count is absent, extended, or excessive")
    if not 1 < header.section_count <= MAX_SECTIONS:
        fail("elf.header", "ELF section count is absent, extended, or excessive")
    if header.shstr_index in (0, 0xFFFF) or header.shstr_index >= header.section_count:
        fail("elf.header", "ELF section-name table index is invalid or extended")
    checked_region(
        data,
        header.program_offset,
        header.program_count * ELF_PROGRAM.size,
        "program-header table",
    )
    checked_region(
        data,
        header.section_offset,
        header.section_count * ELF_SECTION.size,
        "section-header table",
    )

    raw_sections = [
        ELF_SECTION.unpack_from(data, header.section_offset + index * ELF_SECTION.size)
        for index in range(header.section_count)
    ]
    if any(raw_sections[0]):
        fail("elf.sections", "ELF null section header is not all zero")
    shstr = raw_sections[header.shstr_index]
    if shstr[1] != SHT_STRTAB or shstr[5] < 2:
        fail("elf.sections", "ELF section-name table is not a nonempty string table")
    names = checked_region(data, shstr[4], shstr[5], "section-name table")
    if names[0] != 0 or names[-1] != 0:
        fail("elf.sections", "ELF section-name table lacks canonical NUL boundaries")

    sections: list[Section] = []
    seen_names: set[str] = set()
    file_ranges: list[tuple[int, int, str]] = []
    for index, raw in enumerate(raw_sections):
        name_offset = raw[0]
        if name_offset >= len(names):
            fail("elf.sections", f"section {index} name offset is out of bounds")
        name_end = names.find(b"\0", name_offset)
        if name_end < 0:
            fail("elf.sections", f"section {index} name is unterminated")
        try:
            name = names[name_offset:name_end].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            fail("elf.sections", f"section {index} name is not ASCII")
        if index == 0:
            if name:
                fail("elf.sections", "null section has a name")
        else:
            if SECTION_NAME.fullmatch(name) is None:
                fail("elf.sections", f"section {index} has a non-canonical name")
            if name in seen_names:
                fail("elf.sections", f"duplicate section name {name!r}")
            seen_names.add(name)

        section = Section(index, name, *raw[1:])
        if section.alignment and section.alignment & (section.alignment - 1):
            fail("elf.sections", f"section {name!r} alignment is not a power of two")
        if section.section_type == SHT_NOBITS:
            if section.offset > len(data):
                fail("elf.bounds", f"NOBITS section {name!r} has an invalid offset")
        elif section.size:
            checked_region(data, section.offset, section.size, f"section {name!r}")
            file_ranges.append((section.offset, section.offset + section.size, name))
        sections.append(section)

    ordered_ranges = sorted(file_ranges)
    for previous, current in zip(ordered_ranges, ordered_ranges[1:]):
        if current[0] < previous[1]:
            fail(
                "elf.sections",
                "file-backed ELF sections overlap",
                {"first": previous[2], "second": current[2]},
            )

    programs: list[ProgramHeader] = []
    for index in range(header.program_count):
        raw = ELF_PROGRAM.unpack_from(
            data, header.program_offset + index * ELF_PROGRAM.size
        )
        program = ProgramHeader(index, *raw)
        if program.file_size > program.memory_size:
            fail(
                "elf.programs", f"program header {index} has filesz greater than memsz"
            )
        if program.file_size:
            checked_region(data, program.offset, program.file_size, f"segment {index}")
        if program.alignment and program.alignment & (program.alignment - 1):
            fail(
                "elf.programs",
                f"program header {index} alignment is not a power of two",
            )
        programs.append(program)
    return ElfImage(header, tuple(sections), tuple(programs))


def range_contains(start: int, size: int, child_start: int, child_size: int) -> bool:
    return (
        child_start >= start
        and child_size <= size
        and child_start - start <= size - child_size
    )


def checked_memory_end(start: int, size: int, label: str) -> int:
    if start < 0 or size < 0 or start >= U64_SPACE or size > U64_SPACE - start:
        fail("elf.address", f"{label} wraps the 64-bit address space")
    return start + size


def allocated_permissions(section: Section) -> int:
    permissions = PF_R
    if section.flags & SHF_WRITE:
        permissions |= PF_W
    if section.flags & SHF_EXECINSTR:
        permissions |= PF_X
    return permissions


def validate_allocated_mappings(
    sections: Sequence[Section], loads: Sequence[ProgramHeader]
) -> dict[int, ProgramHeader]:
    """Bind every nonempty allocated section to exactly one semantic LOAD.

    File-backed sections must use the same file-to-memory translation as their
    owning LOAD.  NOBITS has no file range to translate, so it is instead
    required to live wholly in the owning LOAD's zero-filled memory suffix.
    Empty marker sections occupy no bytes and intentionally have no owner.
    """

    allocated = tuple(
        section for section in sections if section.flags & SHF_ALLOC and section.size
    )
    ordered_memory = sorted(
        allocated, key=lambda section: (section.address, section.size, section.index)
    )
    memory_ends = {
        section.index: checked_memory_end(
            section.address, section.size, f"allocated section {section.name!r}"
        )
        for section in allocated
    }
    for previous, current in zip(ordered_memory, ordered_memory[1:]):
        if current.address < memory_ends[previous.index]:
            fail(
                "elf.sections",
                "allocated ELF sections overlap in memory",
                {"first": previous.name, "second": current.name},
            )

    owners: dict[int, ProgramHeader] = {}
    for section in allocated:
        if section.section_type not in (SHT_PROGBITS, SHT_NOBITS):
            fail(
                "elf.mapping",
                f"allocated section {section.name!r} is not PROGBITS or NOBITS",
            )
        candidates = [
            program
            for program in loads
            if program.flags == allocated_permissions(section)
            and range_contains(
                program.virtual_address,
                program.memory_size,
                section.address,
                section.size,
            )
        ]
        if len(candidates) != 1:
            fail(
                "elf.mapping",
                f"allocated section {section.name!r} lacks one exact LOAD memory owner",
            )
        owner = candidates[0]
        if section.section_type == SHT_NOBITS:
            zero_fill_start = owner.virtual_address + owner.file_size
            if section.address < zero_fill_start:
                fail(
                    "elf.mapping",
                    f"NOBITS section {section.name!r} overlaps file-backed LOAD memory",
                )
        else:
            if not range_contains(
                owner.offset, owner.file_size, section.offset, section.size
            ):
                fail(
                    "elf.mapping",
                    f"file-backed section {section.name!r} is outside its LOAD file range",
                )
            file_delta = section.offset - owner.offset
            memory_delta = section.address - owner.virtual_address
            if file_delta != memory_delta:
                fail(
                    "elf.mapping",
                    f"section {section.name!r} has inconsistent file/memory LOAD mapping",
                    {"file_delta": file_delta, "memory_delta": memory_delta},
                )
        owners[section.index] = owner

    for program in loads:
        if program.flags != (PF_R | PF_X):
            continue
        if (
            program.file_size == 0
            or program.file_size != program.memory_size
            or program.offset & 1
            or program.virtual_address & 1
        ):
            fail(
                "elf.exec-coverage",
                f"executable LOAD segment {program.index} has non-canonical bounds",
            )
        owned = sorted(
            (
                section
                for section in allocated
                if owners[section.index].index == program.index
                and section.flags & SHF_EXECINSTR
            ),
            key=lambda section: (section.address, section.offset, section.index),
        )
        expected_address = program.virtual_address
        expected_offset = program.offset
        for section in owned:
            if section.address != expected_address or section.offset != expected_offset:
                fail(
                    "elf.exec-coverage",
                    f"executable LOAD segment {program.index} has a gap or overlap",
                    {
                        "expected_address": f"0x{expected_address:016x}",
                        "expected_offset": expected_offset,
                        "section": section.name,
                        "section_address": f"0x{section.address:016x}",
                        "section_offset": section.offset,
                    },
                )
            expected_address += section.size
            expected_offset += section.size
        if (
            expected_address
            != checked_memory_end(
                program.virtual_address,
                program.memory_size,
                f"executable LOAD segment {program.index}",
            )
            or expected_offset != program.offset + program.file_size
        ):
            fail(
                "elf.exec-coverage",
                f"executable LOAD segment {program.index} has an uncovered tail",
            )
    return owners


def validate_elf_policy(image: ElfImage) -> tuple[Section, tuple[Section, ...], int]:
    header = image.header
    if (header.elf_type, header.machine, header.version) != (
        ET_EXEC,
        EM_RISCV,
        EV_CURRENT,
    ):
        fail("elf.target", "ELF must be an EM_RISCV ET_EXEC current-version image")
    if header.entry == 0:
        fail("elf.entry", "ELF entry point is zero")
    if header.flags & EF_RISCV_FLOAT_ABI:
        fail("elf.flags", "ELF declares a non-soft RISC-V float ABI")
    if header.flags != EXPECTED_E_FLAGS:
        fail(
            "elf.flags",
            "ELF flags differ from the frozen RVC soft-ABI contract",
            {"expected": EXPECTED_E_FLAGS, "observed": header.flags},
        )

    allowed_section_types = {
        SHT_NULL,
        SHT_PROGBITS,
        SHT_SYMTAB,
        SHT_STRTAB,
        SHT_NOBITS,
        SHT_RISCV_ATTRIBUTES,
    }
    forbidden_types = {SHT_RELA, SHT_DYNAMIC, SHT_REL, SHT_DYNSYM}
    for section in image.sections:
        if (
            section.section_type in forbidden_types
            or section.section_type not in allowed_section_types
        ):
            fail(
                "elf.sections",
                f"section {section.name!r} has a forbidden or unknown type",
                {"type": section.section_type},
            )
        if section.flags & SHF_EXECINSTR:
            if section.section_type != SHT_PROGBITS or section.flags != (
                SHF_ALLOC | SHF_EXECINSTR
            ):
                fail(
                    "elf.sections",
                    f"executable section {section.name!r} is not exact RX PROGBITS",
                )
            if section.size == 0 or section.address & 1:
                fail(
                    "elf.sections",
                    f"executable section {section.name!r} is empty or misaligned",
                )
        if section.flags & SHF_ALLOC and section.flags & ~(
            SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_MERGE | SHF_STRINGS
        ):
            fail(
                "elf.sections", f"allocated section {section.name!r} has unknown flags"
            )
        if section.flags & SHF_WRITE and section.flags & SHF_EXECINSTR:
            fail("elf.sections", f"section {section.name!r} violates W^X")
        if section.section_type == SHT_NOBITS and section.flags != (
            SHF_ALLOC | SHF_WRITE
        ):
            fail(
                "elf.sections",
                f"NOBITS section {section.name!r} is not exact RW alloc storage",
            )
        if not section.flags & SHF_ALLOC:
            allowed = (
                0 if section.section_type != SHT_PROGBITS else (SHF_MERGE | SHF_STRINGS)
            )
            if section.flags not in (0, allowed):
                fail(
                    "elf.sections",
                    f"non-allocated section {section.name!r} has unexpected flags",
                )

    by_name = {section.name: section for section in image.sections}
    required = {".text", ".riscv.attributes", ".symtab", ".strtab", ".shstrtab"}
    missing = sorted(required - by_name.keys())
    if missing:
        fail(
            "elf.sections",
            "ELF lacks required final-image sections",
            {"missing": missing},
        )
    text = by_name[".text"]
    if text.section_type != SHT_PROGBITS or text.flags != (SHF_ALLOC | SHF_EXECINSTR):
        fail("elf.sections", ".text does not have the frozen executable shape")
    attributes = by_name[".riscv.attributes"]
    if (
        attributes.section_type != SHT_RISCV_ATTRIBUTES
        or attributes.flags != 0
        or not attributes.size
    ):
        fail("elf.attributes", ".riscv.attributes has the wrong type, flags, or size")
    symtab = by_name[".symtab"]
    strtab = by_name[".strtab"]
    shstrtab = by_name[".shstrtab"]
    if (
        symtab.section_type != SHT_SYMTAB
        or symtab.entry_size != 24
        or symtab.size == 0
        or symtab.size % symtab.entry_size
        or symtab.link != strtab.index
        or symtab.info > symtab.size // symtab.entry_size
    ):
        fail(
            "elf.symbols",
            ".symtab is absent, malformed, or linked to the wrong string table",
        )
    if strtab.section_type != SHT_STRTAB or shstrtab.section_type != SHT_STRTAB:
        fail("elf.symbols", "ELF string-table types are malformed")
    if shstrtab.index != header.shstr_index:
        fail("elf.sections", ".shstrtab does not match e_shstrndx")

    executable = tuple(
        section for section in image.sections if section.flags & SHF_EXECINSTR
    )
    if not executable:
        fail("elf.sections", "ELF has no executable sections")
    if not any(
        range_contains(section.address, section.size, header.entry, 1)
        for section in executable
    ):
        fail("elf.entry", "ELF entry point is outside executable sections")

    allowed_program_types = {PT_LOAD, PT_GNU_STACK, PT_RISCV_ATTRIBUTES}
    for program in image.programs:
        if (
            program.segment_type in (PT_DYNAMIC, PT_INTERP)
            or program.segment_type not in allowed_program_types
        ):
            fail(
                "elf.programs",
                "ELF has a forbidden or unknown program-header type",
                {"index": program.index, "type": program.segment_type},
            )
        if program.flags & PF_W and program.flags & PF_X:
            fail("elf.programs", f"program header {program.index} violates W^X")

    loads = tuple(
        program for program in image.programs if program.segment_type == PT_LOAD
    )
    stacks = tuple(
        program for program in image.programs if program.segment_type == PT_GNU_STACK
    )
    attr_segments = tuple(
        program
        for program in image.programs
        if program.segment_type == PT_RISCV_ATTRIBUTES
    )
    if not loads or len(stacks) != 1 or len(attr_segments) != 1:
        fail(
            "elf.programs",
            "ELF must have LOAD segments and one stack/attribute segment",
        )
    ordered_loads = sorted(loads, key=lambda program: program.virtual_address)
    load_memory_ends: dict[int, int] = {}
    for program in ordered_loads:
        load_memory_ends[program.index] = checked_memory_end(
            program.virtual_address,
            program.memory_size,
            f"LOAD segment {program.index}",
        )
        if program.flags not in (PF_R, PF_R | PF_W, PF_R | PF_X):
            fail(
                "elf.programs",
                f"LOAD segment {program.index} has non-canonical permissions",
            )
        if program.alignment != 4096:
            fail("elf.programs", f"LOAD segment {program.index} is not page-aligned")
        if program.virtual_address != program.physical_address:
            fail(
                "elf.programs",
                f"LOAD segment {program.index} has distinct virtual/physical addresses",
            )
        if program.virtual_address & 1 or program.offset & 1:
            fail(
                "elf.programs",
                f"LOAD segment {program.index} is not halfword-aligned",
            )
        if (
            program.offset % program.alignment
            != program.virtual_address % program.alignment
        ):
            fail(
                "elf.programs",
                f"LOAD segment {program.index} violates ELF alignment congruence",
            )
    for previous, current in zip(ordered_loads, ordered_loads[1:]):
        if current.virtual_address < load_memory_ends[previous.index]:
            fail("elf.programs", "LOAD segment memory ranges overlap")
    ordered_file_loads = sorted(
        (program for program in loads if program.file_size),
        key=lambda program: program.offset,
    )
    for previous, current in zip(ordered_file_loads, ordered_file_loads[1:]):
        if current.offset < previous.offset + previous.file_size:
            fail("elf.programs", "LOAD segment file ranges overlap")
    stack = stacks[0]
    if stack.flags != (PF_R | PF_W) or stack.file_size or stack.memory_size:
        fail("elf.programs", "GNU stack segment is not exact non-executable RW")
    attr_segment = attr_segments[0]
    if (
        attr_segment.flags != PF_R
        or attr_segment.offset != attributes.offset
        or attr_segment.file_size != attributes.size
        or attr_segment.memory_size != attributes.size
    ):
        fail(
            "elf.attributes",
            "RISC-V attribute segment does not bind its section exactly",
        )

    validate_allocated_mappings(image.sections, loads)
    if not any(
        program.flags & PF_X
        and range_contains(
            program.virtual_address, program.memory_size, header.entry, 1
        )
        for program in loads
    ):
        fail("elf.entry", "ELF entry point is outside executable LOAD segments")
    return attributes, executable, symtab.size // symtab.entry_size


def reject_duplicate_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("readobj.json", f"llvm-readobj repeated JSON member {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> NoReturn:
    fail("readobj.json", f"llvm-readobj emitted non-finite JSON number {value!r}")


def json_integer(value: object, label: str) -> int:
    if isinstance(value, bool):
        fail("readobj.json", f"{label} is a boolean, not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        return int(value)
    fail("readobj.json", f"{label} is not a canonical integer")


def named_value(value: object, label: str) -> tuple[str, int]:
    if not isinstance(value, dict) or set(value) != {"Name", "Value"}:
        fail("readobj.json", f"{label} is not an exact named value")
    name = value["Name"]
    if not isinstance(name, str):
        fail("readobj.json", f"{label} name is not a string")
    return name, json_integer(value["Value"], f"{label}.Value")


def flags_value(value: object, label: str) -> int:
    if not isinstance(value, dict) or set(value) != {"Value", "Flags"}:
        fail("readobj.json", f"{label} is not an exact flags object")
    if not isinstance(value["Flags"], list):
        fail("readobj.json", f"{label}.Flags is not a list")
    observed: set[tuple[str, int]] = set()
    for index, flag in enumerate(value["Flags"]):
        observed.add(named_value(flag, f"{label}.Flags[{index}]"))
    if len(observed) != len(value["Flags"]):
        fail("readobj.json", f"{label} repeats a named flag")
    return json_integer(value["Value"], f"{label}.Value")


def validate_readobj_json(raw: bytes, elf: FileBlob, image: ElfImage) -> None:
    text = strict_utf8(raw, "llvm-readobj JSON")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json,
            parse_constant=reject_json_constant,
        )
    except json.JSONDecodeError as error:
        fail("readobj.json", f"llvm-readobj emitted invalid JSON at byte {error.pos}")
    if (
        not isinstance(parsed, list)
        or len(parsed) != 1
        or not isinstance(parsed[0], dict)
    ):
        fail("readobj.json", "llvm-readobj JSON must contain exactly one ELF object")
    record = parsed[0]
    expected_keys = {
        "FileSummary",
        "ElfHeader",
        "Sections",
        "ProgramHeaders",
        "DynamicSection",
        "NeededLibraries",
        "Relocations",
    }
    if set(record) != expected_keys:
        fail("readobj.json", "llvm-readobj top-level JSON shape drifted")
    if (
        record["DynamicSection"] != []
        or record["NeededLibraries"] != []
        or record["Relocations"] != []
    ):
        fail("elf.dynamic", "final ELF contains dynamic linkage or relocations")

    summary = record["FileSummary"]
    if not isinstance(summary, dict) or summary != {
        "File": os.fspath(elf.path),
        "Format": "elf64-littleriscv",
        "Arch": "riscv64",
        "AddressSize": "64bit",
        "LoadName": "<Not found>",
    }:
        fail(
            "readobj.summary", "llvm-readobj file summary differs from final RISC-V ELF"
        )

    header = record["ElfHeader"]
    if not isinstance(header, dict):
        fail("readobj.header", "llvm-readobj omitted its ELF header object")
    required_header = {
        "Ident",
        "Type",
        "Machine",
        "Version",
        "Entry",
        "ProgramHeaderOffset",
        "SectionHeaderOffset",
        "Flags",
        "HeaderSize",
        "ProgramHeaderEntrySize",
        "ProgramHeaderCount",
        "SectionHeaderEntrySize",
        "SectionHeaderCount",
        "StringTableSectionIndex",
    }
    if set(header) != required_header:
        fail("readobj.header", "llvm-readobj ELF-header JSON shape drifted")
    machine_name, machine_value = named_value(header["Machine"], "ElfHeader.Machine")
    expected_numeric = {
        "Version": image.header.version,
        "Entry": image.header.entry,
        "ProgramHeaderOffset": image.header.program_offset,
        "SectionHeaderOffset": image.header.section_offset,
        "HeaderSize": image.header.header_size,
        "ProgramHeaderEntrySize": image.header.program_entry_size,
        "ProgramHeaderCount": image.header.program_count,
        "SectionHeaderEntrySize": image.header.section_entry_size,
        "SectionHeaderCount": image.header.section_count,
        "StringTableSectionIndex": image.header.shstr_index,
    }
    if header["Type"] != "Executable (0x2)" or (machine_name, machine_value) != (
        "EM_RISCV",
        EM_RISCV,
    ):
        fail("readobj.header", "llvm-readobj did not identify an executable RISC-V ELF")
    for key, expected in expected_numeric.items():
        if json_integer(header[key], f"ElfHeader.{key}") != expected:
            fail("readobj.header", f"llvm-readobj disagrees with raw ELF field {key}")
    if flags_value(header["Flags"], "ElfHeader.Flags") != image.header.flags:
        fail("readobj.header", "llvm-readobj disagrees with raw ELF flags")

    ident = header["Ident"]
    if not isinstance(ident, dict):
        fail("readobj.header", "llvm-readobj Ident is not an object")
    for key, expected in {
        "Class": ("64-bit", 2),
        "DataEncoding": ("LittleEndian", 1),
        "OS/ABI": ("SystemV", 0),
    }.items():
        if named_value(ident.get(key), f"ElfHeader.Ident.{key}") != expected:
            fail("readobj.header", f"llvm-readobj Ident field {key} drifted")

    sections = record["Sections"]
    if not isinstance(sections, list) or len(sections) != len(image.sections):
        fail("readobj.sections", "llvm-readobj section count differs from raw ELF")
    section_keys = {
        "Index",
        "Name",
        "Type",
        "Flags",
        "Address",
        "Offset",
        "Size",
        "Link",
        "Info",
        "AddressAlignment",
        "EntrySize",
    }
    for expected, wrapper in zip(image.sections, sections):
        if not isinstance(wrapper, dict) or set(wrapper) != {"Section"}:
            fail("readobj.sections", "llvm-readobj section wrapper drifted")
        observed = wrapper["Section"]
        if not isinstance(observed, dict) or set(observed) != section_keys:
            fail("readobj.sections", "llvm-readobj section JSON shape drifted")
        name, _name_offset = named_value(observed["Name"], "Section.Name")
        _type_name, section_type = named_value(observed["Type"], "Section.Type")
        values = (
            json_integer(observed["Index"], "Section.Index"),
            name,
            section_type,
            flags_value(observed["Flags"], "Section.Flags"),
            json_integer(observed["Address"], "Section.Address"),
            json_integer(observed["Offset"], "Section.Offset"),
            json_integer(observed["Size"], "Section.Size"),
            json_integer(observed["Link"], "Section.Link"),
            json_integer(observed["Info"], "Section.Info"),
            json_integer(observed["AddressAlignment"], "Section.AddressAlignment"),
            json_integer(observed["EntrySize"], "Section.EntrySize"),
        )
        expected_values = (
            expected.index,
            expected.name,
            expected.section_type,
            expected.flags,
            expected.address,
            expected.offset,
            expected.size,
            expected.link,
            expected.info,
            expected.alignment,
            expected.entry_size,
        )
        if values != expected_values:
            fail(
                "readobj.sections",
                f"llvm-readobj disagrees with raw section {expected.name!r}",
            )

    programs = record["ProgramHeaders"]
    if not isinstance(programs, list) or len(programs) != len(image.programs):
        fail(
            "readobj.programs", "llvm-readobj program-header count differs from raw ELF"
        )
    program_keys = {
        "Type",
        "Offset",
        "VirtualAddress",
        "PhysicalAddress",
        "FileSize",
        "MemSize",
        "Flags",
        "Alignment",
    }
    for expected, wrapper in zip(image.programs, programs):
        if not isinstance(wrapper, dict) or set(wrapper) != {"ProgramHeader"}:
            fail("readobj.programs", "llvm-readobj program-header wrapper drifted")
        observed = wrapper["ProgramHeader"]
        if not isinstance(observed, dict) or set(observed) != program_keys:
            fail("readobj.programs", "llvm-readobj program-header JSON shape drifted")
        _type_name, segment_type = named_value(observed["Type"], "ProgramHeader.Type")
        values = (
            segment_type,
            flags_value(observed["Flags"], "ProgramHeader.Flags"),
            json_integer(observed["Offset"], "ProgramHeader.Offset"),
            json_integer(observed["VirtualAddress"], "ProgramHeader.VirtualAddress"),
            json_integer(observed["PhysicalAddress"], "ProgramHeader.PhysicalAddress"),
            json_integer(observed["FileSize"], "ProgramHeader.FileSize"),
            json_integer(observed["MemSize"], "ProgramHeader.MemSize"),
            json_integer(observed["Alignment"], "ProgramHeader.Alignment"),
        )
        expected_values = (
            expected.segment_type,
            expected.flags,
            expected.offset,
            expected.virtual_address,
            expected.physical_address,
            expected.file_size,
            expected.memory_size,
            expected.alignment,
        )
        if values != expected_values:
            fail(
                "readobj.programs",
                f"llvm-readobj disagrees with program header {expected.index}",
            )


def expected_attribute_output(path: Path) -> str:
    return f"""
File: {path}
Format: elf64-littleriscv
Arch: riscv64
AddressSize: 64bit
LoadName: <Not found>
BuildAttributes {{
  FormatVersion: 0x41
  Section 1 {{
    SectionLength: 98
    Vendor: riscv
    Tag: Tag_File (0x1)
    Size: 88
    FileAttributes {{
      Attribute {{
        Tag: 4
        Value: 16
        TagName: stack_align
        Description: Stack alignment is 16-bytes
      }}
      Attribute {{
        Tag: 5
        TagName: arch
        Value: {EXPECTED_RISCV_ARCH}
      }}
    }}
  }}
}}
"""


def validate_attributes(raw: bytes, path: Path) -> None:
    text = strict_utf8(raw, "llvm-readobj attributes")
    expected = expected_attribute_output(path)
    if text != expected:
        fail(
            "elf.attributes",
            "RISC-V build attributes differ from the frozen RV64 IMAC contract",
        )


def compressed_fp_kind(halfword: int) -> str | None:
    quadrant = halfword & 0x3
    funct3 = (halfword >> 13) & 0x7
    return {
        (0, 1): "C.FLD",
        (0, 5): "C.FSD",
        (2, 1): "C.FLDSP",
        (2, 5): "C.FSDSP",
    }.get((quadrant, funct3))


def forbidden_word_kind(word: int) -> str | None:
    opcode = word & 0x7F
    if opcode in FORBIDDEN_MAJOR_OPCODES:
        return FORBIDDEN_MAJOR_OPCODES[opcode]
    if opcode == 0x73 and (word >> 12) & 0x7:
        csr = (word >> 20) & 0xFFF
        if csr in FP_CSRS:
            return f"FP-CSR:{FP_CSRS[csr]}"
    return None


def scan_halfword_windows(raw: bytes, base_address: int, source: str) -> WindowScan:
    """Scan every architecturally aligned entry, not just linker boundaries."""

    forbidden_count = 0
    examples: list[dict[str, str]] = []
    halfword_starts = 0
    word_starts = 0
    for position in range(0, len(raw) - 1, 2):
        halfword_starts += 1
        halfword = int.from_bytes(raw[position : position + 2], "little")
        address = base_address + position
        kind = compressed_fp_kind(halfword)
        encoding = f"0x{halfword:04x}"
        if halfword & 0x3 == 0x3 and len(raw) - position >= 4:
            word_starts += 1
            word = int.from_bytes(raw[position : position + 4], "little")
            kind = forbidden_word_kind(word)
            encoding = f"0x{word:08x}"
        if kind is not None:
            forbidden_count += 1
            if len(examples) < 32:
                examples.append(
                    {
                        "address": f"0x{address:016x}",
                        "encoding": encoding,
                        "kind": kind,
                        "source": source,
                    }
                )
    return WindowScan(
        halfword_starts=halfword_starts,
        word_starts=word_starts,
        forbidden_count=forbidden_count,
        examples=tuple(examples),
    )


def scan_loaded_instruction_windows(image: ElfImage, data: bytes) -> WindowScan:
    """Return the deliberately non-gating arbitrary-PC diagnostic."""

    total_halfwords = 0
    total_words = 0
    total_forbidden = 0
    examples: list[dict[str, str]] = []
    for program in image.programs:
        if program.segment_type != PT_LOAD or not program.file_size:
            continue
        raw = checked_region(
            data,
            program.offset,
            program.file_size,
            f"LOAD segment {program.index}",
        )
        scan = scan_halfword_windows(
            raw, program.virtual_address, f"PT_LOAD[{program.index}]"
        )
        total_halfwords += scan.halfword_starts
        total_words += scan.word_starts
        total_forbidden += scan.forbidden_count
        examples.extend(scan.examples[: 32 - len(examples)])
    return WindowScan(
        halfword_starts=total_halfwords,
        word_starts=total_words,
        forbidden_count=total_forbidden,
        examples=tuple(examples),
    )


def scan_instruction_bytes(section: Section, data: bytes) -> RawScan:
    raw = checked_region(
        data, section.offset, section.size, f"executable section {section.name!r}"
    )
    position = 0
    lengths = array("B")
    two_byte = 0
    four_byte = 0
    forbidden: list[dict[str, str]] = []
    while position < len(raw):
        if len(raw) - position < 2:
            fail(
                "opcode.truncated",
                f"executable section {section.name!r} ends with a partial instruction",
            )
        halfword = int.from_bytes(raw[position : position + 2], "little")
        address = section.address + position
        if halfword & 0x3 != 0x3:
            length = 2
            operation = compressed_fp_kind(halfword)
            if operation is not None:
                forbidden.append(
                    {
                        "address": f"0x{address:016x}",
                        "encoding": f"0x{halfword:04x}",
                        "kind": operation,
                    }
                )
            two_byte += 1
        elif halfword & 0x1F != 0x1F:
            length = 4
            if len(raw) - position < length:
                fail(
                    "opcode.truncated",
                    f"executable section {section.name!r} ends with a partial 32-bit instruction",
                )
            word = int.from_bytes(raw[position : position + 4], "little")
            operation = forbidden_word_kind(word)
            if operation is not None:
                forbidden.append(
                    {
                        "address": f"0x{address:016x}",
                        "encoding": f"0x{word:08x}",
                        "kind": operation,
                    }
                )
            four_byte += 1
        else:
            fail(
                "opcode.length",
                f"executable section {section.name!r} contains an unsupported >32-bit encoding",
                {"address": f"0x{address:016x}", "prefix": f"0x{halfword:04x}"},
            )
        lengths.append(length)
        position += length
    return RawScan(
        section=section,
        lengths=lengths,
        two_byte=two_byte,
        four_byte=four_byte,
        sha256=hashlib.sha256(raw).hexdigest(),
        forbidden=tuple(forbidden),
    )


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def compressed_direct_target(halfword: int, address: int) -> tuple[str, int] | None:
    if halfword & 0x3 != 0x1:
        return None
    funct3 = (halfword >> 13) & 0x7
    if funct3 == 5:  # C.J on RV64.
        immediate = (
            (((halfword >> 12) & 0x1) << 11)
            | (((halfword >> 11) & 0x1) << 4)
            | (((halfword >> 9) & 0x3) << 8)
            | (((halfword >> 8) & 0x1) << 10)
            | (((halfword >> 7) & 0x1) << 6)
            | (((halfword >> 6) & 0x1) << 7)
            | (((halfword >> 3) & 0x7) << 1)
            | (((halfword >> 2) & 0x1) << 5)
        )
        return "C.J", address + sign_extend(immediate, 12)
    if funct3 in (6, 7):
        immediate = (
            (((halfword >> 12) & 0x1) << 8)
            | (((halfword >> 10) & 0x3) << 3)
            | (((halfword >> 5) & 0x3) << 6)
            | (((halfword >> 3) & 0x3) << 1)
            | (((halfword >> 2) & 0x1) << 5)
        )
        operation = "C.BEQZ" if funct3 == 6 else "C.BNEZ"
        return operation, address + sign_extend(immediate, 9)
    return None


def word_direct_target(word: int, address: int) -> tuple[str, int] | None:
    opcode = word & 0x7F
    if opcode == 0x6F:  # JAL
        immediate = (
            (((word >> 31) & 0x1) << 20)
            | (((word >> 21) & 0x3FF) << 1)
            | (((word >> 20) & 0x1) << 11)
            | (((word >> 12) & 0xFF) << 12)
        )
        return "JAL", address + sign_extend(immediate, 21)
    if opcode == 0x63:  # Conditional branch family.
        immediate = (
            (((word >> 31) & 0x1) << 12)
            | (((word >> 25) & 0x3F) << 5)
            | (((word >> 8) & 0xF) << 1)
            | (((word >> 7) & 0x1) << 11)
        )
        return "BRANCH", address + sign_extend(immediate, 13)
    return None


def validate_canonical_control_flow(
    scans: Sequence[RawScan], data: bytes, entry: int
) -> tuple[frozenset[int], int]:
    instruction_starts: set[int] = set()
    decoder_boundaries: set[int] = set()
    instructions: list[tuple[int, int, int]] = []
    for scan in scans:
        raw = checked_region(
            data,
            scan.section.offset,
            scan.section.size,
            f"executable section {scan.section.name!r}",
        )
        position = 0
        for length in scan.lengths:
            address = scan.section.address + position
            if address in instruction_starts:
                fail("control.boundaries", "canonical instruction boundaries overlap")
            instruction_starts.add(address)
            decoder_boundaries.add(address)
            encoding = int.from_bytes(raw[position : position + length], "little")
            instructions.append((address, length, encoding))
            position += length
        if position != scan.section.size:
            fail("control.boundaries", "canonical scanner length accounting drifted")
        decoder_boundaries.add(scan.section.address + scan.section.size)

    frozen_starts = frozenset(instruction_starts)
    if entry not in frozen_starts:
        fail(
            "control.entry",
            "ELF entry point is not a canonical instruction boundary",
            {"entry": f"0x{entry:016x}"},
        )

    direct_targets = 0
    for address, length, encoding in instructions:
        resolved = (
            compressed_direct_target(encoding, address)
            if length == 2
            else word_direct_target(encoding, address)
        )
        if resolved is None:
            continue
        operation, target = resolved
        direct_targets += 1
        if target not in frozen_starts:
            fail(
                "control.direct-target",
                "direct branch/jump target is not a canonical instruction boundary",
                {
                    "address": f"0x{address:016x}",
                    "kind": operation,
                    "target": (
                        f"0x{target:016x}" if 0 <= target < U64_SPACE else str(target)
                    ),
                },
            )
    return frozenset(decoder_boundaries), direct_targets


def mnemonic_violation(mnemonic: str) -> str | None:
    if (
        mnemonic != mnemonic.lower()
        or re.fullmatch(r"[a-z0-9_.]+|<unknown>", mnemonic) is None
    ):
        return "non-canonical-mnemonic"
    if (
        mnemonic == "<unknown>"
        or mnemonic in FORBIDDEN_DIRECTIVES
        or mnemonic.startswith(".")
    ):
        return "unknown-or-data-directive"
    if mnemonic.startswith("c.f"):
        return "compressed-fp"
    if mnemonic.startswith("f") and mnemonic not in ALLOWED_F_MNEMONICS:
        return "fp"
    if mnemonic.startswith("v"):
        return "vector"
    return None


def validate_objdump(raw: bytes, elf: FileBlob, scan: RawScan) -> int:
    text = strict_utf8(raw, "llvm-objdump")
    prefix = (
        f"\n{elf.path}:\tfile format elf64-littleriscv\n\n"
        f"Disassembly of section {scan.section.name}:\n"
    )
    if not text.startswith(prefix):
        fail("objdump.shape", f"llvm-objdump header drifted for {scan.section.name!r}")
    count = 0
    expected_address = scan.section.address
    violations: list[dict[str, str]] = []
    for line in text[len(prefix) :].splitlines():
        match = OBJDUMP_INSTRUCTION.fullmatch(line)
        if match is None:
            if OBJDUMP_ADDRESS_LINE.match(line):
                fail(
                    "objdump.shape",
                    "llvm-objdump emitted an unparseable instruction line",
                )
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(2)
        if count >= len(scan.lengths):
            fail(
                "objdump.coverage",
                "llvm-objdump emitted more instructions than the raw scanner",
            )
        if address != expected_address:
            fail(
                "objdump.coverage",
                "llvm-objdump instruction boundaries differ from the raw scanner",
                {
                    "expected": f"0x{expected_address:016x}",
                    "observed": f"0x{address:016x}",
                },
            )
        violation = mnemonic_violation(mnemonic)
        if violation is not None:
            violations.append(
                {
                    "address": f"0x{address:016x}",
                    "kind": violation,
                    "mnemonic": mnemonic,
                }
            )
        expected_address += scan.lengths[count]
        count += 1
    if (
        count != len(scan.lengths)
        or expected_address != scan.section.address + scan.section.size
    ):
        fail(
            "objdump.coverage",
            "llvm-objdump did not cover every raw instruction boundary",
            {"expected": len(scan.lengths), "observed": count},
        )
    if violations:
        fail(
            "objdump.forbidden",
            "llvm-objdump found forbidden floating/vector/unknown instructions",
            {"count": len(violations), "examples": violations[:32]},
        )
    return count


def helper_base(symbol: str) -> str:
    base = symbol
    while True:
        stripped = CLONE_SUFFIX.sub("", base)
        if stripped == base:
            return base
        base = stripped


def forbidden_helper(symbol: str) -> bool:
    base = helper_base(symbol)
    if any(pattern.fullmatch(base) is not None for pattern in FP_HELPER_PATTERNS):
        return True
    libm = base[2:] if base.startswith("__") else base
    for suffix in ("", "f", "l"):
        if suffix and not libm.endswith(suffix):
            continue
        candidate = libm[: -len(suffix)] if suffix else libm
        if candidate in LIBM_BASES:
            return True
    return False


def parse_defined_symbols(
    raw: bytes,
) -> tuple[list[tuple[str, str, int, int]], list[str]]:
    text = strict_utf8(raw, "llvm-nm defined symbols")
    if text and not text.endswith("\n"):
        fail("nm.shape", "llvm-nm defined-symbol output lacks a final newline")
    symbols: list[tuple[str, str, int, int]] = []
    helpers: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        match = NM_DEFINED.fullmatch(line)
        if match is None:
            fail("nm.shape", f"llvm-nm defined-symbol line {number} is ambiguous")
        name, symbol_type, value, size = match.groups()
        if not name or any(character in name for character in "\r\n\t"):
            fail(
                "nm.shape", f"llvm-nm defined-symbol line {number} has an invalid name"
            )
        if symbol_type in "Uu?":
            fail("nm.shape", "llvm-nm --defined-only emitted an undefined symbol")
        symbols.append((name, symbol_type, int(value, 16), int(size, 16)))
        if forbidden_helper(name):
            helpers.add(name)
    if not symbols:
        fail("nm.empty", "llvm-nm emitted no defined symbols")
    return symbols, sorted(helpers)


def parse_undefined_symbols(raw: bytes) -> tuple[list[str], list[str]]:
    text = strict_utf8(raw, "llvm-nm undefined symbols")
    if text and not text.endswith("\n"):
        fail("nm.shape", "llvm-nm undefined-symbol output lacks a final newline")
    symbols: list[str] = []
    helpers: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        match = NM_UNDEFINED.fullmatch(line)
        if match is None:
            fail("nm.shape", f"llvm-nm undefined-symbol line {number} is ambiguous")
        name = match.group(1)
        if not name or any(character in name for character in "\r\n\t"):
            fail(
                "nm.shape",
                f"llvm-nm undefined-symbol line {number} has an invalid name",
            )
        symbols.append(name)
        if forbidden_helper(name):
            helpers.add(name)
    return symbols, sorted(helpers)


def audit_symbols(
    defined_raw: bytes,
    undefined_raw: bytes,
    entry: int,
    raw_symbol_count: int,
    canonical_boundaries: frozenset[int],
) -> dict[str, Any]:
    defined, defined_helpers = parse_defined_symbols(defined_raw)
    undefined, undefined_helpers = parse_undefined_symbols(undefined_raw)
    if undefined:
        fail(
            "nm.undefined",
            "final static ELF contains undefined symbols",
            {"count": len(undefined), "examples": sorted(set(undefined))[:32]},
        )
    helpers = sorted(set(defined_helpers + undefined_helpers))
    if helpers:
        fail(
            "nm.float-helpers",
            "final ELF contains forbidden floating-point helper symbols",
            {"count": len(helpers), "symbols": helpers},
        )
    starts = [symbol for symbol in defined if symbol[0] == "_start"]
    if len(starts) != 1 or starts[0][1] != "T" or starts[0][2] != entry:
        fail("nm.entry", "final ELF must define exactly one global _start at e_entry")
    code_symbols = [symbol for symbol in defined if symbol[1] in "TtWwIi"]
    bad_code_symbols = [
        symbol for symbol in code_symbols if symbol[2] not in canonical_boundaries
    ]
    if bad_code_symbols:
        fail(
            "control.code-symbol",
            "defined code symbol is not a canonical instruction boundary",
            {
                "count": len(bad_code_symbols),
                "examples": [
                    {
                        "address": f"0x{value:016x}",
                        "name": name,
                        "type": symbol_type,
                    }
                    for name, symbol_type, value, _size in bad_code_symbols[:32]
                ],
            },
        )
    if len(defined) + len(undefined) != raw_symbol_count - 1:
        fail(
            "nm.count",
            "llvm-nm did not account for every non-null .symtab entry",
            {
                "expected": raw_symbol_count - 1,
                "observed": len(defined) + len(undefined),
            },
        )
    return {
        "code_symbols": len(code_symbols),
        "defined": len(defined),
        "forbidden_helpers": [],
        "raw_symtab_entries": raw_symbol_count,
        "undefined": 0,
    }


def tool_report(toolchain: Toolchain) -> dict[str, Any]:
    return {
        "channel": TOOLCHAIN,
        "host": EXPECTED_HOST,
        "llvm_build": EXPECTED_LLVM_BUILD,
        "llvm_version": EXPECTED_LLVM_VERSION,
        "rustc_commit": EXPECTED_RUSTC_COMMIT,
        "rustc_release": EXPECTED_RUSTC_RELEASE,
        "tools": toolchain.identities,
    }


def audit_elf(path: Path) -> dict[str, Any]:
    elf = read_stable_file(path, "final kernel ELF", MAX_ELF_BYTES)
    image = parse_elf(elf.data)
    _attributes, executable, raw_symbol_count = validate_elf_policy(image)
    toolchain = locate_toolchain()

    readobj_json = run_command(
        [
            toolchain.readobj,
            "--elf-output-style=JSON",
            "--file-headers",
            "--sections",
            "--program-headers",
            "--relocations",
            "--dynamic-table",
            "--needed-libs",
            elf.path,
        ],
        maximum_output=4 * 1024 * 1024,
    )
    validate_readobj_json(readobj_json, elf, image)
    attributes = run_command(
        [toolchain.readobj, "--arch-specific", elf.path],
        maximum_output=64 * 1024,
    )
    validate_attributes(attributes, elf.path)

    scans = [scan_instruction_bytes(section, elf.data) for section in executable]
    raw_forbidden = [item for scan in scans for item in scan.forbidden]
    if raw_forbidden:
        fail(
            "opcode.forbidden",
            "raw executable bytes contain forbidden FP/vector encodings",
            {"count": len(raw_forbidden), "examples": raw_forbidden[:32]},
        )
    canonical_boundaries, direct_targets = validate_canonical_control_flow(
        scans, elf.data, image.header.entry
    )

    executable_report: list[dict[str, Any]] = []
    for scan in scans:
        objdump = run_command(
            [
                toolchain.objdump,
                "--disassemble-all",
                "--disassemble-zeroes",
                "--disassembler-color=off",
                "--no-show-raw-insn",
                f"--section={scan.section.name}",
                elf.path,
            ],
            maximum_output=min(
                MAX_TOOL_OUTPUT,
                max(4 * 1024 * 1024, scan.section.size * 40),
            ),
        )
        disassembled = validate_objdump(objdump, elf, scan)
        executable_report.append(
            {
                "address": f"0x{scan.section.address:016x}",
                "bytes": scan.section.size,
                "four_byte_instructions": scan.four_byte,
                "instructions": disassembled,
                "name": scan.section.name,
                "sha256": scan.sha256,
                "two_byte_instructions": scan.two_byte,
            }
        )

    nm_common = [
        toolchain.nm,
        "--no-demangle",
        "--format=posix",
        "--debug-syms",
        "--special-syms",
        "--print-size",
        "--radix=x",
    ]
    defined = run_command(
        [*nm_common, "--defined-only", elf.path], maximum_output=MAX_TOOL_OUTPUT
    )
    undefined = run_command(
        [*nm_common, "--undefined-only", elf.path], maximum_output=MAX_TOOL_OUTPUT
    )
    symbol_report = audit_symbols(
        defined,
        undefined,
        image.header.entry,
        raw_symbol_count,
        canonical_boundaries,
    )
    for name, path in {
        "rustc": toolchain.rustc,
        "llvm-readobj": toolchain.readobj,
        "llvm-objdump": toolchain.objdump,
        "llvm-nm": toolchain.nm,
    }.items():
        verify_identity(path, name)
    assert_file_unchanged(elf, "final kernel ELF")

    return {
        "checks": [
            "elf64-little-riscv-et_exec",
            "soft-abi-rvc-flags",
            "exact-rv64-imac-attributes",
            "static-no-relocations",
            "section-and-segment-wx",
            "section-load-congruent-mapping",
            "rx-exec-section-exact-coverage",
            "canonical-riscv-opcodes",
            "objdump-boundary-cross-check",
            "canonical-control-flow-targets",
            "nm-zero-float-helpers",
            "stable-input-identity",
        ],
        "elf": {
            "bytes": elf.size,
            "control_flow": {
                "canonical_boundaries": len(canonical_boundaries),
                "direct_targets": direct_targets,
            },
            "e_flags": f"0x{image.header.flags:08x}",
            "entry": f"0x{image.header.entry:016x}",
            "executable_sections": executable_report,
            "forbidden_opcodes": [],
            "program_headers": len(image.programs),
            "riscv_arch": EXPECTED_RISCV_ARCH,
            "sections": len(image.sections),
            "sha256": elf.sha256,
            "symbols": symbol_report,
        },
        "execution_scope": [
            "trusted-native-control-flow",
            "canonical-decoder-boundaries",
            "arbitrary-PC-redirection-not-claimed",
            "hardware-NX-not-claimed",
        ],
        "mode": "audit",
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "target": TARGET,
        "toolchain": tool_report(toolchain),
    }


def expect_failure(code_prefix: str, operation: Any) -> None:
    try:
        operation()
    except AuditFailure as error:
        if not error.code.startswith(code_prefix):
            fail(
                "selftest.wrong-failure",
                f"fixture expected {code_prefix!r}, got {error.code!r}",
            )
    else:
        fail("selftest.missed", f"fixture did not fail with {code_prefix!r}")


def self_test() -> dict[str, Any]:
    section = Section(
        1, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0x1000, 0, 0, 0, 0, 2, 0
    )
    allowed_words = (
        (0x0001).to_bytes(2, "little")
        + (0x00000013).to_bytes(4, "little")
        + (0x0000000F).to_bytes(4, "little")
        + (0x10002073).to_bytes(4, "little")
    )
    allowed_section = Section(**{**section.__dict__, "size": len(allowed_words)})
    allowed_scan = scan_instruction_bytes(allowed_section, allowed_words)
    if allowed_scan.forbidden or list(allowed_scan.lengths) != [2, 4, 4, 4]:
        fail("selftest.allowed", "integer/RVC scanner fixture was rejected")
    allowed_windows = scan_halfword_windows(allowed_words, section.address, ".text")
    if allowed_windows.forbidden_count:
        fail("selftest.allowed", "allowed halfword windows were rejected")

    overlapping = b"\x13\x00\x53\x00\x00\x00"
    overlapping_section = Section(**{**section.__dict__, "size": len(overlapping)})
    overlapping_scan = scan_instruction_bytes(overlapping_section, overlapping)
    if overlapping_scan.forbidden:
        fail("selftest.overlap", "canonical overlapping fixture was unexpectedly bad")
    overlapping_windows = scan_halfword_windows(overlapping, section.address, ".text")
    if (
        overlapping_windows.forbidden_count != 1
        or overlapping_windows.examples[0]["address"] != "0x0000000000001002"
        or overlapping_windows.examples[0]["encoding"] != "0x00000053"
        or overlapping_windows.examples[0]["kind"] != "OP-FP"
    ):
        fail("selftest.overlap", "mid-instruction OP-FP window was not rejected")
    expect_failure(
        "control.entry",
        lambda: validate_canonical_control_flow(
            (overlapping_scan,), overlapping, section.address + 2
        ),
    )

    bad_jal = (0x0020006F).to_bytes(4, "little") + b"\x01\x00"
    bad_jal_section = Section(**{**section.__dict__, "size": len(bad_jal)})
    bad_jal_scan = scan_instruction_bytes(bad_jal_section, bad_jal)
    expect_failure(
        "control.direct-target",
        lambda: validate_canonical_control_flow(
            (bad_jal_scan,), bad_jal, section.address
        ),
    )
    self_jal = (0x0000006F).to_bytes(4, "little")
    self_jal_section = Section(**{**section.__dict__, "size": len(self_jal)})
    self_jal_scan = scan_instruction_bytes(self_jal_section, self_jal)
    self_boundaries, self_targets = validate_canonical_control_flow(
        (self_jal_scan,), self_jal, section.address
    )
    if (
        self_boundaries != frozenset({section.address, section.address + len(self_jal)})
        or self_targets != 1
    ):
        fail("selftest.control", "valid direct control-flow fixture was rejected")
    direct_decoder_fixtures = (
        (word_direct_target(0x0040006F, section.address), ("JAL", section.address + 4)),
        (
            word_direct_target(0x00000263, section.address),
            ("BRANCH", section.address + 4),
        ),
        (
            compressed_direct_target(0xA009, section.address),
            ("C.J", section.address + 2),
        ),
        (
            compressed_direct_target(0xC009, section.address),
            ("C.BEQZ", section.address + 2),
        ),
    )
    if any(observed != expected for observed, expected in direct_decoder_fixtures):
        fail("selftest.control", "direct-target immediate decoder drifted")

    diagnostic_header = ElfHeaderRecord(
        ET_EXEC,
        EM_RISCV,
        EV_CURRENT,
        section.address,
        0,
        0,
        EXPECTED_E_FLAGS,
        ELF_HEADER.size,
        ELF_PROGRAM.size,
        1,
        ELF_SECTION.size,
        2,
        1,
    )
    diagnostic_load = ProgramHeader(
        0,
        PT_LOAD,
        PF_R,
        0,
        section.address,
        section.address,
        len(overlapping),
        len(overlapping),
        4096,
    )
    diagnostic_scan = scan_loaded_instruction_windows(
        ElfImage(diagnostic_header, (), (diagnostic_load,)), overlapping
    )
    if diagnostic_scan.forbidden_count != 1:
        fail("selftest.diagnostic", "all-LOAD diagnostic lost the overlap fixture")

    raw_forbidden = 0
    for opcode in sorted(FORBIDDEN_MAJOR_OPCODES):
        fixture = opcode.to_bytes(4, "little")
        candidate = Section(**{**section.__dict__, "size": 4})
        scan = scan_instruction_bytes(candidate, fixture)
        if len(scan.forbidden) != 1:
            fail("selftest.opcode", f"major opcode 0x{opcode:02x} was not rejected")
        raw_forbidden += 1
    for csr in sorted(FP_CSRS):
        fixture = ((csr << 20) | (2 << 12) | 0x73).to_bytes(4, "little")
        candidate = Section(**{**section.__dict__, "size": 4})
        if len(scan_instruction_bytes(candidate, fixture).forbidden) != 1:
            fail("selftest.csr", f"FP CSR 0x{csr:03x} was not rejected")
        raw_forbidden += 1
    for quadrant, funct3 in ((0, 1), (0, 5), (2, 1), (2, 5)):
        halfword = (funct3 << 13) | quadrant
        fixture = halfword.to_bytes(2, "little")
        candidate = Section(**{**section.__dict__, "size": 2})
        if len(scan_instruction_bytes(candidate, fixture).forbidden) != 1:
            fail("selftest.compressed", "compressed FP fixture was not rejected")
        raw_forbidden += 1
    candidate = Section(**{**section.__dict__, "size": 2})
    expect_failure(
        "opcode.length", lambda: scan_instruction_bytes(candidate, b"\x1f\x00")
    )
    expect_failure(
        "opcode.truncated", lambda: scan_instruction_bytes(candidate, b"\x03\x00")
    )

    mapped_text = Section(
        1,
        ".text",
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        0x1000,
        0x200,
        6,
        0,
        0,
        2,
        0,
    )
    mapped_load = ProgramHeader(
        0,
        PT_LOAD,
        PF_R | PF_X,
        0x200,
        0x1000,
        0x1000,
        6,
        6,
        4096,
    )
    owners = validate_allocated_mappings((mapped_text,), (mapped_load,))
    if owners != {mapped_text.index: mapped_load}:
        fail("selftest.mapping", "valid executable LOAD mapping was rejected")
    mapping_mismatch = Section(
        **{**mapped_text.__dict__, "offset": mapped_text.offset + 2, "size": 4}
    )
    expect_failure(
        "elf.mapping",
        lambda: validate_allocated_mappings(
            (mapping_mismatch,),
            (ProgramHeader(**{**mapped_load.__dict__, "file_size": 6}),),
        ),
    )
    executable_gap = Section(**{**mapped_text.__dict__, "size": 4})
    expect_failure(
        "elf.exec-coverage",
        lambda: validate_allocated_mappings((executable_gap,), (mapped_load,)),
    )
    executable_head_gap = Section(
        **{
            **mapped_text.__dict__,
            "address": mapped_text.address + 2,
            "offset": mapped_text.offset + 2,
            "size": 4,
        }
    )
    expect_failure(
        "elf.exec-coverage",
        lambda: validate_allocated_mappings((executable_head_gap,), (mapped_load,)),
    )
    executable_overlap = Section(
        **{
            **mapped_text.__dict__,
            "index": 2,
            "name": ".text.extra",
            "address": mapped_text.address + 2,
            "offset": mapped_text.offset + 2,
            "size": 4,
        }
    )
    expect_failure(
        "elf.sections",
        lambda: validate_allocated_mappings(
            (Section(**{**mapped_text.__dict__, "size": 4}), executable_overlap),
            (mapped_load,),
        ),
    )
    zero_fill = Section(
        2,
        ".bss",
        SHT_NOBITS,
        SHF_ALLOC | SHF_WRITE,
        0x2004,
        0x404,
        4,
        0,
        0,
        4,
        0,
    )
    data_load = ProgramHeader(
        1, PT_LOAD, PF_R | PF_W, 0x400, 0x2000, 0x2000, 4, 8, 4096
    )
    if validate_allocated_mappings((zero_fill,), (data_load,)) != {
        zero_fill.index: data_load
    }:
        fail("selftest.mapping", "valid NOBITS zero-fill mapping was rejected")
    expect_failure(
        "elf.mapping",
        lambda: validate_allocated_mappings(
            (Section(**{**zero_fill.__dict__, "address": 0x2002, "size": 2}),),
            (data_load,),
        ),
    )

    allowed_mnemonics = ("addi", "fence", "fence.i", "fence.tso", "sfence.vma", "unimp")
    for mnemonic in allowed_mnemonics:
        if mnemonic_violation(mnemonic) is not None:
            fail("selftest.mnemonic", f"allowed mnemonic {mnemonic!r} was rejected")
    forbidden_mnemonics = (
        "fadd.s",
        "fneg.d",
        "fabs.s",
        "fli.s",
        "fround.d",
        "fminm.s",
        "fcvtmod.w.d",
        "fsrmi",
        "fsflagsi",
        "c.fldsp",
        "vsetvli",
        "<unknown>",
        ".word",
        ".2byte",
        ".insn",
    )
    for mnemonic in forbidden_mnemonics:
        if mnemonic_violation(mnemonic) is None:
            fail("selftest.mnemonic", f"forbidden mnemonic {mnemonic!r} was accepted")

    helper_fixtures = (
        "__addsf3",
        "__moddf3",
        "__fmasf4",
        "__unorddf2",
        "__extendsfdf2",
        "__truncdfsf2",
        "__fixunssfdi",
        "__floatundidf",
        "__powisf2",
        "__mulsc3",
        "__gnu_f2h_ieee",
        "sqrt",
        "sqrtf",
        "llround",
        "scalblnf",
        "nanf",
        "__adddf3.llvm.0123abcd",
    )
    for symbol in helper_fixtures:
        if not forbidden_helper(symbol):
            fail("selftest.helper", f"forbidden helper {symbol!r} was accepted")
    symbol_negatives = (
        "_RNvCs123_5floor7wrapper",
        "sqrt_wrapper",
        "__rust_alloc",
        "__bswapsi2",
        "canonical_f32_bits",
        "$d",
        "asdf",
    )
    for symbol in symbol_negatives:
        if forbidden_helper(symbol):
            fail("selftest.helper", f"non-helper symbol {symbol!r} was rejected")

    defined, helpers = parse_defined_symbols(
        b"_start T 1000 4\ninteger_bits t 1004 8\n"
    )
    if len(defined) != 2 or helpers:
        fail("selftest.nm", "valid llvm-nm fixture was rejected")
    undefined, undefined_helpers = parse_undefined_symbols(b"")
    if undefined or undefined_helpers:
        fail("selftest.nm", "empty undefined-symbol fixture was rejected")
    expect_failure("nm.shape", lambda: parse_defined_symbols(b"missing-size T 1000\n"))
    symbol_report = audit_symbols(
        b"_start T 1000 2\nfunction t 1002 4\n",
        b"",
        section.address,
        3,
        frozenset({section.address, section.address + 2}),
    )
    if symbol_report["code_symbols"] != 2:
        fail("selftest.control", "valid code symbols were rejected")
    expect_failure(
        "control.code-symbol",
        lambda: audit_symbols(
            b"_start T 1000 2\nfunction t 1004 2\n",
            b"",
            section.address,
            3,
            frozenset({section.address, section.address + 2}),
        ),
    )

    fake_path = Path("/tmp/c88-f5-selftest.elf")
    validate_attributes(expected_attribute_output(fake_path).encode("utf-8"), fake_path)
    expect_failure(
        "elf.attributes",
        lambda: validate_attributes(
            expected_attribute_output(fake_path)
            .replace(EXPECTED_RISCV_ARCH, EXPECTED_RISCV_ARCH + "_f2p2")
            .encode("utf-8"),
            fake_path,
        ),
    )

    objdump_text = (
        f"\n{fake_path}:\tfile format elf64-littleriscv\n\n"
        "Disassembly of section .text:\n\n"
        "0000000000001000 <_start>:\n"
        "1000:      \tnop\n"
        "1002:      \taddi\tzero, zero, 0x0\n"
    ).encode("utf-8")
    objdump_scan = RawScan(
        Section(**{**section.__dict__, "size": 6}),
        array("B", [2, 4]),
        1,
        1,
        hashlib.sha256(b"\x01\x00\x13\x00\x00\x00").hexdigest(),
        (),
    )
    fake_blob = FileBlob(fake_path, b"", 0, hashlib.sha256(b"").hexdigest(), 0, 0, 0)
    if validate_objdump(objdump_text, fake_blob, objdump_scan) != 2:
        fail("selftest.objdump", "valid objdump fixture was rejected")
    expect_failure(
        "objdump.coverage",
        lambda: validate_objdump(
            objdump_text.replace(b"1002:", b"1004:"), fake_blob, objdump_scan
        ),
    )

    if (
        run_command(
            [sys.executable, "-c", "import os; os.write(1, b'ok')"],
            maximum_output=2,
            timeout_seconds=2,
        )
        != b"ok"
    ):
        fail("selftest.subprocess", "bounded subprocess output was corrupted")
    expect_failure(
        "tool.output-limit",
        lambda: run_command(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"],
            maximum_output=32,
            timeout_seconds=2,
        ),
    )
    expect_failure(
        "tool.timeout",
        lambda: run_command(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            maximum_output=32,
            timeout_seconds=0.05,
        ),
    )

    return {
        "fixtures": {
            "allowed_mnemonics": len(allowed_mnemonics),
            "allowed_raw_instructions": len(allowed_scan.lengths),
            "attribute_mutations": 1,
            "forbidden_helpers": len(helper_fixtures),
            "forbidden_mnemonics": len(forbidden_mnemonics),
            "forbidden_raw_encodings": raw_forbidden,
            "halfword_overlap_mutations": 1,
            "load_window_diagnostics": 1,
            "load_mapping_mutations": 5,
            "nm_mutations": 1,
            "objdump_mutations": 1,
            "subprocess_mutations": 2,
            "trusted_control_flow_mutations": 3,
            "trusted_direct_decoders": len(direct_decoder_fixtures),
            "truncated_or_extended_encodings": 2,
        },
        "mode": "self-test",
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "target": TARGET,
    }


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--elf", type=Path, help="final linked kernel ELF to audit")
    selection.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic detector fixtures without invoking LLVM tools",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="exclusively create this canonical JSON report (stdout when omitted)",
    )
    return parser


def failure_report(error: AuditFailure) -> dict[str, Any]:
    failure: dict[str, Any] = {"code": error.code, "message": error.message}
    if error.details:
        failure["details"] = error.details
    return {
        "error": failure,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": "fail",
        "target": TARGET,
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = argument_parser().parse_args(argv)
    try:
        report = self_test() if arguments.self_test else audit_elf(arguments.elf)
        write_report(report, arguments.output)
        return 0
    except (AuditFailure, OSError, UnicodeError, ValueError, struct.error) as error:
        failure = (
            error
            if isinstance(error, AuditFailure)
            else AuditFailure(
                "internal.fail-closed",
                f"unhandled verifier error: {type(error).__name__}: {error}",
            )
        )
        report = failure_report(failure)
        try:
            write_report(report, arguments.output)
        except AuditFailure as output_error:
            sys.stderr.buffer.write(canonical_json(failure_report(output_error)))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
