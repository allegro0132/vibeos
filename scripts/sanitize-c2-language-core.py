#!/usr/bin/env python3
"""Remove the exact unreferenced linker stack global from pinned C2.3 guests."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path


MAGIC = b"\x00asm\x01\x00\x00\x00"
GLOBAL_SECTION_ID = 6
STACK_GLOBAL_PAYLOAD = bytes.fromhex("01 7f 01 41 80 80 04 0b")

# The compiler outputs are already fixed by source/toolchain pins. Keeping the
# allowlist here makes this transform intentionally unusable as a general Wasm
# rewriter: widening it requires reviewing a new exact input and output pair.
FIXTURES = {
    "149ff653148bf98c6929c9392e5239d1cf3516f3902329a05d0bec3762a0fa11": {
        "name": "Rust compiler Core",
        "input_bytes": 567,
        "output_bytes": 557,
        "output_sha256": "79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52",
    },
    "e3d7284a26c34448465ebc12f5024e41e4cc9cae9943f251523a85863ae2aa91": {
        "name": "C compiler Core",
        "input_bytes": 1040,
        "output_bytes": 1030,
        "output_sha256": "20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e",
    },
}


class SanitizationError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_u32_leb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def read_u32_leb(data: bytes, cursor: int) -> tuple[int, int]:
    start = cursor
    value = 0
    for shift in range(0, 35, 7):
        if cursor >= len(data):
            raise SanitizationError("truncated section length")
        byte = data[cursor]
        cursor += 1
        if shift == 28 and byte & 0xF0:
            raise SanitizationError("section length exceeds u32")
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            if data[start:cursor] != encode_u32_leb(value):
                raise SanitizationError("section length is not canonical ULEB128")
            return value, cursor
    raise SanitizationError("unterminated section length")


def strip_exact_stack_global(data: bytes) -> bytes:
    if not data.startswith(MAGIC):
        raise SanitizationError("input is not a WebAssembly 1.0 module")
    cursor = len(MAGIC)
    global_range: tuple[int, int] | None = None
    while cursor < len(data):
        start = cursor
        section_id = data[cursor]
        cursor += 1
        payload_len, cursor = read_u32_leb(data, cursor)
        end = cursor + payload_len
        if end > len(data):
            raise SanitizationError("section payload exceeds the input")
        if section_id == GLOBAL_SECTION_ID:
            if global_range is not None:
                raise SanitizationError("more than one global section")
            if data[cursor:end] != STACK_GLOBAL_PAYLOAD:
                raise SanitizationError("global section is not the exact private stack pointer")
            global_range = (start, end)
        cursor = end
    if cursor != len(data):
        raise SanitizationError("section framing did not consume the input")
    if global_range is None:
        raise SanitizationError("exact private stack-pointer section is missing")
    start, end = global_range
    return data[:start] + data[end:]


def sanitize_pinned(data: bytes) -> tuple[bytes, str]:
    digest = sha256(data)
    fixture = FIXTURES.get(digest)
    if fixture is None:
        raise SanitizationError(f"compiler Core SHA-256 is not pinned: {digest}")
    if len(data) != fixture["input_bytes"]:
        raise SanitizationError(f"{fixture['name']} length differs")
    sanitized = strip_exact_stack_global(data)
    if len(sanitized) != fixture["output_bytes"]:
        raise SanitizationError(f"{fixture['name']} sanitized length differs")
    expected_output = fixture["output_sha256"]
    observed_output = sha256(sanitized)
    if not expected_output:
        raise SanitizationError(f"{fixture['name']} sanitized SHA-256 is not pinned")
    if observed_output != expected_output:
        raise SanitizationError(
            f"{fixture['name']} sanitized SHA-256 differs: {observed_output}"
        )
    return sanitized, observed_output


def selftest() -> None:
    global_section = bytes([GLOBAL_SECTION_ID, len(STACK_GLOBAL_PAYLOAD)]) + STACK_GLOBAL_PAYLOAD
    assert strip_exact_stack_global(MAGIC + global_section) == MAGIC
    malformed = [
        b"",
        MAGIC,
        MAGIC + global_section + global_section,
        MAGIC + bytes([GLOBAL_SECTION_ID, 1, 0]),
        MAGIC + bytes([GLOBAL_SECTION_ID, 0x80]),
        MAGIC + bytes([GLOBAL_SECTION_ID, 9]) + STACK_GLOBAL_PAYLOAD,
    ]
    for candidate in malformed:
        try:
            strip_exact_stack_global(candidate)
        except SanitizationError:
            pass
        else:
            raise AssertionError(f"malformed self-test input accepted: {candidate.hex()}")


def regular_file(path: Path, label: str) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise SanitizationError(f"{label} must be a regular non-symlink file")
    data = path.read_bytes()
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SanitizationError(f"{label} changed while it was read")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        if args.input is not None or args.output is not None:
            parser.error("--selftest does not accept paths")
        selftest()
        return 0
    if args.input is None or args.output is None:
        parser.error("input and output are required")

    # Keep the final path component unresolved so `regular_file` can actually
    # reject an input symlink instead of inspecting its target.
    input_path = args.input.absolute()
    output_path = args.output.absolute()
    if input_path == output_path:
        raise SanitizationError("input and output must differ")
    data = regular_file(input_path, "compiler Core")
    sanitized, digest = sanitize_pinned(data)
    with output_path.open("xb") as output:
        written = output.write(sanitized)
    if written != len(sanitized):
        raise SanitizationError("sanitized output was only partially written")
    print(f"sanitized_bytes={len(sanitized)} sanitized_sha256={digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SanitizationError) as error:
        print(f"FAIL sanitize-c2-language-core: {error}", file=sys.stderr)
        raise SystemExit(1)
