#!/usr/bin/env python3
"""Create a deterministic, unencrypted OpenSSH Ed25519 test key.

The named accepted/rejected fixtures match the QEMU-only VibeOS SSH policy.
Callers may instead supply both a 32-byte seed and its trusted 32-byte public
key. This utility intentionally does not implement Ed25519 arithmetic and never
prints either private value. Every generated identity is test-only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile


AUTH_MAGIC = b"openssh-key-v1\x00"
KEY_TYPE = b"ssh-ed25519"
NONE_BLOCK_BYTES = 8
MAX_COMMENT_BYTES = 1_024
HEX_32_BYTES = re.compile(r"[0-9a-fA-F]{64}\Z")

# These identities match the QEMU-only SSH fixture policy. They are public test
# vectors, not device provisioning material, and must never be used outside an
# acceptance image.
FIXTURES = {
    "accepted": (
        "b6" * 32,
        "805440ee48051fc82ea64d905acabff0d21780f7fcaba6900e0e41387b1d4a57",
    ),
    "rejected": (
        "c7" * 32,
        "d5af25e204ad03d0a26e236996404f1be51a60948bcc026cd084a83690b756d3",
    ),
}


def _u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF_FFFF:
        raise ValueError("OpenSSH field exceeds uint32")
    return struct.pack(">I", value)


def _ssh_string(value: bytes) -> bytes:
    return _u32(len(value)) + value


def _parse_hex_32(value: str | None, label: str) -> bytes:
    if value is None or HEX_32_BYTES.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 64 hexadecimal characters")
    return bytes.fromhex(value)


def _public_blob(public_key: bytes) -> bytes:
    if len(public_key) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    return _ssh_string(KEY_TYPE) + _ssh_string(public_key)


def _private_block(seed: bytes, public_key: bytes, comment: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must contain exactly 32 bytes")
    if len(public_key) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    if len(comment) > MAX_COMMENT_BYTES:
        raise ValueError(f"comment exceeds {MAX_COMMENT_BYTES} UTF-8 bytes")

    checkint = struct.unpack(
        ">I",
        hashlib.sha256(
            b"vibeos-openssh-test-key-checkint\x00" + seed + public_key + comment
        ).digest()[:4],
    )[0]
    block = b"".join(
        (
            _u32(checkint),
            _u32(checkint),
            _ssh_string(KEY_TYPE),
            _ssh_string(public_key),
            _ssh_string(seed + public_key),
            _ssh_string(comment),
        )
    )
    padding_bytes = NONE_BLOCK_BYTES - len(block) % NONE_BLOCK_BYTES
    return block + bytes(range(1, padding_bytes + 1))


def build_private_key(seed: bytes, public_key: bytes, comment: str) -> bytes:
    try:
        comment_bytes = comment.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError("comment is not valid UTF-8") from error

    public_blob = _public_blob(public_key)
    raw = b"".join(
        (
            AUTH_MAGIC,
            _ssh_string(b"none"),
            _ssh_string(b"none"),
            _ssh_string(b""),
            _u32(1),
            _ssh_string(public_blob),
            _ssh_string(_private_block(seed, public_key, comment_bytes)),
        )
    )
    encoded = base64.b64encode(raw).decode("ascii")
    lines = [encoded[offset : offset + 70] for offset in range(0, len(encoded), 70)]
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    ).encode("ascii")


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_fd = os.open(directory, flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def write_atomic(output: Path, contents: bytes, force: bool) -> None:
    output = output.absolute()
    directory = output.parent
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=directory
    )
    temporary = Path(temporary_name)
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())

        if force:
            os.replace(temporary, output)
            published = True
        else:
            try:
                # A same-directory hard link publishes without the overwrite
                # race inherent in an existence check followed by rename.
                os.link(temporary, output)
            except FileExistsError as error:
                raise FileExistsError(
                    "output exists; pass --force to replace it"
                ) from error
            published = True
            temporary.unlink()

        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
        if published and stat.S_IMODE(output.stat().st_mode) != 0o600:
            raise OSError("published key does not have mode 0600")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self.data):
            raise ValueError("truncated OpenSSH key framing")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def remaining(self) -> bytes:
        return self.take(len(self.data) - self.offset)


def _decode_pem(contents: bytes) -> bytes:
    try:
        text = contents.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("private key PEM is not ASCII") from error
    lines = text.splitlines()
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----"
        or lines[-1] != "-----END OPENSSH PRIVATE KEY-----"
    ):
        raise ValueError("invalid OpenSSH private key PEM envelope")
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except binascii.Error as error:
        raise ValueError("invalid OpenSSH private key base64") from error


def _validate_framing(
    contents: bytes, seed: bytes, public_key: bytes, comment: bytes
) -> None:
    raw = _decode_pem(contents)
    if not raw.startswith(AUTH_MAGIC):
        raise ValueError("invalid openssh-key-v1 magic")
    outer = _Reader(raw[len(AUTH_MAGIC) :])
    if outer.string() != b"none" or outer.string() != b"none" or outer.string() != b"":
        raise ValueError("self-test key is not unencrypted")
    if outer.u32() != 1:
        raise ValueError("self-test key does not contain exactly one identity")
    expected_public_blob = _public_blob(public_key)
    if outer.string() != expected_public_blob:
        raise ValueError("outer public key blob mismatch")
    private = _Reader(outer.string())
    if outer.remaining():
        raise ValueError("trailing outer OpenSSH key data")

    first_check = private.u32()
    if private.u32() != first_check:
        raise ValueError("OpenSSH private checkints differ")
    if private.string() != KEY_TYPE:
        raise ValueError("private key type mismatch")
    if private.string() != public_key:
        raise ValueError("private public key mismatch")
    if private.string() != seed + public_key:
        raise ValueError("Ed25519 seed/public private field mismatch")
    if private.string() != comment:
        raise ValueError("private key comment mismatch")
    padding = private.remaining()
    if not 1 <= len(padding) <= NONE_BLOCK_BYTES:
        raise ValueError("invalid OpenSSH private block padding length")
    if padding != bytes(range(1, len(padding) + 1)):
        raise ValueError("invalid OpenSSH private block padding")


def selftest() -> None:
    with tempfile.TemporaryDirectory(
        prefix="vibeos-openssh-key-selftest-"
    ) as directory_name:
        ssh_keygen = shutil.which("ssh-keygen")
        for fixture, (seed_hex, public_hex) in FIXTURES.items():
            seed = bytes.fromhex(seed_hex)
            public_key = bytes.fromhex(public_hex)
            comment = f"vibeos-{fixture}-selftest".encode("ascii")
            contents = build_private_key(seed, public_key, comment.decode("ascii"))
            if contents != build_private_key(seed, public_key, comment.decode("ascii")):
                raise ValueError(
                    f"{fixture} OpenSSH key generation is not deterministic"
                )
            _validate_framing(contents, seed, public_key, comment)

            output = Path(directory_name) / f"id_ed25519_{fixture}"
            write_atomic(output, contents, force=False)
            if stat.S_IMODE(output.stat().st_mode) != 0o600:
                raise ValueError("atomic writer did not publish mode 0600")
            try:
                write_atomic(output, contents, force=False)
            except FileExistsError:
                pass
            else:
                raise ValueError("atomic writer overwrote a key without --force")
            write_atomic(output, contents, force=True)

            if ssh_keygen is not None:
                result = subprocess.run(
                    [ssh_keygen, "-y", "-f", os.fspath(output)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=10,
                )
                if result.returncode != 0:
                    raise ValueError(
                        f"ssh-keygen rejected the generated {fixture} self-test key"
                    )
                fields = result.stdout.split()
                # OpenSSH may append the private-key comment after the public blob.
                if len(fields) < 2 or fields[0] != KEY_TYPE:
                    raise ValueError(
                        "ssh-keygen returned an unexpected public key format"
                    )
                try:
                    derived_blob = base64.b64decode(fields[1], validate=True)
                except binascii.Error as error:
                    raise ValueError("ssh-keygen returned invalid base64") from error
                if derived_blob != _public_blob(public_key):
                    raise ValueError("ssh-keygen derived a different public key blob")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        choices=sorted(FIXTURES),
        help="generate the named QEMU-only accepted or rejected test identity",
    )
    parser.add_argument("--seed", help="exactly 64 hex characters (never printed)")
    parser.add_argument(
        "--public-key", help="required matching 64-hex Ed25519 public key"
    )
    parser.add_argument("--comment", default="", help="optional OpenSSH key comment")
    parser.add_argument("--output", type=Path, help="destination private-key path")
    parser.add_argument(
        "--force", action="store_true", help="atomically replace an existing path"
    )
    parser.add_argument(
        "--selftest", action="store_true", help="run deterministic framing checks"
    )
    return parser


def main() -> int:
    parser = _parser()
    arguments = parser.parse_args()
    try:
        if arguments.selftest:
            if (
                arguments.seed is not None
                or arguments.public_key is not None
                or arguments.fixture is not None
                or arguments.output is not None
                or arguments.comment
                or arguments.force
            ):
                raise ValueError(
                    "--selftest cannot be combined with key-generation options"
                )
            selftest()
            print("openssh-test-key selftest: ok")
            return 0

        if arguments.output is None:
            raise ValueError("--output is required")
        if arguments.fixture is not None:
            if arguments.seed is not None or arguments.public_key is not None:
                raise ValueError(
                    "--fixture cannot be combined with --seed or --public-key"
                )
            seed_hex, public_hex = FIXTURES[arguments.fixture]
            seed = bytes.fromhex(seed_hex)
            public_key = bytes.fromhex(public_hex)
        else:
            seed = _parse_hex_32(arguments.seed, "seed")
            public_key = _parse_hex_32(arguments.public_key, "public key")
        contents = build_private_key(seed, public_key, arguments.comment)
        write_atomic(arguments.output, contents, arguments.force)
        print(f"wrote OpenSSH private key to {arguments.output}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
