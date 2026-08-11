#!/usr/bin/env python3
"""Convert one OpenSSH ssh-ed25519 public key to VibeOS provisioning hex."""

import argparse
import base64
import struct
import sys


def ssh_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise ValueError("truncated SSH string")
    length = struct.unpack(">I", blob[offset : offset + 4])[0]
    start = offset + 4
    end = start + length
    if end > len(blob):
        raise ValueError("truncated SSH string payload")
    return blob[start:end], end


def convert(line: str) -> str:
    fields = line.strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise ValueError("expected an ssh-ed25519 OpenSSH public key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError as exc:
        raise ValueError("invalid base64 key blob") from exc
    algorithm, offset = ssh_string(blob, 0)
    key, offset = ssh_string(blob, offset)
    if algorithm != b"ssh-ed25519" or len(key) != 32 or offset != len(blob):
        raise ValueError("malformed ssh-ed25519 key blob")
    return key.hex()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("public_key", nargs="?", help=".pub file; stdin when omitted")
    args = parser.parse_args()
    try:
        line = open(args.public_key, encoding="utf-8").read() if args.public_key else sys.stdin.read()
        print(convert(line))
    except (OSError, ValueError) as exc:
        print(f"ssh-ed25519-key-hex: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
