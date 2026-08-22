#!/usr/bin/env python3
"""Drive one VSH/QEMU boot, waiting for a fresh prompt after every command."""

from __future__ import annotations

import argparse
import os
import select
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--boot-timeout", type=float, default=30.0)
    parser.add_argument("--command-timeout", type=float, default=45.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a QEMU command is required after --")

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    assert process.stdin is not None and process.stdout is not None
    pending = bytearray()

    with args.log.open("wb") as log:
        def wait_for_prompt(timeout: float, label: str) -> None:
            deadline = time.monotonic() + timeout
            while b"vsh> " not in pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out waiting for VSH prompt after {label}")
                readable, _, _ = select.select([process.stdout], [], [], remaining)
                if not readable:
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError(f"QEMU exited before VSH prompt after {label}")
                log.write(chunk)
                log.flush()
                pending.extend(chunk)
                if len(pending) > 1 << 20:
                    del pending[: len(pending) - (1 << 20)]
            del pending[: pending.index(b"vsh> ") + len(b"vsh> ")]

        try:
            wait_for_prompt(args.boot_timeout, "boot")
            for raw in args.case.read_text(encoding="utf-8").splitlines():
                if not raw:
                    continue
                if raw.startswith("@sleep "):
                    time.sleep(float(raw.removeprefix("@sleep ")))
                    continue
                if raw == "@quit":
                    break
                process.stdin.write(raw.encode("utf-8") + b"\n")
                process.stdin.flush()
                wait_for_prompt(args.command_timeout, repr(raw))
            process.stdin.write(b"\x01x")
            process.stdin.flush()
            try:
                return process.wait(timeout=10.0)
            except subprocess.TimeoutExpired as error:
                raise TimeoutError("QEMU did not exit after the monitor quit sequence") from error
        except Exception as error:
            print(f"qemu-vsh-driver.py: {error}", file=sys.stderr)
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            return 1


if __name__ == "__main__":
    sys.exit(main())
