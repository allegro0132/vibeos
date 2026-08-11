#!/usr/bin/env python3
"""Send one VibeOS Jitterentropy command and capture its UART transcript."""

from __future__ import annotations

import argparse
import os
import re
import select
import sys
import termios
import time
from pathlib import Path

RAW = re.compile(rb"VIBE_JENT_RAW (\d+) ")


def configure(fd: int) -> None:
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=Path, required=True)
    parser.add_argument("--command")
    parser.add_argument("--wait-for", default="vibe>")
    parser.add_argument("--until")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--quiet", action="store_true", help="write only progress to the terminal")
    args = parser.parse_args()

    args.log.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        configure(fd)
        started = time.monotonic()
        deadline = started + args.timeout
        waiting = args.wait_for.encode("ascii") if args.wait_for else None
        until = args.until.encode("ascii") if args.until else None
        command_sent = args.command is None
        recent = bytearray()
        last_progress = -1
        with args.log.open("wb") as log:
            os.write(fd, b"\r\n")
            while time.monotonic() < deadline:
                readable, _, _ = select.select([fd], [], [], 1.0)
                if not readable:
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    continue
                log.write(chunk)
                log.flush()
                if not args.quiet:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                recent.extend(chunk)
                if len(recent) > 131072:
                    del recent[:-65536]

                if not command_sent and (waiting is None or waiting in recent):
                    os.write(fd, args.command.encode("ascii") + b"\r\n")
                    command_sent = True
                    recent.clear()
                    continue

                matches = list(RAW.finditer(recent))
                if matches:
                    progress = int(matches[-1].group(1)) + 1
                    bucket = progress // 100_000
                    if bucket > last_progress:
                        print(f"\n[capture] samples observed: {progress}", file=sys.stderr)
                        last_progress = bucket
                marker = recent.find(until) if until is not None else -1
                marker_line_complete = marker >= 0 and b"\n" in recent[marker:]
                if command_sent and marker_line_complete:
                    print(
                        f"\n[capture] completion marker observed after "
                        f"{time.monotonic() - started:.1f}s",
                        file=sys.stderr,
                    )
                    return 0
        if not command_sent:
            print(f"timeout waiting for prompt {args.wait_for!r}", file=sys.stderr)
        else:
            print(f"timeout waiting for completion marker {args.until!r}", file=sys.stderr)
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
