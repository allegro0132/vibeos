#!/usr/bin/env python3
"""Exercise the bounded TCP listener on a physical Milk-V Duo."""

from __future__ import annotations

import argparse
import math
import socket
import sys
import time


DEFAULT_PORT = 2222
DEFAULT_ROUNDS = 8
MAX_ROUNDS = 64
MAX_TIMEOUT_SECONDS = 60.0
PAYLOAD_PREFIX = b"vibeos-milkv-tcp-acceptance:"


def exchange(host: str, port: int, timeout: float, round_number: int) -> None:
    payload = PAYLOAD_PREFIX + str(round_number).encode("ascii")
    with socket.create_connection((host, port), timeout=timeout) as peer:
        peer.settimeout(timeout)
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)

        received = bytearray()
        while True:
            chunk = peer.recv(len(payload) + 1 - len(received))
            if not chunk:
                break
            received.extend(chunk)
            if len(received) > len(payload):
                raise RuntimeError(
                    f"round {round_number}: listener returned bytes beyond the sent payload"
                )

    if bytes(received) != payload:
        raise RuntimeError(
            f"round {round_number}: exact echo mismatch: "
            f"expected {payload!r}, received {bytes(received)!r}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Connect repeatedly to a physical Milk-V Duo and require an exact "
            "binary echo on every fresh TCP stream."
        )
    )
    parser.add_argument("host", help="IPv4 address reported by `ip -4 addr show dev net0`")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--timeout", type=float, default=3.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    if not 1 <= args.rounds <= MAX_ROUNDS:
        raise SystemExit(f"--rounds must be between 1 and {MAX_ROUNDS}")
    if (
        not math.isfinite(args.timeout)
        or args.timeout <= 0
        or args.timeout > MAX_TIMEOUT_SECONDS
    ):
        raise SystemExit(
            f"--timeout must be finite and between 0 and {MAX_TIMEOUT_SECONDS:g} seconds"
        )

    try:
        for round_number in range(1, args.rounds + 1):
            exchange(args.host, args.port, args.timeout, round_number)
            if round_number != args.rounds:
                time.sleep(0.05)
    except (OSError, RuntimeError, ValueError, OverflowError) as error:
        print(f"FAIL milkv-tcp-test: {error}", file=sys.stderr)
        return 1

    print(
        f"PASS milkv-tcp-test: {args.rounds} exact echoes over fresh streams "
        f"to {args.host}:{args.port}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
