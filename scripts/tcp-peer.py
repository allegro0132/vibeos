#!/usr/bin/env python3
"""Loopback-only client for the QEMU TCP echo acceptance test.

The payload deliberately contains text, NUL, control, and high-bit bytes so the
test proves that the guest exposes a byte stream rather than a line protocol.
"""

from __future__ import annotations

import argparse
import math
import socket
import sys
import threading
import time


LOOPBACK = "127.0.0.1"
PAYLOAD = b"VIBEOS-TCP-ECHO-v1\x00\x01\x7f\x80\xff\r\n"
CONNECT_ATTEMPT_TIMEOUT = 1.0
RETRY_INTERVAL = 0.05
EXTRA_BYTE_SETTLE = 0.1


class PeerError(RuntimeError):
    pass


class TransientExchangeError(RuntimeError):
    pass


def pick_loopback_port() -> int:
    """Return a currently unused loopback TCP port.

    The socket must be released before QEMU can bind it, so the caller still
    has to handle the small selection-to-bind race.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((LOOPBACK, 0))
        return int(listener.getsockname()[1])


def receive_exact(
    stream: socket.socket, length: int, deadline: float | None = None
) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        if deadline is not None:
            time_left = deadline - time.monotonic()
            if time_left <= 0:
                raise TransientExchangeError(
                    f"deadline expired with {remaining} of {length} byte(s) missing"
                )
            stream.settimeout(min(CONNECT_ATTEMPT_TIMEOUT, time_left))
        chunk = stream.recv(remaining)
        if not chunk:
            raise TransientExchangeError(
                f"connection closed with {remaining} of {length} byte(s) missing"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def exchange(port: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    attempts = 0
    last_error = "guest listener did not accept a connection"

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PeerError(
                f"timed out after {timeout:.1f}s waiting for exact echo; "
                f"last error: {last_error}"
            )

        attempts += 1
        attempt_timeout = min(CONNECT_ATTEMPT_TIMEOUT, remaining)
        try:
            with socket.create_connection(
                (LOOPBACK, port), timeout=attempt_timeout
            ) as stream:
                stream.settimeout(attempt_timeout)
                stream.sendall(PAYLOAD)
                observed = receive_exact(stream, len(PAYLOAD), deadline)
                if observed != PAYLOAD:
                    raise PeerError(
                        "echo payload mismatch\n"
                        f"  expected={PAYLOAD.hex()}\n"
                        f"  observed={observed.hex()}"
                    )

                # The echo service may keep the connection open.  Reject data
                # already queued after the canonical reply without requiring
                # EOF or imposing a close policy on the guest.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PeerError(
                        f"timed out after {timeout:.1f}s while validating the echo boundary"
                    )
                stream.settimeout(min(EXTRA_BYTE_SETTLE, remaining))
                try:
                    extra = stream.recv(1)
                except socket.timeout:
                    extra = b""
                if extra:
                    raise PeerError(
                        f"unexpected byte followed the exact echo: {extra.hex()}"
                    )
                return attempts
        except PeerError:
            raise
        except (OSError, TransientExchangeError) as error:
            last_error = str(error)

        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(RETRY_INTERVAL, remaining))


def selftest() -> None:
    failures: list[Exception] = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((LOOPBACK, 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])

        def serve_once() -> None:
            try:
                stream, address = listener.accept()
                with stream:
                    if address[0] != LOOPBACK:
                        raise PeerError(
                            f"self-test accepted non-loopback peer {address[0]}"
                        )
                    request = receive_exact(stream, len(PAYLOAD))
                    if request != PAYLOAD:
                        raise PeerError("self-test server received the wrong payload")
                    # Fragment the response to exercise receive_exact().
                    stream.sendall(request[:3])
                    stream.sendall(request[3:11])
                    stream.sendall(request[11:])
            except Exception as error:  # Preserve thread failures for the caller.
                failures.append(error)

        server = threading.Thread(target=serve_once, daemon=True)
        server.start()
        attempts = exchange(port, 2.0)
        server.join(2.0)
        if server.is_alive():
            raise PeerError("self-test server did not terminate")
        if failures:
            raise PeerError(f"self-test server failed: {failures[0]}")
        if attempts != 1:
            raise PeerError(f"self-test unexpectedly needed {attempts} attempts")

    selected = pick_loopback_port()
    if not 1 <= selected <= 65535:
        raise PeerError(f"port picker returned invalid port {selected}")


def valid_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be in the range 1..65535")
    return port


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--pick-port",
        action="store_true",
        help="print a currently unused loopback port and exit",
    )
    action.add_argument("--selftest", action="store_true")
    parser.add_argument("--port", type=valid_port, help="forwarded localhost port")
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="seconds to wait for the guest listener (default: 45)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.pick_port:
            print(pick_loopback_port())
            return 0
        if args.selftest:
            selftest()
            print("tcp-peer selftest: ok")
            return 0
        if args.port is None:
            raise PeerError("echo mode requires --port")
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise PeerError("--timeout must be a finite positive number")
        attempts = exchange(args.port, args.timeout)
        print(
            f"tcp-peer: exact {len(PAYLOAD)}-byte echo received "
            f"after {attempts} attempt(s)"
        )
        return 0
    except (OSError, PeerError, ValueError) as error:
        print(f"tcp-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
