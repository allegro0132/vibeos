#!/usr/bin/env python3
"""Loopback-only client for the QEMU TCP echo acceptance test.

The payload deliberately contains text, NUL, control, and high-bit bytes so the
test proves that the guest exposes a byte stream rather than a line protocol.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import socket
import sys
import threading
import time


LOOPBACK = "127.0.0.1"
PAYLOAD = b"VIBEOS-TCP-ECHO-v1\x00\x01\x7f\x80\xff\r\n"
RECOVERY_BEFORE = b"VIBEOS-STACK-BEFORE-v1\x00\x80\xff"
RECOVERY_AFTER = b"VIBEOS-STACK-AFTER-v1\x01\x81\xfe"
RECOVERY_STALE_PROBES = (
    b"VIBEOS-OLD-STREAM-PROBE-A-v1\x00\xff",
    b"VIBEOS-OLD-STREAM-PROBE-B-v1\x01\xfe",
    b"VIBEOS-OLD-STREAM-PROBE-C-v1\x02\xfd",
)
RECOVERY_FRESH_PROBES = (
    b"VIBEOS-FRESH-STREAM-PROBE-A-v1\x03\xfc",
    b"VIBEOS-FRESH-STREAM-PROBE-B-v1\x04\xfb",
    b"VIBEOS-FRESH-STREAM-PROBE-C-v1\x05\xfa",
)
CONNECT_ATTEMPT_TIMEOUT = 1.0
RETRY_INTERVAL = 0.05
EXTRA_BYTE_SETTLE = 0.1
RETIRED_STREAM_OBSERVATION = 6.0


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


def open_echo_stream(
    port: int, payload: bytes, deadline: float
) -> tuple[socket.socket, int]:
    attempts = 0
    last_error = "guest listener did not accept a connection"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PeerError(f"recovery connection timed out; last error: {last_error}")
        attempts += 1
        stream: socket.socket | None = None
        try:
            stream = socket.create_connection(
                (LOOPBACK, port), timeout=min(CONNECT_ATTEMPT_TIMEOUT, remaining)
            )
            stream.sendall(payload)
            observed = receive_exact(stream, len(payload), deadline)
            if observed != payload:
                raise PeerError(
                    "recovery echo payload mismatch\n"
                    f"  expected={payload.hex()}\n"
                    f"  observed={observed.hex()}"
                )
            return stream, attempts
        except PeerError:
            if stream is not None:
                stream.close()
            raise
        except (OSError, TransientExchangeError) as error:
            if stream is not None:
                stream.close()
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(RETRY_INTERVAL, remaining))


def recovery_exchange(
    port: int, timeout: float, ready_path: Path, continue_path: Path
) -> tuple[int, int]:
    deadline = time.monotonic() + timeout
    old_stream, old_attempts = open_echo_stream(port, RECOVERY_BEFORE, deadline)
    try:
        ready_path.write_text("old stream ready\n", encoding="ascii")
        while not continue_path.exists():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerError("timed out waiting for the stack-fault recovery marker")
            time.sleep(min(RETRY_INTERVAL, remaining))

        # Prove that the replacement stack is serving traffic before treating
        # silence on the retired stream as fail-closed evidence, then close the
        # fresh connection so the single guest socket is available. Alternate
        # three never-before-used old-stream probes with short-lived exact
        # fresh exchanges; any old-stream byte fails, while each nearby fresh
        # success rules out listener occupancy and a globally stalled guest.
        new_stream, new_attempts = open_echo_stream(port, RECOVERY_AFTER, deadline)
        new_stream.close()

        observation_deadline = min(
            deadline, time.monotonic() + RETIRED_STREAM_OBSERVATION
        )
        for stale_probe, fresh_probe in zip(
            RECOVERY_STALE_PROBES, RECOVERY_FRESH_PROBES, strict=True
        ):
            remaining = observation_deadline - time.monotonic()
            if remaining <= 0:
                raise PeerError("retired-stream observation window expired early")
            old_stream.settimeout(min(0.6, remaining))
            retired_closed = False
            try:
                old_stream.sendall(stale_probe)
                observed = old_stream.recv(4096)
            except socket.timeout:
                observed = b""
            except (ConnectionError, OSError):
                observed = b""
                retired_closed = True
            if observed:
                raise PeerError(
                    f"retired TCP stream returned data after recovery: {observed.hex()}"
                )

            fresh_deadline = min(
                observation_deadline, time.monotonic() + CONNECT_ATTEMPT_TIMEOUT
            )
            fresh_stream, _ = open_echo_stream(port, fresh_probe, fresh_deadline)
            fresh_stream.close()
            if retired_closed:
                break
    finally:
        old_stream.close()

    return old_attempts, new_attempts


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
    action.add_argument("--recovery", action="store_true")
    parser.add_argument("--port", type=valid_port, help="forwarded localhost port")
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="seconds to wait for the guest listener (default: 45)",
    )
    parser.add_argument(
        "--recovery-ready",
        type=Path,
        help="publish readiness here after the pre-fault stream echoes",
    )
    parser.add_argument(
        "--recovery-continue",
        type=Path,
        help="wait for this file before probing the retired stream",
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
        if args.recovery:
            if args.recovery_ready is None or args.recovery_continue is None:
                raise PeerError(
                    "recovery mode requires --recovery-ready and --recovery-continue"
                )
            old_attempts, new_attempts = recovery_exchange(
                args.port,
                args.timeout,
                args.recovery_ready,
                args.recovery_continue,
            )
            print(
                "tcp-peer: retired stream rejected and fresh stream echoed "
                f"after {old_attempts}/{new_attempts} attempt(s)"
            )
            return 0
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
