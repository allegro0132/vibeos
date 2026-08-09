#!/usr/bin/env python3
"""Deterministic, unprivileged QEMU socket peer for virtio-net acceptance.

QEMU's ``-netdev socket`` stream protocol prefixes each raw Ethernet frame with
a four-byte big-endian length.  This peer binds only to an ephemeral
127.0.0.1 port and accepts exactly the M4.4 test protocol; it is not a TAP
adapter, IP stack, or general packet bridge.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import struct
import sys


LOOPBACK = "127.0.0.1"
ETHERNET_FRAME_LEN = 60
GUEST_MAC = bytes.fromhex("020000000001")
PEER_MAC = bytes.fromhex("020000000002")
ETHERTYPE = bytes.fromhex("88b5")

HELLO_PAYLOAD = b"VIBEOS-NET-HELLO-v1"
CHALLENGE_PAYLOAD = b"VIBEOS-NET-CHALLENGE-v1"
ACK_PAYLOAD = b"VIBEOS-NET-ACK-v1"


class ProtocolError(RuntimeError):
    pass


def ethernet_frame(destination: bytes, source: bytes, payload: bytes) -> bytes:
    if len(destination) != 6 or len(source) != 6:
        raise ValueError("Ethernet addresses must contain exactly six bytes")
    header = destination + source + ETHERTYPE
    if len(header) + len(payload) > ETHERNET_FRAME_LEN:
        raise ValueError("test payload does not fit the canonical frame")
    return (header + payload).ljust(ETHERNET_FRAME_LEN, b"\0")


HELLO = ethernet_frame(PEER_MAC, GUEST_MAC, HELLO_PAYLOAD)
CHALLENGE = ethernet_frame(GUEST_MAC, PEER_MAC, CHALLENGE_PAYLOAD)
ACK = ethernet_frame(PEER_MAC, GUEST_MAC, ACK_PAYLOAD)


def receive_exact(stream: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise ProtocolError(
                f"peer closed with {remaining} of {length} byte(s) still expected"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(stream: socket.socket) -> bytes:
    encoded_length = receive_exact(stream, 4)
    (length,) = struct.unpack("!I", encoded_length)
    if length != ETHERNET_FRAME_LEN:
        raise ProtocolError(
            f"expected a {ETHERNET_FRAME_LEN}-byte raw Ethernet frame, got {length}"
        )
    return receive_exact(stream, length)


def send_frame(stream: socket.socket, frame: bytes) -> None:
    if len(frame) != ETHERNET_FRAME_LEN:
        raise ProtocolError(f"refusing to send non-canonical {len(frame)}-byte frame")
    stream.sendall(struct.pack("!I", len(frame)) + frame)


def expect_frame(stream: socket.socket, expected: bytes, label: str) -> None:
    observed = receive_frame(stream)
    if observed != expected:
        raise ProtocolError(
            f"{label} mismatch\n"
            f"  expected={expected.hex()}\n"
            f"  observed={observed.hex()}"
        )


def evidence_text(mode: str) -> str:
    lines = [
        "version=vibeos-net-peer-v1",
        f"mode={mode}",
        "transport=qemu-socket-4-byte-be",
    ]
    if mode == "recovery":
        lines.append(f"fault_hello={HELLO.hex()}")
        lines.append(f"retry_hello={HELLO.hex()}")
    else:
        lines.append(f"hello={HELLO.hex()}")
    lines.extend(
        [
            f"challenge={CHALLENGE.hex()}",
            f"ack={ACK.hex()}",
            "result=ok",
        ]
    )
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, data: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def serve(mode: str, ready_path: Path, evidence_path: Path, timeout: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LOOPBACK, 0))
        listener.listen(1)
        listener.settimeout(timeout)
        port = listener.getsockname()[1]
        atomic_write(ready_path, f"{port}\n")

        stream, address = listener.accept()
        with stream:
            if address[0] != LOOPBACK:
                raise ProtocolError(f"refusing non-loopback peer {address[0]}")
            stream.settimeout(timeout)
            if mode == "recovery":
                # The first transmit has been exposed before the injected driver
                # fault.  Do not answer it: a challenge queued before reset could
                # otherwise survive in the backend and satisfy the new epoch.
                expect_frame(stream, HELLO, "fault-attempt HELLO")
                expect_frame(stream, HELLO, "post-reset HELLO")
            else:
                expect_frame(stream, HELLO, "HELLO")
            send_frame(stream, CHALLENGE)
            expect_frame(stream, ACK, "ACK")

            # Fail on an immediately buffered fourth protocol frame. The guest
            # remains connected until `halt`, so EOF is not required here.
            stream.settimeout(0.2)
            try:
                extra = stream.recv(1)
            except socket.timeout:
                extra = b""
            if extra:
                raise ProtocolError("unexpected data followed the terminal ACK")

    atomic_write(evidence_path, evidence_text(mode))


def check_evidence(path: Path, mode: str) -> None:
    try:
        observed = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ProtocolError(f"cannot read evidence {path}: {error}") from error
    expected = evidence_text(mode)
    if observed != expected:
        raise ProtocolError(
            f"evidence mismatch for {mode}\n"
            f"  expected={expected!r}\n"
            f"  observed={observed!r}"
        )


def selftest() -> None:
    assert len(HELLO) == ETHERNET_FRAME_LEN
    assert HELLO[:6] == PEER_MAC
    assert HELLO[6:12] == GUEST_MAC
    assert HELLO[12:14] == ETHERTYPE
    assert HELLO[14 : 14 + len(HELLO_PAYLOAD)] == HELLO_PAYLOAD
    assert CHALLENGE[:6] == GUEST_MAC
    assert CHALLENGE[6:12] == PEER_MAC
    assert ACK[:6] == PEER_MAC
    assert ACK[6:12] == GUEST_MAC

    left, right = socket.socketpair()
    with left, right:
        send_frame(left, HELLO)
        assert receive_frame(right) == HELLO

    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", ETHERNET_FRAME_LEN - 1))
        try:
            receive_frame(right)
        except ProtocolError:
            pass
        else:
            raise AssertionError("non-canonical QEMU length was accepted")

    assert "fault_hello=" not in evidence_text("normal")
    assert evidence_text("recovery").count(f"={HELLO.hex()}") == 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--selftest", action="store_true")
    action.add_argument("--check-evidence", type=Path)
    parser.add_argument("--mode", choices=("normal", "recovery"), default="normal")
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--timeout", type=float, default=45.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            selftest()
            print("net-peer selftest: ok")
            return 0
        if args.check_evidence is not None:
            check_evidence(args.check_evidence, args.mode)
            return 0
        if args.ready is None or args.evidence is None:
            raise ProtocolError("server mode requires both --ready and --evidence")
        if args.timeout <= 0:
            raise ProtocolError("--timeout must be positive")
        serve(args.mode, args.ready, args.evidence, args.timeout)
        return 0
    except (OSError, ProtocolError, ValueError) as error:
        print(f"net-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
