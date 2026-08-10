#!/usr/bin/env python3
"""Raw-Ethernet peer for the Milk-V Duo DWMAC acceptance handshake."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import socket
import sys
import time


GUEST_MAC = bytes.fromhex("020000000001")
PEER_MAC = bytes.fromhex("020000000002")
BROADCAST_MAC = b"\xff" * 6
ETHERTYPE = 0x88B5
FRAME_LEN = 60
HELLO_PAYLOAD = b"VIBEOS-NET-HELLO-v1"
CHALLENGE_PAYLOAD = b"VIBEOS-NET-CHALLENGE-v1"
ACK_PAYLOAD = b"VIBEOS-NET-ACK-v1"


def ethernet_frame(destination: bytes, source: bytes, payload: bytes) -> bytes:
    frame = destination + source + ETHERTYPE.to_bytes(2, "big") + payload
    return frame.ljust(FRAME_LEN, b"\0")


HELLO = ethernet_frame(BROADCAST_MAC, GUEST_MAC, HELLO_PAYLOAD)
CHALLENGE = ethernet_frame(GUEST_MAC, PEER_MAC, CHALLENGE_PAYLOAD)
ACK = ethernet_frame(BROADCAST_MAC, GUEST_MAC, ACK_PAYLOAD)


class LinuxPeer:
    def __init__(self, interface: str) -> None:
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE))
        self.sock.bind((interface, 0))
        self.sock.settimeout(0.1)

    def receive(self) -> bytes | None:
        try:
            return self.sock.recv(65535)
        except TimeoutError:
            return None

    def send(self, frame: bytes) -> None:
        if self.sock.send(frame) != len(frame):
            raise RuntimeError("raw socket accepted a short Ethernet frame")

    def close(self) -> None:
        self.sock.close()


class Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class PcapHeader(ctypes.Structure):
    _fields_ = [("ts", Timeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


class DarwinPeer:
    def __init__(self, interface: str) -> None:
        library = ctypes.util.find_library("pcap")
        if not library:
            raise RuntimeError("libpcap is unavailable")
        self.lib = ctypes.CDLL(library)
        self.lib.pcap_open_live.restype = ctypes.c_void_p
        self.lib.pcap_open_live.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        self.lib.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(PcapHeader)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ]
        self.lib.pcap_inject.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        self.lib.pcap_close.argtypes = [ctypes.c_void_p]
        error = ctypes.create_string_buffer(256)
        self.handle = self.lib.pcap_open_live(interface.encode(), 65535, 1, 50, error)
        if not self.handle:
            raise RuntimeError(error.value.decode(errors="replace"))

    def receive(self) -> bytes | None:
        header = ctypes.POINTER(PcapHeader)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        result = self.lib.pcap_next_ex(self.handle, ctypes.byref(header), ctypes.byref(data))
        if result == 0:
            return None
        if result != 1:
            raise RuntimeError(f"pcap_next_ex failed with status {result}")
        return ctypes.string_at(data, header.contents.caplen)

    def send(self, frame: bytes) -> None:
        buffer = ctypes.create_string_buffer(frame)
        written = self.lib.pcap_inject(self.handle, buffer, len(frame))
        if written != len(frame):
            raise RuntimeError(f"pcap injected {written} of {len(frame)} bytes")

    def close(self) -> None:
        self.lib.pcap_close(self.handle)


def open_peer(interface: str):
    if sys.platform == "darwin":
        return DarwinPeer(interface)
    if sys.platform.startswith("linux"):
        return LinuxPeer(interface)
    raise RuntimeError(f"unsupported host platform: {sys.platform}")


def self_test() -> None:
    assert len(HELLO) == len(CHALLENGE) == len(ACK) == FRAME_LEN
    assert HELLO[:6] == BROADCAST_MAC and HELLO[6:12] == GUEST_MAC
    assert CHALLENGE[:6] == GUEST_MAC and CHALLENGE[6:12] == PEER_MAC
    assert ACK[:6] == BROADCAST_MAC and ACK[6:12] == GUEST_MAC
    assert all(frame[12:14] == ETHERTYPE.to_bytes(2, "big") for frame in (HELLO, CHALLENGE, ACK))
    print("Milk-V raw-L2 peer frame self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.interface:
        parser.error("--interface is required unless --self-test is used")

    peer = open_peer(args.interface)
    deadline = time.monotonic() + args.timeout
    hello_seen = False
    try:
        print(f"READY interface={args.interface} ethertype=0x{ETHERTYPE:04x}", flush=True)
        while time.monotonic() < deadline:
            packet = peer.receive()
            if packet is None:
                continue
            frame = packet[:FRAME_LEN]
            if frame == HELLO:
                hello_seen = True
                peer.send(CHALLENGE)
                print("HELLO received; CHALLENGE sent", flush=True)
            elif hello_seen and frame == ACK:
                print("ACK received; raw-L2 handshake PASS", flush=True)
                return 0
    finally:
        peer.close()
    print("raw-L2 handshake timed out", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
