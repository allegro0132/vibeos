#!/usr/bin/env python3
"""Independent byte-count TCP benchmark; no iperf control/data implementation.

Modes are relative to the board: sink=host->board, source=board->host.
Header: 8-byte VBENCH01, mode byte, 7 reserved zero bytes, BE u64 byte count.
Response after payload: BE u64 completed bytes, BE u64 board elapsed ms.
Source result time measures enqueue completion, NOT delivery; host measures RX.
Use --loopback to calibrate the same Python client against a local model server.
"""
import argparse
import concurrent.futures
import json
import socket
import struct
import threading
import time
from pathlib import Path

CHUNK = 32768
MAX_BYTES = 16 * 1024**3


def read_exact(sock, size):
    data = bytearray(size)
    view = memoryview(data)
    pos = 0
    while pos < size:
        n = sock.recv_into(view[pos:])
        if not n:
            raise RuntimeError(f"early EOF: {pos}/{size}")
        pos += n
    return data


def transfer(address, port, size, mode, barrier, timeout):
    with socket.create_connection((address, port), timeout) as sock:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # All handshakes finish before payload starts. Headers go after barrier.
        barrier.wait(timeout=timeout)
        start = time.monotonic_ns()
        sock.sendall(b"VBENCH01" + bytes([mode == "source"]) + bytes(7) + struct.pack("!Q", size))
        done = 0
        first_payload_ns = None
        first_payload_bytes = 0
        socket_buffers_start = dict(send=sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF), receive=sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
        buffer = bytearray(b"\xa5" * CHUNK)
        view = memoryview(buffer)
        while done < size:
            length = min(CHUNK, size - done)
            if mode == "sink":
                sock.sendall(view[:length])
                done += length
            else:
                n = sock.recv_into(view[:length])
                if not n:
                    raise RuntimeError(f"short payload: {done}/{size}")
                done += n
            if first_payload_ns is None:
                first_payload_ns = time.monotonic_ns()
                first_payload_bytes = done
        payload_end = time.monotonic_ns()
        board_bytes, board_ms = struct.unpack("!QQ", read_exact(sock, 16))
        confirmed = time.monotonic_ns()
        if board_bytes != size:
            raise RuntimeError(f"board count mismatch: {board_bytes}/{size}")
        if sock.recv(1):
            raise RuntimeError("unexpected trailing data")
        end = confirmed if mode == "sink" else payload_end
        return dict(port=port, bytes=done, start_ns=start, end_ns=end,
                    seconds=(end-start)/1e9, board_elapsed_ms=board_ms,
                    receiver_mbps=size*8000/(end-start), board_count=board_bytes,
                    first_payload_delay_ms=(first_payload_ns-start)/1e6,
                    payload_span_ms=(payload_end-first_payload_ns)/1e6,
                    confirmation_delay_ms=(confirmed-payload_end)/1e6,
                    first_payload_bytes=first_payload_bytes,
                    first_payload_ns=first_payload_ns, payload_end_ns=payload_end,
                    socket_buffers_start=socket_buffers_start,
                    socket_buffers_end=dict(send=sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF), receive=sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)))


def model_server(listener):
    with listener:
        connection, _ = listener.accept()
        with connection as sock:
            sock.settimeout(120)
            h = read_exact(sock, 24)
            if h[:8] != b"VBENCH01" or h[8] > 1 or any(h[9:16]):
                raise RuntimeError("invalid header")
            size = struct.unpack("!Q", h[16:])[0]
            if not 0 < size <= MAX_BYTES:
                raise RuntimeError("invalid size")
            buffer = bytearray(b"\xa5" * CHUNK)
            view = memoryview(buffer)
            start = time.monotonic_ns()
            done = 0
            while done < size:
                length = min(CHUNK, size-done)
                if h[8]:
                    sock.sendall(view[:length]); done += length
                else:
                    n = sock.recv_into(view[:length])
                    if not n:
                        raise RuntimeError("early EOF")
                    done += n
            sock.sendall(struct.pack("!QQ", done, (time.monotonic_ns()-start)//1000000))


def run(address, ports, size, mode, timeout, loopback=False):
    listeners = []
    server_pool = None
    try:
        if loopback:
            address = "127.0.0.1"
            for _ in ports:
                listener = socket.socket()
                listener.settimeout(timeout)
                listener.bind((address, 0)); listener.listen(1)
                listeners.append(listener)
            ports = [s.getsockname()[1] for s in listeners]
            server_pool = concurrent.futures.ThreadPoolExecutor(len(ports))
            servers = [server_pool.submit(model_server, s) for s in listeners]
        barrier = threading.Barrier(len(ports))
        with concurrent.futures.ThreadPoolExecutor(len(ports)) as pool:
            futures = [pool.submit(transfer, address, port, size, mode, barrier, timeout) for port in ports]
            rows = [f.result() for f in futures]
        if server_pool:
            for f in servers:
                f.result()
        return summarize(mode, rows, size)
    finally:
        for s in listeners:
            s.close()
        if server_pool:
            server_pool.shutdown(wait=True)


def summarize(mode, rows, size):
    duration = (max(r["end_ns"] for r in rows)-min(r["start_ns"] for r in rows))/1e9
    result = dict(mode=mode, flows=len(rows), bytes_per_flow=size, seconds=duration,
                  aggregate_receiver_mbps=sum(r["bytes"] for r in rows)*8/duration/1e6,
                  streams=rows, payload_integrity_checked=False,
                  payload_interval_receiver_mbps=None)
    if mode == "source":
        # Exclude each stream's first recv, whose bytes precede its timestamp.
        # The shared wall interval retains staggered starts and all later pauses.
        span = max(r["payload_end_ns"] for r in rows)-min(r["first_payload_ns"] for r in rows)
        counted = sum(r["bytes"]-r["first_payload_bytes"] for r in rows)
        if span > 0 and counted > 0:
            result["payload_interval_receiver_mbps"] = counted*8000/span
            result["payload_interval_bytes"] = counted
            result["payload_interval_seconds"] = span/1e9
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--address")
    p.add_argument("--first-port", type=int, default=5300)
    p.add_argument("--bytes", type=int, default=1024**3)
    p.add_argument("--flows", type=int, nargs="+", choices=[1, 4], default=[1, 4])
    p.add_argument("--mode", choices=["sink", "source", "both"], default="both")
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--loopback", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not args.loopback and not args.address:
        p.error("--address required for board tests")
    if not 0 < args.bytes <= MAX_BYTES or not 1 <= args.first_port <= 65532:
        p.error("invalid byte count or port range")
    modes = ["sink", "source"] if args.mode == "both" else [args.mode]
    # Reserve path before opening sockets, preserving failed-run evidence.
    with args.output.open("x") as out:
        result = dict(address=args.address, loopback=args.loopback, started_unix=time.time(),
                      io_chunk_bytes=CHUNK, results=[],
                      timing="host monotonic; sink ends at board byte-count confirmation; source ends at final payload receive")
        try:
            for flows in args.flows:
                for mode in modes:
                    row = run(args.address, list(range(args.first_port, args.first_port+flows)), args.bytes, mode, args.timeout, args.loopback)
                    result["results"].append(row)
                    print(f'{mode} flows={flows}: {row["aggregate_receiver_mbps"]:.2f} Mbps', flush=True)
                    time.sleep(2)
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            result["finished_unix"] = time.time()
            json.dump(result, out, indent=2); out.write("\n")

if __name__ == "__main__":
    main()
