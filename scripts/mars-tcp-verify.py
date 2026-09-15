#!/usr/bin/env python3
"""Verify application-visible Mars TCP ingress (requires probe V2 mode 2).

This includes byte verification cost and is not a throughput benchmark.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import struct
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--address', required=True, type=ipaddress.IPv4Address)
    p.add_argument('--port', type=int, default=5300)
    p.add_argument('--bytes', type=int, default=64 * 1024 * 1024)
    p.add_argument('--corrupt-at', type=int)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if not 1 <= a.port <= 65535 or not 1 <= a.bytes <= 16 * 1024**3:
        p.error('port or byte count out of range')
    if a.corrupt_at is not None and not 0 <= a.corrupt_at < a.bytes:
        p.error('corrupt offset must be inside the payload')
    result = dict(address=str(a.address), port=a.port, requested_bytes=a.bytes,
                  corrupt_at=a.corrupt_at, passed=False, benchmark=False)
    # Reserve output before sending anything; previous evidence is never replaced.
    with a.output.open('x') as out:
        started = time.monotonic()
        admitted = False
        try:
            with socket.create_connection((str(a.address), a.port), timeout=30) as s:
                s.settimeout(30)
                s.sendall(b'VBENCH02' + bytes([2]) + bytes(7) + struct.pack('!Q', a.bytes))
                if s.recv(1) != b'R':
                    raise RuntimeError('verified sink did not admit the request')
                admitted = True
                s.sendall(b'G')
                block = bytes(range(251)) * 256
                sent = 0
                while sent < a.bytes:
                    chunk = block[:min(len(block), a.bytes - sent)]
                    if a.corrupt_at is not None and sent <= a.corrupt_at < sent + len(chunk):
                        changed = bytearray(chunk)
                        changed[a.corrupt_at - sent] = 255
                        chunk = changed
                    s.sendall(chunk)
                    sent += len(chunk)
                data = bytearray()
                while len(data) < 16:
                    b = s.recv(16 - len(data))
                    if not b:
                        raise RuntimeError('closed without verification result')
                    data.extend(b)
                count, ms = struct.unpack('!QQ', data)
                result.update(confirmed_bytes=count, board_ms=ms)
                if a.corrupt_at is not None:
                    raise RuntimeError('corrupted input was incorrectly accepted')
                if count != a.bytes or s.recv(1) != b'':
                    raise RuntimeError('invalid verification result or trailing data')
                result['passed'] = True
        except (BrokenPipeError, ConnectionResetError) as e:
            result['connection_error'] = type(e).__name__
            # Admission distinguishes a tested rejection from a missing service.
            result['passed'] = admitted and a.corrupt_at is not None
        except Exception as e:
            result['error'] = str(e)
        finally:
            result['seconds'] = time.monotonic() - started
            json.dump(result, out, indent=2)
            out.write('\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
