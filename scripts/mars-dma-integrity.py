#!/usr/bin/env python3
"""Bounded ICMP echo integrity test for the explicitly addressed Mars link.

Run with permission to open a raw ICMP socket. Each response must reproduce the
entire changing payload, not merely a sequence number or a valid checksum.
This exercises RX/TX and the stack together; it does not isolate DMA failures.
"""
import argparse
import hashlib
import json
import socket
import struct
import time
from pathlib import Path


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def payload(sequence, length):
    # Every frame changes, including repeated lengths and successive ring wraps.
    return hashlib.shake_256(b'Mars DMA integrity v1' + struct.pack('!I', sequence)).digest(length)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--count', type=int, default=4096)
    args = parser.parse_args()
    socket.inet_pton(socket.AF_INET, args.address)
    if not 1 <= args.count <= 65535:
        parser.error('count must be between 1 and 65535')
    # Reserve evidence before issuing any traffic.
    with args.output.open('x') as evidence:
        sizes = [1472, 1, 18, 19, 20, 21, 81, 82, 83, 84, 85, 511, 512, 513, 1023, 1024, 1025, 1471]
        result = {'address': args.address, 'requested': args.count, 'sizes': sizes,
                  'sent': 0, 'verified': 0, 'timeouts': [], 'corruptions': [], 'ignored': 0}
        started = time.monotonic()
        identifier = 0x4d52
        consecutive_timeouts = 0
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                for sequence in range(args.count):
                    body = payload(sequence, sizes[sequence % len(sizes)])
                    header = struct.pack('!BBHHH', 8, 0, 0, identifier, sequence)
                    request = header[:2] + struct.pack('!H', checksum(header + body)) + header[4:] + body
                    sock.sendto(request, (args.address, 0))
                    result['sent'] += 1
                    deadline = time.monotonic() + 2
                    matched = False
                    while time.monotonic() < deadline:
                        sock.settimeout(max(.001, deadline - time.monotonic()))
                        try:
                            frame, peer = sock.recvfrom(65535)
                        except socket.timeout:
                            break
                        if peer[0] != args.address or len(frame) < 28:
                            result['ignored'] += 1
                            continue
                        ihl = (frame[0] & 15) * 4
                        # Darwin raw IPv4 input length fields are host-order;
                        # recvfrom's byte length is the authoritative received span.
                        icmp = frame[ihl:]
                        if ihl < 20 or len(icmp) < 8:
                            result['ignored'] += 1
                            continue
                        typ, code, _, ident, seq = struct.unpack('!BBHHH', icmp[:8])
                        if (typ, code, ident, seq) != (0, 0, identifier, sequence):
                            result['ignored'] += 1
                            continue
                        matched = True
                        if checksum(icmp) != 0 or icmp[8:] != body:
                            result['corruptions'].append({'sequence': sequence, 'expected_length': len(body),
                                'received_length': len(icmp) - 8, 'checksum_valid': checksum(icmp) == 0,
                                'expected_sha256': hashlib.sha256(body).hexdigest(),
                                'received_sha256': hashlib.sha256(icmp[8:]).hexdigest()})
                        else:
                            result['verified'] += 1
                        break
                    if matched:
                        consecutive_timeouts = 0
                    else:
                        result['timeouts'].append(sequence)
                        consecutive_timeouts += 1
                    if consecutive_timeouts >= 3 or result['corruptions']:
                        break
                    time.sleep(.001)
        except Exception as error:
            result['error'] = str(error)
        result['seconds'] = time.monotonic() - started
        result['passed'] = result['verified'] == args.count and not result['corruptions']
        json.dump(result, evidence, indent=2)
        evidence.write('\n')
        print(json.dumps(result), flush=True)
        return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
