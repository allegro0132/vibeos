#!/usr/bin/env python3
"""Compare a sealed one-shot ntxaudit dump with an Ethernet pcap.

Requires a complete capture (including SYN/FIN) started before arming and
stopped after sealing. Check tcpdump kernel drops separately. Header
fingerprints are commutative, exclude offloaded checksums and payload, and
are not a cryptographic integrity or packet-order proof. Driver acceptance
does not prove MAC completion or wire delivery.
"""
import argparse
import json
import re
import struct
from pathlib import Path

MASK = (1 << 64) - 1
FIELDS = ['frames', 'payload_bytes', 'hash_sum', 'hash_xor', 'syn', 'fin']
HARDWARE_FIELDS = ['available', 'accepted', 'pending', 'control',
                   'frames_good_bad', 'frames_good', 'underflow', 'carrier_error', 'pause',
                   'local_advertisement', 'partner_advertisement']


def hardware_comparison(dump):
    rows = {phase: json.loads(values) for phase, values in
            re.findall(r'NTXAUDIT_HW phase=(start|stop) values=(\[[^\r\n]+\])', dump)}
    result = {'fields': HARDWARE_FIELDS, 'snapshots': rows, 'quiescent_comparison_valid': False}
    if set(rows) != {'start', 'stop'} or any(len(v) not in (9, 11) for v in rows.values()):
        return result
    start, stop = rows['start'], rows['stop']
    valid = (start[0] == stop[0] == 1 and start[2] == stop[2] == 0
             and start[3] == stop[3] and not start[3] & 0x3d and stop[1] >= start[1]
             and stop[1] - start[1] < 2**32
             and all(x != 0xffffffff for v in rows.values() for x in v[4:9]))
    if valid:
        result['quiescent_comparison_valid'] = True
        result['accepted_delta'] = stop[1] - start[1]
        result['counter_deltas'] = dict(zip(HARDWARE_FIELDS[4:9],
                                           [(b - a) & 0xffffffff for a, b in zip(start[4:9], stop[4:9])]))
    result['limitation'] = 'Requires no intervening reset/link recovery. MAC counters cover all frames, not only test TCP.'
    return result


def mix(n):
    n = ((n ^ (n >> 30)) * 0xbf58476d1ce4e5b9) & MASK
    n = ((n ^ (n >> 27)) * 0x94d049bb133111eb) & MASK
    return n ^ (n >> 31)


def rotate(n, k):
    return ((n << k) | (n >> (64 - k))) & MASK


def fingerprint(frame):
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
    if (ip[0] >> 4 != 4 or ihl < 20 or total > len(ip) or total < ihl + 20
            or ip[9] != 6 or int.from_bytes(ip[6:8], 'big') & 0x3fff
            or ip[12:16] != bytes([192, 168, 77, 10])
            or ip[16:20] != bytes([192, 168, 77, 1])):
        return None
    tcp = ip[ihl:total]
    if int.from_bytes(tcp[:2], 'big') != 5300:
        return None
    header = (tcp[12] >> 4) * 4
    if header < 20 or header > len(tcp):
        return None
    payload, flags = len(tcp) - header, tcp[13]
    seq_ack, ports = int.from_bytes(tcp[4:12], 'big'), int.from_bytes(tcp[:4], 'big')
    shape = payload | (flags << 32) | (int.from_bytes(tcp[14:16], 'big') << 40) | (header << 56)
    return mix(seq_ack) ^ rotate(mix(shape), 17) ^ rotate(mix(ports), 31), payload, flags


def capture_totals(path, allow_header_only=False):
    totals = [0] * 6
    frames = 0
    with path.open('rb') as file:
        header = file.read(24)
        magics = {b'\xd4\xc3\xb2\xa1': '<', b'\x4d\x3c\xb2\xa1': '<',
                  b'\xa1\xb2\xc3\xd4': '>', b'\xa1\xb2\x3c\x4d': '>'}
        if len(header) != 24 or header[:4] not in magics:
            raise ValueError('expected classic pcap, not pcapng')
        endian = magics[header[:4]]
        if struct.unpack(endian + 'I', header[20:24])[0] != 1:
            raise ValueError('expected Ethernet capture')
        while record := file.read(16):
            if len(record) != 16:
                raise ValueError('partial packet header')
            _, _, size, original = struct.unpack(endian + 'IIII', record)
            if max(size, original) > 1024 * 1024:
                raise ValueError('unreasonable capture record size')
            frame = file.read(size)
            if len(frame) != size or size > original:
                raise ValueError('incomplete or snaplen-truncated capture')
            if size < original:
                if not allow_header_only:
                    raise ValueError('incomplete or snaplen-truncated capture')
                if size < 54 or frame[12:14] != b'\x08\x00':
                    raise ValueError('incomplete Ethernet/IPv4/TCP headers')
                ihl = (frame[14] & 15) * 4
                tcp_offset = 14 + ihl
                if ihl < 20 or size < tcp_offset + 20:
                    raise ValueError('incomplete IPv4/TCP headers')
                tcp_header = (frame[tcp_offset + 12] >> 4) * 4
                if tcp_header < 20 or size < tcp_offset + tcp_header:
                    raise ValueError('incomplete TCP options')
                # Payload is deliberately excluded from the fingerprint. Pad
                # only after every header byte used by the parser is present.
                frame += bytes(original - size)
            frames += 1
            value = fingerprint(frame)
            if value is None:
                continue
            h, payload, flags = value
            totals[0] += 1
            totals[1] += payload
            totals[2] = (totals[2] + h) & MASK
            totals[3] ^= h
            totals[4] += bool(flags & 2)
            totals[5] += bool(flags & 1)
    return frames, totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path)
    parser.add_argument('serial_dump', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-header-only', action='store_true')
    parser.add_argument('--capture-log', type=Path,
                        help='tcpdump completion log; required to assess capture loss')
    args = parser.parse_args()
    dump = args.serial_dump.read_text()
    if 'NTXAUDIT_END' not in dump:
        parser.error('missing sealed audit terminator')
    rows = {int(stage): json.loads(values) for stage, values in
            re.findall(r'NTXAUDIT stage=(\d+) values=(\[[^\r\n]+\])', dump)}
    if set(rows) != {0, 1} or any(len(v) != 6 for v in rows.values()):
        parser.error('expected both six-counter audit stages')
    captured, host = capture_totals(args.pcap, args.allow_header_only)
    drop_matches = (re.findall(r'(\d+) packets dropped by kernel', args.capture_log.read_text())
                    if args.capture_log else [])
    drops = int(drop_matches[-1]) if drop_matches else None
    result = {'fields': FIELDS, 'captured_packets': captured,
              'capture_kernel_drops': drops,
              'capture_loss_check_passed': drops == 0,
              'protocol_generated': rows[0], 'driver_accepted': rows[1], 'host_captured': host,
              'protocol_matches_driver': rows[0] == rows[1],
              'driver_matches_host': rows[1] == host,
              'hardware': hardware_comparison(dump),
              'limitation': 'Check capture drops and scope; acceptance is not DMA completion; fingerprints omit payload and ordering.'}
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
