#!/usr/bin/env python3
"""Summarize host-side TCP header evidence, without attributing CPU bottlenecks.

Wireshark analysis flags are heuristics, not hardware loss counters. Captured
outgoing segments can precede NIC segmentation/checksum offload. Missing SYNs,
capture drops, and offloads limit window/RTT/gap interpretations.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import subprocess

FLAGS = ['retransmission', 'fast_retransmission', 'spurious_retransmission',
         'duplicate_ack', 'zero_window', 'zero_window_probe', 'window_full']
FIELDS = ['frame.time_epoch', 'tcp.stream', 'ip.src', 'tcp.srcport', 'ip.dst',
          'tcp.dstport', 'tcp.len', 'tcp.window_size', 'tcp.window_size_scalefactor',
          'tcp.analysis.bytes_in_flight', 'tcp.analysis.ack_rtt', 'tcp.flags.syn',
          'tcp.options.wscale.shift'] + ['tcp.analysis.' + f for f in FLAGS]


def quantiles(values):
    if not values:
        return None
    values = sorted(values)
    return dict(count=len(values), min=values[0],
                p50=values[int((len(values)-1)*.5)],
                p95=values[int((len(values)-1)*.95)],
                p99=values[int((len(values)-1)*.99)], max=values[-1])


def analyze(lines):
    directions = {}
    windows = {}
    for line in lines:
        v = line.rstrip('\n').split('\t')
        if len(v) != len(FIELDS) or not v[1]:
            continue
        t, stream, src, sport, dst, dport = v[:6]
        t = float(t)
        key = (stream, src, sport, dst, dport)
        peer = (stream, dst, dport, src, sport)
        if key not in directions:
            directions[key] = dict(stream=int(stream), source=f'{src}:{sport}',
                destination=f'{dst}:{dport}', packets=0, data_bytes=0,
                data_packets=0, over_mss_1460=0, syn_seen=False, scale_shifts=[],
                flags=defaultdict(int), windows=[], flights=[], utilization=[],
                ack_rtt_ms=[], data_gaps_ms=[], ack_gaps_ms=[], large_gaps=[],
                last_data=None, last_ack=None, first_data=None, last_time=None)
        d = directions[key]
        d['packets'] += 1
        length = int(v[6] or 0)
        if v[7]:
            window = int(v[7])
            d['windows'].append(window)
            # -1 means scale was not established. Do not infer utilization.
            if v[8] and int(v[8]) != -1:
                windows[key] = window
        if v[10]:
            d['ack_rtt_ms'].append(float(v[10]) * 1000)
        syn = (v[11].lower() == 'true' if v[11].lower() in ('true', 'false')
               else bool(int(v[11] or '0', 0)))
        if syn:
            d['syn_seen'] = True
        if v[12]:
            d['scale_shifts'].append(int(v[12]))
        for flag, value in zip(FLAGS, v[13:]):
            if value:
                d['flags'][flag] += 1
        if length:
            d['data_bytes'] += length
            d['data_packets'] += 1
            d['over_mss_1460'] += length > 1460
            if d['last_data'] is not None:
                gap = (t - d['last_data']) * 1000
                d['data_gaps_ms'].append(gap)
                if gap >= 1:
                    d['large_gaps'].append(dict(end_unix=t, gap_ms=gap,
                        latest_peer_window=windows.get(peer)))
            d['last_data'] = t
            if d['first_data'] is None:
                d['first_data'] = t
            if v[9]:
                flight = int(v[9])
                d['flights'].append(flight)
                if windows.get(peer, 0) > 0:
                    d['utilization'].append(flight / windows[peer])
        elif not syn:
            # Includes FIN/RST/control ACKs; use data-stream directions and
            # inspect raw trace before interpreting this as delayed-ACK time.
            if d['last_ack'] is not None:
                d['ack_gaps_ms'].append((t - d['last_ack']) * 1000)
            d['last_ack'] = t
        d['last_time'] = t
    result = []
    for d in directions.values():
        d['large_gap_count'] = len(d['large_gaps'])
        d['large_gaps'] = sorted(d['large_gaps'], key=lambda x: -x['gap_ms'])[:20]
        for field in ['windows', 'flights', 'utilization', 'ack_rtt_ms',
                      'data_gaps_ms', 'ack_gaps_ms']:
            d[field] = quantiles(d[field])
        result.append(d)
    return sorted(result, key=lambda d: -d['data_bytes'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--tshark', default='tshark')
    a = p.parse_args()
    command = [a.tshark, '-r', str(a.capture), '-o', 'tcp.check_checksum:FALSE',
               '-T', 'fields', '-E', 'occurrence=f']
    for field in FIELDS:
        command += ['-e', field]
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as proc:
        directions = analyze(proc.stdout)
        if proc.wait():
            raise RuntimeError('tshark failed; no successful analysis written')
    result = dict(capture=str(a.capture), command=command, directions=directions,
        limitations=['Host capture point; gaps are not exact wire timing.',
            'Check capture.log for drops before drawing conclusions.',
            'Retransmission flags are Wireshark heuristics.',
            'Checksum validation disabled for truncated/offloaded host capture.',
            'Flight/window ratios use latest observed peer window, not congestion window.',
            'RTT and ACK gaps include host capture/scheduling effects.'],
        references=['https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html',
                    'https://wiki.wireshark.org/CaptureSetup/Offloading'])
    with a.output.open('x') as out:
        json.dump(result, out, indent=2)
        out.write('\n')


if __name__ == '__main__':
    main()
