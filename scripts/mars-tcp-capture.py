#!/usr/bin/env python3
"""Capture TCP headers around a bounded Mars throughput pair (requires capture permission).

Leaves NIC offloads unchanged. Host capture times/segment sizes are not wire
times/segment sizes; checksum and retransmission labels need that qualification.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--interface', required=True)
    p.add_argument('--address', required=True, type=ipaddress.IPv4Address)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--seconds', type=int, choices=range(1, 61), default=20)
    p.add_argument('--iperf', required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    meta = {'started_unix': time.time(), 'address': str(a.address),
            'interface': a.interface, 'snaplen': 128,
            'offloads_changed': False, 'capture_point': 'host NIC API, not wire tap'}
    capture = None
    try:
        with (a.output / 'capture.log').open('x') as log:
            capture = subprocess.Popen([
                '/usr/sbin/tcpdump', '-i', a.interface, '-n', '-s', '128',
                '-w', str(a.output / 'tcp.pcap'),
                f'tcp and host {a.address}'], stdout=log, stderr=log)
            time.sleep(1)
            if capture.poll() is not None:
                raise RuntimeError('capture failed; inspect capture.log')
            meta['bench_start_unix'] = time.time()
            bench = subprocess.run([
                sys.executable, str(Path(__file__).with_name('mars-network-bench.py')),
                '--address', str(a.address), '--output', str(a.output / 'tcp'),
                '--seconds', str(a.seconds), '--rounds', '1', '--iperf', a.iperf,
            ], timeout=2 * (a.seconds + 35))
            meta['bench_exit'] = bench.returncode
            meta['bench_end_unix'] = time.time()
            time.sleep(1)
            return bench.returncode
    finally:
        if capture is not None:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                try:
                    capture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture.kill()
                    capture.wait()
            meta['capture_exit'] = capture.returncode
        meta['finished_unix'] = time.time()
        (a.output / 'run.json').write_text(json.dumps(meta, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
