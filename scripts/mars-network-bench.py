#!/usr/bin/env python3
"""Bounded real-board TCP benchmark; does not boot, flash or alter networking."""
import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True, type=ipaddress.IPv4Address,
                        help='address observed in the board DHCP configuration')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=60, choices=range(1, 61), metavar='1..60')
    parser.add_argument('--rounds', type=int, default=3, choices=range(1, 21), metavar='1..20')
    parser.add_argument('--iperf', default=shutil.which('iperf3'))
    args = parser.parse_args()
    if not args.iperf:
        parser.error('iperf3 is unavailable; pass --iperf')
    # A new directory keeps evidence from previous images intact.
    args.output.mkdir(parents=True, exist_ok=False)
    version = subprocess.check_output([args.iperf, '--version'], text=True)
    summary = {'address': str(args.address), 'seconds': args.seconds,
               'rounds': args.rounds, 'iperf_version': version, 'results': [],
               'passed': False, 'physical_qualification': False}
    try:
        for number in range(1, args.rounds + 1):
            for direction, flags in [('host-to-board', []), ('board-to-host', ['-R'])]:
                path = args.output / f'{number:02}-{direction}.json'
                command = [args.iperf, '-c', str(args.address), '-t', str(args.seconds), '-J', *flags]
                result = {'round': number, 'direction': direction, 'log': path.name}
                summary['results'].append(result)
                try:
                    with path.open('x') as output:
                        process = subprocess.run(command, stdout=output, stderr=subprocess.PIPE,
                                                 text=True, timeout=args.seconds + 30)
                    result['exit_code'] = process.returncode
                    result['stderr'] = process.stderr
                    data = json.loads(path.read_text())
                    result['error'] = data.get('error')
                    received = data.get('end', {}).get('sum_received', {})
                    result['receiver_bps'] = received.get('bits_per_second')
                    result['received_bytes'] = received.get('bytes')
                    result['received_seconds'] = received.get('seconds')
                    start = data.get('start', {})
                    result['tcp_mss'] = start.get('tcp_mss_default')
                    result['test_parameters'] = start.get('test_start', {})
                    sent = data.get('end', {}).get('sum_sent', {})
                    result['sender_bps'] = sent.get('bits_per_second')
                    # Some servers do not report retransmits. Missing is not zero.
                    result['sender_retransmits'] = sent.get('retransmits')
                    if (process.returncode or result['error'] or not result['received_bytes']
                            or received.get('seconds', 0) < args.seconds * 0.9):
                        raise RuntimeError('incomplete TCP test; inspect the saved result')
                except (subprocess.TimeoutExpired, ValueError, RuntimeError) as error:
                    result['failure'] = str(error)
                    print(f'{direction}: FAIL ({error})', flush=True)
                    return 1
                print(f'{number}/{args.rounds} {direction}: '
                      f'{result["receiver_bps"] / 1_000_000:.2f} Mbps', flush=True)
                time.sleep(2)  # allow service close/rearm before the next connection
        summary['passed'] = True
        return 0
    finally:
        (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
