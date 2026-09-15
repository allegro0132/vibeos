#!/usr/bin/env python3
"""Bounded serial/iperf measurements; no flashing or network configuration."""
import argparse
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import termios
import time

spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('mars-cpu-residency.py'))
residency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(residency)


class SerialTimeout(TimeoutError):
    def __init__(self, command, response):
        super().__init__('serial command did not complete: ' + command)
        self.response = bytes(response)


def command(fd, text):
    termios.tcflush(fd, termios.TCIFLUSH)
    os.write(fd, text.encode() + b'\r')
    result = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if select.select([fd], [], [], 0.2)[0]:
            part = os.read(fd, 65536)
            if not part:
                raise RuntimeError('serial disconnected')
            result.extend(part)
            if len(result) > 1024 * 1024:
                raise RuntimeError('unexpected serial output volume')
            if b'vibe> ' in result and (text != 'nidle' or b'NIDLE_END' in result):
                return result.decode(errors='replace')
    raise SerialTimeout(text, result)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--address', required=True, type=ipaddress.IPv4Address)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--seconds', type=int, default=20, choices=range(1, 61))
    p.add_argument('--idle-seconds', type=int, default=10, choices=range(1, 31))
    p.add_argument('--rounds', type=int, default=2, choices=range(1, 21))
    p.add_argument('--direction', choices=['rx', 'tx', 'both'], default='both')
    p.add_argument('--driver-stage-stats', action='store_true', help='Capture sampled driver phase counters')
    p.add_argument('--tx-wait-stats', action='store_true', help='Capture opt-in TX turn counters outside residency snapshots')
    p.add_argument('--rate', help='Optional host-to-board rate, e.g. 300M; requires --direction rx')
    p.add_argument('--iperf', default=shutil.which('iperf3'))
    a = p.parse_args()
    if not a.iperf:
        p.error('iperf3 is unavailable')
    if a.rate and (a.direction != 'rx' or not re.fullmatch(r'\d+(?:\.\d+)?[KMG]?', a.rate)):
        p.error('rate must be a positive iperf bitrate and direction must be rx')
    if a.rate and float(a.rate.rstrip('KMG')) <= 0:
        p.error('rate must be positive')
    a.output.mkdir(parents=True, exist_ok=False)
    summary = dict(address=str(a.address), serial=a.serial, rate=a.rate,
                   iperf_version=subprocess.check_output([a.iperf, '--version'], text=True),
                   passed=False, physical_qualification=False, results=[])
    fd = os.open(a.serial, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    saved = termios.tcgetattr(fd)
    try:
        attrs = copy.deepcopy(saved)
        attrs[:6] = [0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL, 0, termios.B115200, termios.B115200]
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        (a.output / 'quiet.log').write_text(command(fd, 'quiet'))
        directions = ['rx', 'tx'] if a.direction == 'both' else [a.direction]
        jobs = [('idle', a.idle_seconds)] + [(f'{i:02}-{d}', a.seconds) for i in range(1, a.rounds + 1) for d in directions]
        for name, seconds in jobs:
            if a.driver_stage_stats:
                (a.output / (name + '-stage-before.log')).write_text(command(fd, 'ndrvstage'))
            if a.tx_wait_stats:
                (a.output / (name + '-txwait-before.log')).write_text(command(fd, 'ntxwait'))
            before = command(fd, 'nidle')
            residency.parse(before)  # Fail before traffic if diagnostics are absent.
            (a.output / (name + '-before.log')).write_text(before)
            received = None
            if name == 'idle':
                time.sleep(seconds)
            else:
                args = [a.iperf, '-c', str(a.address), '-t', str(seconds), '-J']
                if name.endswith('tx'):
                    args += ['-R']
                if a.rate:
                    args += ['-b', a.rate]
                with (a.output / (name + '-iperf.json')).open('x') as out:
                    proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, text=True, timeout=seconds + 30)
                (a.output / (name + '-stderr.log')).write_text(proc.stderr)
                data = json.loads((a.output / (name + '-iperf.json')).read_text())
                received = data.get('end', {}).get('sum_received', {})
                if proc.returncode or data.get('error') or received.get('seconds', 0) < seconds * 0.9 or not received.get('bytes'):
                    raise RuntimeError('incomplete iperf test: ' + name)
            after = command(fd, 'nidle')
            if a.driver_stage_stats:
                (a.output / (name + '-stage-after.log')).write_text(command(fd, 'ndrvstage'))
            if a.tx_wait_stats:
                (a.output / (name + '-txwait-after.log')).write_text(command(fd, 'ntxwait'))
            (a.output / (name + '-after.log')).write_text(after)
            result = residency.compare(before, after)
            result['name'] = name
            result['received'] = received
            if received:
                result['active_core_seconds_per_GiB'] = result['total_active_core_seconds'] / (received['bytes'] / 2**30)
            (a.output / (name + '-cpu.json')).write_text(json.dumps(result, indent=2) + '\n')
            summary['results'].append(result)
            print(name, 'Mbps=', round(received['bits_per_second'] / 1e6, 2) if received else None,
                  'active%=', [round(h['active_percent'], 2) for h in result['harts']], flush=True)
            time.sleep(2)
        summary['passed'] = True
    except SerialTimeout as error:
        (a.output / 'serial-timeout.log').write_bytes(error.response)
        raise
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, saved)
        os.close(fd)
        (a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
