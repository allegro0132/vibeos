#!/usr/bin/env python3
"""Measure the upstream pthread CoreMark module on a physical Duo over SSH.

Requires the --wasmtime-benchmark image and an already authorized client key.
Raw outputs and UART reclamation evidence are retained for every invocation.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import subprocess
import termios
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coremark_threads', ROOT / 'scripts/benchmark-coremark-threads.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', required=True, type=Path)
    p.add_argument('--known-hosts', required=True, type=Path)
    p.add_argument('--identity', type=Path, default=Path.home()/'.ssh/id_ed25519')
    p.add_argument('--host', default='192.168.77.10')
    p.add_argument('--bind', default='192.168.77.1')
    p.add_argument('--serial', default='/dev/cu.usbmodem54340134951')
    p.add_argument('--module', type=Path, default=ROOT/'target/coremark-wasi/coremark-threads-monotonic.wasm')
    p.add_argument('--samples', type=int, default=3)
    p.add_argument('--seconds', type=float, default=20)
    p.add_argument('--workers', nargs='+', type=int, choices=[1, 2, 3], default=[1, 2, 3])
    args = p.parse_args()
    if args.seconds < 15 or args.samples < 1 or 1 not in args.workers:
        p.error('require >=15 seconds, >=1 sample and M1')
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    data = args.module.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    bench.save(work/'metadata.json', dict(platform='physical-milkv-duo', harts=1,
        module_sha256=sha, clock='WASI CLOCK_MONOTONIC via explicit POSIX timer adapter',
        total_fuel_per_store=100_000_000_000,
        quantum_fuel=10_000, workers=args.workers, samples=args.samples,
        target_seconds=args.seconds, revision=subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()))
    ssh = ['ssh', '-b', args.bind, '-i', str(args.identity), '-o', 'IdentitiesOnly=yes',
           '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10',
           '-o', 'ServerAliveCountMax=6', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile='+str(args.known_hosts.resolve()), 'vibe@'+args.host]
    fd = os.open(args.serial, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    attrs[0] = attrs[1] = attrs[3] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[4] = attrs[5] = termios.B115200
    attrs[6][termios.VMIN] = attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    stopped = threading.Event()
    uart = work/'serial.log'
    uart.touch()

    def watch():
        with uart.open('ab', buffering=0) as out:
            while not stopped.is_set():
                if select.select([fd], [], [], .1)[0]:
                    out.write(os.read(fd, 65536))

    thread = threading.Thread(target=watch)
    thread.start()

    def call(name, command, stdin=b''):
        result = subprocess.run(ssh+[shlex.join(command)], input=stdin,
                                capture_output=True, timeout=max(180, args.seconds*6))
        (work/(name+'.stdout')).write_bytes(result.stdout)
        (work/(name+'.stderr')).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(f'{name}: SSH exit {result.returncode}; inspect raw logs (124 means fuel exhaustion)')
        return result.stdout.decode()

    def run(name, workers, seeds, iterations):
        start = uart.stat().st_size
        text = call(name, ['wasm-run', 'duo-coremark.wasm', f'M{workers}',
                          *seeds.split(), str(iterations)])
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            tail = uart.read_bytes()[start:].decode(errors='replace')
            if 'reclaimed=true caps=0 waiters=0' in tail:
                break
            time.sleep(.1)
        else:
            raise RuntimeError(f'{name}: missing clean reclamation evidence; ensure UART logging is enabled')
        if 'reclaimed=false' in tail:
            raise RuntimeError(f'{name}: reclamation failed')
        return text

    try:
        call('upload', ['wasm-upload', 'duo-coremark.wasm', str(len(data)), sha], data)
        args.platform = 'physical-milkv-duo'
        args.icount_iterations = None
        bench.measure(run, work, args)
    finally:
        stopped.set()
        thread.join()
        os.close(fd)


if __name__ == '__main__':
    main()
