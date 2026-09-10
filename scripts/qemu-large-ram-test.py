#!/usr/bin/env python3
"""Exercise the firmware-supplied four-GiB RAM hierarchy under real Sv39."""
from pathlib import Path
import argparse
import os
import re
import select
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    output = ROOT / 'target/mars-large-ram'
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(output / 'build'))
    if not args.no_build:
        with (output / 'build.log').open('wb') as log:
            subprocess.run(['cargo', 'build', '--locked', '--offline', '--release', '--features', 'mmu-large-memory'],
                           cwd=ROOT / 'firmware/qemu-virt', env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    kernel = output / 'build/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt'
    disk = output / 'block.raw'
    with disk.open('wb') as stream:
        stream.truncate(512 * 2048)
    qemu = subprocess.Popen(['qemu-system-riscv64', '-machine', 'virt', '-cpu', 'rv64', '-smp', '4', '-m', '4G',
        '-accel', 'tcg,thread=multi', '-nographic', '-bios', 'default', '-kernel', str(kernel),
        '-drive', f'if=none,id=d,format=raw,file={disk}', '-device', 'virtio-blk-device,drive=d,bus=virtio-mmio-bus.0,queue-size=8',
        '-global', 'virtio-mmio.force-legacy=false'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert qemu.stdin and qemu.stdout
    transcript = bytearray()
    def wait_for(pattern, timeout):
        start = len(transcript)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if re.search(pattern, transcript[start:]):
                return
            if not select.select([qemu.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                continue
            chunk = os.read(qemu.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError('QEMU exited before expected result')
            transcript.extend(chunk)
        raise TimeoutError(f'waiting for {pattern!r}')
    try:
        wait_for(rb'VibeOS shell ready', 45)
        qemu.stdin.write(b'quiet\n'); qemu.stdin.flush()
        wait_for(rb'vibe> ', 10)
        qemu.stdin.write(b'selftest\n'); qemu.stdin.flush()
        wait_for(rb'selftest: .*passed.*failed', 120)
        qemu.stdin.write(b'halt\n'); qemu.stdin.flush()
        qemu.wait(timeout=10)
        if not re.search(rb'selftest: 393 passed, 0 failed', transcript):
            raise AssertionError('full on-target selftest did not pass')
        print('PASS: four GiB, four harts, 2 MiB high RAM, 393 on-target checks')
    finally:
        if qemu.poll() is None:
            qemu.terminate()
            try: qemu.wait(timeout=3)
            except subprocess.TimeoutExpired: qemu.kill(); qemu.wait()
        (output / 'serial.log').write_bytes(transcript)

if __name__ == '__main__':
    main()
