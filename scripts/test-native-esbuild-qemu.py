#!/usr/bin/env python3
"""Qualify the retained native stack to WASI transform bridge on QEMU."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'target') or work.exists():
        parser.error('use a fresh work directory under target')
    work.mkdir(parents=True)
    kernel = work / 'kernel.elf'
    shutil.copyfile(args.kernel, kernel)
    command = ['qemu-system-riscv64', '-machine', 'virt', '-m', '1G', '-smp', '4',
               '-nographic', '-bios', 'default', '-kernel', str(kernel), '-net', 'none',
               '-object', 'rng-random,id=esbuild_rng,filename=/dev/urandom',
               '-device', 'virtio-rng-device,rng=esbuild_rng', '-global', 'virtio-mmio.force-legacy=false']
    inputs = [ROOT / 'services/file-store/src/lib.rs'] + list((ROOT / 'kernel/src').glob('native_*.rs')) + [
        ROOT / p for p in ['kernel/src/wasi.rs', 'kernel/src/lib.rs', 'kernel/Cargo.toml',
        'kernel/build.rs', 'firmware/qemu-virt/Cargo.toml',
        'tools/node-runtime/tests/esbuild-transform.packet', 'scripts/test-native-esbuild-qemu.py']]
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    with (work / 'serial.log').open('wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 180
        while process.poll() is None:
            serial = (work / 'serial.log').read_text(errors='replace').lower()
            if time.monotonic() >= deadline or any(s in serial for s in ('panicked', 'fatal trap', 'native fatal exit')):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                break
            time.sleep(0.1)
        code = process.returncode
    text = (work / 'serial.log').read_text(errors='replace')
    checks = dict(
        native_bridge='NATIVE ESBUILD BRIDGE transform=1 async=1 cancel=1 rejected=1 busy=1 stale=1 returned=42 parks=' in text,
        reclaimed=text.count('reclaimed=true caps=0 waiters=0') == 3,
        release_order='NATIVE ESBUILD RELEASE pending=denied terminal=allowed PASS' in text,
        no_fatal=not any(s in text.lower() for s in ('panicked', 'fatal trap', 'native fatal exit')),
        shutdown=code == 0,
        source_unchanged=all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items()))
    report = dict(passed=all(checks.values()), checks=checks, seconds=time.monotonic()-started,
                  source_sha256=hashes, kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  command=command, qemu_exit=code,
                  scope='Native retained-stack C ABI to official WASI transform; Node JS binding not yet qualified')
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
