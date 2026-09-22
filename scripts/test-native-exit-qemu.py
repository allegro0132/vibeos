#!/usr/bin/env python3
"""Dedicated fatal native-image test. Not normal teardown or V8 acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'target') or work.exists():
        parser.error('--work must be a fresh directory under target')
    work.mkdir(parents=True)
    kernel = work / 'kernel.elf'
    shutil.copyfile(args.kernel, kernel)
    command = ['qemu-system-riscv64', '-machine', 'virt', '-m', '128M', '-smp', '4',
        '-nographic', '-bios', 'default', '-kernel', str(kernel), '-net', 'none',
        '-object', 'rng-random,id=native_rng,filename=/dev/urandom',
        '-device', 'virtio-rng-device,rng=native_rng', '-global', 'virtio-mmio.force-legacy=false']
    report = dict(command=command, passed=False,
        scope='fatal exit from protected native stack; no recovery or V8 acceptance',
        kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
        qemu_version=subprocess.check_output(['qemu-system-riscv64', '--version'], text=True).strip())
    files = ['kernel/src/native_process.rs', 'kernel/src/native_call.rs',
             'kernel/src/lib.rs', 'kernel/Cargo.toml', 'firmware/qemu-virt/Cargo.toml',
             'runtime/riscv/src/bare.rs', 'scripts/test-native-exit-qemu.py']
    report['source_sha256'] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files}
    started = time.monotonic()
    try:
        with (work / 'serial.log').open('wb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=30)
        serial = (work / 'serial.log').read_text(errors='replace')
        # QEMU 11.0.3/OpenSBI shuts down with host status 0 even when
        # SBI reset reason is SYSTEM_FAILURE. Native status lives in the log.
        checks = dict(qemu_shutdown=result.returncode == 0,
            native_exit='NATIVE FATAL EXIT status=42 scope=trusted-image recovery=none' in serial,
            prior_normal_return='NATIVE PARK PASS' in serial,
            no_return='fatal native exit returned' not in serial,
            no_panic='panicked' not in serial.lower() and 'kernel panic' not in serial.lower())
        report.update(exit_code=result.returncode, native_status=42,
            native_status_propagated_to_host=False, checks=checks, passed=all(checks.values()))
    except subprocess.TimeoutExpired:
        report['error'] = 'QEMU did not terminate within 30 seconds'
    finally:
        report['seconds'] = time.monotonic() - started
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
