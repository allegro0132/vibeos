#!/usr/bin/env python3
"""Qualify live project/tool revocation through the production Node supervisor on QEMU."""
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
        'scripts/test-node-authority-qemu.py', 'scripts/check-v8-firmware-link.py']]
    inputs += sorted((ROOT / 'tools/node-runtime/runtime').glob('node-*'))
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
        project_revoked='NODE AUTHORITY REVOKE kind=project terminal=Denied caps=0 waiters=0 space_refs=0 restart=1 PASS' in text,
        tools_revoked='NODE AUTHORITY REVOKE kind=tools terminal=Denied caps=0 waiters=0 space_refs=0 restart=1 PASS' in text,
        opened_then_revoked=text.count('opened_fds=2 readonly=denied') == 2,
        four_project_grants_reclaimed=text.count('NATIVE GRANT RECLAIM kind=project providers=0 leases=0') == 4,
        two_tool_grants_reclaimed=text.count('NATIVE GRANT RECLAIM kind=tools providers=0 leases=0') == 2,
        four_stream_registries_reclaimed=text.count('NATIVE IO RECLAIM waiters=0') == 4,
        four_page_owners_reclaimed=text.count('NATIVE PAGE RECLAIM live_bytes=0 live_allocations=0 owner_registered=0') == 4,
        no_fatal=not any(s in text.lower() for s in ('panicked', 'fatal trap', 'native fatal exit')),
        shutdown=code == 0,
        source_unchanged=all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items()))
    report = dict(passed=all(checks.values()), checks=checks, seconds=time.monotonic()-started,
                  source_sha256=hashes, kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  command=command, qemu_exit=code,
                  scope='Production native Node supervisor; explicit fixture project/tool authority revocation after file open, Denied cleanup, fresh-capability restart, CSpace destruction')
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
