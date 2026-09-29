#!/usr/bin/env python3
"""Execute official tsc in the guest, then inspect and run guest-emitted files."""
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
        parser.error('--work must be a fresh directory under target')
    work.mkdir(parents=True)
    kernel = work / 'kernel.elf'
    shutil.copyfile(args.kernel, kernel)
    disk = work / 'project.raw'
    with disk.open('wb') as f:
        f.truncate(128 * 1024 * 1024)
    commands = [
        'quiet',
        'mkdir @home/ts-project',
        '''echo '{"compilerOptions":{"target":"ES2020","module":"commonjs","strict":true,"declaration":true,"outDir":"dist"},"include":["*.ts"]}' | write @home/ts-project/tsconfig.json''',
        '''echo 'export const answer: number = 42;' | write @home/ts-project/dep.ts''',
        '''echo "import { answer } from './dep'; export const result: number = answer + 1;" | write @home/ts-project/main.ts''',
        '@send tsc --root @home/ts-project --version',
        '@expect Version 5.9.3',
        '@send if tsc --root @home/ts-project -p tsconfig.json --noEmit; then node --root @home/ts-project check.cjs; else node --root @home/ts-project check-fail.cjs; fi',
        '@expect TSC_GUEST_CHECK=',
        '@send if tsc --root @home/ts-project -p tsconfig.json; then node --root @home/ts-project emit.cjs; else node --root @home/ts-project emit-fail.cjs; fi',
        '@expect TSC_GUEST_EMIT=',
        '''echo 'export const bad: number = "wrong";' | write @home/ts-project/bad.ts''',
        '@send if tsc --root @home/ts-project -p tsconfig.json --noEmit; then node --root @home/ts-project diag-fail.cjs; else node --root @home/ts-project diag.cjs; fi',
        '@expect TSC_GUEST_DIAGNOSTIC=',
    ]
    helpers = {
        'check.cjs': "if(require('fs').existsSync('dist')) throw Error('unexpected emit'); console.log('TSC_GUEST_' + 'CHECK=ok')",
        'check-fail.cjs': "console.log('TSC_GUEST_' + 'CHECK=failed')",
        'emit.cjs': "if(!require('fs').readFileSync('dist/main.d.ts','utf8').includes('result: number')) throw Error('declaration'); console.log('TSC_GUEST_' + 'EMIT=' + require('./dist/main.js').result)",
        'emit-fail.cjs': "console.log('TSC_GUEST_' + 'EMIT=failed')",
        'diag.cjs': "console.log('TSC_GUEST_' + 'DIAGNOSTIC=nonzero')",
        'diag-fail.cjs': "console.log('TSC_GUEST_' + 'DIAGNOSTIC=missing')",
    }
    commands[2:2] = [f'echo "{source}" | write @home/ts-project/{name}' for name, source in helpers.items()]
    # The UART's bounded receive ring must not be overrun by a single burst.
    assert all(len(line.encode('utf-8')) < 240 for line in commands)
    case = work / 'commands.in'
    case.write_text('\n@sleep 0.3\n'.join(commands) + '\n@sleep 1\n@quit\n')
    command = ['qemu-system-riscv64', '-machine', 'virt', '-m', '1G', '-smp', '4',
        '-nographic', '-bios', 'default', '-kernel', str(kernel), '-net', 'none',
        '-object', 'rng-random,id=tool_rng,filename=/dev/urandom',
        '-device', 'virtio-rng-device,rng=tool_rng',
        '-drive', f'if=none,id=project,format=raw,file={disk},cache=writeback',
        '-device', 'virtio-blk-device,drive=project,queue-size=8',
        '-global', 'virtio-mmio.force-legacy=false']
    inputs = [Path(__file__), ROOT / 'scripts/qemu-vsh-driver.py',
              ROOT / 'kernel/src/vsh_platform.rs', ROOT / 'kernel/Cargo.toml',
              ROOT / 'kernel/build.rs', ROOT / 'tools/node-runtime/sources.lock.json',
              ROOT / 'tools/node-runtime/toolkit.lock.json']
    inputs += sorted((ROOT / 'kernel/src').glob('native_*.rs'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '240',
        '--', *command], cwd=ROOT, timeout=1000)
    serial = (work / 'serial.log').read_text(errors='replace')
    checks = {marker: marker in serial for marker in [
        'Version 5.9.3', 'TSC_GUEST_CHECK=ok', 'TSC_GUEST_EMIT=43',
        'TSC_GUEST_DIAGNOSTIC=nonzero', 'error TS2322', 'bad.ts(1,14)']}
    checks['no_fatal'] = not any(s in serial.lower() for s in ('native fatal', 'panicked', 'fatal trap'))
    checks['driver_success'] = result.returncode == 0
    checks['source_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items())
    report = dict(passed=all(checks.values()), checks=checks, command=command,
                  seconds=time.monotonic()-started, source_sha256=hashes,
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest())
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
