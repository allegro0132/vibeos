#!/usr/bin/env python3
"""Verify upstream-adapted tsx via the production VSH command in QEMU."""
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
    shutil.copy2(args.kernel, kernel)
    disk = work / 'project.raw'
    with disk.open('wb') as f:
        f.truncate(128 * 1024 * 1024)
    fixtures = {
        'package.json': ['{"type":"module"}'],
        'tsconfig.json': ['{"compilerOptions":{"jsx":"react","jsxFactory":"h","jsxFragmentFactory":"Fragment","target":"ES2022"}}'],
        'lib.cts': ['export const value: number = 42;'],
        'main.cts': ['import { value } from "./lib.cts";',
            'if (value + 1 !== 43) throw Error("CJS import"); console.log("TSX_TARGET_" + "CJS=43");'],
        'esm-lib.ts': ['export const value: number = 17;'],
        'main.ts': ['import { value } from "./esm-lib.js";',
            'const module = await import("./dynamic.ts");',
            'if (value + module.value !== 42) throw Error("ESM import"); console.log("TSX_TARGET_" + "ESM=42");'],
        'dynamic.ts': ['export const value: number = 25;'],
        'view.tsx': ['function h(tag: string, props: any, ...children: any[]) { return {tag, children}; }',
            'const view = <box>{42}</box>;',
            'if (view.tag !== "box" || view.children[0] !== 42) throw Error("custom JSX factory");',
            'console.log("TSX_TARGET_" + "JSX=42");'],
        'error.ts': ['function fail(): never {', 'throw new Error("TSX_MAPPED_ERROR");', '}', 'fail();'],
        'node_modules/offline/package.json': ['{"name":"offline","main":"index.cjs"}'],
        'node_modules/offline/index.cjs': ['module.exports = { value: 9 };'],
        'offline.ts': ['import pkg from "offline";',
            'if (pkg.value !== 9) throw Error("offline package"); console.log("TSX_TARGET_" + "OFFLINE=9");'],
    }
    commands = ['quiet', 'mkdir @home/project', 'mkdir @home/project/node_modules', 'mkdir @home/project/node_modules/offline']
    for name, lines in fixtures.items():
        for index, line in enumerate(lines):
            assert "'" not in line
            commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/{name}")
    for name, marker in [('main.cts', 'CJS=43'), ('main.ts', 'ESM=42'), ('view.tsx', 'JSX=42'), ('offline.ts', 'OFFLINE=9')]:
        commands += [f'@send tsx --root @home/project {name}', f'@expect TSX_TARGET_{marker}']
    commands += ['@send tsx --root @home/project error.ts', '@expect /error.ts:2:', '@expect Returned(1)',
                 '@send tsx --root @home/project main.cts', '@expect TSX_TARGET_CJS=43']
    assert all(len(line.encode()) < 240 for line in commands)
    # The legacy console redraws prompts while delivering output. Pause after
    # each command so redraws cannot cause the driver to quit a live command;
    # success below is based on actual distinct output, not prompt matching.
    case = work / 'commands.in'
    case.write_text('\n@sleep 0.3\n'.join(commands) + '\n@sleep 1\n@quit\n')
    command = ['qemu-system-riscv64', '-machine', 'virt', '-m', '1G', '-smp', '4',
        '-nographic', '-bios', 'default', '-kernel', str(kernel), '-net', 'none',
        '-object', 'rng-random,id=node_rng,filename=/dev/urandom',
        '-device', 'virtio-rng-device,rng=node_rng',
        '-drive', f'if=none,id=project,format=raw,file={disk},cache=writeback',
        '-device', 'virtio-blk-device,drive=project,queue-size=8',
        '-global', 'virtio-mmio.force-legacy=false']
    inputs = [ROOT / 'services/file-store/src/lib.rs'] + [Path(__file__), ROOT / 'scripts/qemu-vsh-driver.py',
              ROOT / 'kernel/src/vsh_platform.rs', ROOT / 'kernel/Cargo.toml',
              ROOT / 'services/wasi-command/src/lib.rs', ROOT / 'components/vsh/src/engine.rs']
    inputs += sorted((ROOT / 'kernel/src').glob('native_*.rs'))
    inputs += sorted((ROOT / 'tools/node-runtime/runtime').glob('node-*'))
    inputs += [ROOT / 'tools/node-runtime/libuv/vibeos-loop.c',
               ROOT / 'tools/node-runtime/platform/vibeos-esbuild.h']
    inputs += sorted((ROOT / 'tools/node-runtime/toolkit').glob('*.*'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '180',
        '--fail-marker', 'Returned(1)', '--fail-marker', 'panicked at', '--', *command],
        cwd=ROOT, timeout=1000)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    checks = {marker: ('TSX_TARGET_' + marker) in serial
              for marker in ['CJS=43', 'ESM=42', 'JSX=42', 'OFFLINE=9']}
    checks['relaunch'] = serial.count('TSX_TARGET_CJS=43') == 2
    checks['mapped_error'] = '/error.ts:2:' in serial and 'Returned(1)' in serial
    checks['reclaimed'] = serial.count('WASI running') == serial.count('reclaimed=true caps=0 waiters=0') == 10
    checks['no_fatal'] = all(s not in serial.lower() for s in ('native fatal', 'panicked', 'fatal trap'))
    checks['qemu_exit'] = result.returncode == 0
    checks['source_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items())
    report = dict(passed=all(checks.values()), checks=checks, command=command,
                  seconds=time.monotonic()-started,
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  source_sha256=hashes)
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
