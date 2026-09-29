#!/usr/bin/env python3
"""Verify native esbuild JS/Promise bindings on real Node in QEMU."""
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
    import base64
    payload = base64.b64encode((ROOT / 'tools/node-runtime/tests/esbuild-transform.packet').read_bytes()).decode()
    common = ['const bridge = globalThis[Symbol.for("vibeos.esbuild")];', 'let encoded = "";']
    common += [f'encoded += "{payload[i:i+96]}";' for i in range(0, len(payload), 96)]
    common += ['const packet = Buffer.from(encoded, "base64");',
               'function check(data) { if (!Buffer.from(data).includes(Buffer.from("const answer = 42;"))) throw Error("bad transform"); }',
               'module.exports = { bridge, packet, check };']
    head = 'const { bridge, packet, check } = require("./common.cjs");'
    fixtures = {
        'common.cjs': common,
        'sync.cjs': [head, 'check(bridge.transformSync(packet));', 'console.log("NODE_ESBUILD_" + "SYNC=ok");'],
        'async.cjs': [head, 'let ticks = 0; const clock = setInterval(() => ticks++, 10);',
            'Promise.all([bridge.transform(packet), bridge.transform(packet)]).then(results => {',
            'for (const result of results) check(result); clearInterval(clock);',
            'if (ticks < 2) throw Error("timer starved"); console.log("NODE_ESBUILD_" + "ASYNC=ok ticks=" + ticks);',
            '}).catch(error => { clearInterval(clock); throw error; });'],
        'mixed.cjs': [head, 'const pending = bridge.transform(packet); check(bridge.transformSync(packet));',
            'pending.then(data => { check(data); console.log("NODE_ESBUILD_" + "MIXED=ok"); });'],
        'idle.cjs': [head, 'Promise.all([bridge.transform(packet), bridge.transform(packet)]).then(results => {',
            'for (const result of results) check(result); console.log("NODE_ESBUILD_" + "IDLE=ok"); });'],
        'exit.cjs': [head, 'bridge.transform(packet); setTimeout(() => process.exit(7), 20);'],
        'denied.cjs': [head, 'let rejected = false; try { bridge.transformSync(packet); } catch (e) { rejected = e.message.includes("status -3"); }',
            'if (!rejected) throw Error("unexpected authority"); console.log("NODE_ESBUILD_" + "DENIED=ok");'],
    }
    commands = ['quiet', 'mkdir @home/project']
    for name, lines in fixtures.items():
        for index, line in enumerate(lines):
            assert "'" not in line
            commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/{name}")
    for name, marker in [('denied', 'DENIED'), ('sync', 'SYNC'), ('async', 'ASYNC'), ('idle', 'IDLE'), ('mixed', 'MIXED')]:
        cmd = 'node' if name == 'denied' else 'node-tool-probe'
        commands += [f'@send {cmd} --root @home/project {name}.cjs', f'@expect NODE_ESBUILD_{marker}=ok']
    commands += ['@send node-tool-probe --root @home/project exit.cjs', '@expect Returned(7)',
                 '@send node-tool-probe --root @home/project sync.cjs', '@expect NODE_ESBUILD_SYNC=ok',
                 'vtop --once']
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
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '180', '--', *command],
        cwd=ROOT, timeout=1000)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    checks = {marker: ('NODE_ESBUILD_' + marker + '=ok') in serial for marker in ['SYNC', 'ASYNC', 'IDLE', 'MIXED', 'DENIED']}
    checks['relaunch'] = serial.count('NODE_ESBUILD_SYNC=ok') == 2
    checks['exit_7'] = 'Returned(7)' in serial
    checks['reclaimed'] = serial.count('reclaimed=true caps=0 waiters=0') == 9
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
