#!/usr/bin/env python3
"""Run 100 production Node invocations and collect guest heap snapshots."""
import argparse
import hashlib
import json
import re
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
    fixtures = {'helper.mjs': ['export default value => value + 1;'],
 'cycle.cjs': ['const fs = require("fs"), id = Number(process.argv[2]); let input = "";',
               'process.stdin.setEncoding("utf8"); process.stdin.on("data", data => input += data);',
               'process.stdin.on("end", async () => {',
               'const previous = fs.existsSync("counter") ? Number(fs.readFileSync("counter","utf8")) : 0;',
               'if (previous+1 !== id || input.trim() !== "payload") throw Error("cycle sequence/stdin");',
               'fs.writeFileSync("counter", String(id)); fs.openSync("counter", "r");',
               'if (await fs.promises.readFile("counter","utf8") !== String(id)) throw Error("async file");',
               'const module = await import("./helper.mjs"); if(module.default(41)!==42) throw Error("module import");',
               'await new Promise(resolve => setTimeout(resolve,1));',
               'const buffer = Buffer.alloc(65536, id); if(buffer[65535] !== id) throw Error("buffer");',
               'console.log("NODE_CYCLE_" + "OK=" + id); });']}
    commands = ['quiet', 'mkdir @home/project']
    for name, lines in fixtures.items():
        for index, line in enumerate(lines):
            assert "'" not in line
            commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/{name}")
    for iteration in range(1, 101):
        commands += [f'@send echo payload | node --root @home/project cycle.cjs {iteration}',
                     f'@expect NODE_CYCLE_OK={iteration}']
        if iteration in (1, 10, 50, 100):
            commands += ['@send vtop --once', '@expect --: awaiting interval sample.']
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
    inputs += [ROOT / 'tools/node-runtime/libuv/vibeos-loop.c', ROOT / 'tools/node-runtime/libuv/vibeos-fs.c',
               ROOT / 'tools/node-runtime/platform/vibeos-esbuild.h']
    inputs += sorted((ROOT / 'tools/node-runtime/toolkit').glob('*.*'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '180',
        '--fail-marker', 'Returned(1)', '--fail-marker', 'panicked at', '--', *command],
        cwd=ROOT, timeout=1000)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    cycles = [int(n) for n in re.findall(r'NODE_CYCLE_OK=(\d+)', serial)]
    samples = re.findall(r'heap ([\d.]+) (B|KiB|MiB|GiB) / .*?peak ([\d.]+) (B|KiB|MiB|GiB)', serial)
    scale = dict(B=1, KiB=1024, MiB=1024**2, GiB=1024**3)
    memory = [dict(live=int(float(n)*scale[u]), peak=int(float(p)*scale[pu])) for n,u,p,pu in samples]
    late = [m['live'] for m in memory[1:]]
    checks = {'100_ordered_invocations': cycles == list(range(1,101)),
              'four_memory_samples': len(memory) == 4,
              'late_heap_spread_under_2MiB': len(late) == 3 and max(late)-min(late) <= 2*1024**2}
    checks['no_fatal'] = all(s not in serial.lower() for s in ('native fatal', 'panicked', 'fatal trap'))
    checks['qemu_exit'] = result.returncode == 0
    checks['source_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items())
    report = dict(passed=all(checks.values()), checks=checks, command=command, memory_samples_rounded=memory,
                  seconds=time.monotonic()-started,
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  source_sha256=hashes)
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
