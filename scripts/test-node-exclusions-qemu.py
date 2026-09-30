#!/usr/bin/env python3
"""Verify explicit first-release exclusions on the production Node image."""
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
    fixture = [
        'const assert = require("assert/strict"), fs = require("fs");',
        'function denied(name, run, code) {',
        'let caught; try { run(); } catch(e) { caught=e; }',
        'assert.equal(caught?.code, code, name); console.log("NODE_EXCLUDED_"+name+"="+code); }',
        'denied("WORKER",()=>new (require("worker_threads").Worker)("1",{eval:true}),"ERR_VIBEOS_UNSUPPORTED");',
        'denied("SPAWN",()=>require("child_process").spawn("node",["-e","1"]),"ERR_VIBEOS_UNSUPPORTED");',
        'denied("SPAWN_SYNC",()=>{throw require("child_process").spawnSync("node",["-e","1"]).error},"ENOTSUP");',
        'denied("TCP",()=>require("net").createServer().listen(0),"ERR_VIBEOS_UNSUPPORTED");',
        'denied("UDP",()=>require("dgram").createSocket("udp4"),"ERR_VIBEOS_UNSUPPORTED");',
        'denied("SIGNAL",()=>process.on("SIGUSR1",()=>{}),"ERR_VIBEOS_UNSUPPORTED");',
        'fs.writeFileSync("addon.node","not a native image");',
        'denied("ADDON",()=>require("./addon.node"),"ERR_DLOPEN_DISABLED");',
        'denied("WATCH",()=>fs.watch("addon.node",()=>{}),"ENOTSUP");',
        'denied("WATCH_FILE",()=>fs.watchFile("addon.node",()=>{}),"ERR_VIBEOS_UNSUPPORTED");',
        'assert.equal(typeof WebAssembly,"undefined"); console.log("NODE_EXCLUDED_"+"WASM=unavailable");',
        'console.log("NODE_EXCLUDED_"+"DONE");',
    ]
    commands = ['quiet', 'mkdir @home/project']
    for index, line in enumerate(fixture):
        assert "'" not in line
        commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/exclusions.cjs")
    commands += ['@send node --root @home/project exclusions.cjs', '@expect NODE_EXCLUDED_DONE', '@expect vsh> ',
                 '@send tsx --root @home/project watch exclusions.cjs', '@expect watch and subprocess modes are unavailable',
                 '@expect Unavailable', '@expect vsh> ',
                 '''@send node --root @home/project -e "console.log('NODE_EXCLUDED_'+'RESTART')"''', '@expect NODE_EXCLUDED_RESTART', '@expect vsh> ']
    assert all(len(line.encode()) < 240 for line in commands)
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
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--fail-marker', 'Returned(1)', '--', *command],
        cwd=ROOT, timeout=120)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    markers = ['WORKER=ERR_VIBEOS_UNSUPPORTED', 'SPAWN=ERR_VIBEOS_UNSUPPORTED', 'SPAWN_SYNC=ENOTSUP',
               'TCP=ERR_VIBEOS_UNSUPPORTED', 'UDP=ERR_VIBEOS_UNSUPPORTED', 'SIGNAL=ERR_VIBEOS_UNSUPPORTED',
               'ADDON=ERR_DLOPEN_DISABLED', 'WATCH=ENOTSUP', 'WATCH_FILE=ERR_VIBEOS_UNSUPPORTED',
               'WASM=unavailable', 'DONE', 'RESTART']
    checks = {marker: ('NODE_EXCLUDED_' + marker) in serial for marker in markers}
    checks['tsx_watch_rejected'] = 'watch and subprocess modes are unavailable' in serial and ': Unavailable' in serial
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
