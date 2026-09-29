#!/usr/bin/env python3
"""Boot the native Node VSH image and execute capability-rooted shell commands."""
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
    commands = [
        'quiet',
        'mkdir @home/project',
        'echo "module.exports = 42" | write @home/project/dep.cjs',
        '''echo "console.log('VSH_NODE_' + 'FILE=' + require('./dep.cjs'))" | write @home/project/main.cjs''',
        '''node --root @home/project -e "console.log('VSH_NODE_' + 'EVAL=' + (1 + 2))"''',
        'node --root @home/project main.cjs',
        '''echo stream-input | node --root @home/project -e "process.stdin.setEncoding('utf8'); let s=''; process.stdin.on('data', x => s += x); process.stdin.on('end', () => console.log('VSH_NODE_' + 'STDIN=' + s.trim()))"''',
        '''node --root @home/project -e "const fs=require('fs'); fs.writeFileSync('out.txt','saved'); console.log('VSH_NODE_' + 'FS=' + fs.readFileSync('out.txt','utf8'))"''',
        '''node --root @home/project -e "setTimeout(() => console.log('VSH_NODE_' + 'TIMER=done'), 10)"''',
        'echo "export default 99" | write @home/project/dep.mjs',
        '''node --root @home/project -e "import('./dep.mjs').then(m => console.log('VSH_NODE_' + 'ESM=' + m.default))"''',
        '''node --root @home/project -e "console.log('VSH_NODE_' + 'REDIRECT=console')" > @console''',
        '''node --root @home/project -e "process.exit(7)"''',
        '''if node --root @home/project -e "process.exit(7)"; then node --root @home/project -e "console.log('VSH_NODE_' + 'EXIT=bad')"; else node --root @home/project -e "console.log('VSH_NODE_' + 'EXIT=nonzero')"; fi''',
        '''node --root @home/project -e "throw new Error('VSH_NODE_' + 'EXPECTED_ERROR')"''',
        '''@send node --root @home/project -e "for(let once=true;;){if(once){console.log('VSH_NODE_' + 'CPU_READY');once=false}}"''',
        '@expect VSH_NODE_CPU_READY',
        '@ctrl-c',
        '''node --root @home/project -e "console.log('VSH_NODE_' + 'AFTER_CPU=ok')"''',
        '''@send node --root @home/project -e "setTimeout(() => console.log('VSH_NODE_' + 'IDLE_MISSED'),60000); console.log('VSH_NODE_' + 'IDLE_READY')"''',
        '@expect VSH_NODE_IDLE_READY',
        '@ctrl-c',
        '''node --root @home/project -e "console.log('VSH_NODE_' + 'AFTER_IDLE=ok')"''',
    ]
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
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--', *command],
        cwd=ROOT, timeout=120)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    markers = ['EVAL=3', 'FILE=42', 'STDIN=stream-input', 'FS=saved', 'TIMER=done',
               'ESM=99', 'REDIRECT=console', 'EXIT=nonzero', 'CPU_READY',
               'AFTER_CPU=ok', 'IDLE_READY', 'AFTER_IDLE=ok']
    checks = {marker: ('VSH_NODE_' + marker) in serial for marker in markers}
    checks['no_fatal'] = all(s not in serial.lower() for s in ('native fatal', 'panicked', 'fatal trap'))
    checks['no_auto_gate'] = 'V8 GATE native_entry' not in serial
    checks['uncaught_error'] = 'Error: VSH_NODE_EXPECTED_ERROR' in serial
    checks['exit_status_7'] = ': Returned(7)' in serial
    checks['error_source_location'] = 'at [eval]:1:7' in serial
    checks['idle_interrupted'] = 'VSH_NODE_IDLE_MISSED' not in serial
    checks['qemu_exit'] = result.returncode == 0
    inputs = [Path(__file__), ROOT / 'scripts/qemu-vsh-driver.py',
              ROOT / 'kernel/src/vsh_platform.rs', ROOT / 'kernel/Cargo.toml',
              ROOT / 'services/wasi-command/src/lib.rs', ROOT / 'components/vsh/src/engine.rs']
    inputs += sorted((ROOT / 'kernel/src').glob('native_*.rs'))
    report = dict(passed=all(checks.values()), checks=checks, command=command,
                  seconds=time.monotonic()-started,
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs})
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
