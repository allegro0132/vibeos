#!/usr/bin/env python3
"""Verify the adapted official esbuild JavaScript API on real Node in QEMU."""
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
    head = 'const es = require("/.vibeos-tools/node_modules/esbuild");'
    fixtures = {
        'sync.cjs': [head,
            'const result = es.transformSync("const answer: number = 42", {loader:"ts", sourcemap:"external", sourcefile:"answer.ts"});',
            'if (!result.code.includes("const answer = 42;")) throw Error("bad TS");',
            'const map = JSON.parse(result.map); if (map.sources[0] !== "answer.ts" || !map.mappings) throw Error("bad map");',
            'if (!map.sourcesContent[0].includes(": number")) throw Error("missing source");',
            'console.log("ESBUILD_API_" + "SYNC=ok");'],
        'async.cjs': [head,
            'const opts = {loader:"tsx", jsxFactory:"h", jsxFragment:"Fragment", sourcemap:"external", sourcefile:"view.tsx"};',
            'es.transform("const view = <Box value={42} />", opts).then(result => {',
            'if (!result.code.includes("h(Box, { value: 42 })")) throw Error("bad TSX");',
            'if (JSON.parse(result.map).sources[0] !== "view.tsx") throw Error("bad TSX map");',
            'console.log("ESBUILD_API_" + "ASYNC=ok"); });'],
        'error.cjs': [head,
            'let found = false; try { es.transformSync("const value: = 1", {loader:"ts", sourcefile:"broken.ts"}); } catch (e) {',
            'found = e.errors.length === 1 && e.errors[0].location.file === "broken.ts" && e.errors[0].location.line === 1;',
            'console.log(e.message); } if (!found) throw Error("missing syntax diagnostic");',
            'console.log("ESBUILD_API_" + "ERROR=ok");'],
        'options.cjs': [head,
            'let found = false; try { es.transformSync("let n = 1", {notAnOption:true}); } catch (e) {',
            'found = e.errors.length === 1 && e.errors[0].text.includes("notAnOption"); }',
            'if (!found) throw Error("missing option diagnostic");',
            'let limited = false; try { es.transformSync("x".repeat(1048577)); } catch(e) { limited = e.code === "EFBIG"; }',
            'if (!limited) throw Error("missing input limit");',
            'es.transform("let n = 1", {notAnOption:true}).then(() => { throw Error("accepted option"); }, e => {',
            'if (!e.errors[0].text.includes("notAnOption")) throw Error("missing async diagnostic");',
            'console.log("ESBUILD_API_" + "OPTIONS=ok"); });'],
        'unsupported.cjs': [head,
            'let denied = false; try { es.buildSync({}); } catch (e) { denied = e.code === "ENOTSUP"; }',
            'if (!denied) throw Error("build accepted");',
            'es.context({}).then(() => { throw Error("context accepted"); }, e => {',
            'if (e.code !== "ENOTSUP") throw e; console.log("ESBUILD_API_" + "UNSUPPORTED=ok"); });'],
    }
    commands = ['quiet', 'mkdir @home/project']
    for name, lines in fixtures.items():
        for index, line in enumerate(lines):
            assert "'" not in line
            commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/{name}")
    for name in fixtures:
        marker = name.split(".")[0].upper()
        commands += [f'@send node-tool-probe --root @home/project {name}', f'@expect ESBUILD_API_{marker}=ok']
    commands += ['@send node-tool-probe --root @home/project sync.cjs', '@expect ESBUILD_API_SYNC=ok']
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
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '180', '--', *command],
        cwd=ROOT, timeout=1000)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    checks = {marker: ('ESBUILD_API_' + marker + '=ok') in serial
              for marker in ['SYNC', 'ASYNC', 'ERROR', 'OPTIONS', 'UNSUPPORTED']}
    checks['relaunch'] = serial.count('ESBUILD_API_SYNC=ok') == 2
    checks['reclaimed'] = serial.count('reclaimed=true caps=0 waiters=0') == 4
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
