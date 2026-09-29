#!/usr/bin/env python3
"""Verify project/tool directory boundaries through production Node and tsx commands."""
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
        'large.cjs': ['const fs = require("fs");',
            'const text = Array.from({length:4097}, (_,i) => String.fromCharCode(233+i%53)).join("");',
            'const expected = Buffer.from(text); fs.writeFileSync("large", text);',
            '(async () => {',
            'if (!(await fs.promises.readFile("large")).equals(expected)) throw Error("binary read truncated");',
            'if (await fs.promises.readFile("large", "utf8") !== text) throw Error("UTF8 read truncated");',
            'const h = await fs.promises.open("large", "r"), buffer = Buffer.alloc(7000);',
            'const part = await h.read(buffer, 0, buffer.length, 101);',
            'if (part.bytesRead !== 7000 || !buffer.equals(expected.subarray(101,7101))) throw Error("positional read");',
            'const eof = await h.read(Buffer.alloc(10000), 0, 10000, 0); if (eof.bytesRead !== 8194) throw Error("EOF count");',
            'const current = await h.read(Buffer.alloc(512), 0, 512, null);',
            'if (!current.buffer.equals(expected.subarray(0,512))) throw Error("position changed");',
            'await h.close(); console.log("TOOLKIT_BOUNDARY_" + "LARGE_READ=8194"); })();'],
        'boundary.ts': ['import fs from "node:fs";',
            'const tool = "/.vibeos-tools/node_modules/typescript/package.json";',
            'const original = fs.readFileSync(tool, "utf8");',
            'let denied = 0;',
            'function reject(action: () => void, codes = ["EACCES"]) { try { action(); } catch (e: any) {',
            'if (codes.includes(e.code)) { denied++; return; } throw e; } throw Error("authority escaped"); }',
            'if (fs.existsSync("/secret") || fs.existsSync("/secret.cjs")) throw Error("sibling visible");',
            'reject(() => fs.readFileSync("../secret"));',
            'reject(() => fs.realpathSync("../secret"), ["EACCES", "ENOENT"]);',
            'reject(() => fs.writeFileSync("../secret", "changed"));',
            'reject(() => fs.writeFileSync(tool, "changed"));',
            'reject(() => fs.openSync(tool, "r+"));',
            'reject(() => fs.unlinkSync(tool));',
            'reject(() => fs.renameSync(tool, "stolen.json"));',
            'reject(() => fs.mkdirSync("/.vibeos-tools/new-dir"));',
            'process.chdir("/.vibeos-tools/node_modules/typescript");',
            'if (process.cwd() !== "/.vibeos-tools/node_modules/typescript") throw Error("tool cwd");',
            'reject(() => fs.writeFileSync("package.json", "changed"));',
            'process.chdir("/");',
            'try { await fs.promises.writeFile(tool, "changed"); throw Error("async write admitted"); } catch (e: any) {',
            'if (e.code !== "EACCES") throw e; denied++; }',
            'const after = await fs.promises.readFile(tool, "utf8"), syncAfter = fs.readFileSync(tool, "utf8");',
            'console.log("BOUNDARY_READ lengths="+original.length+"/"+after.length+"/"+syncAfter.length+" syncEqual="+(original===syncAfter));',
            'if (after !== original) throw Error("tool differs: " + after.slice(0,48));',
            'fs.writeFileSync("allowed.txt", "yes");',
            'if (fs.readFileSync("allowed.txt", "utf8") !== "yes" || denied !== 10) throw Error("boundary checks");',
            'console.log("TOOLKIT_BOUNDARY_" + "PASS=10");'],
        'ungranted.cjs': ['const fs = require("fs");',
            'if (fs.existsSync("/.vibeos-tools/node_modules/typescript/package.json")) throw Error("ambient tool authority");',
            'fs.mkdirSync("subdir"); process.chdir("subdir");',
            'if (process.cwd() !== "/subdir") throw Error("project cwd"); fs.writeFileSync("inside", "yes"); process.chdir("/");',
            'if (fs.readFileSync("subdir/inside", "utf8") !== "yes") throw Error("relative cwd write");',
            'for (const [value, code] of [[7,"ERR_INVALID_ARG_TYPE"],["sub"+String.fromCharCode(0)+"dir","ERR_INVALID_ARG_VALUE"]]) {',
            'let denied=false; try { process.chdir(value); } catch(e) { denied=e.code===code; } if(!denied) throw Error("cwd argument"); }',
            'if (process.cwd() !== "/") throw Error("failed chdir changed cwd");',
            'console.log("TOOLKIT_BOUNDARY_" + "UNGRANTED=ok");'],
        'check-secret.cjs': ['const fs = require("fs");',
            'if (fs.readFileSync("secret", "utf8").trim() !== "original") throw Error("secret modified");',
            'console.log("TOOLKIT_BOUNDARY_" + "SECRET=unchanged");'],
    }
    commands = ['quiet', 'mkdir @home/project', 'echo original | write @home/secret']
    for name, lines in fixtures.items():
        for index, line in enumerate(lines):
            assert "'" not in line
            commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/{name}")
    commands += ['@send node --root @home/project ungranted.cjs', '@expect TOOLKIT_BOUNDARY_UNGRANTED=ok',
                 '@send node --root @home/project large.cjs', '@expect TOOLKIT_BOUNDARY_LARGE_READ=8194',
                 '@send tsx --root @home/project boundary.ts', '@expect TOOLKIT_BOUNDARY_PASS=10',
                 '@send node --root @home project/check-secret.cjs', '@expect TOOLKIT_BOUNDARY_SECRET=unchanged']
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
    checks = {marker: ('TOOLKIT_BOUNDARY_' + marker) in serial
              for marker in ['PASS=10', 'UNGRANTED=ok', 'LARGE_READ=8194', 'SECRET=unchanged']}
    checks['reclaimed'] = serial.count('WASI running') == serial.count('reclaimed=true caps=0 waiters=0') == 1
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
