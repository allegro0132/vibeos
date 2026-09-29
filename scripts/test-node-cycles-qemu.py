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
    parser.add_argument('--lifecycle-audit', action='store_true',
                        help='require exact file, TLS and page-owner teardown records')
    parser.add_argument('--eval-entrypoint', action='store_true',
                        help='run the same 100 workloads through Node -e and its cppgc wrappers')
    parser.add_argument('--uncaught-error', action='store_true',
                        help='end every workload with an uncaught error and verify cleanup')
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
 'cycle.cjs': ['const fs = require("fs"), id = Number(process.argv[process.argv.length-1]); let input = "";',
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
    if args.uncaught_error:
        fixtures['cycle.cjs'][-1] = ('console.log("NODE_CYCLE_" + "OK=" + id); '
                                    'throw Error("CYCLE_FAILURE_" + id); });')
    commands = ['quiet', 'mkdir @home/project']
    for name, lines in fixtures.items():
        for index, line in enumerate(lines):
            assert "'" not in line
            commands.append(f"echo '{line}' | write {'--append ' if index else ''}@home/project/{name}")
    for iteration in range(1, 101):
        entrypoint = '''-e 'require("./cycle.cjs")' ''' if args.eval_entrypoint else 'cycle.cjs '
        commands += [f'@send echo payload | node --root @home/project {entrypoint}{iteration}',
                     f'@expect NODE_CYCLE_OK={iteration}']
        if args.lifecycle_audit:
            commands += ['@expect NATIVE IO RECLAIM waiters=0']
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
    fail_markers = ['--fail-marker', 'panicked at']
    if not args.uncaught_error:
        fail_markers += ['--fail-marker', 'Returned(1)']
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '180',
        *fail_markers, '--', *command],
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
    if args.uncaught_error:
        failures = [int(n) for n in re.findall(r'Error: CYCLE_FAILURE_(\d+)', serial)]
        checks['100_ordered_uncaught_errors'] = failures == list(range(1, 101))
        checks['100_failure_exit_statuses'] = serial.count('Returned(1)') == 100
    audit = None
    if args.lifecycle_audit:
        tls = re.findall(r'NATIVE TLS RECLAIM id=(\d+) released_slots=(\d+) slots=0 destructors=0 waiters=0', serial)
        files = serial.count('NATIVE FILE RECLAIM descriptors=0 reads=0 mutations=0')
        pages = serial.count('NATIVE PAGE RECLAIM live_bytes=0 live_allocations=0 owner_registered=0')
        grants = serial.count('NATIVE GRANT RECLAIM kind=project providers=0 leases=0')
        streams = serial.count('NATIVE IO RECLAIM waiters=0')
        events = re.findall(r'NODE_CYCLE_OK=\d+|NATIVE (?:TLS|FILE|PAGE|GRANT|IO) RECLAIM', serial)
        expected = [event for i in range(1, 101) for event in
                    (f'NODE_CYCLE_OK={i}', 'NATIVE TLS RECLAIM', 'NATIVE FILE RECLAIM', 'NATIVE PAGE RECLAIM', 'NATIVE GRANT RECLAIM', 'NATIVE IO RECLAIM')]
        checks['ordered_teardown_for_every_cycle'] = events == expected
        checks['100_distinct_tls_owners'] = len(tls) == 100 and len({i for i, _ in tls}) == 100
        sync = [dict(id=int(i), handles=int(n)) for i, n in re.findall(
            r'NATIVE SYNC SNAPSHOT id=(\d+) handles=(\d+) external_refs=0 waiters=0', serial)]
        checks['100_idle_sync_snapshots'] = len(sync) == 100 and [s['id'] for s in sync] == [int(i) for i, _ in tls]
        checks['sync_handles_stable_after_10'] = len(sync) == 100 and len({s['handles'] for s in sync[10:]}) == 1
        checks['100_file_tables_reclaimed'] = files == 100
        checks['100_page_owners_reclaimed'] = pages == 100
        checks['100_project_authorities_reclaimed'] = grants == 100
        checks['100_stream_waiter_registries_reclaimed'] = streams == 100
        libc = [dict(id=int(i), arena=int(a), live=int(l), free=int(f), free_chunks=int(c),
                     cached_blocks=int(cb), cached_bytes=int(cbytes), noncache_live=int(l)-int(cbytes))
                for i,a,l,f,c,cb,cbytes in re.findall(r'NATIVE LIBC SNAPSHOT id=(\d+) arena=(\d+) live=(\d+) free=(\d+) free_chunks=(\d+) cached_blocks=(\d+) cached_bytes=(\d+)', serial)]
        checks['100_libc_snapshots'] = len(libc) == 100 and [s['id'] for s in libc] == [int(i) for i,_ in tls]
        checks['libc_accounting_consistent'] = bool(libc) and all(s['arena'] == s['live'] + s['free'] and 0 <= s['cached_bytes'] <= s['live'] for s in libc)
        # Warm-up may install process-wide caches. Require the remaining 90
        # identical workloads to have exactly the same non-cache byte count.
        # Only physically enumerated, unused newlib bigint free-list chunks
        # are excluded; this is not an allowed drift or rounded threshold.
        checks['libc_noncache_live_bytes_stable_after_10'] = len(libc) == 100 and len({s['noncache_live'] for s in libc[10:]}) == 1
        audit = dict(tls=[dict(id=int(i), released_slots=int(n)) for i, n in tls],
                     synchronization=sync,
                     file_tables=files, page_owners=pages, project_authorities=grants,
                     stream_registries=streams, libc=libc)
    checks['no_fatal'] = all(s not in serial.lower() for s in ('native fatal', 'panicked', 'fatal trap'))
    checks['qemu_exit'] = result.returncode == 0
    checks['source_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items())
    report = dict(passed=all(checks.values()), checks=checks, command=command, memory_samples_rounded=memory,
                  entrypoint='eval' if args.eval_entrypoint else 'file',
                  uncaught_error=args.uncaught_error,
                  lifecycle_audit=audit,
                  seconds=time.monotonic()-started,
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  source_sha256=hashes)
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
