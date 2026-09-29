#!/usr/bin/env python3
"""Run target-only real V8/libuv or preliminary Node embedding gates."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--uv-loop', action='store_true', help='require the libuv timer/async prerequisite')
    parser.add_argument('--node', action='store_true', help='require actual Node embedding markers, not V8-only markers')
    parser.add_argument('--node-exit-code', type=int, choices=range(256), default=0, metavar='0..255', help='expected Node/native return code')
    parser.add_argument('--node-explicit-exit', action='store_true', help='require active process.exit path')
    parser.add_argument('--node-cancel', action='store_true', help='test same-hart infinite-loop cancellation')
    parser.add_argument('--node-main', action='store_true', help='use upstream Node main-module startup from project file')
    parser.add_argument('--node-revoke', action='store_true', help='revoke project parent authority after normal project checks')
    parser.add_argument('--node-repeat', type=int, choices=range(1,101), default=1, metavar='1..100')
    parser.add_argument('--node-eval', action='store_true', help='require upstream eval bootstrap marker')
    parser.add_argument('--node-idle-cancel', action='store_true', help='cancel a native event loop parked on a 60-second timer')
    args = parser.parse_args()
    if args.node_idle_cancel and (not args.node_eval or args.node_exit_code != 130 or args.node_cancel or args.node_revoke or args.node_explicit_exit):
        parser.error('--node-idle-cancel requires --node-eval --node-exit-code 130 and excludes other exit fixtures')
    if args.node_eval and (not args.node or args.node_main):
        parser.error('--node-eval requires --node and excludes --node-main')
    if args.node_repeat != 1 and (not args.node or args.node_exit_code or args.node_cancel or args.node_explicit_exit or args.node_revoke):
        parser.error('--node-repeat requires ordinary exit-0 Node mode')
    if args.node_revoke and (not args.node or args.node_cancel or args.node_explicit_exit):
        parser.error('--node-revoke requires --node and excludes cancellation/explicit exit')
    if args.node_main and not args.node:
        parser.error('--node-main requires --node')
    if args.node_cancel and (not args.node or args.node_explicit_exit):
        parser.error('--node-cancel requires --node and excludes --node-explicit-exit')
    if (args.node_exit_code or args.node_explicit_exit) and not args.node:
        parser.error('--node-exit-code and --node-explicit-exit require --node')
    if args.node and args.uv_loop:
        parser.error('--node and --uv-loop select different gate images')
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'target') or work.exists():
        parser.error('--work must be a fresh directory under target')
    work.mkdir(parents=True)
    kernel = work / 'kernel.elf'
    shutil.copyfile(args.kernel, kernel)
    tool = ROOT / 'target/node-runtime/toolchain/xpack-riscv-none-elf-gcc-14.2.0-3/bin/riscv-none-elf-nm'
    symbols = subprocess.check_output([str(tool), '-n', str(kernel)], text=True)
    (work / 'symbols.txt').write_text(symbols)
    if 'FLAG_PROBE' in symbols or not re.search(r'\b[tT] vibeos_v8_smoke$', symbols, re.M):
        parser.error('kernel is not the dedicated real-V8 gate image')
    if args.node and not re.search(r'\b[tT] _ZN4node[^\n]*InitializeOncePerProcess', symbols):
        parser.error('Node initialization implementation is missing from the image')
    symbol_values = {name: int(address, 16) for address, _, name in
                     (line.split(maxsplit=2) for line in symbols.splitlines() if len(line.split()) == 3)}
    sections = subprocess.check_output([str(tool.with_name('riscv-none-elf-readelf')), '-SW', str(kernel)], text=True)
    (work / 'sections.txt').write_text(sections)
    for match in re.finditer(r'\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S+)', sections):
        name, address, size, flags = match.groups()
        if 'A' in flags and 'W' in flags and 'X' in flags:
            parser.error('writable executable section: ' + name)
        if 'A' in flags and 'X' in flags:
            start, end = int(address, 16), int(address, 16) + int(size, 16)
            if not symbol_values['__text_start'] <= start <= end <= symbol_values['__text_end']:
                parser.error('executable section outside admitted RX text: ' + name)
    command = ['qemu-system-riscv64', '-machine', 'virt', '-m', '1G', '-smp', '4',
        '-nographic', '-bios', 'default', '-kernel', str(kernel), '-net', 'none',
        '-object', 'rng-random,id=v8_rng,filename=/dev/urandom',
        '-device', 'virtio-rng-device,rng=v8_rng', '-global', 'virtio-mmio.force-legacy=false']
    report = dict(command=command, passed=False,
        kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
        qemu_version=subprocess.check_output(['qemu-system-riscv64', '--version'], text=True).strip(),
        scope=('Preliminary real Node embedding on VibeOS RV64GC; not complete M2/TypeScript acceptance' if args.node else
               'Real V8 on VibeOS RV64GC; no Node/TypeScript compatibility claim'))
    inputs = [ROOT / name for name in (
        'kernel/src/lib.rs', 'kernel/src/mmu.rs', 'kernel/src/trap.rs',
        'services/wasi-command/src/lib.rs',
        'kernel/src/world.rs', 'kernel/Cargo.toml', 'kernel/build.rs',
        'firmware/qemu-virt/Cargo.toml', 'firmware/qemu-virt/build.rs',
        'firmware/qemu-virt/linker.ld', 'boards/qemu-virt/Cargo.toml',
        'boards/qemu-virt/src/lib.rs', 'runtime/riscv/src/bare.rs',
        'tools/node-runtime/tests/v8-smoke.cc', 'scripts/test-v8-gate-qemu.py')]
    inputs += sorted((ROOT / 'kernel/src').glob('native_*.rs'))
    inputs += sorted(p for p in (ROOT / 'tools/node-runtime/platform').iterdir() if p.is_file())
    inputs += sorted((ROOT / 'tools/node-runtime/patches').glob('*.patch'))
    if args.node:
        inputs += [ROOT / 'tools/node-runtime/tests/node-smoke.cc',
                   ROOT / 'tools/node-runtime/tests/node-project-smoke.js']
        inputs += sorted((ROOT / 'tools/node-runtime/runtime').glob('*'))
    if args.uv_loop or args.node:
        inputs += sorted(p for p in (ROOT / 'tools/node-runtime/libuv').iterdir()
                         if p.suffix in ('.c', '.h'))
        inputs += [ROOT / 'tools/node-runtime/tests/uv-loop-smoke.c']
        inputs += [ROOT / 'tools/node-runtime/tests/uv-file-smoke.c',
                   ROOT / 'tools/node-runtime/tests/uv-sync-smoke.c']
        inputs += [ROOT / 'services/file-store/src/lib.rs', ROOT / 'services/file-store/src/path.rs',
                   ROOT / 'services/file-store/src/storage.rs']
    report['source_sha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    started = time.monotonic()
    try:
        with (work / 'serial.log').open('wb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=120)
        report['qemu_exit_code'] = result.returncode
    except subprocess.TimeoutExpired:
        report['error'] = 'QEMU did not terminate within 120 seconds'
    finally:
        serial = (work / 'serial.log').read_text(errors='replace')
        memories = list(re.finditer(r'V8 GATE memory global_live_before=(\d+) global_live_after=(\d+) global_peak=(\d+) bump_remaining=(\d+)', serial))
        memory = memories[-1] if memories else None
        if memory:
            report['kernel_memory_history_bytes'] = [dict(zip(('live_before', 'live_after', 'global_peak', 'bump_remaining'), map(int, item.groups()))) for item in memories]
            report['kernel_memory_bytes'] = report['kernel_memory_history_bytes'][-1]
        checks = dict(memory=memory is not None, expression='V8 SMOKE expression=42 PASS' in serial,
            exception='V8 SMOKE exception=Error:vibeos-v8-smoke PASS' in serial,
            gc=bool(re.search(r'V8 SMOKE gc_callbacks=[1-9][0-9]* heap_used=[0-9]+ PASS', serial)),
            teardown='V8 SMOKE teardown PASS' in serial,
            returned=bool(re.search(r'V8 GATE returned=' + str(args.node_exit_code) + r' parks=[0-9]+ waiters=0', serial)),
            no_fatal='NATIVE FATAL EXIT' not in serial and 'panicked' not in serial.lower() and 'fatal trap' not in serial.lower(),
            qemu_shutdown=report.get('qemu_exit_code') == 0)
        if args.node:
            for name in ('expression', 'exception', 'gc', 'teardown'):
                del checks[name]
            node_serial = serial.replace('vsh> \n\x1b[2K', '')
            report['expected_node_exit_code'] = args.node_exit_code
            if args.node_explicit_exit:
                checks['node_explicit_exit'] = 'NODE EXIT explicit=1 PASS' in node_serial
            checks.update(node_authority='NATIVE PROJECT AUTH revoked=1 replaced=1 retargeted=1 readonly=1 PASS' in node_serial,
                          node_root='NODE ROOT sibling_hidden=1 symlink_denied=3 PASS' in node_serial and 'NODE ROOT outside_unchanged=1 PASS' in node_serial,
                          node_exit=f'NODE EXIT observed={args.node_exit_code} PASS' in node_serial,
                          node_js='NODE SMOKE buffer promise timer=42 PASS' in node_serial,
                          node_work='NODE SMOKE queued zlib roundtrip PASS' in node_serial,
                          node_cjs_file='NODE PROJECT cjs=42 sync_file=1 PASS' in node_serial,
                          node_esm_file='NODE PROJECT esm=99 dynamic_import=1 async_file=1 PASS' in node_serial,
                          node_stdin='NODE STDIN utf8=1 eof=1 bytes=15 PASS' in node_serial,
                          node_teardown='NODE SMOKE teardown PASS' in node_serial,
                          node_no_error='NODE SMOKE exception:' not in node_serial and 'NODE SMOKE FAILED' not in node_serial)
        if args.node_repeat > 1:
            checks['node_repeat'] = all(f'NATIVE INVOCATION index={i} returned=0 released=1' in node_serial
                                        for i in range(1, args.node_repeat + 1))
            checks['node_repeat_teardown'] = node_serial.count('NODE SMOKE teardown PASS') == args.node_repeat
            checks['node_repeat_memory'] = len(memories) == args.node_repeat
            checks['node_repeat_execution'] = all(node_serial.count(marker) == args.node_repeat for marker in (
                'NODE PROJECT cjs=42 sync_file=1 PASS',
                'NODE PROJECT esm=99 dynamic_import=1 async_file=1 PASS',
                'NODE STDIN utf8=1 eof=1 bytes=15 PASS',
                'NODE ROOT sibling_hidden=1 symlink_denied=3 PASS'))
            report['expected_node_invocations'] = args.node_repeat
        if args.node_revoke:
            checks['node_revoke'] = 'NODE REVOKE new_path=1 open_fd=1 PASS' in node_serial
        if args.node_eval and not args.node_idle_cancel:
            checks['node_eval'] = 'NODE EVAL require=1 argv=1 PASS' in node_serial
        if args.node_main:
            checks['node_main'] = 'NODE MAIN file=1 argv=1 cwd=1 PASS' in node_serial
        if args.node_cancel:
            checks.pop('node_exit')
            checks['node_cancel'] = 'NODE CANCEL infinite_loop=1 terminated=1 PASS' in serial
            checks['same_hart_cancel'] = 'NODE CANCEL same_hart_peer=1 requested=1' in serial
            if args.node_eval:
                checks['cpu_loop_entered'] = 'NODE CPU CANCEL entered_loop=1' in node_serial
                checks['cpu_no_resume'] = ('NODE CPU CANCEL unexpected_finally=1' not in node_serial and
                                            'NODE CPU CANCEL unexpected_return=1' not in node_serial)
        if args.node_idle_cancel:
            for key in ('node_js', 'node_work', 'node_cjs_file', 'node_esm_file', 'node_stdin'):
                del checks[key]
            checks['node_root'] = 'NODE ROOT outside_unchanged=1 PASS' in serial
            checks['idle_wait'] = bool(re.search(r'NODE IDLE CANCEL entered_wait_us=[1-9][0-9]{7,}', serial))
            elapsed = re.search(r'NODE IDLE CANCEL elapsed_ms=(\d+) returned=130 PASS', serial)
            checks['idle_cancel'] = elapsed is not None and int(elapsed[1]) < 10000
            checks['same_hart_cancel'] = 'NODE CANCEL same_hart_peer=1 requested=1' in serial
        if args.uv_loop:
            checks['libuv_loop'] = bool(re.search(
                r'UV LOOP timers=3 async=1 closed=4 phases=[1-9][0-9]* read=8 written=9216 PASS', serial))
            checks['libuv_clock'] = 'UV CLOCK realtime=1 monotonic=1 sleep=1 identity=1 PASS' in serial
            checks['libuv_rwlock'] = 'UV RWLOCK readers=2 exclusive=1 busy=4 PASS' in serial
            checks['libuv_metrics'] = 'UV METRICS loops=8 idle_measured=1 closed=8 PASS' in serial
            checks['libuv_sync'] = 'UV SYNC recursive=2 permits=3 timeout_relocked=1 PASS' in serial
            checks['libuv_output'] = 'UV OUTPUT bytes=9216 PASS' in serial
            checks['native_libc'] = 'NATIVE LIBC stat=1 escape=1 revoked=1 link_denied=1 sleep=1 PASS' in serial
            checks['unlink_readonly'] = 'UV UNLINK readonly_admission=denied PASS' in serial
            checks['libuv_cancel_started'] = 'UV CANCEL started_busy=1 read_completed=1 PASS' in serial
            checks['libuv_cancel'] = 'UV CANCEL queued=1 callback=1 file_preserved=1 PASS' in serial
            checks['libuv_unlink'] = 'UV UNLINK sync=1 async=1 escape=1 directory=1 revoked=1 PASS' in serial
            checks['libuv_readlink'] = 'UV READLINK literal=1 short_buffer=1 async=1 escape=1 revoked=1 PASS' in serial
            checks['stream_handles'] = 'UV STREAM HANDLE stdio=3 open=1 modes=1 close=1 ipc_denied=1 PASS' in serial
            checks['stream_read'] = 'UV STREAM READ bytes=12 chunks=4 paused=1 enobufs=1 eof=1 PASS' in serial
            checks['cwd'] = 'UV CWD root=1 relative=1 short=1 escape=1 identity=1 PASS' in serial
            checks['links'] = 'UV LINKS literal=1 inode=1 async=2 cancel=1 escape=1 PASS' in serial
            checks['links_readonly'] = 'UV LINKS readonly_denied=2 PASS' in serial
            checks['metadata_unsupported'] = 'UV METADATA unsupported=8 deferred=8 cancelled=1 unchanged=1 PASS' in serial
            checks['file_sync'] = 'UV FSYNC committed=1 busy=1 async=2 cancelled=1 unchanged=1 PASS' in serial
            checks['ipc_tty_excluded'] = 'UV IPC TTY denied=8 untouched=1 callbacks=0 PASS' in serial
            checks['directory'] = ('UV DIRECTORY types=3 cursor=1 eof=1 async=3 cancelled=2 replaced=1 PASS' in serial and
                                   'UV DIRECTORY revoked=1 close_after_revoke=1 PASS' in serial)
            checks['mutating_open'] = 'UV OPEN async_create=1 async_truncate=1 copied_path=1 cancelled=2 preserved=1 PASS' in serial
            checks['copyfile'] = ('UV COPY content=1 independent=1 links=1 exclusive=1 async=1 cancelled=1 statfs_unsupported=1 PASS' in serial and
                                 'UV COPY revoked=1 statfs_revoked=1 PASS' in serial)
            checks['system_information'] = 'UV SYSTEM image_labels=1 hostname_explicit=1 cpu_unsupported=1 load_unavailable=1 PASS' in serial
            checks['temporary'] = ('UV TEMP sync=2 async=2 unique=1 content=1 cancelled=2 no_mutation=1 PASS' in serial and
                                   'UV TEMP revoked=2 PASS' in serial)
            checks['os_boundaries'] = 'UV OS denied=7 untouched=1 home_explicit=1 no_account_fallback=1 PASS' in serial
            checks['work_queue'] = 'UV WORK deferred=1 worked=3 requeued=2 cancelled=1 busy=1 fs=1 timers=1 freed=1 PASS' in serial
            checks['thread_exclusions'] = 'UV THREAD denied=4 untouched=1 entries=0 identity=1 PASS' in serial
            checks['process_metadata'] = 'UV PROCESS title_owned=1 isolation=1 bounds=1 identity=1 exepath_unsupported=1 stdio=1 PASS' in serial
            checks['memory_queries'] = 'UV MEMORY measured=1 allocation_visible=1 quota_unknown=1 rss_unsupported=1 PASS' in serial
            checks['environment'] = 'UV ENV seeded=1 isolated=1 shared_libc=1 snapshot=1 bounded=1 empty=1 PASS' in serial
            # Each vector can be a distinct console delivery. VSH redraws its
            # prompt between deliveries; discard only that exact UI sequence.
            # read_text normalizes the carriage return to a newline.
            stream_output = serial.replace('vsh> \n\x1b[2K', '')
            checks['stream_write'] = 'UV STREAM WRITE vectors=3 PASS' in stream_output
            # The separate stderr shutdown fixture can be delivered between
            # stdout vectors. Require its exact payload once, then compare the
            # complete stdout sequence without assuming cross-stream ordering.
            shutdown_data = 'UV SHUTDOWN DATA\n'
            stdout_output = stream_output.replace(shutdown_data, '')
            checks['async_stream_write'] = ('UV STREAM WRITE vectors=3 PASS\n' +
                'Y' * 16384 + '\nUV ASYNC STREAM bytes=16384 callbacks=3 PASS') in stdout_output
            checks['stream_cancelled_output_absent'] = 'MUST-NOT-BE-WRITTEN' not in stream_output
            checks['stream_shutdown'] = (stream_output.count(shutdown_data) == 1 and
                'UV SHUTDOWN drained=1 order=1 descriptor=1 denied=1 PASS' in stream_output)
            checks['network_exclusions'] = 'UV NETWORK denied=32 untouched=1 handles=0 PASS' in serial
            checks['positioned_io'] = 'UV POSITIONED sync=2 async=2 cursor=1 invalid=1 pipe=1 PASS' in serial
            checks['async_file_read'] = 'UV ASYNC READ bytes=3 eof=1 cancel=1 retry=1 revoked_delivery=1 PASS' in serial
            checks['excluded_operations'] = 'UV EXCLUDED operations=14 untouched=1 callbacks=0 handles=0 PASS' in serial
            checks['async_file_write'] = 'UV ASYNC FILE write=1 truncate=1 deferred=1 cancelled=2 content=1 PASS' in serial
            checks['libuv_create'] = 'UV CREATE content=1 exclusive=1 append=1 truncate=1 revoked=1 PASS' in serial
            checks['create_readonly'] = 'UV CREATE readonly_denied=1 PASS' in serial
            checks['libuv_write_file'] = 'UV WRITE identity=1 content=1 truncate=1 modes=1 revoked=1 PASS' in serial
            checks['write_readonly'] = 'UV WRITE readonly_open_denied=1 PASS' in serial
            checks['file_range'] = 'NATIVE FILE RANGE identity=1 sparse=1 truncate=1 snapshot=1 PASS' in serial
            checks['tree_readonly'] = 'UV TREE readonly_mutations_denied=3 PASS' in serial
            checks['libuv_tree'] = 'UV TREE mkdir=1 rename=1 rmdir=1 async=3 types=1 revoked=1 PASS' in serial
            checks['libuv_scandir'] = 'UV SCANDIR types=3 sorted=1 cleanup=1 async=1 revoked=1 PASS' in serial
            checks['libuv_access'] = 'UV ACCESS read_write=1 missing=1 escape=1 async=1 revoked=1 PASS' in serial
            checks['access_readonly'] = 'UV ACCESS readonly_read=1 readonly_write_denied=1 PASS' in serial
            checks['libuv_files'] = 'UV FILE open=1 read=1 stat=1 close=1 revoked=1 callbacks=2 PASS' in serial
            checks['libuv_paths'] = 'UV PATH stat=1 lstat=1 realpath=1 symlink=1 escape=1 loop=1 PASS' in serial
        report.update(checks=checks, passed=all(checks.values()), seconds=time.monotonic() - started)
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
