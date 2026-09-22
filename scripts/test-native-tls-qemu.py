#!/usr/bin/env python3
"""Verify hart identity while tp contains a foreign TLS pointer (not V8 acceptance).

Build firmware/qemu-virt with wasi-ssh-upload,native-runtime-probe first.
"""
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
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, default=ROOT / 'target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt')
    parser.add_argument('--native-call', action='store_true',
                        help='also require the LP64D call and suspend/resume probes')
    parser.add_argument('--native-cxx', action='store_true',
                        help='also require the cross-compiled C++ RAII probe')
    parser.add_argument("--entropy", action="store_true", help="require granted virtio entropy execution")
    args = parser.parse_args()
    args.native_call = args.native_call or args.native_cxx
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    kernel = work / 'kernel.elf'
    shutil.copyfile(args.kernel, kernel)
    command = ['qemu-system-riscv64', '-machine', 'virt', '-m', '128M',
               '-smp', '4', '-nographic', '-bios', 'default', '-kernel',
               str(kernel), '-net', 'none']
    if args.entropy:
        command += ['-object', 'rng-random,id=native_rng,filename=/dev/urandom',
                    '-device', 'virtio-rng-device,rng=native_rng',
                    '-global', 'virtio-mmio.force-legacy=false']
    started = time.monotonic()
    report = {'scope': 'hart identity under foreign tp; not full native TLS or V8 acceptance',
              'kernel_sha256': hashlib.sha256(kernel.read_bytes()).hexdigest(),
              'command': command, 'passed': False}
    if args.native_call:
        report['scope'] += '; protected native call/return, suspend/resume, Rust Drop and FCSR restoration'
    if args.native_cxx:
        report['scope'] += '; C++ RAII, per-context GCC emutls across suspension, dynamic TLS initialization and LIFO exit destructors (not the full static C++ runtime)'
    report['qemu_version'] = subprocess.check_output(
        ['qemu-system-riscv64', '--version'], text=True).strip()
    report['source_sha256'] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ['runtime/riscv/src/bare.rs', 'kernel/src/lib.rs',
                     'kernel/Cargo.toml', 'firmware/qemu-virt/Cargo.toml',
                     'kernel/src/mmu.rs', 'kernel/src/trap.rs', 'kernel/src/native_call.rs',
                     'kernel/src/native_files.rs', 'kernel/src/native_process.rs', 'kernel/src/native_stdio.rs', 'kernel/src/native_libc_heap.rs', 'kernel/src/native_clock.rs', 'kernel/src/wasi_clock.rs', 'kernel/src/native_entropy.rs', 'kernel/src/world.rs', 'kernel/src/native_semaphore.rs', 'kernel/src/native_wait.rs', 'kernel/src/native_notify.rs', 'kernel/src/native_memory.rs', 'kernel/src/native_page_pool.rs', 'kernel/src/native_pages.rs', 'kernel/src/native_tcb_pages.rs', 'kernel/src/native_tls.rs',
                     'firmware/qemu-virt/linker.ld', 'firmware/qemu-virt/build.rs',
                     'kernel/build.rs', 'tools/node-runtime/tests/native-cxx-probe.cc',
                     'tools/node-runtime/toolchain.lock.json',
                     'tools/node-runtime/platform/vibeos-memory.h', 'tools/node-runtime/platform/vibeos-backtrace.h', 'tools/node-runtime/platform/vibeos-sync.h', 'tools/node-runtime/platform/vibeos-time.h', 'tools/node-runtime/platform/vibeos-cache.h',
                     'tools/node-runtime/platform/vibeos-stack.h', 'tools/node-runtime/platform/vibeos-tcb-pages.h',
                     'scripts/test-native-tls-qemu.py']}
    log = work / 'serial.log'
    sent = False
    try:
        with log.open('wb') as output:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT)
            try:
                while time.monotonic() - started < 60:
                    text = log.read_text(errors='replace')
                    pairs = {(int(p), int(l)) for p, l in re.findall(
                        r'NATIVE TLS identity physical=(\d+) logical=(\d+) PASS', text)}
                    if 'vsh> ' in text and not sent:
                        process.stdin.write(b'echo NATIVE_TLS_SHELL_OK\r')
                        process.stdin.flush()
                        sent = True
                    native_call = ('NATIVE CALL PASS runs=4 stack=262144 guard=1 nx=1 '
                                   'tls=1 fp=1 returned=1 unmapped=1') in text
                    native_suspend = ('NATIVE SUSPEND PASS yields=3 resumes=4 drops=1 '
                                      'tls=1 fcsr=1 local_fp=1 unmapped=1') in text
                    native_cxx = 'NATIVE CXX PASS yields=3 cpp_drops=1 rust_drops=1 returned=1' in text
                    native_park = 'NATIVE PARK PASS waits=3 peer_progress=1 cpp_drops=1 returned=1 unmapped=1 cxx_tls=1' in text
                    native_cxx_tls = 'NATIVE CXX TLS PASS initialized=1 zero=1 aligned=1 isolated=2 restored=1' in text
                    native_tls_dtor = 'NATIVE TLS DTOR PASS constructors=2 once=1 lifo=21 tls_access=1 stack_bounds=1' in text
                    native_tcb = 'NATIVE TCB PAGES PASS owned=1 invalid_release=1 double_free=1 reclaimed=1' in text
                    entropy = 'NATIVE ENTROPY PASS granted=1 device=1 parked=1 bytes=32' in text
                    semaphore_owner = 'NATIVE SEMAPHORE OWNER PASS foreign_denied=1 owner_post=1 destroyed=1' in text
                    semaphore_wake = 'NATIVE SEMAPHORE WAKE PASS parked=1 backend_post=1 consumed_once=1' in text
                    native_semaphore = 'NATIVE SEMAPHORE PASS permits=1 timeout=1 stale=1 overflow=1 destroyed=1' in text
                    native_wait = 'NATIVE WAIT ABI PASS timeouts=2 immediate=1 cpp_return=1 peer_progress=1' in text
                    native_notify = 'NATIVE NOTIFY PASS early=1 parked=1 exclusive=1 cancelled=1 reclaimed=1' in text
                    file_open = 'NATIVE OPEN PASS read=1 seek=1 chunks=1 eof=1 close=1 revoked=1 readonly=1' in text
                    unlink = 'NATIVE UNLINK PASS no_grant=1 readonly=1 escape=1 directory=1 removed=1 revoked=1' in text
                    native_fd = 'NATIVE FD PASS pipe=1 close=1 stale=1 revoked_cleanup=1 drained=1' in text
                    stdio = 'NATIVE STDIO PASS no_grant=1 backpressure=1 ordered=1 read=1 eof=1 revoked=1 waiters=0' in text
                    libc_heap = 'NATIVE LIBC HEAP PASS bounded=1 overflow=1 trim=1 zero=1 nx=1 tcb_accounted=1' in text
                    native_flags = 'NATIVE FLAGS PASS exact_range=1 readonly=1 nx=1 no_heap_thaw=1' in text
                    native_memory = 'NATIVE MEMORY ABI PASS isolated=2 revoked=1 reclaimed=1' in text
                    native_pool = 'NATIVE PAGE POOL PASS tail_reuse=1 prefix_stable=1 zero=1 ownership=1 reclaimed=1' in text
                    native_cache = 'NATIVE CACHE PASS c_abi=1 remote_fence=1' in text
                    native_pages = 'NATIVE PAGES PASS zero=1 align=1 ro=1 none=1 nx=1 atomic_reject=1 restored=1 discard=1 decommit=1' in text
                    harts = len({p for p, _ in pairs}) == 4 and {l for _, l in pairs} == set(range(4))
                    shell = text.count('NATIVE_TLS_SHELL_OK') >= 2
                    report['observed_checks'] = dict(harts=harts, shell=shell,
                        call=native_call, suspend=native_suspend, cxx=native_cxx,
                        park=native_park, pages=native_pages, cache=native_cache, cxx_tls=native_cxx_tls, tls_dtor=native_tls_dtor, tcb_pages=native_tcb, page_pool=native_pool, memory_abi=native_memory, static_flags=native_flags, notify=native_notify, wait_abi=native_wait, semaphore=native_semaphore, semaphore_owner=semaphore_owner, semaphore_wake=semaphore_wake, entropy=entropy, libc_heap=libc_heap, stdio=stdio, native_fd=native_fd, unlink=unlink, file_open=file_open)
                    if harts and shell and (not args.entropy or entropy) and (not args.native_call or (native_call and native_suspend)) and (not args.native_cxx or (native_cxx and native_park and native_pages and native_cache and native_cxx_tls and native_tls_dtor and native_tcb and native_pool and native_memory and native_flags and native_notify and native_wait and native_semaphore and semaphore_owner and semaphore_wake and libc_heap and stdio and native_fd and unlink and file_open)):
                        report.update(passed=True, hart_pairs=sorted(pairs))
                        if args.native_call:
                            report['native_call_passed'] = True
                            report['native_suspend_passed'] = True
                        if args.native_cxx:
                            report['native_cxx_passed'] = True
                            report['native_executor_parking_passed'] = True
                            report['native_page_permissions_passed'] = True
                        break
                    if process.poll() is not None:
                        raise RuntimeError(f'QEMU exited early: {process.returncode}')
                    time.sleep(0.05)
                if not report['passed']:
                    raise RuntimeError('required checks missing within 60 seconds: ' +
                                       json.dumps(report.get('observed_checks', {})))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
