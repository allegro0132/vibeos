#!/usr/bin/env python3
"""Exercise the optional live boot-dtb-probe, then the existing target selftest.
Build firmware/qemu-virt with boot-dtb-probe,legacy-shell first. No hardware
qualification is implied. A supplied --dtb may deliberately test rejection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time


def run(kernel, output, dtb=None, expect_rejection=False, require_admission=False, memory="128M"):
    output.mkdir(parents=True, exist_ok=True)
    # Refuse to overwrite evidence before starting a VM.
    with (output / 'serial.log').open('xb') as log, tempfile.TemporaryDirectory(prefix='vibeos-dtb-') as work:
        disk = Path(work) / 'data.raw'
        with disk.open('wb') as f:
            f.truncate(128 * 1024 * 1024)
        cmd = ['qemu-system-riscv64', '-machine', 'virt', '-cpu', 'rv64', '-smp', '4', '-m', memory,
               '-nographic', '-bios', 'default', '-kernel', str(kernel), '-nic', 'none',
               '-drive', f'if=none,id=disk,format=raw,file={disk}',
               '-device', 'virtio-blk-device,drive=disk,bus=virtio-mmio-bus.0,queue-size=8',
               '-global', 'virtio-mmio.force-legacy=false']
        if dtb is not None:
            cmd += ['-dtb', str(dtb)]
        vm = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        selector = selectors.DefaultSelector()
        selector.register(vm.stdout, selectors.EVENT_READ)
        data = bytearray()
        sent = False
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                for key, _ in selector.select(0.25):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    log.write(chunk); log.flush(); data.extend(chunk)
                failure = re.search(rb'(?:BOOT_DTB_CPUS|BOOT_ADMISSION) FAIL: ([^\r\n]+)[\r\n]', data)
                if failure:
                    if not expect_rejection:
                        raise RuntimeError(failure.group(1).decode())
                    vm.wait(timeout=10)
                    if require_admission and (b'BOOT_ADMISSION FAIL:' not in data or b'v0.1' in data or b'  heap      ' in data):
                        raise RuntimeError('rejection did not precede kernel banner')
                    result = {'status': 'rejected', 'reason': failure.group(1).decode()}
                    break
                if b'vibe> ' in data and not sent:
                    if expect_rejection:
                        raise RuntimeError('invalid handoff reached the shell')
                    vm.stdin.write(b'selftest\r'); vm.stdin.flush(); sent = True
                tests = re.search(rb'selftest: (\d+) passed, (\d+) failed[\r\n]', data)
                if tests:
                    topology = re.search(rb'BOOT_DTB_CPUS PASS boot=(\d+) count=(\d+) timebase=(\d+)[\r\n]', data)
                    if not topology or int(tests[2]) != 0 or int(tests[1]) < 390:
                        raise RuntimeError('handoff or target selftest failed')
                    boot, count, hz = map(int, topology.groups())
                    if require_admission:
                        admissions = re.findall(rb'BOOT_ADMISSION PASS boot=(\d+) count=(\d+) timebase=(\d+)[\r\n]', data)
                        if len(admissions) != 1 or admissions[0] != topology.groups():
                            raise RuntimeError('runtime metadata was not published exactly once')
                    if boot not in range(4) or count != 4 or hz != 10_000_000:
                        raise RuntimeError('unexpected live CPU inventory')
                    result = {'status': 'passed', 'boot_hart': boot, 'harts': count, 'timebase_hz': hz, 'selftests': int(tests[1])}
                    if require_admission:
                        heap = re.search(rb'BOOT_HEAP PASS regions=(\d+) bytes=(\d+)[\r\n]', data)
                        actual = re.search(rb'  heap +0x[0-9a-f]+\.\.0x[0-9a-f]+ +\((\d+) KiB\)', data)
                        if not heap or not actual or int(heap[1]) == 0 or int(heap[2]) // 1024 != int(actual[1]) or int(tests[1]) < 395:
                            raise RuntimeError('usable heap metadata or disjoint allocator selftests failed')
                        result['heap_regions'] = int(heap[1])
                        result['heap_bytes'] = int(heap[2])
                    break
                if vm.poll() is not None and not selector.get_map():
                    raise RuntimeError('QEMU exited before completing the probe')
            else:
                raise TimeoutError('QEMU boot DTB probe timed out')
        finally:
            selector.close()
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    vm.kill(); vm.wait()
            vm.stdin.close(); vm.stdout.close()
    result['kernel_sha256'] = hashlib.sha256(kernel.read_bytes()).hexdigest()
    result['physical_acceptance'] = False
    result['require_admission'] = require_admission
    result['memory'] = memory
    (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--dtb', type=Path)
    parser.add_argument('--expect-rejection', action='store_true')
    parser.add_argument('--require-admission', action='store_true')
    parser.add_argument('--memory', default='128M', choices=['128M', '4G'])
    args = parser.parse_args()
    print(json.dumps(run(args.kernel, args.output, args.dtb, args.expect_rejection, args.require_admission, args.memory), indent=2))
