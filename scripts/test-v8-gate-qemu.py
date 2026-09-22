#!/usr/bin/env python3
"""Run the real, target-only V8 expression/exception/GC acceptance gate."""
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
    args = parser.parse_args()
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
    symbol_values = {name: int(address, 16) for address, _, name in
                     (line.split(maxsplit=2) for line in symbols.splitlines() if len(line.split()) == 3)}
    sections = subprocess.check_output([str(tool.with_name('riscv-none-elf-readelf')), '-SW', str(kernel)], text=True)
    (work / 'sections.txt').write_text(sections)
    for match in re.finditer(r'\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S+)', sections):
        name, address, size, flags = match.groups()
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
        scope='Real V8 on VibeOS RV64GC; no Node/TypeScript compatibility claim')
    inputs = [ROOT / name for name in (
        'kernel/src/lib.rs', 'kernel/src/mmu.rs', 'kernel/src/trap.rs',
        'kernel/src/world.rs', 'kernel/Cargo.toml', 'kernel/build.rs',
        'firmware/qemu-virt/Cargo.toml', 'firmware/qemu-virt/build.rs',
        'firmware/qemu-virt/linker.ld', 'boards/qemu-virt/Cargo.toml',
        'boards/qemu-virt/src/lib.rs', 'runtime/riscv/src/bare.rs',
        'tools/node-runtime/tests/v8-smoke.cc', 'scripts/test-v8-gate-qemu.py')]
    inputs += sorted((ROOT / 'kernel/src').glob('native_*.rs'))
    inputs += sorted(p for p in (ROOT / 'tools/node-runtime/platform').iterdir() if p.is_file())
    inputs += sorted((ROOT / 'tools/node-runtime/patches').glob('*.patch'))
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
        memory = re.search(r'V8 GATE memory global_live_before=(\d+) global_live_after=(\d+) global_peak=(\d+) bump_remaining=(\d+)', serial)
        if memory:
            report['kernel_memory_bytes'] = dict(zip(('live_before', 'live_after', 'global_peak', 'bump_remaining'), map(int, memory.groups())))
        checks = dict(memory=memory is not None, expression='V8 SMOKE expression=42 PASS' in serial,
            exception='V8 SMOKE exception=Error:vibeos-v8-smoke PASS' in serial,
            gc=bool(re.search(r'V8 SMOKE gc_callbacks=[1-9][0-9]* heap_used=[0-9]+ PASS', serial)),
            teardown='V8 SMOKE teardown PASS' in serial,
            returned=bool(re.search(r'V8 GATE returned=0 parks=[0-9]+ waiters=0', serial)),
            no_fatal='NATIVE FATAL EXIT' not in serial and 'panicked' not in serial.lower() and 'fatal trap' not in serial.lower(),
            qemu_shutdown=report.get('qemu_exit_code') == 0)
        report.update(checks=checks, passed=all(checks.values()), seconds=time.monotonic() - started)
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
