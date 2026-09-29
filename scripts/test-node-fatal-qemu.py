#!/usr/bin/env python3
"""Record a real non-OOM V8 fatal error in a separate fault-injection QEMU image."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ADDR2LINE = ROOT / 'target/node-runtime/toolchain/xpack-riscv-none-elf-gcc-14.2.0-3/bin/riscv-none-elf-addr2line'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    if not ADDR2LINE.is_file():
        parser.error('pinned RISC-V addr2line is required to verify the fatal backtrace')
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'target') or work.exists():
        parser.error('--work must be a fresh directory under target')
    work.mkdir(parents=True)
    kernel = work / 'kernel.elf'
    shutil.copy2(args.kernel, kernel)
    disk = work / 'project.raw'
    with disk.open('wb') as f:
        f.truncate(128 * 1024 * 1024)
    commands = ['quiet', 'mkdir @home/project',
                "@send node --root @home/project -e \"console.log('NODE_FATAL_'+'UNREACHED')\"",
                '@expect fatal trap: cause=3', '@wait-exit']
    assert all(len(line.encode()) < 240 for line in commands)
    # The legacy console redraws prompts while delivering output. Pause after
    # each command so redraws cannot cause the driver to quit a live command;
    # success below is based on actual distinct output, not prompt matching.
    case = work / 'commands.in'
    case.write_text('\n@sleep 0.3\n'.join(commands) + '\n')
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
               ROOT / 'tools/node-runtime/libuv/vibeos-fs.c',
               ROOT / 'tools/node-runtime/toolchain.lock.json',
               ROOT / 'tools/node-runtime/platform/vibeos-esbuild.h']
    inputs += sorted((ROOT / 'tools/node-runtime/toolkit').glob('*.*'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    result = subprocess.run(['python3', str(ROOT / 'scripts/qemu-vsh-driver.py'),
        '--case', str(case), '--log', str(work / 'serial.log'), '--command-timeout', '180',
        '--', *command],
        cwd=ROOT, timeout=1000)
    serial = (work / 'serial.log').read_text(errors='replace').replace('vsh> \n\x1b[2K', '')
    trap = re.search(r'fatal trap: cause=(\d+) stval=(0x[0-9a-fA-F]+) sepc=(0x[0-9a-fA-F]+) \(breakpoint\)', serial)
    # Buffered stderr may be lost during fatal shutdown. The exact ELF must
    # prove the real V8 fatal/startup-order path, not an arbitrary native abort.
    addresses = re.findall(r'#\d+ (0x[0-9a-fA-F]+)', serial)
    if trap:
        addresses.append(trap.group(3))
    symbols = subprocess.run([str(ADDR2LINE), '-C', '-f', '-e', str(kernel), *addresses],
                             capture_output=True, text=True, timeout=30) if addresses else None
    symbol_text = symbols.stdout if symbols else ''
    (work / 'symbolized.txt').write_text(symbol_text)
    if symbols:
        (work / 'symbolizer-stderr.txt').write_text(symbols.stderr)
    checks = dict(v8_fatal=bool(symbols and symbols.returncode == 0 and
                              'V8_Fatal(' in symbol_text and
                              'v8::internal::V8::InitializePlatform(' in symbol_text and
                              'v8::base::OS::Abort()' in symbol_text),
                  non_oom='FatalProcessOutOfMemory' not in symbol_text,
                  wrong_initialization_order='Wrong initialization order: from 4 to 5, expected to 1!' in serial,
                  fatal_breakpoint=trap is not None and int(trap.group(1)) == 3,
                  # QEMU/OpenSBI exits zero even though the guest requests
                  # failure shutdown. The fatal trap and symbols prove failure.
                  firmware_shutdown=result.returncode == 0,
                  no_user_execution='NODE_FATAL_UNREACHED' not in serial,
                  no_normal_completion='Returned(0)' not in serial)
    checks['source_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in hashes.items())
    report = dict(passed=all(checks.values()), checks=checks, command=command,
                  fault='Duplicate V8 platform initialization after successful Node process startup',
                  trap_cause=int(trap.group(1)) if trap else None,
                  trap_pc=trap.group(3) if trap else None,
                  qemu_exit=result.returncode, recovery="not attempted; trusted image terminates",
                  seconds=time.monotonic()-started,
                  fatal_addresses=addresses,
                  symbolizer_sha256=hashlib.sha256(ADDR2LINE.read_bytes()).hexdigest(),
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
                  source_sha256=hashes)
    (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
