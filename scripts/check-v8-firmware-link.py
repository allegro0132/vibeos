#!/usr/bin/env python3
"""Link the real V8 smoke entry with Rust kernel bridges.

By default this uses diagnostic C++ fixture firmware, which must NOT be run as
a V8 acceptance image: it includes an extra flag page and never calls the gate.
Use --gate for the dedicated execution image, then test-v8-gate-qemu.py to run it.
Successful linking alone never establishes V8 execution acceptance.
The required forced undefined symbol prevents dead stripping of the real gate.
"""
import argparse
import hashlib
import shutil
import importlib.util
import json
import os
import re
from collections import Counter
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent

def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()

def archive_inputs(archives, ar):
    inputs = {}
    for archive in archives:
        inputs[str(archive)] = digest(archive)
        with archive.open('rb') as source:
            thin = source.read(8) == b'!<thin>\n'
        if thin:
            # A thin archive's index does not contain the object bytes. GNU ar
            # resolves these member paths relative to the supplied archive.
            members = subprocess.check_output([str(ar), 't', str(archive)], text=True)
            for name in members.splitlines():
                member = Path(name)
                if not member.is_absolute():
                    member = archive.parent / member
                member = member.resolve(strict=True)
                inputs[str(member)] = digest(member)
    return inputs

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate', action='store_true', help='build the dedicated 1GiB V8 execution image')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    source, work = args.source.resolve(), args.work.resolve()
    if not work.is_relative_to(ROOT / 'target') or work.exists():
        parser.error('--work must be a fresh directory under target')
    spec = importlib.util.spec_from_file_location('v8_builder', ROOT / 'scripts/build-v8.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    config = builder.validate_configuration(source)
    tool = ROOT / 'target/node-runtime/toolchain/xpack-riscv-none-elf-gcc-14.2.0-3/bin'
    cxx = tool / 'riscv-none-elf-g++'
    archives = [source / f'out/Release/obj.target/tools/v8_gypfiles/lib{name}.a'
                for name in ('v8_snapshot', 'v8_base_without_compiler', 'v8_compiler',
                             'v8_libbase', 'v8_libplatform', 'abseil', 'v8_zlib',
                             'simdutf', 'highway')]
    for name in ('stdc++', 'm', 'c', 'gcc'):
        path = subprocess.check_output([str(cxx), '-march=rv64gc', '-mabi=lp64d',
                                       f'-print-file-name=lib{name}.a'], text=True).strip()
        archives.append(Path(path).resolve())
    if any(not archive.is_file() for archive in archives):
        parser.error('target V8 and pinned C/C++ archives must exist')
    work.mkdir(parents=True)
    smoke = work / 'v8-smoke.o'
    compile_command = builder.smoke_command(source, cxx, smoke)
    with (work / 'compile.log').open('w') as log:
        subprocess.run(compile_command, stdout=log, stderr=subprocess.STDOUT, check=True)
    input_hashes = archive_inputs(archives, tool / 'riscv-none-elf-ar')
    (work / 'archive-inputs.json').write_text(json.dumps(input_hashes, indent=2) + '\n')
    link_args = ['--undefined=vibeos_v8_smoke', str(smoke), '--start-group',
                 *map(str, archives), '--end-group', '--error-limit=0']
    command = ['rustup', 'run', 'nightly-2026-08-01', 'cargo', 'rustc', '--locked',
               '--offline', '--release', '--target', 'riscv64gc-unknown-none-elf',
               '--features', ('wasi-ssh-upload,node-runtime' if args.gate else
                              'wasi-ssh-upload,native-runtime-probe,native-cxx-probe'),
               '--bin', 'vibeos-qemu-virt', '--',
               *[f'-Clink-arg={arg}' for arg in link_args]]
    env = dict(os.environ)
    for variable, binary in [('RUSTC', 'rustc'), ('RUSTDOC', 'rustdoc')]:
        env[variable] = subprocess.check_output(
            ['rustup', 'which', '--toolchain', 'nightly-2026-08-01', binary], text=True).strip()
    started = time.monotonic()
    with (work / 'link.log').open('w') as log:
        result = subprocess.run(command, cwd=ROOT / 'firmware/qemu-virt', env=env,
                                stdout=log, stderr=subprocess.STDOUT)
    diagnostics = (work / 'link.log').read_text(errors='replace')
    report = dict(command=command, compile_command=compile_command,
                  missing_symbols=sorted(set(re.findall(r'undefined symbol: ([^\n]+)', diagnostics))),
                  linker_error_counts=dict(Counter(re.findall(r'ld.lld: error: ([^:\n]+)', diagnostics))),
                  exit_code=result.returncode, seconds=time.monotonic() - started,
                  configuration=config, runtime_acceptance='NOT_RUN',
                  scope=('Dedicated V8 gate image; execution still required' if args.gate else
                         'Diagnostic fixture firmware link; not a runnable V8 acceptance image'))
    report['compiler_sha256'] = digest(cxx)
    report['smoke_source_sha256'] = digest(ROOT / 'tools/node-runtime/tests/v8-smoke.cc')
    report['smoke_object_sha256'] = digest(smoke)
    report['archive_inputs_sha256'] = digest(work / 'archive-inputs.json')
    report['archive_input_count'] = len(input_hashes)
    report['inputs_unchanged_during_link'] = input_hashes == archive_inputs(archives, tool / 'riscv-none-elf-ar')
    if not report['inputs_unchanged_during_link']:
        report['build_exit_code'] = report['exit_code']
        report['exit_code'] = 1
        report['error'] = 'archive/object inputs changed during link; result is not qualified'
    if report['exit_code'] == 0:
        kernel = work / ('v8-gate.elf' if args.gate else 'diagnostic-NOT-RUN.elf')
        shutil.copyfile(ROOT / 'target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt', kernel)
        report['kernel'] = str(kernel)
        report['kernel_sha256'] = digest(kernel)
    (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return report['exit_code']

if __name__ == '__main__':
    raise SystemExit(main())
