#!/usr/bin/env python3
"""Prepare and cross-build the native V8 port. No runtime acceptance is implied."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
PORT = ROOT / 'tools/node-runtime'


def validate_configuration(source):
    path = source / 'config.gypi'
    values = json.loads('\n'.join(line for line in path.read_text().splitlines()
                                  if not line.lstrip().startswith('#')))['variables']
    required = {'OS': 'vibeos', 'target_arch': 'riscv64', 'host_arch': 'x64',
                'v8_enable_lite_mode': 1, 'v8_enable_webassembly': 0,
                'v8_enable_i18n_support': 0, 'v8_enable_pointer_compression': 0,
                'v8_enable_pointer_compression_shared_cage': 0, 'v8_enable_sandbox': 0}
    for key, expected in required.items():
        if values.get(key) != expected:
            raise ValueError(f'configuration drift: {key}={values.get(key)!r}, expected {expected!r}')
    # GYP's generator flavor is independent of config.gypi's OS variable.
    # A flavor-less regeneration on macOS can preserve that file byte-for-byte
    # while silently generating Darwin flags for the bare-metal target.
    for toolset in ('host', 'target'):
        makefile = source / f'out/tools/v8_gypfiles/v8_libbase.{toolset}.mk'
        generated = makefile.read_text()
        if 'V8_ENABLE_LEAPTIERING' in generated:
            raise ValueError(f'generated {toolset} enables large dispatch-table reservation')
        if '-std=gnu++20' not in generated:
            raise ValueError(f'generated {toolset} flags lost C++20')
        for flag in ('-march=rv64gc', '-mabi=lp64d', '-mcmodel=medany'):
            if (flag in generated) != (toolset == 'target'):
                raise ValueError(f'generated {toolset} compiler flag mismatch: {flag}')
    for library in ('v8_base_without_compiler', 'v8_compiler', 'v8_libbase',
                    'v8_libplatform', 'abseil'):
        generated = (source / f'out/tools/v8_gypfiles/{library}.target.mk').read_text()
        for flag in ('-fno-exceptions', '-fno-rtti', '-fno-strict-aliasing'):
            if flag not in generated:
                raise ValueError(f'generated {library} lost upstream C++ default {flag}')
        if re.search(r'(?<![\w-])-fexceptions(?![\w-])', generated):
            raise ValueError(f'generated {library} unexpectedly enables C++ exceptions')
    if '--regenerate -fmake-vibeos' not in (source / 'out/Makefile').read_text():
        raise ValueError('GYP regeneration rule lost the VibeOS generator flavor')
    return required


def smoke_command(source, cxx, output, input_source=None, library='v8_libplatform'):
    # Use the generated target library's definitions, including V8's public
    # ABI/build-configuration bits. Do not guess a smaller set of -D flags.
    makefile = source / f'out/tools/v8_gypfiles/{library}.target.mk'
    settings = makefile.read_text().replace('\\\n', ' ')
    flags = []
    for name in ('DEFS_Release', 'CFLAGS_Release', 'CFLAGS_CC_Release', 'INCS_Release'):
        match = re.search(r'^' + name + r' :=([^\n]*)', settings, re.MULTILINE)
        if not match:
            raise ValueError(f'missing target compiler settings: {name}')
        for flag in shlex.split(match.group(1)):
            flag = flag.replace('$(srcdir)', str(source))
            if '$(' in flag:
                raise ValueError(f'unresolved target setting: {flag}')
            flags.append(flag)
    return [str(cxx), *flags, '-I' + str(PORT / 'platform'), '-c',
            str(input_source or PORT / 'tests/v8-smoke.cc'), '-o', str(output)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'configure', 'base', 'support', 'snapshot', 'engine', 'smoke'])
    parser.add_argument('--work', type=Path, default=ROOT / 'target/node-runtime/native')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to((ROOT / 'target').resolve()) or work == (ROOT / 'target').resolve():
        parser.error('--work must be a subdirectory of this repository\'s target directory')
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be in 1..32')
    spec = importlib.util.spec_from_file_location('inputs', ROOT / 'scripts/node-runtime.py')
    inputs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inputs)
    lock = json.loads(inputs.LOCK.read_text())
    node = lock['artifacts']['node']
    source = work / 'source' / f'node-v{node["version"]}'
    patches = sorted((PORT / 'patches').glob('*.patch'))
    overlays = sorted(p for p in (PORT / 'platform').iterdir()
                      if p.suffix in ('.h', '.inc', '.cc'))
    port_hashes = {str(p.relative_to(ROOT)): inputs.digest(p) for p in patches + overlays}
    marker = work / 'prepared.json'
    if args.phase == 'prepare':
        if work.exists():
            parser.error('prepare needs a fresh work directory; existing builds are never erased')
        archive = inputs.fetch(node, ROOT / 'target/node-runtime/downloads', offline=True)
        work.mkdir(parents=True)
        inputs.extract(archive, work / 'source', node['member'])
        for patch in patches:
            subprocess.run(['patch', '-p1', '--fuzz=0', '--batch', '-i', str(patch)], cwd=source, check=True)
        for header in overlays:
            shutil.copyfile(header, source / 'deps/v8/src/base/platform' / header.name)
        marker.write_text(json.dumps({'source_sha256': inputs.digest(archive),
            'port_inputs': port_hashes}, indent=2) + '\n')
        print(source)
        return 0
    prepared = json.loads(marker.read_text())
    if prepared['port_inputs'] != port_hashes or prepared['source_sha256'] != node['sha256']:
        parser.error('port inputs changed; prepare a fresh --work directory')
    toolchain = json.loads((PORT / 'toolchain.lock.json').read_text())
    toolroot = ROOT / 'target/node-runtime/toolchain' / toolchain['directory']
    cc = toolroot / 'bin/riscv-none-elf-gcc'
    cxx = toolroot / 'bin/riscv-none-elf-g++'
    ar = toolroot / 'bin/riscv-none-elf-ar'
    for path in (cc, cxx, ar):
        if not path.is_file():
            parser.error('run scripts/prepare-node-toolchain.py first')
    host_cc, host_cxx = 'cc', 'c++'
    if platform.system() == 'Darwin':
        # This pinned V8 supports RV64 simulation on x64, not on arm64 hosts.
        # These executables generate target builtins; they never run user JS.
        subprocess.run(['arch', '-x86_64', '/usr/bin/true'], check=True)
        host_cc, host_cxx = 'clang -arch x86_64', 'clang++ -arch x86_64'
    elif platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('native V8 build currently requires macOS with x64 execution or Linux x64')
    env = dict(os.environ, CC=str(cc), CXX=str(cxx), AR=str(ar),
               CC_target=str(cc), CXX_target=str(cxx), AR_target=str(ar),
               CC_host=host_cc, CXX_host=host_cxx, AR_host='ar')
    if args.phase == 'smoke':
        command = smoke_command(source, cxx, work / 'v8-smoke.o')
        cwd = source / 'out'
    elif args.phase == 'configure':
        command = [sys.executable, 'configure.py', '--dest-os=vibeos', '--dest-cpu=riscv64',
            '--cross-compiling', '--without-intl', '--without-ssl', '--without-inspector',
            '--without-npm', '--without-corepack', '--without-amaro', '--v8-lite-mode',
            '--v8-options=--jitless', '--without-node-snapshot']
        cwd = source
    else:
        targets = {'base': ['v8_libbase'], 'support': ['abseil', 'v8_libplatform'], 'snapshot': ['mksnapshot'],
            'engine': ['v8_snapshot', 'v8_base', 'v8_libbase', 'v8_libplatform', 'abseil', 'v8_zlib', 'simdutf', 'highway']}
        command = ['make', f'-j{args.jobs}', 'BUILDTYPE=Release', *targets[args.phase]]
        cwd = source / 'out'
    evidence = work / f'{args.phase}-{time.time_ns()}'
    evidence.mkdir()
    before_config = None
    if args.phase != 'configure':
        validate_configuration(source)
        before_config = inputs.digest(source / 'config.gypi')
    result = inputs.check(args.phase, command, evidence, cwd=cwd, timeout=14400, env=env)
    result.update(runtime_acceptance='NOT_RUN', port_inputs=port_hashes,
                  compiler_sha256=inputs.digest(cxx), source_sha256=prepared['source_sha256'],
                  target_compiler_version=subprocess.check_output([cxx, '--version'], text=True),
                  host_compiler_version=subprocess.check_output(shlex.split(host_cxx) + ['--version'], text=True))
    if args.phase == 'smoke':
        result['smoke_source_sha256'] = inputs.digest(PORT / 'tests/v8-smoke.cc')
    try:
        result['configuration'] = validate_configuration(source)
        result['config_sha256'] = inputs.digest(source / 'config.gypi')
        if before_config is not None and before_config != result['config_sha256']:
            raise ValueError('build changed config.gypi; rerun configure and investigate regeneration')
    except (ValueError, OSError, KeyError) as error:
        result['configuration_error'] = str(error)
        result['build_exit_code'] = result['exit_code']
        result['exit_code'] = 1
    (evidence / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'Evidence: {evidence}', flush=True)
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
