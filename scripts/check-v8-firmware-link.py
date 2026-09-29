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
import struct
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

def validate_toolkit(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest['schema'] != 1:
        raise ValueError('unsupported toolkit manifest')
    for name, expected in manifest.get('adaptations', {}).get('inputs', {}).items():
        if Path(name).name != name or digest(ROOT / 'tools/node-runtime/toolkit' / name) != expected:
            raise ValueError('toolkit adapter changed; prepare again')
    for name in ('sources.lock.json', 'toolkit.lock.json'):
        if manifest['locks'][name] != digest(ROOT / 'tools/node-runtime' / name):
            raise ValueError('toolkit source lock changed; prepare again')
    packed = hashlib.sha256(b'VIBETOOL1' + struct.pack('<I', len(manifest['files'])))
    for name, metadata in sorted(manifest['files'].items()):
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or path.as_posix() != name:
            raise ValueError('invalid toolkit selector')
        data = (directory / path).read_bytes()
        if len(data) != metadata['bytes'] or hashlib.sha256(data).hexdigest() != metadata['sha256']:
            raise ValueError(f'toolkit file changed: {name}')
        encoded = name.encode('utf-8')
        packed.update(struct.pack('<HI', len(encoded), len(data)))
        packed.update(encoded)
        packed.update(data)
    if packed.hexdigest() != digest(directory / 'toolkit.pack'):
        raise ValueError('toolkit pack does not match manifest')
    return dict(pack_sha256=packed.hexdigest(), manifest_sha256=digest(directory / 'manifest.json'))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', action='store_true', help='link the one-shot Node embedding gate; requires --gate and --uv-archive')
    parser.add_argument('--node-exit-code', type=int, choices=range(256), default=0, metavar='0..255', help='Node exitCode fixture (requires --node)')
    parser.add_argument('--gate', action='store_true', help='build the dedicated 1GiB V8 execution image')
    parser.add_argument('--uv-loop', action='store_true', help='also run the libuv timer/async prerequisite (requires --gate)')
    parser.add_argument('--uv-archive', type=Path, help='link the GYP-built libuv archive instead of individual backend objects')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--node-explicit-exit', action='store_true', help='test active process.exit (requires --node)')
    parser.add_argument('--node-cancel', action='store_true', help='test same-hart infinite-loop cancellation')
    parser.add_argument('--node-main', action='store_true', help='use upstream Node main-module startup from project file')
    parser.add_argument('--node-revoke', action='store_true', help='revoke project parent authority after normal project checks')
    parser.add_argument('--node-repeat', type=int, choices=range(1,101), default=1, metavar='1..100')
    parser.add_argument('--node-entry', action='store_true', help='use reusable launcher ABI instead of inline embedding fixture')
    parser.add_argument('--node-eval', action='store_true', help='exercise upstream -e through launcher ABI')
    parser.add_argument('--node-idle-cancel', action='store_true', help='cancel a native event loop parked on a 60-second timer')
    parser.add_argument('--node-shell', action='store_true', help='build native Node VSH commands without the automatic gate')
    parser.add_argument('--toolkit', type=Path, help='prepared offline tool directory; requires --node-shell')
    parser.add_argument('--esbuild-probe', action='store_true', help='run the native/WASI transform bridge gate')
    parser.add_argument('--js-esbuild-probe', action='store_true', help='register the tool-authorized Node fixture command')
    args = parser.parse_args()
    if args.toolkit and not args.node_shell:
        parser.error('--toolkit requires --node-shell')
    if args.esbuild_probe and not args.toolkit:
        parser.error('--esbuild-probe requires --toolkit')
    if args.js_esbuild_probe and (not args.toolkit or args.esbuild_probe):
        parser.error('--js-esbuild-probe requires --toolkit and excludes --esbuild-probe')
    if args.node_shell and (not args.node or args.node_entry or args.node_main or args.node_eval or args.node_cancel or args.node_idle_cancel or args.node_revoke or args.node_explicit_exit or args.node_exit_code or args.node_repeat != 1):
        parser.error('--node-shell requires --node and excludes gate fixture modes')
    if args.node_idle_cancel and (not args.node_eval or args.node_exit_code != 130 or args.node_cancel or args.node_revoke or args.node_explicit_exit):
        parser.error('--node-idle-cancel requires --node-eval --node-exit-code 130 and excludes other exit fixtures')
    if args.node_eval and (not args.node_entry or args.node_main):
        parser.error('--node-eval requires --node-entry and excludes --node-main')
    if args.node_entry and (not args.node or (not args.node_main and not args.node_eval) or args.node_revoke):
        parser.error('--node-entry requires --node and main/eval mode; excludes fixture revocation')
    if args.node_entry and args.node_cancel and (not args.node_eval or args.node_exit_code != 130):
        parser.error('launcher CPU cancellation requires --node-eval --node-exit-code 130')
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
    if args.uv_loop and not args.gate:
        parser.error('--uv-loop requires --gate')
    if args.node and (not args.gate or not args.uv_archive or args.uv_loop):
        parser.error('--node requires --gate and --uv-archive, and excludes --uv-loop')
    if args.uv_archive and not (args.uv_loop or args.node):
        parser.error('--uv-archive requires --uv-loop or --node')
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
    if args.uv_archive:
        archives.append(args.uv_archive.resolve(strict=True))
    if args.node:
        archives.append(source / 'out/Release/obj.target/libnode.a')
        # Bundled Node dependencies, excluding the already-selected libuv.
        archives += sorted(p for p in (source / 'out/Release/obj.target/deps').rglob('*.a')
                           if p.name != 'libuv.a')
    if any(not archive.is_file() for archive in archives):
        parser.error('target V8 and pinned C/C++ archives must exist')
    work.mkdir(parents=True)
    smoke = work / 'v8-smoke.o'
    smoke_source = ROOT / ('tools/node-runtime/tests/node-smoke.cc' if args.node else 'tools/node-runtime/tests/v8-smoke.cc')
    compile_command = builder.smoke_command(source, cxx, smoke, input_source=smoke_source)
    if args.node:
        fixture = (ROOT / 'tools/node-runtime/tests/node-project-smoke.js').read_text()
        if ')VIBEOSJS"' in fixture:
            parser.error('fixture conflicts with C++ raw-string delimiter')
        (work / 'node-project-smoke.inc').write_text('R"VIBEOSJS(' + fixture + ')VIBEOSJS"\n')
        compile_command += ['-I' + str(work), '-DVIBEOS_NODE_MAIN=' + str(int(args.node_main))]
        compile_command += ['-I' + str(source / 'src'), '-I' + str(source / 'deps/uv/include')]
        compile_command += ['-DVIBEOS_NODE_EXPECTED_EXIT_CODE=' + str(args.node_exit_code)]
        compile_command += ['-DVIBEOS_NODE_EXPLICIT_EXIT=' + str(int(args.node_explicit_exit))]
        compile_command += ['-DVIBEOS_NODE_IDLE_CANCEL=' + str(int(args.node_idle_cancel))]
        compile_command += ['-DVIBEOS_NODE_CANCEL=' + str(int(args.node_cancel))]
        compile_command += ['-DVIBEOS_NODE_REVOKE=' + str(int(args.node_revoke))]
        compile_command += ['-DVIBEOS_NODE_ENTRY=' + str(2 if args.node_eval else int(args.node_entry))]
        compile_command += ['-DVIBEOS_NODE_REPEAT=' + str(args.node_repeat), '-I' + str(ROOT / 'tools/node-runtime/runtime')]
    smoke_input_hash = digest(smoke_source)
    uv_objects = []
    uv_inputs = {}
    if args.node:
        for path in (ROOT / 'tools/node-runtime/tests/node-project-smoke.js',
                     work / 'node-project-smoke.inc'):
            uv_inputs[str(path)] = digest(path)
    if args.uv_loop:
        compile_command += ['-DVIBEOS_UV_LOOP_GATE=1']
        uv = source / 'deps/uv'
        sources = [uv / 'src' / name for name in ('uv-common.c', 'timer.c', 'unix/loop-watcher.c')]
        sources += [ROOT / 'tools/node-runtime/libuv/vibeos-loop.c',
                    ROOT / 'tools/node-runtime/libuv/vibeos-fs.c',
                    ROOT / 'tools/node-runtime/libuv/vibeos-sync.c',
                    ROOT / 'tools/node-runtime/libuv/vibeos-time.c',
                    ROOT / 'tools/node-runtime/libuv/vibeos-stream.c',
                    ROOT / 'tools/node-runtime/libuv/vibeos-env.c',
                    ROOT / 'tools/node-runtime/libuv/vibeos-unavailable.c',
                    ROOT / 'tools/node-runtime/tests/uv-loop-smoke.c',
                    ROOT / 'tools/node-runtime/tests/uv-file-smoke.c',
                       ROOT / 'tools/node-runtime/tests/uv-sync-smoke.c']
        if args.uv_archive:
            sources = [ROOT / 'tools/node-runtime/tests/uv-loop-smoke.c',
                       ROOT / 'tools/node-runtime/tests/uv-file-smoke.c',
                       ROOT / 'tools/node-runtime/tests/uv-sync-smoke.c']
        for index, path in enumerate(sources):
            obj = work / f'uv-{index}.o'
            cmd = [str(tool / 'riscv-none-elf-gcc'), '-std=gnu11', '-O2',
                   '-ffunction-sections', '-fdata-sections', '-D__vibeos__=1',
                   '-march=rv64gc', '-mabi=lp64d', '-mcmodel=medany',
                   '-I' + str(uv / 'include'), '-I' + str(uv / 'src'),
                   '-I' + str(ROOT / 'tools/node-runtime/platform'),
                   '-c', str(path), '-o', str(obj)]
            with (work / f'uv-{index}.log').open('w') as log:
                subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
            uv_objects.append(obj)
            uv_inputs[str(path)] = digest(path)
            uv_inputs[str(obj)] = digest(obj)
        for path in sorted((uv / 'include').rglob('*.h')):
            uv_inputs[str(path)] = digest(path)
        for directory in (uv / 'src', ROOT / 'tools/node-runtime/libuv',
                          ROOT / 'tools/node-runtime/platform'):
            for path in sorted(directory.glob('*.h')):
                uv_inputs[str(path)] = digest(path)
    if args.node:
        for runtime in sorted((ROOT / 'tools/node-runtime/runtime').glob('*.cc')):
            obj = work / (runtime.stem + '.o')
            cmd = builder.smoke_command(source, cxx, obj, input_source=runtime, library='node')
            cmd += ['-I' + str(ROOT / 'tools/node-runtime/runtime'), '-I' + str(ROOT / 'tools/node-runtime/platform')]
            if args.toolkit:
                cmd += ['-DVIBEOS_NODE_TOOLKIT=1']
            with (work / (runtime.stem + '.log')).open('w') as log:
                subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
            uv_objects.append(obj)
            for path in (runtime, runtime.with_suffix('.h'), obj):
                uv_inputs[str(path)] = digest(path)
        # Node's own embedder supplies this source when snapshots are disabled.
        stub = source / 'src/node_snapshot_stub.cc'
        obj = work / 'node-snapshot-stub.o'
        cmd = builder.smoke_command(source, cxx, obj, input_source=stub, library='node')
        with (work / 'node-snapshot-stub.log').open('w') as log:
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
        uv_objects.append(obj)
        uv_inputs[str(stub)] = digest(stub)
        uv_inputs[str(obj)] = digest(obj)
    with (work / 'compile.log').open('w') as log:
        subprocess.run(compile_command, stdout=log, stderr=subprocess.STDOUT, check=True)
    input_hashes = archive_inputs(archives, tool / 'riscv-none-elf-ar')
    (work / 'archive-inputs.json').write_text(json.dumps(input_hashes, indent=2) + '\n')
    entry_objects = ['--undefined=vibeos_node_run'] if args.node_shell else ['--undefined=vibeos_v8_smoke', str(smoke)]
    link_args = [*entry_objects, *map(str, uv_objects), '--start-group',
                 *map(str, archives), '--end-group', '--error-limit=0']
    command = ['rustup', 'run', 'nightly-2026-08-01', 'cargo', 'rustc', '--locked',
               '--offline', '--release', '--target', 'riscv64gc-unknown-none-elf',
               '--features', ('wasi-ssh-upload,native-uv-probe' if args.uv_loop else
                              'wasi-ssh-upload,node-toolkit-probe' if args.js_esbuild_probe else
                              'wasi-ssh-upload,node-esbuild-probe' if args.esbuild_probe else
                              'wasi-ssh-upload,node-toolkit' if args.toolkit else
                              'wasi-ssh-upload,node-runtime' if args.node_shell else
                              'wasi-ssh-upload,node-runtime-gate' if args.gate else
                              'wasi-ssh-upload,native-runtime-probe,native-cxx-probe'),
               '--bin', 'vibeos-qemu-virt', '--',
               *[f'-Clink-arg={arg}' for arg in link_args]]
    env = dict(os.environ)
    toolkit = None
    if args.toolkit:
        toolkit = validate_toolkit(args.toolkit.resolve())
        frozen = work / 'toolkit.pack'
        shutil.copyfile(args.toolkit / 'toolkit.pack', frozen)
        if digest(frozen) != toolkit['pack_sha256']:
            raise ValueError('toolkit changed during copy')
        shutil.copyfile(args.toolkit / 'manifest.json', work / 'toolkit-manifest.json')
        env['VIBEOS_NODE_TOOLKIT'] = str(frozen)
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
    if toolkit:
        report['toolkit'] = toolkit
    if args.uv_loop:
        report['libuv_scope'] = 'timer/async loop prerequisite only; not full libuv or Node'
        report['libuv_inputs_sha256'] = uv_inputs
        report['libuv_archive'] = str(args.uv_archive.resolve()) if args.uv_archive else None
    if args.node:
        report['scope'] = ('Native Node VSH image; execution still required' if args.node_shell else
                           f'Real Node embedding gate ({args.node_repeat} invocation(s)); execution still required')
    report['smoke_source'] = str(smoke_source)
    report['smoke_source_sha256'] = digest(smoke_source)
    report['smoke_object_sha256'] = digest(smoke)
    report['archive_inputs_sha256'] = digest(work / 'archive-inputs.json')
    report['archive_input_count'] = len(input_hashes)
    report['inputs_unchanged_during_link'] = (input_hashes == archive_inputs(archives, tool / 'riscv-none-elf-ar')
                                             and smoke_input_hash == digest(smoke_source))
    if args.uv_loop or args.node:
        report['additional_inputs_sha256'] = uv_inputs
        report['inputs_unchanged_during_link'] &= all(
            digest(Path(path)) == expected for path, expected in uv_inputs.items())
    if not report['inputs_unchanged_during_link']:
        report['build_exit_code'] = report['exit_code']
        report['exit_code'] = 1
        report['error'] = 'archive/object inputs changed during link; result is not qualified'
    if report['exit_code'] == 0:
        kernel = work / ('node-shell.elf' if args.node_shell else 'node-gate.elf' if args.node else 'v8-gate.elf' if args.gate else 'diagnostic-NOT-RUN.elf')
        shutil.copyfile(ROOT / 'target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt', kernel)
        report['kernel'] = str(kernel)
        report['kernel_sha256'] = digest(kernel)
    (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return report['exit_code']

if __name__ == '__main__':
    raise SystemExit(main())
