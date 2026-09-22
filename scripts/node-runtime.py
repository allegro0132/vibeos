#!/usr/bin/env python3
"""Fetch pinned JS toolchain inputs and record prerequisites for the native port.

This is a feasibility probe, not a Node implementation or a QEMU acceptance gate.
It never executes JavaScript on the host as a substitute for target execution.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'tools/node-runtime/sources.lock.json'


def rust_tools():
    """Resolve both Cargo and rustc; rustup run alone can inherit a host rustc."""
    channel = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    tools = {name: subprocess.check_output(
        ['rustup', 'which', '--toolchain', channel, name], text=True).strip()
        for name in ('cargo', 'rustc', 'rustdoc')}
    return tools, dict(os.environ, RUSTC=tools['rustc'], RUSTDOC=tools['rustdoc'])


def digest(path, algorithm='sha256'):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def verify(path, artifact):
    if 'sha256' in artifact and digest(path) != artifact['sha256']:
        raise ValueError(f'{path}: SHA-256 mismatch')
    if 'integrity' in artifact:
        algorithm, expected = artifact['integrity'].split('-', 1)
        if algorithm != 'sha512':
            raise ValueError('only SHA-512 package integrity is supported')
        actual = base64.b64encode(bytes.fromhex(digest(path, algorithm))).decode()
        if actual != expected:
            raise ValueError(f'{path}: package integrity mismatch')
    if not {'sha256', 'integrity'} & artifact.keys():
        raise ValueError('artifact has no pinned checksum')


def fetch(artifact, downloads, offline):
    path = downloads / artifact['archive']
    if path.exists():
        verify(path, artifact)
        return path
    if offline:
        raise FileNotFoundError(f'missing cached artifact: {path}')
    downloads.mkdir(parents=True, exist_ok=True)
    # An interrupted or unverified download can never replace a verified input.
    with tempfile.NamedTemporaryFile(dir=downloads, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            with urllib.request.urlopen(artifact['url'], timeout=120) as source:
                shutil.copyfileobj(source, stream)
            stream.close()
            verify(temporary, artifact)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    return path


def extract(archive, destination, member):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        staging = Path(temp) / 'tree'
        staging.mkdir()
        with tarfile.open(archive) as source:
            # Disallow links, devices, absolute paths and traversal even for
            # checksum-verified archives. No install scripts are executed.
            for entry in source.getmembers():
                parts = Path(entry.name).parts
                if (Path(entry.name).is_absolute() or '..' in parts
                        or not (entry.isfile() or entry.isdir())):
                    raise ValueError(f'unsafe archive entry: {entry.name}')
            source.extractall(staging, filter='data')
        if not (staging / member).is_file():
            raise ValueError(f'archive is missing {member}')
        if destination.is_symlink():
            raise ValueError(f'refusing symlink destination: {destination}')
        if destination.exists():
            shutil.rmtree(destination)
        staging.replace(destination)


def check(name, command, evidence, cwd=ROOT, timeout=120, env=None):
    started = time.monotonic()
    out, err = evidence / f'{name}.stdout', evidence / f'{name}.stderr'
    timed_out = False
    with out.open('wb') as stdout, err.open('wb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        except OSError as error:
            stderr.write(str(error).encode())
            code = 127
    result = {'name': name, 'command': [str(x) for x in command], 'cwd': str(cwd),
              'exit_code': code, 'timeout': timed_out,
              'seconds': round(time.monotonic() - started, 3),
              'stdout': out.name, 'stderr': err.name}
    print(f'{name}: {"OK" if code == 0 else "BLOCKED"} (exit {code})', flush=True)
    return result


def probe(args, lock):
    # Re-extract verified inputs; previous configure output or edited source
    # trees are not accepted as evidence for the pinned upstream source.
    for name in ('node', 'esbuild'):
        artifact = lock['artifacts'][name]
        archive = fetch(artifact, args.work / 'downloads', offline=True)
        extract(archive, args.work / 'unpacked' / name, artifact['member'])
    node = args.work / 'unpacked/node' / f'node-v{lock["artifacts"]["node"]["version"]}'
    module = args.work / 'unpacked/esbuild/package/esbuild.wasm'
    if digest(module) != lock['artifacts']['esbuild']['module_sha256']:
        raise ValueError('esbuild module SHA-256 mismatch')
    evidence = Path(tempfile.mkdtemp(prefix='probe-', dir=args.work))
    report = {'schema': 1, 'kind': 'prerequisites-only',
              'runtime_acceptance': 'NOT_RUN', 'qemu_execution': 'NOT_RUN',
              'wasi_profile': args.wasi_profile,
              'source_lock_sha256': digest(LOCK),
              'esbuild_module_sha256': digest(module), 'checks': []}
    report['repository_commit'] = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    (evidence / 'repository-status.txt').write_bytes(subprocess.check_output(
        ['git', 'status', '--short'], cwd=ROOT))
    (evidence / 'sources.lock.json').write_bytes(LOCK.read_bytes())
    checks = report['checks']
    rust, env = rust_tools()
    checks.append(check('rustc-version', [rust['rustc'], '-Vv'], evidence))
    checks.append(check('workspace-resolution',
        [rust['cargo'], 'metadata', '--locked', '--offline', '--format-version=1'], evidence, env=env))
    checks.append(check('node-configure', [sys.executable, 'configure.py',
        '--dest-cpu=riscv64', '--dest-os=vibeos', '--cross-compiling',
        '--without-intl', '--without-ssl', '--v8-options=--jitless'], evidence, cwd=node))
    checks.append(check('cxx-version', [args.cxx, '--version'], evidence))
    header = evidence / 'v8-header.cc'
    header.write_text('#include "v8.h"\nint main() { return v8::V8::GetVersion()[0] == 0; }\n')
    command = [args.cxx]
    if args.cxx_kind == 'clang':
        command += ['--no-default-config', '--target=riscv64-unknown-elf', '-ferror-limit=3']
    command += ['-march=rv64gc', '-mabi=lp64d', '-std=c++20',
               '-fsyntax-only', '-I', str(node / 'deps/v8/include'), str(header)]
    if args.sysroot:
        command.append('--sysroot=' + str(args.sysroot.resolve(strict=True)))
    checks.append(check('v8-target-headers', command, evidence))
    # Independent workspace avoids unrelated network-feature resolution. It
    # compiles the real runtime unchanged, only for host admission diagnostics.
    host = args.work / 'admission-probe'
    host.mkdir(exist_ok=True)
    rust_source = ROOT / 'tools/node-runtime/wasi-probe.rs'
    (host / 'main.rs').write_bytes(rust_source.read_bytes())
    (host / 'Cargo.toml').write_text(
        '[package]\nname="vibeos-node-admission-probe"\nversion="0.1.0"\nedition="2021"\n'
        '[workspace]\n[[bin]]\nname="wasi-probe"\npath="main.rs"\n'
        '[dependencies]\nwasmparser="=0.255.0"\n'
        'vibeos-wasi-runtime={path=' + json.dumps(str(ROOT / 'wasi-runtime'))
        + ',features=[' + json.dumps(args.wasi_profile) + ']}\n')
    # Seed the diagnostic workspace from the repository's versions. Cargo may
    # prune unrelated packages/add this probe, but cannot fetch new versions.
    (host / 'Cargo.lock').write_bytes((ROOT / 'Cargo.lock').read_bytes())
    env['CARGO_TARGET_DIR'] = str(args.work / 'host-target')
    checks.append(check('esbuild-host-admission', [rust['cargo'], 'run', '--offline',
        '--release', '--manifest-path', str(host / 'Cargo.toml'), '--bin', 'wasi-probe',
        '--', str(module)], evidence, timeout=300, env=env))
    shutil.copyfile(host / 'Cargo.lock', evidence / 'host-probe.Cargo.lock')
    report['host_probe_source_sha256'] = digest(rust_source)
    # Record the files that implement the actual admission and default bounds.
    report['runtime_source_sha256'] = {
        str(path.relative_to(ROOT)): digest(path)
        for path in sorted((ROOT / 'wasi-runtime/src').glob('*.rs'))}
    report['status'] = 'BLOCKED' if any(c['exit_code'] != 0 for c in checks) else 'PREREQUISITES_ONLY'
    (evidence / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'Evidence: {evidence}\nRuntime acceptance: NOT_RUN', flush=True)
    return 1 if report['status'] == 'BLOCKED' else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'probe'])
    parser.add_argument('--work', type=Path, default=ROOT / 'target/node-runtime')
    parser.add_argument('--only', nargs='+', choices=['node', 'esbuild', 'typescript', 'tsx'])
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'clang++'))
    parser.add_argument('--cxx-kind', choices=['clang', 'gcc'], default='clang')
    parser.add_argument('--sysroot', type=Path)
    parser.add_argument('--wasi-profile', choices=['python-wasi', 'esbuild-wasi'], default='esbuild-wasi')
    args = parser.parse_args()
    args.work = args.work.resolve()
    if not args.work.is_relative_to((ROOT / 'target').resolve()) or args.work == (ROOT / 'target').resolve():
        parser.error('--work must be a subdirectory of this repository\'s target directory')
    args.work.mkdir(parents=True, exist_ok=True)
    lock = json.loads(LOCK.read_text())
    if lock['schema'] != 1:
        parser.error('unsupported source lock schema')
    if args.action == 'probe' and args.only:
        parser.error('--only applies to fetch')
    try:
        if args.action == 'probe':
            return probe(args, lock)
        for name in args.only or lock['artifacts']:
            path = fetch(lock['artifacts'][name], args.work / 'downloads', args.offline)
            print(f'{name}: verified {path}', flush=True)
        return 0
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f'node-runtime: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
