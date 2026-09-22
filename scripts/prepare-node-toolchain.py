#!/usr/bin/env python3
"""Install the checksum-pinned bare-metal C++ compiler used by the V8 port."""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT / 'target/node-runtime')
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    args.work = args.work.resolve()
    if not args.work.is_relative_to((ROOT / 'target').resolve()) or args.work == (ROOT / 'target').resolve():
        parser.error('--work must be a subdirectory of this repository\'s target directory')
    spec = importlib.util.spec_from_file_location('node_runtime', ROOT / 'scripts/node-runtime.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    lock_path = ROOT / 'tools/node-runtime/toolchain.lock.json'
    lock = json.loads(lock_path.read_text())
    architecture = {'aarch64': 'arm64', 'arm64': 'arm64',
                    'x86_64': 'x64', 'AMD64': 'x64'}.get(platform.machine())
    host = f'{platform.system().lower()}-{architecture}'
    if host not in lock['platforms']:
        parser.error(f'no pinned compiler for {host}')
    artifact = lock['platforms'][host]
    archive = helper.fetch({'archive': artifact['fileName'],
        'url': lock['base_url'] + '/' + artifact['fileName'],
        'sha256': artifact['sha256']}, args.work / 'downloads', args.offline)
    parent = args.work.resolve() / 'toolchain'
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / lock['directory']
    # Always reinstall from the verified archive; an existing compiler is not
    # accepted merely because its --version string matches. The data filter
    # permits the distribution's internal symlinks, but rejects escaping links.
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        staging = Path(temporary)
        with tarfile.open(archive) as source:
            for entry in source.getmembers():
                parts = Path(entry.name).parts
                if not parts or parts[0] != lock['directory']:
                    raise ValueError(f'unexpected archive root: {entry.name}')
            source.extractall(staging, filter='data')
        if destination.is_symlink():
            raise ValueError(f'refusing symlink destination: {destination}')
        if destination.exists():
            shutil.rmtree(destination)
        (staging / lock['directory']).replace(destination)
    compiler = destination / 'bin/riscv-none-elf-g++'
    version = subprocess.check_output([compiler, '--version'], text=True)
    multilib = subprocess.check_output([compiler, '-march=rv64gc', '-mabi=lp64d',
        '-print-file-name=libstdc++.a'], text=True).strip()
    if not Path(multilib).is_file():
        raise RuntimeError('RV64GC LP64D static C++ runtime missing')
    report = {'host': host, 'lock_sha256': helper.digest(lock_path),
              'archive_sha256': helper.digest(archive), 'compiler': str(compiler),
              'version': version, 'libstdcxx': multilib,
              'libstdcxx_sha256': helper.digest(Path(multilib))}
    (parent / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
    print(compiler)


if __name__ == '__main__':
    main()
