#!/usr/bin/env python3
"""Cross-compile upstream libuv common code; NOT an event-loop execution gate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ('timer.c', 'uv-common.c', 'uv-data-getter-setters.c', 'version.c',
           'idna.c', 'inet.c', 'strscpy.c', 'strtok.c', 'thread-common.c')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve() / 'deps/uv'
    work = args.work.resolve()
    if work.exists() or not work.is_relative_to(ROOT / 'target'):
        parser.error('--work must be a fresh directory under target')
    work.mkdir(parents=True)
    cc = ROOT / ('target/node-runtime/toolchain/'
                 'xpack-riscv-none-elf-gcc-14.2.0-3/bin/riscv-none-elf-gcc')
    results = []
    for name in SOURCES:
        command = [str(cc), '-std=gnu11', '-O2', '-Wall', '-Wextra',
                   '-Werror=implicit-function-declaration',
                   '-march=rv64gc', '-mabi=lp64d', '-mcmodel=medany',
                   '-D__vibeos__=1', '-I' + str(source / 'include'),
                   '-I' + str(source / 'src'), '-c', str(source / 'src' / name),
                   '-o', str(work / (name + '.o'))]
        with (work / (name + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        results.append(dict(source=name, command=command, exit_code=result.returncode))
    inputs = list((source / 'include').rglob('*.h'))
    inputs += [source / 'src' / name for name in SOURCES]
    inputs += list((source / 'src').glob('*.h'))
    report = dict(scope='libuv common target objects only; backend/link/runtime NOT_RUN',
                  compiler=subprocess.check_output([str(cc), '--version'], text=True),
                  source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sorted(inputs)}, results=results,
                  passed=all(r['exit_code'] == 0 for r in results))
    (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print([(r['source'], r['exit_code']) for r in results])
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
