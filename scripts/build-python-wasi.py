#!/usr/bin/env python3
"""Build a self-contained CPython command with the reviewed wasi-sdk 33.

Supply the unmodified Python-3.14.0 release source and its native build Python.
Downloads are deliberately separate from this repeatable, offline build step.
"""
import argparse
import hashlib
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--build-python', type=Path, required=True)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--work', type=Path, default=ROOT / 'target/python-wasi')
    p.add_argument('--jobs', type=int, default=8)
    p.add_argument('--skip-configure', action='store_true', help='reuse this work directory\'s configured WASI build')
    args = p.parse_args()
    source, python, sdk, work = (x.resolve() for x in
                               (args.source, args.build_python, args.sdk, args.work))
    version = subprocess.check_output([python, '-c', 'import platform; print(platform.python_version())'], text=True).strip()
    if version != '3.14.0':
        p.error('build Python must be exactly 3.14.0 (frozen bytecode producer)')
    compiler = subprocess.check_output([sdk / 'bin/clang', '--version'], text=True)
    if '22.1.0-wasi-sdk' not in compiler:
        p.error('wasi-sdk 33 (clang 22.1.0-wasi-sdk) is required')
    work.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(CC=str(sdk / 'bin/clang'), AR=str(sdk / 'bin/llvm-ar'),
               RANLIB=str(sdk / 'bin/llvm-ranlib'),
               CONFIG_SITE=str(source / 'Tools/wasm/wasi/config.site-wasm32-wasi'),
               CFLAGS='-O2 -mno-simd128 -mno-relaxed-simd -mno-extended-const',
               LDFLAGS='-Wl,--max-memory=67108864 -Wl,-z,stack-size=1048576',
               CPPFLAGS='', PKG_CONFIG_PATH='',
               PKG_CONFIG_LIBDIR=str(sdk / 'share/wasi-sysroot/lib/pkgconfig'),
               PKG_CONFIG_SYSROOT_DIR=str(sdk / 'share/wasi-sysroot'),
               SOURCE_DATE_EPOCH='1759708800')
    build = subprocess.check_output([source / 'config.guess'], text=True).strip()
    if not args.skip_configure:
        run([source / 'configure', '--host=wasm32-wasi', f'--build={build}',
             f'--with-build-python={python}', '--without-ensurepip', '--disable-test-modules'],
            cwd=work, env=env)
    run(['make', f'-j{args.jobs}', 'libpython3.14.a'], cwd=work, env=env)
    run([python, ROOT / 'scripts/freeze-python-wasi.py', source / 'Lib', work / 'frozen-stdlib.h'])
    # Retain CPython's actual library closure (mpdecimal, expat, HACL, wasi-libc)
    # instead of guessing libraries or accidentally linking host dependencies.
    libraries = subprocess.check_output([
        'make', '--no-print-directory', '-f', '-', 'vibe-print-libs'],
        input='include Makefile\nvibe-print-libs:\n\t@echo $(LIBS) $(MODLIBS) $(SYSLIBS)\n',
        cwd=work, env=env, text=True)
    run([sdk / 'bin/clang', '--target=wasm32-wasip1', '-O2',
         '-I' + str(work), '-I' + str(source / 'Include'),
         ROOT / 'tests/python-wasi/main.c', work / 'libpython3.14.a',
         *shlex.split(libraries),
         '-Wl,--max-memory=67108864', '-Wl,-z,stack-size=1048576', '-Wl,--strip-all',
         '-o', work / 'python.wasm'], cwd=work, env=env)
    module = (work / 'python.wasm').read_bytes()
    (work / 'build.json').write_text(json.dumps({
        'python': version, 'compiler': compiler, 'bytes': len(module),
        'sha256': hashlib.sha256(module).hexdigest(),
    }, indent=2) + '\n')
    print(work / 'python.wasm')


if __name__ == '__main__':
    main()
