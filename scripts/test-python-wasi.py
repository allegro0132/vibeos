#!/usr/bin/env python3
"""Exact-output CPython acceptance against a host runner or the QEMU SSH image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

CASES = [
    ('arithmetic', ['-c', 'print(sum(i*i for i in range(100))); print(2**100)'], b'',
     b'328350\n1267650600228229401496703205376\n', b'', 0),
    ('stdlib', ['-c', 'import json, math, fractions, collections; print(json.dumps({"answer": math.isqrt(1764)}, sort_keys=True)); print(fractions.Fraction(2, 3) + fractions.Fraction(1, 6)); print(collections.Counter("ababa")["a"])'], b'',
     b'{"answer": 42}\n5/6\n3\n', b'', 0),
    ('unicode-argv', ['-c', 'import sys; print(repr(sys.argv[1:])); print("你好，Python")', 'a b', '中文'], b'',
     "['a b', '中文']\n你好，Python\n".encode(), b'', 0),
    ('stdlib-helpers', ['-c', 'import dataclasses, inspect, pathlib, traceback, datetime; print(pathlib.PurePosixPath("a") / "b"); print(datetime.datetime.strptime("2026-09-09", "%Y-%m-%d").date()); print("helpers OK")'], b'',
     b'a/b\n2026-09-09\nhelpers OK\n', b'', 0),
    ('stdin', ['-'], 'import sys\nprint("stdin 脚本", 6*7)\n'.encode(),
     'stdin 脚本 42\n'.encode(), b'', 0),
    ('streams-exit', ['-c', 'import sys; print("out"); print("err", file=sys.stderr); sys.exit(7)'], b'', b'out\n', b'err\n', 7),
    ('no-filesystem', ['-c', 'import os; print(os.listdir("/"))'], b'', None, None, 1),
    ('exception', ['-c', 'raise ValueError("python-wasi-error")'], b'', None, None, 1),
    ('reuse', ['-c', 'print("PYTHON_WASI PASS")'], b'', b'PYTHON_WASI PASS\n', b'', 0),
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runner', type=Path, help='host wasi-runtime run example')
    p.add_argument('--module', type=Path, default=Path('target/python-wasi/python.wasm'))
    p.add_argument('--work', type=Path, default=Path('target/python-wasi/acceptance'))
    p.add_argument('--ssh-work', type=Path, default=Path('target/wasi-qemu'))
    p.add_argument('--port', type=int, default=22222)
    p.add_argument('--skip-upload', action='store_true', help='reuse python.wasm already uploaded to this image')
    p.add_argument('--boot', action='store_true', help='start and stop the already-built Python QEMU image')
    p.add_argument('--boot-timeout', type=int, default=900, help='allow persistent-store recovery before SSH execution')
    args = p.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    if args.runner and args.boot:
        p.error('--boot and --runner are mutually exclusive')
    qemu = None
    try:
        if args.boot:
            env = os.environ.copy()
            env.update(WASI_PYTHON='1', WASI_SKIP_BUILD='1', WASI_WORK_DIR=str(args.ssh_work),
                       WASI_SSH_PORT=str(args.port))
            with (args.work / 'qemu.log').open('wb') as log:
                qemu = subprocess.Popen(['scripts/run-wasi-qemu.sh'], env=env, stdin=subprocess.PIPE,
                                        stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + args.boot_timeout
            while 'vsh> ' not in (args.work / 'qemu.log').read_text(errors='replace'):
                if qemu.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('QEMU did not become ready; see qemu.log')
                time.sleep(0.2)
        check_cases(args)
    finally:
        if qemu is not None:
            qemu.terminate()
            try:
                qemu.wait(timeout=10)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait()


def check_cases(args):
    client = [sys.executable, 'scripts/wasi-client.py', '--python', '--port', str(args.port),
              '--identity', str(args.ssh_work / 'id_ed25519'),
              '--known-hosts', str(args.ssh_work / 'known_hosts')]
    if not args.runner and not args.skip_upload:
        subprocess.run(client + ['upload', str(args.module), '--name', 'python.wasm'], check=True, timeout=600)
    results = []
    for name, argv, stdin, stdout, stderr, status in CASES:
        command = ([str(args.runner.resolve()), str(args.module.resolve())] if args.runner
                   else client + ['run', 'python.wasm']) + argv
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=600)
        err = result.stderr
        if args.runner:
            # Diagnostic runner retains exact guest exit in its terminal record.
            terminal = f'terminal=Exited({status})'.encode()
            assert terminal in err, (name, result.returncode, err[-3000:])
            err = b'\n'.join(line for line in err.split(b'\n')
                             if not line.startswith((b'setup_seconds=', b'terminal=')))
        else:
            assert result.returncode == status, (name, result.returncode, result.stderr[-3000:])
        (args.work / (name + '.stdout')).write_bytes(result.stdout)
        (args.work / (name + '.stderr')).write_bytes(result.stderr)
        if stdout is not None:
            assert result.stdout == stdout, (name, result.stdout, stdout)
            assert err == stderr, (name, err, stderr)
        elif name == 'exception':
            assert b'ValueError: python-wasi-error' in err, err
        else:
            assert b'OSError' in err or b'FileNotFoundError' in err, err
        results.append({'case': name, 'guest_exit': status})
        print(name + ': PASS', flush=True)
    if args.boot:
        log = (args.work / 'qemu.log').read_text(errors='replace')
        assert log.count('reclaimed=true caps=0 waiters=0') == len(CASES), \
            'each guest must reclaim its arena, capabilities and waiters'
    (args.work / 'results.json').write_text(json.dumps({
        'backend': 'host-wasmi' if args.runner else 'qemu-ssh',
        'module_sha256': hashlib.sha256(args.module.read_bytes()).hexdigest(),
        'cases': results,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
