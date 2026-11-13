#!/usr/bin/env python3
"""Explicit-target SSH/WASM evidence capture; requires a provisioned test board.

Run upload before an operator-controlled reboot, then verify with the same
fixtures. Does not configure identity, authorize clients, reboot or qualify
physical hardware/entropy. No retries and no implicit host/key defaults.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

import wasi_threads_cases


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--user', required=True)
    p.add_argument('--identity', type=Path, required=True)
    p.add_argument('--known-hosts', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--phase', choices=['upload', 'verify'], required=True)
    p.add_argument('--baseline', type=Path, help='successful upload summary, required for verify')
    p.add_argument('--command-module', type=Path, required=True)
    p.add_argument('--trap-module', type=Path, required=True)
    p.add_argument('--thread-fixtures', type=Path)
    p.add_argument('--pthread-module', type=Path)
    a = p.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]*', a.host):
        p.error('host must be an explicit hostname or IP address without SSH options')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', a.user):
        p.error('invalid SSH user')
    if not 1 <= a.port <= 65535:
        p.error('port out of range')
    if bool(a.thread_fixtures) != bool(a.pthread_module):
        p.error('thread fixtures and pthread module must be supplied together')
    if (a.phase == 'verify') != bool(a.baseline):
        p.error('--baseline is required only for verify')
    for path in [a.identity, a.known_hosts]:
        if not path.is_file():
            p.error(f'required file missing: {path}')
    return a


def modules_for(a):
    modules = {'mars-accept-hello.wasm': a.command_module.read_bytes(),
               'mars-accept-trap.wasm': a.trap_module.read_bytes()}
    if a.thread_fixtures:
        modules.update({'mars-accept-' + name + '.wasm':
                        (a.thread_fixtures / (name + '.wasm')).read_bytes()
                        for name, _ in wasi_threads_cases.FIXTURES})
        modules['mars-accept-pthreads.wasm'] = a.pthread_module.read_bytes()
    for name, data in modules.items():
        if not (8 <= len(data) <= 512 * 1024 and data.startswith(b'\0asm\x01\0\0\0')):
            raise ValueError(f'invalid or oversized core WASM fixture: {name}')
    return modules


def ssh_base(a, known_hosts=None):
    return ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes',
            '-o', 'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=yes',
            '-o', f'UserKnownHostsFile={(known_hosts or a.known_hosts).resolve()}',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentityAgent=none',
            '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-i', str(a.identity.resolve()), '-p', str(a.port), f'{a.user}@{a.host}']


def run(a):
    modules = modules_for(a)
    # Copy only public host pins and fixture bytes, never private credentials.
    pins = a.known_hosts.read_bytes()
    entries = [line.split() for line in pins.decode('ascii').splitlines()
               if line.strip() and not line.lstrip().startswith('#')]
    if len(entries) != 1 or len(entries[0]) < 3 or entries[0][1] != 'ssh-ed25519':
        raise ValueError('provide a dedicated known-hosts file with exactly one Ed25519 host pin')
    host_key = ' '.join(entries[0][1:3])
    result = {'status': 'running', 'phase': a.phase, 'host': a.host, 'port': a.port,
              'user': a.user, 'physical_acceptance': False, 'entropy_qualified': False,
              'cold_boot_verified': False, 'native_backend_verified': False,
              'multi_hart_execution_verified': False, 'retries': 0,
              'thread_checks_requested': bool(a.thread_fixtures),
              'fixture_sha256': {n: hashlib.sha256(b).hexdigest() for n, b in modules.items()},
              'known_hosts_sha256': hashlib.sha256(pins).hexdigest(),
              'host_public_key': host_key, 'commands': []}
    if a.phase == 'verify':
        if a.baseline is None:
            raise ValueError('verify requires a successful upload summary')
        previous = a.baseline.read_bytes()
        baseline = json.loads(previous)
        if (baseline.get('status') != 'ssh-command-checks-passed'
                or baseline.get('phase') != 'upload'
                or baseline.get('fixture_sha256') != result['fixture_sha256']
                or baseline.get('host_public_key') != host_key
                or baseline.get('user') != a.user):
            raise ValueError('upload baseline, fixture hashes, host public key or user changed')
        result['baseline_sha256'] = hashlib.sha256(previous).hexdigest()
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'known-hosts').write_bytes(pins)
    # Pin the exact snapshot recorded as evidence throughout this run.
    base = ssh_base(a, a.output / 'known-hosts')
    def save():
        (a.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    save()

    def execute(words, data=b'', status=0, stdout=b'', stderr=b''):
        sequence = len(result['commands']) + 1
        started = time.monotonic()
        record = {'command': words, 'expected_status': status,
                  'stdin_bytes': len(data), 'stdin_sha256': hashlib.sha256(data).hexdigest()}
        result['commands'].append(record)
        try:
            completed = subprocess.run([*base, shlex.join(words)], input=data,
                                       capture_output=True, timeout=120)
            code, out, err = completed.returncode, completed.stdout, completed.stderr
        except subprocess.TimeoutExpired as e:
            code, out, err = None, e.stdout or b'', e.stderr or b''
            record['timeout'] = True
        for label, payload in [('stdout', out), ('stderr', err)]:
            path = a.output / f'{sequence:03d}-{label}.bin'
            path.write_bytes(payload)
            record[label] = {'path': path.name, 'bytes': len(payload),
                             'sha256': hashlib.sha256(payload).hexdigest()}
        record.update(status=code, elapsed_seconds=time.monotonic() - started,
                      passed=(code, out, err) == (status, stdout, stderr))
        save()
        if not record['passed']:
            raise RuntimeError(f'command {sequence} failed: {shlex.join(words)}')

    try:
        execute(['echo', 'mars-accept-ready'], stdout=b'mars-accept-ready\n')
        if a.phase == 'upload':
            for name, data in modules.items():
                execute(['wasm-upload', name, str(len(data)), hashlib.sha256(data).hexdigest()], data)
        command = ['wasm-run', 'mars-accept-hello.wasm']
        execute(command, stdout=b'Hello from C WASI!\n')
        execute([*command, 'args', 'a b', '中文'], stdout='a b\n中文\n'.encode())
        data = b'ab\0cde\n' * 1900
        execute([*command, 'filter'], data, stdout=data.upper())
        execute([*command, 'filter'])
        execute([*command, 'stderr'], stdout=b'out\n', stderr=b'err\n')
        execute([*command, 'exit'], status=7)
        execute(['wasm-run', 'mars-accept-trap.wasm'], status=125)
        if a.thread_fixtures:
            for name, status in wasi_threads_cases.FIXTURES:
                execute(['wasm-run', 'mars-accept-' + name + '.wasm'], status=status)
            for args, status, stdout in wasi_threads_cases.PTHREADS:
                execute(['wasm-run', 'mars-accept-pthreads.wasm', *args], status=status, stdout=stdout)
        result['status'] = 'ssh-command-checks-passed'
    except BaseException as e:
        result['status'] = 'failed'
        result['error'] = f'{type(e).__name__}: {e}'
        raise
    finally:
        save()
    return result


if __name__ == '__main__':
    print(json.dumps(run(parse_args()), indent=2))
