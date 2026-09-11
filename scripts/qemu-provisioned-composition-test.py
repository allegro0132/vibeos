#!/usr/bin/env python3
"""Two-boot provisioned SSH/WASI composition check on disposable QEMU media.

Build qemu-hal-test with boot-admission-test,ssh-composition-test,
entropy-composition-test first. Uses host /dev/urandom and no fixed host identity.
Optional --command-module/--trap-module also test public-key authentication,
upload, WASI IO/arguments/exit/traps and persistence. Build command-composition-test
instead of ssh-composition-test for that mode. Does not test threads or physical
entropy quality. Never use the generated disk as a production identity.
Command checks never reconnect or replay on failure. PCAP files are retained
for virtual TCP close/accept diagnostics.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import time


def boot(kernel, output, disk, number, modules=None, expected_key=None):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    path = output / f'boot-{number}.log'
    with path.open('xb') as log:
        vm = subprocess.Popen([
            'qemu-system-riscv64', '-machine', 'virt', '-cpu', 'rv64', '-smp', '4',
            '-m', '128M', '-nographic', '-bios', 'default', '-kernel', str(kernel),
            '-global', 'virtio-mmio.force-legacy=false',
            '-drive', f'if=none,id=data,format=raw,file={disk}',
            '-device', 'virtio-blk-device,drive=data',
            '-object', 'rng-random,filename=/dev/urandom,id=rng0',
            '-device', 'virtio-rng-device,rng=rng0',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22',
            '-object', f'filter-dump,id=capture,netdev=net0,file={output / f"network-{number}.pcap"}',
            '-device', 'virtio-net-device,netdev=net0'],
            stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
        try:
            time.sleep(2)
            vm.stdin.write(b'quiet\ncaps virtio-rng\ncaps sshd\nselftest\n')
            vm.stdin.flush()
            deadline = time.monotonic() + 45
            key = None
            attempts = []
            while time.monotonic() < deadline and vm.poll() is None:
                known = output / f'known-hosts-{number}'
                # ssh-keyscan does not negotiate Sunset's required strict KEX.
                # A normal OpenSSH client verifies transport signatures, then
                # deliberately stops at authentication without offering secrets.
                scan = subprocess.run([
                    'ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=accept-new',
                    '-o', f'UserKnownHostsFile={known}', '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'HashKnownHosts=no', '-o', 'HostKeyAlgorithms=ssh-ed25519',
                    '-o', 'PreferredAuthentications=none', '-o', 'IdentityAgent=none',
                    '-o', 'IdentityFile=none', '-o', 'ConnectTimeout=2',
                    '-o', 'ConnectionAttempts=1', '-p', str(port), 'vibe@127.0.0.1'],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
                attempts.append(scan.stderr + scan.stdout)
                keys = [line.split()[1:3] for line in
                        (known.read_text().splitlines() if known.exists() else [])
                        if not line.startswith('#') and len(line.split()) == 3]
                if (scan.returncode == 255 and 'Permission denied' in scan.stderr
                        and len(keys) == 1 and keys[0][0] == 'ssh-ed25519'):
                    key = keys[0]
                    break
                time.sleep(0.25)
            (output / f'handshake-{number}.log').write_text('\n'.join(attempts))
            if key is None:
                raise RuntimeError(f'boot {number}: no provisioned SSH handshake; inspect {path}')
            if expected_key is not None and key != expected_key:
                raise RuntimeError('host identity changed before authenticated commands')
            if modules is not None:
                commands(table_path=path, output=output, vm=vm, port=port,
                         number=number, modules=modules)
            time.sleep(1)
        finally:
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait()
            vm.stdin.close()
    text = path.read_text(errors='replace')
    if 'no such space: sshd' in text or 'no such space: virtio-rng' in text:
        raise RuntimeError('required capability absent')
    if 'selftest: 395 passed, 0 failed' not in text:
        raise RuntimeError('kernel selftest did not pass')
    return key


def commands(table_path, output, vm, port, number, modules):
    key = output / 'client-key'
    if number == 1:
        public = key.with_suffix('.pub').read_text().split()
        assert public[0] == 'ssh-ed25519'
        offset = table_path.stat().st_size
        vm.stdin.write(('vsh ssh-authorize add ' + ' '.join(public[:2]) + '\n').encode())
        vm.stdin.flush()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if b'ssh-authorize: client key persisted; password authentication disabled' in table_path.read_bytes()[offset:]:
                break
            if vm.poll() is not None:
                raise RuntimeError('QEMU stopped during key authorization')
            time.sleep(0.05)
        else:
            raise RuntimeError('client public key was not persisted')
    base = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes',
            '-o', 'LogLevel=ERROR',
            '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={output / f"known-hosts-{number}"}',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentityAgent=none',
            '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
            '-o', 'ConnectTimeout=2', '-i', str(key), '-p', str(port), 'vibe@127.0.0.1']
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready = subprocess.run([*base, 'echo ready'], input=b'', capture_output=True, timeout=5)
        if ready.returncode == 0 and ready.stdout == b'ready\n':
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('persisted client key did not authenticate')
    evidence = []
    def execute(words, data=b'', status=0, stdout=b'', stderr=b''):
        result = subprocess.run([*base, shlex.join(words)], input=data,
                                capture_output=True, timeout=30)
        evidence.append({'command': words, 'status': result.returncode,
                         'preauth_retry': False,
                         'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex()})
        (output / f'commands-{number}.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if (result.returncode, result.stdout, result.stderr) != (status, stdout, stderr):
            raise RuntimeError(f'command mismatch: {words}; inspect commands-{number}.json')
    # Boot two deliberately skips both authorization and upload.
    if number == 1:
        for name, data in modules.items():
            execute(['wasm-upload', name, str(len(data)), hashlib.sha256(data).hexdigest()], data)
    run = ['wasm-run', 'composition-hello.wasm']
    execute(run, stdout=b'Hello from C WASI!\n')
    execute([*run, 'args', 'a b', '中文'], stdout='a b\n中文\n'.encode())
    data = b'ab\0cde\n' * 1900
    execute([*run, 'filter'], data, stdout=data.upper())
    execute([*run, 'filter'])
    execute([*run, 'stderr'], stdout=b'out\n', stderr=b'err\n')
    execute([*run, 'exit'], status=7)
    execute(['wasm-run', 'composition-trap.wasm'], status=125)
    # No pacing or reconnect retry: a successor SYN may overlap the previous
    # command's passive TCP close. Each connection gets a fresh SSH session.
    for index in range(16):
        execute(['echo', f'connection-{index}'], stdout=f'connection-{index}\n'.encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--command-module', type=Path, help='compiled tests/wasi/hello.c module')
    parser.add_argument('--trap-module', type=Path, help='fixture exporting an immediately trapping _start')
    args = parser.parse_args()
    if bool(args.command_module) != bool(args.trap_module):
        parser.error('--command-module and --trap-module must be supplied together')
    modules = None if args.command_module is None else {
        'composition-hello.wasm': args.command_module.read_bytes(),
        'composition-trap.wasm': args.trap_module.read_bytes()}
    if modules is not None and any(not (8 <= len(b) <= 512 * 1024 and b.startswith(b'\0asm\x01\0\0\0')) for b in modules.values()):
        parser.error('fixtures must be bounded core WASM modules')
    kernel = args.kernel.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    frozen_kernel = output / 'kernel.elf'
    shutil.copyfile(kernel, frozen_kernel)
    kernel = frozen_kernel
    kernel_hash = hashlib.sha256(kernel.read_bytes()).hexdigest()
    if modules is not None:
        fixtures = output / 'fixtures'
        fixtures.mkdir()
        for name, data in modules.items():
            (fixtures / name).write_bytes(data)
    disk = output / 'disposable-data.raw'
    with disk.open('xb') as f:
        f.truncate(128 * 1024 * 1024)
    if modules is not None:
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-f', str(output / 'client-key')], check=True)
    first = boot(kernel, output, disk, 1, modules)
    second = boot(kernel, output, disk, 2, modules, first)
    if first != second:
        raise RuntimeError('provisioned public host identity changed across reboot')
    if hashlib.sha256(kernel.read_bytes()).hexdigest() != kernel_hash:
        raise RuntimeError('frozen kernel changed during the test')
    result = {'status': 'passed', 'boots': 2, 'harts': 4, 'selftests_per_boot': 395,
              'host_public_key': ' '.join(first), 'identity_persisted': True,
              'authentication_tested': modules is not None, 'wasm_tested': modules is not None,
              'wasm_threads_tested': False,
              'command_retries_allowed': False,
              'consecutive_echo_connections_per_boot': 0 if modules is None else 16,
              'module_sha256': {} if modules is None else {n: hashlib.sha256(b).hexdigest() for n, b in modules.items()},
              'physical_acceptance': False,
              'kernel_sha256': kernel_hash,
              'preauth_command_retries': 0 if modules is None else sum(
                  int(item['preauth_retry']) for n in [1, 2] for item in
                  json.loads((output / f'commands-{n}.json').read_text()))}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
