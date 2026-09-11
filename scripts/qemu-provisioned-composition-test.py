#!/usr/bin/env python3
"""Two-boot provisioned SSH handshake check on disposable QEMU media.

Build qemu-hal-test with boot-admission-test,ssh-composition-test,
entropy-composition-test first. Uses host /dev/urandom and no fixed host identity.
Proves key exchange and persisted public identity, not authentication/WASM or
physical entropy quality. Never use the generated disk as a production identity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time


def boot(kernel, output, disk, number):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    kernel = args.kernel.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    disk = output / 'disposable-data.raw'
    with disk.open('xb') as f:
        f.truncate(128 * 1024 * 1024)
    first = boot(kernel, output, disk, 1)
    second = boot(kernel, output, disk, 2)
    if first != second:
        raise RuntimeError('provisioned public host identity changed across reboot')
    result = {'status': 'passed', 'boots': 2, 'harts': 4, 'selftests_per_boot': 395,
              'host_public_key': ' '.join(first), 'identity_persisted': True,
              'authentication_tested': False, 'wasm_tested': False,
              'physical_acceptance': False,
              'kernel_sha256': hashlib.sha256(kernel.read_bytes()).hexdigest()}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
