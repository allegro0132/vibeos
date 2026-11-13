#!/usr/bin/env python3
"""Exercise generic provisioned SSH on QEMU with real RNG and persistent storage.

No SSH port is forwarded. Temporary media contains generated test identities and
is deleted after the run. Logs contain public keys only, never private-key output.
This is software composition evidence, not physical entropy qualification.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def identity(disk):
    data = disk.read_bytes()
    records = []
    position = 0
    while True:
        position = data.find(b'VSSHKEY1', position)
        if position < 0:
            break
        block = data[position:position + 512]
        position += 8
        if len(block) != 512 or crc32c(block[:508]) != int.from_bytes(block[508:], 'little'):
            continue
        version, flags = struct.unpack_from('<HH', block, 8)
        generation = int.from_bytes(block[12:20], 'little')
        if version == 1:
            records.append((generation, flags, block[20:52], block[352:384]))
    assert records, 'no complete, CRC-verified unregistered identity record'
    generation = max(item[0] for item in records)
    latest = set(item for item in records if item[0] == generation)
    assert len(latest) == 1, 'conflicting identity records at one generation'
    generation, flags, host, public = latest.pop()
    assert flags == 5, 'latest identity must be complete and not authorize the client'
    return generation, host, public


def boot(kernel, disk, log, create_client):
    command = ['qemu-system-riscv64', '-machine', 'virt', '-cpu', 'rv64',
               '-smp', '4', '-m', '128M', '-accel', 'tcg,thread=multi',
               '-nographic', '-bios', 'default', '-kernel', str(kernel),
               '-drive', f'if=none,id=disk,format=raw,file={disk},cache=writeback',
               '-device', 'virtio-blk-device,drive=disk,bus=virtio-mmio-bus.0,queue-size=8',
               '-object', 'rng-random,id=rng,filename=/dev/urandom',
               '-device', 'virtio-rng-device,rng=rng,bus=virtio-mmio-bus.1',
               '-netdev', 'user,id=net', '-device', 'virtio-net-device,netdev=net,bus=virtio-mmio-bus.2',
               '-global', 'virtio-mmio.force-legacy=false']
    log.touch(mode=0o600, exist_ok=False)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    transcript = bytearray()
    try:
        with log.open('wb') as output:
            def wait_for(marker, timeout=120):
                deadline = time.monotonic() + timeout
                start = len(transcript)
                while marker not in transcript[start:]:
                    if time.monotonic() >= deadline:
                        raise AssertionError(f'timed out waiting for {marker!r}; see {log}')
                    for key, _ in selector.select(min(1, max(0, deadline-time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            raise AssertionError(f'QEMU exited before {marker!r}; see {log}')
                        transcript.extend(chunk)
                        output.write(chunk)
                        output.flush()
                        if b'native init rejected cold recovery:' in transcript or b'fatal trap:' in transcript or b'vsh: unknown command' in transcript or b'vsh: bare paths' in transcript:
                            raise AssertionError(f'boot failed; see {log}')
                return start

            wait_for(b'SSH host identity verified; starting DHCP SSH on port 22')
            if create_client:
                process.stdin.write(b'ssh-keygen\n')
                process.stdin.flush()
                wait_for(b'ssh-keygen: client keypair persisted; it was not authorized')
            process.stdin.write(b'ssh-keycat ssh-client-key.pub\n')
            process.stdin.flush()
            wait_for(b'ssh-ed25519 ')
            # Capture the public key's complete line, not only its prefix.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if b'\n' in transcript[transcript.rfind(b'ssh-ed25519 '):]:
                    break
                for key, _ in selector.select(0.2):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        raise AssertionError('QEMU ended during public-key output')
                    transcript.extend(chunk)
                    output.write(chunk)
            assert b'fatal trap:' not in transcript
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdin.close()
        process.stdout.close()
    return bytes(transcript)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True, help='freshly built provisioned-command firmware')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    kernel = args.kernel.resolve()
    with tempfile.TemporaryDirectory(prefix='vibeos-provisioned-') as temp:
        disk = Path(temp) / 'test.img'
        with disk.open('xb') as stream:
            os.chmod(disk, 0o600)
            # provisioned-command enables file-tree: match its 128 MiB policy.
            stream.truncate(128 * 1024 * 1024)
        first_log = boot(kernel, disk, args.output/'boot-1.log', True)
        first = identity(disk)
        second_log = boot(kernel, disk, args.output/'boot-2.log', False)
        second = identity(disk)
        assert first == second, 'provisioned identity changed across reboot'
        assert first[1] != bytes(32) and first[2] != bytes(32)
        public = b'ssh-ed25519'
        blob = struct.pack('>I', len(public)) + public + struct.pack('>I', 32) + first[2]
        line = b'ssh-ed25519 ' + base64.b64encode(blob)
        assert line in first_log and line in second_log, 'VSH public key differs from persistent identity'
    result = {'status':'passed', 'boots':2, 'host_identity_persisted':True,
              'client_public_key_persisted':True, 'client_key_not_automatically_authorized':True,
              'kernel_sha256':hashlib.sha256(kernel.read_bytes()).hexdigest(),
              'physical_entropy_qualified':False}
    (args.output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    print('PASS: generic provisioned service, VirtIO entropy, VSH key generation and two-boot identity persistence')


if __name__ == '__main__':
    main()
