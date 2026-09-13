#!/usr/bin/env python3
"""Run a verified universal image using only its configured QEMU devices."""
import argparse
import os
import subprocess
from universal_artifacts import load_manifest


def command(manifest, image):
    features = set(manifest['features'])
    args = ['qemu-system-riscv64', '-machine', 'virt', '-cpu', 'rv64', '-smp', '4', '-m', '128M',
            '-nographic', '-bios', 'default', '-kernel', str(image), '-global', 'virtio-mmio.force-legacy=false']
    if 'driver-virtio-blk' in features:
        disk = image.parent / 'qemu-data.raw'
        try:
            with disk.open('xb') as stream:
                stream.truncate(128 * 1024 * 1024)
        except FileExistsError:
            if disk.stat().st_size != 128 * 1024 * 1024:
                raise ValueError('existing QEMU data disk must be 128 MiB')
        args += ['-drive', f'if=none,id=data,format=raw,file={disk}', '-device',
                 'virtio-blk-device,drive=data,bus=virtio-mmio-bus.0,queue-size=8']
    if 'driver-virtio-net' in features:
        args += ['-netdev', 'user,id=net0', '-device', 'virtio-net-device,netdev=net0']
    if 'driver-virtio-rng' in features:
        args += ['-object', 'rng-random,filename=/dev/urandom,id=rng0', '-device', 'virtio-rng-device,rng=rng0']
    if 'driver-xhci' in features:
        args += ['-device', 'qemu-xhci,id=xhci', '-device', 'usb-kbd,bus=xhci.0']
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    manifest, image = load_manifest(args.manifest, 'qemu-virt')
    qemu = command(manifest, image)
    if args.dry_run:
        import shlex
        print(shlex.join(qemu))
    else:
        os.execvp(qemu[0], qemu)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(f'run-universal: {error}')
