#!/usr/bin/env python3
"""Exercise the explicit-target Mars SSH collector using disposable QEMU.

Accepts qemu-provisioned-composition-test.py's arguments. Select command fixtures;
optional Wasmtime/thread arguments exercise the collector's thread mode too.
This remains virtual testing, never Mars physical evidence.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


qemu = load('qemu_composition', 'qemu-provisioned-composition-test.py')
client = load('mars_ssh', 'mars-ssh-accept.py')
original = qemu.commands


def commands(*args, **kwargs):
    original(*args, **kwargs)
    output, number = kwargs['output'], kwargs['number']
    threads = kwargs.get('threads', False)
    client.run(SimpleNamespace(
        host='127.0.0.1', port=kwargs['port'], user='vibe',
        identity=output / 'client-key', known_hosts=output / f'known-hosts-{number}',
        output=output / f'mars-ssh-{number}', phase='upload' if number == 1 else 'verify',
        baseline=output / 'mars-ssh-1/summary.json' if number == 2 else None,
        command_module=output / 'fixtures/composition-hello.wasm',
        trap_module=output / 'fixtures/composition-trap.wasm',
        thread_fixtures=output / 'fixtures' if threads else None,
        pthread_module=output / 'fixtures/c-threads.wasm' if threads else None))


if __name__ == '__main__':
    qemu.commands = commands
    qemu.main()
