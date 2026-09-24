#!/usr/bin/env python3
"""Bounded, passive UART capture plus independent ICMP liveness evidence.

Never sends UART input or resets the board. Use as the sole serial reader.
Raw bytes and timestamped chunk offsets are retained, including boot prefixes.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import select
import subprocess
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--address', type=ipaddress.IPv4Address, required=True)
    parser.add_argument('--seconds', type=int, default=180)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error('--seconds must be between 1 and 3600')
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('mars_serial', Path(__file__).with_name('mars-serial-command.py'))
    serial = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(serial)
    stop = threading.Event()
    started = time.monotonic()
    metadata = dict(start_unix_ns=time.time_ns(), start_monotonic_ns=time.monotonic_ns(),
                    serial=args.serial, address=str(args.address), seconds=args.seconds,
                    uart_writes=False, completed=False)
    (args.output / 'metadata.json').write_text(json.dumps(metadata, indent=2))

    def network():
        with (args.output / 'network.jsonl').open('x') as log:
            while not stop.is_set():
                row = dict(unix_ns=time.time_ns(), monotonic_ns=time.monotonic_ns())
                try:
                    result = subprocess.run(['ping', '-n', '-c', '1', str(args.address)],
                                            capture_output=True, timeout=2)
                    row.update(exit_code=result.returncode,
                               output=result.stdout.decode(errors='replace'),
                               error=result.stderr.decode(errors='replace'))
                except Exception as error:
                    row['error'] = repr(error)
                log.write(json.dumps(row) + '\n')
                log.flush()
                stop.wait(5)

    worker = None
    try:
        with serial.SerialSession(args.serial, args.output / 'serial.bin') as session:
            worker = threading.Thread(target=network, daemon=True)
            worker.start()
            print('CAPTURE_READY ' + str(args.output.resolve()), flush=True)
            with (args.output / 'serial-chunks.jsonl').open('x') as chunks:
                while time.monotonic() - started < args.seconds:
                    if not select.select([session.fd], [], [], .2)[0]:
                        continue
                    offset = session.log.tell()
                    data = session._read()
                    chunks.write(json.dumps(dict(unix_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(),
                                                 offset=offset, length=len(data))) + '\n')
                    chunks.flush()
            metadata['completed'] = True
    except BaseException as error:
        metadata['error'] = repr(error)
        raise
    finally:
        stop.set()
        if worker is not None:
            worker.join(timeout=3)
        metadata.update(end_unix_ns=time.time_ns(), elapsed_seconds=time.monotonic()-started)
        for path in args.output.iterdir():
            if path.is_file() and path.name != 'metadata.json':
                metadata.setdefault('files', {})[path.name] = dict(bytes=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        (args.output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        print('CAPTURE_END ' + json.dumps(metadata), flush=True)


if __name__ == '__main__':
    main()
