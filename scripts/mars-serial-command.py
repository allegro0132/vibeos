#!/usr/bin/env python3
"""Run one serial command with an explicit response marker; retain raw diagnostics."""
import argparse
import os
from pathlib import Path
import re
import select
import termios
import time


def run(port, command, output, expected, seconds, interrupt_autoboot=False):
    marker = re.compile(expected.encode(), re.MULTILINE)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    saved = termios.tcgetattr(fd)
    try:
        attrs = termios.tcgetattr(fd)
        attrs[:6] = [0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL, 0,
                     termios.B115200, termios.B115200]
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        with output.open('xb') as log:
            # Preserve old output, but never accept it as this command's reply.
            drained = 0
            while select.select([fd], [], [], 0)[0]:
                part = os.read(fd, 65536)
                if not part:
                    raise RuntimeError('serial disconnected')
                log.write(part); log.flush(); drained += len(part)
                if drained > 1024 * 1024:
                    raise RuntimeError('serial did not quiesce')
            deadline = time.monotonic() + seconds
            pending = (command + '\r').encode()
            while pending:
                if time.monotonic() >= deadline:
                    raise TimeoutError('serial write timed out')
                if select.select([], [fd], [], 0.1)[1]:
                    try:
                        count = os.write(fd, pending[:8])
                    except BlockingIOError:
                        continue
                    pending = pending[count:]
                    time.sleep(0.025)
            reply = bytearray()
            interrupted = False
            while time.monotonic() < deadline:
                if not select.select([fd], [], [], min(.2, max(0, deadline-time.monotonic())))[0]:
                    continue
                part = os.read(fd, 65536)
                if not part:
                    raise RuntimeError('serial disconnected')
                log.write(part); log.flush(); reply.extend(part)
                if len(reply) > 8 * 1024 * 1024:
                    raise RuntimeError('serial response exceeds 8 MiB')
                if interrupt_autoboot and not interrupted and b'Hit any key to stop autoboot:' in reply:
                    os.write(fd, b' ')
                    interrupted = True
                if marker.search(reply):
                    return bytes(reply)
            raise TimeoutError('expected serial response was not observed')
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, saved)
        finally:
            os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--command', required=True)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--expect', required=True, help='Regex for a command-specific response, not a generic shell prompt')
    p.add_argument('--seconds', type=float, default=15)
    p.add_argument('--interrupt-autoboot', action='store_true')
    a = p.parse_args()
    if not 0 < a.seconds <= 120:
        p.error('--seconds must be in (0, 120]')
    print(run(a.serial, a.command, a.output, a.expect, a.seconds, a.interrupt_autoboot).decode(errors='replace'))


if __name__ == '__main__':
    main()
