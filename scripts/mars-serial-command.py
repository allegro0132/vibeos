#!/usr/bin/env python3
"""Bounded serial commands or a sequence on one 115200 connection; retain raw output."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import sys
import termios
import time


class SerialSession:
    """One owner/reader; configure once, restore only when the whole session ends.

    Commands exclude already-buffered markers. Passive collection preserves
    asynchronous diagnostics between commands. No input flush or board reset.
    """
    def __init__(self, port, output):
        self.port, self.output = port, Path(output)
        self.fd = self.saved = self.log = None

    def __enter__(self):
        try:
            self.log = self.output.open('xb')
            self.fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            self.saved = termios.tcgetattr(self.fd)
            attrs = termios.tcgetattr(self.fd)
            attrs[:6] = [0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL, 0,
                         termios.B115200, termios.B115200]
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, exc_type, exc, traceback):
        try:
            if self.fd is not None and self.saved is not None:
                try:
                    termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
                except (OSError, termios.error):
                    if exc_type is None:
                        raise
        finally:
            if self.fd is not None:
                os.close(self.fd); self.fd = None
            if self.log is not None:
                self.log.close(); self.log = None

    def _read(self):
        part = os.read(self.fd, 65536)
        if not part:
            raise RuntimeError('serial disconnected')
        self.log.write(part); self.log.flush()
        if self.log.tell() > 64 * 1024 * 1024:
            raise RuntimeError('serial capture exceeds 64 MiB')
        return part

    def collect(self, seconds):
        if not 0 < seconds <= 60:
            raise ValueError('collection seconds must be in (0, 60]')
        before = self.log.tell()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([self.fd], [], [], min(.2, max(0, deadline-time.monotonic())))[0]:
                self._read()
        return self.log.tell() - before

    def command(self, command, expected, seconds=15, interrupt_autoboot=False):
        if not 0 < seconds <= 120 or not isinstance(command, str) or '\r' in command or '\n' in command:
            raise ValueError('expected one command line and timeout in (0, 120]')
        marker = re.compile(expected.encode(), re.MULTILINE)
        drained = 0
        while select.select([self.fd], [], [], 0)[0]:
            drained += len(self._read())
            if drained > 1024 * 1024:
                raise RuntimeError('serial did not quiesce')
        deadline = time.monotonic() + seconds
        pending = (command + '\r').encode()
        while pending:
            if time.monotonic() >= deadline:
                raise TimeoutError('serial write timed out')
            if select.select([], [self.fd], [], .1)[1]:
                try:
                    count = os.write(self.fd, pending[:8])
                except BlockingIOError:
                    continue
                pending = pending[count:]
                time.sleep(.025)
        reply = bytearray()
        interrupted = False
        while time.monotonic() < deadline:
            if not select.select([self.fd], [], [], min(.2, max(0, deadline-time.monotonic())))[0]:
                continue
            reply.extend(self._read())
            if len(reply) > 8 * 1024 * 1024:
                raise RuntimeError('serial response exceeds 8 MiB')
            if interrupt_autoboot and not interrupted and b'Hit any key to stop autoboot:' in reply:
                os.write(self.fd, b' '); interrupted = True
            if marker.search(reply):
                return bytes(reply)
        raise TimeoutError('expected serial response was not observed')


def run(port, command, output, expected, seconds, interrupt_autoboot=False):
    with SerialSession(port, output) as session:
        return session.command(command, expected, seconds, interrupt_autoboot)


def sequence_steps(path):
    steps = json.loads(path.read_text())
    if not isinstance(steps, list) or not 1 <= len(steps) <= 256:
        raise ValueError('sequence must contain 1..256 steps')
    budget = 0
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError('each step must be an object')
        if set(step) == {'collect_seconds'}:
            duration = float(step['collect_seconds'])
            if not 0 < duration <= 60: raise ValueError('collection exceeds 60 seconds')
        else:
            if not {'command', 'expect'} <= set(step) or set(step) - {'command','expect','seconds','interrupt_autoboot'}:
                raise ValueError('command step requires command and expect')
            if not isinstance(step['command'], str) or any(c in step['command'] for c in '\r\n'):
                raise ValueError('expected one command line')
            re.compile(step['expect'].encode())
            duration = float(step.get('seconds', 15))
            if not 0 < duration <= 120: raise ValueError('command timeout exceeds 120 seconds')
        budget += duration
    if budget > 3600: raise ValueError('sequence exceeds one hour')
    return steps


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--command')
    mode.add_argument('--sequence', type=Path, help='JSON command/collect steps; keeps one port open throughout')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--expect', help='Command-specific response regex, not a generic shell prompt')
    p.add_argument('--seconds', type=float, default=15)
    p.add_argument('--interrupt-autoboot', action='store_true')
    a = p.parse_args()
    if a.sequence:
        try: steps = sequence_steps(a.sequence)
        except (ValueError, TypeError, AttributeError, re.error) as error: p.error(str(error))
        with SerialSession(a.serial, a.output) as session:
            for i, step in enumerate(steps):
                if 'collect_seconds' in step:
                    result = {'step': i, 'collected_bytes': session.collect(float(step['collect_seconds']))}
                else:
                    reply = session.command(step['command'], step['expect'], float(step.get('seconds',15)), step.get('interrupt_autoboot',False))
                    result = {'step': i, 'command': step['command'], 'reply': reply.decode(errors='replace')}
                print(json.dumps(result), flush=True)
    else:
        if not a.expect or not 0 < a.seconds <= 120:
            p.error('single command requires --expect and --seconds in (0, 120]')
        print(run(a.serial, a.command, a.output, a.expect, a.seconds, a.interrupt_autoboot).decode(errors='replace'))


if __name__ == '__main__': main()
