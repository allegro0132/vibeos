#!/usr/bin/env python3
"""Passively capture one Mars boot at 115200 8N1; never transmit or power-cycle.

Markers prove only observations in this capture, not physical identity, an SD
write, network operation, entropy quality or the complete acceptance plan.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import stat
import termios
import time

LIMIT = 16 * 1024 * 1024


def inspect(data, require_trng_probe=False):
    # Keep raw evidence untouched. Only normalize CRLF and complete ANSI CSI
    # sequences for parsing; a partial last line must not satisfy a gate.
    normalized = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', data).replace(b'\r\n', b'\n')
    lines = normalized.split(b'\n')[:-1]
    gates = [
        ('entry', rb'\[VibeOS\] entry'),
        ('page_tables', rb'\[VibeOS\] page tables ready'),
        ('sv39', rb'\[VibeOS\] Sv39 enabled'),
        ('platform', rb'  platform  Milk-V Mars \(JH7110, 4 GiB\) \(4 MHz timebase\)'),
        ('admission', rb'MARS_BOOT_ADMISSION PASS boot=([1-4]) harts=4 timebase=4000000 heap_regions=([1-9]|1[0-6]) SBI=HSM,IPI,RFENCE,TIME'),
        ('smp', rb'  smp       4 hart\(s\) online'),
        ('mmu', rb'  mmu       Sv39 single address space, hart mask 0xf'),
    ]
    if require_trng_probe or b'MARS_TRNG_PROBE' in normalized:
        gates.insert(3, ('trng_probe', rb'MARS_TRNG_PROBE protocol-observed parent_hz=([0-9]{8,9}) blocks=2 stopped=true entropy=unqualified'))
    errors, observed, positions = [], {}, []
    for name, pattern in gates:
        matches = [(i, re.fullmatch(pattern, line)) for i, line in enumerate(lines)]
        matches = [(i, m) for i, m in matches if m]
        observed[name] = len(matches)
        if len(matches) != 1:
            errors.append(f'{name}: expected exactly one valid line, observed {len(matches)}')
        else:
            positions.append(matches[0][0])
            if name == 'trng_probe' and not 20_000_000 <= int(matches[0][1][1]) <= 300_000_000:
                errors.append('TRNG parent frequency outside supported range')
    if positions != sorted(positions):
        errors.append('boot markers out of order')
    # Count invalid attempts too: a successful second boot must not hide the
    # failure of the first, even if its admission tuple was not valid.
    for prefix in [b'[VibeOS] entry', b'MARS_BOOT_ADMISSION', b'  smp ', b'  mmu ', b'MARS_TRNG_PROBE']:
        if sum(line.startswith(prefix) for line in normalized.split(b'\n')) > 1:
            errors.append('multiple boot attempts: ' + prefix.decode())
    if re.search(rb'(?i)(?:panic|panicked|fatal|MARS_TRNG_PROBE FAIL|BOOT_ADMISSION FAIL|MARS_BOOT_ADMISSION FAIL)', normalized):
        errors.append('failure diagnostic observed')
    return {
        'status': 'boot-markers-observed' if not errors else 'boot-markers-incomplete-or-failed',
        'gates': observed, 'errors': errors,
        'trng_probe_required': require_trng_probe,
        'trng_protocol_observed': observed.get('trng_probe') == 1 and not errors,
        'entropy_qualified': False,
        'physical_acceptance': False,
        'cold_boot_verified': False,
        'network_verified': False,
        'ssh_verified': False,
    }


def capture(port, output, duration, board_revision, require_trng_probe=False):
    if not math.isfinite(duration) or not 0 < duration <= 86400:
        raise ValueError('duration must be finite and between 0 and 86400 seconds')
    if not board_revision.strip():
        raise ValueError('board revision must be supplied by the operator')
    # No existing evidence can be replaced, including an existing empty folder.
    output.mkdir(parents=True, exist_ok=False)
    data = bytearray()
    fd, saved, error = None, None, None
    started = time.monotonic()
    utc = datetime.now(timezone.utc).isoformat()
    try:
        with (output / 'serial.log').open('xb') as log:
            # Read-only descriptor: no probe, newline, reset or shell command.
            fd = os.open(port, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
            if not stat.S_ISCHR(os.fstat(fd).st_mode) or not os.isatty(fd):
                raise ValueError('port must be a serial character device / TTY')
            saved = termios.tcgetattr(fd)
            attrs = termios.tcgetattr(fd)
            attrs[:6] = [0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL, 0,
                         termios.B115200, termios.B115200]
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            # Discard already-buffered data so an old boot cannot satisfy this
            # capture. Operator must start the new boot after opening capture.
            termios.tcflush(fd, termios.TCIFLUSH)
            (output / 'ready.json').write_text(json.dumps({'port': str(port), 'baud': 115200}) + '\n')
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                if not select.select([fd], [], [], min(0.25, max(0, deadline - time.monotonic())))[0]:
                    continue
                try:
                    chunk = os.read(fd, min(65536, LIMIT - len(data)))
                except BlockingIOError:
                    continue
                if not chunk:
                    raise OSError('serial device disconnected')
                log.write(chunk)
                log.flush()
                data.extend(chunk)
                if len(data) >= LIMIT:
                    raise ValueError('capture byte limit reached')
            os.fsync(log.fileno())
    except (OSError, ValueError, termios.error, KeyboardInterrupt) as exc:
        error = 'interrupted' if isinstance(exc, KeyboardInterrupt) else str(exc)
    finally:
        if fd is not None:
            try:
                if saved is not None:
                    termios.tcsetattr(fd, termios.TCSANOW, saved)
            except (OSError, termios.error) as exc:
                error = error or 'cannot restore serial settings: ' + str(exc)
            finally:
                os.close(fd)
    result = inspect(bytes(data), require_trng_probe)
    result.update(port=str(port), board_revision=board_revision, started_utc=utc,
                  elapsed_seconds=time.monotonic() - started, requested_seconds=duration,
                  bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                  observation_only=True, complete_interval=error is None)
    if error is not None:
        result['capture_error'] = error
        result['status'] = 'capture-failed'
    (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    parser.add_argument('--board-revision', required=True, help='operator-reported revision; not auto-detected')
    parser.add_argument('--require-trng-probe', action='store_true', help='require one ordered, stopped TRNG diagnostic; never qualifies entropy')
    parser.add_argument('--seconds', type=float, default=120)
    args = parser.parse_args()
    print('Waiting for capture readiness; power-cycle only after ready.json appears.', flush=True)
    try:
        result = capture(args.port, args.output, args.seconds, args.board_revision, args.require_trng_probe)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'MARS_SERIAL: {exc}\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'boot-markers-observed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
