"""PTY tests exercise capture/parsing, never a physical Mars or a cold boot."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'mars-serial-accept.py'
spec = importlib.util.spec_from_file_location('mars_serial', SCRIPT)
serial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serial)
BOOT = (b'[VibeOS] entry\r\n[VibeOS] page tables ready\r\n[VibeOS] Sv39 enabled\r\n'
        b'  platform  Milk-V Mars (JH7110, 4 GiB) (4 MHz timebase)\r\n'
        b'MARS_BOOT_ADMISSION PASS boot=4 harts=4 timebase=4000000 heap_regions=2 SBI=HSM,IPI,RFENCE,TIME\r\n'
        b'  smp       4 hart(s) online\r\n'
        b'  mmu       Sv39 single address space, hart mask 0xf\r\n')


class ParserTests(unittest.TestCase):
    def test_four_boot_harts_and_no_physical_claim(self):
        for hart in range(1, 5):
            result = serial.inspect(BOOT.replace(b'boot=4', f'boot={hart}'.encode()))
            self.assertEqual(result['status'], 'boot-markers-observed')
            for field in ['physical_acceptance', 'cold_boot_verified', 'network_verified', 'ssh_verified']:
                self.assertFalse(result[field])

    def test_each_gate_is_required(self):
        for line in BOOT.splitlines(keepends=True):
            with self.subTest(line=line):
                self.assertNotEqual(serial.inspect(BOOT.replace(line, b''))['status'], 'boot-markers-observed')

    def test_wrong_board_topology_sbi_timebase_and_mmu_rejected(self):
        for a, b in [(b'boot=4', b'boot=0'), (b'harts=4', b'harts=1'),
                     (b'4000000', b'10000000'), (b'heap_regions=2', b'heap_regions=0'),
                     (b'RFENCE,', b''), (b'4 hart(s)', b'1 hart(s)'), (b'0xf', b'0x7'),
                     (b'Milk-V Mars', b'Milk-V Duo')]:
            with self.subTest(a=a):
                self.assertNotEqual(serial.inspect(BOOT.replace(a, b))['status'], 'boot-markers-observed')

    def test_duplicate_reordered_partial_and_late_failure(self):
        lines = BOOT.splitlines(keepends=True)
        for data in [BOOT + BOOT, b''.join(lines[1:] + lines[:1]), BOOT[:-1],
                     BOOT + b'\n[!] panic: late fault',
                     BOOT + b'MARS_BOOT_ADMISSION FAIL: invalid CPU\n',
                     BOOT + b'  smp       1 hart(s) online\n',
                     BOOT + b'[VibeOS] entry']:
            with self.subTest(data=data[-65:]):
                self.assertNotEqual(serial.inspect(data)['status'], 'boot-markers-observed')
        self.assertEqual(serial.inspect(b'\x1b[32m' + BOOT)['status'], 'boot-markers-observed')


class CaptureTests(unittest.TestCase):
    def run_capture(self, chunks, limit=None, interrupt=False):
        with tempfile.TemporaryDirectory() as tmp:
            master, slave = pty.openpty()
            original = termios.tcgetattr(slave)
            output = Path(tmp) / 'evidence'
            command = [sys.executable, str(SCRIPT)]
            if limit is not None:
                command = [sys.executable, '-c',
                           'import runpy; m=runpy.run_path(' + repr(str(SCRIPT)) + '); '
                           + 'm["capture"].__globals__["LIMIT"]=' + str(limit) + '; '
                           + 'raise SystemExit(m["main"]())']
            child = subprocess.Popen(command + ['--port', os.ttyname(slave),
                                      '--output', str(output), '--seconds', '0.8',
                                      '--board-revision', 'PTY model (not hardware)'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not (output / 'ready.json').exists():
                    if child.poll() is not None or time.monotonic() > deadline:
                        self.fail('capture did not become ready')
                    time.sleep(0.01)
                for chunk in chunks:
                    os.write(master, chunk)
                    time.sleep(0.03)
                if interrupt:
                    child.send_signal(signal.SIGINT)
                stdout, stderr = child.communicate(timeout=5)
                self.assertFalse(stderr, (stdout, stderr))
                result = json.loads((output / 'summary.json').read_text())
                raw = (output / 'serial.log').read_bytes()
                self.assertEqual(raw, b''.join(chunks)[:limit])
                self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())
                restored = termios.tcgetattr(slave)
                # BSD may set PENDIN when restoring canonical input. This is
                # kernel queue state, not a lost user mode/baud setting.
                restored[3] &= ~getattr(termios, 'PENDIN', 0)
                original[3] &= ~getattr(termios, 'PENDIN', 0)
                self.assertEqual(restored, original)
                if limit is None:
                    self.assertFalse(select.select([master], [], [], 0)[0], 'capture transmitted bytes')
                self.assertEqual(result['complete_interval'], limit is None and not interrupt)
                return child.returncode, result
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()
                os.close(master)
                os.close(slave)

    def test_fragmented_real_tty_capture_preserves_raw_bytes(self):
        code, result = self.run_capture([BOOT[:7], BOOT[7:170], BOOT[170:]])
        self.assertEqual(code, 0)
        self.assertFalse(result['physical_acceptance'])
        self.assertGreaterEqual(result['elapsed_seconds'], 0.8)

    def test_late_failure_is_not_hidden_by_early_success(self):
        code, result = self.run_capture([BOOT, b'\n[!] panic: fault after startup\n'])
        self.assertEqual(code, 1)
        self.assertTrue(result['errors'])

    def test_empty_capture_cannot_pass(self):
        code, result = self.run_capture([])
        self.assertEqual(code, 1)
        self.assertEqual(result['bytes'], 0)

    def test_byte_limit_retains_partial_evidence_and_fails(self):
        code, result = self.run_capture([BOOT], limit=32)
        self.assertEqual(code, 1)
        self.assertEqual(result['capture_error'], 'capture byte limit reached')

    def test_interruption_cannot_pass_after_valid_boot_markers(self):
        code, result = self.run_capture([BOOT], interrupt=True)
        self.assertEqual(code, 1)
        self.assertEqual(result['capture_error'], 'interrupted')

    def test_regular_file_rejected_and_evidence_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            port = Path(tmp) / 'fake-port'
            port.write_bytes(BOOT)
            output = Path(tmp) / 'evidence'
            result = serial.capture(port, output, 0.01, 'model')
            self.assertEqual(result['status'], 'capture-failed')
            self.assertEqual(port.read_bytes(), BOOT)
            before = (output / 'summary.json').read_bytes()
            with self.assertRaises(FileExistsError):
                serial.capture(port, output, 0.01, 'model')
            self.assertEqual((output / 'summary.json').read_bytes(), before)

    def test_invalid_duration_or_identity_precedes_output_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'evidence'
            for duration, revision in [(0, 'test'), (float('nan'), 'test'),
                                       (float('inf'), 'test'), (86401, 'test'), (1, ' ' )]:
                with self.assertRaises(ValueError):
                    serial.capture(Path('/not-opened'), output, duration, revision)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
