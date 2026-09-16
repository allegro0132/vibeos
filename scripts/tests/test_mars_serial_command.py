import importlib.util
import os
from pathlib import Path
import pty
import select
import tempfile
import termios
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('serial_command', Path(__file__).parents[1] / 'mars-serial-command.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class SerialCommandTest(unittest.TestCase):
    def exercise(self, reply, expected, *, prelude=b'', timeout=.7, interrupt=False):
        master, slave = pty.openpty()
        # Raw input allows prelude bytes to be pending before the command opens.
        attrs = termios.tcgetattr(slave); attrs[3] = 0
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        saved = termios.tcgetattr(slave)
        errors = []
        if prelude:
            os.write(master, prelude); time.sleep(.02)
        def peer():
            try:
                data = b''; end = time.monotonic()+2
                while b'\r' not in data and time.monotonic() < end:
                    if select.select([master], [], [], .1)[0]: data += os.read(master, 1024)
                if b'\r' not in data: raise AssertionError('no command')
                reply(master)
            except BaseException as error: errors.append(error)
        t = threading.Thread(target=peer); t.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                log = Path(d)/'raw.log'
                try:
                    result = m.run(os.ttyname(slave), 'reboot', log, expected, timeout, interrupt)
                    failed = False
                except TimeoutError:
                    result = b''; failed = True
                raw = log.read_bytes()
            t.join(3)
            self.assertFalse(t.is_alive()); self.assertEqual(errors, [])
            self.assertEqual(termios.tcgetattr(slave), saved)
            return failed, result, raw
        finally:
            os.close(master); os.close(slave)

    def test_stale_marker_and_unrelated_prompt_cannot_succeed(self):
        failed, _, raw = self.exercise(lambda fd: os.write(fd,b'vibe> '), r'^StarFive # ', prelude=b'StarFive # ')
        self.assertTrue(failed); self.assertIn(b'StarFive # ',raw); self.assertIn(b'vibe> ',raw)

    def test_reboot_waits_for_uboot_and_intercepts_autoboot(self):
        def peer(fd):
            os.write(fd,b'vibe> \r\nrebooting\r\nHit any key to stop autoboot: 2')
            self.assertTrue(select.select([fd],[],[],.5)[0])
            self.assertEqual(os.read(fd,1),b' ')
            os.write(fd,b'\r\nStar'); time.sleep(.02); os.write(fd,b'Five # ')
        failed, result, _ = self.exercise(peer,r'^StarFive # ',interrupt=True)
        self.assertFalse(failed); self.assertTrue(result.endswith(b'StarFive # '))

    def test_timeout_preserves_asynchronous_fault(self):
        failed, _, raw = self.exercise(lambda fd: os.write(fd,b'panic: diagnostic\r\n'),r'^StarFive # ')
        self.assertTrue(failed); self.assertIn(b'panic: diagnostic',raw)


if __name__ == '__main__': unittest.main()
