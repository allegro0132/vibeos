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
from unittest.mock import patch
import json

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

    def test_session_keeps_settings_between_commands_and_captures_idle_output(self):
        master, slave = pty.openpty()
        saved = termios.tcgetattr(slave)
        errors = []
        def peer():
            try:
                for command, reply in [(b'one', b'ONE'), (b'two', b'TWO')]:
                    data = b''; end = time.monotonic()+2
                    while b'\r' not in data and time.monotonic()<end:
                        if select.select([master],[],[],.1)[0]: data += os.read(master,1024)
                    self.assertEqual(data, command+b'\r')
                    os.write(master,reply+b'\r\n')
                    if command == b'one':
                        time.sleep(.04);os.write(master,b'ASYNC FAULT\r\n')
            except BaseException as error: errors.append(error)
        try:
            with tempfile.TemporaryDirectory() as directory:
                log = Path(directory)/'session.log'
                original = termios.tcsetattr
                with patch.object(m.termios,'tcsetattr',wraps=original) as settings:
                    with m.SerialSession(os.ttyname(slave),log) as session:
                        t=threading.Thread(target=peer);t.start()
                        fd=session.fd
                        session.command('one',r'^ONE\r?$',1)
                        session.collect(.12)
                        session.command('two',r'^TWO\r?$',1)
                        self.assertEqual(session.fd,fd)
                        self.assertEqual(settings.call_count,1)
                        attrs=termios.tcgetattr(slave)
                        self.assertEqual(attrs[4:6],[termios.B115200]*2)
                        self.assertFalse(attrs[2]&termios.HUPCL)
                        t.join(2);self.assertFalse(t.is_alive())
                    self.assertEqual(settings.call_count,2)
                    self.assertEqual(settings.call_args_list[-1].args[2],saved)
                self.assertEqual(errors,[])
                self.assertIn(b'ASYNC FAULT',log.read_bytes())
                # Darwin may add PENDIN when raw unread input is restored to
                # canonical mode. Verify the exact requested restore above;
                # this kernel-maintained flag is not a configuration change.
                actual=termios.tcgetattr(slave)
                actual[3] &= ~getattr(termios,'PENDIN',0)
                saved[3] &= ~getattr(termios,'PENDIN',0)
                self.assertEqual(actual,saved)
        finally: os.close(master);os.close(slave)

    def test_sequence_rejects_unbounded_waits_before_opening_serial(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'steps.json'
            for steps in [[{'collect_seconds':61}], [{'command':'x\ny','expect':'y'}],
                          [{'collect_seconds':60}]*61, [{'command':'x'}]]:
                path.write_text(json.dumps(steps))
                with self.assertRaises(ValueError):m.sequence_steps(path)
            valid=[{'command':'bootlog','expect':'BOOTLOG_END'}, {'collect_seconds':1}]
            path.write_text(json.dumps(valid));self.assertEqual(m.sequence_steps(path),valid)


if __name__ == '__main__': unittest.main()
