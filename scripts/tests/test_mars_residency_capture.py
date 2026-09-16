"""Host PTY tests; these do not qualify physical Mars stability/performance."""
import importlib.util
import os
from pathlib import Path
import pty
import subprocess
import sys
import tempfile
import threading
import time
import tty
import unittest

spec = importlib.util.spec_from_file_location('bench', Path(__file__).resolve().parents[1] / 'mars-residency-bench.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.master, self.slave = pty.openpty()
        tty.setraw(self.slave)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.capture = (self.root/'serial.log').open('w+b')

    def tearDown(self):
        self.capture.close()
        os.close(self.master)
        os.close(self.slave)
        self.tmp.cleanup()

    def test_precommand_fault_is_preserved_but_not_mistaken_for_reply(self):
        os.write(self.master,b'panic: previous workload\r\nvibe> ')
        def board():
            request=b''
            while not request.endswith(b'\r'):
                request+=os.read(self.master,128)
            os.write(self.master,b'nidle\r\nNIDLE_END\r\nvibe> ')
        worker=threading.Thread(target=board,daemon=True);worker.start()
        response=bench.command(self.slave,'nidle',self.capture)
        worker.join(1);self.assertFalse(worker.is_alive())
        self.assertNotIn('panic',response)
        self.assertIn('NIDLE_END',response)
        self.assertEqual((self.root/'serial.log').read_bytes(),b'panic: previous workload\r\nvibe> nidle\r\nNIDLE_END\r\nvibe> ')

    def test_fault_during_client_failure_and_partial_outputs_survive(self):
        def emit_fault():
            time.sleep(0.05)
            os.write(self.master,b'FATAL during transfer\r\n')
        worker=threading.Thread(target=emit_fault);worker.start()
        args=[sys.executable,'-c',"import sys,time;print('partial JSON',flush=True);print('client failed',file=sys.stderr,flush=True);time.sleep(0.15);sys.exit(3)"]
        result=bench.run_iperf(self.slave,self.capture,args,self.root/'iperf.json',self.root/'stderr.log',2)
        worker.join(1);self.assertFalse(worker.is_alive())
        self.assertEqual(result,3)
        self.assertIn(b'FATAL during transfer',(self.root/'serial.log').read_bytes())
        self.assertIn('partial JSON',(self.root/'iperf.json').read_text())
        self.assertIn('client failed',(self.root/'stderr.log').read_text())

    def test_timeout_preserves_evidence_and_reaps_only_its_child(self):
        os.write(self.master,b'TX stuck\r\n')
        args=[sys.executable,'-c',"import os,time,sys;print(os.getpid(),flush=True);print('waiting',file=sys.stderr,flush=True);time.sleep(20)"]
        with self.assertRaises(subprocess.TimeoutExpired):
            bench.run_iperf(self.slave,self.capture,args,self.root/'pid',self.root/'stderr.log',1.0)
        pid=int((self.root/'pid').read_text())
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
        self.assertEqual((self.root/'serial.log').read_bytes(),b'TX stuck\r\n')
        self.assertIn('waiting',(self.root/'stderr.log').read_text())

    def test_idle_capture_keeps_unsolicited_diagnostics(self):
        os.write(self.master,b'idle fault\r\n')
        bench.collect_serial(self.slave,self.capture,0.05)
        self.assertEqual((self.root/'serial.log').read_bytes(),b'idle fault\r\n')

if __name__=='__main__':unittest.main()
