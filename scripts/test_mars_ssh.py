"""Host checks for SSH evidence integrity; no network or private keys used."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mars_ssh', Path(__file__).with_name('mars-ssh-accept.py'))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class SshEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, data in [('key', b'never-copy-this-private-key'),
                           ('pins', b'board ssh-ed25519 AAAATEST\n'),
                           ('hello', b'\0asm\x01\0\0\0'), ('trap', b'\0asm\x01\0\0\0')]:
            (self.root / name).write_bytes(data)
        self.args = SimpleNamespace(host='board', port=22, user='vibe',
            identity=self.root/'key', known_hosts=self.root/'pins', output=self.root/'upload',
            phase='upload', command_module=self.root/'hello', trap_module=self.root/'trap',
            thread_fixtures=None, pthread_module=None, baseline=None)

    def peer(self, command, **kwargs):
        words = shlex.split(command[-1])
        code, out, err = 0, b'', b''
        if words[0] == 'echo': out = b'mars-accept-ready\n'
        if words[0] == 'wasm-run':
            if words[1] == 'mars-accept-trap.wasm': code = 125
            elif len(words) == 2: out = b'Hello from C WASI!\n'
            elif words[2] == 'args': out = 'a b\n中文\n'.encode()
            elif words[2] == 'filter': out = kwargs['input'].upper()
            elif words[2] == 'stderr': out, err = b'out\n', b'err\n'
            elif words[2] == 'exit': code = 7
        return subprocess.CompletedProcess(command, code, out, err)

    def upload(self):
        with patch.object(client.subprocess, 'run', side_effect=self.peer) as peer:
            result = client.run(self.args)
        self.assertEqual(peer.call_count, 10)
        return result

    def verify_args(self):
        self.args.baseline = self.args.output/'summary.json'
        self.args.output = self.root/'verify'
        self.args.phase = 'verify'

    def test_upload_then_verify_without_reupload_or_private_key_copy(self):
        self.upload()
        self.verify_args()
        with patch.object(client.subprocess, 'run', side_effect=self.peer) as peer:
            result = client.run(self.args)
        self.assertEqual(peer.call_count, 8)
        self.assertFalse(any('wasm-upload' in call.args[0][-1] for call in peer.call_args_list))
        self.assertFalse(result['physical_acceptance'])
        self.assertFalse(result['cold_boot_verified'])
        for path in self.args.output.iterdir():
            self.assertNotIn(b'never-copy-this-private-key', path.read_bytes())
        command = peer.call_args_list[0].args[0]
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertIn('PreferredAuthentications=publickey', command)

    def test_failed_connection_is_not_retried_and_outputs_survive(self):
        with patch.object(client.subprocess, 'run', return_value=subprocess.CompletedProcess([], 255, b'', b'reset')) as peer:
            with self.assertRaises(RuntimeError): client.run(self.args)
        self.assertEqual(peer.call_count, 1)
        summary = json.loads((self.args.output/'summary.json').read_text())
        self.assertEqual(summary['status'], 'failed')
        self.assertEqual((self.args.output/'001-stderr.bin').read_bytes(), b'reset')

    def test_timeout_is_failure_with_partial_output(self):
        with patch.object(client.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 120, output=b'partial')):
            with self.assertRaises(RuntimeError): client.run(self.args)
        summary = json.loads((self.args.output/'summary.json').read_text())
        self.assertTrue(summary['commands'][0]['timeout'])
        self.assertEqual((self.args.output/'001-stdout.bin').read_bytes(), b'partial')

    def test_interruption_cannot_leave_a_passing_summary(self):
        with patch.object(client.subprocess, 'run', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): client.run(self.args)
        summary = json.loads((self.args.output/'summary.json').read_text())
        self.assertEqual(summary['status'], 'failed')
        self.assertIn('KeyboardInterrupt', summary['error'])

    def test_existing_output_is_not_overwritten(self):
        self.args.output.mkdir()
        (self.args.output/'keep').write_bytes(b'old evidence')
        with patch.object(client.subprocess, 'run') as peer:
            with self.assertRaises(FileExistsError): client.run(self.args)
            peer.assert_not_called()
        self.assertEqual((self.args.output/'keep').read_bytes(), b'old evidence')

    def test_zero_exit_with_wrong_bytes_still_fails(self):
        with patch.object(client.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'wrong', b'')):
            with self.assertRaises(RuntimeError): client.run(self.args)
        self.assertEqual(json.loads((self.args.output/'summary.json').read_text())['status'], 'failed')

    def test_changed_fixture_cannot_claim_persistence(self):
        self.upload(); self.verify_args()
        self.args.command_module.write_bytes(b'\0asm\x01\0\0\0changed')
        with patch.object(client.subprocess, 'run') as peer:
            with self.assertRaises(ValueError): client.run(self.args)
            peer.assert_not_called()

    def test_changed_host_key_cannot_claim_identity_persistence(self):
        self.upload(); self.verify_args()
        self.args.known_hosts.write_bytes(b'board ssh-ed25519 DIFFERENT\n')
        with patch.object(client.subprocess, 'run') as peer:
            with self.assertRaises(ValueError): client.run(self.args)
            peer.assert_not_called()


if __name__ == '__main__': unittest.main()
