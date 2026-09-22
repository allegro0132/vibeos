"""Pinning, extraction and failure-reporting tests for the native JS probe."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('node_runtime', Path(__file__).parents[1] / 'node-runtime.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_corrupt_cache_is_rejected_without_network(self):
        path = self.root / 'input.tgz'
        path.write_bytes(b'correct')
        pin = {'archive': path.name, 'sha256': hashlib.sha256(b'correct').hexdigest()}
        self.assertEqual(probe.fetch(pin, self.root, True), path)
        path.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            probe.fetch(pin, self.root, True)

    def test_sri_and_missing_pin(self):
        path = self.root / 'input.tgz'
        path.write_bytes(b'package')
        integrity = 'sha512-' + base64.b64encode(hashlib.sha512(b'package').digest()).decode()
        probe.verify(path, {'integrity': integrity})
        path.write_bytes(b'other package')
        with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
            probe.verify(path, {'integrity': integrity})
        with self.assertRaisesRegex(ValueError, 'no pinned checksum'):
            probe.verify(path, {})

    def test_missing_offline_input(self):
        with self.assertRaisesRegex(FileNotFoundError, 'missing cached artifact'):
            probe.fetch({'archive': 'missing.tgz', 'sha256': '0' * 64}, self.root, True)

    def archive(self, name, kind=tarfile.REGTYPE):
        path = self.root / 'input.tar'
        with tarfile.open(path, 'w') as stream:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = 2
                stream.addfile(entry, io.BytesIO(b'ok'))
            else:
                entry.linkname = '../outside'
                stream.addfile(entry)
        return path

    def test_extract_and_replace_only_after_validation(self):
        destination = self.root / 'unpacked'
        probe.extract(self.archive('package/main.js'), destination, 'package/main.js')
        self.assertEqual((destination / 'package/main.js').read_bytes(), b'ok')
        for name, kind in [('../outside', tarfile.REGTYPE),
                           ('/absolute', tarfile.REGTYPE),
                           ('package/link', tarfile.SYMTYPE),
                           ('package/link', tarfile.LNKTYPE)]:
            with self.subTest(name=name, kind=kind):
                with self.assertRaisesRegex(ValueError, 'unsafe archive'):
                    probe.extract(self.archive(name, kind), destination, 'package/main.js')
                self.assertEqual((destination / 'package/main.js').read_bytes(), b'ok')
        with self.assertRaisesRegex(ValueError, 'missing'):
            probe.extract(self.archive('package/other.js'), destination, 'package/main.js')

    def test_failed_command_retains_output_and_status(self):
        result = probe.check('failure', [sys.executable, '-c',
            'import sys; print("output"); print("reason", file=sys.stderr); sys.exit(7)'], self.root)
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual((self.root / result['stdout']).read_text(), 'output\n')
        self.assertEqual((self.root / result['stderr']).read_text(), 'reason\n')

    def test_missing_command_is_reported(self):
        result = probe.check('missing', [str(self.root / 'not-a-tool')], self.root)
        self.assertEqual(result['exit_code'], 127)
        self.assertTrue((self.root / result['stderr']).read_text())

    def test_timeout_is_reported(self):
        result = probe.check('timeout', [sys.executable, '-c', 'import time; time.sleep(10)'],
                             self.root, timeout=0.05)
        self.assertEqual(result['exit_code'], 124)
        self.assertTrue(result['timeout'])

    def test_lockfile_has_fixed_https_inputs(self):
        lock = json.loads(probe.LOCK.read_text())
        self.assertEqual(lock['schema'], 1)
        self.assertEqual(set(lock['artifacts']), {'node', 'esbuild', 'typescript', 'tsx'})
        for artifact in lock['artifacts'].values():
            self.assertTrue(artifact['url'].startswith('https://'))
            self.assertEqual(len(artifact['commit']), 40)
            self.assertTrue({'sha256', 'integrity'} & artifact.keys())
            self.assertNotIn('..', Path(artifact['archive']).parts)


if __name__ == '__main__':
    unittest.main()
