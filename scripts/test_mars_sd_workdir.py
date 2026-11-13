#!/usr/bin/env python3
"""Check build-output admission before any SDK, compiler or Docker access."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class WorkDirectory(unittest.TestCase):
    def run_builder(self, *args):
        # If output admission regresses, stop before real SDK/network/build IO.
        with tempfile.TemporaryDirectory() as guard:
            git = Path(guard) / 'git'
            git.write_text('#!/bin/sh\nexit 99\n')
            git.chmod(0o755)
            env = {**os.environ, 'PATH': guard + os.pathsep + os.environ['PATH']}
            return subprocess.run(['sh', str(ROOT / 'scripts/build-mars-sd.sh'), *args],
                                  cwd='/', env=env, capture_output=True, text=True)

    def test_rejects_invalid_arguments(self):
        for args in [('--work-dir',), ('--work-dir', ''),
                     ('--work-dir', '--trng-probe'),
                     ('--trng-probe', '--trng-probe'),
                     ('--work-dir', 'one', '--work-dir', 'two')]:
            with self.subTest(args=args):
                result = self.run_builder(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn('usage:', result.stderr)

    def test_preserves_existing_image_and_evidence_for_every_profile(self):
        for name in ['mars-serial-sd.img', 'mars-ethernet-trng-probe-sd.img']:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='Mars SD archive ') as work:
                out = Path(work) / 'out'
                out.mkdir()
                image = out / name
                image.write_bytes(b'existing image')
                manifest = out / 'manifest.json'
                manifest.write_bytes(b'existing evidence')
                result = self.run_builder('--ethernet', '--trng-probe', '--work-dir', work)
                self.assertEqual(result.returncode, 1)
                self.assertIn('before rebuilding', result.stderr)
                self.assertEqual(image.read_bytes(), b'existing image')
                self.assertEqual(manifest.read_bytes(), b'existing evidence')
                self.assertFalse((Path(work) / 'input').exists())

    def test_rejects_dangling_image_link(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / 'out'
            out.mkdir()
            image = out / 'mars-serial-sd.img'
            image.symlink_to(out / 'missing')
            result = self.run_builder('--work-dir', work)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(image.is_symlink())
            self.assertFalse((Path(work) / 'input').exists())


if __name__ == '__main__':
    unittest.main()
