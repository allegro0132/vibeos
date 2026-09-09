"""Regression checks for the CV1800B U-Boot FIT load window."""
import importlib.util
import lzma
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("duo_fit", ROOT / "scripts/milkv-duo-fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)


class FitTests(unittest.TestCase):
    def test_reported_hang_image_rejected(self):
        with self.assertRaises(ValueError):
            fit.check_layout(8402256, 8423752)

    def test_fit_and_decompression_boundaries(self):
        fit.check_layout(fit.LOAD - fit.ENTRY, fit.FIT_LIMIT)
        for kernel, packed in [(0, 1), (1, 0),
                               (fit.LOAD - fit.ENTRY + 1, 1),
                               (1, fit.FIT_LIMIT + 1)]:
            with self.assertRaises(ValueError):
                fit.check_layout(kernel, packed)

    def test_prepare_preserves_kernel_and_fdt_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            raw = bytes(range(256)) * 1024
            (directory / "vibeos-milkv-duo.bin").write_bytes(raw)
            fit.prepare(directory, ROOT / "scripts/milkv-duo.its")
            packed = (directory / "vibeos-milkv-duo.bin.lzma").read_bytes()
            self.assertEqual(lzma.decompress(packed, format=lzma.FORMAT_ALONE), raw)
            self.assertEqual((directory / "vibeos-milkv-duo.bin").read_bytes(), raw)
            its = (directory / "milkv-duo.its").read_text()
            self.assertEqual(its.count('compression = "lzma";'), 1)
            self.assertEqual(its.count('compression = "none";'), 1)
            self.assertIn('entry = <0x00000000 0x80200000>;', its)


if __name__ == "__main__":
    unittest.main()
