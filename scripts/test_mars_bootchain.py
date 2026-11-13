"""Run inside the tools container against actual compiled artifacts.

Mutations test contract checks, not execution of firmware on a Mars board.
"""
import importlib.util
from pathlib import Path
import unittest
import shutil

spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('mars-check-bootchain.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
OUT = Path('/work/out')


@unittest.skipUnless(OUT.is_dir() and shutil.which('riscv64-linux-gnu-nm'), 'requires built artifacts in the tools container')
class BootchainTests(unittest.TestCase):
    def test_real_artifacts(self):
        self.assertEqual(boot.check(OUT)['status'], 'bootchain-contract-passed')

    def test_mutations(self):
        for name, mutate, message in [
            ('u-boot-spl.bin.normal.out', lambda b: b[:-1] + bytes([b[-1] ^ 1]), 'SPL CRC'),
            ('opensbi.config', lambda b: b.replace(b'CONFIG_SBI_ECALL_HSM=y', b'CONFIG_SBI_ECALL_HSM=n'), 'extension disabled'),
            ('uboot.config', lambda b: b.replace(b'CONFIG_ENV_IS_NOWHERE=y', b'CONFIG_ENV_IS_IN_SPI_FLASH=y'), 'U-Boot setting'),
            ('vibeos.bin', lambda b: bytes([b[0] ^ 1]) + b[1:], 'embedded bytes'),
        ]:
            with self.subTest(name=name):
                path = OUT / 'artifacts' / name
                original = path.read_bytes()
                changed = mutate(original)
                self.assertNotEqual(original, changed)
                try:
                    path.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, message):
                        boot.check(OUT)
                finally:
                    path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
