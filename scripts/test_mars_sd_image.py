"""Host image tests do not emulate the Mars ROM or exercise an SD controller."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import struct
import zlib

spec = importlib.util.spec_from_file_location("mars_sd", Path(__file__).with_name("mars-sd-image.py"))
sd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sd)


class ImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.image = cls.root / "test.img"
        for _, _, _, _, name in sd.PARTITIONS:
            if name:
                (cls.root / name).write_bytes((name + " test payload").encode())
        cls.report = sd.assemble(cls.image, cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_data_contract(self):
        self.assertEqual(self.report["partitions"][3], {
            "name": "vibeos-data", "first_sector": 262144, "sector_count": 1048576})
        self.assertFalse(self.report["physical_acceptance"])

    def test_reject_overwrite_and_symlink(self):
        with self.assertRaises(FileExistsError):
            sd.assemble(self.image, self.root)
        link = self.root / "link"
        link.symlink_to(self.image)
        with self.assertRaises(FileExistsError):
            sd.assemble(link, self.root)

    def test_corruption(self):
        for offset, diagnostic in [
            (4, "ROM backup SPL"), (0x290, "ROM fallback CRC"),
            (510, "MBR"), (512 + 16, "header CRC"),
            (1024 + 32, "entries CRC"), (sd.IMAGE_BYTES - 512 + 16, "header CRC"),
            (2 * sd.MIB, "payload mismatch"), (128 * sd.MIB, "must be blank"),
        ]:
            with self.subTest(offset=offset):
                with self.image.open("r+b") as f:
                    f.seek(offset)
                    original = f.read(1)
                    f.seek(offset)
                    f.write(bytes([original[0] ^ 0x80]))
                try:
                    with self.assertRaisesRegex(ValueError, diagnostic):
                        sd.inspect(self.image, self.root)
                finally:
                    with self.image.open("r+b") as f:
                        f.seek(offset)
                        f.write(original)

    def test_oversized_input_before_output(self):
        p = self.root / "firmware.itb"
        original = p.read_bytes()
        try:
            with p.open("wb") as f:
                f.truncate(4 * sd.MIB + 1)
            output = self.root / "invalid.img"
            with self.assertRaisesRegex(ValueError, "invalid payload"):
                sd.assemble(output, self.root)
            self.assertFalse(output.exists())
        finally:
            p.write_bytes(original)

    def test_resealed_partition_boundary(self):
        end = sd.IMAGE_BYTES // sd.SECTOR - 1
        with self.image.open('r+b') as f:
            head = f.read(34 * sd.SECTOR)
            f.seek((end - 32) * sd.SECTOR)
            tail = f.read(33 * sd.SECTOR)
            entries = bytearray(head[1024:])
            struct.pack_into('<Q', entries, 3 * 128 + 32, 262145)
            crc = zlib.crc32(entries)
            for current, backup, lba in [(1, end, 2), (end, 1, end - 32)]:
                f.seek(current * sd.SECTOR)
                h = sd.header(current, backup, lba, crc)
                if current == 1:
                    struct.pack_into('<I', h, sd.ROM_CRC_OFFSET - sd.SECTOR, sd.ROM_FAILED_CRC)
                f.write(h)
                f.seek(lba * sd.SECTOR)
                f.write(entries)
        try:
            with self.assertRaisesRegex(ValueError, 'partition bounds'):
                sd.inspect(self.image, self.root)
        finally:
            with self.image.open('r+b') as f:
                f.write(head)
                f.seek((end - 32) * sd.SECTOR)
                f.write(tail)


if __name__ == "__main__":
    unittest.main()
