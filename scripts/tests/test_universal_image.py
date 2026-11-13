import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('universal_image', SCRIPTS / 'universal-image.py')
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)
from universal_artifacts import load_manifest


def fixture():
    names = {'_start': 0, '__text_end': 4096, '__rodata_start': 4096, '__rodata_end': 8192,
             '__rela_start': 8192, '__rela_end': 8216, '__image_file_end': 8216,
             '__image_mem_end': 16384, '__bss_start': 12288, '__bss_end': 16384, '__heap_start': 16384}
    data = bytearray(12312)
    struct.pack_into('<QQq', data, 12288, 4096, 3, 12288)
    symbols = bytearray(24)
    strings = bytearray(b'\0')
    for name, address in names.items():
        symbols.extend(struct.pack('<IBBHQQ', len(strings), 0x10, 0, 1, address, 0))
        strings.extend(name.encode() + b'\0')
    symbol_offset = len(data)
    data.extend(symbols)
    string_offset = len(data)
    data.extend(strings)
    section_offset = len(data)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (0, 4, 2, 8192, 12288, 24, 0, 0, 8, 24),
                (0, 2, 0, 0, symbol_offset, len(symbols), 3, 1, 8, 24),
                (0, 3, 0, 0, string_offset, len(strings), 0, 0, 1, 0)]
    for section in sections:
        data.extend(struct.pack('<IIQQQQIIQQ', *section))
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01' + bytes(9), 3, 243, 1,
                     0, 64, section_offset, 0, 64, 56, 4, 64, len(sections), 0)
    for i, (flags, offset, address, filesz, memsz) in enumerate([
        (5, 4096, 0, 4096, 4096), (4, 8192, 4096, 4096, 4096),
        (6, 12288, 8192, 24, 24), (6, 0, 12288, 0, 4096)]):
        struct.pack_into('<IIQQQQQQ', data, 64 + i * 56, 1, flags, offset, address, address, filesz, memsz, 4096)
    return data


class ImageTests(unittest.TestCase):
    def test_valid_relative_image_and_raw_match(self):
        data = fixture()
        layout = image.inspect(data)
        self.assertEqual(layout['relocations'], 1)
        self.assertEqual(layout['static_bytes'], 16384)
        image.verify_raw(data, data[4096:12312], layout)
        with self.assertRaises(ValueError):
            image.verify_raw(data, bytes(8216), layout)

    def test_rejects_wrong_type_entry_and_writable_code(self):
        for offset, fmt, value in [(16, '<H', 2), (24, '<Q', 4), (68, '<I', 7)]:
            data = fixture()
            struct.pack_into(fmt, data, offset, value)
            with self.assertRaises(ValueError):
                image.inspect(data)

    def test_rejects_symbol_relocation_code_target_and_bad_addend(self):
        for target, kind, addend in [(4096, 2, 0), (4096, (1 << 32) | 3, 0),
                                    (0, 3, 0), (4097, 3, 0), (8216, 3, 0), (4096, 3, -1), (4096, 3, 16385)]:
            data = fixture()
            struct.pack_into('<QQq', data, 12288, target, kind, addend)
            with self.assertRaises(ValueError):
                image.inspect(data)

    def test_truncated_tables_fail(self):
        data = fixture()
        for size in [0, 8, 63, 128, 4096, len(data)-1]:
            with self.assertRaises(ValueError):
                image.inspect(data[:size])

    def test_manifest_rejects_tampered_kernel_and_configuration(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            raw = b'kernel'
            resolved = b'configuration'
            digest = hashlib.sha256(raw).hexdigest()
            record = dict(schema=1, boards=['qemu-virt'], image='vibeos.bin', bytes=len(raw), sha256=digest,
                          resolved_sha256=hashlib.sha256(resolved).hexdigest(), layout={'sha256': digest})
            (path / 'manifest.json').write_text(json.dumps(record))
            (path / 'vibeos.bin').write_bytes(raw)
            (path / 'resolved.toml').write_bytes(resolved)
            load_manifest(path / 'manifest.json', 'qemu-virt')
            with self.assertRaises(ValueError):
                load_manifest(path / 'manifest.json', 'milkv-mars')
            (path / 'resolved.toml').write_bytes(b'modified')
            with self.assertRaises(ValueError):
                load_manifest(path / 'manifest.json', 'qemu-virt')
            (path / 'resolved.toml').write_bytes(resolved)
            (path / 'vibeos.bin').write_bytes(b'modified')
            with self.assertRaises(ValueError):
                load_manifest(path / 'manifest.json', 'qemu-virt')


if __name__ == '__main__':
    unittest.main()
