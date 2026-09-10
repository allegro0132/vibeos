import importlib.util
from pathlib import Path
import struct
import unittest
spec = importlib.util.spec_from_file_location('mars_image', Path(__file__).resolve().parents[1] / 'mars-check-image.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def fixture():
    data = bytearray(0x3600)
    load = module.LOAD
    stack = load + 0x3000
    values = {'_start': load, '__heap_start': stack + 0x100000, '__heap_end': module.RAM_END,
              '__stacks_bottom': stack, '__stacks_top': stack + 0x100000,
              '__stack_guard_size': 4096, '__kernel_stack_stride': 256 * 1024,
              '__bss_start': load + 0x1100, '__bss_end': load + 0x2000}
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 2, 243, 1, load, 64, 0x400, 1, 64, 56, 2, 64, 3, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x1000, load, load, 0x100, 0x100, 4096)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 6, 0x2000, load + 0x1000, load + 0x1000, 0x100, 0x2000, 4096)
    strings = bytearray(b'\0')
    offsets = {}
    for i, (name, value) in enumerate(values.items()):
        offset = 0x3100 + (i + 1) * 24
        struct.pack_into('<IBBHQQ', data, offset, len(strings), 0x10, 0, 1, value, 0)
        strings.extend(name.encode() + b'\0')
        offsets[name] = offset + 8
    data[0x3000:0x3000 + len(strings)] = strings
    struct.pack_into('<IIQQQQIIQQ', data, 0x440, 0, 3, 0, 0, 0x3000, len(strings), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 0x480, 0, 2, 0, 0, 0x3100, (len(values) + 1) * 24, 1, 0, 8, 24)
    return data, offsets

class MarsImage(unittest.TestCase):
    def test_64_bit_heap_ceiling_is_preserved(self):
        report = module.inspect(fixture()[0])
        self.assertEqual(report['heap_end'], 0x140000000)
        self.assertFalse(report['flashable_sd_image'])
        self.assertFalse(report['physical_acceptance'])
    def test_rejects_header_load_and_stack_corruption(self):
        base, symbols = fixture()
        for fmt, offset, value in [('<Q', 24, 0x80200000), ('<I', 124, 7),
                                   ('<Q', 64 + 24, 0x40000000),
                                   ('<Q', symbols['__heap_end'], 0x88000000),
                                   ('<Q', symbols['__stack_guard_size'], 0),
                                   ('<Q', symbols['__bss_end'], module.RAM_END)]:
            mutated = base.copy()
            struct.pack_into(fmt, mutated, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                module.inspect(mutated)
    def test_rejects_truncation_and_missing_boot_symbols(self):
        data, _ = fixture()
        for size in [0, 63, 128, 0x3100]:
            with self.subTest(size=size), self.assertRaises(ValueError):
                module.inspect(data[:size])
        start = data.index(b'__heap_start\0')
        data[start] = ord('x')
        with self.assertRaises(ValueError):
            module.inspect(data)
