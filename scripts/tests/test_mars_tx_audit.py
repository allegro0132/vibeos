import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('audit', Path(__file__).parents[1] / 'mars-tx-audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def frame():
    b = bytearray(60)
    b[12:14] = b'\x08\x00'
    b[14] = 0x45
    b[16:18] = (46).to_bytes(2, 'big')
    b[23] = 6
    b[26:30] = bytes([192, 168, 77, 10])
    b[30:34] = bytes([192, 168, 77, 1])
    b[34:38] = struct.pack('!HH', 5300, 40000)
    b[38:46] = struct.pack('!II', 123456, 765432)
    b[46:50] = bytes([0x50, 0x18, 0x10, 0])
    return b


class AuditTests(unittest.TestCase):
    def test_hardware_delta_requires_quiescence_and_non_destructive_mode(self):
        def dump(start, stop):
            return f'NTXAUDIT_HW phase=start values={start}\nNTXAUDIT_HW phase=stop values={stop}\n'
        start = [1, 20, 0, 0, 20, 20, 0, 0, 0]
        stop = [1, 120, 0, 0, 120, 120, 0, 0, 0]
        result = audit.hardware_comparison(dump(start, stop))
        self.assertTrue(result['quiescent_comparison_valid'])
        self.assertEqual(result['accepted_delta'], 100)
        self.assertEqual(result['counter_deltas']['frames_good'], 100)
        for index, value in [(0, 0), (2, 1), (3, 4), (4, 0xffffffff)]:
            invalid = stop.copy()
            invalid[index] = value
            self.assertFalse(audit.hardware_comparison(dump(start, invalid))['quiescent_comparison_valid'])

    def test_golden_and_checksum_offload_equivalence(self):
        b = frame()
        original = audit.fingerprint(b)
        self.assertEqual(original[0], 7696094402707891304)
        self.assertEqual(original[1:], (6, 0x18))
        b[24] = 0xaa
        b[50] = 0xbb
        self.assertEqual(audit.fingerprint(b), original)
        b[41] ^= 1
        self.assertNotEqual(audit.fingerprint(b), original)

    def test_pcap_duplicate_counts_and_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'test.pcap'
            header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            packet = struct.pack('<IIII', 1, 0, 60, 60) + frame()
            p.write_bytes(header + packet + packet)
            captured, totals = audit.capture_totals(p)
            self.assertEqual((captured, totals[0], totals[1], totals[3]), (2, 2, 12, 0))
            p.write_bytes(header + struct.pack('<IIII', 1, 0, 59, 60) + frame()[:59])
            with self.assertRaisesRegex(ValueError, 'truncated'):
                audit.capture_totals(p)
            self.assertEqual(audit.capture_totals(p, True)[1][0:2], [1, 6])
            p.write_bytes(header + struct.pack('<IIII', 1, 0, 53, 60) + frame()[:53])
            with self.assertRaisesRegex(ValueError, 'headers'):
                audit.capture_totals(p, True)

    def test_host_ack_is_excluded(self):
        b = frame()
        b[26:30], b[30:34] = b[30:34], b[26:30]
        self.assertIsNone(audit.fingerprint(b))


if __name__ == '__main__':
    unittest.main()
