"""The persisted-identity probe must fail on bad or ambiguous evidence."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
path=Path(__file__).resolve().parents[1]/'qemu-provisioned-service-test.py'
spec=importlib.util.spec_from_file_location('probe',path)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
def record(generation=1,flags=5,seed=42):
    data=bytearray(512);data[:8]=b'VSSHKEY1';struct.pack_into('<HHQ',data,8,1,flags,generation)
    data[20:52]=bytes([seed])*32;data[352:384]=bytes([43])*32
    struct.pack_into('<I',data,508,probe.crc32c(data[:508]));return bytes(data)
class Probe(unittest.TestCase):
    def test_crc32c_standard_vector(self):self.assertEqual(probe.crc32c(b'123456789'),0xe3069283)
    def test_latest_record_and_ambiguous_or_invalid_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            disk=Path(temp)/'disk'
            disk.write_bytes(record()+record(2));self.assertEqual(probe.identity(disk)[0],2)
            bad=bytearray(record());bad[20]^=1
            for data in [bytes(bad),record()[:128],record(flags=7),record(flags=13),record()+record(seed=44),record()+record(2,flags=7)]:
                disk.write_bytes(data)
                with self.assertRaises(AssertionError):probe.identity(disk)
    def test_existing_log_does_not_launch_qemu(self):
        with tempfile.TemporaryDirectory() as temp:
            log=Path(temp)/'log';log.touch()
            with patch.object(probe.subprocess,'Popen') as launch:
                with self.assertRaises(FileExistsError):probe.boot(Path(temp)/'kernel',Path(temp)/'disk',log,False)
                launch.assert_not_called()
if __name__=='__main__':unittest.main()
