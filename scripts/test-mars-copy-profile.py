import importlib.util
import unittest
spec=importlib.util.spec_from_file_location('copies','scripts/mars-copy-profile.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class CopyParserTests(unittest.TestCase):
    def setUp(self):
        self.dump=('NCOPY window=(100, 1100) hz=1000 interval=127 min_bytes=256 capacity=512 units=timer_ticks\n'
            + ''.join(f'NCOPY_HART h={h} eligible={128 if h==0 else 0} dropped=0\n' for h in range(4))
            + 'NCOPY_ENTRY h=0 caller=0x100 key=64 calls=2 bytes=1024 ticks=10 max=7\nNCOPY_END\n')
    def test_complete(self):
        self.assertEqual(p.parse(self.dump)['harts'][0]['entries'][0]['size_bin'],1)
    def test_reject_incomplete_and_corrupt(self):
        for bad in [self.dump.replace('NCOPY_END',''),self.dump*2,
                    self.dump.replace('dropped=0','dropped=1'),self.dump.replace('calls=2','calls=1'),
                    self.dump.replace('bytes=1024','bytes=511'),self.dump.replace('max=7','max=11'),
                    self.dump.replace('key=64','key=512'),self.dump.replace('caller=0x100','caller=bad')]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):p.parse(bad)
    def test_reject_duplicate_record(self):
        row='NCOPY_ENTRY h=0 caller=0x100 key=64 calls=2 bytes=1024 ticks=10 max=7\n'
        with self.assertRaises(ValueError):p.parse(self.dump.replace(row,row*2))
if __name__=='__main__':unittest.main()
