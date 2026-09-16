import importlib.util
import unittest

spec = importlib.util.spec_from_file_location("pc", "scripts/mars-pc-sample.py")
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)

class ParserTests(unittest.TestCase):
    def setUp(self):
        self.dump = ('NPC window=(100, 1100, 2) hz=1000\n'
            + ''.join(f'NPC_HART h={h} count={int(h == 0)} dropped=0\n' for h in range(4))
            + 'NPC_SAMPLE h=0 i=0 time=102 due=102 pc=0x100 ra=0x108\nNPC_END\n')

    def test_complete(self):
        self.assertEqual(pc.parse(self.dump)['harts'][0]['count'], 1)

    def test_reject_incomplete_and_corrupt(self):
        for bad in [self.dump.replace('NPC_END', ''),
                    self.dump.replace('time=102', 'time=1100'),
                    self.dump.replace('i=0', 'i=1'),
                    self.dump.replace('pc=0x100', 'pc=garbage'),
                    self.dump.replace('dropped=0', 'dropped=1'), self.dump * 2]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                pc.parse(bad)

    def test_folded_symbols(self):
        table = pc.symbols('00000100 00000008 T one\n00000100 00000008 T two\n')
        self.assertEqual(pc.symbolize(table, 0x104), 'shared@0x100 (2 aliases)')

    def test_symbol_bounds(self):
        table = pc.symbols('00000100 00000008 T one\n00000110 00000004 T two\n')
        self.assertEqual(pc.symbolize(table, 0x104), 'one')
        self.assertEqual(pc.symbolize(table, 0x108), '<unmapped>')

if __name__ == '__main__':
    unittest.main()
