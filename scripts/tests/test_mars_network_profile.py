import importlib.util
import json
import re
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'mars_network_profile', Path(__file__).parents[1] / 'mars-network-profile.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ProfileTests(unittest.TestCase):
    def fixture(self):
        values = 'ticks=[1, 2, 3, 4, 0, 0, 0, 0] wait=[0, 1, 0, 0, 0, 0, 0, 0] calls=[1, 1, 1, 1, 0, 0, 0, 0]'
        return ('NPROF window=(100, 200, 100)\n'
                f'NPROF_HART h=0 {values}\n'
                f'NPROF i=0 {values} high=[32, 8] full=[9, 0] dma=[1, 3204, 65536]\n'
                'NPROF_END\n')

    def test_wait_is_separate_and_queue_full_is_attempt_count(self):
        d = m.analyze(self.fixture())
        self.assertEqual(d['phases']['driver']['exclusive_ticks'], 2)
        self.assertEqual(d['phases']['driver']['contended_wait_ticks'], 1)
        self.assertEqual(d['queues']['inbound']['full_attempts'], 9)
        self.assertEqual(d['dma_observations'][0]['mtl'], 65536)
        self.assertAlmostEqual(sum(p['percent_active_work'] + p['percent_active_wait']
                                   for p in d['phases'].values()), 100)

    def test_exact_lock_identity_and_totals(self):
        row = 'NPROF_LOCK h=0 address=0x1000 wait=[0, 1, 0, 0, 0, 0, 0, 0] calls=[0, 1, 0, 0, 0, 0, 0, 0]\n'
        text = self.fixture() + 'NPROF_LOCK_NAME address=0x1000 name=control\n' + row
        self.assertEqual(m.analyze(text)['locks'][0]['name'], 'control')
        for bad in [text + row, text.replace('wait=[0, 1', 'wait=[0, 2', 1)]:
            with self.assertRaises(ValueError):
                m.analyze(bad)

    def test_extended_schema_preserves_legacy_and_checks_new_stage_lengths(self):
        text = self.fixture().replace('window=(100, 200, 100)',
            'window=(100, 200, 100) stages=' + json.dumps(m.EXTENDED_STAGES))
        text = re.sub(r'(ticks|wait|calls)=(\[[^\]]*\])',
            lambda x: x[1] + '=' + json.dumps(json.loads(x[2]) + [7, 0, 0, 0]), text)
        d = m.analyze(text)
        self.assertEqual(d['phases']['packet_queue']['exclusive_ticks'], 7)
        self.assertEqual(len(d['stages']), 12)
        with self.assertRaises(ValueError):
            m.analyze(text.replace('"completion"', '"unexpected"'))
        with self.assertRaises(ValueError):
            m.analyze(text.replace(', 7, 0, 0, 0]', ']', 1))

    def test_incomplete_or_inconsistent_dump_is_not_success(self):
        for text in [self.fixture().replace('NPROF_END', ''),
                     self.fixture().replace('i=0', 'i=1'),
                     self.fixture().replace('ticks=[1', 'ticks=[2', 1),
                     self.fixture() + self.fixture().splitlines()[2] + '\n']:
            with self.assertRaises(ValueError):
                m.analyze(text)


if __name__ == '__main__':
    unittest.main()
