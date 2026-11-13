import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('soak_audit', Path(__file__).parents[1] / 'mars-soak-audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SoakAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rx = {'seconds': 60, 'bits_per_second': 949000000, 'bytes': 7117500000}
        self.pool = dict(received=10, acquired=10, released=10, full=0, dropped=0, free=128, ready=0, borrowed=0)
        self.state = dict(requested_rounds=60, seconds_per_round=60, phase='traffic', passed=False, results=[
            dict(round=1, received=self.rx, resident_cores=.4, gap_seconds=None, pool=self.pool)])
        self.write('live.json', self.state)
        self.write('01-iperf.json', {'end': {'sum_received': self.rx}})
        (self.root / '01-pool.log').write_text('RX_POOL Stats { ' + ', '.join(f'{k}: {v}' for k, v in self.pool.items()) + ' }')
        for suffix, now, idle in [('before', 10000, 9000), ('after', 70000, 63000)]:
            lines = ['NIDLE hz=1000 harts=4 units=timer_ticks source=wfi_interval']
            lines += [f'NIDLE_HART h={h} active=true since=0 now={now} idle={idle} sleeps={now}' for h in range(4)]
            lines += ['NIDLE_END']
            (self.root / f'01-{suffix}.log').write_text('\n'.join(lines))

    def write(self, name, data):
        (self.root / name).write_text(json.dumps(data))

    def test_partial_success_remains_collecting(self):
        result = audit.audit(self.root)
        self.assertEqual(result['status'], 'collecting', result)
        self.assertEqual(result['completed_rounds'], 1)

    def test_raw_result_and_cpu_mismatches_fail(self):
        self.state['results'][0]['resident_cores'] = .2
        self.write('live.json', self.state)
        self.write('01-iperf.json', {'end': {'sum_received': dict(self.rx, bits_per_second=899000000)}})
        result = audit.audit(self.root)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(any('raw receiver' in p for p in result['problems']))
        self.assertTrue(any('four-hart' in p for p in result['problems']))

    def test_terminal_failure_cannot_be_hidden_by_good_rounds(self):
        self.write('summary.json', dict(self.state, phase='failed', error='serial timeout'))
        self.assertEqual(audit.audit(self.root)['status'], 'failed')

    def test_terminal_success_requires_all_rounds_and_final_integrity(self):
        self.write('summary.json', dict(self.state, passed=True, phase='complete'))
        self.write('integrity.json', dict(passed=False, phase='connect', requested_bytes=67108864))
        (self.root / 'pool-final.log').write_text('acquired: 10, released: 9, free: 127, ready: 0, borrowed: 1')
        for name, now in [('before', 1), ('after', 2)]:
            (self.root / f'bootlog-{name}.log').write_text(f'entry_ticks=0 now_ticks={now}\nBOOTLOG_END')
        result = audit.audit(self.root)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(any('all requested rounds' in p for p in result['problems']))
        self.assertTrue(any('64 MiB' in p for p in result['problems']))
        self.assertTrue(any('all loans' in p for p in result['problems']))

    def test_complete_consistent_evidence_passes(self):
        rows = []
        for index in range(1, 61):
            prefix = f'{index:02}'
            rows.append(dict(self.state['results'][0], round=index,
                             gap_seconds=None if index == 1 else 1.0))
            self.write(prefix + '-iperf.json', {'end': {'sum_received': self.rx}})
            (self.root / (prefix + '-pool.log')).write_text(
                'RX_POOL Stats { ' + ', '.join(f'{k}: {v}' for k, v in self.pool.items()) + ' }')
            for suffix, offset in [('before', 0), ('after', 60000)]:
                now = 10000 + (index - 1) * 61000 + offset
                lines = ['NIDLE hz=1000 harts=4 units=timer_ticks source=wfi_interval']
                lines += [f'NIDLE_HART h={h} active=true since=0 now={now} idle={now * 9 // 10} sleeps={now}' for h in range(4)]
                (self.root / (prefix + '-' + suffix + '.log')).write_text('\n'.join(lines + ['NIDLE_END']))
        self.write('summary.json', dict(self.state, results=rows, passed=True, phase='complete'))
        self.write('integrity.json', dict(passed=True, phase='complete', requested_bytes=67108864, confirmed_bytes=67108864))
        (self.root / 'pool-final.log').write_text('acquired: 10, released: 10, free: 128, ready: 0, borrowed: 0')
        for name, now in [('before', 1), ('after', 4000000)]:
            (self.root / f'bootlog-{name}.log').write_text(f'entry_ticks=0 now_ticks={now}\nBOOTLOG_END')
        result = audit.audit(self.root)
        self.assertEqual(result['status'], 'passed', result)
        self.assertEqual(result['completed_rounds'], 60)

    def test_reused_cpu_evidence_is_rejected(self):
        second = dict(self.state['results'][0], round=2, gap_seconds=.1)
        self.state['results'].append(second)
        self.write('live.json', self.state)
        for suffix in ['iperf.json', 'pool.log', 'before.log', 'after.log']:
            (self.root / ('02-' + suffix)).write_bytes((self.root / ('01-' + suffix)).read_bytes())
        result = audit.audit(self.root)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(any('continuity' in p for p in result['problems']))


if __name__ == '__main__':
    unittest.main()
