#!/usr/bin/env python3
"""Check versioned stage schemas and reconciliation of frontend phase totals."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('profile_parser', Path(__file__).with_name('mars-network-profile.py'))
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def capture(stages):
    ticks = [i + 1 for i in range(len(stages))]
    zero = [0] * len(stages)
    values = f'ticks={json.dumps(ticks)} wait={json.dumps(zero)} calls={json.dumps(ticks)}'
    return '\n'.join([
        f'NPROF window=(100, 200, 100) stages={json.dumps(stages)}',
        f'NPROF_SAMPLING stages={json.dumps(parser.RX_STAGES[-4:])} interval=64',
        f'NPROF_HART h=0 {values}',
        f'NPROF i=0 {values} high=[0, 0] full=[0, 0] dma=[0, 0, 0]',
        'NPROF_END',
    ])


class SchemaTests(unittest.TestCase):
    def test_old_and_frontend_schemas(self):
        for stages in [parser.RX_STAGES, parser.FRONTEND_STAGES]:
            result = parser.analyze(capture(stages))
            self.assertEqual(result['stages'], stages)
            self.assertEqual(result['sampling']['stages'], parser.RX_STAGES[-4:])
            for i, stage in enumerate(stages):
                self.assertEqual(result['phases'][stage]['exclusive_ticks'], i + 1)

    def test_sampled_frontend_phases(self):
        sampled = parser.RX_STAGES[-4:] + parser.FRONTEND_STAGES[-4:]
        text = capture(parser.FRONTEND_STAGES).replace(json.dumps(parser.RX_STAGES[-4:]), json.dumps(sampled))
        self.assertEqual(parser.analyze(text)['sampling']['stages'], sampled)
        self.assertEqual(parser.analyze(text.replace('interval=64', 'interval=127'))['sampling']['interval'], 127)

    def test_truncated_phase_array_rejected(self):
        text = capture(parser.FRONTEND_STAGES)
        text = text.replace('calls=' + json.dumps(list(range(1, 21))), 'calls=' + json.dumps(list(range(1, 20))), 1)
        with self.assertRaises(ValueError):
            parser.analyze(text)

    def test_mismatched_hart_total_rejected(self):
        text = capture(parser.FRONTEND_STAGES).replace('ticks=[1, 2,', 'ticks=[2, 2,', 1)
        with self.assertRaises(ValueError):
            parser.analyze(text)

    def test_new_phases_must_not_be_declared_sampled(self):
        text = capture(parser.FRONTEND_STAGES).replace(json.dumps(parser.RX_STAGES[-4:]), json.dumps(parser.FRONTEND_STAGES[-4:]))
        with self.assertRaises(ValueError):
            parser.analyze(text)


if __name__ == '__main__':
    unittest.main()
