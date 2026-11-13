import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('probe', Path(__file__).parents[1] / 'mars-tcp-probe.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class TimingTests(unittest.TestCase):
    def rows(self):
        # Both start at zero; service admission is delayed and staggered.
        return [dict(bytes=1010000, first_payload_bytes=10000, start_ns=0,
                     end_ns=10_000_000_000, first_payload_ns=8_000_000_000,
                     payload_end_ns=10_000_000_000),
                dict(bytes=1010000, first_payload_bytes=10000, start_ns=0,
                     end_ns=12_000_000_000, first_payload_ns=9_000_000_000,
                     payload_end_ns=12_000_000_000)]

    def test_common_wall_interval_excludes_startup_without_summing_stream_rates(self):
        result = m.summarize('source', self.rows(), 1010000)
        self.assertEqual(result['payload_interval_bytes'], 2000000)
        self.assertEqual(result['payload_interval_seconds'], 4)
        self.assertEqual(result['payload_interval_receiver_mbps'], 4)
        self.assertAlmostEqual(result['aggregate_receiver_mbps'], 2020000*8/12/1e6)

    def test_host_send_time_is_not_reported_as_board_receive_time(self):
        result = m.summarize('sink', self.rows(), 1010000)
        self.assertIsNone(result['payload_interval_receiver_mbps'])

    def test_single_read_cannot_estimate_payload_interval_rate(self):
        row = self.rows()[0]
        row['first_payload_bytes'] = row['bytes']
        row['first_payload_ns'] = row['payload_end_ns']
        self.assertIsNone(m.summarize('source', [row], row['bytes'])['payload_interval_receiver_mbps'])

if __name__ == '__main__':
    unittest.main()
