import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'mars_tcp_analyze', Path(__file__).parents[1] / 'mars-tcp-analyze.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(**fields):
    return '\t'.join(str(fields.get(f, '')) for f in module.FIELDS) + '\n'


class TcpAnalysisTests(unittest.TestCase):
    def test_window_belongs_to_opposite_direction_and_stream(self):
        common = {'tcp.stream': 1, 'ip.src': 'board', 'tcp.srcport': 5201,
                  'ip.dst': 'host', 'tcp.dstport': 9000}
        peer = {'tcp.stream': 1, 'ip.src': 'host', 'tcp.srcport': 9000,
                'ip.dst': 'board', 'tcp.dstport': 5201}
        lines = [row(**{**peer, 'frame.time_epoch': 1,
                       'tcp.window_size': 1000, 'tcp.window_size_scalefactor': 1}),
                 row(**{**common, 'frame.time_epoch': 2, 'tcp.len': 100,
                        'tcp.window_size': 9000, 'tcp.window_size_scalefactor': 1,
                        'tcp.analysis.bytes_in_flight': 500}),
                 row(**{**common, 'frame.time_epoch': 2.002, 'tcp.len': 100,
                        'tcp.analysis.bytes_in_flight': 600}),
                 row(**{**common, 'tcp.stream': 2, 'frame.time_epoch': 3,
                        'tcp.len': 1600, 'tcp.analysis.bytes_in_flight': 1600})]
        result = {d['stream']: d for d in module.analyze(lines) if d['data_bytes']}
        self.assertEqual(result[1]['utilization']['max'], .6)
        self.assertEqual(result[1]['data_gaps_ms']['count'], 1)
        self.assertEqual(result[1]['large_gap_count'], 1)
        self.assertAlmostEqual(result[1]['large_gaps'][0]['gap_ms'], 2)
        self.assertIsNone(result[2]['utilization'])
        self.assertEqual(result[2]['over_mss_1460'], 1)

    def test_missing_scale_does_not_create_window_utilization(self):
        result = module.analyze([row(**{'frame.time_epoch': 1, 'tcp.stream': 0,
            'ip.src': 'a', 'tcp.srcport': 1, 'ip.dst': 'b', 'tcp.dstport': 2,
            'tcp.len': 100, 'tcp.window_size': 1234,
            'tcp.window_size_scalefactor': -1,
            'tcp.analysis.retransmission': 1, 'tcp.analysis.ack_rtt': .002})])[0]
        self.assertEqual(result['flags']['retransmission'], 1)
        self.assertIsNone(result['utilization'])
        self.assertEqual(result['ack_rtt_ms']['max'], 2)
        self.assertFalse(result['syn_seen'])

    def test_tshark_hex_syn_is_recognized(self):
        result = module.analyze([row(**{'frame.time_epoch': 1, 'tcp.stream': 0,
            'ip.src': 'a', 'tcp.srcport': 1, 'ip.dst': 'b', 'tcp.dstport': 2,
            'tcp.flags.syn': '0x00000001', 'tcp.options.wscale.shift': 3})])[0]
        self.assertTrue(result['syn_seen'])
        self.assertEqual(result['scale_shifts'], [3])
        self.assertIsNone(result['last_ack'])

    def test_tshark_boolean_syn_is_recognized(self):
        for value, expected in [('True', True), ('False', False)]:
            result = module.analyze([row(**{'frame.time_epoch': 1, 'tcp.stream': 0,
                'ip.src': 'a', 'tcp.srcport': 1, 'ip.dst': 'b', 'tcp.dstport': 2,
                'tcp.flags.syn': value})])[0]
            self.assertEqual(result['syn_seen'], expected)


if __name__ == '__main__':
    unittest.main()
