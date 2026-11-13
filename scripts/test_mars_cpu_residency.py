import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('mars-cpu-residency.py'))
residency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(residency)


def sample(now, idle, *, active='true', since=10):
    return (f'NIDLE hz=100 harts=1 units=timer_ticks source=wfi_interval\n'
            f'NIDLE_HART h=0 active={active} since={since} now={now} idle={idle} sleeps=2\nNIDLE_END\n')


class ResidencyTests(unittest.TestCase):
    def test_delta_includes_only_non_idle_time(self):
        result = residency.compare(sample(100, 20), sample(1100, 820))
        self.assertEqual(result['harts'][0]['active_percent'], 20)
        self.assertEqual(result['total_active_core_seconds'], 2)

    def test_invalid_and_unavailable_samples_are_not_zero_cpu(self):
        for after in (sample(1100, 1021), sample(1100, 820, since=11),
                      sample(1100, 820, active='false'),
                      sample(1100, 820) + 'NIDLE_UNAVAILABLE h=0\n',
                      sample(1100, 820).replace('harts=1', 'harts=2'),
                      sample(1100, 820).replace('idle=820', 'idle=bad')):
            with self.subTest(after=after), self.assertRaises(ValueError):
                residency.compare(sample(100, 20), after)

    def test_counter_wrap(self):
        limit = 1 << 64
        result = residency.compare(sample(limit - 20, limit - 30), sample(80, 20))
        self.assertEqual(result['harts'][0]['active_percent'], 50)


if __name__ == '__main__':
    unittest.main()
