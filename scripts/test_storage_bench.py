import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("storage-bench.py")
SPEC = importlib.util.spec_from_file_location("storage_bench", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class StorageBenchTests(unittest.TestCase):
    def test_validator_selftest(self):
        MODULE.selftest()

    def test_percentiles_are_interpolated(self):
        self.assertEqual(MODULE.percentile([1.0, 2.0, 3.0], 0.5), 2.0)
        self.assertAlmostEqual(MODULE.percentile([1.0, 3.0], 0.95), 2.9)

    def test_guest_sample_is_enriched_outside_guest(self):
        record = MODULE.convert_guest_sample(
            {"schema": "vibeos.storage-bench.sample", "version": 1,
             "backend": "storage-v2", "layer": "object",
             "workload": "object-durable-put-get", "object_bytes": 4096,
             "seed": 7, "timebase_hz": 10_000_000, "put_ticks": 10,
             "get_ticks": 20, "block_requests": 3, "block_read_requests": 1,
             "block_write_requests": 1, "block_flush_requests": 1,
             "block_read_bytes": 4096, "block_write_bytes": 4096,
             "block_used_interrupts": 3, "status": "ok"},
            run_id="r", vm_index=2, sample_index=3, warmup=False, seed=7,
            env={"git_commit": "1234567", "qemu_version": "qemu",
                 "qemu_args": [], "cache_state": "unknown"},
        )
        self.assertEqual(record["metrics"]["put_latency_ns"], 1000.0)
        self.assertEqual(record["vm_index"], 2)

    def test_linux_sample_preserves_device_accounting(self):
        record = MODULE.convert_linux_sample(
            {"schema": "vibeos.storage-bench.sample", "version": 1,
             "backend": "linux-ext4", "layer": "object",
             "workload": "object-durable-put-get", "object_bytes": 4096,
             "seed": 8, "sample_index": 0, "warmup": False,
             "put_ns": 100, "get_ns": 20, "block_requests": 7,
             "block_read_requests": 1, "block_write_requests": 4,
             "block_flush_requests": 2, "block_read_bytes": 4096,
             "block_write_bytes": 16384, "status": "ok"},
            run_id="linux", vm_index=0,
            env={"git_commit": "1234567", "qemu_version": "qemu",
                 "qemu_args": [], "cache_state": "unknown"},
        )
        self.assertEqual(record["metrics"]["put_latency_ns"], 100.0)
        self.assertEqual(record["counters"]["flush_requests"], 2)
        self.assertEqual(record["counters"]["write_bytes"], 16384)

    def test_guest_phase_io_is_split_and_inconsistent_totals_rejected(self):
        sample = {"schema": "vibeos.storage-bench.sample", "version": 1,
                  "backend": "storage-v2", "layer": "object", "workload": "object-range-get",
                  "object_bytes": 131072, "seed": 7, "timebase_hz": 1000,
                  "put_ticks": 10, "get_ticks": 2, "latency_ticks": 12, "status": "ok"}
        for name, put, get in [("requests", 10, 3), ("read_requests", 5, 3),
                               ("write_requests", 3, 0), ("flush_requests", 2, 0),
                               ("read_bytes", 8192, 4096), ("write_bytes", 8192, 0),
                               ("used_interrupts", 10, 3)]:
            sample["put_block_" + name] = put
            sample["block_" + name] = put + get
        args = dict(run_id="r", vm_index=0, sample_index=0, warmup=False, seed=7,
                    env={"git_commit": "1234567", "qemu_version": "qemu",
                         "qemu_args": [], "cache_state": "unknown"})
        record = MODULE.convert_guest_sample(sample, **args)
        self.assertEqual(record["phases"]["get_requests"], 3)
        self.assertEqual(record["phases"]["get_read_bytes"], 4096)
        self.assertEqual(record["phases"]["get_flush_requests"], 0)
        self.assertEqual(record["metrics"]["get_latency_ns"], 2_000_000)
        self.assertEqual(record["metrics"]["latency_ns"], 12_000_000)
        sample["block_requests"] = 9
        with self.assertRaises(MODULE.ValidationError):
            MODULE.convert_guest_sample(sample, **args)

    def test_linux_composite_keeps_total_and_pure_read_latency(self):
        record = MODULE.convert_linux_sample(
            {"schema": "vibeos.storage-bench.sample", "version": 1,
             "backend": "linux-ext4", "layer": "object", "workload": "object-range-get",
             "object_bytes": 131072, "seed": 8, "sample_index": 0, "warmup": False,
             "latency_ns": 130, "put_ns": 100, "get_ns": 20, "status": "ok"},
            run_id="linux", vm_index=0,
            env={"git_commit": "1234567", "qemu_version": "qemu", "qemu_args": [],
                 "cache_state": "unknown"})
        self.assertEqual(record["metrics"], {"latency_ns": 130.0,
                         "put_latency_ns": 100.0, "get_latency_ns": 20.0})


if __name__ == "__main__":
    unittest.main()
