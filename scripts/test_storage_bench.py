import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("storage-bench.py")
SPEC = importlib.util.spec_from_file_location("storage_bench", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class StorageBenchTests(unittest.TestCase):
    def test_serial_transcript_survives_partial_marker_and_eof(self):
        import io
        from unittest.mock import Mock, patch
        for chunks, succeeds in [([b"diagnostic\r\nVI", b"BE!"], True),
                                 ([b"diagnostic\r\n", b""], False)]:
            transcript = io.BytesIO()
            selector = Mock()
            selector.select.return_value = [(object(), 1)]
            with patch.object(MODULE.selectors, "DefaultSelector", return_value=selector), \
                 patch.object(MODULE.os, "read", side_effect=chunks):
                if succeeds:
                    data = MODULE.wait_for(Mock(), Mock(), b"VIBE!", 30, transcript)
                    self.assertEqual(data, b"diagnostic\r\nVIBE!")
                else:
                    with self.assertRaisesRegex(RuntimeError, "serial closed"):
                        MODULE.wait_for(Mock(), Mock(), b"VIBE!", 30, transcript)
            self.assertEqual(transcript.getvalue(), b"".join(chunks))
            selector.close.assert_called_once()

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

    def test_storage_throttle_options_and_comparison_profiles(self):
        from argparse import Namespace
        self.assertEqual(MODULE.throttle_drive_options(Namespace()), "")
        args = Namespace(read_bps=4194304, write_bps=2097152, read_iops=400, write_iops=200)
        self.assertEqual(MODULE.throttle_drive_options(args),
                         ",bps_rd=4194304,bps_wr=2097152,iops_rd=400,iops_wr=200")
        with self.assertRaises(MODULE.ValidationError):
            MODULE.throttle_drive_options(Namespace(read_bps=-1))
        record = {"backend": "storage-v2", "layer": "object", "workload": "object-range-get",
                  "object_bytes": 4096, "object_count": 1, "queue_depth": 1,
                  "status": "ok", "warmup": False, "metrics": {"get_latency_ns": 100},
                  "environment": {}}
        compatible = dict(record, backend="linux-ext4", environment={"storage_throttle": MODULE.storage_throttle(Namespace())})
        self.assertEqual(len(MODULE.summaries([record, compatible])), 2)
        incompatible = dict(compatible, environment={"storage_throttle": MODULE.storage_throttle(args)})
        with self.assertRaises(MODULE.ValidationError):
            MODULE.summaries([record, incompatible])
        with self.assertRaisesRegex(MODULE.ValidationError, "cannot replace"):
            MODULE.require_baseline_evidence([incompatible], pathlib.Path("unused"), pathlib.Path("unused"))

    def test_guest_geometry_is_validated_and_different_store_sizes_do_not_mix(self):
        import json
        prefix = b"VIBE_STORAGE_BENCH_GEOMETRY "
        small = prefix + b'{"provisioned_segments":16}\r\n'
        self.assertEqual(MODULE.guest_storage_geometry(b"boot\n" + small),
                         {"storage_v2_provisioned_segments": 16})
        self.assertEqual(MODULE.guest_storage_geometry(b"old kernel boot\n"), {})
        with self.assertRaises(MODULE.ValidationError):
            MODULE.guest_storage_geometry(small + small)
        for invalid in (0, -1, True, "16", None):
            with self.assertRaises(MODULE.ValidationError):
                MODULE.guest_storage_geometry(prefix + json.dumps(
                    {"provisioned_segments": invalid}).encode())
        record = {"backend": "storage-v2", "layer": "object", "workload": "v2-dedup-gc",
                  "object_bytes": 4096, "object_count": 8, "queue_depth": 1,
                  "status": "ok", "warmup": False, "metrics": {"latency_ns": 100},
                  "environment": {"storage_v2_provisioned_segments": 16}}
        self.assertEqual(len(MODULE.summaries([record, record])), 1)
        for environment in ({}, {"storage_v2_provisioned_segments": 223}):
            with self.assertRaisesRegex(MODULE.ValidationError, "incompatible storage geometries"):
                MODULE.summaries([record, dict(record, environment=environment)])
        # The separate raw-block window is unaffected by the v2 partition size.
        raw = dict(record, layer="block")
        self.assertEqual(len(MODULE.summaries([raw, dict(raw, environment={})])), 1)

    def test_memory_profiles_cannot_be_mixed(self):
        record = {"backend": "storage-v2", "layer": "file-tree", "workload": "file-sequential",
                  "object_bytes": 16777216, "object_count": 1, "queue_depth": 1,
                  "status": "ok", "warmup": False, "metrics": {"latency_ns": 100},
                  "environment": {}}
        explicit_default = dict(record, environment={"memory_mib": 512})
        self.assertEqual(len(MODULE.summaries([record, explicit_default])), 1)
        smaller = dict(record, environment={"memory_mib": 128})
        with self.assertRaisesRegex(MODULE.ValidationError, "incompatible guest memory"):
            MODULE.summaries([record, smaller])
        for invalid in (0, -1, True, "128"):
            with self.assertRaisesRegex(MODULE.ValidationError, "invalid guest memory"):
                MODULE.summaries([dict(record, environment={"memory_mib": invalid})])

    def test_content_pattern_identity_is_preserved_and_mixing_rejected(self):
        sample = {"schema": "vibeos.storage-bench.sample", "version": 1,
                  "backend": "storage-v2", "layer": "file-tree", "workload": "file-sequential",
                  "object_bytes": 4096, "seed": 7, "timebase_hz": 1000,
                  "latency_ticks": 10, "latency_ns": 10, "sample_index": 0, "warmup": False,
                  "content_pattern": "splitmix64-offset-v1", "latency_scope": "workload", "status": "ok"}
        env = {"git_commit": "1234567", "qemu_version": "qemu", "qemu_args": [], "cache_state": "unknown"}
        record = MODULE.convert_guest_sample(sample, run_id="r", vm_index=0,
                 sample_index=0, warmup=False, seed=7, env=env)
        linux = MODULE.convert_linux_sample(dict(sample, backend="linux-ext4"),
                 run_id="linux", vm_index=0, env=env)
        self.assertEqual(record["environment"]["content_pattern"], "splitmix64-offset-v1")
        self.assertEqual(record["environment"]["latency_scope"], "workload")
        self.assertNotIn("content_pattern", env)
        with self.assertRaisesRegex(MODULE.ValidationError, "latency scopes"):
            MODULE.summaries([record, dict(linux, environment={**env, "content_pattern": "splitmix64-offset-v1"})])
        self.assertEqual(len(MODULE.summaries([record, linux])), 2)
        with self.assertRaisesRegex(MODULE.ValidationError, "content patterns"):
            MODULE.summaries([record, dict(linux, environment=env)])

    def test_sequential_pattern_matches_rust_and_c_and_detects_corruption(self):
        import json
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("rustc") or not shutil.which("cc"):
            self.skipTest("cross-language pattern check requires rustc and cc")
        root = SCRIPT.parent.parent
        source = (root / "benchmarks/storage/linux/package/storage-bench-agent/src/storage-bench-agent.c").read_text()
        c = source.split("// BEGIN offset-addressed")[1].split("// END offset-addressed")[0]
        c = c[c.index("static uint64_t"):]
        cases = [(0, 0), (19, 1), (19, 7), (19, 4095), (2**64-1, 3*1024*1024)]
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            c += "\nint main(void) { unsigned char b[129];\n"
            r = '#[path = ' + json.dumps(str(root / "kernel/src/storage_bench_pattern.rs")) + '] mod pattern;\nuse std::io::Write;\nfn main() { let mut b = [0u8;129];\n'
            for seed, offset in cases:
                c += f"sequential_pattern(b,129,UINT64_C({seed}),{offset},false); assert(sequential_pattern(b,129,UINT64_C({seed}),{offset},true)); fwrite(b,1,129,stdout); b[7]^=1; assert(!sequential_pattern(b,129,UINT64_C({seed}),{offset},true));\n"
                r += f"pattern::fill(&mut b,{seed},{offset}); assert!(pattern::matches(&b,{seed},{offset})); std::io::stdout().write_all(&b).unwrap(); b[7]^=1; assert!(!pattern::matches(&b,{seed},{offset}));\n"
            (d / "pattern.c").write_text("#include <stdint.h>\n#include <stdbool.h>\n#include <stdio.h>\n#include <assert.h>\n" + c + "return 0;}\n")
            (d / "pattern.rs").write_text(r + "}\n")
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(d / "pattern.c"), "-o", str(d / "c")], check=True, capture_output=True)
            subprocess.run(["rustc", "--edition=2021", str(d / "pattern.rs"), "-o", str(d / "rust")], check=True, capture_output=True)
            actual = subprocess.check_output([str(d / "rust")])
            self.assertEqual(actual, subprocess.check_output([str(d / "c")]))
            self.assertEqual(len(actual), 129 * len(cases))


if __name__ == "__main__":
    unittest.main()
