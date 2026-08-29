#!/usr/bin/env python3
"""Collect one fresh C8.11-S3 fixed-QEMU code-8 SIMD campaign."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
BASE_PATH = HERE.with_name("qemu-c88-f5-float-target.py")
SPEC = importlib.util.spec_from_file_location("_vibeos_c811_s3_runner", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the frozen fixed-QEMU collector")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

BASE.__file__ = str(HERE)
BASE.VERIFIER = HERE.with_name("verify-c811-s3-simd-evidence.py")
BASE.PRODUCER = BASE.ROOT / "kernel/src/wasm_simd_executable_target.rs"
BASE.QUALIFICATION = BASE.ROOT / "acceptance/wasm-simd-target/src/c811.rs"
BASE.QUALIFICATION_MANIFEST = BASE.ROOT / "acceptance/wasm-simd-target/artifacts/c811-s3-qualification-manifest.json"
BASE.FEATURE = "wasm-c811-s3-simd-qemu-qualification"
BASE.SOURCE_COMMIT_ENV = "VIBEOS_C811_S3_SOURCE_COMMIT"
BASE.SOURCE_TREE_ENV = "VIBEOS_C811_S3_SOURCE_TREE"
BASE.CHALLENGE_ENV = "VIBEOS_C811_S3_CHALLENGE"
BASE.RUN_ID_ENV = "VIBEOS_C811_S3_RUN_ID"
BASE.MANIFEST_SHA256_ENV = "VIBEOS_C811_S3_MANIFEST_SHA256"
BASE.TRANSCRIPT_SCHEMA_SHA256_ENV = "VIBEOS_C811_S3_TRANSCRIPT_SCHEMA_SHA256"
BASE.SUITE_ID = "vibeos.c811.s3.simd-fixed-qemu"
BASE.ENVIRONMENT_SCHEMA = "vibeos.c811.s3.simd-fixed-qemu.environment"
BASE.RUN_ID_DOMAIN = b"vibeos.c811.s3.simd-fixed-qemu.run.v1\0"
BASE.COMPONENT_SHA256 = "7b85b9324409d7cc4484ca9e661a44fce2275e70407338a4f4326f71809a40a1"
BASE.QUALIFICATION_MANIFEST_SHA256 = "62ac9ba3adba3e6946624cfb4e20a0c7672ed18f7f79775551205a5fc3705c3f"
BASE.QUALIFICATION_MANIFEST_BYTES = 2_012
BASE.EXPECTED_SEMANTIC_SHA256 = "ddab9d539744523b332787be6f8a101de00108479c9644136538524f20cd4514"
BASE.META_PREFIX = "VIBE_C811_S3_META "
BASE.END_PREFIX = "VIBE_C811_S3_END "
BASE.PASS_PREFIX = "VIBE_C811_S3_PASS "
BASE.FAIL_PREFIX = "VIBE_C811_S3_FAIL"
BASE.FAMILY_PREFIX = "VIBE_C811_S3_"


def selftest() -> None:
    BASE.verify_qemu_contract()
    source_commit, source_tree = "1" * 40, "2" * 40
    challenge, manifest, schema = "3" * 64, "4" * 64, "5" * 64
    run_id = BASE.compute_run_id(source_commit, source_tree, challenge, manifest, schema)
    terminal = {"challenge": challenge, "run_id": run_id, "semantic_sha256": BASE.EXPECTED_SEMANTIC_SHA256}
    meta = {"source_commit": source_commit, "source_tree": source_tree, "challenge": challenge, "run_id": run_id, "manifest_sha256": manifest, "transcript_schema_sha256": schema}
    raw = (BASE.META_PREFIX + BASE.json.dumps(meta, separators=(",", ":"), sort_keys=True) + "\n"
        + BASE.END_PREFIX + BASE.json.dumps(terminal, separators=(",", ":"), sort_keys=True) + "\n"
        + BASE.PASS_PREFIX + BASE.json.dumps(terminal, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    observed = BASE.transcript_bindings(raw, source_commit=source_commit, source_tree=source_tree,
        challenge=challenge, run_id=run_id, manifest_sha256=manifest, transcript_schema_sha256=schema)
    if observed != BASE.EXPECTED_SEMANTIC_SHA256:
        BASE.fail("selftest terminal semantic binding differs")
    if BASE.transcript_failure(raw + b"VIBE_C811_S3_FAIL {}\n") is None:
        BASE.fail("selftest explicit failure was accepted")
    print("qemu-c811-s3-simd.py selftest: PASS")


BASE.selftest = selftest

if __name__ == "__main__":
    raise SystemExit(BASE.main())
