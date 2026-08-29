#!/usr/bin/env python3
"""Collect one fresh C8.10-S5 fixed-QEMU SIMD qualification campaign."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
BASE_PATH = HERE.with_name("qemu-c88-f5-float-target.py")
SPEC = importlib.util.spec_from_file_location("_vibeos_c810_s5_runner", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the frozen fixed-QEMU collector")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

BASE.__file__ = str(HERE)
BASE.VERIFIER = HERE.with_name("verify-c810-s5-simd-evidence.py")
BASE.PRODUCER = BASE.ROOT / "kernel/src/wasm_simd_target.rs"
BASE.QUALIFICATION = BASE.ROOT / "acceptance/wasm-simd-target/src/lib.rs"
BASE.QUALIFICATION_MANIFEST = (
    BASE.ROOT
    / "acceptance/wasm-simd-target/artifacts/c810-s5-qualification-manifest.json"
)
BASE.FEATURE = "wasm-c810-s5-simd-qemu-qualification"
BASE.SOURCE_COMMIT_ENV = "VIBEOS_C810_S5_SOURCE_COMMIT"
BASE.SOURCE_TREE_ENV = "VIBEOS_C810_S5_SOURCE_TREE"
BASE.CHALLENGE_ENV = "VIBEOS_C810_S5_CHALLENGE"
BASE.RUN_ID_ENV = "VIBEOS_C810_S5_RUN_ID"
BASE.MANIFEST_SHA256_ENV = "VIBEOS_C810_S5_MANIFEST_SHA256"
BASE.TRANSCRIPT_SCHEMA_SHA256_ENV = "VIBEOS_C810_S5_TRANSCRIPT_SCHEMA_SHA256"
BASE.SUITE_ID = "vibeos.c810.s5.simd-fixed-qemu"
BASE.ENVIRONMENT_SCHEMA = "vibeos.c810.s5.simd-fixed-qemu.environment"
BASE.RUN_ID_DOMAIN = b"vibeos.c810.s5.simd-fixed-qemu.run.v1\0"
BASE.COMPONENT_SHA256 = (
    "217c1eb45d78d7cc4a267ae9b1c3e0b366f281e4b8048a86b6ce4f5a0990186f"
)
BASE.QUALIFICATION_MANIFEST_SHA256 = (
    "2a76b48905638b0a12bb3277f296a869c736f063331e79bc17fc8ac125a4109c"
)
BASE.QUALIFICATION_MANIFEST_BYTES = 1_975
BASE.EXPECTED_SEMANTIC_SHA256 = (
    "6b34b541a42fdf838eccd55e43473a4154421eadc0e3b4292a5a89fde54ae1c6"
)
BASE.META_PREFIX = "VIBE_C810_S5_META "
BASE.END_PREFIX = "VIBE_C810_S5_END "
BASE.PASS_PREFIX = "VIBE_C810_S5_PASS "
BASE.FAIL_PREFIX = "VIBE_C810_S5_FAIL"
BASE.FAMILY_PREFIX = "VIBE_C810_S5_"


def selftest() -> None:
    BASE.verify_qemu_contract()
    source_commit = "1" * 40
    source_tree = "2" * 40
    challenge = "3" * 64
    manifest = "4" * 64
    schema = "5" * 64
    run_id = BASE.compute_run_id(
        source_commit, source_tree, challenge, manifest, schema
    )
    terminal = {
        "challenge": challenge,
        "run_id": run_id,
        "semantic_sha256": BASE.EXPECTED_SEMANTIC_SHA256,
    }
    meta = {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "challenge": challenge,
        "run_id": run_id,
        "manifest_sha256": manifest,
        "transcript_schema_sha256": schema,
    }
    raw = (
        BASE.META_PREFIX
        + BASE.json.dumps(meta, separators=(",", ":"), sort_keys=True)
        + "\n"
        + BASE.END_PREFIX
        + BASE.json.dumps(terminal, separators=(",", ":"), sort_keys=True)
        + "\n"
        + BASE.PASS_PREFIX
        + BASE.json.dumps(terminal, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    observed = BASE.transcript_bindings(
        raw,
        source_commit=source_commit,
        source_tree=source_tree,
        challenge=challenge,
        run_id=run_id,
        manifest_sha256=manifest,
        transcript_schema_sha256=schema,
    )
    if observed != BASE.EXPECTED_SEMANTIC_SHA256:
        BASE.fail("selftest terminal semantic binding differs")
    if BASE.transcript_failure(raw + b"VIBE_C810_S5_FAIL {}\n") is None:
        BASE.fail("selftest explicit failure was accepted")
    print("qemu-c810-s5-simd.py selftest: PASS")


BASE.selftest = selftest


if __name__ == "__main__":
    raise SystemExit(BASE.main())
