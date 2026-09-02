#!/usr/bin/env python3
"""Collect one fresh C8.12-R3 fixed-QEMU code-9 Reference Types campaign."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
BASE_PATH = HERE.with_name("qemu-c88-f5-float-target.py")
SPEC = importlib.util.spec_from_file_location("_vibeos_c812_r3_runner", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the frozen fixed-QEMU collector")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

BASE.__file__ = str(HERE)
BASE.VERIFIER = HERE.with_name("verify-c812-r3-reference-evidence.py")
BASE.PRODUCER = BASE.ROOT / "kernel/src/wasm_reference_target.rs"
BASE.QUALIFICATION = BASE.ROOT / "acceptance/wasm-reference-target/src/lib.rs"
BASE.QUALIFICATION_MANIFEST = (
    BASE.ROOT
    / "acceptance/wasm-reference-target/artifacts/c812-r3-qualification-manifest.json"
)
BASE.FEATURE = "wasm-c812-r3-reference-qemu-qualification"
BASE.SOURCE_COMMIT_ENV = "VIBEOS_C812_R3_SOURCE_COMMIT"
BASE.SOURCE_TREE_ENV = "VIBEOS_C812_R3_SOURCE_TREE"
BASE.CHALLENGE_ENV = "VIBEOS_C812_R3_CHALLENGE"
BASE.RUN_ID_ENV = "VIBEOS_C812_R3_RUN_ID"
BASE.MANIFEST_SHA256_ENV = "VIBEOS_C812_R3_MANIFEST_SHA256"
BASE.TRANSCRIPT_SCHEMA_SHA256_ENV = "VIBEOS_C812_R3_TRANSCRIPT_SCHEMA_SHA256"
BASE.SUITE_ID = "vibeos.c812.r3.reference-fixed-qemu"
BASE.ENVIRONMENT_SCHEMA = "vibeos.c812.r3.reference-fixed-qemu.environment"
BASE.RUN_ID_DOMAIN = b"vibeos.c812.r3.reference-fixed-qemu.run.v1\0"
BASE.COMPONENT_SHA256 = "38b29ea038466e0b3c75b6477dae6f91d6addd5ab97ffefccaaca638ae1ec8c0"
BASE.QUALIFICATION_MANIFEST_SHA256 = "22dd4ba1f6c64b6cd9dcf93f8042baa2527b431ae4ab6e3fd34f7f562cc308dd"
BASE.QUALIFICATION_MANIFEST_BYTES = 2_480
BASE.EXPECTED_SEMANTIC_SHA256 = "bf33470617822af905ab8877797416e79aed3cde5a257689b3bbdda4df156279"
BASE.META_PREFIX = "VIBE_C812_R3_META "
BASE.END_PREFIX = "VIBE_C812_R3_END "
BASE.PASS_PREFIX = "VIBE_C812_R3_PASS "
BASE.FAIL_PREFIX = "VIBE_C812_R3_FAIL"
BASE.FAMILY_PREFIX = "VIBE_C812_R3_"


def selftest() -> None:
    BASE.verify_qemu_contract()
    source_commit, source_tree = "1" * 40, "2" * 40
    challenge, manifest, schema = "3" * 64, "4" * 64, "5" * 64
    run_id = BASE.compute_run_id(source_commit, source_tree, challenge, manifest, schema)
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
    if BASE.transcript_failure(raw + b"VIBE_C812_R3_FAIL {}\n") is None:
        BASE.fail("selftest explicit failure was accepted")
    print("qemu-c812-r3-reference.py selftest: PASS")


BASE.selftest = selftest

if __name__ == "__main__":
    raise SystemExit(BASE.main())
