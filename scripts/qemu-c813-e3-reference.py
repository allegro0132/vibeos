#!/usr/bin/env python3
"""Collect one fresh C8.13-E3 fixed-QEMU code-10 Reference Types campaign."""
from __future__ import annotations
import importlib.util, pathlib, sys

HERE = pathlib.Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location("_vibeos_c813_e3_runner", HERE.with_name("qemu-c88-f5-float-target.py"))
if SPEC is None or SPEC.loader is None: raise RuntimeError("cannot load fixed-QEMU collector")
BASE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = BASE; SPEC.loader.exec_module(BASE)
BASE.__file__ = str(HERE)
BASE.VERIFIER = HERE.with_name("verify-c813-e3-reference-evidence.py")
BASE.PRODUCER = BASE.ROOT / "kernel/src/wasm_reference_executable_target.rs"
BASE.QUALIFICATION = BASE.ROOT / "acceptance/wasm-reference-target/src/lib.rs"
BASE.QUALIFICATION_MANIFEST = BASE.ROOT / "acceptance/wasm-reference-target/artifacts/c813-e3-qualification-manifest.json"
BASE.FEATURE = "wasm-c813-e3-reference-qemu-qualification"
BASE.SOURCE_COMMIT_ENV = "VIBEOS_C813_E3_SOURCE_COMMIT"
BASE.SOURCE_TREE_ENV = "VIBEOS_C813_E3_SOURCE_TREE"
BASE.CHALLENGE_ENV = "VIBEOS_C813_E3_CHALLENGE"
BASE.RUN_ID_ENV = "VIBEOS_C813_E3_RUN_ID"
BASE.MANIFEST_SHA256_ENV = "VIBEOS_C813_E3_MANIFEST_SHA256"
BASE.TRANSCRIPT_SCHEMA_SHA256_ENV = "VIBEOS_C813_E3_TRANSCRIPT_SCHEMA_SHA256"
BASE.SUITE_ID = "vibeos.c813.e3.reference-fixed-qemu"
BASE.ENVIRONMENT_SCHEMA = "vibeos.c813.e3.reference-fixed-qemu.environment"
BASE.RUN_ID_DOMAIN = b"vibeos.c813.e3.reference-fixed-qemu.run.v1\0"
BASE.COMPONENT_SHA256 = "38b29ea038466e0b3c75b6477dae6f91d6addd5ab97ffefccaaca638ae1ec8c0"
BASE.QUALIFICATION_MANIFEST_SHA256 = "f27036d546cb62e89f8931c65281656d61f034514bffd341510289a865938e38"
BASE.QUALIFICATION_MANIFEST_BYTES = 2_284
BASE.EXPECTED_SEMANTIC_SHA256 = "6a654a8428f4f4479db637ab90d391c989c43b2c67dfc51570bd4ac617cc1a49"
BASE.META_PREFIX = "VIBE_C813_E3_META "
BASE.END_PREFIX = "VIBE_C813_E3_END "
BASE.PASS_PREFIX = "VIBE_C813_E3_PASS "
BASE.FAIL_PREFIX = "VIBE_C813_E3_FAIL"
BASE.FAMILY_PREFIX = "VIBE_C813_E3_"

def selftest():
    BASE.verify_qemu_contract()
    commit, tree, challenge, manifest, schema = "1"*40, "2"*40, "3"*64, "4"*64, "5"*64
    run_id = BASE.compute_run_id(commit, tree, challenge, manifest, schema)
    terminal = {"challenge": challenge, "run_id": run_id, "semantic_sha256": BASE.EXPECTED_SEMANTIC_SHA256}
    meta = {"source_commit": commit, "source_tree": tree, "challenge": challenge, "run_id": run_id, "manifest_sha256": manifest, "transcript_schema_sha256": schema}
    raw = (BASE.META_PREFIX + BASE.json.dumps(meta,separators=(",",":"),sort_keys=True) + "\n" + BASE.END_PREFIX + BASE.json.dumps(terminal,separators=(",",":"),sort_keys=True) + "\n" + BASE.PASS_PREFIX + BASE.json.dumps(terminal,separators=(",",":"),sort_keys=True) + "\n").encode("ascii")
    if BASE.transcript_bindings(raw, source_commit=commit, source_tree=tree, challenge=challenge, run_id=run_id, manifest_sha256=manifest, transcript_schema_sha256=schema) != BASE.EXPECTED_SEMANTIC_SHA256: BASE.fail("selftest binding differs")
    if BASE.transcript_failure(raw + b"VIBE_C813_E3_FAIL {}\n") is None: BASE.fail("failure accepted")
    print("qemu-c813-e3-reference.py selftest: PASS")

BASE.selftest = selftest
if __name__ == "__main__": raise SystemExit(BASE.main())
