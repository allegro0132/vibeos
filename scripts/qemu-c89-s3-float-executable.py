#!/usr/bin/env python3
"""Collect one fresh C8.9-S3 fixed-QEMU code-6 qualification campaign.

The hardened process, build, publication, rollback, and fixed-QEMU machinery
is inherited from the frozen C8.8-F5 collector. This adapter replaces every
evidence identity with the independently numbered C8.9-S3 domain and selects
the code-6 executor feature; it never selects or observes Milk-V Duo.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
BASE_PATH = HERE.with_name("qemu-c88-f5-float-target.py")
SPEC = importlib.util.spec_from_file_location("_vibeos_c88_f5_runner", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the frozen fixed-QEMU collector")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

BASE.__file__ = str(HERE)
BASE.VERIFIER = HERE.with_name("verify-c89-s3-float-executable.py")
BASE.QUALIFICATION_MANIFEST = (
    BASE.ROOT
    / "acceptance/wasm-float-target/artifacts/c89-s3-qualification-manifest.json"
)
BASE.FEATURE = "wasm-c89-s3-float-qemu-qualification"
BASE.SOURCE_COMMIT_ENV = "VIBEOS_C89_S3_SOURCE_COMMIT"
BASE.SOURCE_TREE_ENV = "VIBEOS_C89_S3_SOURCE_TREE"
BASE.CHALLENGE_ENV = "VIBEOS_C89_S3_CHALLENGE"
BASE.RUN_ID_ENV = "VIBEOS_C89_S3_RUN_ID"
BASE.MANIFEST_SHA256_ENV = "VIBEOS_C89_S3_MANIFEST_SHA256"
BASE.TRANSCRIPT_SCHEMA_SHA256_ENV = "VIBEOS_C89_S3_TRANSCRIPT_SCHEMA_SHA256"
BASE.SUITE_ID = "vibeos.c89.s3.float-executable"
BASE.ENVIRONMENT_SCHEMA = "vibeos.c89.s3.float-executable.environment"
BASE.RUN_ID_DOMAIN = b"vibeos.c89.s3.float-executable.run.v1\0"
BASE.QUALIFICATION_MANIFEST_SHA256 = (
    "a9e25bcadfac2b839ae90cad0fb20e40b4a9682a7ec12e2264a0daddbec25fd4"
)
BASE.QUALIFICATION_MANIFEST_BYTES = 2_467
BASE.EXPECTED_SEMANTIC_SHA256 = (
    "44cb0a12c01906b31a42fc6550d485496206ea23a08bc073a685e1b893fb94b8"
)
BASE.META_PREFIX = "VIBE_C89_S3_META "
BASE.END_PREFIX = "VIBE_C89_S3_END "
BASE.PASS_PREFIX = "VIBE_C89_S3_PASS "
BASE.FAIL_PREFIX = "VIBE_C89_S3_FAIL"
BASE.FAMILY_PREFIX = "VIBE_C89_S3_"


def selftest() -> None:
    BASE.verify_qemu_contract()
    if BASE.git_environment().get("GIT_NO_REPLACE_OBJECTS") != "1":
        BASE.fail("selftest: Git replace objects are not disabled")
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
        BASE.fail("selftest: terminal semantic binding differs")
    if BASE.transcript_failure(raw + b"VIBE_C89_S3_FAIL {}\n") is None:
        BASE.fail("selftest: explicit C8.9-S3 failure was accepted")
    print("qemu-c89-s3-float-executable.py selftest: PASS")


BASE.selftest = selftest


if __name__ == "__main__":
    raise SystemExit(BASE.main())
