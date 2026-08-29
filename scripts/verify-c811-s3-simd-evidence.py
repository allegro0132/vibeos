#!/usr/bin/env python3
"""Verify C8.11-S3 fixed-QEMU code-8 SIMD evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location("_vibeos_c811_s3_base", HERE.with_name("verify-c810-s5-simd-evidence.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load SIMD evidence verifier")
OLD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OLD
SPEC.loader.exec_module(OLD)
BASE = OLD.BASE
ORIGINAL_VALIDATE_ENVIRONMENT = OLD.ORIGINAL_VALIDATE_ENVIRONMENT

EXPECTED_SEMANTIC = "ddab9d539744523b332787be6f8a101de00108479c9644136538524f20cd4514"
EXPECTED_MANIFEST_SHA256 = "62ac9ba3adba3e6946624cfb4e20a0c7672ed18f7f79775551205a5fc3705c3f"
EXPECTED_MANIFEST_BYTES = 2_012
CASE_IDS = OLD.CASE_IDS
PREFIXES = {
    "META": "VIBE_C811_S3_META ", "CASE": "VIBE_C811_S3_CASE ",
    "LIFECYCLE": "VIBE_C811_S3_LIFECYCLE ", "END": "VIBE_C811_S3_END ",
    "PASS": "VIBE_C811_S3_PASS ",
}
SEMANTIC_DOMAIN = b"vibeos.c811.s3.simd.fixed-qemu.semantic.v1\0"

BASE.__file__ = str(HERE)
BASE.SUITE_ID = "vibeos.c811.s3.simd-fixed-qemu"
BASE.RUN_ID_DOMAIN = b"vibeos.c811.s3.simd-fixed-qemu.run.v1\0"
BASE.EXPECTED_COMPONENT_SHA256 = "7b85b9324409d7cc4484ca9e661a44fce2275e70407338a4f4326f71809a40a1"
BASE.EXPECTED_MANIFEST_SHA256 = EXPECTED_MANIFEST_SHA256
BASE.EXPECTED_MANIFEST_BYTES = EXPECTED_MANIFEST_BYTES
BASE.EXPECTED_SEMANTIC_SHA256 = EXPECTED_SEMANTIC


def records(uart: bytes, family: str) -> list[BASE.Record]:
    prefix = PREFIXES[family]
    text = uart.decode("utf-8", errors="strict")
    found = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if "VIBE_C811_S3_" in line and not line.startswith("VIBE_C811_S3_"):
            BASE.fail(f"C8.11-S3 family text is not column-zero on line {line_number}")
        if line.startswith(prefix):
            payload = line[len(prefix):]
            value = BASE.strict_json_text(payload, f"{family} line {line_number}")
            if not isinstance(value, dict) or BASE.canonical_json(value).decode() != payload:
                BASE.fail(f"{family} line {line_number} is not canonical JSON")
            found.append(BASE.Record(family, value, line_number))
    return found


def semantic_digest(data: list[BASE.Record]) -> str:
    digest = hashlib.sha256(SEMANTIC_DOMAIN)
    for record in data:
        payload = BASE.canonical_json(record.value)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def validate_semantics(uart: bytes, expected: dict[str, object]) -> BASE.VerifiedTranscript:
    text = uart.decode("utf-8", errors="strict")
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith("VIBE_C811_S3_") and not any(line.startswith(value) for value in PREFIXES.values()) and not line.startswith("VIBE_C811_S3_FAIL"):
            BASE.fail(f"unknown C8.11-S3 family on line {line_number}")
    meta, cases = records(uart, "META"), records(uart, "CASE")
    lifecycle, endings, passings = records(uart, "LIFECYCLE"), records(uart, "END"), records(uart, "PASS")
    if b"VIBE_C811_S3_FAIL" in uart:
        BASE.fail("UART contains an explicit C8.11-S3 failure")
    if len(meta) != 1 or len(endings) != 1 or len(passings) != 1 or len(cases) != 6 or len(lifecycle) != 1:
        BASE.fail("UART semantic record counts differ")
    expected_meta = {
        "artifact_abi": 8, "artifact_profile_code": 8, "challenge": expected["challenge"],
        "code5_inert": True, "code7_inert": True, "component_profile": 5, "core_profile": 5,
        "durable_authorized": False, "engine": "vibeos-wasmi-simd-executable-softfloat@1.1.0-vibeos-simd2.1",
        "manifest_sha256": expected["manifest_sha256"], "node": "C8.11-S3", "release_authorized": False,
        "run_id": expected["run_id"], "runtime_abi": 8, "source_commit": expected["source"]["commit"],
        "source_tree": expected["source"]["tree"], "stage": "executable",
        "transcript_schema_sha256": expected["transcript_schema_sha256"], "world": "vibe:simd/runtime@1.0.0",
    }
    if meta[0].value != expected_meta:
        BASE.fail("META differs from frozen code-8 boundary")
    for index, record in enumerate(cases):
        if record.value != {"id": CASE_IDS[index], "passed": True}:
            BASE.fail(f"CASE[{index}] differs")
    expected_lifecycle = {"cancellations": 1, "faults": 2, "live_instances": 0, "passed": True,
        "reclaimed_instances": 4, "recoveries": 3, "revocations": 1}
    if lifecycle[0].value != expected_lifecycle:
        BASE.fail("LIFECYCLE differs")
    data = cases + lifecycle
    semantic = semantic_digest(data)
    if semantic != EXPECTED_SEMANTIC or expected["expected_semantic_sha256"] != semantic:
        BASE.fail("semantic digest differs")
    terminal = {"challenge": expected["challenge"], "run_id": expected["run_id"], "semantic_sha256": semantic}
    if endings[0].value != terminal or passings[0].value != terminal:
        BASE.fail("terminal binding differs")
    if sorted(data, key=lambda record: record.line) != data:
        BASE.fail("semantic record order differs")
    return BASE.VerifiedTranscript(meta[0].value, tuple(data), endings[0].value, passings[0].value,
        semantic, hashlib.sha256(uart).hexdigest(), len(uart))


def validate_environment(value: object, uart: bytes, *, verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("schema") != "vibeos.c811.s3.simd-fixed-qemu.environment" or value.get("suite_id") != BASE.SUITE_ID:
        BASE.fail("environment identity differs")
    if value.get("evidence_sha256") != BASE.environment_evidence_sha256(value):
        BASE.fail("environment evidence digest differs")
    if not isinstance(value.get("build"), dict) or value["build"].get("feature") != "wasm-c811-s3-simd-qemu-qualification":
        BASE.fail("environment build feature differs")
    transformed = copy.deepcopy(value)
    transformed["schema"] = "vibeos.c88.f5.float-target.environment"
    transformed["build"]["feature"] = "wasm-c88-f5-float-qemu-acceptance"
    transformed["evidence_sha256"] = BASE.environment_evidence_sha256(transformed)
    validated = ORIGINAL_VALIDATE_ENVIRONMENT(transformed, uart, verify_self_identity=False,
        expected_semantic_sha256=expected_semantic_sha256)
    if verify_self_identity:
        source = value["source"]
        contracts = (
            (BASE.identity_record(value["manifest"], "manifest"), BASE.ROOT / "acceptance/wasm-simd-target/artifacts/c811-s3-qualification-manifest.json", "manifest"),
            (BASE.identity_record(value["producer"], "producer"), BASE.ROOT / "kernel/src/wasm_simd_executable_target.rs", "producer"),
            (BASE.identity_record(value["qualification"], "qualification"), BASE.ROOT / "acceptance/wasm-simd-target/src/c811.rs", "qualification"),
            (BASE.identity_record(value["runner"], "runner"), HERE.with_name("qemu-c811-s3-simd.py"), "runner"),
            (BASE.identity_record(value["verifier"], "verifier"), HERE, "verifier"),
            (BASE.identity_record(value["elf_auditor"], "ELF auditor"), BASE.ROOT / "scripts/verify-c88-f5-riscv-elf.py", "ELF auditor"),
        )
        for identity, path, label in contracts:
            BASE.require_local_identity(identity, path, label)
        cargo_lock, cargo_config = BASE.validate_dependency_archives(value["dependency_archives"], verify_local_identity=True)
        BASE.require_git_source_membership(source, contracts + ((cargo_lock, BASE.ROOT / "Cargo.lock", "Cargo.lock"), (cargo_config, BASE.ROOT / "firmware/.cargo/config.toml", "Cargo config")))
        BASE.require_local_identity(BASE.identity_record(value["python"], "Python interpreter"), pathlib.Path(sys.executable).resolve(strict=True), "Python interpreter", maximum=BASE.MAX_KERNEL_BYTES)
    return validated


def verify_uart_bytes(uart: bytes, environment_value: object, *, verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC) -> BASE.VerifiedTranscript:
    validate_environment(environment_value, uart, verify_self_identity=verify_self_identity,
        expected_semantic_sha256=expected_semantic_sha256)
    assert isinstance(environment_value, dict)
    return validate_semantics(uart, environment_value)


def selftest() -> None:
    source = {"commit": "1" * 40, "tree": "2" * 40}
    expected = {"source": source, "challenge": "3" * 64, "run_id": "4" * 64,
        "manifest_sha256": "5" * 64, "transcript_schema_sha256": "6" * 64,
        "expected_semantic_sha256": EXPECTED_SEMANTIC}
    meta = {"artifact_abi": 8, "artifact_profile_code": 8, "challenge": expected["challenge"],
        "code5_inert": True, "code7_inert": True, "component_profile": 5, "core_profile": 5,
        "durable_authorized": False, "engine": "vibeos-wasmi-simd-executable-softfloat@1.1.0-vibeos-simd2.1",
        "manifest_sha256": expected["manifest_sha256"], "node": "C8.11-S3", "release_authorized": False,
        "run_id": expected["run_id"], "runtime_abi": 8, "source_commit": source["commit"], "source_tree": source["tree"],
        "stage": "executable", "transcript_schema_sha256": expected["transcript_schema_sha256"], "world": "vibe:simd/runtime@1.0.0"}
    lines = [PREFIXES["META"] + BASE.canonical_json(meta).decode()]
    lines += [PREFIXES["CASE"] + BASE.canonical_json({"id": item, "passed": True}).decode() for item in CASE_IDS]
    lines.append(PREFIXES["LIFECYCLE"] + BASE.canonical_json({"cancellations": 1, "faults": 2, "live_instances": 0, "passed": True, "reclaimed_instances": 4, "recoveries": 3, "revocations": 1}).decode())
    terminal = {"challenge": expected["challenge"], "run_id": expected["run_id"], "semantic_sha256": EXPECTED_SEMANTIC}
    lines += [PREFIXES["END"] + BASE.canonical_json(terminal).decode(), PREFIXES["PASS"] + BASE.canonical_json(terminal).decode()]
    uart = ("\n".join(lines) + "\n").encode()
    if len(validate_semantics(uart, expected).records) != 7:
        BASE.fail("selftest valid fixture differs")
    for mutation in (uart.replace(b'"artifact_profile_code":8', b'"artifact_profile_code":7', 1), uart.replace(b'"passed":true', b'"passed":false', 1), uart + b"VIBE_C811_S3_FAIL {}\n"):
        try: validate_semantics(mutation, expected)
        except BASE.VerificationError: continue
        BASE.fail("selftest mutation accepted")
    print("verify-c811-s3-simd-evidence.py selftest: PASS cases=3 records=7")


BASE.validate_environment = validate_environment
BASE.verify_uart_bytes = verify_uart_bytes
BASE.selftest = selftest

if __name__ == "__main__":
    raise SystemExit(BASE.main())
