#!/usr/bin/env python3
"""Verify C8.10-S5 fixed-QEMU SIMD evidence and its non-release boundary."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
BASE_PATH = HERE.with_name("verify-c88-f5-float-target.py")
SPEC = importlib.util.spec_from_file_location("_vibeos_c810_s5_verifier", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the frozen fixed-QEMU verifier")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

ORIGINAL_VALIDATE_ENVIRONMENT = BASE.validate_environment
EXPECTED_SEMANTIC = "6b34b541a42fdf838eccd55e43473a4154421eadc0e3b4292a5a89fde54ae1c6"
EXPECTED_MANIFEST_SHA256 = "2a76b48905638b0a12bb3277f296a869c736f063331e79bc17fc8ac125a4109c"
EXPECTED_MANIFEST_BYTES = 1_975
CASE_IDS = [
    "integer-lanes",
    "float-lanes",
    "nan-canonical",
    "saturation-memory",
    "fuel-adjacent",
    "component-binding",
]
PREFIXES = {
    "META": "VIBE_C810_S5_META ",
    "CASE": "VIBE_C810_S5_CASE ",
    "LIFECYCLE": "VIBE_C810_S5_LIFECYCLE ",
    "END": "VIBE_C810_S5_END ",
    "PASS": "VIBE_C810_S5_PASS ",
}
SEMANTIC_DOMAIN = b"vibeos.c810.s5.simd.fixed-qemu.semantic.v1\0"

BASE.__file__ = str(HERE)
BASE.SUITE_ID = "vibeos.c810.s5.simd-fixed-qemu"
BASE.RUN_ID_DOMAIN = b"vibeos.c810.s5.simd-fixed-qemu.run.v1\0"
BASE.COMPONENT_SHA256 = "217c1eb45d78d7cc4a267ae9b1c3e0b366f281e4b8048a86b6ce4f5a0990186f"
BASE.EXPECTED_MANIFEST_SHA256 = EXPECTED_MANIFEST_SHA256
BASE.EXPECTED_MANIFEST_BYTES = EXPECTED_MANIFEST_BYTES
BASE.EXPECTED_SEMANTIC_SHA256 = EXPECTED_SEMANTIC


def records(uart: bytes, family: str) -> list[BASE.Record]:
    prefix = PREFIXES[family]
    try:
        text = uart.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        BASE.fail(f"UART is not strict UTF-8: {error}")
    found: list[BASE.Record] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if "VIBE_C810_S5_" in line and not line.startswith("VIBE_C810_S5_"):
            BASE.fail(f"C8.10-S5 family text is not column-zero on line {line_number}")
        if not line.startswith(prefix):
            continue
        payload = line[len(prefix) :]
        value = BASE.strict_json_text(payload, f"{family} line {line_number}")
        if not isinstance(value, dict) or BASE.canonical_json(value).decode() != payload:
            BASE.fail(f"{family} line {line_number} is not a canonical JSON object")
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
    try:
        text = uart.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        BASE.fail(f"UART is not strict UTF-8: {error}")
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith("VIBE_C810_S5_") and not any(
            line.startswith(prefix) for prefix in PREFIXES.values()
        ) and not line.startswith("VIBE_C810_S5_FAIL"):
            BASE.fail(f"unknown C8.10-S5 family on line {line_number}")
    failures = records(uart, "META")
    cases = records(uart, "CASE")
    lifecycles = records(uart, "LIFECYCLE")
    endings = records(uart, "END")
    passings = records(uart, "PASS")
    if b"VIBE_C810_S5_FAIL" in uart:
        BASE.fail("UART contains an explicit C8.10-S5 failure")
    if len(failures) != 1 or len(endings) != 1 or len(passings) != 1:
        BASE.fail("UART must contain exactly one META, END, and PASS")
    if len(cases) != 6 or len(lifecycles) != 1:
        BASE.fail("UART semantic record counts differ")
    meta = failures[0].value
    expected_meta = {
        "artifact_abi": 7,
        "artifact_profile_code": 7,
        "challenge": expected["challenge"],
        "code5_inert": True,
        "component_profile": 4,
        "core_profile": 4,
        "durable_authorized": False,
        "engine": "vibeos-wasmi-simd-softfloat@1.1.0-vibeos-simd1.1",
        "manifest_sha256": expected["manifest_sha256"],
        "node": "C8.10-S5",
        "release_authorized": False,
        "run_id": expected["run_id"],
        "runtime_abi": 7,
        "source_commit": expected["source"]["commit"],
        "source_tree": expected["source"]["tree"],
        "stage": "validation-only",
        "transcript_schema_sha256": expected["transcript_schema_sha256"],
        "world": "vibe:simd/validation@1.0.0",
    }
    if meta != expected_meta:
        BASE.fail("META differs from the frozen code-7 boundary")
    for index, record in enumerate(cases):
        if record.value != {"id": CASE_IDS[index], "passed": True}:
            BASE.fail(f"CASE[{index}] differs")
    lifecycle = {
        "cancellations": 1,
        "faults": 2,
        "live_instances": 0,
        "passed": True,
        "recoveries": 3,
        "reclaimed_instances": 4,
        "revocations": 1,
    }
    if lifecycles[0].value != lifecycle:
        BASE.fail("LIFECYCLE differs")
    data = cases + lifecycles
    semantic = semantic_digest(data)
    if semantic != EXPECTED_SEMANTIC or expected["expected_semantic_sha256"] != semantic:
        BASE.fail("semantic digest differs")
    terminal = {
        "challenge": expected["challenge"],
        "run_id": expected["run_id"],
        "semantic_sha256": semantic,
    }
    if endings[0].value != terminal or passings[0].value != terminal:
        BASE.fail("terminal binding differs")
    ordered = sorted(data, key=lambda record: record.line)
    if ordered != data:
        BASE.fail("semantic record order differs")
    return BASE.VerifiedTranscript(
        metadata=meta,
        records=tuple(data),
        ending=endings[0].value,
        passing=passings[0].value,
        semantic_sha256=semantic,
        uart_sha256=hashlib.sha256(uart).hexdigest(),
        uart_bytes=len(uart),
    )


def validate_environment(
    value: object,
    uart: bytes,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC,
) -> dict[str, object]:
    if not isinstance(value, dict):
        BASE.fail("environment must be an object")
    if value.get("schema") != "vibeos.c810.s5.simd-fixed-qemu.environment":
        BASE.fail("environment schema differs")
    if value.get("suite_id") != BASE.SUITE_ID:
        BASE.fail("environment suite differs")
    if value.get("evidence_sha256") != BASE.environment_evidence_sha256(value):
        BASE.fail("environment evidence digest differs")
    build = value.get("build")
    if not isinstance(build, dict) or build.get("feature") != (
        "wasm-c810-s5-simd-qemu-qualification"
    ):
        BASE.fail("environment build feature differs")
    transformed = copy.deepcopy(value)
    transformed["schema"] = "vibeos.c88.f5.float-target.environment"
    transformed["build"]["feature"] = "wasm-c88-f5-float-qemu-acceptance"
    transformed["evidence_sha256"] = BASE.environment_evidence_sha256(transformed)
    validated = ORIGINAL_VALIDATE_ENVIRONMENT(
        transformed,
        uart,
        verify_self_identity=False,
        expected_semantic_sha256=expected_semantic_sha256,
    )
    if verify_self_identity:
        source = value["source"]
        contracts = (
            (
                BASE.identity_record(value["manifest"], "manifest"),
                BASE.ROOT / "acceptance/wasm-simd-target/artifacts/c810-s5-qualification-manifest.json",
                "manifest",
            ),
            (
                BASE.identity_record(value["producer"], "producer"),
                BASE.ROOT / "kernel/src/wasm_simd_target.rs",
                "producer",
            ),
            (
                BASE.identity_record(value["qualification"], "qualification"),
                BASE.ROOT / "acceptance/wasm-simd-target/src/lib.rs",
                "qualification",
            ),
            (
                BASE.identity_record(value["runner"], "runner"),
                HERE.with_name("qemu-c810-s5-simd.py"),
                "runner",
            ),
            (BASE.identity_record(value["verifier"], "verifier"), HERE, "verifier"),
            (
                BASE.identity_record(value["elf_auditor"], "ELF auditor"),
                BASE.ROOT / "scripts/verify-c88-f5-riscv-elf.py",
                "ELF auditor",
            ),
        )
        for identity, path, label in contracts:
            BASE.require_local_identity(identity, path, label)
        cargo_lock, cargo_config = BASE.validate_dependency_archives(
            value["dependency_archives"], verify_local_identity=True
        )
        BASE.require_git_source_membership(
            source,
            contracts
            + (
                (cargo_lock, BASE.ROOT / "Cargo.lock", "Cargo.lock"),
                (cargo_config, BASE.ROOT / "firmware/.cargo/config.toml", "Cargo config"),
            ),
        )
        try:
            python_path = pathlib.Path(sys.executable).resolve(strict=True)
        except OSError as error:
            BASE.fail(f"cannot resolve Python interpreter: {error}")
        BASE.require_local_identity(
            BASE.identity_record(value["python"], "Python interpreter"),
            python_path,
            "Python interpreter",
            maximum=BASE.MAX_KERNEL_BYTES,
        )
    return validated


def verify_uart_bytes(
    uart: bytes,
    environment_value: object,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC,
) -> BASE.VerifiedTranscript:
    validate_environment(
        environment_value,
        uart,
        verify_self_identity=verify_self_identity,
        expected_semantic_sha256=expected_semantic_sha256,
    )
    assert isinstance(environment_value, dict)
    return validate_semantics(uart, environment_value)


def selftest() -> None:
    source = {"commit": "1" * 40, "tree": "2" * 40}
    expected = {
        "source": source,
        "challenge": "3" * 64,
        "run_id": "4" * 64,
        "manifest_sha256": "5" * 64,
        "transcript_schema_sha256": "6" * 64,
        "expected_semantic_sha256": EXPECTED_SEMANTIC,
    }
    meta = {
        "artifact_abi": 7,
        "artifact_profile_code": 7,
        "challenge": expected["challenge"],
        "code5_inert": True,
        "component_profile": 4,
        "core_profile": 4,
        "durable_authorized": False,
        "engine": "vibeos-wasmi-simd-softfloat@1.1.0-vibeos-simd1.1",
        "manifest_sha256": expected["manifest_sha256"],
        "node": "C8.10-S5",
        "release_authorized": False,
        "run_id": expected["run_id"],
        "runtime_abi": 7,
        "source_commit": source["commit"],
        "source_tree": source["tree"],
        "stage": "validation-only",
        "transcript_schema_sha256": expected["transcript_schema_sha256"],
        "world": "vibe:simd/validation@1.0.0",
    }
    lines = [PREFIXES["META"] + BASE.canonical_json(meta).decode()]
    for case_id in CASE_IDS:
        lines.append(PREFIXES["CASE"] + BASE.canonical_json({"id": case_id, "passed": True}).decode())
    lifecycle = {"cancellations": 1, "faults": 2, "live_instances": 0, "passed": True, "recoveries": 3, "reclaimed_instances": 4, "revocations": 1}
    lines.append(PREFIXES["LIFECYCLE"] + BASE.canonical_json(lifecycle).decode())
    terminal = {"challenge": expected["challenge"], "run_id": expected["run_id"], "semantic_sha256": EXPECTED_SEMANTIC}
    lines.append(PREFIXES["END"] + BASE.canonical_json(terminal).decode())
    lines.append(PREFIXES["PASS"] + BASE.canonical_json(terminal).decode())
    uart = ("\n".join(lines) + "\n").encode()
    if len(validate_semantics(uart, expected).records) != 7:
        BASE.fail("selftest valid fixture differs")
    mutations = [
        uart.replace(b'"artifact_profile_code":7', b'"artifact_profile_code":5', 1),
        uart.replace(b'"passed":true', b'"passed":false', 1),
        uart + b"VIBE_C810_S5_FAIL {}\n",
    ]
    for mutation in mutations:
        try:
            validate_semantics(mutation, expected)
        except BASE.VerificationError:
            continue
        BASE.fail("selftest mutation accepted")
    print("verify-c810-s5-simd-evidence.py selftest: PASS cases=3 records=7")


BASE.validate_environment = validate_environment
BASE.verify_uart_bytes = verify_uart_bytes
BASE.selftest = selftest


if __name__ == "__main__":
    raise SystemExit(BASE.main())
