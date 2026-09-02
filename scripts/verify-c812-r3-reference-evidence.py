#!/usr/bin/env python3
"""Verify C8.12-R3 fixed-QEMU code-9 Reference Types evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location(
    "_vibeos_c812_r3_base", HERE.with_name("verify-c810-s5-simd-evidence.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load fixed-QEMU evidence verifier")
OLD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OLD
SPEC.loader.exec_module(OLD)
BASE = OLD.BASE
ORIGINAL_VALIDATE_ENVIRONMENT = OLD.ORIGINAL_VALIDATE_ENVIRONMENT

EXPECTED_SEMANTIC = "bf33470617822af905ab8877797416e79aed3cde5a257689b3bbdda4df156279"
EXPECTED_MANIFEST_SHA256 = "22dd4ba1f6c64b6cd9dcf93f8042baa2527b431ae4ab6e3fd34f7f562cc308dd"
EXPECTED_MANIFEST_BYTES = 2_480
CASE_IDS = [
    "nullable-funcref",
    "table-operations",
    "active-elements",
    "externref-containment",
    "reference-boundary-containment",
    "adjacent-proposals",
    "component-containment",
    "mutation-containment",
]
PREFIXES = {
    "META": "VIBE_C812_R3_META ",
    "CASE": "VIBE_C812_R3_CASE ",
    "CONTAINMENT": "VIBE_C812_R3_CONTAINMENT ",
    "END": "VIBE_C812_R3_END ",
    "PASS": "VIBE_C812_R3_PASS ",
}
SEMANTIC_DOMAIN = b"vibeos.c812.r3.reference.fixed-qemu.semantic.v1\0"

BASE.__file__ = str(HERE)
BASE.SUITE_ID = "vibeos.c812.r3.reference-fixed-qemu"
BASE.RUN_ID_DOMAIN = b"vibeos.c812.r3.reference-fixed-qemu.run.v1\0"
BASE.EXPECTED_COMPONENT_SHA256 = "38b29ea038466e0b3c75b6477dae6f91d6addd5ab97ffefccaaca638ae1ec8c0"
BASE.EXPECTED_MANIFEST_SHA256 = EXPECTED_MANIFEST_SHA256
BASE.EXPECTED_MANIFEST_BYTES = EXPECTED_MANIFEST_BYTES
BASE.EXPECTED_SEMANTIC_SHA256 = EXPECTED_SEMANTIC


def records(uart: bytes, family: str) -> list[BASE.Record]:
    prefix = PREFIXES[family]
    try:
        text = uart.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        BASE.fail(f"UART is not strict UTF-8: {error}")
    found = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if "VIBE_C812_R3_" in line and not line.startswith("VIBE_C812_R3_"):
            BASE.fail(f"C8.12-R3 family text is not column-zero on line {line_number}")
        if line.startswith(prefix):
            payload = line[len(prefix) :]
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
        if (
            line.startswith("VIBE_C812_R3_")
            and not any(line.startswith(prefix) for prefix in PREFIXES.values())
            and not line.startswith("VIBE_C812_R3_FAIL")
        ):
            BASE.fail(f"unknown C8.12-R3 family on line {line_number}")
    meta = records(uart, "META")
    cases = records(uart, "CASE")
    containment = records(uart, "CONTAINMENT")
    endings = records(uart, "END")
    passings = records(uart, "PASS")
    if b"VIBE_C812_R3_FAIL" in uart:
        BASE.fail("UART contains an explicit C8.12-R3 failure")
    if (
        len(meta) != 1
        or len(cases) != 8
        or len(containment) != 1
        or len(endings) != 1
        or len(passings) != 1
    ):
        BASE.fail("UART semantic record counts differ")
    expected_meta = {
        "artifact_abi": 9,
        "artifact_profile_code": 9,
        "challenge": expected["challenge"],
        "code5_inert": True,
        "code7_inert": True,
        "component_profile": 6,
        "core_profile": 6,
        "durable_authorized": False,
        "engine": "vibeos-wasmi-reference-validation@1.1.0-vibeos-ref1.1",
        "execution_authorized": False,
        "manifest_sha256": expected["manifest_sha256"],
        "node": "C8.12-R3",
        "release_authorized": False,
        "run_id": expected["run_id"],
        "runtime_abi": 9,
        "source_commit": expected["source"]["commit"],
        "source_tree": expected["source"]["tree"],
        "stage": "validation-only",
        "successor_review_eligible_before_qualification": False,
        "transcript_schema_sha256": expected["transcript_schema_sha256"],
        "world": "vibe:references/validation@1.0.0",
    }
    if meta[0].value != expected_meta:
        BASE.fail("META differs from frozen code-9 boundary")
    for index, record in enumerate(cases):
        if record.value != {"id": CASE_IDS[index], "passed": True}:
            BASE.fail(f"CASE[{index}] differs")
    exact_containment = {
        "accepted_inert": 48,
        "passed": True,
        "rejected": 208,
        "total": 256,
    }
    if containment[0].value != exact_containment:
        BASE.fail("CONTAINMENT differs")
    data = cases + containment
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
    if sorted(data, key=lambda record: record.line) != data:
        BASE.fail("semantic record order differs")
    return BASE.VerifiedTranscript(
        meta[0].value,
        tuple(data),
        endings[0].value,
        passings[0].value,
        semantic,
        hashlib.sha256(uart).hexdigest(),
        len(uart),
    )


def validate_environment(
    value: object,
    uart: bytes,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC,
) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or value.get("schema") != "vibeos.c812.r3.reference-fixed-qemu.environment"
        or value.get("suite_id") != BASE.SUITE_ID
    ):
        BASE.fail("environment identity differs")
    if value.get("evidence_sha256") != BASE.environment_evidence_sha256(value):
        BASE.fail("environment evidence digest differs")
    build = value.get("build")
    if not isinstance(build, dict) or build.get("feature") != (
        "wasm-c812-r3-reference-qemu-qualification"
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
                BASE.ROOT
                / "acceptance/wasm-reference-target/artifacts/c812-r3-qualification-manifest.json",
                "manifest",
            ),
            (
                BASE.identity_record(value["producer"], "producer"),
                BASE.ROOT / "kernel/src/wasm_reference_target.rs",
                "producer",
            ),
            (
                BASE.identity_record(value["qualification"], "qualification"),
                BASE.ROOT / "acceptance/wasm-reference-target/src/lib.rs",
                "qualification",
            ),
            (
                BASE.identity_record(value["runner"], "runner"),
                HERE.with_name("qemu-c812-r3-reference.py"),
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
        BASE.require_local_identity(
            BASE.identity_record(value["python"], "Python interpreter"),
            pathlib.Path(sys.executable).resolve(strict=True),
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
        "artifact_abi": 9,
        "artifact_profile_code": 9,
        "challenge": expected["challenge"],
        "code5_inert": True,
        "code7_inert": True,
        "component_profile": 6,
        "core_profile": 6,
        "durable_authorized": False,
        "engine": "vibeos-wasmi-reference-validation@1.1.0-vibeos-ref1.1",
        "execution_authorized": False,
        "manifest_sha256": expected["manifest_sha256"],
        "node": "C8.12-R3",
        "release_authorized": False,
        "run_id": expected["run_id"],
        "runtime_abi": 9,
        "source_commit": source["commit"],
        "source_tree": source["tree"],
        "stage": "validation-only",
        "successor_review_eligible_before_qualification": False,
        "transcript_schema_sha256": expected["transcript_schema_sha256"],
        "world": "vibe:references/validation@1.0.0",
    }
    lines = [PREFIXES["META"] + BASE.canonical_json(meta).decode()]
    lines += [
        PREFIXES["CASE"]
        + BASE.canonical_json({"id": case_id, "passed": True}).decode()
        for case_id in CASE_IDS
    ]
    lines.append(
        PREFIXES["CONTAINMENT"]
        + BASE.canonical_json(
            {"accepted_inert": 48, "passed": True, "rejected": 208, "total": 256}
        ).decode()
    )
    terminal = {
        "challenge": expected["challenge"],
        "run_id": expected["run_id"],
        "semantic_sha256": EXPECTED_SEMANTIC,
    }
    lines += [
        PREFIXES["END"] + BASE.canonical_json(terminal).decode(),
        PREFIXES["PASS"] + BASE.canonical_json(terminal).decode(),
    ]
    uart = ("\n".join(lines) + "\n").encode()
    if len(validate_semantics(uart, expected).records) != 9:
        BASE.fail("selftest valid fixture differs")
    for mutation in (
        uart.replace(b'"artifact_profile_code":9', b'"artifact_profile_code":5', 1),
        uart.replace(b'"rejected":208', b'"rejected":207', 1),
        uart.replace(b'"passed":true', b'"passed":false', 1),
        uart + b"VIBE_C812_R3_FAIL {}\n",
    ):
        try:
            validate_semantics(mutation, expected)
        except BASE.VerificationError:
            continue
        BASE.fail("selftest mutation accepted")
    print("verify-c812-r3-reference-evidence.py selftest: PASS cases=4 records=9")


BASE.validate_environment = validate_environment
BASE.verify_uart_bytes = verify_uart_bytes
BASE.selftest = selftest

if __name__ == "__main__":
    raise SystemExit(BASE.main())
