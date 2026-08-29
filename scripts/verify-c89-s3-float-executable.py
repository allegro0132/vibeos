#!/usr/bin/env python3
"""Verify C8.9-S3 code-6 evidence with the frozen F5 semantic oracle.

The predecessor verifier remains byte-for-byte intact. This adapter gives the
same independently implemented 1,176-record parser and oracle a disjoint C8.9
evidence domain, then tightens META and source identities to the executable
code-6 profile. Physical inputs are neither accepted nor claimed.
"""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
BASE_PATH = HERE.with_name("verify-c88-f5-float-target.py")
SPEC = importlib.util.spec_from_file_location("_vibeos_c88_f5_verifier", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the frozen C8.8-F5 semantic verifier")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

ORIGINAL_VALIDATE_ENVIRONMENT = BASE.validate_environment
ORIGINAL_VALIDATE_META = BASE.validate_meta
ORIGINAL_VERIFY_UART_BYTES = BASE.verify_uart_bytes
ORIGINAL_META_KEYS = set(BASE.META_KEYS)

BASE.__file__ = str(HERE)
BASE.SUITE_ID = "vibeos.c89.s3.float-executable"
BASE.RUN_ID_DOMAIN = b"vibeos.c89.s3.float-executable.run.v1\0"
BASE.SEMANTIC_DIGEST_DOMAIN = b"vibeos.c89.s3.float-executable.semantic.v1\0"
BASE.FAMILY_PREFIX = "VIBE_C89_S3_"
BASE.PREFIXES = {
    "META": "VIBE_C89_S3_META ",
    "CORE_CASE": "VIBE_C89_S3_CORE_CASE ",
    "F3_CASE": "VIBE_C89_S3_F3_CASE ",
    "F4_VECTOR": "VIBE_C89_S3_F4_VECTOR ",
    "FUEL": "VIBE_C89_S3_FUEL ",
    "LIFECYCLE": "VIBE_C89_S3_LIFECYCLE ",
    "END": "VIBE_C89_S3_END ",
    "PASS": "VIBE_C89_S3_PASS ",
    "FAIL": "VIBE_C89_S3_FAIL",
}
BASE.SCHEMAS = {
    family: f"vibeos.c89.s3.float-executable.{suffix}"
    for family, suffix in {
        "META": "meta",
        "CORE_CASE": "core-case",
        "F3_CASE": "f3-case",
        "F4_VECTOR": "f4-vector",
        "FUEL": "fuel",
        "LIFECYCLE": "lifecycle",
        "END": "end",
        "PASS": "pass",
    }.items()
}
BASE.EXPECTED_WIT_SHA256 = (
    "0fed13d57d96685734e622c7b82bf722600974f6a04a6f386a3805682094d80f"
)
BASE.EXPECTED_WORLD = "vibe:float/runtime@1.0.0"
BASE.EXPECTED_ACTIVATION_LABEL = "c89-float-runtime"
BASE.EXPECTED_CANDIDATE = {
    **BASE.EXPECTED_CANDIDATE,
    "candidate_acceptance_feature": "c89-executable",
}
BASE.EXPECTED_SEMANTIC_SHA256 = (
    "44cb0a12c01906b31a42fc6550d485496206ea23a08bc073a685e1b893fb94b8"
)
BASE.EXPECTED_MANIFEST_SHA256 = (
    "a9e25bcadfac2b839ae90cad0fb20e40b4a9682a7ec12e2264a0daddbec25fd4"
)
BASE.EXPECTED_MANIFEST_BYTES = 2_467
EXTRA_META_KEYS = {
    "qualification_node",
    "code5_inert",
    "durable_authorized",
    "release_authorized",
}
BASE.META_KEYS = ORIGINAL_META_KEYS | EXTRA_META_KEYS


def _identity(value: dict[str, object], key: str) -> dict[str, object]:
    return BASE.identity_record(value[key], f"environment.{key}")


def validate_environment(
    value: object,
    uart: bytes,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = BASE.EXPECTED_SEMANTIC_SHA256,
) -> dict[str, object]:
    if not isinstance(value, dict):
        BASE.fail("environment must be one JSON object")
    BASE.exact_keys(value, BASE.ENVIRONMENT_KEYS, "environment")
    if value["schema"] != "vibeos.c89.s3.float-executable.environment":
        BASE.fail("environment schema is not C8.9-S3")
    if value["suite_id"] != BASE.SUITE_ID:
        BASE.fail("environment suite is not C8.9-S3")
    build = value.get("build")
    if not isinstance(build, dict) or build.get("feature") != (
        "wasm-c89-s3-float-qemu-qualification"
    ):
        BASE.fail("environment does not select the code-6 QEMU feature")
    if value.get("evidence_sha256") != BASE.environment_evidence_sha256(value):
        BASE.fail("C8.9-S3 evidence digest differs")

    transformed = copy.deepcopy(value)
    transformed["schema"] = "vibeos.c88.f5.float-target.environment"
    transformed_build = transformed["build"]
    assert isinstance(transformed_build, dict)
    transformed_build["feature"] = "wasm-c88-f5-float-qemu-acceptance"
    transformed["evidence_sha256"] = BASE.environment_evidence_sha256(transformed)
    ORIGINAL_VALIDATE_ENVIRONMENT(
        transformed,
        uart,
        verify_self_identity=False,
        expected_semantic_sha256=expected_semantic_sha256,
    )

    if verify_self_identity:
        source = value["source"]
        assert isinstance(source, dict)
        manifest = _identity(value, "manifest")
        producer = _identity(value, "producer")
        qualification = _identity(value, "qualification")
        runner = _identity(value, "runner")
        verifier = _identity(value, "verifier")
        elf_auditor = _identity(value, "elf_auditor")
        contracts = (
            (
                manifest,
                BASE.ROOT
                / "acceptance/wasm-float-target/artifacts/c89-s3-qualification-manifest.json",
                "C8.9-S3 manifest",
            ),
            (producer, BASE.ROOT / "kernel/src/wasm_float_target.rs", "producer"),
            (
                qualification,
                BASE.ROOT / "acceptance/wasm-float-target/src/lib.rs",
                "qualification",
            ),
            (runner, HERE.with_name("qemu-c89-s3-float-executable.py"), "runner"),
            (verifier, HERE, "verifier"),
            (
                elf_auditor,
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
                (
                    cargo_config,
                    BASE.ROOT / "firmware/.cargo/config.toml",
                    "bare-metal Cargo config",
                ),
            ),
        )
        python = _identity(value, "python")
        BASE.require_local_identity(
            python,
            pathlib.Path(sys.executable).resolve(strict=True),
            "Python interpreter",
            maximum=BASE.MAX_KERNEL_BYTES,
        )
    return value


def validate_meta(
    record: BASE.Record, environment: dict[str, object]
) -> tuple[dict[str, object], dict[str, int]]:
    value = record.value
    BASE.exact_keys(value, ORIGINAL_META_KEYS | EXTRA_META_KEYS, "META")
    exact = {
        "qualification_node": "C8.9-S3",
        "code5_inert": True,
        "durable_authorized": False,
        "release_authorized": False,
        "artifact_profile_code": 6,
        "artifact_abi": 6,
        "component_profile": 3,
        "core_profile": 3,
        "runtime_abi": 6,
        "stage": "executable",
        "runtime_ready": True,
        "native_async_runtime_ready": False,
        "execution_enabled": True,
        "current_validation_engine": True,
        "current_component_engine": True,
        "candidate_production_ready": True,
        "executable_exports": 1,
    }
    for key, expected in exact.items():
        if type(value.get(key)) is not type(expected) or value.get(key) != expected:
            BASE.fail(f"META {key} is not the frozen code-6 value")

    transformed_value = copy.deepcopy(value)
    for key in EXTRA_META_KEYS:
        transformed_value.pop(key)
    transformed_value.update(
        {
            "artifact_profile_code": 5,
            "artifact_abi": 5,
            "component_profile": 2,
            "core_profile": 2,
            "runtime_abi": 5,
            "stage": "validation-only",
            "runtime_ready": False,
            "execution_enabled": False,
            "current_validation_engine": False,
            "current_component_engine": False,
            "candidate_production_ready": False,
            "executable_exports": 0,
        }
    )
    transformed = BASE.Record(record.family, transformed_value, record.line)
    BASE.META_KEYS = ORIGINAL_META_KEYS
    try:
        _, counts = ORIGINAL_VALIDATE_META(transformed, environment)
    finally:
        BASE.META_KEYS = ORIGINAL_META_KEYS | EXTRA_META_KEYS
    return value, counts


def verify_uart_bytes(
    uart: bytes,
    environment_value: object,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = BASE.EXPECTED_SEMANTIC_SHA256,
) -> BASE.VerifiedTranscript:
    return ORIGINAL_VERIFY_UART_BYTES(
        uart,
        environment_value,
        verify_self_identity=verify_self_identity,
        expected_semantic_sha256=expected_semantic_sha256,
    )


def selftest() -> None:
    uart, environment = BASE.synthetic_fixture()
    fixture_semantic = str(environment["expected_semantic_sha256"])
    environment["schema"] = "vibeos.c89.s3.float-executable.environment"
    build = environment["build"]
    assert isinstance(build, dict)
    build["feature"] = "wasm-c89-s3-float-qemu-qualification"
    lines = uart.decode("utf-8").splitlines()
    prefix = BASE.PREFIXES["META"]
    meta = BASE.strict_json_text(lines[0][len(prefix) :], "selftest META")
    assert isinstance(meta, dict)
    meta.update(
        {
            "qualification_node": "C8.9-S3",
            "code5_inert": True,
            "durable_authorized": False,
            "release_authorized": False,
            "artifact_profile_code": 6,
            "artifact_abi": 6,
            "component_profile": 3,
            "core_profile": 3,
            "runtime_abi": 6,
            "stage": "executable",
            "runtime_ready": True,
            "execution_enabled": True,
            "current_validation_engine": True,
            "current_component_engine": True,
            "candidate_production_ready": True,
            "executable_exports": 1,
        }
    )
    lines[0] = prefix + BASE.canonical_json(meta).decode("ascii")
    uart = ("\n".join(lines) + "\n").encode("utf-8")
    BASE.refresh_uart_identity(environment, uart)
    BASE.refresh_evidence_identity(environment)
    verified = BASE.verify_uart_bytes(
        uart,
        environment,
        verify_self_identity=False,
        expected_semantic_sha256=fixture_semantic,
    )
    if len(verified.records) != 1_176:
        BASE.fail("selftest record count differs")

    bad_lines = uart.decode("utf-8").splitlines()
    bad_meta = BASE.strict_json_text(
        bad_lines[0][len(prefix) :], "selftest bad META"
    )
    assert isinstance(bad_meta, dict)
    bad_meta["artifact_profile_code"] = 5
    bad_lines[0] = prefix + BASE.canonical_json(bad_meta).decode("ascii")
    bad_uart = ("\n".join(bad_lines) + "\n").encode("utf-8")
    bad_environment = copy.deepcopy(environment)
    BASE.refresh_uart_identity(bad_environment, bad_uart)
    BASE.refresh_evidence_identity(bad_environment)
    try:
        BASE.verify_uart_bytes(
            bad_uart,
            bad_environment,
            verify_self_identity=False,
            expected_semantic_sha256=fixture_semantic,
        )
    except BASE.VerificationError:
        pass
    else:
        BASE.fail("selftest accepted code 5 as C8.9-S3 evidence")
    print("verify-c89-s3-float-executable.py selftest: PASS cases=2 records=1176")


BASE.validate_environment = validate_environment
BASE.validate_meta = validate_meta
BASE.verify_uart_bytes = verify_uart_bytes
BASE.selftest = selftest


if __name__ == "__main__":
    raise SystemExit(BASE.main())
