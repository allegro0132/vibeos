#!/usr/bin/env python3
"""Verify the future C8.8-F5 Duo physical transcript contract on the host.

This verifier is deliberately non-evidence.  It has no serial, ``/dev``,
package, flash, reset, boot, or board interface.  A valid single transcript
proves only the closed 1,176-record semantic grammar.  It cannot prove a power
cycle, cold boot, capture provenance, terminal quiescence, or physical origin.

The physical producer does not exist in this node.  Its future wire contract is
separate from fixed QEMU and from the permanently inert Duo readiness sentinel.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import tempfile
import types
from dataclasses import dataclass
from typing import Any, Callable, NoReturn, Sequence


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT_PATH = (
    ROOT
    / "acceptance/wasm-float-target/artifacts/qualification-duo-physical-v1-contract.json"
)
TRANSCRIPT_SCHEMA_PATH = (
    ROOT
    / "acceptance/wasm-float-target/artifacts/qualification-duo-physical-v1-transcript-schema.json"
)
ORACLE_PATH = ROOT / "scripts/verify-c88-f5-float-target.py"

EXPECTED_CONTRACT_BYTES = 5_605
EXPECTED_CONTRACT_SHA256 = (
    "01284fa4bb76a24e0a40e39fddec109e98ff36ec8912bb806f7a52a520a6617e"
)
EXPECTED_TRANSCRIPT_SCHEMA_BYTES = 5_923
EXPECTED_TRANSCRIPT_SCHEMA_SHA256 = (
    "08007a5e68e53181592dd9eaecf124a630b2eddfdc20c146504ff1d4df8811f5"
)
EXPECTED_ORACLE_BYTES = 134_348
EXPECTED_ORACLE_SHA256 = (
    "36451c3c614486a714b3466b77b329fee8a1368603ffaa9d2925b75b3f666686"
)

SUITE_ID = "vibeos.c88.f5.float-target.duo-physical-v1"
RUN_ID_DOMAIN = b"vibeos.c88.f5.float-target.duo-physical-v1.run.v1\0"
RUN_ID_FIELDS = (
    "source_commit",
    "source_tree",
    "challenge",
    "contract_sha256",
    "transcript_schema_sha256",
    "candidate_sha256",
)
RUN_ID_DESCRIPTION = {
    "algorithm": "sha256",
    "domain_ascii": "vibeos.c88.f5.float-target.duo-physical-v1.run.v1",
    "domain_nul_terminated": True,
    "nul_separated_fields": list(RUN_ID_FIELDS),
}
SEMANTIC_DIGEST_DOMAIN = b"vibeos.c88.f5.float-target.semantic.v1\0"
EXPECTED_SEMANTIC_SHA256 = (
    "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1"
)
# The independent oracle's synthetic fixture uses deliberately solved aggregate
# Core witnesses rather than the producer's per-record trace words.  It is
# accepted only with the reserved selftest identity; normal mode always requires
# EXPECTED_SEMANTIC_SHA256.
SELFTEST_SEMANTIC_SHA256 = (
    "248884c598f37b6dcfdd49ad36c6be474f691fb73d01e4a87dfb9b4eb38e680f"
)
EXPECTED_CANDIDATE_SHA256 = (
    "5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a"
)
PLATFORM = "milkv-duo-cv1800b-c906-v1"
PLATFORM_CLASS = "physical-target"
TARGET = "riscv64imac-unknown-none-elf"
PHYSICAL_PROVENANCE = "not-claimed"

READINESS_SUITE_ID = "vibeos.c88.f5.float-target.duo-v1"
READINESS_SOURCE_COMMIT = "d1" * 20
READINESS_SOURCE_TREE = "d2" * 20
READINESS_CHALLENGE = "d3" * 32
READINESS_RUN_ID = "c5c8ec42e56fbeaf38106965e5ec6735cb86a93af530cd37f5002dba1971b4ac"
READINESS_ARM_MARKER = "vibeos.c88.f5.duo.compile-readiness.arm=0"
PHYSICAL_ARM_MARKER = "vibeos.c88.f5.duo.physical-qualification.arm=1"
PHYSICAL_FEATURE = "wasm-c88-f5-float-duo-physical-qualification"

SELFTEST_SOURCE_COMMIT = "e1" * 20
SELFTEST_SOURCE_TREE = "e2" * 20
SELFTEST_CHALLENGE = "e3" * 32
SELFTEST_RUN_ID = "24f65f1f0100ebc90c34cff1cf44f4b58e102d1a47f11159848c75d94ef5cacd"

FAMILY_PREFIX = "VIBE_C88_F5_DUO_PHYSICAL_"
PREFIXES = {
    "META": FAMILY_PREFIX + "META ",
    "CORE_CASE": FAMILY_PREFIX + "CORE_CASE ",
    "F3_CASE": FAMILY_PREFIX + "F3_CASE ",
    "F4_VECTOR": FAMILY_PREFIX + "F4_VECTOR ",
    "FUEL": FAMILY_PREFIX + "FUEL ",
    "LIFECYCLE": FAMILY_PREFIX + "LIFECYCLE ",
    "END": FAMILY_PREFIX + "END ",
    "PASS": FAMILY_PREFIX + "PASS ",
    "FAIL": FAMILY_PREFIX + "FAIL ",
}
SCHEMAS = {
    "META": "vibeos.c88.f5.float-target.duo-physical-v1.meta",
    "CORE_CASE": "vibeos.c88.f5.float-target.duo-physical-v1.core-case",
    "F3_CASE": "vibeos.c88.f5.float-target.duo-physical-v1.f3-case",
    "F4_VECTOR": "vibeos.c88.f5.float-target.duo-physical-v1.f4-vector",
    "FUEL": "vibeos.c88.f5.float-target.duo-physical-v1.fuel",
    "LIFECYCLE": "vibeos.c88.f5.float-target.duo-physical-v1.lifecycle",
    "END": "vibeos.c88.f5.float-target.duo-physical-v1.end",
    "PASS": "vibeos.c88.f5.float-target.duo-physical-v1.pass",
    "FAIL": "vibeos.c88.f5.float-target.duo-physical-v1.fail",
}
DATA_FAMILIES = ("CORE_CASE", "F3_CASE", "F4_VECTOR", "FUEL", "LIFECYCLE")
FAMILY_ORDER = {
    "META": 0,
    "CORE_CASE": 1,
    "F3_CASE": 2,
    "F4_VECTOR": 3,
    "FUEL": 4,
    "LIFECYCLE": 5,
    "END": 6,
    "PASS": 7,
}
EXPECTED_COUNTS = {
    "CORE_CASE": 146,
    "F3_CASE": 13,
    "F4_VECTOR": 12,
    "FUEL": 1_000,
    "LIFECYCLE": 5,
}
EXPECTED_RECORDS = 1_176

EXPECTED_PHYSICAL_METADATA = {
    "platform": PLATFORM,
    "platform_class": PLATFORM_CLASS,
    "target": TARGET,
    "physical_provenance": PHYSICAL_PROVENANCE,
    "qualification_mode": "physical-qualification",
    "contract_stage": "physical-run-contract",
    "binding_mode": "formal-non-sentinel",
    "producer_feature": PHYSICAL_FEATURE,
    "arm_marker": PHYSICAL_ARM_MARKER,
    "sentinel_bindings_present": False,
    "formal_physical_bindings_present": True,
    "execution_armed": True,
    "physical_evidence_present": False,
    "operator_power_cycle_claimed_by_target": False,
    "operator_cold_boot_claimed_by_target": False,
    "capture_claimed_by_target": False,
    "terminal_quiescence_claimed_by_target": False,
    "f5_complete": False,
    "float_complete": False,
    "c88_complete": False,
    "executable_successor_authorized": False,
}

PHYSICAL_ONLY_META_KEYS = set(EXPECTED_PHYSICAL_METADATA) - {
    "platform",
    "platform_class",
    "target",
    "physical_provenance",
}
TERMINAL_KEYS = {
    "schema",
    "version",
    "run_id",
    "challenge",
    "core_cases",
    "f3_cases",
    "f4_vectors",
    "fuel_records",
    "lifecycle_records",
    "records",
    "semantic_sha256",
}

MAX_UART_BYTES = 16 * 1024 * 1024
MAX_CONTRACT_BYTES = 64 * 1024
MAX_SUMMARY_BYTES = 64 * 1024
MAX_UART_LINES = 20_000
MAX_LINE_BYTES = 1024 * 1024
MAX_JSON_INTEGER_DIGITS = 20
READ_CHUNK_BYTES = 64 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FATAL_MARKERS = ("panicked at", "panic", "fatal")
C84_MARKERS = ("VIBE_WASM_AOT_", "vibeos.c84.")


class VerificationError(RuntimeError):
    """A fail-closed contract, transcript, or publication rejection."""


@dataclass(frozen=True)
class VerifiedTranscript:
    metadata: dict[str, object]
    records: tuple[Any, ...]
    ending: dict[str, object]
    passing: dict[str, object]
    semantic_sha256: str
    uart_sha256: str
    uart_bytes: int


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, member in pairs:
        if key in value:
            fail(f"duplicate JSON member {key!r}")
        value[key] = member
    return value


def reject_json_number(token: str) -> NoReturn:
    fail(f"non-integer JSON number {token!r} is forbidden")


def parse_json_integer(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        fail(f"JSON integer exceeds frozen {MAX_JSON_INTEGER_DIGITS}-digit bound")
    return int(token, 10)


def strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        fail(f"{label} is not strict UTF-8: {error}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_members,
            parse_int=parse_json_integer,
            parse_float=reject_json_number,
            parse_constant=reject_json_number,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        fail(f"invalid {label} JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be one JSON object")
    return value


def exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def stable_regular_bytes(path: pathlib.Path, label: str, *, maximum: int) -> bytes:
    requested = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )
    try:
        before_path = requested.lstat()
        if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
            fail(f"{label} must be a direct singly-linked regular file")
        if requested.resolve(strict=True) != requested:
            fail(f"{label} path must not traverse symbolic links")
        descriptor = os.open(requested, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                fail(f"{label} opened object must be a singly-linked regular file")
            if not 0 < before.st_size <= maximum:
                fail(f"{label} byte length is outside (0, {maximum}]")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    fail(f"{label} grew beyond {maximum} bytes while read")
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = requested.lstat()
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    identities = [
        (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        for item in (before_path, before, after, after_path)
    ]
    if len(set(identities)) != 1:
        fail(f"{label} changed while it was read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"{label} byte length changed while it was read")
    return raw


def load_oracle(raw: bytes) -> types.ModuleType:
    name = "_vibeos_c88_f5_transcript_oracle"
    module = types.ModuleType(name)
    module.__file__ = str(ORACLE_PATH)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(raw, str(ORACLE_PATH), "exec"), module.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise
    # Route every oracle fail-closed path through this verifier's public error
    # type so normal CLI failures never escape as tracebacks.
    module.VerificationError = VerificationError
    return module


def check_contract() -> tuple[dict[str, object], dict[str, object], types.ModuleType]:
    contract_raw = stable_regular_bytes(
        CONTRACT_PATH, "physical contract", maximum=MAX_CONTRACT_BYTES
    )
    schema_raw = stable_regular_bytes(
        TRANSCRIPT_SCHEMA_PATH,
        "physical transcript schema",
        maximum=MAX_CONTRACT_BYTES,
    )
    oracle_raw = stable_regular_bytes(
        ORACLE_PATH, "independent semantic oracle", maximum=1024 * 1024
    )
    identities = (
        (
            contract_raw,
            EXPECTED_CONTRACT_BYTES,
            EXPECTED_CONTRACT_SHA256,
            "physical contract",
        ),
        (
            schema_raw,
            EXPECTED_TRANSCRIPT_SCHEMA_BYTES,
            EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
            "physical transcript schema",
        ),
        (
            oracle_raw,
            EXPECTED_ORACLE_BYTES,
            EXPECTED_ORACLE_SHA256,
            "independent semantic oracle",
        ),
    )
    for raw, expected_bytes, expected_sha256, label in identities:
        require(len(raw) == expected_bytes, f"{label} byte identity differs")
        require(sha256_bytes(raw) == expected_sha256, f"{label} SHA-256 differs")

    contract = strict_json(contract_raw, "physical contract")
    schema = strict_json(schema_raw, "physical transcript schema")
    require(contract.get("suite_id") == SUITE_ID, "contract suite differs")
    require(contract.get("status") == "non-evidence", "contract status differs")
    require(schema.get("suite_id") == SUITE_ID, "schema suite differs")
    require(schema.get("status") == "non-evidence", "schema status differs")
    require(contract.get("run_id") == RUN_ID_DESCRIPTION, "contract run ID differs")
    require(schema.get("run_id") == RUN_ID_DESCRIPTION, "schema run ID differs")
    platform = contract.get("platform")
    require(
        isinstance(platform, dict)
        and platform
        == {
            "id": PLATFORM,
            "class": PLATFORM_CLASS,
            "target": TARGET,
            "physical_provenance": PHYSICAL_PROVENANCE,
        },
        "contract platform differs",
    )
    require(
        schema.get("metadata") == EXPECTED_PHYSICAL_METADATA,
        "schema physical metadata contract differs",
    )
    uart = schema.get("uart")
    require(isinstance(uart, dict), "schema UART contract is absent")
    require(
        uart.get("family_prefix") == FAMILY_PREFIX,
        "schema physical family prefix differs",
    )
    schema_prefixes = uart.get("prefixes")
    schema_ids = uart.get("schema_ids")
    expected_prefixes = {
        "metadata": PREFIXES["META"],
        "core": PREFIXES["CORE_CASE"],
        "canonical_abi": PREFIXES["F3_CASE"],
        "component_vector": PREFIXES["F4_VECTOR"],
        "fuel": PREFIXES["FUEL"],
        "lifecycle": PREFIXES["LIFECYCLE"],
        "end": PREFIXES["END"],
        "pass": PREFIXES["PASS"],
        "fail": PREFIXES["FAIL"],
    }
    expected_schema_ids = {
        "metadata": SCHEMAS["META"],
        "core": SCHEMAS["CORE_CASE"],
        "canonical_abi": SCHEMAS["F3_CASE"],
        "component_vector": SCHEMAS["F4_VECTOR"],
        "fuel": SCHEMAS["FUEL"],
        "lifecycle": SCHEMAS["LIFECYCLE"],
        "end": SCHEMAS["END"],
        "pass": SCHEMAS["PASS"],
        "fail": SCHEMAS["FAIL"],
    }
    require(schema_prefixes == expected_prefixes, "schema UART prefixes differ")
    require(schema_ids == expected_schema_ids, "schema UART IDs differ")
    require(
        schema.get("records")
        == {
            "core": 146,
            "canonical_abi": 13,
            "component_vectors": 12,
            "fuel": 1_000,
            "lifecycle": 5,
            "total": EXPECTED_RECORDS,
        },
        "schema record counts differ",
    )
    formal_bindings = contract.get("formal_bindings")
    require(
        isinstance(formal_bindings, dict)
        and formal_bindings.get("candidate_sha256") == EXPECTED_CANDIDATE_SHA256,
        "contract candidate binding differs",
    )
    shared = contract.get("shared_qualification")
    require(
        isinstance(shared, dict)
        and shared.get("semantic_sha256") == EXPECTED_SEMANTIC_SHA256
        and shared.get("candidate_sha256") == EXPECTED_CANDIDATE_SHA256
        and shared.get("semantic_sha256_domain_ascii")
        == SEMANTIC_DIGEST_DOMAIN[:-1].decode("ascii")
        and shared.get("semantic_domain_nul_terminated") is True,
        "shared qualification identity differs",
    )
    semantic = schema.get("semantic_digest")
    require(
        isinstance(semantic, dict)
        and semantic.get("expected_sha256") == EXPECTED_SEMANTIC_SHA256
        and semantic.get("domain_ascii") == SEMANTIC_DIGEST_DOMAIN[:-1].decode("ascii")
        and semantic.get("domain_nul_terminated") is True,
        "schema semantic identity differs",
    )
    producer = contract.get("future_physical_producer")
    require(
        isinstance(producer, dict)
        and producer.get("arm_marker") == PHYSICAL_ARM_MARKER
        and producer.get("producer_present_in_this_node") is False
        and producer.get("readiness_arm_marker_forbidden") == READINESS_ARM_MARKER,
        "future producer separation differs",
    )
    require(
        contract.get("verifier_only")
        == {
            "producer_present": False,
            "physical_feature_present": False,
            "execution_arm_present": False,
            "image_present": False,
            "package_present": False,
            "capture_present": False,
            "device_access_permitted": False,
            "serial_access_permitted": False,
            "flash_permitted": False,
            "reset_permitted": False,
            "physical_evidence_present": False,
        },
        "host-verifier-only boundary differs",
    )
    completion = contract.get("completion")
    require(
        completion
        == {
            "physical_provenance": PHYSICAL_PROVENANCE,
            "f5_complete": False,
            "float_complete": False,
            "c88_complete": False,
            "executable_successor_authorized": False,
        },
        "contract completion non-claim differs",
    )
    campaign = contract.get("future_three_boot_gate")
    require(
        isinstance(campaign, dict)
        and campaign.get("same_identity_fields_required")
        == [
            *RUN_ID_FIELDS[:3],
            "run_id",
            *RUN_ID_FIELDS[3:],
            "build_environment_sha256",
            "package_envelope_sha256",
            "kernel_elf_sha256",
            "full_sd_image_sha256",
        ]
        and campaign.get("external_build_package_custody_required") is True
        and campaign.get("present")
        == {
            "operator_confirmed_power_cycles": 0,
            "operator_confirmed_cold_boots": 0,
            "complete_transcripts": 0,
            "terminal_quiescences": 0,
            "operator_power_off_confirmations": 0,
        }
        and campaign.get("gate_satisfied") is False,
        "future physical campaign custody differs",
    )
    schema_campaign = schema.get("future_three_boot_gate")
    require(
        isinstance(schema_campaign, dict)
        and schema_campaign.get("same_build_environment_sha256_required") is True
        and schema_campaign.get("same_package_envelope_sha256_required") is True
        and schema_campaign.get("same_kernel_elf_sha256_required") is True
        and schema_campaign.get("same_full_sd_image_sha256_required") is True
        and schema_campaign.get("external_build_package_custody_required") is True
        and schema_campaign.get("gate_satisfied") is False,
        "schema future physical campaign custody differs",
    )
    oracle = load_oracle(oracle_raw)
    require(
        oracle.SEMANTIC_DIGEST_DOMAIN == SEMANTIC_DIGEST_DOMAIN
        and oracle.EXPECTED_SEMANTIC_SHA256 == EXPECTED_SEMANTIC_SHA256
        and oracle.EXPECTED_COMPONENT_SHA256 == EXPECTED_CANDIDATE_SHA256,
        "independent semantic oracle identity differs",
    )
    return contract, schema, oracle


def canonical_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        fail(f"{label} is not canonical lowercase hexadecimal")
    if not any(character != "0" for character in value):
        fail(f"{label} must not be all zero")
    return value


def expected_run_id(source_commit: str, source_tree: str, challenge: str) -> str:
    digest = hashlib.sha256()
    digest.update(RUN_ID_DOMAIN)
    for index, field in enumerate(
        (
            source_commit,
            source_tree,
            challenge,
            EXPECTED_CONTRACT_SHA256,
            EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
            EXPECTED_CANDIDATE_SHA256,
        )
    ):
        if index:
            digest.update(b"\0")
        digest.update(field.encode("ascii"))
    return digest.hexdigest()


def validate_formal_bindings(
    source_commit: str,
    source_tree: str,
    challenge: str,
    *,
    allow_selftest: bool,
) -> str:
    canonical_hex(source_commit, HEX40, "source commit")
    canonical_hex(source_tree, HEX40, "source tree")
    canonical_hex(challenge, HEX64, "challenge")
    if source_commit == READINESS_SOURCE_COMMIT:
        fail("readiness source-commit sentinel is forbidden")
    if source_tree == READINESS_SOURCE_TREE:
        fail("readiness source-tree sentinel is forbidden")
    if challenge == READINESS_CHALLENGE:
        fail("readiness challenge sentinel is forbidden")
    if (
        not allow_selftest
        and source_commit == SELFTEST_SOURCE_COMMIT
        and source_tree == SELFTEST_SOURCE_TREE
        and challenge == SELFTEST_CHALLENGE
    ):
        fail("reserved synthetic selftest bindings are forbidden in normal mode")
    run_id = expected_run_id(source_commit, source_tree, challenge)
    if run_id == READINESS_RUN_ID:
        fail("readiness run ID is forbidden")
    return run_id


def parse_record(
    oracle: types.ModuleType,
    line: str,
    family: str,
    line_number: int,
) -> Any:
    prefix = PREFIXES[family]
    payload = line[len(prefix) :]
    if not payload or payload != payload.strip():
        fail(f"line {line_number} {family} payload has surrounding whitespace")
    value = strict_json(payload.encode("utf-8"), f"line {line_number} {family}")
    return oracle.Record(family, value, line_number)


def parse_uart(
    oracle: types.ModuleType, uart: bytes
) -> tuple[Any, tuple[Any, ...], Any, Any]:
    if len(uart) > MAX_UART_BYTES:
        fail(f"UART exceeds {MAX_UART_BYTES} bytes")
    if not uart.endswith(b"\n"):
        fail("UART must end at an exact newline boundary")
    if b"\r" in uart:
        fail("UART carriage returns are forbidden")
    try:
        text = uart.decode("utf-8", errors="strict")
    except UnicodeError as error:
        fail(f"UART is not strict UTF-8: {error}")
    lines = text[:-1].split("\n")
    if len(lines) > MAX_UART_LINES:
        fail(f"UART has more than {MAX_UART_LINES} lines")

    records: list[Any] = []
    stream_started = False
    pass_seen = False
    previous_rank = -1
    for line_number, line in enumerate(lines, 1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            fail(f"UART line {line_number} exceeds {MAX_LINE_BYTES} bytes")
        lowered = line.lower()
        if any(marker in lowered for marker in FATAL_MARKERS):
            fail(f"UART contains a fatal marker on line {line_number}")
        if any(marker in line for marker in C84_MARKERS):
            fail(f"UART contains a C8.4 marker on line {line_number}")
        if "VIBE_C88_F5_" in line and not line.startswith("VIBE_C88_F5_"):
            fail(f"F5 family text is not column-zero on line {line_number}")
        if not line.startswith(FAMILY_PREFIX):
            if line.startswith("VIBE_C88_F5_"):
                fail(f"foreign QEMU/readiness F5 family on line {line_number}")
            if stream_started:
                fail(f"non-contract UART bytes appear after META on line {line_number}")
            continue
        if pass_seen:
            fail(f"physical family output appears after PASS on line {line_number}")
        if line.startswith(PREFIXES["FAIL"]):
            fail(f"guest emitted explicit physical FAIL on line {line_number}")
        matched = None
        for family in ("META", *DATA_FAMILIES, "END", "PASS"):
            if line.startswith(PREFIXES[family]):
                matched = parse_record(oracle, line, family, line_number)
                break
        if matched is None:
            fail(f"unknown physical family record on line {line_number}")
        if not stream_started and matched.family != "META":
            fail("physical transcript does not begin with META")
        stream_started = True
        rank = FAMILY_ORDER[matched.family]
        if rank < previous_rank:
            fail(f"physical family order regressed on line {line_number}")
        previous_rank = rank
        records.append(matched)
        if matched.family == "PASS":
            pass_seen = True

    metadata = [record for record in records if record.family == "META"]
    endings = [record for record in records if record.family == "END"]
    passings = [record for record in records if record.family == "PASS"]
    if len(metadata) != 1 or len(endings) != 1 or len(passings) != 1:
        fail(
            "UART must contain exactly one META, END, and PASS: "
            f"got {len(metadata)}, {len(endings)}, {len(passings)}"
        )
    data = tuple(record for record in records if record.family in DATA_FAMILIES)
    if records[-2].family != "END" or records[-1].family != "PASS":
        fail("END and PASS must be the final two physical records")
    return metadata[0], data, endings[0], passings[0]


def validate_schema(oracle: types.ModuleType, record: Any) -> None:
    if record.value.get("schema") != SCHEMAS[record.family]:
        fail(f"line {record.line} {record.family} schema differs")
    if type(record.value.get("version")) is not int or record.value["version"] != 1:
        fail(f"line {record.line} {record.family} version differs")


def validate_metadata(
    oracle: types.ModuleType,
    record: Any,
    source_commit: str,
    source_tree: str,
    challenge: str,
    run_id: str,
) -> tuple[dict[str, object], dict[str, int]]:
    value = record.value
    expected_keys = (set(oracle.META_KEYS) - {"manifest_sha256"}) | {
        "contract_sha256",
        *PHYSICAL_ONLY_META_KEYS,
    }
    exact_keys(value, expected_keys, "META")
    validate_schema(oracle, record)
    exact_bindings = {
        "suite_id": SUITE_ID,
        "suite_revision": 1,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "challenge": challenge,
        "run_id": run_id,
        "contract_sha256": EXPECTED_CONTRACT_SHA256,
        "transcript_schema_sha256": EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
        **EXPECTED_PHYSICAL_METADATA,
    }
    for key, expected in exact_bindings.items():
        if type(value.get(key)) is not type(expected) or value.get(key) != expected:
            fail(f"META {key} differs: {value.get(key)!r} != {expected!r}")
    if READINESS_SUITE_ID in value.values() or READINESS_ARM_MARKER in value.values():
        fail("META contains a readiness identity")

    converted = copy.deepcopy(value)
    for key in PHYSICAL_ONLY_META_KEYS:
        del converted[key]
    converted["manifest_sha256"] = converted.pop("contract_sha256")
    converted["schema"] = oracle.SCHEMAS["META"]
    converted["suite_id"] = oracle.SUITE_ID
    converted["platform"] = "qemu-virt-rv64-tcg-icount-v1"
    converted["platform_class"] = "emulator"
    exact_keys(converted, set(oracle.META_KEYS), "converted META")
    environment = {
        "source": {"commit": source_commit, "tree": source_tree},
        "challenge": challenge,
        "run_id": run_id,
        "manifest_sha256": EXPECTED_CONTRACT_SHA256,
        "transcript_schema_sha256": EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
        "platform": {
            "id": "qemu-virt-rv64-tcg-icount-v1",
            "class": "emulator",
            "target": TARGET,
            "physical_provenance": PHYSICAL_PROVENANCE,
        },
    }
    _, counts = oracle.validate_meta(
        oracle.Record("META", converted, record.line), environment
    )
    return value, counts


def validate_terminal(
    oracle: types.ModuleType,
    record: Any,
    family: str,
    *,
    run_id: str,
    challenge: str,
    counts: dict[str, int],
    semantic_sha256: str,
) -> dict[str, object]:
    value = record.value
    exact_keys(value, TERMINAL_KEYS, family)
    validate_schema(oracle, record)
    expected = {
        "version": 1,
        "run_id": run_id,
        "challenge": challenge,
        "core_cases": counts["CORE_CASE"],
        "f3_cases": counts["F3_CASE"],
        "f4_vectors": counts["F4_VECTOR"],
        "fuel_records": counts["FUEL"],
        "lifecycle_records": counts["LIFECYCLE"],
        "records": sum(counts.values()),
        "semantic_sha256": semantic_sha256,
    }
    for key, member in expected.items():
        if type(value.get(key)) is not type(member) or value.get(key) != member:
            fail(f"{family} {key} differs")
    return value


def verify_uart_bytes(
    uart: bytes,
    source_commit: str,
    source_tree: str,
    challenge: str,
    *,
    allow_selftest: bool = False,
) -> VerifiedTranscript:
    _, _, oracle = check_contract()
    run_id = validate_formal_bindings(
        source_commit, source_tree, challenge, allow_selftest=allow_selftest
    )
    meta_record, records, end_record, pass_record = parse_uart(oracle, uart)
    metadata, declared_counts = validate_metadata(
        oracle, meta_record, source_commit, source_tree, challenge, run_id
    )

    groups = {family: [] for family in DATA_FAMILIES}
    for sequence, record in enumerate(records):
        validate_schema(oracle, record)
        if record.value.get("run_id") != run_id:
            fail(f"line {record.line} run ID differs")
        if type(record.value.get("sequence")) is not int:
            fail(f"line {record.line} sequence is not an integer")
        if record.value["sequence"] != sequence:
            fail(f"line {record.line} sequence differs from {sequence}")
        groups[record.family].append(record)

    counts = {family: len(groups[family]) for family in DATA_FAMILIES}
    if counts != EXPECTED_COUNTS:
        fail(f"physical record counts differ: {counts!r}")
    if len(records) != EXPECTED_RECORDS:
        fail("physical transcript does not contain exactly 1,176 data records")
    mapping = {
        "CORE_CASE": "core_cases",
        "F3_CASE": "f3_cases",
        "F4_VECTOR": "f4_vectors",
        "FUEL": "fuel_records",
        "LIFECYCLE": "lifecycle_records",
    }
    for family, key in mapping.items():
        if declared_counts[key] != counts[family]:
            fail(f"META {key} differs from observed {family} count")
    if declared_counts["records"] != EXPECTED_RECORDS:
        fail("META record total differs")

    oracle.validate_core(groups["CORE_CASE"], metadata)
    oracle.validate_f3(groups["F3_CASE"])
    oracle.validate_f4(groups["F4_VECTOR"], metadata)
    oracle.validate_fuel(groups["FUEL"], metadata)
    oracle.validate_lifecycle(groups["LIFECYCLE"], metadata)
    semantic_sha256 = oracle.semantic_digest(records)
    reserved_selftest = (
        allow_selftest
        and source_commit == SELFTEST_SOURCE_COMMIT
        and source_tree == SELFTEST_SOURCE_TREE
        and challenge == SELFTEST_CHALLENGE
    )
    expected_semantic_sha256 = (
        SELFTEST_SEMANTIC_SHA256 if reserved_selftest else EXPECTED_SEMANTIC_SHA256
    )
    if semantic_sha256 != expected_semantic_sha256:
        fail("physical transcript semantic digest differs from the frozen witness")
    ending = validate_terminal(
        oracle,
        end_record,
        "END",
        run_id=run_id,
        challenge=challenge,
        counts=counts,
        semantic_sha256=semantic_sha256,
    )
    passing = validate_terminal(
        oracle,
        pass_record,
        "PASS",
        run_id=run_id,
        challenge=challenge,
        counts=counts,
        semantic_sha256=semantic_sha256,
    )
    return VerifiedTranscript(
        metadata=metadata,
        records=records,
        ending=ending,
        passing=passing,
        semantic_sha256=semantic_sha256,
        uart_sha256=sha256_bytes(uart),
        uart_bytes=len(uart),
    )


def summary_value(
    verified: VerifiedTranscript, *, synthetic_test_only: bool
) -> dict[str, object]:
    metadata = verified.metadata
    return {
        "schema": "vibeos.c88.f5.float-target.duo-physical-v1.single-boot-summary",
        "version": 1,
        "suite_id": SUITE_ID,
        "status": "verified-transcript-non-evidence",
        "source_commit": metadata["source_commit"],
        "source_tree": metadata["source_tree"],
        "challenge": metadata["challenge"],
        "run_id": metadata["run_id"],
        "contract_sha256": EXPECTED_CONTRACT_SHA256,
        "transcript_schema_sha256": EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
        "candidate_sha256": EXPECTED_CANDIDATE_SHA256,
        "uart_sha256": verified.uart_sha256,
        "uart_bytes": verified.uart_bytes,
        "records": {
            "core": 146,
            "canonical_abi": 13,
            "component_vectors": 12,
            "fuel": 1_000,
            "lifecycle": 5,
            "total": EXPECTED_RECORDS,
        },
        "semantic_sha256": verified.semantic_sha256,
        "transcript_grammar_verified": True,
        "post_pass_bytes_absent": True,
        "uart_file_present": True,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "source_build_provenance": "not-claimed",
        "operator_power_cycle_confirmed": False,
        "operator_cold_boot_confirmed": False,
        "capture_boot_id_present": False,
        "capture_present": False,
        "terminal_quiescence_verified": False,
        "operator_power_off_confirmed": False,
        "physical_evidence_present": False,
        "f5_complete": False,
        "float_complete": False,
        "c88_complete": False,
        "executable_successor_authorized": False,
        "synthetic_test_only": synthetic_test_only,
    }


def rendered_summary(value: dict[str, object]) -> bytes:
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "ascii"
    )
    if len(raw) > MAX_SUMMARY_BYTES:
        fail("derived summary exceeds its host bound")
    return raw


def write_summary_no_clobber(path: pathlib.Path, raw: bytes) -> None:
    requested = pathlib.Path(os.path.abspath(os.fspath(path)))
    parent = requested.parent
    basename = requested.name
    if not basename or basename in (".", ".."):
        fail("summary output basename is invalid")
    try:
        before_parent = parent.lstat()
        if (
            not stat.S_ISDIR(before_parent.st_mode)
            or parent.resolve(strict=True) != parent
        ):
            fail("summary output parent must be a direct directory")
        directory_fd = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        fail(f"cannot open summary output directory: {error}")
    temporary_name: str | None = None
    descriptor: int | None = None
    try:
        opened_parent = os.fstat(directory_fd)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            before_parent.st_dev,
            before_parent.st_ino,
        ):
            fail("summary output directory changed while opened")
        for _ in range(128):
            candidate = (
                f".vibeos-c88-f5-physical-{os.getpid()}-{secrets.token_hex(12)}.tmp"
            )
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if descriptor is None or temporary_name is None:
            fail("cannot allocate summary temporary file")
        output_descriptor = descriptor
        descriptor = None
        with os.fdopen(output_descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(
                temporary_name,
                basename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise VerificationError(
                "summary output already exists; refusing to overwrite"
            ) from error
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_name = None
        os.fsync(directory_fd)
        after_parent = parent.lstat()
        if not stat.S_ISDIR(after_parent.st_mode) or (
            after_parent.st_dev,
            after_parent.st_ino,
        ) != (opened_parent.st_dev, opened_parent.st_ino):
            fail("summary output directory changed while publishing")
    except OSError as error:
        fail(f"cannot publish summary output: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)
    observed = stable_regular_bytes(
        requested, "published summary", maximum=MAX_SUMMARY_BYTES
    )
    if observed != raw:
        fail("published summary bytes differ")


def render_record(record: Any) -> str:
    return PREFIXES[record.family] + json.dumps(
        record.value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def synthetic_transcript(
    oracle: types.ModuleType,
    source_commit: str,
    source_tree: str,
    challenge: str,
) -> bytes:
    qemu_uart, _ = oracle.synthetic_fixture()
    qemu_meta, qemu_records, qemu_end, qemu_pass = oracle.parse_uart(qemu_uart)
    run_id = expected_run_id(source_commit, source_tree, challenge)
    meta = copy.deepcopy(qemu_meta.value)
    meta["schema"] = SCHEMAS["META"]
    meta["suite_id"] = SUITE_ID
    meta["source_commit"] = source_commit
    meta["source_tree"] = source_tree
    meta["challenge"] = challenge
    meta["run_id"] = run_id
    meta["contract_sha256"] = EXPECTED_CONTRACT_SHA256
    del meta["manifest_sha256"]
    meta["transcript_schema_sha256"] = EXPECTED_TRANSCRIPT_SCHEMA_SHA256
    meta.update(EXPECTED_PHYSICAL_METADATA)

    records: list[Any] = []
    for original in qemu_records:
        value = copy.deepcopy(original.value)
        value["schema"] = SCHEMAS[original.family]
        value["run_id"] = run_id
        records.append(oracle.Record(original.family, value, 0))
    terminal_records = []
    for original in (qemu_end, qemu_pass):
        value = copy.deepcopy(original.value)
        value["schema"] = SCHEMAS[original.family]
        value["run_id"] = run_id
        value["challenge"] = challenge
        terminal_records.append(oracle.Record(original.family, value, 0))
    lines = ["VibeOS physical-contract synthetic preamble"]
    lines.append(PREFIXES["META"] + json.dumps(meta, separators=(",", ":")))
    lines.extend(render_record(record) for record in records)
    lines.extend(render_record(record) for record in terminal_records)
    return ("\n".join(lines) + "\n").encode("utf-8")


def update_json_line(
    raw: bytes,
    family: str,
    occurrence: int,
    update: Callable[[dict[str, object]], None],
) -> bytes:
    lines = raw.decode("utf-8").splitlines()
    positions = [
        index for index, line in enumerate(lines) if line.startswith(PREFIXES[family])
    ]
    position = positions[occurrence]
    payload = lines[position][len(PREFIXES[family]) :]
    value = strict_json(payload.encode("utf-8"), f"selftest {family}")
    update(value)
    lines[position] = PREFIXES[family] + json.dumps(
        value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def expect_rejection(label: str, action: Callable[[], object]) -> None:
    try:
        action()
    except VerificationError:
        return
    fail(f"selftest mutation was accepted: {label}")


def selftest() -> int:
    _, _, oracle = check_contract()
    require(
        expected_run_id(
            SELFTEST_SOURCE_COMMIT, SELFTEST_SOURCE_TREE, SELFTEST_CHALLENGE
        )
        == SELFTEST_RUN_ID,
        "selftest run ID golden differs",
    )
    raw = synthetic_transcript(
        oracle, SELFTEST_SOURCE_COMMIT, SELFTEST_SOURCE_TREE, SELFTEST_CHALLENGE
    )
    verified = verify_uart_bytes(
        raw,
        SELFTEST_SOURCE_COMMIT,
        SELFTEST_SOURCE_TREE,
        SELFTEST_CHALLENGE,
        allow_selftest=True,
    )
    require(len(verified.records) == EXPECTED_RECORDS, "selftest record count differs")
    require(
        verified.semantic_sha256 == SELFTEST_SEMANTIC_SHA256,
        "selftest semantic digest differs",
    )
    deterministic = rendered_summary(summary_value(verified, synthetic_test_only=True))
    require(
        deterministic
        == rendered_summary(summary_value(verified, synthetic_test_only=True)),
        "selftest summary is not deterministic",
    )
    expect_rejection(
        "reserved-selftest-normal-mode",
        lambda: verify_uart_bytes(
            raw, SELFTEST_SOURCE_COMMIT, SELFTEST_SOURCE_TREE, SELFTEST_CHALLENGE
        ),
    )

    mutations: list[tuple[str, bytes, str, str, str]] = []

    def add(name: str, mutated: bytes) -> None:
        mutations.append(
            (
                name,
                mutated,
                SELFTEST_SOURCE_COMMIT,
                SELFTEST_SOURCE_TREE,
                SELFTEST_CHALLENGE,
            )
        )

    add("missing-final-newline", raw[:-1])
    add("invalid-utf8", b"\xff" + raw)
    add("carriage-return", raw.replace(b"\n", b"\r\n", 1))
    add("non-lf-line-separator", raw.replace(b"\n", "\u2028".encode("utf-8"), 1))
    add("fatal-preamble", b"panic\n" + raw)
    add("c84-marker", b"VIBE_WASM_AOT_META {}\n" + raw)
    add("non-column-family", b"x" + PREFIXES["META"].encode() + b"{}\n" + raw)
    add("foreign-qemu-family", b"VIBE_C88_F5_META {}\n" + raw)
    add("foreign-readiness-family", b"VIBE_C88_F5_DUO_META {}\n" + raw)
    add(
        "explicit-fail",
        raw.replace(PREFIXES["META"].encode(), PREFIXES["FAIL"].encode(), 1),
    )
    add(
        "unknown-family",
        raw.replace(
            PREFIXES["META"].encode(), (FAMILY_PREFIX + "UNKNOWN ").encode(), 1
        ),
    )
    add("post-pass-bytes", raw + b"unexpected\n")
    lines = raw.decode("utf-8").splitlines()
    meta_index = next(
        i for i, line in enumerate(lines) if line.startswith(PREFIXES["META"])
    )
    add(
        "ambient-after-meta",
        (
            "\n".join(lines[: meta_index + 1] + ["noise"] + lines[meta_index + 1 :])
            + "\n"
        ).encode(),
    )
    add(
        "missing-meta",
        ("\n".join(lines[:meta_index] + lines[meta_index + 1 :]) + "\n").encode(),
    )
    add(
        "duplicate-meta",
        (
            "\n".join(
                lines[: meta_index + 1] + [lines[meta_index]] + lines[meta_index + 1 :]
            )
            + "\n"
        ).encode(),
    )
    add(
        "missing-end",
        (
            "\n".join(line for line in lines if not line.startswith(PREFIXES["END"]))
            + "\n"
        ).encode(),
    )
    add(
        "missing-pass",
        (
            "\n".join(line for line in lines if not line.startswith(PREFIXES["PASS"]))
            + "\n"
        ).encode(),
    )
    core_index = next(
        i for i, line in enumerate(lines) if line.startswith(PREFIXES["CORE_CASE"])
    )
    f3_index = next(
        i for i, line in enumerate(lines) if line.startswith(PREFIXES["F3_CASE"])
    )
    reordered = list(lines)
    reordered[core_index], reordered[f3_index] = (
        reordered[f3_index],
        reordered[core_index],
    )
    add("family-reorder", ("\n".join(reordered) + "\n").encode())
    add(
        "missing-data",
        ("\n".join(lines[:core_index] + lines[core_index + 1 :]) + "\n").encode(),
    )
    add(
        "duplicate-data",
        (
            "\n".join(
                lines[: core_index + 1] + [lines[core_index]] + lines[core_index + 1 :]
            )
            + "\n"
        ).encode(),
    )
    add(
        "meta-extra-key",
        update_json_line(raw, "META", 0, lambda value: value.update(extra=False)),
    )
    add(
        "meta-version-bool",
        update_json_line(raw, "META", 0, lambda value: value.update(version=True)),
    )
    add(
        "wrong-suite",
        update_json_line(
            raw, "META", 0, lambda value: value.update(suite_id=READINESS_SUITE_ID)
        ),
    )
    add(
        "wrong-contract",
        update_json_line(
            raw, "META", 0, lambda value: value.update(contract_sha256="1" * 64)
        ),
    )
    add(
        "wrong-schema-hash",
        update_json_line(
            raw,
            "META",
            0,
            lambda value: value.update(transcript_schema_sha256="2" * 64),
        ),
    )
    add(
        "claimed-provenance",
        update_json_line(
            raw, "META", 0, lambda value: value.update(physical_provenance="claimed")
        ),
    )
    add(
        "readiness-arm",
        update_json_line(
            raw, "META", 0, lambda value: value.update(arm_marker=READINESS_ARM_MARKER)
        ),
    )
    add(
        "unarmed",
        update_json_line(
            raw, "META", 0, lambda value: value.update(execution_armed=False)
        ),
    )
    add(
        "physical-evidence",
        update_json_line(
            raw, "META", 0, lambda value: value.update(physical_evidence_present=True)
        ),
    )
    add(
        "f5-complete",
        update_json_line(raw, "META", 0, lambda value: value.update(f5_complete=True)),
    )
    add(
        "wrong-run-id",
        update_json_line(raw, "META", 0, lambda value: value.update(run_id="4" * 64)),
    )
    add(
        "wrong-data-schema",
        update_json_line(
            raw,
            "CORE_CASE",
            0,
            lambda value: value.update(schema=oracle.SCHEMAS["CORE_CASE"]),
        ),
    )
    add(
        "wrong-sequence",
        update_json_line(raw, "CORE_CASE", 0, lambda value: value.update(sequence=1)),
    )
    add(
        "wrong-core-result",
        update_json_line(
            raw, "CORE_CASE", 0, lambda value: value.update(actual="0000000000000000")
        ),
    )
    add(
        "wrong-f3-result",
        update_json_line(
            raw, "F3_CASE", 0, lambda value: value.update(actual_f32="ffffffff")
        ),
    )
    add(
        "wrong-f4-result",
        update_json_line(
            raw,
            "F4_VECTOR",
            0,
            lambda value: value.update(actual_f64="ffffffffffffffff"),
        ),
    )
    add(
        "wrong-fuel",
        update_json_line(raw, "FUEL", 0, lambda value: value.update(delta=100)),
    )
    add(
        "wrong-lifecycle",
        update_json_line(
            raw, "LIFECYCLE", 0, lambda value: value.update(state="running")
        ),
    )
    add(
        "wrong-end-semantic",
        update_json_line(
            raw, "END", 0, lambda value: value.update(semantic_sha256="5" * 64)
        ),
    )
    add(
        "wrong-pass-count",
        update_json_line(raw, "PASS", 0, lambda value: value.update(records=1_175)),
    )
    meta_line = lines[meta_index]
    duplicate_payload = meta_line[len(PREFIXES["META"]) :].replace(
        "{", '{"schema":"duplicate",', 1
    )
    duplicate_lines = list(lines)
    duplicate_lines[meta_index] = PREFIXES["META"] + duplicate_payload
    add("duplicate-json-member", ("\n".join(duplicate_lines) + "\n").encode())
    float_lines = list(lines)
    float_lines[meta_index] = meta_line.replace('"version":1', '"version":1.0', 1)
    add("json-float", ("\n".join(float_lines) + "\n").encode())
    huge_integer_lines = list(lines)
    huge_integer_lines[meta_index] = meta_line.replace(
        '"version":1', '"version":' + "9" * 5_000, 1
    )
    add("oversized-json-integer", ("\n".join(huge_integer_lines) + "\n").encode())

    for name, mutated, source_commit, source_tree, challenge in mutations:
        parameters = (mutated, source_commit, source_tree, challenge)
        expect_rejection(
            name,
            lambda parameters=parameters: verify_uart_bytes(
                *parameters, allow_selftest=True
            ),
        )

    binding_mutations = (
        (
            "readiness-source",
            READINESS_SOURCE_COMMIT,
            SELFTEST_SOURCE_TREE,
            SELFTEST_CHALLENGE,
        ),
        (
            "readiness-tree",
            SELFTEST_SOURCE_COMMIT,
            READINESS_SOURCE_TREE,
            SELFTEST_CHALLENGE,
        ),
        (
            "readiness-challenge",
            SELFTEST_SOURCE_COMMIT,
            SELFTEST_SOURCE_TREE,
            READINESS_CHALLENGE,
        ),
        ("zero-source", "0" * 40, SELFTEST_SOURCE_TREE, SELFTEST_CHALLENGE),
        ("uppercase-source", "A" * 40, SELFTEST_SOURCE_TREE, SELFTEST_CHALLENGE),
    )
    for name, source_commit, source_tree, challenge in binding_mutations:
        parameters = (raw, source_commit, source_tree, challenge)
        expect_rejection(
            name,
            lambda parameters=parameters: verify_uart_bytes(
                *parameters, allow_selftest=True
            ),
        )

    filesystem_rejections = 0
    temporary_root = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="c88-f5-physical-", dir=temporary_root
    ) as temporary:
        root = pathlib.Path(temporary)
        uart_path = root / "uart.log"
        uart_path.write_bytes(raw)
        require(
            stable_regular_bytes(uart_path, "selftest UART", maximum=MAX_UART_BYTES)
            == raw,
            "selftest stable read differs",
        )
        symlink_path = root / "uart-link.log"
        symlink_path.symlink_to(uart_path.name)
        expect_rejection(
            "symlink-input",
            lambda: stable_regular_bytes(
                symlink_path, "selftest symlink", maximum=MAX_UART_BYTES
            ),
        )
        filesystem_rejections += 1
        fifo_path = root / "uart.fifo"
        os.mkfifo(fifo_path)
        expect_rejection(
            "fifo-input",
            lambda: stable_regular_bytes(
                fifo_path, "selftest FIFO", maximum=MAX_UART_BYTES
            ),
        )
        filesystem_rejections += 1
        hardlink_path = root / "uart-hardlink.log"
        os.link(uart_path, hardlink_path)
        expect_rejection(
            "hardlink-input",
            lambda: stable_regular_bytes(
                hardlink_path, "selftest hardlink", maximum=MAX_UART_BYTES
            ),
        )
        filesystem_rejections += 1
        hardlink_path.unlink()
        summary_path = root / "summary.json"
        write_summary_no_clobber(summary_path, deterministic)
        require(summary_path.read_bytes() == deterministic, "published summary differs")
        expect_rejection(
            "summary-no-clobber",
            lambda: write_summary_no_clobber(summary_path, deterministic),
        )
        filesystem_rejections += 1

    rejected = 1 + len(mutations) + len(binding_mutations) + filesystem_rejections
    print(
        "verify-c88-f5-duo-physical-transcript.py selftest: PASS "
        f"({rejected} mutations rejected) records={EXPECTED_RECORDS} "
        f"selftest_semantic_sha256={SELFTEST_SEMANTIC_SHA256} "
        f"required_physical_semantic_sha256={EXPECTED_SEMANTIC_SHA256} "
        "physical_provenance=not-claimed f5_complete=false"
    )
    return rejected


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    mode = value.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-contract", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--uart", type=pathlib.Path)
    value.add_argument("--source-commit")
    value.add_argument("--source-tree")
    value.add_argument("--challenge")
    value.add_argument("--summary-output", type=pathlib.Path)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.check_contract:
            require(
                arguments.source_commit is None
                and arguments.source_tree is None
                and arguments.challenge is None
                and arguments.summary_output is None,
                "--check-contract accepts no transcript arguments",
            )
            check_contract()
            print(
                "verify-c88-f5-duo-physical-transcript.py: PASS "
                f"contract_sha256={EXPECTED_CONTRACT_SHA256} "
                f"contract_bytes={EXPECTED_CONTRACT_BYTES} "
                f"transcript_schema_sha256={EXPECTED_TRANSCRIPT_SCHEMA_SHA256} "
                f"transcript_schema_bytes={EXPECTED_TRANSCRIPT_SCHEMA_BYTES} "
                f"oracle_sha256={EXPECTED_ORACLE_SHA256} "
                "stage=host-verifier-only physical_provenance=not-claimed "
                "producer_present=false f5_complete=false"
            )
            return 0
        if arguments.selftest:
            require(
                arguments.source_commit is None
                and arguments.source_tree is None
                and arguments.challenge is None
                and arguments.summary_output is None,
                "--selftest accepts no transcript arguments",
            )
            selftest()
            return 0
        require(arguments.uart is not None, "normal mode requires --uart")
        require(
            arguments.source_commit is not None, "normal mode requires --source-commit"
        )
        require(arguments.source_tree is not None, "normal mode requires --source-tree")
        require(arguments.challenge is not None, "normal mode requires --challenge")
        if arguments.summary_output is not None:
            uart_absolute = pathlib.Path(os.path.abspath(os.fspath(arguments.uart)))
            summary_absolute = pathlib.Path(
                os.path.abspath(os.fspath(arguments.summary_output))
            )
            require(
                uart_absolute != summary_absolute,
                "summary output must not alias the UART input",
            )
        uart = stable_regular_bytes(
            arguments.uart, "UART transcript", maximum=MAX_UART_BYTES
        )
        verified = verify_uart_bytes(
            uart,
            arguments.source_commit,
            arguments.source_tree,
            arguments.challenge,
        )
        summary = summary_value(verified, synthetic_test_only=False)
        if arguments.summary_output is not None:
            write_summary_no_clobber(
                arguments.summary_output, rendered_summary(summary)
            )
        print(
            "verify-c88-f5-duo-physical-transcript.py: PASS "
            f"records={len(verified.records)} "
            f"semantic_sha256={verified.semantic_sha256} "
            f"uart_sha256={verified.uart_sha256} uart_bytes={verified.uart_bytes} "
            "physical_provenance=not-claimed cold_boot_verified=false "
            "capture_verified=false terminal_quiescence_verified=false "
            "f5_complete=false"
        )
        return 0
    except VerificationError as error:
        print(
            f"verify-c88-f5-duo-physical-transcript.py: FAIL ({error})",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
