#!/usr/bin/env python3
"""Independently verify the frozen C8.4 AOT-decision preparation contract.

This host-only verifier uses only Python's standard library.  It does not run
the guest or compile WAT. It binds the checked-in contract to the executable
image policy and exact OpenSSH product fixture, checks the closed manifest and
schema, and semantically verifies one raw transcript claiming a physical cold
boot. It does not attest the transcript's hardware provenance or the cold-boot
operation. A later evidence verifier must aggregate three independently
verified boots and prove the C8.3 precondition before deriving any AOT decision.
"""

from __future__ import annotations

import argparse
import ast
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
from dataclasses import dataclass
from typing import Any, Callable


SCRIPT_PATH = pathlib.Path(__file__).resolve()
ROOT = SCRIPT_PATH.parent.parent
MANIFEST_PATH = ROOT / "benchmarks/wasm-aot-decision/workloads-v1.json"
SCHEMA_PATH = ROOT / "benchmarks/wasm-aot-decision/schema-v1.json"
BUILD_PATH = ROOT / "policy/image/build.rs"
POLICY_PATH = ROOT / "policy/image/src/lib.rs"
PROFILE_PATH = ROOT / "component-format/src/lib.rs"
WAT_PATH = ROOT / "policy/image/artifacts/c53-stream-filter.component.wat"
OPENSSH_PEER_PATH = ROOT / "scripts/openssh-peer.py"
VSH_ENGINE_PATH = ROOT / "components/vsh/src/engine.rs"
COMPONENT_HOST_STREAM_PATH = ROOT / "services/component-host/src/stream.rs"
KERNEL_COMPONENT_INSTANCES_PATH = ROOT / "kernel/src/component_instances.rs"
VERIFIER_INPUT_PATHS = (
    MANIFEST_PATH,
    SCHEMA_PATH,
    BUILD_PATH,
    POLICY_PATH,
    PROFILE_PATH,
    WAT_PATH,
    OPENSSH_PEER_PATH,
    VSH_ENGINE_PATH,
    COMPONENT_HOST_STREAM_PATH,
    KERNEL_COMPONENT_INSTANCES_PATH,
    SCRIPT_PATH,
)

# Filled from the reviewed files below.  Byte identity is intentionally
# independent of JSON parsing and makes formatting changes review-visible.
EXPECTED_MANIFEST_SHA256 = "87026895f2207d85a04f5c04f11420530f1c8f922391f71915f173b18dcfd9d8"
EXPECTED_SCHEMA_SHA256 = "b608aa3de46aac1a73fb321babdcd4ad18ec43c60b54760f53b9e5e8d317bf3a"
EXPECTED_WAT_SHA256 = "6db36b58350c4de22077fba4dd9dd1166f0808e2adc8488ba086d91c6f659cc1"
EXPECTED_COMPONENT_SHA256 = "180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72"
EXPECTED_COMPONENT_BYTES = 2012
EXPECTED_BUILD_SOURCE_SHA256 = "ca0d4f100d136d26c0ac1e1beeb0919b12c8f8a9e2345d15b6284b041e6ed74e"
EXPECTED_POLICY_SOURCE_SHA256 = "d4912916f8407ddcb4ae7914186f6d567468896c72a39da0ddbbe957d1a7b2e0"
EXPECTED_OPENSSH_SOURCE_SHA256 = "00d5002a8f2725c275995b1eff5d469f1d1eac1741b1eaef3f3623c3c746ac8c"
EXPECTED_WIT_SHA256 = "61710f784d4814d87a9a5542edfb2e43bc2844fc04df679fd19490932038039a"
EXPECTED_KERNEL_STREAM_CHARGE_SCOPES_SHA256 = (
    "f2c3b2f539f450d556e6c243200a512f1230050add6c9ab25d8418bc384c642b"
)
EXPECTED_KERNEL_COMPONENT_INSTANCES_SOURCE_SHA256 = (
    "2f0b45e25a90922a2f36f43c1df9f8fe8ca6bcba62f0954e0671367348693c8f"
)

INPUT_LENGTH = 12 * 1024 + 37
INPUT_GENERATOR = "bytes((index * 17 + 3) % 251 for index in range(12 * 1024 + 37))"
OUTPUT_TRANSFORM = "bytes(byte ^ 0x20 for byte in CASE_FILTER_INPUT)"
INPUT_BYTES = bytes((index * 17 + 3) % 251 for index in range(INPUT_LENGTH))
OUTPUT_BYTES = bytes(byte ^ 0x20 for byte in INPUT_BYTES)
INPUT_SHA256 = hashlib.sha256(INPUT_BYTES).hexdigest()
OUTPUT_SHA256 = hashlib.sha256(OUTPUT_BYTES).hexdigest()

TOP_KEYS = {
    "schema",
    "version",
    "suite_id",
    "workload_revision",
    "scope",
    "fixture",
    "platforms",
    "sampling",
    "budget",
    "phases",
    "transcript",
    "decision_rule",
    "publication_gates",
}
PHASE_IDS = (
    "validation",
    "instantiation",
    "abi",
    "interpretation",
    "host",
    "wait",
    "cleanup",
)
PHASE_BOUNDARIES = (
    "after authenticated SessionExec(case-filter) acceptance through exact credential, policy, manifest, image-root, and plan revalidation, including validator/compiler work and excluding Core/adapter instruction execution",
    "owner, arena, CSpace, task envelope, ProfileEngine, SynchronousComponent, ResourceTable, and typed-call construction",
    "Canonical lower/lift, realloc, resource-token, return-pointer, and value encoding/decoding",
    "only wasmi Core or adapter instruction execution; validation and compilation are excluded",
    "runnable stream read/write/close and SSH pump/protocol transport work",
    "yield, HostPending, backpressure, scheduler, and network waiting",
    "after guest Ready or trap through terminal/stream finalization, CSpace/registry/arena/owner reclaim, VSH reaper acknowledgement, and stdout drain",
)
DECISION_RULE = {
    "preconditions": "C8.3 is complete and every C8.4 publication gate passes on the eligible physical-Duo dataset",
    "budget_miss": "p95(total_ticks) > 2500000",
    "interpretation_attribution": "p95(total_ticks - phase_ticks.interpretation) <= 2500000",
    "candidate_outcome": "only when both predicates are true, AOT becomes eligible for C8.5 design review",
    "otherwise": "AOT is not justified for ssh-case-filter-12k-v1",
    "authorization": "no outcome here authorizes JIT, RWX, external native bytes, or bypass of authoritative component bytes, profile, WIT, CSpace, and admission policy",
}
PUBLICATION_GATES = {
    "precondition": "C8.3 fixed-QEMU and three-cold-boot physical-Duo publication is complete",
    "identity": "source commit, manifest, schema, artifact, WAT, input, output, command, world, entrypoint, image policy, and platform envelope match exactly",
    "completeness": "three independently verified single-cold-boot raw transcripts each contain one META, exactly three warmups then twenty-one retained samples, and one END; host evidence binds distinct boot indexes 0 through 2",
    "correctness": "every sample exits zero, emits the exact 12325-byte output hash, emits empty stderr, consumes 1 through 500000 fuel, and reports positive poll quanta",
    "successful_samples_only": "timed-out, trapped, failed, truncated, or otherwise non-successful attempts are diagnostic records outside the formal dataset and can never authorize AOT",
    "phase_partition": "intervals are non-empty, ordered, gap-free, non-overlapping, and labeled with exactly one of seven phases; adjacent intervals have different phases; total_ticks equals both the response interval and the sum of phase_ticks",
    "interval_capacity": "every formal sample pins interval_capacity to 65536, requires interval_count == len(intervals), and sets intervals_complete true; interval overflow or truncation is diagnostic-only and cannot enter the decision population",
    "duo_stability": "within each boot retained p95(total_ticks) divided by p50(total_ticks) is at most 1.50",
    "qemu_exclusion": "QEMU records are integration-only and absent from every budget and attribution statistic",
    "preparation_only": "this manifest contains no measurement result and does not complete C8.3 or authorize AOT",
}
PROFILE_IDENTITY = {
    "artifact_abi": 1,
    "component_profile": 1,
    "core_profile": 1,
    "runtime_abi": 1,
    "core_revision": "webassembly-core-2.0-integer-v1",
    "component_revision": "wasmparser-component-model-0.255.0",
    "canonical_abi_revision": "component-model-0.255.0-sync",
    "wasm_tools_revision": "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380",
    "wasi_revision": "wasi-not-selected-sync",
    "canonical_features": 7,
    "stage": "executable",
}
TRANSCRIPT_CONTRACT = {
    "framing": {
        "raw_scope": "one independently booted physical Milk-V Duo session",
        "required_raw_transcripts": 3,
        "meta_records_per_raw": 1,
        "sample_records_per_raw": 24,
        "end_records_per_raw": 1,
        "warmups_per_raw": 3,
        "retained_per_raw": 21,
        "maximum_raw_bytes": 268_435_456,
        "record_order": "META, SAMPLE sequence 0 through 23, END",
        "boot_index_binding": "host evidence assigns boot_index 0 through 2 after independent raw verification; target records contain no boot index",
        "prefixes": {
            "meta": "VIBE_WASM_AOT_META ",
            "sample": "VIBE_WASM_AOT_SAMPLE ",
            "end": "VIBE_WASM_AOT_END ",
        },
    },
    "run_id": {
        "domain": "vibeos.c84.aot-decision.run-id.v1",
        "algorithm": "sha256",
        "encoding": "domain followed by fields as NUL-separated ASCII values with no trailing NUL",
        "fields": [
            "source_commit",
            "challenge",
            "artifact_sha256",
            "input_sha256",
            "output_sha256",
            "manifest_sha256",
            "transcript_schema_sha256",
        ],
        "meaning": "shared campaign identity only; it does not prove a cold boot",
    },
    "accumulator": {
        "width_bits": 64,
        "initial": 0,
        "update": "acc = rotl64(acc, 7).wrapping_add(word)",
        "sample_domain_word": 4_843_678_931_419_484_236,
        "interval_domain_word": 4_843_678_888_688_374_358,
        "sample_prefix_words": [
            "sample_domain_word",
            "sequence",
            "sample_index",
            "warmup(0|1)",
            "total_ticks",
            "phase_ticks in canonical phase order",
            "interval_capacity",
            "interval_count",
            "intervals_complete(0|1)",
        ],
        "interval_words": [
            "interval_domain_word",
            "sequence",
            "phase_code",
            "start_offset_ticks",
            "end_offset_ticks",
        ],
        "sample_suffix_words": [
            "read_chunks",
            "write_chunks",
            "fuel_consumed",
            "poll_quanta",
            "terminal_code(success=1)",
            "logical_live_after",
            "timed_out(0|1)",
            "timeout_phase_code(none=0)",
            "exit_status",
            "stdout_bytes",
            "stdout_sha256 as four big-endian u64 words",
            "stderr_bytes",
        ],
        "phase_codes": {
            "validation": 1,
            "instantiation": 2,
            "abi": 3,
            "interpretation": 4,
            "host": 5,
            "wait": 6,
            "cleanup": 7,
        },
        "purpose": "ordered truncation and corruption check, not authentication",
    },
}
U64_MAX = (1 << 64) - 1
HEX_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
META_PREFIX = "VIBE_WASM_AOT_META "
SAMPLE_PREFIX = "VIBE_WASM_AOT_SAMPLE "
END_PREFIX = "VIBE_WASM_AOT_END "
SAMPLES_PER_BOOT = 24
WARMUPS_PER_BOOT = 3
RETAINED_PER_BOOT = 21
INTERVAL_CAPACITY = 65_536
MAX_RAW_TRANSCRIPT_BYTES = 268_435_456
MAX_BOOT_SUMMARY_BYTES = 1_048_576
MAX_CONTRACT_FILE_BYTES = 1_048_576
SAMPLE_DOMAIN_WORD = 4_843_678_931_419_484_236
INTERVAL_DOMAIN_WORD = 4_843_678_888_688_374_358
PHASE_CODES = {phase: index + 1 for index, phase in enumerate(PHASE_IDS)}
FAILURE_MARKERS = (
    "[!] fatal",
    "[!] panic",
    "panicked at",
    "WASM_C84_PROFILE_SLOT FAIL",
    "WASM_C84_CORE_POLL FAIL",
    "WASM_C84_PROFILE_IRQ_OVERLAY FAIL",
    "WASM_C84_PROFILE_CHILD_DELEGATION FAIL",
)
META_KEYS = {
    "schema",
    "version",
    "suite_id",
    "workload_revision",
    "source_commit",
    "challenge",
    "run_id",
    "manifest_sha256",
    "transcript_schema_sha256",
    "platform",
    "decision_eligible",
    "clock",
    "timebase_hz",
    "hart_id",
    "hart_count",
    "transcript_scope",
    "required_cold_boots",
    "samples_per_boot",
    "warmup_per_boot",
    "retained_per_boot",
    "workload_id",
    "artifact_sha256",
    "artifact_bytes",
    "input_sha256",
    "input_bytes",
    "output_sha256",
    "output_bytes",
    "budget_ticks",
}
SAMPLE_KEYS = {
    "schema",
    "version",
    "run_id",
    "challenge",
    "sequence",
    "sample_index",
    "warmup",
    "workload_id",
    "total_ticks",
    "phase_ticks",
    "interval_capacity",
    "interval_count",
    "intervals_complete",
    "intervals",
    "read_chunks",
    "write_chunks",
    "fuel_consumed",
    "poll_quanta",
    "terminal",
    "logical_live_after",
    "timed_out",
    "timeout_phase",
    "exit_status",
    "stdout_bytes",
    "stdout_sha256",
    "stderr_bytes",
}
INTERVAL_KEYS = {"sequence", "phase", "start_offset_ticks", "end_offset_ticks"}
END_KEYS = {
    "schema",
    "version",
    "run_id",
    "challenge",
    "samples",
    "warmups",
    "retained",
    "accumulator",
}


class VerificationError(RuntimeError):
    """Fail-closed contract validation error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256_file(path: pathlib.Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise VerificationError(f"cannot read {path}: {error}") from error


def reviewed_source_identity(source: str, expected_sha256: str, label: str) -> None:
    require(
        hashlib.sha256(source.encode("utf-8")).hexdigest() == expected_sha256,
        f"{label} reviewed source identity differs",
    )


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        require(key not in value, f"duplicate JSON member {key!r}")
        value[key] = child
    return value


def strict_json_bytes(raw: bytes, label: str) -> Any:
    def reject_number(_token: str) -> Any:
        raise VerificationError(f"{label} contains an unsupported JSON number")

    def parse_integer(token: str) -> int:
        digits = token[1:] if token.startswith("-") else token
        require(len(digits) <= 20, f"{label} contains an oversized JSON integer")
        return int(token, 10)

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_members,
            parse_int=parse_integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise VerificationError(f"invalid strict UTF-8 {label} JSON: {error}") from error


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    require(not missing and not extra, f"{label} keys differ: missing={missing}, extra={extra}")
    return value


def exact_literal(value: Any, expected: Any, label: str) -> None:
    """Require equal values without Python's bool-is-an-int coercion."""
    require(type(value) is type(expected), f"{label} has the wrong type")
    if type(expected) is dict:
        exact_keys(value, set(expected), label)
        for key, child in expected.items():
            exact_literal(value[key], child, f"{label}.{key}")
    elif type(expected) is list:
        require(len(value) == len(expected), f"{label} length differs")
        for index, child in enumerate(expected):
            exact_literal(value[index], child, f"{label}[{index}]")
    else:
        require(value == expected, f"{label} differs")


def exact_int(value: Any, label: str, *, minimum: int = 0, maximum: int = U64_MAX) -> int:
    require(type(value) is int, f"{label} must be an integer, not {type(value).__name__}")
    require(minimum <= value <= maximum, f"{label} is outside [{minimum}, {maximum}]")
    return value


def exact_bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be a boolean")
    return value


def exact_text(value: Any, label: str, *, maximum: int = 4096) -> str:
    require(type(value) is str, f"{label} must be a string")
    require(0 < len(value.encode("utf-8")) <= maximum, f"{label} is empty or too long")
    require("\0" not in value, f"{label} contains NUL")
    return value


def exact_sha256(value: Any, label: str) -> str:
    require(
        type(value) is str and HEX_SHA256.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-256",
    )
    require(value != "0" * 64, f"{label} uses the all-zero sentinel")
    return value


def exact_commit(value: Any, label: str) -> str:
    require(
        type(value) is str and HEX_COMMIT.fullmatch(value) is not None,
        f"{label} must be a lowercase 40-hex commit",
    )
    require(value != "0" * 40, f"{label} uses the all-zero sentinel")
    return value


def exact_repo_path(value: Any, expected: str, label: str) -> pathlib.Path:
    text = exact_text(value, label)
    relative = pathlib.PurePosixPath(text)
    require(not relative.is_absolute(), f"{label} must be repository-relative")
    require(".." not in relative.parts and "." not in relative.parts, f"{label} escapes the repository")
    require(text == expected, f"{label} differs")
    path = ROOT.joinpath(*relative.parts)
    require(path.is_file(), f"{label} does not name a file")
    return path


def parse_rust_product(expression: str, label: str) -> int:
    require(
        re.fullmatch(r"[0-9][0-9_]*(?:\s*\*\s*[0-9][0-9_]*)*", expression.strip())
        is not None,
        f"{label} is not a closed integer product",
    )
    value = 1
    for factor in expression.split("*"):
        value *= int(factor.strip().replace("_", ""))
        require(value <= U64_MAX, f"{label} overflows u64")
    return value


def rust_struct_block(source: str, declaration: str, label: str) -> str:
    start = source.find(declaration)
    require(start >= 0, f"missing {label} declaration")
    open_brace = source.find("{", start + len(declaration))
    require(open_brace >= 0, f"missing {label} body")
    depth = 0
    for position in range(open_brace, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : position]
    raise VerificationError(f"unterminated {label} body")


def rust_field(block: str, name: str, pattern: str, label: str) -> str:
    matches = re.findall(rf"(?m)^\s*{re.escape(name)}:\s*({pattern})\s*,\s*$", block)
    require(len(matches) == 1, f"{label}.{name} must occur exactly once")
    return matches[0]


@dataclass(frozen=True)
class ImageIdentity:
    sha256: str
    command: str
    profile: str
    world: str
    entrypoint: str
    min_args: int
    max_args: int
    stdin: str
    stdout: str
    stderr: str
    memory_bytes: int
    total_fuel: int
    poll_quantum: int
    resources: int


@dataclass(frozen=True)
class VerifiedBootTranscript:
    metadata: dict[str, Any]
    samples: list[dict[str, Any]]
    ending: dict[str, Any]
    raw_sha256: str
    raw_bytes: int


@dataclass(frozen=True)
class SummaryOutputTarget:
    directory_path: pathlib.Path
    basename: str
    directory_fd: int
    directory_device: int
    directory_inode: int
    overwrite: bool


def image_identity() -> ImageIdentity:
    try:
        build = BUILD_PATH.read_text(encoding="utf-8")
        policy = POLICY_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise VerificationError(f"cannot load image policy source: {error}") from error
    reviewed_source_identity(build, EXPECTED_BUILD_SOURCE_SHA256, "build.rs")
    reviewed_source_identity(policy, EXPECTED_POLICY_SOURCE_SHA256, "policy/image/src/lib.rs")
    build_flow = (
        'const SOURCE: &str = include_str!("artifacts/c53-stream-filter.component.wat");',
        'let bytes = wat::parse_str(SOURCE).expect("pinned Component WAT must parse");',
        "let observed: [u8; 32] = Sha256::digest(&bytes).into();",
        "observed, EXPECTED_SHA256,",
        'fs::write(output.join("c53-stream-filter.component.wasm"), bytes)',
        'output.join("c53-stream-filter.sha256.rs"),',
        'format!("{EXPECTED_SHA256:?}"),',
    )
    for statement in build_flow:
        require(statement in build, f"build.rs flow differs at {statement!r}")
    require(
        build.count('"c53-stream-filter.component.wasm"') == 1
        and build.count('"c53-stream-filter.sha256.rs"') == 1,
        "build.rs output identity is ambiguous",
    )
    policy_bindings = (
        'const C53_STREAM_FILTER_BYTES: &[u8] = include_bytes!(concat!(',
        '"/c53-stream-filter.component.wasm"',
        "const C53_STREAM_FILTER_SHA256: [u8; 32] =",
        'include!(concat!(env!("OUT_DIR"), "/c53-stream-filter.sha256.rs"));',
    )
    for binding in policy_bindings:
        require(policy.count(binding) == 1, f"image policy artifact include differs at {binding!r}")

    wit_start = 'const C53_STREAM_FILTER_WIT: &str = r#"'
    start = policy.find(wit_start)
    require(start >= 0, "C53_STREAM_FILTER_WIT declaration is missing")
    start += len(wit_start)
    end = policy.find('"#;', start)
    require(end >= 0, "C53_STREAM_FILTER_WIT declaration is unterminated")
    wit = policy[start:end].encode("utf-8")
    require(hashlib.sha256(wit).hexdigest() == EXPECTED_WIT_SHA256, "C53_STREAM_FILTER_WIT differs")

    digest_match = re.search(
        r"(?ms)^const EXPECTED_SHA256:\s*\[u8;\s*32\]\s*=\s*\[(.*?)^\];",
        build,
    )
    require(digest_match is not None, "build.rs EXPECTED_SHA256 declaration differs")
    octets = re.findall(r"0x([0-9a-f]{2})", digest_match.group(1))
    require(len(octets) == 32, "build.rs EXPECTED_SHA256 must contain 32 octets")
    require(
        re.sub(r"0x[0-9a-f]{2}|[\s,]", "", digest_match.group(1)) == "",
        "build.rs EXPECTED_SHA256 contains unsupported syntax",
    )
    digest = "".join(octets)
    require(digest == EXPECTED_COMPONENT_SHA256, "build.rs EXPECTED_SHA256 identity differs")

    block = rust_struct_block(
        policy,
        "pub const SSH_EXEC_COMPONENT: ComponentCommandPin = ComponentCommandPin",
        "SSH_EXEC_COMPONENT",
    )
    require(
        rust_field(block, "artifact_bytes", r"[A-Z][A-Z0-9_]*", "SSH_EXEC_COMPONENT")
        == "C53_STREAM_FILTER_BYTES",
        "SSH_EXEC_COMPONENT artifact binding differs",
    )
    require(
        rust_field(block, "expected_sha256", r"[A-Z][A-Z0-9_]*", "SSH_EXEC_COMPONENT")
        == "C53_STREAM_FILTER_SHA256",
        "SSH_EXEC_COMPONENT digest binding differs",
    )
    require(
        rust_field(block, "profile", r"[A-Za-z0-9_:]+", "SSH_EXEC_COMPONENT")
        == "ProfileIdentity::PROFILE_1",
        "SSH_EXEC_COMPONENT profile differs",
    )
    require(
        rust_field(block, "wit_source", r"[A-Z][A-Z0-9_]*", "SSH_EXEC_COMPONENT")
        == "C53_STREAM_FILTER_WIT",
        "SSH_EXEC_COMPONENT WIT binding differs",
    )
    limits = rust_struct_block(block, "limits: ComponentInstanceLimits", "SSH_EXEC_COMPONENT limits")

    def quoted(name: str) -> str:
        raw = rust_field(block, name, r'"[^"\n]*"', "SSH_EXEC_COMPONENT")
        return raw[1:-1]

    def number(container: str, name: str, label: str) -> int:
        raw = rust_field(container, name, r"[0-9][0-9_]*(?:\s*\*\s*[0-9][0-9_]*)*", label)
        return parse_rust_product(raw, f"{label}.{name}")

    identity = ImageIdentity(
        sha256=digest,
        command=quoted("command_name"),
        profile=rust_field(block, "profile", r"[A-Za-z0-9_:]+", "SSH_EXEC_COMPONENT"),
        world=quoted("world"),
        entrypoint=quoted("entrypoint"),
        min_args=number(block, "min_args", "SSH_EXEC_COMPONENT"),
        max_args=number(block, "max_args", "SSH_EXEC_COMPONENT"),
        stdin=rust_field(block, "stdin", r"ComponentStreamMode::[A-Za-z]+", "SSH_EXEC_COMPONENT").split("::", 1)[1].lower(),
        stdout=rust_field(block, "stdout", r"ComponentStreamMode::[A-Za-z]+", "SSH_EXEC_COMPONENT").split("::", 1)[1].lower(),
        stderr=rust_field(block, "stderr", r"ComponentStreamMode::[A-Za-z]+", "SSH_EXEC_COMPONENT").split("::", 1)[1].lower(),
        memory_bytes=number(limits, "memory_bytes", "SSH_EXEC_COMPONENT.limits"),
        total_fuel=number(limits, "total_fuel", "SSH_EXEC_COMPONENT.limits"),
        poll_quantum=number(limits, "poll_quantum", "SSH_EXEC_COMPONENT.limits"),
        resources=number(limits, "resources", "SSH_EXEC_COMPONENT.limits"),
    )
    require(
        identity
        == ImageIdentity(
            sha256=EXPECTED_COMPONENT_SHA256,
            command="case-filter",
            profile="ProfileIdentity::PROFILE_1",
            world="vibe:stream/filter@1.0.0",
            entrypoint="run",
            min_args=0,
            max_args=0,
            stdin="required",
            stdout="required",
            stderr="optional",
            memory_bytes=512 * 1024,
            total_fuel=500_000,
            poll_quantum=100,
            resources=4,
        ),
        "SSH_EXEC_COMPONENT fixed identity differs",
    )
    require(sha256_file(WAT_PATH) == EXPECTED_WAT_SHA256, "case-filter WAT source identity differs")
    return identity


def profile_identity() -> dict[str, Any]:
    """Bind the profile named by SSH_EXEC_COMPONENT to its exact format source."""
    try:
        source = PROFILE_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise VerificationError(f"cannot load ProfileIdentity source: {error}") from error

    integers = {
        "ARTIFACT_ABI_VERSION": 1,
        "COMPONENT_PROFILE_VERSION": 1,
        "CORE_PROFILE_VERSION": 1,
        "RUNTIME_ABI_VERSION": 1,
    }
    for name, expected in integers.items():
        matches = re.findall(
            rf"(?m)^pub const {name}: u16 = ([0-9][0-9_]*);$",
            source,
        )
        require(len(matches) == 1, f"ProfileIdentity constant {name} differs")
        require(int(matches[0].replace("_", "")) == expected, f"{name} value differs")

    strings = {
        "CORE_SPEC_REVISION": PROFILE_IDENTITY["core_revision"],
        "COMPONENT_MODEL_REVISION": PROFILE_IDENTITY["component_revision"],
        "CANONICAL_ABI_REVISION": PROFILE_IDENTITY["canonical_abi_revision"],
        "SYNC_WASM_TOOLS_REVISION": PROFILE_IDENTITY["wasm_tools_revision"],
    }
    for name, expected in strings.items():
        matches = re.findall(
            rf'(?ms)^pub const {name}: &str =\s*"([^"\n]+)";$',
            source,
        )
        require(len(matches) == 1, f"ProfileIdentity constant {name} differs")
        require(matches[0] == expected, f"{name} value differs")

    block = rust_struct_block(
        source,
        "pub const PROFILE_1_SYNC: Self = Self",
        "ProfileIdentity::PROFILE_1_SYNC",
    )
    expected_symbols = {
        "artifact_abi": "ARTIFACT_ABI_VERSION",
        "component_profile": "COMPONENT_PROFILE_VERSION",
        "core_profile": "CORE_PROFILE_VERSION",
        "runtime_abi": "RUNTIME_ABI_VERSION",
        "core_revision": "CORE_SPEC_REVISION",
        "component_revision": "COMPONENT_MODEL_REVISION",
        "canonical_abi_revision": "CANONICAL_ABI_REVISION",
        "wasm_tools_revision": "SYNC_WASM_TOOLS_REVISION",
    }
    for field, symbol in expected_symbols.items():
        require(
            rust_field(block, field, r"[A-Z][A-Z0-9_]*", "PROFILE_1_SYNC") == symbol,
            f"PROFILE_1_SYNC.{field} binding differs",
        )
    require(
        rust_field(block, "wasi_revision", r'"[^"\n]*"', "PROFILE_1_SYNC")
        == '"wasi-not-selected-sync"',
        "PROFILE_1_SYNC.wasi_revision differs",
    )
    require(
        rust_field(block, "stage", r"ProfileStage::[A-Za-z]+", "PROFILE_1_SYNC")
        == "ProfileStage::Executable",
        "PROFILE_1_SYNC stage differs",
    )
    feature_match = re.search(
        r"(?ms)^\s*canonical_features:\s*(.*?)^\s*stage:",
        block,
    )
    require(feature_match is not None, "PROFILE_1_SYNC canonical feature expression differs")
    features = re.findall(r"CanonicalAbiFeature::([A-Za-z0-9_]+)\.bit\(\)", feature_match.group(1))
    require(features == ["Utf8", "SyncLiftLower", "Resources"], "PROFILE_1_SYNC features differ")
    require(
        re.sub(
            r"CanonicalAbiFeature::[A-Za-z0-9_]+\.bit\(\)|[\s|,]",
            "",
            feature_match.group(1),
        )
        == "",
        "PROFILE_1_SYNC feature expression contains unsupported syntax",
    )
    require(
        re.search(
            r"(?m)^\s*pub const PROFILE_1: Self = Self::PROFILE_1_SYNC;$",
            source,
        )
        is not None,
        "ProfileIdentity::PROFILE_1 alias differs",
    )
    return dict(PROFILE_IDENTITY)


def stream_chunk_limit() -> int:
    values: list[int] = []
    for path, label in (
        (VSH_ENGINE_PATH, "VSH"),
        (COMPONENT_HOST_STREAM_PATH, "component-host"),
    ):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            raise VerificationError(f"cannot load {label} stream policy: {error}") from error
        matches = re.findall(
            r"(?m)^pub const MAX_STREAM_CHUNK_BYTES: usize = ([0-9][0-9_]*);$",
            source,
        )
        require(len(matches) == 1, f"{label} MAX_STREAM_CHUNK_BYTES declaration differs")
        values.append(int(matches[0].replace("_", "")))
    require(values == [1024, 1024], "product stream chunk limits differ")
    return values[0]


def rust_code_without_comments_and_literals(source: str) -> str:
    """Blank Rust comments and literals while preserving offsets and newlines."""
    output = list(source)
    length = len(source)

    def blank(start: int, end: int) -> None:
        for index in range(start, end):
            if source[index] not in "\r\n":
                output[index] = " "

    def boundary(index: int) -> bool:
        return index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")

    def quoted_end(quote: int, label: str) -> int:
        cursor = quote + 1
        while cursor < length:
            if source[cursor] == "\\":
                cursor += 2
                continue
            if source[cursor] == '"':
                return cursor + 1
            cursor += 1
        raise VerificationError(f"unterminated Rust {label}")

    cursor = 0
    while cursor < length:
        if source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            if end < 0:
                end = length
            blank(cursor, end)
            cursor = end
            continue

        if source.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            require(depth == 0, "unterminated nested Rust block comment")
            blank(cursor, end)
            cursor = end
            continue

        raw_prefix = 0
        if boundary(cursor) and source.startswith(("br", "rb", "cr", "rc"), cursor):
            raw_prefix = 2
        elif boundary(cursor) and source[cursor] == "r":
            raw_prefix = 1
        if raw_prefix:
            quote = cursor + raw_prefix
            while quote < length and source[quote] == "#":
                quote += 1
            if quote < length and source[quote] == '"':
                hashes = source[cursor + raw_prefix : quote]
                terminator = '"' + hashes
                end = source.find(terminator, quote + 1)
                require(end >= 0, "unterminated Rust raw string literal")
                end += len(terminator)
                blank(cursor, end)
                cursor = end
                continue

        if source[cursor] == '"':
            end = quoted_end(cursor, "string literal")
            blank(cursor, end)
            cursor = end
            continue
        if boundary(cursor) and source.startswith('b"', cursor):
            end = quoted_end(cursor + 1, "byte string literal")
            blank(cursor, end)
            cursor = end
            continue
        if boundary(cursor) and source.startswith('c"', cursor):
            end = quoted_end(cursor + 1, "C string literal")
            blank(cursor, end)
            cursor = end
            continue

        char_prefix = 0
        if boundary(cursor) and source.startswith("b'", cursor):
            char_prefix = 1
        elif source[cursor] == "'":
            char_prefix = 0
        else:
            cursor += 1
            continue
        quote = cursor + char_prefix
        candidate_end = quote + 2
        if quote + 1 < length and source[quote + 1] == "\\":
            candidate_end = source.find("'", quote + 2)
            if candidate_end >= 0:
                candidate_end += 1
        elif quote + 2 < length and source[quote + 2] == "'":
            candidate_end = quote + 3
        else:
            cursor += 1
            continue
        require(candidate_end > quote, "unterminated Rust character literal")
        blank(cursor, candidate_end)
        cursor = candidate_end

    return "".join(output)


def rust_braced_scope(source: str, opening_brace: int, label: str) -> str:
    require(
        0 <= opening_brace < len(source) and source[opening_brace] == "{",
        f"{label} opening brace differs",
    )
    depth = 1
    cursor = opening_brace + 1
    while cursor < len(source) and depth:
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
        cursor += 1
    require(depth == 0, f"unterminated {label}")
    return source[opening_brace + 1 : cursor - 1]


def registry_dispatcher_impl(source: str) -> str:
    matches = list(
        re.finditer(
            r"\bimpl\s+HostDispatcher\s*<\s*ComponentAuthority\s*>\s*"
            r"for\s+RegistryStreamDispatcher\s*\{",
            source,
        )
    )
    require(len(matches) == 1, "RegistryStreamDispatcher HostDispatcher impl differs")
    return rust_braced_scope(source, matches[0].end() - 1, "RegistryStreamDispatcher impl")


def registry_dispatcher_inherent_impls(source: str) -> list[str]:
    matches = list(re.finditer(r"\bimpl\s+RegistryStreamDispatcher\s*\{", source))
    require(matches, "RegistryStreamDispatcher inherent impls are missing")
    return [
        rust_braced_scope(source, match.end() - 1, "RegistryStreamDispatcher inherent impl")
        for match in matches
    ]


def rust_method_scope(implementation: str, name: str) -> str:
    matches = list(re.finditer(rf"\bfn\s+{re.escape(name)}\s*\(", implementation))
    require(len(matches) == 1, f"RegistryStreamDispatcher::{name} definition differs")
    opening_brace = implementation.find("{", matches[0].end())
    require(opening_brace >= 0, f"RegistryStreamDispatcher::{name} body differs")
    return rust_braced_scope(
        implementation,
        opening_brace,
        f"RegistryStreamDispatcher::{name}",
    )


def rust_unique_method_scope(implementations: list[str], name: str) -> str:
    containing = [
        implementation
        for implementation in implementations
        if re.search(rf"\bfn\s+{re.escape(name)}\s*\(", implementation)
    ]
    require(len(containing) == 1, f"RegistryStreamDispatcher::{name} owner impl differs")
    return rust_method_scope(containing[0], name)


def canonical_rust_scopes_sha256(scopes: list[tuple[str, str]]) -> str:
    records = []
    for name, scope in scopes:
        canonical = re.sub(r"\s+", " ", scope).strip()
        records.append(f"{len(name)}:{name}:{len(canonical)}:{canonical}")
    return hashlib.sha256("\n".join(records).encode("utf-8")).hexdigest()


def kernel_stream_work_charges(
    maximum_chunk: int, source: str | None = None
) -> tuple[int, int, int]:
    """Bind the profile preflight's charges to the product dispatcher source."""
    if source is None:
        try:
            source = KERNEL_COMPONENT_INSTANCES_PATH.read_text(encoding="utf-8")
        except OSError as error:
            raise VerificationError(f"cannot load kernel component dispatcher: {error}") from error

    require(
        EXPECTED_KERNEL_COMPONENT_INSTANCES_SOURCE_SHA256 != "",
        "kernel component dispatcher reviewed source identity is not pinned",
    )
    reviewed_source_identity(
        source,
        EXPECTED_KERNEL_COMPONENT_INSTANCES_SOURCE_SHA256,
        "kernel component dispatcher",
    )
    code = rust_code_without_comments_and_literals(source)
    implementation = registry_dispatcher_impl(code)
    inherent_implementations = registry_dispatcher_inherent_impls(code)
    required_work = rust_method_scope(implementation, "required_work")
    commit_prepared = rust_method_scope(implementation, "commit_prepared")
    ready_read_closed = rust_unique_method_scope(inherent_implementations, "ready_read_closed")
    start_write = rust_unique_method_scope(inherent_implementations, "start_write")
    resume_write = rust_unique_method_scope(inherent_implementations, "resume_write")
    close_reader = rust_unique_method_scope(inherent_implementations, "close_reader")
    close_writer = rust_unique_method_scope(inherent_implementations, "close_writer")
    reviewed_scopes = [
        ("required_work", required_work),
        ("commit_prepared", commit_prepared),
        ("ready_read_closed", ready_read_closed),
        ("start_write", start_write),
        ("resume_write", resume_write),
        ("close_reader", close_reader),
        ("close_writer", close_writer),
    ]
    require(
        EXPECTED_KERNEL_STREAM_CHARGE_SCOPES_SHA256 != "",
        "kernel stream charge scope identity is not pinned",
    )
    require(
        canonical_rust_scopes_sha256(reviewed_scopes)
        == EXPECTED_KERNEL_STREAM_CHARGE_SCOPES_SHA256,
        "reviewed kernel stream charge method identity differs",
    )

    import_blocks = re.findall(
        r"(?ms)^use vibeos_component_host::\{\n(.*?)^\};$",
        code,
    )
    imported_chunk_limits = sum(
        len(re.findall(r"\bMAX_STREAM_CHUNK_BYTES\b", block)) for block in import_blocks
    )
    require(
        imported_chunk_limits == 1,
        "kernel dispatcher must import the component-host MAX_STREAM_CHUNK_BYTES exactly once",
    )
    require(
        re.search(r"(?m)^const MAX_STREAM_CHUNK_BYTES\b", code) is None,
        "kernel dispatcher shadows the component-host stream chunk limit",
    )

    read_matches = re.findall(
        r"(?m)^const STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 \+ ([0-9][0-9_]*);$",
        code,
    )
    write_matches = re.findall(
        r"(?m)^const STREAM_WRITE_BASE_WORK: u64 = ([0-9][0-9_]*);$",
        code,
    )
    close_matches = re.findall(
        r"(?m)^const STREAM_CLOSE_WORK: u64 = ([0-9][0-9_]*);$",
        code,
    )
    require(len(read_matches) == 1, "kernel STREAM_READ_WORK declaration differs")
    require(len(write_matches) == 1, "kernel STREAM_WRITE_BASE_WORK declaration differs")
    require(len(close_matches) == 1, "kernel STREAM_CLOSE_WORK declaration differs")
    read_overhead = int(read_matches[0].replace("_", ""))
    write_base = int(write_matches[0].replace("_", ""))
    close = int(close_matches[0].replace("_", ""))
    require(
        (maximum_chunk, read_overhead, write_base, close) == (1024, 4, 4, 1),
        "kernel product stream work charges differ from the frozen preflight",
    )
    require(
        required_work.count("return Ok(STREAM_READ_WORK);") == 1,
        "kernel required_work does not return STREAM_READ_WORK exactly once",
    )
    require(
        len(
            re.findall(
                r"return STREAM_WRITE_BASE_WORK\s*"
                r"\.checked_add\(u64::try_from\(values\.len\(\)\)"
                r"\.map_err\(\|_\| HostError::Exhausted\)\?\)\s*"
                r"\.ok_or\(HostError::Exhausted\);",
                required_work,
            )
        )
        == 1,
        "kernel required_work write charge is not base plus exact value length",
    )
    require(
        required_work.count("return Ok(STREAM_CLOSE_WORK);") == 1,
        "kernel required_work does not return STREAM_CLOSE_WORK exactly once",
    )
    require(
        commit_prepared.count("HostResponse::reserve_one(STREAM_READ_WORK)?") == 1
        and ready_read_closed.count("HostResponse::reserve_one(STREAM_READ_WORK)?") == 1,
        "kernel ready/commit read responses do not each consume STREAM_READ_WORK",
    )
    require(
        start_write.count("STREAM_WRITE_BASE_WORK + bytes.len() as u64") == 1
        and resume_write.count("STREAM_WRITE_BASE_WORK + bytes.len() as u64") == 1,
        "kernel start/resume write responses do not each consume base plus exact byte length",
    )
    require(
        close_reader.count("HostResponse::unit(STREAM_CLOSE_WORK)?") == 1
        and close_writer.count("HostResponse::unit(STREAM_CLOSE_WORK)?") == 1,
        "kernel reader/writer close responses do not each consume STREAM_CLOSE_WORK",
    )
    return maximum_chunk + read_overhead, write_base, close


def named_assignment(tree: ast.Module, name: str) -> ast.AST:
    matches = [
        node.value
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and (
            isinstance(getattr(node, "target", None), ast.Name)
            and getattr(node, "target").id == name
            or isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        )
    ]
    require(len(matches) == 1, f"{OPENSSH_PEER_PATH.name} must assign {name} exactly once")
    return matches[0]


def openssh_fixture_identity() -> None:
    try:
        source = OPENSSH_PEER_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(OPENSSH_PEER_PATH))
    except (OSError, SyntaxError) as error:
        raise VerificationError(f"cannot parse openssh fixture source: {error}") from error
    reviewed_source_identity(source, EXPECTED_OPENSSH_SOURCE_SHA256, "openssh-peer")

    expected_input = ast.parse(INPUT_GENERATOR, mode="eval").body
    expected_output = ast.parse(OUTPUT_TRANSFORM, mode="eval").body
    require(
        ast.dump(named_assignment(tree, "CASE_FILTER_INPUT"), include_attributes=False)
        == ast.dump(expected_input, include_attributes=False),
        "CASE_FILTER_INPUT generator differs",
    )
    require(
        ast.dump(named_assignment(tree, "CASE_FILTER_OUTPUT"), include_attributes=False)
        == ast.dump(expected_output, include_attributes=False),
        "CASE_FILTER_OUTPUT transform differs",
    )

    functions = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_acceptance"
    ]
    require(len(functions) == 1, "openssh-peer run_acceptance definition differs")
    calls = [node for node in ast.walk(functions[0]) if isinstance(node, ast.Call)]
    invocation = [
        call
        for call in calls
        if isinstance(call.func, ast.Name)
        and call.func.id == "invoke"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == "authorized WASM case-filter"
    ]
    require(len(invocation) == 1, "authorized case-filter invocation differs")
    call = invocation[0]
    require(len(call.args) == 4, "authorized case-filter invocation arity differs")
    require(
        isinstance(call.args[1], ast.Name) and call.args[1].id == "accepted_key",
        "authorized case-filter credential binding differs",
    )
    require(
        ast.dump(call.args[2], include_attributes=False)
        == ast.dump(ast.parse('["-T"]', mode="eval").body, include_attributes=False),
        "authorized case-filter SSH option binding differs",
    )
    require(
        ast.dump(call.args[3], include_attributes=False)
        == ast.dump(ast.parse('["case-filter"]', mode="eval").body, include_attributes=False),
        "authorized case-filter command differs",
    )
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    require(set(keywords) == {"input_bytes"}, "authorized case-filter invocation keywords differ")
    require(
        isinstance(keywords["input_bytes"], ast.Name)
        and keywords["input_bytes"].id == "CASE_FILTER_INPUT",
        "authorized case-filter input binding differs",
    )

    result_checks = [
        call
        for call in calls
        if isinstance(call.func, ast.Name)
        and call.func.id == "require_result"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == "authorized WASM case-filter"
    ]
    require(len(result_checks) == 1, "authorized case-filter result check differs")
    check = result_checks[0]
    require(len(check.args) == 4, "authorized case-filter result check arity differs")
    require(
        isinstance(check.args[1], ast.Name) and check.args[1].id == "case_filter",
        "authorized case-filter result binding differs",
    )
    require(
        ast.dump(check.args[2], include_attributes=False)
        == ast.dump(ast.parse("{0}", mode="eval").body, include_attributes=False),
        "authorized case-filter exit contract differs",
    )
    require(
        isinstance(check.args[3], ast.Name) and check.args[3].id == "CASE_FILTER_OUTPUT",
        "authorized case-filter output binding differs",
    )
    check_keywords = {keyword.arg: keyword.value for keyword in check.keywords}
    require(set(check_keywords) == {"stderr_exact"}, "authorized case-filter result keywords differ")
    stderr = check_keywords["stderr_exact"]
    require(isinstance(stderr, ast.Constant) and stderr.value == b"", "case-filter stderr contract differs")

    statement_index = [
        index
        for index, statement in enumerate(functions[0].body)
        if isinstance(statement, ast.Assign) and statement.value is call
    ]
    require(len(statement_index) == 1, "authorized case-filter invocation is not a direct reachable assignment")
    index = statement_index[0]
    statement = functions[0].body[index]
    require(
        len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "case_filter",
        "authorized case-filter result assignment differs",
    )
    require(index + 1 < len(functions[0].body), "authorized case-filter result check is missing")
    next_statement = functions[0].body[index + 1]
    require(
        isinstance(next_statement, ast.Expr) and next_statement.value is check,
        "authorized case-filter result is not checked immediately",
    )
    for prior in functions[0].body[:index]:
        if isinstance(prior, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        require(
            not any(isinstance(node, ast.Return) for node in ast.walk(prior)),
            "authorized case-filter invocation can be bypassed by an earlier return",
        )


def load_contract_files() -> tuple[dict[str, Any], dict[str, Any]]:
    require(EXPECTED_MANIFEST_SHA256 != "", "verifier manifest identity is not pinned")
    require(EXPECTED_SCHEMA_SHA256 != "", "verifier schema identity is not pinned")
    manifest_raw, _manifest_path = read_stable_regular_file(
        MANIFEST_PATH,
        maximum_bytes=MAX_CONTRACT_FILE_BYTES,
        label="manifest",
    )
    schema_raw, _schema_path = read_stable_regular_file(
        SCHEMA_PATH,
        maximum_bytes=MAX_CONTRACT_FILE_BYTES,
        label="schema",
    )
    require(
        hashlib.sha256(manifest_raw).hexdigest() == EXPECTED_MANIFEST_SHA256,
        "manifest byte identity differs",
    )
    require(
        hashlib.sha256(schema_raw).hexdigest() == EXPECTED_SCHEMA_SHA256,
        "schema byte identity differs",
    )
    manifest = strict_json_bytes(manifest_raw, "manifest")
    schema = strict_json_bytes(schema_raw, "schema")
    require(type(manifest) is dict, "manifest must be an object")
    require(type(schema) is dict, "schema must be an object")
    return manifest, schema


def validate_manifest(value: dict[str, Any]) -> None:
    """Validate the closed C8.4 manifest and every executable-source binding."""
    exact_keys(value, TOP_KEYS, "manifest")
    exact_literal(value["schema"], "vibeos.wasm-aot-decision.manifest", "manifest.schema")
    exact_literal(value["version"], 1, "manifest.version")
    exact_literal(value["suite_id"], "vibeos.c84.aot-decision", "manifest.suite_id")
    exact_literal(value["workload_revision"], 1, "manifest.workload_revision")

    exact_literal(
        value["scope"],
        {
            "roadmap_item": "C8.4",
            "state": "preparation-only",
            "c83_status": "incomplete-until-three-physical-duo-cold-boots-are-published",
            "aot_authorized": False,
            "native_code_accepted": False,
        },
        "manifest.scope",
    )

    fixture = exact_keys(
        value["fixture"],
        {
            "id",
            "product_path",
            "transport",
            "command",
            "profile",
            "policy",
            "artifact",
            "input",
            "output",
            "chunking",
        },
        "manifest.fixture",
    )
    exact_literal(fixture["id"], "ssh-case-filter-12k-v1", "fixture.id")
    exact_literal(
        fixture["product_path"],
        "authenticated OpenSSH SessionExec of the image-pinned case-filter command",
        "fixture.product_path",
    )
    exact_literal(fixture["transport"], "authenticated-openssh-exec", "fixture.transport")
    exact_literal(fixture["command"], "case-filter", "fixture.command")
    exact_literal(fixture["profile"], PROFILE_IDENTITY, "fixture.profile")

    identity = image_identity()
    require(fixture["command"] == identity.command, "fixture command does not match image policy")
    require(fixture["profile"] == profile_identity(), "fixture profile does not match format source")

    policy = exact_keys(
        fixture["policy"],
        {"path", "symbol", "world", "entrypoint", "args", "streams", "limits"},
        "fixture.policy",
    )
    exact_repo_path(policy["path"], "policy/image/src/lib.rs", "fixture.policy.path")
    exact_literal(policy["symbol"], "SSH_EXEC_COMPONENT", "fixture.policy.symbol")
    exact_literal(policy["world"], identity.world, "fixture.policy.world")
    exact_literal(policy["entrypoint"], identity.entrypoint, "fixture.policy.entrypoint")
    exact_literal(
        policy["args"],
        {"minimum": identity.min_args, "maximum": identity.max_args},
        "fixture.policy.args",
    )
    exact_literal(
        policy["streams"],
        {"stdin": identity.stdin, "stdout": identity.stdout, "stderr": identity.stderr},
        "fixture.policy.streams",
    )
    exact_literal(
        policy["limits"],
        {
            "memory_bytes": identity.memory_bytes,
            "total_fuel": identity.total_fuel,
            "poll_quantum": identity.poll_quantum,
            "resources": identity.resources,
        },
        "fixture.policy.limits",
    )

    artifact = exact_keys(
        fixture["artifact"],
        {"wat_path", "wat_sha256", "builder_path", "byte_len", "sha256"},
        "fixture.artifact",
    )
    wat = exact_repo_path(
        artifact["wat_path"],
        "policy/image/artifacts/c53-stream-filter.component.wat",
        "fixture.artifact.wat_path",
    )
    builder = exact_repo_path(
        artifact["builder_path"],
        "policy/image/build.rs",
        "fixture.artifact.builder_path",
    )
    require(wat == WAT_PATH and builder == BUILD_PATH, "artifact repository path binding differs")
    exact_literal(
        exact_sha256(artifact["wat_sha256"], "fixture.artifact.wat_sha256"),
        sha256_file(wat),
        "fixture.artifact.wat_sha256",
    )
    exact_literal(artifact["byte_len"], EXPECTED_COMPONENT_BYTES, "fixture.artifact.byte_len")
    exact_literal(
        exact_sha256(artifact["sha256"], "fixture.artifact.sha256"),
        identity.sha256,
        "fixture.artifact.sha256",
    )

    input_fixture = exact_keys(
        fixture["input"],
        {"source_path", "source_symbol", "generator", "byte_len", "sha256"},
        "fixture.input",
    )
    exact_repo_path(input_fixture["source_path"], "scripts/openssh-peer.py", "fixture.input.source_path")
    exact_literal(input_fixture["source_symbol"], "CASE_FILTER_INPUT", "fixture.input.source_symbol")
    exact_literal(input_fixture["generator"], INPUT_GENERATOR, "fixture.input.generator")
    exact_literal(input_fixture["byte_len"], len(INPUT_BYTES), "fixture.input.byte_len")
    exact_literal(
        exact_sha256(input_fixture["sha256"], "fixture.input.sha256"),
        INPUT_SHA256,
        "fixture.input.sha256",
    )

    output_fixture = exact_keys(
        fixture["output"],
        {
            "source_path",
            "source_symbol",
            "transform",
            "byte_len",
            "sha256",
            "exit_status",
            "stderr_bytes",
        },
        "fixture.output",
    )
    exact_repo_path(output_fixture["source_path"], "scripts/openssh-peer.py", "fixture.output.source_path")
    exact_literal(output_fixture["source_symbol"], "CASE_FILTER_OUTPUT", "fixture.output.source_symbol")
    exact_literal(output_fixture["transform"], OUTPUT_TRANSFORM, "fixture.output.transform")
    exact_literal(output_fixture["byte_len"], len(OUTPUT_BYTES), "fixture.output.byte_len")
    exact_literal(
        exact_sha256(output_fixture["sha256"], "fixture.output.sha256"),
        OUTPUT_SHA256,
        "fixture.output.sha256",
    )
    exact_literal(output_fixture["exit_status"], 0, "fixture.output.exit_status")
    exact_literal(output_fixture["stderr_bytes"], 0, "fixture.output.stderr_bytes")
    require(len(INPUT_BYTES) == len(OUTPUT_BYTES), "fixture transform changed the byte length")
    require(
        OUTPUT_BYTES == bytes(byte ^ 0x20 for byte in INPUT_BYTES),
        "fixture output is not the exact XOR transform",
    )
    openssh_fixture_identity()

    maximum_chunk = stream_chunk_limit()
    exact_literal(
        kernel_stream_work_charges(maximum_chunk),
        (1028, 4, 1),
        "kernel product stream work charges",
    )
    chunking = exact_keys(
        fixture["chunking"],
        {"maximum_chunk_bytes", "full_chunks", "final_chunk_bytes", "total_chunks"},
        "fixture.chunking",
    )
    exact_literal(chunking["maximum_chunk_bytes"], maximum_chunk, "fixture.chunking.maximum_chunk_bytes")
    exact_literal(chunking["full_chunks"], 12, "fixture.chunking.full_chunks")
    exact_literal(chunking["final_chunk_bytes"], 37, "fixture.chunking.final_chunk_bytes")
    exact_literal(chunking["total_chunks"], 13, "fixture.chunking.total_chunks")
    require(
        chunking["full_chunks"] * maximum_chunk + chunking["final_chunk_bytes"]
        == input_fixture["byte_len"],
        "fixture chunk partition does not cover the input",
    )
    require(
        chunking["total_chunks"] == chunking["full_chunks"] + 1,
        "fixture total chunk count differs",
    )
    require(
        0 < chunking["final_chunk_bytes"] < maximum_chunk,
        "fixture final chunk is not an exact nonempty tail",
    )

    exact_literal(
        value["platforms"],
        {
            "milkv-duo-cv1800b": {
                "role": "physical-budget-decision",
                "decision_eligible": True,
                "board": "Milk-V Duo CV1800B",
                "cpu": "C906B",
                "hart_id": 0,
                "hart_count": 1,
                "clock": "riscv.rdtime",
                "timebase_hz": 25_000_000,
            },
            "qemu-virt": {
                "role": "instrumentation-and-integration-only",
                "decision_eligible": False,
                "budget_use": "forbidden; QEMU ticks are not converted, combined, or compared with the physical-Duo budget",
            },
        },
        "manifest.platforms",
    )

    sampling = value["sampling"]
    exact_literal(
        sampling,
        {
            "cold_boots": 3,
            "warmup_per_boot": 3,
            "retained_per_boot": 21,
            "retained_total": 63,
            "order": "three discarded warmups followed by twenty-one retained samples on each cold boot",
            "statistics": {
                "p50": "nearest-rank index ceil(0.50*n)-1 after ascending sort",
                "p95": "nearest-rank index ceil(0.95*n)-1 after ascending sort",
                "decision_population": "all 63 retained physical-Duo samples only",
                "timer_overhead_subtracted": False,
            },
        },
        "manifest.sampling",
    )
    require(
        sampling["retained_total"]
        == sampling["cold_boots"] * sampling["retained_per_boot"],
        "retained sample count does not cover every cold boot",
    )

    budget = value["budget"]
    exact_literal(
        budget,
        {
            "metric": "retained end-to-end response p95",
            "clock": "riscv.rdtime",
            "timebase_hz": 25_000_000,
            "ticks": 2_500_000,
            "milliseconds": 100,
            "comparison": "miss iff p95(total_ticks) > 2500000",
            "eligible_platform": "milkv-duo-cv1800b",
        },
        "manifest.budget",
    )
    require(
        budget["ticks"] * 1000 == budget["milliseconds"] * budget["timebase_hz"],
        "budget ticks and milliseconds differ",
    )
    require(
        budget["timebase_hz"]
        == value["platforms"][budget["eligible_platform"]]["timebase_hz"],
        "budget timebase is not the eligible platform timebase",
    )

    phases = value["phases"]
    require(type(phases) is list and len(phases) == len(PHASE_IDS), "phase set differs")
    seen: set[str] = set()
    attributable: list[str] = []
    for index, phase in enumerate(phases):
        phase = exact_keys(phase, {"id", "order", "boundary", "aot_attributable"}, f"phase[{index}]")
        exact_literal(phase["id"], PHASE_IDS[index], f"phase[{index}].id")
        exact_literal(phase["order"], index + 1, f"phase[{index}].order")
        exact_literal(phase["boundary"], PHASE_BOUNDARIES[index], f"phase[{index}].boundary")
        exact_bool(phase["aot_attributable"], f"phase[{index}].aot_attributable")
        require(phase["id"] not in seen, f"duplicate phase {phase['id']}")
        seen.add(phase["id"])
        if phase["aot_attributable"]:
            attributable.append(phase["id"])
    require(tuple(phase["id"] for phase in phases) == PHASE_IDS, "canonical phase order differs")
    require(attributable == ["interpretation"], "AOT-attributable phase differs")

    exact_literal(value["transcript"], TRANSCRIPT_CONTRACT, "manifest.transcript")
    exact_literal(value["decision_rule"], DECISION_RULE, "manifest.decision_rule")
    exact_literal(value["publication_gates"], PUBLICATION_GATES, "manifest.publication_gates")


def validate_schema(value: dict[str, Any]) -> None:
    """Validate the reviewable, closed transcript-schema description."""

    def closed(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        }

    phase_tick_properties = {phase: {"$ref": "#/$defs/u64"} for phase in PHASE_IDS}
    interval_properties = {
        "sequence": {"type": "integer", "minimum": 0, "maximum": 65_535},
        "phase": {"$ref": "#/$defs/phase"},
        "start_offset_ticks": {"$ref": "#/$defs/u64"},
        "end_offset_ticks": {"$ref": "#/$defs/positiveU64"},
    }
    meta_properties = {
        "schema": {"const": "vibeos.wasm-aot-decision.meta"},
        "version": {"const": 1},
        "suite_id": {"const": "vibeos.c84.aot-decision"},
        "workload_revision": {"const": 1},
        "source_commit": {"$ref": "#/$defs/hex40"},
        "challenge": {"$ref": "#/$defs/hex64"},
        "run_id": {"$ref": "#/$defs/hex64"},
        "manifest_sha256": {"$ref": "#/$defs/hex64"},
        "transcript_schema_sha256": {"$ref": "#/$defs/hex64"},
        "platform": {"const": "milkv-duo-cv1800b"},
        "decision_eligible": {"const": True},
        "clock": {"const": "riscv.rdtime"},
        "timebase_hz": {"const": 25_000_000},
        "hart_id": {"const": 0},
        "hart_count": {"const": 1},
        "transcript_scope": {"const": "single-cold-boot"},
        "required_cold_boots": {"const": 3},
        "samples_per_boot": {"const": 24},
        "warmup_per_boot": {"const": 3},
        "retained_per_boot": {"const": 21},
        "workload_id": {"const": "ssh-case-filter-12k-v1"},
        "artifact_sha256": {"const": EXPECTED_COMPONENT_SHA256},
        "artifact_bytes": {"const": EXPECTED_COMPONENT_BYTES},
        "input_sha256": {"const": INPUT_SHA256},
        "input_bytes": {"const": len(INPUT_BYTES)},
        "output_sha256": {"const": OUTPUT_SHA256},
        "output_bytes": {"const": len(OUTPUT_BYTES)},
        "budget_ticks": {"const": 2_500_000},
    }
    sample_properties = {
        "schema": {"const": "vibeos.wasm-aot-decision.sample"},
        "version": {"const": 1},
        "run_id": {"$ref": "#/$defs/hex64"},
        "challenge": {"$ref": "#/$defs/hex64"},
        "sequence": {"type": "integer", "minimum": 0, "maximum": 23},
        "sample_index": {"type": "integer", "minimum": 0, "maximum": 23},
        "warmup": {"type": "boolean"},
        "workload_id": {"const": "ssh-case-filter-12k-v1"},
        "total_ticks": {"$ref": "#/$defs/positiveU64"},
        "phase_ticks": {"$ref": "#/$defs/phaseTicks"},
        "interval_capacity": {"const": 65536},
        "interval_count": {"type": "integer", "minimum": 1, "maximum": 65536},
        "intervals_complete": {"const": True},
        "intervals": {
            "type": "array",
            "minItems": 1,
            "maxItems": 65536,
            "items": {"$ref": "#/$defs/interval"},
        },
        "read_chunks": {"const": 13},
        "write_chunks": {"const": 13},
        "fuel_consumed": {"type": "integer", "minimum": 1, "maximum": 500_000},
        "poll_quanta": {"$ref": "#/$defs/positiveU64"},
        "terminal": {"const": "success"},
        "logical_live_after": {"const": 0},
        "timed_out": {"const": False},
        "timeout_phase": {"const": "none"},
        "exit_status": {"const": 0},
        "stdout_bytes": {"const": len(OUTPUT_BYTES)},
        "stdout_sha256": {"const": OUTPUT_SHA256},
        "stderr_bytes": {"const": 0},
    }
    end_properties = {
        "schema": {"const": "vibeos.wasm-aot-decision.end"},
        "version": {"const": 1},
        "run_id": {"$ref": "#/$defs/hex64"},
        "challenge": {"$ref": "#/$defs/hex64"},
        "samples": {"const": 24},
        "warmups": {"const": 3},
        "retained": {"const": 21},
        "accumulator": {"$ref": "#/$defs/u64"},
    }
    expected = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://vibeos.invalid/schemas/wasm-aot-decision-v1.json",
        "title": "VibeOS C8.4 single-cold-boot physical AOT-decision transcript records",
        "oneOf": [
            {"$ref": "#/$defs/meta"},
            {"$ref": "#/$defs/sample"},
            {"$ref": "#/$defs/end"},
        ],
        "$defs": {
            "hex40": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "u64": {"type": "integer", "minimum": 0, "maximum": U64_MAX},
            "positiveU64": {"type": "integer", "minimum": 1, "maximum": U64_MAX},
            "phase": {"type": "string", "enum": list(PHASE_IDS)},
            "phaseTicks": closed(phase_tick_properties, list(PHASE_IDS)),
            "interval": closed(interval_properties, list(interval_properties)),
            "meta": closed(meta_properties, list(meta_properties)),
            "sample": closed(sample_properties, list(sample_properties)),
            "end": closed(end_properties, list(end_properties)),
        },
    }
    exact_literal(value, expected, "transcript schema")


def parse_record(line: str, prefix: str, label: str) -> dict[str, Any] | None:
    position = line.find(prefix)
    if position < 0:
        return None
    require(position == 0, f"{label} marker must begin at column zero")
    payload = line[len(prefix) :]
    require(payload != "" and payload == payload.strip(), f"{label} payload is empty or padded")
    value = strict_json_bytes(payload.encode("utf-8"), label)
    require(type(value) is dict, f"{label} must be an object")
    return value


def rotate_left(value: int, amount: int) -> int:
    value &= U64_MAX
    return ((value << amount) | (value >> (64 - amount))) & U64_MAX


def fold_word(accumulator: int, word: int) -> int:
    exact_int(accumulator, "accumulator")
    exact_int(word, "accumulator word")
    return (rotate_left(accumulator, 7) + word) & U64_MAX


def stdout_digest_words(value: str) -> list[int]:
    raw = bytes.fromhex(exact_sha256(value, "sample.stdout_sha256"))
    return [int.from_bytes(raw[offset : offset + 8], "big") for offset in range(0, 32, 8)]


def transcript_accumulator(samples: list[dict[str, Any]]) -> int:
    accumulator = 0
    for sample in samples:
        prefix_words = [
            SAMPLE_DOMAIN_WORD,
            sample["sequence"],
            sample["sample_index"],
            int(sample["warmup"]),
            sample["total_ticks"],
            *(sample["phase_ticks"][phase] for phase in PHASE_IDS),
            sample["interval_capacity"],
            sample["interval_count"],
            int(sample["intervals_complete"]),
        ]
        for word in prefix_words:
            accumulator = fold_word(accumulator, word)
        for interval in sample["intervals"]:
            for word in (
                INTERVAL_DOMAIN_WORD,
                interval["sequence"],
                PHASE_CODES[interval["phase"]],
                interval["start_offset_ticks"],
                interval["end_offset_ticks"],
            ):
                accumulator = fold_word(accumulator, word)
        suffix_words = [
            sample["read_chunks"],
            sample["write_chunks"],
            sample["fuel_consumed"],
            sample["poll_quanta"],
            1,
            sample["logical_live_after"],
            int(sample["timed_out"]),
            0,
            sample["exit_status"],
            sample["stdout_bytes"],
            *stdout_digest_words(sample["stdout_sha256"]),
            sample["stderr_bytes"],
        ]
        for word in suffix_words:
            accumulator = fold_word(accumulator, word)
    return accumulator


def expected_run_id(meta: dict[str, Any]) -> str:
    contract = TRANSCRIPT_CONTRACT["run_id"]
    values = [contract["domain"], *(meta[field] for field in contract["fields"])]
    require(all(type(value) is str and "\0" not in value for value in values), "run-id field is not plain ASCII text")
    try:
        payload = "\0".join(values).encode("ascii")
    except UnicodeEncodeError as error:
        raise VerificationError("run-id field is not ASCII") from error
    return hashlib.sha256(payload).hexdigest()


def verify_transcript_meta(
    meta: dict[str, Any],
    *,
    expected_source: str,
    expected_challenge: str,
) -> None:
    exact_keys(meta, META_KEYS, "metadata")
    fixed = {
        "schema": "vibeos.wasm-aot-decision.meta",
        "version": 1,
        "suite_id": "vibeos.c84.aot-decision",
        "workload_revision": 1,
        "manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "transcript_schema_sha256": EXPECTED_SCHEMA_SHA256,
        "platform": "milkv-duo-cv1800b",
        "decision_eligible": True,
        "clock": "riscv.rdtime",
        "timebase_hz": 25_000_000,
        "hart_id": 0,
        "hart_count": 1,
        "transcript_scope": "single-cold-boot",
        "required_cold_boots": 3,
        "samples_per_boot": SAMPLES_PER_BOOT,
        "warmup_per_boot": WARMUPS_PER_BOOT,
        "retained_per_boot": RETAINED_PER_BOOT,
        "workload_id": "ssh-case-filter-12k-v1",
        "artifact_sha256": EXPECTED_COMPONENT_SHA256,
        "artifact_bytes": EXPECTED_COMPONENT_BYTES,
        "input_sha256": INPUT_SHA256,
        "input_bytes": len(INPUT_BYTES),
        "output_sha256": OUTPUT_SHA256,
        "output_bytes": len(OUTPUT_BYTES),
        "budget_ticks": 2_500_000,
    }
    for field, expected in fixed.items():
        exact_literal(meta[field], expected, f"metadata.{field}")
    source = exact_commit(meta["source_commit"], "metadata.source_commit")
    challenge = exact_sha256(meta["challenge"], "metadata.challenge")
    exact_literal(source, exact_commit(expected_source, "expected source"), "metadata.source_commit")
    exact_literal(
        challenge,
        exact_sha256(expected_challenge, "expected challenge"),
        "metadata.challenge",
    )
    run_id = exact_sha256(meta["run_id"], "metadata.run_id")
    require(run_id == expected_run_id(meta), "metadata run id does not bind the campaign")


def verify_transcript_sample(
    sample: dict[str, Any],
    *,
    position: int,
    meta: dict[str, Any],
) -> None:
    label = f"sample[{position}]"
    exact_keys(sample, SAMPLE_KEYS, label)
    fixed = {
        "schema": "vibeos.wasm-aot-decision.sample",
        "version": 1,
        "workload_id": "ssh-case-filter-12k-v1",
        "interval_capacity": INTERVAL_CAPACITY,
        "intervals_complete": True,
        "read_chunks": 13,
        "write_chunks": 13,
        "terminal": "success",
        "logical_live_after": 0,
        "timed_out": False,
        "timeout_phase": "none",
        "exit_status": 0,
        "stdout_bytes": len(OUTPUT_BYTES),
        "stdout_sha256": OUTPUT_SHA256,
        "stderr_bytes": 0,
    }
    for field, expected in fixed.items():
        exact_literal(sample[field], expected, f"{label}.{field}")
    exact_literal(exact_sha256(sample["run_id"], f"{label}.run_id"), meta["run_id"], f"{label}.run_id")
    exact_literal(
        exact_sha256(sample["challenge"], f"{label}.challenge"),
        meta["challenge"],
        f"{label}.challenge",
    )
    exact_literal(exact_int(sample["sequence"], f"{label}.sequence", maximum=23), position, f"{label}.sequence")
    exact_literal(
        exact_int(sample["sample_index"], f"{label}.sample_index", maximum=23),
        position,
        f"{label}.sample_index",
    )
    exact_literal(
        exact_bool(sample["warmup"], f"{label}.warmup"),
        position < WARMUPS_PER_BOOT,
        f"{label}.warmup",
    )
    total_ticks = exact_int(sample["total_ticks"], f"{label}.total_ticks", minimum=1)
    exact_int(sample["fuel_consumed"], f"{label}.fuel_consumed", minimum=1, maximum=500_000)
    exact_int(sample["poll_quanta"], f"{label}.poll_quanta", minimum=1)

    phase_ticks = exact_keys(sample["phase_ticks"], set(PHASE_IDS), f"{label}.phase_ticks")
    declared_phase_ticks = {
        phase: exact_int(phase_ticks[phase], f"{label}.phase_ticks.{phase}") for phase in PHASE_IDS
    }
    require(sum(declared_phase_ticks.values()) == total_ticks, f"{label} phase ticks do not sum to total")

    intervals = sample["intervals"]
    require(type(intervals) is list, f"{label}.intervals must be an array")
    require(1 <= len(intervals) <= INTERVAL_CAPACITY, f"{label}.intervals length is out of range")
    interval_count = exact_int(
        sample["interval_count"],
        f"{label}.interval_count",
        minimum=1,
        maximum=INTERVAL_CAPACITY,
    )
    require(interval_count == len(intervals), f"{label} interval count differs from array length")

    observed_phase_ticks = {phase: 0 for phase in PHASE_IDS}
    previous_end = 0
    previous_phase: str | None = None
    for interval_index, interval in enumerate(intervals):
        interval_label = f"{label}.intervals[{interval_index}]"
        exact_keys(interval, INTERVAL_KEYS, interval_label)
        exact_literal(
            exact_int(interval["sequence"], f"{interval_label}.sequence", maximum=65_535),
            interval_index,
            f"{interval_label}.sequence",
        )
        phase = exact_text(interval["phase"], f"{interval_label}.phase")
        require(phase in PHASE_CODES, f"{interval_label}.phase is not canonical")
        require(phase != previous_phase, f"{interval_label} repeats an adjacent phase")
        start = exact_int(interval["start_offset_ticks"], f"{interval_label}.start_offset_ticks")
        end = exact_int(interval["end_offset_ticks"], f"{interval_label}.end_offset_ticks", minimum=1)
        require(start == previous_end, f"{interval_label} has a gap or overlap")
        require(end > start, f"{interval_label} is empty or reversed")
        observed_phase_ticks[phase] += end - start
        require(observed_phase_ticks[phase] <= U64_MAX, f"{interval_label} phase total overflows u64")
        previous_end = end
        previous_phase = phase
    require(previous_end == total_ticks, f"{label} intervals do not cover total_ticks")
    require(observed_phase_ticks == declared_phase_ticks, f"{label} interval phase totals differ")


def nearest_rank(values: list[int], percentile: int) -> int:
    require(values, "nearest-rank input is empty")
    exact_int(percentile, "percentile", minimum=1, maximum=100)
    ordered = sorted(values)
    return ordered[(percentile * len(ordered) + 99) // 100 - 1]


def retained_stability_passes(values: list[int]) -> bool:
    return nearest_rank(values, 95) * 100 <= nearest_rank(values, 50) * 150


def verify_transcript_end(
    ending: dict[str, Any],
    *,
    samples: list[dict[str, Any]],
    meta: dict[str, Any],
) -> None:
    exact_keys(ending, END_KEYS, "end")
    fixed = {
        "schema": "vibeos.wasm-aot-decision.end",
        "version": 1,
        "samples": SAMPLES_PER_BOOT,
        "warmups": WARMUPS_PER_BOOT,
        "retained": RETAINED_PER_BOOT,
    }
    for field, expected in fixed.items():
        exact_literal(ending[field], expected, f"end.{field}")
    exact_literal(exact_sha256(ending["run_id"], "end.run_id"), meta["run_id"], "end.run_id")
    exact_literal(
        exact_sha256(ending["challenge"], "end.challenge"),
        meta["challenge"],
        "end.challenge",
    )
    observed = exact_int(ending["accumulator"], "end.accumulator")
    require(observed == transcript_accumulator(samples), "end accumulator differs")


def verify_transcript_bytes(
    raw: bytes,
    *,
    expected_source: str,
    expected_challenge: str,
) -> VerifiedBootTranscript:
    require(
        0 < len(raw) <= MAX_RAW_TRANSCRIPT_BYTES,
        f"transcript byte length is outside [1, {MAX_RAW_TRANSCRIPT_BYTES}]",
    )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(f"transcript is not strict UTF-8: {error}") from error
    lowered = text.lower()
    for marker in FAILURE_MARKERS:
        require(marker.lower() not in lowered, f"transcript contains failure marker {marker!r}")

    records: list[tuple[str, dict[str, Any]]] = []
    for line in text.splitlines():
        matched = 0
        for kind, prefix in (("meta", META_PREFIX), ("sample", SAMPLE_PREFIX), ("end", END_PREFIX)):
            record = parse_record(line, prefix, kind)
            if record is not None:
                records.append((kind, record))
                matched += 1
        require(matched <= 1, "one serial line contains multiple record markers")

    expected_kinds = ["meta", *(["sample"] * SAMPLES_PER_BOOT), "end"]
    require([kind for kind, _ in records] == expected_kinds, "record count or order differs")
    meta = records[0][1]
    samples = [record for kind, record in records if kind == "sample"]
    ending = records[-1][1]
    verify_transcript_meta(
        meta,
        expected_source=expected_source,
        expected_challenge=expected_challenge,
    )
    for position, sample in enumerate(samples):
        verify_transcript_sample(sample, position=position, meta=meta)
    retained_ticks = [sample["total_ticks"] for sample in samples if not sample["warmup"]]
    require(len(retained_ticks) == RETAINED_PER_BOOT, "retained sample count differs")
    require(
        retained_stability_passes(retained_ticks),
        "single-boot retained stability exceeds 1.50",
    )
    verify_transcript_end(ending, samples=samples, meta=meta)
    return VerifiedBootTranscript(
        metadata=meta,
        samples=samples,
        ending=ending,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_bytes=len(raw),
    )


def distribution(values: list[int]) -> dict[str, int]:
    require(values, "distribution input is empty")
    ordered = sorted(values)
    return {
        "min": ordered[0],
        "p50": nearest_rank(ordered, 50),
        "p95": nearest_rank(ordered, 95),
        "max": ordered[-1],
        "mean": sum(ordered) // len(ordered),
    }


def derive_boot_summary(verified: VerifiedBootTranscript, *, boot_index: int) -> dict[str, Any]:
    exact_int(boot_index, "boot index", maximum=2)
    retained = [sample for sample in verified.samples if not sample["warmup"]]
    retained_samples = [
        {
            "sample_index": sample["sample_index"],
            "total_ticks": sample["total_ticks"],
            "interpretation_ticks": sample["phase_ticks"]["interpretation"],
            "non_interpretation_ticks": sample["total_ticks"]
            - sample["phase_ticks"]["interpretation"],
        }
        for sample in retained
    ]
    totals = [sample["total_ticks"] for sample in retained_samples]
    interpretation = [sample["interpretation_ticks"] for sample in retained_samples]
    non_interpretation = [sample["non_interpretation_ticks"] for sample in retained_samples]
    total_distribution = distribution(totals)
    return {
        "schema": "vibeos.wasm-aot-decision.boot-summary",
        "version": 1,
        "suite_id": "vibeos.c84.aot-decision",
        "workload_revision": 1,
        "scope": "single-boot-transcript-semantics-only-no-aot-decision",
        "physical_provenance": "unverified",
        "cold_boot_provenance": "unverified",
        "source_commit": verified.metadata["source_commit"],
        "challenge": verified.metadata["challenge"],
        "run_id": verified.metadata["run_id"],
        "manifest_sha256": verified.metadata["manifest_sha256"],
        "transcript_schema_sha256": verified.metadata["transcript_schema_sha256"],
        "platform": verified.metadata["platform"],
        "boot_index": boot_index,
        "required_cold_boots": 3,
        "warmups": WARMUPS_PER_BOOT,
        "retained": RETAINED_PER_BOOT,
        "timebase_hz": verified.metadata["timebase_hz"],
        "raw_transcript_sha256": verified.raw_sha256,
        "raw_transcript_bytes": verified.raw_bytes,
        "end_accumulator": verified.ending["accumulator"],
        "retained_samples": retained_samples,
        "statistics": {
            "total_ticks": total_distribution,
            "interpretation_ticks": distribution(interpretation),
            "non_interpretation_ticks": distribution(non_interpretation),
            "stability": {
                "criterion": "p95(total_ticks) * 100 <= p50(total_ticks) * 150",
                "passed": retained_stability_passes(totals),
            },
        },
    }


def verify_derived_summary(value: Any, expected: dict[str, Any]) -> None:
    exact_literal(value, expected, "checked boot summary")


def serialize_transcript(
    meta: dict[str, Any],
    samples: list[dict[str, Any]],
    ending: dict[str, Any],
) -> bytes:
    def compact(value: dict[str, Any]) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    lines = ["VibeOS C8.4 synthetic boot"]
    lines.append(META_PREFIX + compact(meta))
    lines.extend(SAMPLE_PREFIX + compact(sample) for sample in samples)
    lines.append(END_PREFIX + compact(ending))
    lines.append("VibeOS C8.4 synthetic trailer")
    return ("\n".join(lines) + "\n").encode("utf-8")


def synthetic_transcript_records() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    source = "a" * 40
    challenge = "b" * 64
    meta = {
        "schema": "vibeos.wasm-aot-decision.meta",
        "version": 1,
        "suite_id": "vibeos.c84.aot-decision",
        "workload_revision": 1,
        "source_commit": source,
        "challenge": challenge,
        "run_id": "1" * 64,
        "manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "transcript_schema_sha256": EXPECTED_SCHEMA_SHA256,
        "platform": "milkv-duo-cv1800b",
        "decision_eligible": True,
        "clock": "riscv.rdtime",
        "timebase_hz": 25_000_000,
        "hart_id": 0,
        "hart_count": 1,
        "transcript_scope": "single-cold-boot",
        "required_cold_boots": 3,
        "samples_per_boot": SAMPLES_PER_BOOT,
        "warmup_per_boot": WARMUPS_PER_BOOT,
        "retained_per_boot": RETAINED_PER_BOOT,
        "workload_id": "ssh-case-filter-12k-v1",
        "artifact_sha256": EXPECTED_COMPONENT_SHA256,
        "artifact_bytes": EXPECTED_COMPONENT_BYTES,
        "input_sha256": INPUT_SHA256,
        "input_bytes": len(INPUT_BYTES),
        "output_sha256": OUTPUT_SHA256,
        "output_bytes": len(OUTPUT_BYTES),
        "budget_ticks": 2_500_000,
    }
    meta["run_id"] = expected_run_id(meta)
    samples: list[dict[str, Any]] = []
    for sample_index in range(SAMPLES_PER_BOOT):
        durations = [10, 20, 30, 40, 50, 60, 70 + sample_index]
        phase_ticks = dict(zip(PHASE_IDS, durations, strict=True))
        intervals: list[dict[str, Any]] = []
        start = 0
        for interval_index, (phase, duration) in enumerate(zip(PHASE_IDS, durations, strict=True)):
            end = start + duration
            intervals.append(
                {
                    "sequence": interval_index,
                    "phase": phase,
                    "start_offset_ticks": start,
                    "end_offset_ticks": end,
                }
            )
            start = end
        samples.append(
            {
                "schema": "vibeos.wasm-aot-decision.sample",
                "version": 1,
                "run_id": meta["run_id"],
                "challenge": challenge,
                "sequence": sample_index,
                "sample_index": sample_index,
                "warmup": sample_index < WARMUPS_PER_BOOT,
                "workload_id": "ssh-case-filter-12k-v1",
                "total_ticks": start,
                "phase_ticks": phase_ticks,
                "interval_capacity": INTERVAL_CAPACITY,
                "interval_count": len(intervals),
                "intervals_complete": True,
                "intervals": intervals,
                "read_chunks": 13,
                "write_chunks": 13,
                "fuel_consumed": 1000 + sample_index,
                "poll_quanta": 2000 + sample_index,
                "terminal": "success",
                "logical_live_after": 0,
                "timed_out": False,
                "timeout_phase": "none",
                "exit_status": 0,
                "stdout_bytes": len(OUTPUT_BYTES),
                "stdout_sha256": OUTPUT_SHA256,
                "stderr_bytes": 0,
            }
        )
    ending = {
        "schema": "vibeos.wasm-aot-decision.end",
        "version": 1,
        "run_id": meta["run_id"],
        "challenge": challenge,
        "samples": SAMPLES_PER_BOOT,
        "warmups": WARMUPS_PER_BOOT,
        "retained": RETAINED_PER_BOOT,
        "accumulator": transcript_accumulator(samples),
    }
    return meta, samples, ending


def selftest(manifest: dict[str, Any], schema: dict[str, Any]) -> None:
    validate_manifest(manifest)
    validate_schema(schema)

    manifest_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("missing-top-field", lambda value: value.pop("budget")),
        ("extra-top-field", lambda value: value.update(extra=None)),
        ("missing-policy-field", lambda value: value["fixture"]["policy"].pop("world")),
        ("extra-policy-field", lambda value: value["fixture"]["policy"].update(extra=1)),
        ("bool-as-integer", lambda value: value["sampling"].update(cold_boots=True)),
        ("missing-transcript-contract", lambda value: value.pop("transcript")),
        (
            "transcript-framing-drift",
            lambda value: value["transcript"]["framing"].update(sample_records_per_raw=72),
        ),
        (
            "transcript-run-id-drift",
            lambda value: value["transcript"]["run_id"].update(algorithm="sha512"),
        ),
        (
            "transcript-accumulator-drift",
            lambda value: value["transcript"]["accumulator"].update(
                update="acc = acc + word"
            ),
        ),
        ("integer-as-boolean", lambda value: value["scope"].update(aot_authorized=0)),
        ("budget-drift", lambda value: value["budget"].update(ticks=2_500_001)),
        ("budget-timebase-drift", lambda value: value["budget"].update(timebase_hz=1_000_000)),
        ("sampling-total-drift", lambda value: value["sampling"].update(retained_total=62)),
        ("sampling-order-drift", lambda value: value["sampling"].update(warmup_per_boot=2)),
        ("phase-missing", lambda value: value["phases"].pop()),
        ("phase-duplicate", lambda value: value["phases"][1].update(id="validation")),
        ("phase-order-drift", lambda value: value["phases"][2].update(order=4)),
        (
            "phase-attribution-drift",
            lambda value: value["phases"][3].update(aot_attributable=False),
        ),
        (
            "decision-budget-rule-drift",
            lambda value: value["decision_rule"].update(budget_miss="p95(total_ticks) >= 2500000"),
        ),
        (
            "decision-authorization-drift",
            lambda value: value["decision_rule"].update(authorization="AOT authorized"),
        ),
        ("wat-path-drift", lambda value: value["fixture"]["artifact"].update(wat_path="../escape.wat")),
        ("policy-path-drift", lambda value: value["fixture"]["policy"].update(path="policy/image/build.rs")),
        ("wat-hash-drift", lambda value: value["fixture"]["artifact"].update(wat_sha256="1" * 64)),
        ("artifact-hash-drift", lambda value: value["fixture"]["artifact"].update(sha256="2" * 64)),
        ("input-hash-drift", lambda value: value["fixture"]["input"].update(sha256="3" * 64)),
        ("output-hash-drift", lambda value: value["fixture"]["output"].update(sha256="4" * 64)),
        ("fixture-formula-drift", lambda value: value["fixture"]["input"].update(generator="bytes()")),
        ("fixture-symbol-drift", lambda value: value["fixture"]["input"].update(source_symbol="OTHER")),
        ("fixture-command-drift", lambda value: value["fixture"].update(command="other")),
        ("profile-drift", lambda value: value["fixture"]["profile"].update(canonical_features=3)),
        ("limit-drift", lambda value: value["fixture"]["policy"]["limits"].update(total_fuel=499_999)),
        ("chunk-limit-drift", lambda value: value["fixture"]["chunking"].update(maximum_chunk_bytes=2048)),
        ("chunk-tail-drift", lambda value: value["fixture"]["chunking"].update(final_chunk_bytes=36)),
        (
            "duo-platform-drift",
            lambda value: value["platforms"]["milkv-duo-cv1800b"].update(decision_eligible=False),
        ),
        (
            "qemu-platform-drift",
            lambda value: value["platforms"]["qemu-virt"].update(decision_eligible=True),
        ),
        ("preparation-authority-drift", lambda value: value["scope"].update(native_code_accepted=True)),
        (
            "publication-gate-drift",
            lambda value: value["publication_gates"].update(qemu_exclusion="QEMU is eligible"),
        ),
        (
            "publication-interval-capacity-drift",
            lambda value: value["publication_gates"].update(
                interval_capacity="truncated intervals are accepted"
            ),
        ),
        (
            "publication-fuel-bound-drift",
            lambda value: value["publication_gates"].update(
                correctness="fuel and poll counters are unchecked"
            ),
        ),
    ]
    schema_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("schema-id-drift", lambda value: value.update({"$id": "https://example.invalid/other"})),
        ("schema-extra-field", lambda value: value.update(extra=True)),
        ("schema-missing-def", lambda value: value["$defs"].pop("interval")),
        (
            "schema-u64-bound-drift",
            lambda value: value["$defs"]["u64"].update(maximum=U64_MAX - 1),
        ),
        ("schema-phase-drift", lambda value: value["$defs"]["phase"]["enum"].reverse()),
        (
            "schema-bool-integer",
            lambda value: value["$defs"]["meta"]["properties"]["decision_eligible"].update(const=1),
        ),
        (
            "schema-interval-bound-drift",
            lambda value: value["$defs"]["sample"]["properties"]["intervals"].update(maxItems=65535),
        ),
        (
            "schema-interval-capacity-drift",
            lambda value: value["$defs"]["sample"]["properties"]["interval_capacity"].update(
                const=65535
            ),
        ),
        (
            "schema-interval-count-minimum-drift",
            lambda value: value["$defs"]["sample"]["properties"]["interval_count"].update(
                minimum=0
            ),
        ),
        (
            "schema-interval-count-maximum-drift",
            lambda value: value["$defs"]["sample"]["properties"]["interval_count"].update(
                maximum=65535
            ),
        ),
        (
            "schema-intervals-complete-drift",
            lambda value: value["$defs"]["sample"]["properties"]["intervals_complete"].update(
                const=False
            ),
        ),
        (
            "schema-timeout-drift",
            lambda value: value["$defs"]["sample"]["properties"]["timed_out"].update(const=True),
        ),
        (
            "schema-terminal-drift",
            lambda value: value["$defs"]["sample"]["properties"]["terminal"].update(const="failed"),
        ),
        (
            "schema-fuel-maximum-drift",
            lambda value: value["$defs"]["sample"]["properties"]["fuel_consumed"].update(
                maximum=500_001
            ),
        ),
        (
            "schema-poll-minimum-drift",
            lambda value: value["$defs"]["sample"]["properties"].update(
                poll_quanta={"$ref": "#/$defs/u64"}
            ),
        ),
        (
            "schema-sample-boot-index",
            lambda value: value["$defs"]["sample"]["properties"].update(
                cold_boot_index={"type": "integer", "minimum": 0, "maximum": 2}
            ),
        ),
        (
            "schema-meta-scope-drift",
            lambda value: value["$defs"]["meta"]["properties"]["transcript_scope"].update(
                const="three-cold-boots"
            ),
        ),
        (
            "schema-required-drift",
            lambda value: value["$defs"]["sample"]["required"].remove("interval_count"),
        ),
        (
            "schema-count-drift",
            lambda value: value["$defs"]["end"]["properties"]["retained"].update(const=62),
        ),
    ]

    rejected = 0
    for name, mutation in manifest_mutations:
        candidate = copy.deepcopy(manifest)
        mutation(candidate)
        try:
            validate_manifest(candidate)
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted manifest mutation {name}")
    for name, mutation in schema_mutations:
        candidate = copy.deepcopy(schema)
        mutation(candidate)
        try:
            validate_schema(candidate)
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted schema mutation {name}")

    strict_json_mutations = {
        "duplicate-manifest-member": b'{"schema":"one","schema":"two"}',
        "duplicate-schema-member": b'{"$id":"one","$id":"two"}',
        "float-number": b'{"ticks":1.0}',
        "nonfinite-number": b'{"ticks":NaN}',
    }
    for name, raw in strict_json_mutations.items():
        try:
            strict_json_bytes(raw, name)
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted JSON mutation {name}")

    source_mutations = [
        (
            "build-source-binding-drift",
            BUILD_PATH.read_text(encoding="utf-8").replace(
                "wat::parse_str(SOURCE)", "wat::parse_str(NATIVE_ASYNC_SOURCE)", 1
            ),
            EXPECTED_BUILD_SOURCE_SHA256,
        ),
        (
            "build-output-binding-drift",
            BUILD_PATH.read_text(encoding="utf-8").replace(
                "c53-stream-filter.component.wasm", "other.component.wasm", 1
            ),
            EXPECTED_BUILD_SOURCE_SHA256,
        ),
        (
            "policy-artifact-include-drift",
            POLICY_PATH.read_text(encoding="utf-8").replace(
                "/c53-stream-filter.component.wasm", "/other.component.wasm", 1
            ),
            EXPECTED_POLICY_SOURCE_SHA256,
        ),
        (
            "policy-wit-drift",
            POLICY_PATH.read_text(encoding="utf-8").replace(
                "package vibe:%stream@1.0.0;", "package other:stream@1.0.0;", 1
            ),
            EXPECTED_POLICY_SOURCE_SHA256,
        ),
        (
            "openssh-credential-drift",
            OPENSSH_PEER_PATH.read_text(encoding="utf-8").replace(
                '"authorized WASM case-filter",\n        accepted_key,',
                '"authorized WASM case-filter",\n        rejected_key,',
                1,
            ),
            EXPECTED_OPENSSH_SOURCE_SHA256,
        ),
        (
            "openssh-decoy-drift",
            OPENSSH_PEER_PATH.read_text(encoding="utf-8") + "\nCASE_FILTER_INPUT = b'decoy'\n",
            EXPECTED_OPENSSH_SOURCE_SHA256,
        ),
    ]
    for name, candidate, expected in source_mutations:
        try:
            reviewed_source_identity(candidate, expected, name)
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted source mutation {name}")

    kernel_source = KERNEL_COMPONENT_INSTANCES_PATH.read_text(encoding="utf-8")
    kernel_binding_cfg_alias_decoy = kernel_source.replace(
        "VibeHostManifest, MAX_STREAM_CHUNK_BYTES,",
        "VibeHostManifest,",
        1,
    ).replace(
        "static INSTANCES: InstanceRegistry = InstanceRegistry::new();",
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "const OTHER_STREAM_CHUNK_BYTES: usize = 2048;\n"
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "use self::OTHER_STREAM_CHUNK_BYTES as MAX_STREAM_CHUNK_BYTES;\n"
        "#[cfg(any())]\n"
        "use vibeos_component_host::{\n"
        "    MAX_STREAM_CHUNK_BYTES,\n"
        "};\n\n"
        "static INSTANCES: InstanceRegistry = InstanceRegistry::new();",
        1,
    )
    kernel_read_cfg_false_decoy = kernel_source.replace(
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "const STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 4;",
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "const OTHER_STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 5;\n"
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "use self::OTHER_STREAM_READ_WORK as STREAM_READ_WORK;\n"
        "#[cfg(any())]\n"
        "const STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 4;",
        1,
    )
    kernel_write_cfg_alias_decoy = kernel_source.replace(
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "const STREAM_WRITE_BASE_WORK: u64 = 4;",
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "const OTHER_STREAM_WRITE_BASE_WORK: u64 = 5;\n"
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "use self::OTHER_STREAM_WRITE_BASE_WORK as STREAM_WRITE_BASE_WORK;\n"
        "#[cfg(any())]\n"
        "const STREAM_WRITE_BASE_WORK: u64 = 4;",
        1,
    )
    kernel_cfg_feature_string_drift = kernel_source.replace(
        "#[cfg(feature = \"ssh-component-command\")]\n"
        "const STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 4;",
        "#[cfg(feature = \"ssh-component-command-alias\")]\n"
        "const STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 4;",
        1,
    )
    kernel_charge_mutations = [
        (
            "kernel-stream-cfg-feature-string-drift",
            kernel_cfg_feature_string_drift,
        ),
        (
            "kernel-stream-chunk-cfg-alias-import-decoy",
            kernel_binding_cfg_alias_decoy,
        ),
        (
            "kernel-stream-read-cfg-false-alias-decoy",
            kernel_read_cfg_false_decoy,
        ),
        (
            "kernel-stream-write-cfg-false-alias-decoy",
            kernel_write_cfg_alias_decoy,
        ),
        (
            "kernel-stream-chunk-import-drift",
            kernel_source.replace(
                "VibeHostManifest, MAX_STREAM_CHUNK_BYTES,",
                "VibeHostManifest,",
                1,
            ),
        ),
        (
            "kernel-stream-read-work-drift",
            kernel_source.replace(
                "STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 4;",
                "STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 5;",
                1,
            ),
        ),
        (
            "kernel-stream-write-work-drift",
            kernel_source.replace(
                "STREAM_WRITE_BASE_WORK: u64 = 4;",
                "STREAM_WRITE_BASE_WORK: u64 = 5;",
                1,
            ),
        ),
        (
            "kernel-stream-close-work-drift",
            kernel_source.replace(
                "STREAM_CLOSE_WORK: u64 = 1;",
                "STREAM_CLOSE_WORK: u64 = 2;",
                1,
            ),
        ),
        (
            "kernel-required-read-charge-use-drift",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-write-charge-use-drift",
            kernel_source.replace(
                "return STREAM_WRITE_BASE_WORK\n                .checked_add(",
                "return STREAM_WRITE_BASE_WORK\n                .saturating_add(",
                1,
            ),
        ),
        (
            "kernel-required-close-charge-use-drift",
            kernel_source.replace(
                "return Ok(STREAM_CLOSE_WORK);",
                "return Ok(STREAM_CLOSE_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-ready-read-charge-use-drift",
            kernel_source.replace(
                "HostResponse::reserve_one(STREAM_READ_WORK)?",
                "HostResponse::reserve_one(STREAM_READ_WORK + 1)?",
                1,
            ),
        ),
        (
            "kernel-ready-write-charge-use-drift",
            kernel_source.replace(
                "STREAM_WRITE_BASE_WORK + bytes.len() as u64",
                "bytes.len() as u64 + STREAM_WRITE_BASE_WORK",
                1,
            ),
        ),
        (
            "kernel-ready-close-charge-use-drift",
            kernel_source.replace(
                "HostResponse::unit(STREAM_CLOSE_WORK)?",
                "HostResponse::unit(STREAM_CLOSE_WORK + 1)?",
                1,
            ),
        ),
        (
            "kernel-required-read-line-comment-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                "return Ok(STREAM_READ_WORK + 1); "
                "// } return Ok(STREAM_READ_WORK); {",
                1,
            ),
        ),
        (
            "kernel-required-read-nested-block-comment-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                "return Ok(STREAM_READ_WORK + 1); "
                "/* outer } /* return Ok(STREAM_READ_WORK); */ { comment */",
                1,
            ),
        ),
        (
            "kernel-required-read-string-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                'let _decoy = "} return Ok(STREAM_READ_WORK); {"; '
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-byte-string-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                'let _decoy = b"} return Ok(STREAM_READ_WORK); {"; '
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-raw-string-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                'let _decoy = r###"} return Ok(STREAM_READ_WORK); {"###; '
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-byte-raw-string-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                'let _decoy = br###"} return Ok(STREAM_READ_WORK); {"###; '
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-c-string-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                'let _decoy = c"} return Ok(STREAM_READ_WORK); {"; '
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-c-raw-string-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                'let _decoy = cr###"} return Ok(STREAM_READ_WORK); {"###; '
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-dead-code-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                "if false { return Ok(STREAM_READ_WORK); } "
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
        (
            "kernel-required-read-stringify-decoy",
            kernel_source.replace(
                "return Ok(STREAM_READ_WORK);",
                "let _decoy = stringify!(return Ok(STREAM_READ_WORK);); "
                "return Ok(STREAM_READ_WORK + 1);",
                1,
            ),
        ),
    ]
    for name, candidate in kernel_charge_mutations:
        try:
            kernel_stream_work_charges(stream_chunk_limit(), candidate)
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted kernel charge mutation {name}")

    synthetic_meta, synthetic_samples, synthetic_end = synthetic_transcript_records()
    rank_vector = list(range(21))
    require(nearest_rank(rank_vector, 50) == 10, "nearest-rank p50 vector differs")
    require(nearest_rank(rank_vector, 95) == 19, "nearest-rank p95 vector differs")
    require(
        retained_stability_passes([100] * 19 + [150] * 2),
        "stability equality boundary was rejected",
    )
    require(
        not retained_stability_passes([100] * 19 + [151] * 2),
        "stability over-boundary vector was accepted",
    )
    require(
        synthetic_meta["run_id"]
        == "89be700330cb0f73f57ea5a18a8924b4ae356b7733e45c2335dbca7a80d6601a",
        "run-id known-answer vector differs",
    )
    require(
        synthetic_end["accumulator"] == 3_004_087_110_682_629_508,
        "accumulator known-answer vector differs",
    )
    synthetic_raw = serialize_transcript(synthetic_meta, synthetic_samples, synthetic_end)
    verified = verify_transcript_bytes(
        synthetic_raw,
        expected_source="a" * 40,
        expected_challenge="b" * 64,
    )
    summary = derive_boot_summary(verified, boot_index=0)
    verify_derived_summary(copy.deepcopy(summary), summary)

    maximum_meta, maximum_samples, maximum_end = synthetic_transcript_records()
    for sample in maximum_samples:
        sample["total_ticks"] = U64_MAX
        sample["phase_ticks"] = {phase: 0 for phase in PHASE_IDS}
        sample["phase_ticks"]["validation"] = U64_MAX
        sample["interval_count"] = 1
        sample["intervals"] = [
            {
                "sequence": 0,
                "phase": "validation",
                "start_offset_ticks": 0,
                "end_offset_ticks": U64_MAX,
            }
        ]
    maximum_end["accumulator"] = transcript_accumulator(maximum_samples)
    maximum_verified = verify_transcript_bytes(
        serialize_transcript(maximum_meta, maximum_samples, maximum_end),
        expected_source="a" * 40,
        expected_challenge="b" * 64,
    )
    maximum_summary = derive_boot_summary(maximum_verified, boot_index=2)
    maximum_summary_bytes = (
        json.dumps(maximum_summary, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    verify_derived_summary(
        strict_json_bytes(maximum_summary_bytes, "maximum-u64 boot summary"),
        maximum_summary,
    )

    def mutate_transcript(
        mutation: Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], None],
        *,
        refresh_accumulator: bool = False,
    ) -> bytes:
        meta, samples, ending = synthetic_transcript_records()
        mutation(meta, samples, ending)
        if refresh_accumulator:
            ending["accumulator"] = transcript_accumulator(samples)
        return serialize_transcript(meta, samples, ending)

    def swap_samples(
        _meta: dict[str, Any], samples: list[dict[str, Any]], _ending: dict[str, Any]
    ) -> None:
        samples[3], samples[4] = samples[4], samples[3]

    def adjacent_same_phase(
        _meta: dict[str, Any], samples: list[dict[str, Any]], _ending: dict[str, Any]
    ) -> None:
        sample = samples[3]
        interval = sample["intervals"][1]
        duration = interval["end_offset_ticks"] - interval["start_offset_ticks"]
        interval["phase"] = "validation"
        sample["phase_ticks"]["validation"] += duration
        sample["phase_ticks"]["instantiation"] = 0

    def valid_interval_change_with_stale_accumulator(
        _meta: dict[str, Any], samples: list[dict[str, Any]], _ending: dict[str, Any]
    ) -> None:
        sample = samples[3]
        sample["total_ticks"] += 1
        sample["phase_ticks"]["cleanup"] += 1
        sample["intervals"][-1]["end_offset_ticks"] += 1

    def unstable_retained(
        _meta: dict[str, Any], samples: list[dict[str, Any]], _ending: dict[str, Any]
    ) -> None:
        for index in (22, 23):
            sample = samples[index]
            interval = sample["intervals"][-1]
            interval["end_offset_ticks"] = 10_000
            sample["total_ticks"] = 10_000
            sample["phase_ticks"]["cleanup"] = 10_000 - interval["start_offset_ticks"]

    transcript_mutations: list[
        tuple[
            str,
            Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], None],
            bool,
        ]
    ] = [
        ("metadata-missing-field", lambda meta, _samples, _end: meta.pop("clock"), False),
        ("metadata-extra-field", lambda meta, _samples, _end: meta.update(extra=1), False),
        ("metadata-run-id", lambda meta, _samples, _end: meta.update(run_id="c" * 64), False),
        (
            "metadata-source",
            lambda meta, _samples, _end: meta.update(source_commit="c" * 40),
            False,
        ),
        (
            "metadata-challenge",
            lambda meta, _samples, _end: meta.update(challenge="c" * 64),
            False,
        ),
        (
            "metadata-manifest-hash",
            lambda meta, _samples, _end: meta.update(manifest_sha256="c" * 64),
            False,
        ),
        (
            "metadata-schema-hash",
            lambda meta, _samples, _end: meta.update(transcript_schema_sha256="c" * 64),
            False,
        ),
        (
            "metadata-scope",
            lambda meta, _samples, _end: meta.update(transcript_scope="three-cold-boots"),
            False,
        ),
        ("missing-sample", lambda _meta, samples, _end: samples.pop(), False),
        (
            "extra-sample",
            lambda _meta, samples, _end: samples.append(copy.deepcopy(samples[-1])),
            False,
        ),
        ("reordered-samples", swap_samples, False),
        (
            "sample-sequence",
            lambda _meta, samples, _end: samples[3].update(sequence=4),
            False,
        ),
        (
            "sample-index",
            lambda _meta, samples, _end: samples[3].update(sample_index=4),
            False,
        ),
        (
            "sample-warmup",
            lambda _meta, samples, _end: samples[3].update(warmup=True),
            False,
        ),
        (
            "sample-bool-as-int",
            lambda _meta, samples, _end: samples[3].update(warmup=0),
            False,
        ),
        (
            "sample-run-id",
            lambda _meta, samples, _end: samples[3].update(run_id="c" * 64),
            False,
        ),
        (
            "sample-challenge",
            lambda _meta, samples, _end: samples[3].update(challenge="c" * 64),
            False,
        ),
        (
            "sample-float",
            lambda _meta, samples, _end: samples[3].update(total_ticks=1.5),
            False,
        ),
        (
            "phase-total",
            lambda _meta, samples, _end: samples[3]["phase_ticks"].update(host=51),
            False,
        ),
        (
            "interval-count",
            lambda _meta, samples, _end: samples[3].update(interval_count=6),
            False,
        ),
        (
            "empty-intervals",
            lambda _meta, samples, _end: samples[3].update(interval_count=0, intervals=[]),
            False,
        ),
        (
            "interval-sequence",
            lambda _meta, samples, _end: samples[3]["intervals"][1].update(sequence=2),
            False,
        ),
        (
            "interval-gap",
            lambda _meta, samples, _end: samples[3]["intervals"][1].update(
                start_offset_ticks=11
            ),
            True,
        ),
        (
            "interval-overlap",
            lambda _meta, samples, _end: samples[3]["intervals"][1].update(
                start_offset_ticks=9
            ),
            True,
        ),
        (
            "interval-reversed",
            lambda _meta, samples, _end: samples[3]["intervals"][1].update(
                end_offset_ticks=10
            ),
            True,
        ),
        (
            "interval-phase",
            lambda _meta, samples, _end: samples[3]["intervals"][1].update(phase="other"),
            False,
        ),
        ("adjacent-same-phase", adjacent_same_phase, True),
        (
            "interval-tail",
            lambda _meta, samples, _end: samples[3]["intervals"][-1].update(
                end_offset_ticks=282
            ),
            True,
        ),
        (
            "interval-change-stale-accumulator",
            valid_interval_change_with_stale_accumulator,
            False,
        ),
        (
            "sample-incomplete",
            lambda _meta, samples, _end: samples[3].update(intervals_complete=False),
            False,
        ),
        (
            "sample-capacity",
            lambda _meta, samples, _end: samples[3].update(interval_capacity=4096),
            False,
        ),
        (
            "sample-fuel-zero",
            lambda _meta, samples, _end: samples[3].update(fuel_consumed=0),
            False,
        ),
        (
            "sample-fuel-over-budget",
            lambda _meta, samples, _end: samples[3].update(fuel_consumed=500_001),
            False,
        ),
        (
            "sample-polls-zero",
            lambda _meta, samples, _end: samples[3].update(poll_quanta=0),
            False,
        ),
        (
            "sample-output-hash",
            lambda _meta, samples, _end: samples[3].update(stdout_sha256="c" * 64),
            False,
        ),
        ("end-count", lambda _meta, _samples, end: end.update(samples=23), False),
        ("end-run-id", lambda _meta, _samples, end: end.update(run_id="c" * 64), False),
        (
            "end-challenge",
            lambda _meta, _samples, end: end.update(challenge="c" * 64),
            False,
        ),
        (
            "end-accumulator",
            lambda _meta, _samples, end: end.update(accumulator=end["accumulator"] ^ 1),
            False,
        ),
        (
            "end-accumulator-overflow",
            lambda _meta, _samples, end: end.update(accumulator=U64_MAX + 1),
            False,
        ),
        ("unstable-retained", unstable_retained, True),
    ]
    for name, mutation, refresh_accumulator in transcript_mutations:
        candidate = mutate_transcript(mutation, refresh_accumulator=refresh_accumulator)
        try:
            verify_transcript_bytes(
                candidate,
                expected_source="a" * 40,
                expected_challenge="b" * 64,
            )
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted transcript mutation {name}")

    raw_mutations = {
        "missing-meta": synthetic_raw.replace(
            next(line for line in synthetic_raw.splitlines(keepends=True) if line.startswith(META_PREFIX.encode())),
            b"",
            1,
        ),
        "missing-end": synthetic_raw.replace(
            next(line for line in synthetic_raw.splitlines(keepends=True) if line.startswith(END_PREFIX.encode())),
            b"",
            1,
        ),
        "duplicate-end": synthetic_raw
        + next(line for line in synthetic_raw.splitlines(keepends=True) if line.startswith(END_PREFIX.encode())),
        "prefixed-sample-marker": synthetic_raw.replace(
            SAMPLE_PREFIX.encode(), b"noise " + SAMPLE_PREFIX.encode(), 1
        ),
        "duplicate-json-member": synthetic_raw.replace(
            META_PREFIX.encode() + b"{",
            META_PREFIX.encode() + b'{"schema":"duplicate",',
            1,
        ),
        "fatal-after-end": synthetic_raw + b"[!] panic: after end\n",
        "non-utf8": synthetic_raw + b"\xff\n",
        "empty": b"",
        "oversized-integer": synthetic_raw.replace(
            b'"version":1',
            b'"version":' + b"1" * 5_000,
            1,
        ),
        "excessive-json-depth": synthetic_raw.replace(
            b'"version":1',
            b'"version":' + b"[" * 2_000 + b"1" + b"]" * 2_000,
            1,
        ),
    }
    for marker in FAILURE_MARKERS:
        raw_mutations[f"failure-marker-{marker}"] = synthetic_raw + marker.encode("ascii") + b"\n"
    for name, candidate in raw_mutations.items():
        try:
            verify_transcript_bytes(
                candidate,
                expected_source="a" * 40,
                expected_challenge="b" * 64,
            )
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted raw transcript mutation {name}")

    for name, source, challenge in (
        ("wrong-expected-source", "c" * 40, "b" * 64),
        ("wrong-expected-challenge", "a" * 40, "c" * 64),
    ):
        try:
            verify_transcript_bytes(
                synthetic_raw,
                expected_source=source,
                expected_challenge=challenge,
            )
        except VerificationError:
            rejected += 1
        else:
            raise VerificationError(f"selftest accepted {name}")

    changed_summary = copy.deepcopy(summary)
    changed_summary["statistics"]["total_ticks"]["p95"] += 1
    try:
        verify_derived_summary(changed_summary, summary)
    except VerificationError:
        rejected += 1
    else:
        raise VerificationError("selftest accepted changed boot summary")

    with tempfile.TemporaryDirectory(prefix="vibeos-c84-transcript-selftest-", dir="/tmp") as name:
        temporary_root = pathlib.Path(name)
        transcript_path = temporary_root / "uart.log"
        transcript_path.write_bytes(synthetic_raw)
        observed_raw, resolved_transcript = read_stable_regular_file(
            transcript_path,
            maximum_bytes=MAX_RAW_TRANSCRIPT_BYTES,
            label="selftest transcript",
        )
        require(observed_raw == synthetic_raw, "selftest stable transcript read differs")

        summary_path = temporary_root / "summary.json"
        summary_target = prepare_summary_output_target(
            summary_path,
            transcript=resolved_transcript,
            overwrite=False,
        )
        try:
            write_json_atomic(summary_target, summary)
            checked_raw = read_stable_regular_at(
                summary_target,
                maximum_bytes=MAX_BOOT_SUMMARY_BYTES,
                label="selftest summary",
            )
            verify_derived_summary(strict_json_bytes(checked_raw, "selftest summary"), summary)
        finally:
            os.close(summary_target.directory_fd)
        overwrite_target = prepare_summary_output_target(
            summary_path,
            transcript=resolved_transcript,
            overwrite=True,
        )
        try:
            write_json_atomic(overwrite_target, summary)
            overwritten_raw = read_stable_regular_at(
                overwrite_target,
                maximum_bytes=MAX_BOOT_SUMMARY_BYTES,
                label="selftest overwritten summary",
            )
            verify_derived_summary(
                strict_json_bytes(overwritten_raw, "selftest overwritten summary"),
                summary,
            )
        finally:
            os.close(overwrite_target.directory_fd)

        def reject_no_clobber_publish_race() -> None:
            race_path = temporary_root / "raced-summary.json"
            race_target = prepare_summary_output_target(
                race_path,
                transcript=resolved_transcript,
                overwrite=False,
            )
            sentinel = b"preexisting-race-winner\n"
            try:
                race_path.write_bytes(sentinel)
                try:
                    write_json_atomic(race_target, summary)
                except VerificationError:
                    if race_path.read_bytes() != sentinel:
                        raise RuntimeError("no-clobber race modified the winning file")
                    raise
            finally:
                os.close(race_target.directory_fd)

        def reject_replaced_output_parent() -> None:
            output_parent = temporary_root / "checked-output-parent"
            output_path = output_parent / "summary.json"
            target = prepare_summary_output_target(
                output_path,
                transcript=resolved_transcript,
                overwrite=True,
            )
            moved_parent = temporary_root / "moved-output-parent"
            replacement_parent = temporary_root / "replacement-output-parent"
            output_parent.rename(moved_parent)
            replacement_parent.mkdir()
            output_parent.symlink_to(replacement_parent, target_is_directory=True)
            try:
                try:
                    write_json_atomic(target, summary)
                except VerificationError:
                    if (replacement_parent / "summary.json").exists():
                        raise RuntimeError("replaced output parent received summary bytes")
                    raise
            finally:
                os.close(target.directory_fd)

        def reject_dirfd_fifo_read() -> None:
            fifo_output = temporary_root / "summary-output.fifo"
            target = prepare_summary_output_target(
                fifo_output,
                transcript=resolved_transcript,
                overwrite=False,
            )
            os.mkfifo(fifo_output, 0o600)
            try:
                read_stable_regular_at(
                    target,
                    maximum_bytes=MAX_BOOT_SUMMARY_BYTES,
                    label="selftest dirfd FIFO summary",
                )
            finally:
                os.close(target.directory_fd)

        rejection_checks: list[tuple[str, Callable[[], Any]]] = []
        transcript_alias = temporary_root / "transcript-alias.json"
        os.link(transcript_path, transcript_alias)
        rejection_checks.append(
            (
                "hardlink-output-alias",
                lambda: prepare_summary_output_target(
                    transcript_alias,
                    transcript=resolved_transcript,
                    overwrite=True,
                ),
            )
        )
        transcript_symlink = temporary_root / "transcript-symlink.log"
        transcript_symlink.symlink_to(transcript_path)
        rejection_checks.append(
            (
                "symlink-transcript",
                lambda: read_stable_regular_file(
                    transcript_symlink,
                    maximum_bytes=MAX_RAW_TRANSCRIPT_BYTES,
                    label="selftest symlink transcript",
                ),
            )
        )
        summary_symlink = temporary_root / "summary-symlink.json"
        summary_symlink.symlink_to(summary_path)
        rejection_checks.append(
            (
                "symlink-summary-output",
                lambda: prepare_summary_output_target(
                    summary_symlink,
                    transcript=resolved_transcript,
                    overwrite=True,
                ),
            )
        )
        empty_path = temporary_root / "empty.log"
        empty_path.touch()
        fifo_path = temporary_root / "serial.fifo"
        os.mkfifo(fifo_path, 0o600)
        rejection_checks.extend(
            [
                (
                    "existing-summary-no-clobber",
                    lambda: prepare_summary_output_target(
                        summary_path,
                        transcript=resolved_transcript,
                        overwrite=False,
                    ),
                ),
                ("no-clobber-publish-race", reject_no_clobber_publish_race),
                ("replaced-output-parent", reject_replaced_output_parent),
                ("dirfd-fifo-read", reject_dirfd_fifo_read),
                (
                    "stable-read-size-bound",
                    lambda: read_stable_regular_file(
                        transcript_path,
                        maximum_bytes=len(synthetic_raw) - 1,
                        label="selftest oversized transcript",
                    ),
                ),
                (
                    "empty-stable-input",
                    lambda: read_stable_regular_file(
                        empty_path,
                        maximum_bytes=MAX_RAW_TRANSCRIPT_BYTES,
                        label="selftest empty transcript",
                    ),
                ),
                (
                    "fifo-stable-input",
                    lambda: read_stable_regular_file(
                        fifo_path,
                        maximum_bytes=MAX_RAW_TRANSCRIPT_BYTES,
                        label="selftest FIFO transcript",
                    ),
                ),
            ]
        )
        for protected in VERIFIER_INPUT_PATHS:
            rejection_checks.append(
                (
                    f"protected-output-{protected.relative_to(ROOT)}",
                    lambda protected=protected: prepare_summary_output_target(
                        protected,
                        transcript=resolved_transcript,
                        overwrite=True,
                    ),
                )
            )
        for name, check in rejection_checks:
            try:
                check()
            except VerificationError:
                rejected += 1
            else:
                raise VerificationError(f"selftest accepted host-file mutation {name}")

    print(
        "verify-c84-aot-decision.py selftest: "
        f"PASS ({rejected} mutations rejected)"
    )


def file_stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_stable_regular_file(
    path: pathlib.Path,
    *,
    maximum_bytes: int,
    label: str,
) -> tuple[bytes, pathlib.Path]:
    resolved = path.resolve(strict=True)
    initial = os.lstat(path)
    require(stat.S_ISREG(initial.st_mode), f"{label} must be a regular file, not a symlink or special file")
    require(0 < initial.st_size <= maximum_bytes, f"{label} byte length is outside [1, {maximum_bytes}]")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        require(
            file_stat_identity(opened) == file_stat_identity(initial),
            f"{label} changed while it was opened",
        )
        raw = source.read(maximum_bytes + 1)
        after_read = os.fstat(source.fileno())
    final = os.lstat(path)
    expected_identity = file_stat_identity(initial)
    require(file_stat_identity(after_read) == expected_identity, f"{label} changed while it was read")
    require(file_stat_identity(final) == expected_identity, f"{label} path changed while it was read")
    require(
        file_stat_identity(os.stat(resolved, follow_symlinks=False)) == expected_identity,
        f"{label} resolved path changed while it was read",
    )
    require(len(raw) == initial.st_size, f"{label} read length differs from its stable size")
    return raw, resolved


def inode_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def require_output_directory_binding(target: SummaryOutputTarget) -> None:
    opened = os.fstat(target.directory_fd)
    require(
        inode_identity(opened) == (target.directory_device, target.directory_inode),
        "pinned summary output directory identity changed",
    )
    current = os.stat(target.directory_path, follow_symlinks=False)
    require(stat.S_ISDIR(current.st_mode), "summary output directory path is no longer a directory")
    require(
        inode_identity(current) == (target.directory_device, target.directory_inode),
        "summary output directory path was replaced",
    )


def read_stable_regular_at(
    target: SummaryOutputTarget,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    initial = os.stat(target.basename, dir_fd=target.directory_fd, follow_symlinks=False)
    require(stat.S_ISREG(initial.st_mode), f"{label} must be a regular file")
    require(0 < initial.st_size <= maximum_bytes, f"{label} byte length is outside [1, {maximum_bytes}]")
    descriptor = os.open(
        target.basename,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=target.directory_fd,
    )
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        require(
            file_stat_identity(opened) == file_stat_identity(initial),
            f"{label} changed while it was opened",
        )
        raw = source.read(maximum_bytes + 1)
        after_read = os.fstat(source.fileno())
    final = os.stat(target.basename, dir_fd=target.directory_fd, follow_symlinks=False)
    expected_identity = file_stat_identity(initial)
    require(file_stat_identity(after_read) == expected_identity, f"{label} changed while it was read")
    require(file_stat_identity(final) == expected_identity, f"{label} path changed while it was read")
    require(len(raw) == initial.st_size, f"{label} read length differs from its stable size")
    return raw


def write_json_atomic(target: SummaryOutputTarget, value: Any) -> None:
    require_output_directory_binding(target)
    rendered = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    require(len(rendered) <= MAX_BOOT_SUMMARY_BYTES, "derived boot summary exceeds its host bound")
    temporary_name: str | None = None
    descriptor: int | None = None
    for _attempt in range(128):
        candidate = f".vibeos-c84-summary-{os.getpid()}-{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=target.directory_fd,
            )
        except FileExistsError:
            continue
        temporary_name = candidate
        break
    require(descriptor is not None and temporary_name is not None, "cannot allocate summary temporary file")
    try:
        output_descriptor = descriptor
        descriptor = None
        with os.fdopen(output_descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        if target.overwrite:
            os.replace(
                temporary_name,
                target.basename,
                src_dir_fd=target.directory_fd,
                dst_dir_fd=target.directory_fd,
            )
        else:
            try:
                os.link(
                    temporary_name,
                    target.basename,
                    src_dir_fd=target.directory_fd,
                    dst_dir_fd=target.directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise VerificationError(
                    "summary output already exists; use --overwrite to replace a verified regular file"
                ) from error
            os.unlink(temporary_name, dir_fd=target.directory_fd)
            temporary_name = None
        os.fsync(target.directory_fd)
        require_output_directory_binding(target)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=target.directory_fd)
            except FileNotFoundError:
                pass


def prepare_summary_output_target(
    path: pathlib.Path,
    *,
    transcript: pathlib.Path,
    overwrite: bool,
) -> SummaryOutputTarget:
    require(path.name not in {"", ".", ".."}, "summary output must name a file")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    require(stat.S_ISDIR(os.lstat(parent).st_mode), "summary output parent is not a directory")
    directory_fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        directory_status = os.fstat(directory_fd)
        current_parent = os.stat(parent, follow_symlinks=False)
        require(
            stat.S_ISDIR(directory_status.st_mode)
            and inode_identity(directory_status) == inode_identity(current_parent),
            "summary output parent changed while it was opened",
        )
        forbidden_paths = {transcript, *(item.resolve(strict=True) for item in VERIFIER_INPUT_PATHS)}
        require(parent / path.name not in forbidden_paths, "summary output aliases a protected input")
        forbidden_identities = {
            inode_identity(os.stat(protected, follow_symlinks=False)) for protected in forbidden_paths
        }
        try:
            output_status = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            output_status = None
        if output_status is not None:
            require(
                stat.S_ISREG(output_status.st_mode),
                "existing summary output must be a regular file, not a symlink or special file",
            )
            require(
                inode_identity(output_status) not in forbidden_identities,
                "summary output aliases a protected input",
            )
            require(overwrite, "summary output already exists; use --overwrite to replace it")
        return SummaryOutputTarget(
            directory_path=parent,
            basename=path.name,
            directory_fd=directory_fd,
            directory_device=directory_status.st_dev,
            directory_inode=directory_status.st_ino,
            overwrite=overwrite,
        )
    except BaseException:
        os.close(directory_fd)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-manifest", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--transcript",
        type=pathlib.Path,
        help="semantically verify one raw transcript claiming the frozen physical-Duo envelope",
    )
    parser.add_argument(
        "--expect-source",
        help="40-hex preparation commit required with --transcript",
    )
    parser.add_argument(
        "--expect-challenge",
        help="fresh 256-bit campaign challenge required with --transcript",
    )
    parser.add_argument(
        "--boot-index",
        type=int,
        choices=range(3),
        metavar="{0,1,2}",
        help="host-assigned cold-boot index required with --transcript",
    )
    summary_group = parser.add_mutually_exclusive_group()
    summary_group.add_argument(
        "--summary-in",
        type=pathlib.Path,
        help="require a checked boot summary to exactly match fresh derivation",
    )
    summary_group.add_argument(
        "--summary-out",
        type=pathlib.Path,
        help="atomically write and recheck the derived single-boot summary",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing regular --summary-out after all input checks pass",
    )
    arguments = parser.parse_args()
    transcript_options = (
        arguments.expect_source,
        arguments.expect_challenge,
        arguments.boot_index,
        arguments.summary_in,
        arguments.summary_out,
        True if arguments.overwrite else None,
    )
    if arguments.transcript is None and any(value is not None for value in transcript_options):
        parser.error("transcript-only options require --transcript")
    if arguments.overwrite and arguments.summary_out is None:
        parser.error("--overwrite requires --summary-out")
    if not arguments.check_manifest and not arguments.selftest and arguments.transcript is None:
        parser.error("choose --check-manifest, --selftest, and/or --transcript")
    try:
        manifest, schema = load_contract_files()
        validate_manifest(manifest)
        validate_schema(schema)
        image_identity()
        openssh_fixture_identity()
        if arguments.selftest:
            selftest(manifest, schema)
        if arguments.transcript is not None:
            require(arguments.expect_source is not None, "--expect-source is required with --transcript")
            require(
                arguments.expect_challenge is not None,
                "--expect-challenge is required with --transcript",
            )
            require(arguments.boot_index is not None, "--boot-index is required with --transcript")
            raw, transcript_path = read_stable_regular_file(
                arguments.transcript,
                maximum_bytes=MAX_RAW_TRANSCRIPT_BYTES,
                label="raw transcript",
            )
            verified = verify_transcript_bytes(
                raw,
                expected_source=arguments.expect_source,
                expected_challenge=arguments.expect_challenge,
            )
            derived = derive_boot_summary(verified, boot_index=arguments.boot_index)
            summary_status = "derived-only"
            if arguments.summary_in is not None:
                checked_raw, _checked_path = read_stable_regular_file(
                    arguments.summary_in,
                    maximum_bytes=MAX_BOOT_SUMMARY_BYTES,
                    label="checked boot summary",
                )
                checked = strict_json_bytes(
                    checked_raw,
                    "checked boot summary",
                )
                verify_derived_summary(checked, derived)
                summary_status = "checked"
            if arguments.summary_out is not None:
                summary_target = prepare_summary_output_target(
                    arguments.summary_out,
                    transcript=transcript_path,
                    overwrite=arguments.overwrite,
                )
                try:
                    write_json_atomic(summary_target, derived)
                    written_raw = read_stable_regular_at(
                        summary_target,
                        maximum_bytes=MAX_BOOT_SUMMARY_BYTES,
                        label="written boot summary",
                    )
                    written = strict_json_bytes(
                        written_raw,
                        "written boot summary",
                    )
                    verify_derived_summary(written, derived)
                    post_manifest, post_schema = load_contract_files()
                    validate_manifest(post_manifest)
                    validate_schema(post_schema)
                    image_identity()
                    openssh_fixture_identity()
                    require_output_directory_binding(summary_target)
                finally:
                    os.close(summary_target.directory_fd)
                summary_status = "written"
            print(
                "PASS C8.4 single-raw transcript-semantics "
                "scope=single-boot-transcript-semantics-only-no-aot-decision "
                "physical_provenance=unverified cold_boot_provenance=unverified "
                f"source={verified.metadata['source_commit']} "
                f"challenge={verified.metadata['challenge']} "
                f"run_id={verified.metadata['run_id']} "
                f"boot_index={arguments.boot_index} "
                f"samples={len(verified.samples)} retained={RETAINED_PER_BOOT} "
                f"raw_sha256={verified.raw_sha256} summary={summary_status}"
            )
        if arguments.check_manifest:
            print(
                "PASS C8.4 AOT decision manifest "
                f"manifest_sha256={EXPECTED_MANIFEST_SHA256} "
                f"schema_sha256={EXPECTED_SCHEMA_SHA256}"
            )
        return 0
    except (OSError, UnicodeDecodeError, VerificationError) as error:
        print(f"FAIL verify-c84-aot-decision: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
