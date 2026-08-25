#!/usr/bin/env python3
"""Independently verify the frozen C8.4 AOT-decision preparation contract.

This host-only verifier uses only Python's standard library.  It does not run
the guest, compile WAT, or accept profiling results.  It binds the checked-in
contract to the executable image policy and to the exact OpenSSH product
fixture, then checks the closed manifest and transcript-schema descriptions.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable


ROOT = pathlib.Path(__file__).resolve().parent.parent
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

# Filled from the reviewed files below.  Byte identity is intentionally
# independent of JSON parsing and makes formatting changes review-visible.
EXPECTED_MANIFEST_SHA256 = "5eb32eaec43b456b8c5fa1428464e27d869419e79d4eb29a5512182d04b5e8e5"
EXPECTED_SCHEMA_SHA256 = "ea0646f06f0f0b03d0e9b6286e802de9138e6b5cd085cd4e8d7648d8c1bf4d33"
EXPECTED_WAT_SHA256 = "6db36b58350c4de22077fba4dd9dd1166f0808e2adc8488ba086d91c6f659cc1"
EXPECTED_COMPONENT_SHA256 = "180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72"
EXPECTED_COMPONENT_BYTES = 2012
EXPECTED_BUILD_SOURCE_SHA256 = "ca0d4f100d136d26c0ac1e1beeb0919b12c8f8a9e2345d15b6284b041e6ed74e"
EXPECTED_POLICY_SOURCE_SHA256 = "d4912916f8407ddcb4ae7914186f6d567468896c72a39da0ddbbe957d1a7b2e0"
EXPECTED_OPENSSH_SOURCE_SHA256 = "00d5002a8f2725c275995b1eff5d469f1d1eac1741b1eaef3f3623c3c746ac8c"
EXPECTED_WIT_SHA256 = "61710f784d4814d87a9a5542edfb2e43bc2844fc04df679fd19490932038039a"
EXPECTED_KERNEL_STREAM_CHARGE_SCOPES_SHA256 = (
    "446e14cd17439d5199135f710d91eadb63bc89d4c24a3d1ca60783e3051fef4d"
)
EXPECTED_KERNEL_COMPONENT_INSTANCES_SOURCE_SHA256 = (
    "107061bbffe2886ec48919a0912505858b14242f04bfcf4b0ca5974b8d25fdca"
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
    "completeness": "each of three physical cold boots has exactly three warmups then twenty-one retained samples; every coordinate occurs once",
    "correctness": "every sample exits zero, emits the exact 12325-byte output hash, and emits empty stderr",
    "successful_samples_only": "timed-out, trapped, failed, truncated, or otherwise non-successful attempts are diagnostic records outside the formal dataset and can never authorize AOT",
    "phase_partition": "intervals are ordered, gap-free, non-overlapping, and labeled with exactly one of seven phases; total_ticks equals both the response interval and the sum of phase_ticks",
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
U64_MAX = (1 << 64) - 1
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


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
    def reject_number(token: str) -> Any:
        raise VerificationError(f"{label} contains unsupported JSON number {token}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_members,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
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
    require(sha256_file(MANIFEST_PATH) == EXPECTED_MANIFEST_SHA256, "manifest byte identity differs")
    require(sha256_file(SCHEMA_PATH) == EXPECTED_SCHEMA_SHA256, "schema byte identity differs")
    manifest = strict_json_bytes(MANIFEST_PATH.read_bytes(), "manifest")
    schema = strict_json_bytes(SCHEMA_PATH.read_bytes(), "schema")
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

    phase_tick_properties = {
        phase: {"type": "integer", "minimum": 0} for phase in PHASE_IDS
    }
    interval_properties = {
        "sequence": {"type": "integer", "minimum": 0},
        "phase": {"$ref": "#/$defs/phase"},
        "start_offset_ticks": {"type": "integer", "minimum": 0},
        "end_offset_ticks": {"type": "integer", "minimum": 1},
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
        "cold_boots": {"const": 3},
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
        "sequence": {"type": "integer", "minimum": 0},
        "cold_boot_index": {"type": "integer", "minimum": 0, "maximum": 2},
        "sample_index": {"type": "integer", "minimum": 0, "maximum": 23},
        "warmup": {"type": "boolean"},
        "workload_id": {"const": "ssh-case-filter-12k-v1"},
        "total_ticks": {"type": "integer", "minimum": 1},
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
        "fuel_consumed": {"type": "integer", "minimum": 0},
        "poll_quanta": {"type": "integer", "minimum": 0},
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
        "cold_boots": {"const": 3},
        "samples": {"const": 72},
        "warmups": {"const": 9},
        "retained": {"const": 63},
        "accumulator": {"type": "integer", "minimum": 0},
    }
    expected = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://vibeos.invalid/schemas/wasm-aot-decision-v1.json",
        "title": "VibeOS C8.4 physical AOT-decision transcript records",
        "oneOf": [
            {"$ref": "#/$defs/meta"},
            {"$ref": "#/$defs/sample"},
            {"$ref": "#/$defs/end"},
        ],
        "$defs": {
            "hex40": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "phase": {"type": "string", "enum": list(PHASE_IDS)},
            "phaseTicks": closed(phase_tick_properties, list(PHASE_IDS)),
            "interval": closed(interval_properties, list(interval_properties)),
            "meta": closed(meta_properties, list(meta_properties)),
            "sample": closed(sample_properties, list(sample_properties)),
            "end": closed(end_properties, list(end_properties)),
        },
    }
    exact_literal(value, expected, "transcript schema")


def selftest(manifest: dict[str, Any], schema: dict[str, Any]) -> None:
    validate_manifest(manifest)
    validate_schema(schema)

    manifest_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("missing-top-field", lambda value: value.pop("budget")),
        ("extra-top-field", lambda value: value.update(extra=None)),
        ("missing-policy-field", lambda value: value["fixture"]["policy"].pop("world")),
        ("extra-policy-field", lambda value: value["fixture"]["policy"].update(extra=1)),
        ("bool-as-integer", lambda value: value["sampling"].update(cold_boots=True)),
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
    ]
    schema_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("schema-id-drift", lambda value: value.update({"$id": "https://example.invalid/other"})),
        ("schema-extra-field", lambda value: value.update(extra=True)),
        ("schema-missing-def", lambda value: value["$defs"].pop("interval")),
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

    print(
        "verify-c84-aot-decision.py selftest: "
        f"PASS ({rejected} mutations rejected)"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-manifest", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    if not arguments.check_manifest and not arguments.selftest:
        parser.error("choose --check-manifest and/or --selftest")
    try:
        manifest, schema = load_contract_files()
        validate_manifest(manifest)
        validate_schema(schema)
        image_identity()
        openssh_fixture_identity()
        if arguments.selftest:
            selftest(manifest, schema)
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
