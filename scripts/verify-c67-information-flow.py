#!/usr/bin/env python3
"""Strict C6.7 semantic information-flow block verifier.

The verifier accepts one closed record schema and one exact target fixture. It
never interprets generic Debug output. Unknown, missing, duplicated, reordered,
or semantically changed fields fail closed.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path


BEGIN = "WASM_C67_INFORMATION_FLOW BEGIN"
END = "WASM_C67_INFORMATION_FLOW END"
PASS = (
    "WASM_C67_INFORMATION_FLOW PASS harts=4 nodes=3 edges=2 principal_policy_labels=3 "
    "typed_edges=2 async_edges=2 published=1 exact_render=1 negative_rejections=5 "
    "forbidden_classes=5 forbidden_hits=0 manifest_only=1 runtime_ready=0 guest_calls=0 "
    "registry_occupied=0 registry_header_mismatches=0"
)

SHAPE = (
    "interface{byte-stream:type=record{bytes:stream<u8>,closed:future<enum{normal,failure,"
    "cancelled,denied,unavailable,exhausted,invalid,backend-fault}>};bytes:type=stream<u8>;"
    "close-reason:type=enum{normal,failure,cancelled,denied,unavailable,exhausted,invalid,"
    "backend-fault};closed:type=future<enum{normal,failure,cancelled,denied,unavailable,"
    "exhausted,invalid,backend-fault}>;run:async-func(input:record{bytes:stream<u8>,closed:"
    "future<enum{normal,failure,cancelled,denied,unavailable,exhausted,invalid,backend-fault}>}"
    ")->record{bytes:stream<u8>,closed:future<enum{normal,failure,cancelled,denied,unavailable,"
    "exhausted,invalid,backend-fault}>}}"
)

EXPECTED_LINES = [
    'graph policy="c67-information-flow" runtime_ready=false nodes=3 internal=2 external=0 authorities=0 published=1',
    'node policy="input.untrusted" world="test:c65-chain/source@1.0.0" parent=root',
    'node policy="output.approved" world="test:c65-chain/sink@1.0.0" parent=root',
    'node policy="transform.filtered" world="test:c65-chain/relay@1.0.0" parent=root',
    (
        'internal source_policy="input.untrusted" source_entity="test:c65-chain/pipe@1.0.0" '
        'target_policy="transform.filtered" target_entity="test:c65-chain/pipe@1.0.0" '
        f'shape="{SHAPE}" exact_type=true resource_mode=none resources=[] '
        'async_functions=1 streams=4 futures=4'
    ),
    (
        'internal source_policy="transform.filtered" source_entity="test:c65-chain/pipe@1.0.0" '
        'target_policy="output.approved" target_entity="test:c65-chain/pipe@1.0.0" '
        f'shape="{SHAPE}" exact_type=true resource_mode=none resources=[] '
        'async_functions=1 streams=4 futures=4'
    ),
    (
        'published source_policy="output.approved" source_entity="test:c65-chain/pipe@1.0.0" '
        f'shape="{SHAPE}"'
    ),
]

SCHEMA = {
    "graph": [
        "policy",
        "runtime_ready",
        "nodes",
        "internal",
        "external",
        "authorities",
        "published",
    ],
    "node": ["policy", "world", "parent"],
    "internal": [
        "source_policy",
        "source_entity",
        "target_policy",
        "target_entity",
        "shape",
        "exact_type",
        "resource_mode",
        "resources",
        "async_functions",
        "streams",
        "futures",
    ],
    "published": ["source_policy", "source_entity", "shape"],
}

FORBIDDEN = [
    "resource_index",
    "guest_index",
    "ResourceToken",
    "ResourceTypeId",
    "ComponentGraphNodeId",
    "ComponentGraphEntityIndex",
    "cap:",
    "Cap {",
    "slot=",
    "generation",
    "pointer",
    "address",
    "0x",
    "ObjectId",
    "SpaceId",
    "DerivationId",
    "durable",
    "artifact",
    "digest",
    "sha256",
    "ComponentIdentity",
    "TaskId",
    "CSpace",
    "OwnerId",
    "ArenaId",
    "AllocationDomain",
    "InstanceToken",
    "HostOperationToken",
    "incarnation",
    "runtime_abi",
]


class VerificationError(Exception):
    pass


def normalize_lines(raw: str) -> list[str]:
    return [line for line in raw.replace("\r", "\n").splitlines() if line]


def exact_occurrence(lines: list[str], marker: str) -> list[int]:
    return [index for index, line in enumerate(lines) if line == marker]


def parse_record(line: str) -> tuple[str, list[tuple[str, str]]]:
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError as error:
        raise VerificationError(f"invalid quoting: {error}") from error
    if not tokens:
        raise VerificationError("empty record")
    record = tokens[0]
    expected_keys = SCHEMA.get(record)
    if expected_keys is None:
        raise VerificationError(f"unknown record: {record}")
    fields: list[tuple[str, str]] = []
    for token in tokens[1:]:
        if "=" not in token:
            raise VerificationError(f"unkeyed token in {record}: {token}")
        key, value = token.split("=", 1)
        fields.append((key, value))
    keys = [key for key, _ in fields]
    if keys != expected_keys:
        raise VerificationError(
            f"{record} keys/order differ: observed={keys!r} expected={expected_keys!r}"
        )
    if len(keys) != len(set(keys)):
        raise VerificationError(f"duplicate key in {record}")
    return record, fields


def verify_report_lines(lines: list[str]) -> None:
    block = "\n".join(lines)
    leaked = [token for token in FORBIDDEN if token in block]
    if leaked:
        raise VerificationError(f"forbidden diagnostic token(s): {leaked!r}")
    if re.search(r"(?i)[0-9a-f]{16,}", block):
        raise VerificationError("long hexadecimal identity/address run")
    if len(lines) != len(EXPECTED_LINES):
        raise VerificationError(
            f"record count differs: observed={len(lines)} expected={len(EXPECTED_LINES)}"
        )
    for line in lines:
        parse_record(line)
    if lines != EXPECTED_LINES:
        for index, (observed, expected) in enumerate(zip(lines, EXPECTED_LINES), start=1):
            if observed != expected:
                raise VerificationError(
                    f"golden record {index} differs\nobserved: {observed}\nexpected: {expected}"
                )
        raise VerificationError("golden block differs")


def verify_transcript(raw: str) -> None:
    lines = normalize_lines(raw)
    begins = exact_occurrence(lines, BEGIN)
    ends = exact_occurrence(lines, END)
    passes = exact_occurrence(lines, PASS)
    if len(begins) != 1 or len(ends) != 1 or len(passes) != 1:
        raise VerificationError(
            f"marker counts begin={len(begins)} end={len(ends)} pass={len(passes)}"
        )
    if not (begins[0] < ends[0] < passes[0]):
        raise VerificationError("BEGIN/END/PASS order is invalid")
    if any(line == "WASM_C67_INFORMATION_FLOW FAIL" for line in lines):
        raise VerificationError("guest reported C6.7 failure")
    if any(re.search(r"\[!\] (fatal|panic)|panicked at", line) for line in lines):
        raise VerificationError("guest reported panic/fatal output")
    verify_report_lines(lines[begins[0] + 1 : ends[0]])


def verify_log(path: Path) -> None:
    verify_transcript(path.read_bytes().decode("utf-8", errors="replace"))


def expect_rejected(lines: list[str], label: str) -> None:
    try:
        verify_report_lines(lines)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def selftest() -> None:
    verify_report_lines(EXPECTED_LINES.copy())
    valid_transcript = "\n".join([BEGIN, *EXPECTED_LINES, END, PASS])
    verify_transcript(valid_transcript)

    forbidden_mutations = {
        "resource-index": " resource_index=7",
        "cap-slot-generation": " cap:3.9 slot=3 generation=9",
        "pointer": " pointer=0x1234",
        "durable-artifact": " ObjectId=11 durable artifact digest=deadbeefdeadbeef",
        "runtime-identity": " TaskId=5 CSpace=guest OwnerId=7 ArenaId=8",
    }
    for label, suffix in forbidden_mutations.items():
        mutated = EXPECTED_LINES.copy()
        mutated[0] += suffix
        expect_rejected(mutated, label)

    semantic_mutations = {
        "policy-label": (1, "input.untrusted", "input.trusted"),
        "world-version": (1, "@1.0.0", "@2.0.0"),
        "effect": (4, "async-func", "func"),
        "edge-direction": (4, "transform.filtered", "output.approved"),
        "async-count": (4, "streams=4", "streams=3"),
    }
    for label, (index, old, new) in semantic_mutations.items():
        mutated = EXPECTED_LINES.copy()
        mutated[index] = mutated[index].replace(old, new, 1)
        expect_rejected(mutated, label)

    missing = EXPECTED_LINES.copy()
    missing.pop()
    expect_rejected(missing, "missing-record")
    duplicated = EXPECTED_LINES.copy()
    duplicated.insert(1, duplicated[1])
    expect_rejected(duplicated, "duplicate-record")
    reordered = EXPECTED_LINES.copy()
    reordered[1], reordered[2] = reordered[2], reordered[1]
    expect_rejected(reordered, "reordered-record")

    embedded_clear = EXPECTED_LINES.copy()
    embedded_clear[0] = embedded_clear[0].replace("graph ", "graph\x1b[2K ", 1)
    expect_rejected(normalize_lines("\n".join(embedded_clear)), "embedded-terminal-escape")
    for label, suffix in [
        ("post-pass-fail", "\nWASM_C67_INFORMATION_FLOW FAIL"),
        ("post-pass-panic", "\npanicked at synthetic post-pass fault"),
    ]:
        try:
            verify_transcript(valid_transcript + suffix)
        except VerificationError:
            continue
        raise VerificationError(f"selftest transcript unexpectedly accepted: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if not args.selftest and args.log is None:
        parser.error("provide --selftest and/or a QEMU log")
    try:
        if args.selftest:
            selftest()
        if args.log is not None:
            verify_log(args.log)
    except (OSError, VerificationError) as error:
        print(f"FAIL verify-c67-information-flow: {error}", file=sys.stderr)
        return 1
    print("PASS verify-c67-information-flow: closed schema and mutation gates accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
