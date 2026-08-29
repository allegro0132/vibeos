#!/usr/bin/env python3
"""Verify the frozen C8.13-E1 Reference Types executable successor design."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "acceptance/wasm-reference-target/artifacts/"
    "c813-reference-executable-design-v1-contract.json"
)
BYTES = 4_616
SHA256 = "a1f20d7ebc64bd9bfdc32eade9728eb727ef4c92af4fc58fcca541280a694363"
POSITION = "c813-e1-reference-executable-design-frozen-pre-implementation"
LIVE_POSITION = "c813-e3-qualified-sealed-reference-runtime-released"
AUTHORIZATION = (
    ROOT
    / "acceptance/wasm-reference-target/artifacts/"
    "c812-r3-fixed-qemu-qualification-v1-contract.json"
)


class Failure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def read(path: Path) -> bytes:
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
        f"non-regular input: {path}",
    )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.read(descriptor, info.st_size + 1)
    finally:
        os.close(descriptor)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def validate(value: dict[str, Any]) -> None:
    require(
        value.get("schema") == "vibeos.c813.reference-executable-design-v1.contract"
        and value.get("version") == 1,
        "contract identity drift",
    )
    require(
        value.get("status")
        == "c813-e1-reference-executable-design-frozen-not-implemented-not-qualified-not-released",
        "status drift",
    )
    require(
        value.get("identity")
        == {
            "artifact_abi": 10,
            "artifact_profile_code": 10,
            "component_profile": 7,
            "core_profile": 7,
            "name": "PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE",
            "runtime_abi": 10,
            "stage": "executable",
        },
        "code-10 identity drift",
    )
    allocation = value.get("allocation", {})
    require(
        allocation
        == {
            "authorization_contract": "acceptance/wasm-reference-target/artifacts/c812-r3-fixed-qemu-qualification-v1-contract.json",
            "authorization_contract_sha256": "83a78e8fe9a02f9a7b32ab509a7895a89bfca10ce6c76f78d2499b8fac5671f7",
            "authorized_scope": "independently-numbered-reference-executable-successor-design-only",
            "code9_promoted": False,
            "new_artifact_profile_code": 10,
            "node": "C8.13-E1",
            "predecessor_validation_profile_code": 9,
        },
        "allocation drift",
    )
    require(
        value.get("basis")
        == {
            "source_commit": "e7ff1a8435d50e3e627ed7874e8242c76d450bbb",
            "source_tree": "365d610d735b8785aa43092bdcd371a5b58199dc",
        },
        "source basis drift",
    )
    engine = value.get("engine", {})
    require(
        engine.get("package_identity")
        == "vibeos-wasmi-reference-executable@1.1.0-vibeos-ref2.1"
        and engine.get("candidate_package") == "vibeos-wasmi-reference-executable"
        and engine.get("candidate_version") == "1.1.0-vibeos-ref2.1"
        and engine.get("source_base") == "vibeos-wasmi-softfloat@1.1.0-vibeos-f2.1"
        and engine.get("implementation_status")
        == "selected-for-c813-e2-facade-not-materialized"
        and engine.get("default_features") is False
        and engine.get("required_features")
        == ["extra-checks", "prefer-btree-collections"],
        "engine identity drift",
    )
    require(
        engine.get("wasmi_configuration")
        == {
            "bulk_memory": False,
            "consume_fuel": True,
            "floats": False,
            "memory64": False,
            "multi_memory": False,
            "reference_types": True,
            "simd": False,
            "threads": False,
        },
        "engine configuration drift",
    )
    require(
        value.get("revisions")
        == {
            "canonical_abi": "component-model-0.255.0-sync-no-core-reference-boundary-c813-reference-executable-v1",
            "component": "wasmparser-component-model-0.255.0-c813-reference-executable-v1",
            "core": "webassembly-core-2.0-reference-types-1.0-nullable-funcref-c813-executable-v1",
        },
        "revision drift",
    )
    world = value.get("world", {})
    require(
        world.get("identity") == "vibe:references/runtime@1.0.0"
        and world.get("exact_wit")
        == "package vibe:references@1.0.0;\nworld runtime {\n  export run: func(mode: u32, input: list<u8>) -> list<u8>;\n}\n"
        and world.get("resources") == 0
        and world.get("surface") == "authority-free-sync-integer-and-byte-boundary",
        "world drift",
    )
    semantics = value.get("semantics", {})
    require(
        semantics.get("bounded_core_internal_funcref") is True
        and semantics.get("nullable_funcref") is True
        and semantics.get("maximum_tables") == 1
        and semantics.get("active_element_segments") is True
        and semantics.get("deterministic_fuel") is True
        and semantics.get("host_boundary_integer_only") is True
        and semantics.get("reference_operations")
        == [
            "ref.null func",
            "ref.is_null",
            "ref.func",
            "typed-select-single-funcref",
            "table.get",
            "table.set",
            "table.grow",
            "table.size",
            "table.fill",
        ],
        "semantic surface drift",
    )
    boundaries = value.get("boundaries", {})
    required_false = {
        "aot",
        "bulk_memory",
        "code5_current_engine",
        "code7_current_engine",
        "code8_scope_changed",
        "code9_current_engine",
        "code9_execution_authorized",
        "code9_migration_authorized",
        "code9_promoted",
        "component_reference_values",
        "externref",
        "gc_semantics",
        "host_reference_values",
        "jit",
        "native_bytes",
        "rwx",
        "typed_function_references",
    }
    require(
        boundaries.get("code5_permanently_inert") is True
        and all(boundaries.get(key) is False for key in required_false),
        "authority boundary drift",
    )
    require(
        value.get("authority")
        == {
            "admission_authorized": False,
            "durable_publication_authorized": False,
            "execution_authorized": False,
            "migration_authorized": False,
            "ordinary_command_authorized": False,
            "production_authorized": False,
            "release_authorized": False,
            "runtime_ready": False,
        },
        "design-only authority drift",
    )
    require(
        value.get("qualification_policy")
        == {
            "duo_gate_effect": False,
            "fixed_qemu_is_hardware_equivalent": False,
            "physical_inputs_permitted": 0,
            "physical_inputs_required": 0,
            "platform": "qemu-virt-rv64-tcg-icount-v1",
        },
        "qualification policy drift",
    )
    require(
        value.get("nodes")
        == [
            {
                "exit_gate": "freeze-independent-code10-executable-design-engine-world-authority-and-qemu-policy",
                "id": "C8.13-E1",
            },
            {
                "exit_gate": "implement-executor-current-engine-sealed-volatile-admission-lifecycle-durable-rejection-supply-chain-and-riscv-audit",
                "id": "C8.13-E2",
            },
            {
                "exit_gate": "fresh-source-bound-normal-and-optimized-fixed-qemu-qualification-before-sealed-release",
                "id": "C8.13-E3",
            },
        ],
        "node ordering drift",
    )
    require(
        value.get("roadmap")
        == {
            "allocated_node": "C8.13",
            "completed_node": "C8.13-E1",
            "current_position": POSITION,
            "next_node": "C8.13-E2",
        },
        "roadmap drift",
    )


def verify_files(value: dict[str, Any]) -> None:
    authorization = read(AUTHORIZATION)
    require(
        hashlib.sha256(authorization).hexdigest()
        == value["allocation"]["authorization_contract_sha256"],
        "authorization contract identity drift",
    )
    authorization_value = json.loads(authorization)
    require(
        authorization_value.get("authority", {}).get(
            "successor_design_review_eligible"
        )
        is True
        and authorization_value.get("review", {}).get("allocated_successor") is False,
        "authorization scope missing",
    )
    result = subprocess.run(
        ["git", "rev-parse", f"{value['basis']['source_commit']}^{{tree}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    require(
        result.returncode == 0
        and result.stdout.strip() == value["basis"]["source_tree"],
        "source tree unavailable or drifted",
    )
    rust = "\n".join(
        read(ROOT / path).decode()
        for path in (
            "component-format/src/lib.rs",
            "component-format/src/engine.rs",
            "component-format/src/artifact.rs",
        )
    )
    require("PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE" in rust, "code 10 E2 materialization missing")
    cargo = read(ROOT / "Cargo.toml").decode()
    lock = read(ROOT / "Cargo.lock").decode()
    require(
        "wasmi-reference-executable" in cargo
        and "vibeos-wasmi-reference-executable" in lock,
        "selected E2 facade missing",
    )
    for path in (
        "docs/WASM_ROADMAP.md",
        "docs/WASM_REFERENCE_TYPES_EXECUTABLE_PROFILE.md",
        "TESTING.md",
    ):
        require(LIVE_POSITION in read(ROOT / path).decode(), f"live position missing: {path}")
    ci = read(ROOT / ".github/workflows/ci.yml").decode()
    require(
        "Verify the C8.13-E1 Reference Types executable successor design" in ci,
        "CI design step missing",
    )


def check() -> None:
    raw = read(CONTRACT)
    require(
        len(raw) == BYTES and hashlib.sha256(raw).hexdigest() == SHA256,
        "contract identity drift",
    )
    value = json.loads(raw)
    require(canonical(value) == raw, "contract not canonical")
    validate(value)
    verify_files(value)


def selftest() -> None:
    value = json.loads(read(CONTRACT))
    mutations = [
        ("identity.artifact_profile_code", 9),
        ("identity.stage", "validation-only"),
        ("allocation.code9_promoted", True),
        ("engine.default_features", True),
        ("engine.wasmi_configuration.floats", True),
        ("revisions.core", "floating"),
        ("semantics.maximum_tables", 2),
        ("boundaries.externref", True),
        ("boundaries.code5_permanently_inert", False),
        ("boundaries.code9_execution_authorized", True),
        ("authority.execution_authorized", True),
        ("authority.runtime_ready", True),
        ("qualification_policy.physical_inputs_required", 1),
        ("roadmap.next_node", "released"),
    ]
    rejected = 0
    for path, replacement in mutations:
        changed = copy.deepcopy(value)
        target: Any = changed
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = replacement
        try:
            validate(changed)
        except Failure:
            rejected += 1
    require(rejected == len(mutations), "mutation accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-contract", action="store_true")
    group.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        selftest() if args.selftest else check()
        print("C8.13-E1 Reference Types executable design verification: PASS")
        return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.13-E1 verification: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
