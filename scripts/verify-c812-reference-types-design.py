#!/usr/bin/env python3
"""Verify the frozen C8.12-R1 Reference Types validation design."""

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
CONTRACT = ROOT / "acceptance/wasm-reference-target/artifacts/c812-reference-types-design-v1-contract.json"
CONTRACT_BYTES = 8_780
CONTRACT_SHA256 = "ed8fdbe4964b7a42967258dabb5871c360899d1006666a7f9ab54c6b5f33db42"
BASIS_COMMIT = "4402f76fa2adb690ee591f81bbca0f3588dd089e"
BASIS_TREE = "d7049e03b9c6a212b2a86377b42c752e9da5977d"
POSITION = "c812-r1-reference-types-validation-design-frozen-pre-implementation"
LIVE_POSITION = "c812-r2-reference-types-validation-implemented-pre-fixed-qemu"
COMMANDS = (
    "python3 -B scripts/verify-c812-reference-types-design.py --check-contract",
    "python3 -O -B scripts/verify-c812-reference-types-design.py --check-contract",
    "python3 -B scripts/verify-c812-reference-types-design.py --selftest",
    "python3 -O -B scripts/verify-c812-reference-types-design.py --selftest",
)


class Failure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def read_regular(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), f"non-regular input: {path}")
    require(before.st_nlink == 1 and before.st_size <= maximum, f"unsafe input: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), f"raced input: {path}")
        data = os.read(descriptor, opened.st_size + 1)
        require(len(data) == opened.st_size, f"short or growing input: {path}")
        return data
    finally:
        os.close(descriptor)


def strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"duplicate key: {key}")
            result[key] = value
        return result

    value = json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_float=lambda value: (_ for _ in ()).throw(Failure(f"float: {value}")),
        parse_constant=lambda value: (_ for _ in ()).throw(Failure(f"constant: {value}")),
    )
    require(type(value) is dict, "JSON root is not an object")
    return value


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def git(*arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(ROOT),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        },
    )
    require(result.returncode == 0, f"git {' '.join(arguments)} failed")
    return result.stdout


def validate(value: dict[str, Any]) -> None:
    require(value.get("schema") == "vibeos.c812.reference-types-design-v1.contract", "schema drift")
    require(value.get("version") == 1 and value.get("status") == "c812-r1-design-frozen-not-implemented-not-qualified-not-released", "status drift")

    allocation = value.get("allocation_authority", {})
    require(allocation.get("basis_commit") == BASIS_COMMIT and allocation.get("basis_tree") == BASIS_TREE, "allocation basis drift")
    require(allocation.get("source") == "standing-user-wasm-roadmap-goal", "allocation authority drift")
    require(allocation.get("user_selected_code5_promotion") is False and allocation.get("user_selected_physical_duo_gate") is False, "forbidden user selection")

    identity = value.get("identity", {})
    require(identity.get("name") == "PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION", "identity name drift")
    require([identity.get(key) for key in ("artifact_profile_code", "artifact_abi", "runtime_abi")] == [9, 9, 9], "code or ABI drift")
    require([identity.get(key) for key in ("component_profile", "core_profile")] == [6, 6] and identity.get("execution_stage") == "validation-only", "profile or stage drift")
    require(identity.get("core_wasm_revision") == "webassembly-core-2.0-reference-types-1.0-nullable-funcref-c812-validation-v1", "Core revision drift")
    require(identity.get("component_model_revision") == "wasmparser-component-model-0.255.0-c812-ref-validation-v1", "Component revision drift")
    require(identity.get("canonical_abi_revision") == "component-model-0.255.0-sync-no-core-reference-boundary-c812-ref-validation-v1", "Canonical ABI revision drift")
    require(identity.get("canonical_features") == ["utf8", "sync-lift-lower", "resources"], "Canonical feature drift")
    world = identity.get("wit_world", {})
    require(world.get("identity") == "vibe:references/validation@1.0.0" and world.get("imports") == [], "WIT world drift")
    require(world.get("core_references_cross_component_boundary") is False, "Core reference boundary widened")

    engine = value.get("engine_selection", {})
    require(engine.get("package") == "vibeos-wasmi-reference-validation" and engine.get("version") == "1.1.0-vibeos-ref1.1", "engine identity drift")
    require(engine.get("base_package") == "vibeos-wasmi-softfloat" and engine.get("base_version") == "1.1.0-vibeos-f2.1", "engine base drift")
    require(engine.get("feature_set") == "default-features=false,extra-checks,prefer-btree-collections;simd=false", "engine feature drift")
    require(engine.get("implementation_status") == "selected-for-c812-r2-facade-not-materialized", "engine materialization drift")

    semantics = value.get("semantics", {})
    require(semantics.get("proposal") == "webassembly-reference-types-1.0-bounded-nullable-funcref", "proposal drift")
    require(semantics.get("numeric_profile") == "profile1-integer-only", "numeric profile widened")
    require(semantics.get("externref") == "forbidden" and semantics.get("component_core_reference_boundary") == "forbidden", "reference boundary widened")
    require(
        semantics.get("allowed_core_reference_forms")
        == [
            "nullable-funcref",
            "ref.null-func",
            "ref.is_null",
            "ref.func",
            "typed-select-single",
            "funcref-tables",
            "table.get",
            "table.set",
            "table.size",
            "table.grow",
            "table.fill",
            "single-table-only",
            "active-element-segments-only",
        ],
        "allowed Reference Types surface drift",
    )
    dependency = semantics.get("engine_parser_dependency", {})
    require(dependency == {"gc_types_bit_required_by_wasmi_api": True, "gc_types_semantics_enabled": False, "reference_types_bit": True}, "parser/semantic dependency drift")
    forbidden = semantics.get("forbidden_adjacent_features", [])
    for feature in ("floats", "simd", "typed-function-references", "gc-structs-arrays-i31", "exceptions", "memory64", "multiple-memories", "threads", "bulk-memory"):
        require(feature in forbidden, f"forbidden feature missing: {feature}")

    code5 = value.get("code5_boundary", {})
    require(code5.get("artifact_profile_code") == 5 and code5.get("permanent") is True and code5.get("inert") is True, "code 5 permanence drift")
    require(code5.get("stage") == "validation-only" and code5.get("current_engine") is False and code5.get("migration_authorized") is False, "code 5 boundary drift")
    code7 = value.get("code7_boundary", {})
    require(code7.get("artifact_profile_code") == 7 and code7.get("stage") == "validation-only" and code7.get("current_engine") is False, "code 7 boundary drift")
    require(code7.get("execution_authorized") is False and code7.get("migration_authorized") is False, "code 7 authority widened")
    code8 = value.get("code8_boundary", {})
    require(code8 == {"artifact_profile_code": 8, "identity": "PROFILE_5_SYNC_SIMD_EXECUTABLE", "reference_types_enabled": False, "release_scope_unchanged": True, "stage": "executable"}, "code 8 scope drift")

    authority = value.get("authority", {})
    require(authority.get("design_authorized") is True and authority.get("implementation_authorized") is True, "design/implementation authority missing")
    for key in ("admission_authorized", "aot_authorized", "command_authorized", "current_engine_binding_authorized", "durable_publication_authorized", "in_place_promotion_authorized", "jit_authorized", "migration_authorized", "native_bytes_authorized", "production_authorized", "release_authorized", "rwx_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")

    plan = value.get("implementation_plan", [])
    require([item.get("id") for item in plan] == ["C8.12-R1", "C8.12-R2", "C8.12-R3"], "plan order drift")
    require([item.get("complete") for item in plan] == [True, False, False], "plan completion drift")
    roadmap = value.get("roadmap", {})
    require(roadmap.get("allocated_node") == "C8.12" and roadmap.get("current_position") == POSITION, "roadmap drift")
    require(roadmap.get("implementation_node") == "C8.12-R2" and roadmap.get("qualification_node") == "C8.12-R3", "next-node drift")

    hardware = value.get("hardware_policy", {})
    require(hardware.get("duo_inputs_required") == 0 and hardware.get("duo_inputs_permitted") == 0 and hardware.get("duo_gate_effect") is False, "Duo gate drift")
    require(hardware.get("fixed_qemu_is_hardware_equivalent") is False and hardware.get("other_hardware_gates_unchanged") is True, "hardware claim drift")
    target = value.get("target_policy", {})
    require(target.get("baseline") == "qemu-virt-rv64-tcg-icount-v1" and target.get("normal_and_optimized_required") is True, "fixed-QEMU policy drift")
    for key in ("fresh_capture_required", "fresh_challenge_required", "fresh_node_specific_contract_required", "fresh_run_id_required", "fresh_source_commit_and_tree_required"):
        require(target.get(key) is True, f"fresh-evidence requirement missing: {key}")
    require(target.get("qualification_status") == "not-started" and target.get("release_status") == "not-authorized", "premature qualification or release")


def verify_historical(record: dict[str, Any]) -> None:
    raw = git("show", f"{BASIS_COMMIT}:{record['path']}")
    require(len(raw) == record["bytes"] and hashlib.sha256(raw).hexdigest() == record["sha256"], f"historical identity drift: {record['path']}")


def verify_repository(value: dict[str, Any]) -> None:
    require(git("rev-parse", f"{BASIS_COMMIT}^{{tree}}").decode().strip() == BASIS_TREE, "basis tree drift")
    verify_historical(value["predecessor"]["qualification_contract"])
    verify_historical(value["predecessor"]["release_decision"])
    base = value["engine_selection"]["base_source"]
    require(git("rev-parse", f"{base['commit']}:{base['path']}").decode().strip() == base["git_tree"], "engine base tree drift")
    provenance = git("show", f"{base['commit']}:{base['path']}/PROVENANCE.toml")
    require(len(provenance) == base["provenance_bytes"] and hashlib.sha256(provenance).hexdigest() == base["provenance_sha256"], "engine provenance drift")

    roots = ("component-format/", "component-runtime/", "wasm-runtime/", "services/component-admission/", "services/component-loader/", "kernel/")
    for path in git("ls-tree", "-r", "--name-only", BASIS_COMMIT).decode().splitlines():
        if path.endswith(".rs") and path.startswith(roots):
            require(b"PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION" not in git("show", f"{BASIS_COMMIT}:{path}"), f"code 9 existed at basis: {path}")
    engine_source = read_regular(ROOT / "component-format/src/engine.rs").decode()
    require("ProfileIdentity::PROFILE_2_SYNC_FLOAT {\n        None" in engine_source, "code 5 current-engine rejection missing")
    require("ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION {\n        None" in engine_source, "code 7 current-engine rejection missing")
    require("reference_types: false" in engine_source, "Profile-1 reference-types closure missing")

    roadmap = read_regular(ROOT / "docs/WASM_ROADMAP.md").decode()
    profile = read_regular(ROOT / "docs/WASM_REFERENCE_TYPES_PROFILE.md").decode()
    testing = read_regular(ROOT / "TESTING.md").decode()
    ci = read_regular(ROOT / ".github/workflows/ci.yml").decode()
    require(POSITION in roadmap and LIVE_POSITION in roadmap and LIVE_POSITION in profile, "live position missing")
    require("## 9.4 C8.12 independent Reference Types validation widening" in roadmap, "roadmap section missing")
    require("# Reference Types validation profile" in profile, "profile document missing")
    require("## C8.12-R1 Reference Types validation design" in testing, "TESTING section missing")
    require("Verify the C8.12-R1 Reference Types validation design" in ci, "CI step missing")
    for command in COMMANDS:
        require(testing.count(command) == 1, f"TESTING command drift: {command}")
        require(ci.count(command) == 1, f"CI command drift: {command}")


def verify_live() -> None:
    raw = read_regular(CONTRACT)
    require(len(raw) == CONTRACT_BYTES, "contract byte length drift")
    require(hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256, "contract hash drift")
    value = strict_json(raw)
    require(raw == canonical(value), "contract is not canonical JSON")
    validate(value)
    verify_repository(value)


def selftest() -> None:
    original = strict_json(read_regular(CONTRACT))
    mutations: list[tuple[str, Any]] = [
        ("identity.artifact_profile_code", 8),
        ("identity.artifact_abi", 8),
        ("identity.runtime_abi", 8),
        ("identity.execution_stage", "executable"),
        ("identity.wit_world.core_references_cross_component_boundary", True),
        ("engine_selection.version", "1.1.0"),
        ("semantics.numeric_profile", "float"),
        ("semantics.externref", "enabled"),
        ("semantics.engine_parser_dependency.gc_types_semantics_enabled", True),
        ("semantics.allowed_core_reference_forms.12", "passive-element-segments"),
        ("code5_boundary.current_engine", True),
        ("code5_boundary.inert", False),
        ("code7_boundary.execution_authorized", True),
        ("code8_boundary.reference_types_enabled", True),
        ("authority.current_engine_binding_authorized", True),
        ("authority.release_authorized", True),
        ("hardware_policy.duo_inputs_required", 1),
        ("target_policy.fresh_capture_required", False),
        ("implementation_plan.1.complete", True),
        ("roadmap.current_position", "released"),
    ]
    for index, (path, replacement) in enumerate(mutations):
        changed: Any = copy.deepcopy(original)
        parts = path.split(".")
        target = changed
        for part in parts[:-1]:
            target = target[int(part)] if part.isdigit() else target[part]
        last = parts[-1]
        if last.isdigit():
            target[int(last)] = replacement
        else:
            target[last] = replacement
        try:
            validate(changed)
        except Failure:
            continue
        raise Failure(f"mutation {index} was accepted: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-contract", action="store_true")
    group.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    try:
        selftest() if arguments.selftest else verify_live()
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.12-R1 design verification: FAIL: {error}", file=sys.stderr)
        return 1
    print("C8.12-R1 Reference Types design verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
