#!/usr/bin/env python3
"""Verify the frozen C8.12-R2 Reference Types implementation closure."""

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
CONTRACT = ROOT / "acceptance/wasm-reference-target/artifacts/c812-reference-types-implementation-v1-contract.json"
BYTES = 5_108
SHA256 = "4a1f216a79a4364d3bd34e4a3bbf4ed98246e5f9a6f31270b7d1dea36045f9dd"
DESIGN_COMMIT = "d8032d7fab63fe02fb6b53dfe0df5f81a0b83880"
DESIGN_TREE = "db141307819f17c32a19d772384a67509742b21c"
POSITION = "c812-r2-reference-types-validation-implemented-pre-fixed-qemu"
LIVE_POSITION = "c813-e3-qualified-sealed-reference-runtime-released"
COMMANDS = (
    "python3 -B scripts/verify-c812-reference-types-implementation.py --check-contract",
    "python3 -O -B scripts/verify-c812-reference-types-implementation.py --check-contract",
    "python3 -B scripts/verify-c812-reference-types-implementation.py --selftest",
    "python3 -O -B scripts/verify-c812-reference-types-implementation.py --selftest",
)


class Failure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def read(path: Path) -> bytes:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), f"non-regular input: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.read(descriptor, info.st_size + 1)
    finally:
        os.close(descriptor)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def git(*arguments: str) -> bytes:
    result = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True)
    require(result.returncode == 0, f"git {' '.join(arguments)} failed")
    return result.stdout


def validate(value: dict[str, Any]) -> None:
    require(value.get("schema") == "vibeos.c812.reference-types-implementation-v1.contract" and value.get("version") == 1, "contract identity drift")
    require(value.get("status") == "c812-r2-reference-types-validation-implemented-contained-not-qualified-not-released", "status drift")
    identity = value.get("identity", {})
    require(identity == {"artifact_abi": 9, "artifact_profile_code": 9, "component_profile": 6, "core_profile": 6, "name": "PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION", "runtime_abi": 9, "stage": "validation-only"}, "code-9 identity drift")
    basis = value.get("basis", {})
    require(basis.get("design_commit") == DESIGN_COMMIT and basis.get("design_tree") == DESIGN_TREE, "design basis drift")
    engine = value.get("engine", {})
    require(engine.get("package") == "vibeos-wasmi-reference-validation" and engine.get("version") == "1.1.0-vibeos-ref1.1", "engine identity drift")
    require(engine.get("reference_types") is True and engine.get("gc_types_parser_dependency") is True and engine.get("gc_types_semantics") is False and engine.get("floats") is False, "engine feature drift")
    containment = value.get("containment", {})
    require(containment.get("core_nullable_funcref") is True and containment.get("maximum_tables") == 1 and containment.get("active_element_segments_only") is True, "funcref containment drift")
    for key in ("component_core_reference_boundary", "externref", "gc_semantics", "host_reference_imports_or_exports", "passive_or_declarative_elements", "typed_function_references"):
        require(containment.get(key) is False, f"containment widened: {key}")
    boundaries = value.get("boundaries", {})
    require(boundaries.get("code5_permanently_inert") is True and boundaries.get("code5_current_engine") is False, "code 5 drift")
    require(boundaries.get("code7_current_engine") is False and boundaries.get("code7_execution_authorized") is False, "code 7 drift")
    require(boundaries.get("code8_reference_types_enabled") is False and boundaries.get("code8_release_scope_unchanged") is True, "code 8 drift")
    require(boundaries.get("code9_current_engine") is False and boundaries.get("code9_executable") is False and boundaries.get("code9_durable_authorized") is False and boundaries.get("code9_migration_authorized") is False, "code 9 authority drift")
    authority = value.get("authority", {})
    require(authority.get("implementation_authorized") is True and authority.get("candidate_validation_authorized") is True, "R2 authority missing")
    for key in ("admission_authorized", "aot_authorized", "command_authorized", "current_engine_bound", "durable_publication_authorized", "migration_authorized", "production_authorized", "release_authorized", "rwx_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")
    audit = value.get("riscv_object_audit", {})
    require(audit.get("status") == "passed" and audit.get("target") == "riscv64imac-unknown-none-elf" and audit.get("artifacts") == 7 and audit.get("libm_reachable") is False, "RISC-V audit drift")
    tests = value.get("tests", {})
    require(tests.get("candidate_unit_tests") == 4 and tests.get("component_containment_tests") == 3 and tests.get("fixed_component_mutations") == 256 and tests.get("fixed_component_mutations_rejected") == 208, "test evidence drift")
    qualification = value.get("qualification", {})
    require(qualification == {"fixed_qemu": "not-started-c812-r3", "release": "not-authorized", "successor_design_review_eligible": False}, "qualification drift")
    roadmap = value.get("roadmap", {})
    require(roadmap.get("completed_node") == "C8.12-R2" and roadmap.get("current_position") == POSITION and roadmap.get("next_node") == "C8.12-R3", "roadmap drift")
    hardware = value.get("hardware_policy", {})
    require(hardware.get("duo_inputs_required") == 0 and hardware.get("duo_inputs_permitted") == 0 and hardware.get("duo_gate_effect") is False and hardware.get("fixed_qemu_is_hardware_equivalent") is False, "hardware policy drift")


def verify_repository(value: dict[str, Any]) -> None:
    require(git("rev-parse", f"{DESIGN_COMMIT}^{{tree}}").decode().strip() == DESIGN_TREE, "design tree unavailable")
    design = value["basis"]["design_contract"]
    historical = git("show", f"{DESIGN_COMMIT}:{design['path']}")
    require(len(historical) == design["bytes"] and hashlib.sha256(historical).hexdigest() == design["sha256"], "design contract drift")

    format_source = read(ROOT / "component-format/src/lib.rs").decode()
    engine_source = read(ROOT / "component-format/src/engine.rs").decode()
    artifact_source = read(ROOT / "component-format/src/artifact.rs").decode()
    candidate_source = read(ROOT / "wasm-reference-candidate/src/lib.rs").decode()
    component_source = read(ROOT / "component-runtime/src/decode.rs").decode()
    loader_tests = read(ROOT / "services/component-loader/src/tests.rs").decode()
    for marker in ("PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE: u16 = 9", "PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_ARTIFACT_ABI_VERSION: u16 = 9", "PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_RUNTIME_ABI_VERSION: u16 = 9"):
        require(marker in format_source, f"format identity missing: {marker}")
    require("ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION {\n        None" in engine_source, "code 9 became current")
    require("PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE" in artifact_source, "code-9 codec missing")
    for marker in ("WasmFeatures::REFERENCE_TYPES", "WasmFeatures::GC_TYPES", "into_iter_err_on_gc_types", "RefType::FUNCREF", "Module::new(&engine()?", "production_ready: false"):
        require(marker in candidate_source, f"candidate closure missing: {marker}")
    require("inspect_component_for_profile_6_candidate" in component_source and "Profile6ReferenceCandidate" in component_source, "Component containment missing")
    require("reference_candidate.profile = ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION" in loader_tests, "durable loader rejection missing")

    testing = read(ROOT / "TESTING.md").decode()
    ci = read(ROOT / ".github/workflows/ci.yml").decode()
    roadmap = read(ROOT / "docs/WASM_ROADMAP.md").decode()
    profile = read(ROOT / "docs/WASM_REFERENCE_TYPES_PROFILE.md").decode()
    require(
        LIVE_POSITION in roadmap
        and LIVE_POSITION in profile
        and LIVE_POSITION in testing,
        "live position missing",
    )
    require("## C8.12-R2 Reference Types implementation" in testing, "TESTING section missing")
    require("Verify the C8.12-R2 Reference Types implementation" in ci, "CI step missing")
    for command in COMMANDS:
        require(testing.count(command) == 1 and ci.count(command) == 1, f"command integration drift: {command}")


def check() -> None:
    raw = read(CONTRACT)
    require(len(raw) == BYTES and hashlib.sha256(raw).hexdigest() == SHA256, "contract identity drift")
    value = json.loads(raw)
    require(canonical(value) == raw, "contract is not canonical JSON")
    validate(value)
    verify_repository(value)


def selftest() -> None:
    original = json.loads(read(CONTRACT))
    mutations = [
        ("identity.artifact_profile_code", 8),
        ("identity.stage", "executable"),
        ("engine.floats", True),
        ("engine.gc_types_semantics", True),
        ("containment.externref", True),
        ("containment.maximum_tables", 2),
        ("boundaries.code5_current_engine", True),
        ("boundaries.code8_reference_types_enabled", True),
        ("boundaries.code9_current_engine", True),
        ("authority.admission_authorized", True),
        ("riscv_object_audit.libm_reachable", True),
        ("tests.fixed_component_mutations_rejected", 0),
        ("qualification.successor_design_review_eligible", True),
        ("hardware_policy.duo_inputs_required", 1),
        ("roadmap.current_position", "released"),
    ]
    for index, (path, replacement) in enumerate(mutations):
        changed: Any = copy.deepcopy(original)
        target = changed
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = replacement
        try:
            validate(changed)
        except Failure:
            continue
        raise Failure(f"mutation {index} accepted: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-contract", action="store_true")
    group.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        selftest() if args.selftest else check()
        print("C8.12-R2 Reference Types implementation verification: PASS")
        return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.12-R2 implementation verification: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
