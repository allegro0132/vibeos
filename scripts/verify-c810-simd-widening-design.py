#!/usr/bin/env python3
"""Verify the frozen C8.10-S1 deterministic SIMD widening design."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = Path(
    "acceptance/wasm-simd-target/artifacts/"
    "c810-simd-widening-design-v1-contract.json"
)
CONTRACT_BYTES = 8_228
CONTRACT_SHA256 = "6e0728ed4d9c0452a5c895b17a87bb8c90a1fa30fee0eb751dbfb8b52f995be1"
PREDECESSOR_COMMIT = "cf71ce04e6bcfda862f6ebf7944cc9204867561b"
PREDECESSOR_TREE = "a8364fd5893cb652675ea24f3a0b7cc6a25ff9c0"
CURRENT_POSITION = "c810-s1-simd-design-frozen-pre-implementation"
DESIGN_COMMIT = "409ca79114ffe5b52cafa2669a1e9a61dd9a15f0"


class VerificationError(RuntimeError):
    """Fail-closed design-contract violation."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, *, maximum: int = 2 * 1024 * 1024) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), f"non-regular input: {path}")
    require(not stat.S_ISLNK(before.st_mode), f"symlink input: {path}")
    require(before.st_size <= maximum, f"oversized input: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            f"raced input: {path}",
        )
        data = bytearray()
        while len(data) < opened.st_size:
            chunk = os.read(descriptor, min(64 * 1024, opened.st_size - len(data)))
            require(bool(chunk), f"short input: {path}")
            data.extend(chunk)
        require(not os.read(descriptor, 1), f"growing input: {path}")
        return bytes(data)
    finally:
        os.close(descriptor)


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid {label}: {error}") from error
    require(type(value) is dict, f"{label} root must be one object")
    return value


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def git(*args: str, allow_failure: bool = False) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(ROOT),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        },
        check=False,
        capture_output=True,
    )
    if result.returncode and not allow_failure:
        fail(
            f"git {' '.join(args)} failed: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def at(value: dict[str, Any], *path: str) -> Any:
    current: Any = value
    for key in path:
        require(type(current) is dict and key in current, f"missing {'.'.join(path)}")
        current = current[key]
    return current


def validate_contract(contract: dict[str, Any]) -> None:
    require(
        set(contract)
        == {
            "allocation_authority",
            "authority",
            "code5_boundary",
            "code6_boundary",
            "contract_verifier",
            "engine_selection",
            "evidence_policy",
            "hardware_policy",
            "identity",
            "implementation_plan",
            "predecessor",
            "roadmap",
            "schema",
            "semantics",
            "status",
            "target_policy",
            "version",
        },
        "contract root keys drift",
    )
    require(
        contract["schema"] == "vibeos.c810.simd-widening-design-v1.contract"
        and contract["version"] == 1
        and contract["status"]
        == "c810-s1-simd-design-frozen-not-implemented-not-qualified",
        "contract identity/status drift",
    )
    allocation = contract["allocation_authority"]
    require(
        allocation
        == {
            "basis_commit": PREDECESSOR_COMMIT,
            "basis_tree": PREDECESSOR_TREE,
            "date": "2026-08-29",
            "scope": "progress-first-unfinished-c88-non-float-widening-design-only",
            "source": "explicit-user-wasm-roadmap-goal",
        },
        "allocation authority drift",
    )
    identity = contract["identity"]
    require(
        at(identity, "name") == "PROFILE_4_SYNC_SIMD_VALIDATION"
        and at(identity, "artifact_profile_code") == 7
        and at(identity, "artifact_abi") == 7
        and at(identity, "runtime_abi") == 7
        and at(identity, "component_profile") == 4
        and at(identity, "core_profile") == 4
        and at(identity, "execution_stage") == "validation-only",
        "code-7 identity drift",
    )
    world = at(identity, "wit_world")
    require(
        world
        == {
            "exports": ["run(mode: u32, input: list<u8>) -> list<u8>"],
            "identity": "vibe:simd/validation@1.0.0",
            "imports": [],
            "v128_crosses_component_boundary": False,
        },
        "closed WIT world drift",
    )
    engine = contract["engine_selection"]
    require(
        at(engine, "package") == "vibeos-wasmi-simd-softfloat"
        and at(engine, "version") == "1.1.0-vibeos-simd1.1"
        and at(engine, "implementation_status")
        == "selected-for-c810-s2-fork-not-materialized"
        and at(engine, "feature_set")
        == "default-features=false,extra-checks,prefer-btree-collections,simd;relaxed-simd=false",
        "SIMD engine selection drift",
    )
    semantics = contract["semantics"]
    require(
        at(semantics, "fixed_simd_proposal") == "webassembly-fixed-width-simd-1.0"
        and at(semantics, "relaxed_simd_enabled") is False
        and at(semantics, "native_simd_required") is False
        and at(semantics, "v128_component_or_wit_value_allowed") is False
        and at(semantics, "v128_host_import_or_export_allowed") is False
        and "relaxed-simd" in at(semantics, "forbidden_adjacent_features"),
        "SIMD semantic boundary drift",
    )
    authority = contract["authority"]
    for field in (
        "admission_authorized",
        "aot_authorized",
        "command_authorized",
        "current_engine_bound",
        "durable_publication_authorized",
        "execution_authorized",
        "in_place_promotion_authorized",
        "jit_authorized",
        "migration_authorized",
        "native_bytes_authorized",
        "production_authorized",
        "release_authorized",
        "rwx_authorized",
    ):
        require(authority.get(field) is False, f"authority.{field} widened")
    require(authority.get("design_authorized") is True, "design authority missing")
    code5 = contract["code5_boundary"]
    require(
        code5
        == {
            "artifact_profile_code": 5,
            "current_engine": False,
            "executable": False,
            "inert": True,
            "migration_authorized": False,
            "permanent": True,
            "promotion_authorized": False,
            "stage": "validation-only",
        },
        "permanent code-5 boundary drift",
    )
    code6 = contract["code6_boundary"]
    require(
        code6.get("artifact_profile_code") == 6
        and code6.get("identity") == "PROFILE_3_SYNC_FLOAT_EXECUTABLE"
        and code6.get("release_scope_unchanged") is True
        and code6.get("simd_enabled") is False,
        "code-6 isolation drift",
    )
    plan = contract["implementation_plan"]
    require(type(plan) is list and len(plan) == 5, "implementation plan drift")
    require(
        [item.get("id") for item in plan]
        == ["C8.10-S1", "C8.10-S2", "C8.10-S3", "C8.10-S4", "C8.10-S5"]
        and [item.get("complete") for item in plan]
        == [True, False, False, False, False],
        "implementation node state drift",
    )
    target = contract["target_policy"]
    require(
        target.get("baseline") == "qemu-virt-rv64-tcg-icount-v1"
        and target.get("physical_duo_required") is False
        and target.get("qualification_status") == "not-started"
        and target.get("release_status") == "not-authorized",
        "target policy drift",
    )
    hardware = contract["hardware_policy"]
    require(
        hardware.get("duo_inputs_required") == 0
        and hardware.get("duo_inputs_permitted") == 0
        and hardware.get("duo_gate_effect") is False
        and hardware.get("fixed_qemu_is_hardware_equivalent") is False,
        "hardware policy drift",
    )
    roadmap = contract["roadmap"]
    require(
        roadmap.get("allocated_node") == "C8.10"
        and roadmap.get("current_position") == CURRENT_POSITION
        and roadmap.get("next_node") == "C8.10-S2",
        "roadmap allocation drift",
    )


def verify_history(contract: dict[str, Any]) -> None:
    predecessor = contract["predecessor"]
    publication = predecessor["publication"]
    require(
        git("rev-parse", f"{PREDECESSOR_COMMIT}^{{tree}}").decode().strip()
        == PREDECESSOR_TREE,
        "predecessor tree drift",
    )
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", PREDECESSOR_COMMIT, "HEAD"],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(ROOT),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        },
        check=False,
        capture_output=True,
    )
    require(ancestor.returncode == 0, "predecessor is not an ancestor of HEAD")
    require(publication.get("must_be_ancestor_of_checked_head") is True, "history policy drift")
    for label in ("c89_qualification", "fixed_qemu_policy"):
        record = predecessor[label]
        path = record["path"]
        historical = git("show", f"{PREDECESSOR_COMMIT}:{path}")
        require(len(historical) == record["bytes"], f"{label} historical bytes drift")
        require(digest(historical) == record["sha256"], f"{label} historical hash drift")
        tree_line = git("ls-tree", PREDECESSOR_COMMIT, path).decode().strip().split()
        require(len(tree_line) >= 3 and tree_line[2] == record["git_blob"], f"{label} blob drift")
    base = contract["engine_selection"]["base_source"]
    require(
        git("rev-parse", f"{PREDECESSOR_COMMIT}:{base['path']}").decode().strip()
        == base["git_tree"],
        "SIMD engine base tree drift",
    )


def verify_repository() -> None:
    component_format = git("show", f"{DESIGN_COMMIT}:component-format/src/lib.rs").decode()
    engine = read_regular(ROOT / "component-format/src/engine.rs").decode()
    require(
        "PROFILE_2_SYNC_FLOAT_PROFILE_CODE: u16 = 5;" in component_format
        and "PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE: u16 = 6;"
        in component_format,
        "predecessor profile identities drift",
    )
    require("PROFILE_4_SYNC_SIMD" not in component_format, "code 7 implemented during design node")
    require(
        "profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT {\n        None" in engine,
        "code 5 entered current engine",
    )
    require("simd_compiled: false" in engine, "existing engine SIMD isolation missing")
    require(
        "profile == ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION {\n        None"
        in engine,
        "code 7 entered current engine after design",
    )
    markers = {
        "docs/WASM_ROADMAP.md": "c810-s4-simd-admission-lifecycle-closed-pre-fixed-qemu",
        "docs/WASM_SIMD_PROFILE.md": "PROFILE_4_SYNC_SIMD_VALIDATION",
        "TESTING.md": "## C8.10-S1 deterministic SIMD widening design",
        ".github/workflows/ci.yml": "Verify the C8.10-S1 SIMD widening design",
    }
    for relative, marker in markers.items():
        text = read_regular(ROOT / relative).decode()
        require(text.count(marker) >= 1, f"repository marker missing: {relative}")
    ci = read_regular(ROOT / ".github/workflows/ci.yml").decode()
    for command in (
        "python3 -B scripts/verify-c810-simd-widening-design.py --check-contract",
        "python3 -O -B scripts/verify-c810-simd-widening-design.py --check-contract",
        "python3 -B scripts/verify-c810-simd-widening-design.py --selftest",
        "python3 -O -B scripts/verify-c810-simd-widening-design.py --selftest",
    ):
        require(ci.count(command) == 1, f"CI command count drift: {command}")


def check_contract() -> None:
    raw = read_regular(ROOT / CONTRACT, maximum=64 * 1024)
    require(len(raw) == CONTRACT_BYTES, "contract byte length drift")
    require(digest(raw) == CONTRACT_SHA256, "contract SHA-256 drift")
    contract = strict_json(raw, "contract")
    require(raw == canonical(contract), "contract is not canonical JSON")
    validate_contract(contract)
    verify_history(contract)
    verify_repository()


def selftest() -> None:
    raw = read_regular(ROOT / CONTRACT, maximum=64 * 1024)
    contract = strict_json(raw, "contract")
    mutations: list[tuple[tuple[str, ...], object]] = [
        (("identity", "artifact_profile_code"), 6),
        (("identity", "execution_stage"), "executable"),
        (("authority", "execution_authorized"), True),
        (("authority", "release_authorized"), True),
        (("code5_boundary", "inert"), False),
        (("code6_boundary", "simd_enabled"), True),
        (("semantics", "relaxed_simd_enabled"), True),
        (("semantics", "v128_component_or_wit_value_allowed"), True),
        (("engine_selection", "package"), "vibeos-wasmi-softfloat"),
        (("target_policy", "physical_duo_required"), True),
        (("roadmap", "next_node"), "C8.10-S5"),
        (("implementation_plan",), []),
    ]
    rejected = 0
    for path, replacement in mutations:
        candidate = copy.deepcopy(contract)
        current: Any = candidate
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = replacement
        try:
            validate_contract(candidate)
        except VerificationError:
            rejected += 1
    require(rejected == len(mutations), "selftest mutation escaped validation")
    print(f"PASS verify-c810-simd-widening-design selftest cases={rejected}")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-contract", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest()
        else:
            check_contract()
            print(
                "PASS verify-c810-simd-widening-design "
                f"position={CURRENT_POSITION} code7_stage=validation-only "
                "next=C8.10-S2 duo_gate_effect=false"
            )
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"FAIL verify-c810-simd-widening-design: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
