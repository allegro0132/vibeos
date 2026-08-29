#!/usr/bin/env python3
"""Verify the C8.11-S1 independent SIMD executable successor design."""

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
    / "acceptance/wasm-simd-target/artifacts/"
    "c811-simd-successor-design-v1-contract.json"
)
CONTRACT_BYTES = 8_267
CONTRACT_SHA256 = "5995b8513f182d891c30d95530d31f6b571c14b0649c39c438f99990f58133ee"
BASIS_COMMIT = "2038c3134fe94d1ca297764c9fd8ee7d39a24123"
BASIS_TREE = "4332275a81379b68e6daddaab7599a942054e9e1"
POSITION = "c811-s1-simd-executable-design-frozen-pre-implementation"
CHECK_COMMANDS = (
    "python3 -B scripts/verify-c811-simd-successor-design.py --check-contract",
    "python3 -O -B scripts/verify-c811-simd-successor-design.py --check-contract",
    "python3 -B scripts/verify-c811-simd-successor-design.py --selftest",
    "python3 -O -B scripts/verify-c811-simd-successor-design.py --selftest",
)


class Failure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def read_regular(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode),
        f"non-regular input: {path}",
    )
    require(before.st_nlink == 1 and before.st_size <= maximum, f"unsafe input: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        require(
            (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
            f"raced input: {path}",
        )
        data = os.read(descriptor, opened.st_size + 1)
        require(len(data) == opened.st_size, f"short/growing input: {path}")
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
        parse_constant=lambda value: (_ for _ in ()).throw(
            Failure(f"constant: {value}")
        ),
    )
    require(type(value) is dict, "JSON root is not an object")
    return value


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
    require(
        value.get("schema") == "vibeos.c811.simd-successor-design-v1.contract",
        "schema drift",
    )
    require(
        value.get("version") == 1
        and value.get("status")
        == "c811-s1-design-frozen-not-implemented-not-qualified-not-released",
        "status drift",
    )
    allocation = value.get("allocation_authority", {})
    require(
        allocation.get("basis_commit") == BASIS_COMMIT
        and allocation.get("basis_tree") == BASIS_TREE,
        "allocation basis drift",
    )
    require(
        allocation.get("source") == "standing-user-wasm-roadmap-goal"
        and allocation.get("user_selected_profile7_promotion") is False
        and allocation.get("user_selected_physical_duo_gate") is False,
        "allocation authority drift",
    )
    identity = value.get("identity", {})
    require(
        identity.get("name") == "PROFILE_5_SYNC_SIMD_EXECUTABLE"
        and identity.get("artifact_profile_code") == 8
        and identity.get("artifact_abi") == 8
        and identity.get("runtime_abi") == 8,
        "successor identity drift",
    )
    require(
        identity.get("component_profile") == 5
        and identity.get("core_profile") == 5
        and identity.get("execution_stage") == "executable",
        "successor profile drift",
    )
    require(
        identity.get("core_wasm_revision")
        == "webassembly-core-2.0-fixed-width-simd-1.0-deterministic-software-float-c811-exec-v1"
        and identity.get("component_model_revision")
        == "wasmparser-component-model-0.255.0-c811-simd-exec-v1"
        and identity.get("canonical_abi_revision")
        == "component-model-0.255.0-sync-float-values-no-v128-boundary-c811-simd-exec-v1",
        "revision drift",
    )
    world = identity.get("wit_world", {})
    require(
        world.get("identity") == "vibe:simd/runtime@1.0.0"
        and world.get("imports") == []
        and world.get("v128_crosses_component_boundary") is False,
        "WIT boundary drift",
    )
    engine = value.get("engine_selection", {})
    require(
        engine.get("package") == "vibeos-wasmi-simd-executable-softfloat"
        and engine.get("version") == "1.1.0-vibeos-simd2.1"
        and engine.get("implementation_status")
        == "selected-for-c811-s2-fork-not-materialized",
        "engine selection drift",
    )
    semantics = value.get("semantics", {})
    require(
        semantics.get("fixed_width_simd_1_0") is True
        and semantics.get("software_float_required") is True
        and semantics.get("v128_component_boundary") == "forbidden",
        "SIMD semantics drift",
    )
    require(
        semantics.get("adjacent_features_enabled") == []
        and "relaxed-simd" in semantics.get("forbidden_adjacent_features", []),
        "adjacent feature drift",
    )
    for boundary_name, code in (("code5_boundary", 5), ("code7_boundary", 7)):
        boundary = value.get(boundary_name, {})
        require(
            boundary.get("artifact_profile_code") == code
            and boundary.get("stage") == "validation-only"
            and boundary.get("current_engine") is False,
            f"{boundary_name} drift",
        )
        require(
            boundary.get("migration_authorized") is False,
            f"{boundary_name} migration authorized",
        )
    code5 = value.get("code5_boundary", {})
    require(code5.get("permanent") is True and code5.get("inert") is True, "code 5 drift")
    code7 = value.get("code7_boundary", {})
    for key in (
        "durable_authorized",
        "execution_authorized",
        "in_place_promotion_authorized",
        "production_authorized",
        "release_authorized",
    ):
        require(code7.get(key) is False, f"code 7 authority widened: {key}")
    authority = value.get("authority", {})
    require(
        authority.get("design_authorized") is True
        and authority.get("implementation_authorized") is True
        and authority.get("current_engine_bound") is False,
        "design authority drift",
    )
    for key in (
        "admission_authorized",
        "aot_authorized",
        "command_authorized",
        "durable_publication_authorized",
        "in_place_promotion_authorized",
        "jit_authorized",
        "migration_authorized",
        "native_bytes_authorized",
        "production_authorized",
        "release_authorized",
        "rwx_authorized",
    ):
        require(authority.get(key) is False, f"authority widened: {key}")
    plan = value.get("implementation_plan", [])
    require(
        [item.get("id") for item in plan] == ["C8.11-S1", "C8.11-S2", "C8.11-S3"]
        and [item.get("complete") for item in plan] == [True, False, False],
        "implementation plan drift",
    )
    roadmap = value.get("roadmap", {})
    require(
        roadmap.get("allocated_node") == "C8.11"
        and roadmap.get("current_position") == POSITION
        and roadmap.get("implementation_node") == "C8.11-S2"
        and roadmap.get("qualification_node") == "C8.11-S3",
        "roadmap drift",
    )
    hardware = value.get("hardware_policy", {})
    require(
        hardware.get("duo_inputs_required") == 0
        and hardware.get("duo_inputs_permitted") == 0
        and hardware.get("duo_gate_effect") is False
        and hardware.get("fixed_qemu_is_hardware_equivalent") is False,
        "hardware boundary drift",
    )


def verify_historical_identity(record: dict[str, Any]) -> None:
    raw = git("show", f"{BASIS_COMMIT}:{record['path']}")
    require(len(raw) == record["bytes"], f"historical bytes drift: {record['path']}")
    require(
        hashlib.sha256(raw).hexdigest() == record["sha256"],
        f"historical hash drift: {record['path']}",
    )


def verify_repository(value: dict[str, Any]) -> None:
    require(
        git("rev-parse", f"{BASIS_COMMIT}^{{tree}}").decode().strip() == BASIS_TREE,
        "basis tree drift",
    )
    predecessor = value["predecessor"]
    verify_historical_identity(predecessor["qualification_contract"])
    verify_historical_identity(predecessor["review_decision"])
    base = value["engine_selection"]["base_source"]
    require(
        git("rev-parse", f"{base['commit']}:{base['path']}").decode().strip()
        == base["git_tree"],
        "engine base tree drift",
    )
    provenance = git("show", f"{base['commit']}:{base['path']}/PROVENANCE.toml")
    require(
        len(provenance) == base["provenance_bytes"]
        and hashlib.sha256(provenance).hexdigest() == base["provenance_sha256"],
        "engine provenance drift",
    )
    names = git("ls-tree", "-r", "--name-only", BASIS_COMMIT).decode().splitlines()
    roots = (
        "component-format/",
        "component-runtime/",
        "wasm-runtime/",
        "services/component-admission/",
        "services/component-loader/",
        "kernel/",
    )
    for path in names:
        if path.endswith(".rs") and path.startswith(roots):
            source = git("show", f"{BASIS_COMMIT}:{path}")
            require(
                b"PROFILE_5_SYNC_SIMD_EXECUTABLE" not in source,
                f"code 8 materialized before S1: {path}",
            )
    live_format = read_regular(ROOT / "component-format/src/engine.rs").decode()
    require(
        "if profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT {\n        None"
        in live_format,
        "code 5 current-engine rejection missing",
    )
    require(
        "else if profile == ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION {\n        None"
        in live_format,
        "code 7 current-engine rejection missing",
    )
    roadmap = read_regular(ROOT / "docs/WASM_ROADMAP.md").decode()
    profile = read_regular(ROOT / "docs/WASM_SIMD_EXECUTABLE_PROFILE.md").decode()
    testing = read_regular(ROOT / "TESTING.md").decode()
    ci = read_regular(ROOT / ".github/workflows/ci.yml").decode()
    require(POSITION in roadmap and POSITION in profile and POSITION in testing, "live position missing")
    require("## 9.3 C8.11 independent executable SIMD successor" in roadmap, "roadmap C8.11 section missing")
    require("# Executable SIMD successor profile" in profile, "profile document missing")
    require("## C8.11-S1 SIMD successor design contract" in testing, "TESTING section missing")
    require("Verify the C8.11-S1 SIMD successor design" in ci, "CI step missing")
    for command in CHECK_COMMANDS:
        require(testing.count(command) == 1, f"TESTING command drift: {command}")
        require(ci.count(command) == 1, f"CI command drift: {command}")


def verify_live() -> None:
    raw = read_regular(CONTRACT)
    require(len(raw) == CONTRACT_BYTES, "contract byte length drift")
    require(hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256, "contract hash drift")
    value = strict_json(raw)
    require(
        raw == (json.dumps(value, sort_keys=True, indent=2) + "\n").encode(),
        "contract is not canonical JSON",
    )
    validate(value)
    verify_repository(value)


def selftest() -> None:
    original = strict_json(read_regular(CONTRACT))
    mutations: list[dict[str, Any]] = []
    for index in range(12):
        value = copy.deepcopy(original)
        if index == 0:
            value["identity"]["artifact_profile_code"] = 7
        elif index == 1:
            value["identity"]["artifact_abi"] = 7
        elif index == 2:
            value["identity"]["runtime_abi"] = 7
        elif index == 3:
            value["identity"]["execution_stage"] = "validation-only"
        elif index == 4:
            value["engine_selection"]["version"] = "1.1.0-vibeos-simd1.1"
        elif index == 5:
            value["semantics"]["v128_component_boundary"] = "enabled"
        elif index == 6:
            value["code5_boundary"]["current_engine"] = True
        elif index == 7:
            value["code7_boundary"]["execution_authorized"] = True
        elif index == 8:
            value["authority"]["release_authorized"] = True
        elif index == 9:
            value["hardware_policy"]["duo_inputs_required"] = 1
        elif index == 10:
            value["implementation_plan"][1]["complete"] = True
        else:
            value["roadmap"]["current_position"] = "released"
        mutations.append(value)
    for index, value in enumerate(mutations):
        try:
            validate(value)
        except Failure:
            continue
        raise Failure(f"mutation {index} was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    require(arguments.check_contract or arguments.selftest, "select a mode")
    try:
        if arguments.check_contract:
            verify_live()
        if arguments.selftest:
            selftest()
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.11-S1 design verification: FAIL: {error}", file=sys.stderr)
        return 1
    print("C8.11-S1 SIMD successor design verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
