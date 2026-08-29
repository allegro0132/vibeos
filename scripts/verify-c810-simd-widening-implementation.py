#!/usr/bin/env python3
"""Verify the C8.10-S2 deterministic fixed-SIMD implementation closure."""

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
CONTRACT = ROOT / "acceptance/wasm-simd-target/artifacts/c810-simd-widening-implementation-v1-contract.json"
CONTRACT_BYTES = 5_053
CONTRACT_SHA256 = "6083c0d132df4c2027dd826601dd9ad351ecebe844edf52290fd139a150e7c26"
DESIGN_COMMIT = "409ca79114ffe5b52cafa2669a1e9a61dd9a15f0"
DESIGN_TREE = "c2124cd6328c490eaf96524ca8fa68076d5d79a8"
POSITION = "c810-s2-simd-engine-implemented-pre-containment"


class Failure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def read_regular(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), f"non-regular input: {path}")
    require(before.st_size <= maximum, f"oversized input: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), f"raced input: {path}")
        data = os.read(descriptor, opened.st_size + 1)
        require(len(data) == opened.st_size, f"short/growing input: {path}")
        return data
    finally:
        os.close(descriptor)


def strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"duplicate contract key: {key}")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict, "contract root is not an object")
    return value


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def validate(contract: dict[str, Any]) -> None:
    require(contract.get("schema") == "vibeos.c810.simd-widening-implementation-v1.contract", "schema drift")
    require(contract.get("version") == 1, "version drift")
    require(contract.get("status") == "c810-s2-simd-engine-implemented-not-contained-not-qualified-not-released", "status drift")
    require(contract.get("basis") == {
        "design_commit": DESIGN_COMMIT,
        "design_contract": "acceptance/wasm-simd-target/artifacts/c810-simd-widening-design-v1-contract.json",
        "design_tree": DESIGN_TREE,
    }, "design basis drift")
    identity = contract.get("identity", {})
    require(identity == {
        "artifact_abi": 7,
        "artifact_profile_code": 7,
        "component_profile": 4,
        "core_profile": 4,
        "name": "PROFILE_4_SYNC_SIMD_VALIDATION",
        "runtime_abi": 7,
        "stage": "validation-only",
    }, "code-7 identity drift")
    engine = contract.get("engine", {})
    require(engine.get("package") == "vibeos-wasmi-simd-softfloat", "engine package drift")
    require(engine.get("version") == "1.1.0-vibeos-simd1.1", "engine version drift")
    require(engine.get("fork_sha256") == "8f8113e46b928204e957ebcdb472cec13c7aee0b0acebc34c4883d27d9b751cb", "fork digest drift")
    require(engine.get("libm_reachable") is False and engine.get("relaxed_simd_validation") is False, "engine feature widening")
    authority = contract.get("authority", {})
    require(authority.get("implementation_authorized") is True and authority.get("acceptance_candidate_execution") is True, "S2 authority missing")
    for key in ("admission_authorized", "aot_authorized", "command_authorized", "current_engine_bound", "durable_publication_authorized", "migration_authorized", "production_authorized", "release_authorized", "rwx_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")
    code5 = contract.get("code5_boundary", {})
    require(code5.get("artifact_profile_code") == 5 and code5.get("permanent") is True and code5.get("inert") is True and code5.get("current_engine") is False and code5.get("executable") is False, "code 5 boundary drift")
    require([item.get("complete") for item in contract.get("implementation_plan", [])] == [True, True, False, False, False], "node completion drift")
    roadmap = contract.get("roadmap", {})
    require(roadmap.get("completed_node") == "C8.10-S2" and roadmap.get("current_position") == POSITION and roadmap.get("next_node") == "C8.10-S3", "roadmap drift")
    fuel = contract.get("fuel", {})
    require(all(fuel.get(key) == 1 for key in ("base", "call", "fixed_simd", "instance", "load", "store")), "fuel unit schedule drift")
    require(fuel.get("bytes_per_fuel") == 64 and fuel.get("sample_i64x2_add_consumed") == 3, "fuel boundary drift")
    hardware = contract.get("hardware_policy", {})
    require(hardware.get("duo_inputs_required") == 0 and hardware.get("duo_inputs_permitted") == 0 and hardware.get("duo_gate_effect") is False and hardware.get("fixed_qemu_is_hardware_equivalent") is False, "hardware policy drift")
    qualification = contract.get("qualification", {})
    require(qualification.get("fixed_qemu") == "not-started-c810-s5" and qualification.get("release") == "not-authorized", "qualification promoted early")


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, check=False, capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(ROOT), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C"})
    require(result.returncode == 0, f"git {' '.join(args)} failed")
    return result.stdout.strip()


def verify_repository() -> None:
    require(git("rev-parse", f"{DESIGN_COMMIT}^{{tree}}") == DESIGN_TREE, "design tree drift")
    result = subprocess.run(["git", "merge-base", "--is-ancestor", DESIGN_COMMIT, "HEAD"], cwd=ROOT, check=False)
    require(result.returncode == 0, "design commit is not an ancestor")
    component = read_regular(ROOT / "component-format/src/lib.rs").decode()
    engine = read_regular(ROOT / "component-format/src/engine.rs").decode()
    candidate = read_regular(ROOT / "wasm-simd-candidate/src/lib.rs").decode()
    require("PROFILE_4_SYNC_SIMD_VALIDATION" in component and "PROFILE_4_SYNC_SIMD_VALIDATION" in engine, "code 7 implementation missing")
    require("profile == ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION {\n        None" in engine, "code 7 became current")
    require("profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT {\n        None" in engine, "code 5 became current")
    require("production_ready: false" in candidate and "wasm_relaxed_simd(false)" in candidate, "candidate authority drift")
    require("assert_eq!(used, 3" in candidate, "exact fuel regression missing")
    markers = {
        "docs/WASM_ROADMAP.md": "c810-s3-simd-contained-corpora-passed-pre-admission",
        "docs/WASM_SIMD_PROFILE.md": "c810-s3-simd-contained-corpora-passed-pre-admission",
        "TESTING.md": "## C8.10-S2 deterministic Core SIMD engine",
        ".github/workflows/ci.yml": "Verify the C8.10-S2 SIMD implementation",
    }
    for relative, marker in markers.items():
        require(marker in read_regular(ROOT / relative).decode(), f"repository marker missing: {relative}")


def check() -> None:
    raw = read_regular(CONTRACT, 64 * 1024)
    require(len(raw) == CONTRACT_BYTES, f"contract byte drift: {len(raw)}")
    require(hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256, "contract digest drift")
    contract = strict_json(raw)
    require(canonical(contract) == raw, "contract is not canonical JSON")
    validate(contract)
    verify_repository()


def selftest() -> None:
    contract = strict_json(read_regular(CONTRACT, 64 * 1024))
    mutations = [
        ("schema", "adjacent"),
        ("status", "released"),
        ("identity.stage", "executable"),
        ("identity.artifact_profile_code", 5),
        ("engine.libm_reachable", True),
        ("engine.relaxed_simd_validation", True),
        ("authority.current_engine_bound", True),
        ("code5_boundary.current_engine", True),
        ("fuel.fixed_simd", 0),
        ("hardware_policy.duo_inputs_required", 1),
        ("qualification.fixed_qemu", "passed"),
        ("roadmap.next_node", "C8.10-S5"),
    ]
    rejected = 0
    for path, value in mutations:
        changed = copy.deepcopy(contract)
        current: Any = changed
        parts = path.split(".")
        for part in parts[:-1]:
            current = current[part]
        current[parts[-1]] = value
        try:
            validate(changed)
        except Failure:
            rejected += 1
    require(rejected == len(mutations), "mutation selftest accepted drift")
    print(f"PASS verify-c810-simd-widening-implementation selftest cases={rejected}")


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-contract", action="store_true")
    group.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest()
        else:
            check()
            print("PASS verify-c810-simd-widening-implementation node=C8.10-S2 next=C8.10-S3 current_engine=false release=false duo_gate=false")
        return 0
    except (Failure, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"FAIL verify-c810-simd-widening-implementation: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
