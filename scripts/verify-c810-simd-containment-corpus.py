#!/usr/bin/env python3
"""Verify the C8.10-S3 fixed-SIMD Component containment and corpus closure."""

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
CONTRACT = ROOT / "acceptance/wasm-simd-target/artifacts/c810-simd-containment-corpus-v1-contract.json"
CONTRACT_BYTES = 3_635
CONTRACT_SHA256 = "56bfce66eac664e0a28671f3f0b8adb36e1817e09c94519f6bc7edff13051e74"
BASIS_COMMIT = "15495794fae82100b18ad55b5e141d4abdcc065e"
BASIS_TREE = "b9582cc377409a3c2db880c171affb248c30f2b3"
POSITION = "c810-s3-simd-contained-corpora-passed-pre-admission"


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
            require(key not in result, f"duplicate key: {key}")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict, "contract root is not an object")
    return value


def validate(value: dict[str, Any]) -> None:
    require(value.get("schema") == "vibeos.c810.simd-containment-corpus-v1.contract", "schema drift")
    require(value.get("version") == 1, "version drift")
    require(value.get("status") == "c810-s3-simd-contained-corpora-passed-not-admitted-not-qualified-not-released", "status drift")
    require(value.get("basis") == {
        "implementation_commit": BASIS_COMMIT,
        "implementation_contract": "acceptance/wasm-simd-target/artifacts/c810-simd-widening-implementation-v1-contract.json",
        "implementation_tree": BASIS_TREE,
    }, "basis drift")
    identity = value.get("identity", {})
    require(identity == {
        "artifact_abi": 7,
        "artifact_profile_code": 7,
        "component_profile": 4,
        "core_profile": 4,
        "name": "PROFILE_4_SYNC_SIMD_VALIDATION",
        "runtime_abi": 7,
        "stage": "validation-only",
    }, "identity drift")
    code5 = value.get("code5_boundary", {})
    require(code5.get("artifact_profile_code") == 5 and code5.get("permanent") is True and code5.get("inert") is True, "code 5 drift")
    require(code5.get("current_engine") is False and code5.get("executable") is False and code5.get("migration_authorized") is False, "code 5 promoted")
    authority = value.get("authority", {})
    for key in ("admission_authorized", "current_engine_bound", "durable_publication_authorized", "production_authorized", "release_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")
    containment = value.get("containment", {})
    require(containment.get("v128_scope") == "embedded-core-only", "v128 scope drift")
    require(containment.get("component_or_wit_v128") == "unrepresentable", "Component v128 boundary opened")
    require(containment.get("host_import_or_export_v128") is False and containment.get("current_engine_resolution") is False, "v128 escaped containment")
    differential = value.get("corpora", {}).get("differential", {})
    require(differential.get("cases") == 512 and differential.get("fnv1a64") == "fcb8de3059c13007", "differential corpus drift")
    mutation = value.get("corpora", {}).get("mutation", {})
    require(mutation.get("cases") == 512 and mutation.get("fnv1a64") == "8af29a0ea0a0b294" and mutation.get("panic_free") is True, "mutation corpus drift")
    require([item.get("complete") for item in value.get("implementation_plan", [])] == [True, True, True, False, False], "node completion drift")
    roadmap = value.get("roadmap", {})
    require(roadmap.get("completed_node") == "C8.10-S3" and roadmap.get("current_position") == POSITION and roadmap.get("next_node") == "C8.10-S4", "roadmap drift")
    qualification = value.get("qualification", {})
    require(qualification.get("fixed_qemu") == "not-started-c810-s5" and qualification.get("release") == "not-authorized", "qualification promoted early")
    hardware = value.get("hardware_policy", {})
    require(hardware.get("duo_inputs_required") == 0 and hardware.get("duo_inputs_permitted") == 0 and hardware.get("duo_gate_effect") is False, "physical-Duo gate restored")
    require(hardware.get("fixed_qemu_is_hardware_equivalent") is False, "physical equivalence claimed")


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, check=False, capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(ROOT), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C"})
    require(result.returncode == 0, f"git {' '.join(args)} failed")
    return result.stdout.strip()


def verify_repository() -> None:
    raw = read_regular(CONTRACT)
    require(len(raw) == CONTRACT_BYTES, "contract byte length drift")
    require(hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256, "contract digest drift")
    value = strict_json(raw)
    require(raw == (json.dumps(value, sort_keys=True, indent=2) + "\n").encode(), "contract is not canonical JSON")
    validate(value)
    require(git("rev-parse", f"{BASIS_COMMIT}^{{tree}}") == BASIS_TREE, "basis tree drift")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", BASIS_COMMIT, "HEAD"], cwd=ROOT, check=False).returncode == 0, "basis is not an ancestor")
    cargo = read_regular(ROOT / "component-runtime/Cargo.toml").decode()
    decode = read_regular(ROOT / "component-runtime/src/decode.rs").decode()
    runtime = read_regular(ROOT / "wasm-runtime/src/lib.rs").decode()
    tests = read_regular(ROOT / "component-runtime/tests/c810_s3_simd_containment.rs").decode()
    require('c810-s3-acceptance = [' in cargo and 'default = []' in cargo, "acceptance feature/default drift")
    for marker in ("inspect_component_for_profile_4_candidate", "Profile4SimdCandidate", "SyncSimdCandidate"):
        require(marker in decode, f"missing containment marker: {marker}")
    require("inspect_core_for_profile_4_candidate" in runtime and "VisitSimdOperator" in runtime, "fixed-SIMD structural inspector missing")
    for marker in ("EXPECTED_DIFFERENTIAL_FNV64", "EXPECTED_MUTATION_FNV64", "PROFILE_2_SYNC_FLOAT_PROFILE_CODE", "v128"):
        require(marker in tests, f"missing corpus marker: {marker}")


def selftest() -> None:
    original = strict_json(read_regular(CONTRACT))
    mutations: list[dict[str, Any]] = []
    for change in range(6):
        value = copy.deepcopy(original)
        if change == 0:
            value["identity"]["artifact_profile_code"] = 5
        elif change == 1:
            value["code5_boundary"]["current_engine"] = True
        elif change == 2:
            value["containment"]["v128_scope"] = "component-boundary"
        elif change == 3:
            value["corpora"]["differential"]["cases"] = 511
        elif change == 4:
            value["qualification"]["fixed_qemu"] = "passed"
        else:
            value["hardware_policy"]["duo_inputs_required"] = 1
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
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest()
        if args.check_contract or not args.selftest:
            verify_repository()
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.10-S3 verification: FAIL: {error}", file=sys.stderr)
        return 1
    print("C8.10-S3 containment/corpus verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
