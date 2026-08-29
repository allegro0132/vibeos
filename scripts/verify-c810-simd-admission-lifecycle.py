#!/usr/bin/env python3
"""Verify the C8.10-S4 default-off SIMD admission/lifecycle closure."""

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
CONTRACT = ROOT / "acceptance/wasm-simd-target/artifacts/c810-simd-admission-lifecycle-v1-contract.json"
CONTRACT_BYTES = 3_694
CONTRACT_SHA256 = "217c1eb45d78d7cc4a267ae9b1c3e0b366f281e4b8048a86b6ce4f5a0990186f"
BASIS_COMMIT = "ff2eb0700efb5fe08ff76476b94a29096ba92b65"
BASIS_TREE = "5c355b0292e13b004c0482aa2cb9799d1acfd0d9"
POSITION = "c810-s4-simd-admission-lifecycle-closed-pre-fixed-qemu"


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
    require(value.get("schema") == "vibeos.c810.simd-admission-lifecycle-v1.contract", "schema drift")
    require(value.get("version") == 1, "version drift")
    require(value.get("status") == "c810-s4-simd-admission-lifecycle-closed-not-qualified-not-released", "status drift")
    require(value.get("basis") == {
        "containment_commit": BASIS_COMMIT,
        "containment_contract": "acceptance/wasm-simd-target/artifacts/c810-simd-containment-corpus-v1-contract.json",
        "containment_tree": BASIS_TREE,
    }, "basis drift")
    identity = value.get("identity", {})
    require(identity.get("artifact_profile_code") == 7 and identity.get("runtime_abi") == 7 and identity.get("stage") == "validation-only", "identity drift")
    code5 = value.get("code5_boundary", {})
    require(code5.get("artifact_profile_code") == 5 and code5.get("permanent") is True and code5.get("inert") is True, "code 5 drift")
    require(code5.get("current_engine") is False and code5.get("executable") is False and code5.get("migration_authorized") is False, "code 5 promoted")
    admission = value.get("admission", {})
    require(admission.get("cargo_feature") == "c810-s4-acceptance" and admission.get("default_enabled") is False, "default-off gate drift")
    require(admission.get("authority_offers") == 0 and admission.get("imports") == 0 and admission.get("resource_ceiling") == 0, "authority boundary drift")
    require(admission.get("command_route") is False and admission.get("durable_conversion") is False, "production route opened")
    lifecycle = value.get("lifecycle", {})
    require(lifecycle.get("maximum_live_instances") == 1 and lifecycle.get("cold_recovery_after_cancel_or_fault") is True, "lifecycle drift")
    require(lifecycle.get("revocation_idempotent") is True and lifecycle.get("revoked_recovery") is False and lifecycle.get("fuel_exhaustion_bounded") is True, "lifecycle authority drift")
    durability = value.get("durability", {})
    require(durability.get("ordinary_loader_accepts_code7") is False and durability.get("persistent_command_projection") is False, "durable route opened")
    require(durability.get("profile1_loader_unchanged") is True, "Profile-1 loader drift")
    require(durability.get("volatile_activation_revalidates_before_lifecycle") is True, "activation revalidation drift")
    require(durability.get("volatile_recovery_next_poll_recompiles_core") is True, "volatile recovery drift")
    authority = value.get("authority", {})
    for key in ("admission_authorized", "current_engine_bound", "durable_publication_authorized", "production_authorized", "release_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")
    require([item.get("complete") for item in value.get("implementation_plan", [])] == [True, True, True, True, False], "node completion drift")
    qualification = value.get("qualification", {})
    require(qualification.get("fixed_qemu") == "not-started-c810-s5" and qualification.get("release") == "not-authorized", "qualification/release drift")
    roadmap = value.get("roadmap", {})
    require(roadmap.get("completed_node") == "C8.10-S4" and roadmap.get("current_position") == POSITION and roadmap.get("next_node") == "C8.10-S5", "roadmap drift")
    hardware = value.get("hardware_policy", {})
    require(hardware.get("duo_inputs_required") == 0 and hardware.get("duo_inputs_permitted") == 0 and hardware.get("duo_gate_effect") is False, "physical-Duo gate restored")
    require(hardware.get("fixed_qemu_qualification_node") == "C8.10-S5" and hardware.get("fixed_qemu_is_hardware_equivalent") is False, "fixed-QEMU boundary drift")


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
    cargo = read_regular(ROOT / "services/component-admission/Cargo.toml").decode()
    admission = read_regular(ROOT / "services/component-admission/src/lib.rs").decode()
    tests = read_regular(ROOT / "services/component-admission/tests/c810_s4_simd_admission.rs").decode()
    loader = read_regular(ROOT / "services/component-loader/src/tests.rs").decode()
    require('default = []' in cargo and 'c810-s4-acceptance = [' in cargo, "default-off feature drift")
    for marker in ("admit_simd_acceptance_candidate", "SimdCandidateLifecycle", "SIMD_ACCEPTANCE_ACTIVATION_LABEL", "profile_4_candidate_required_compile_bytes"):
        require(marker in admission, f"missing admission marker: {marker}")
    for marker in ("quota_cancel_fault_cold_recovery_and_revoke_are_instance_exact", "ordinary_artifact", "UntrustedArtifact"):
        require(marker in tests, f"missing lifecycle test marker: {marker}")
    require("PROFILE_4_SYNC_SIMD_VALIDATION" in loader and "S4 grants no" in loader, "durable code-7 rejection missing")


def selftest() -> None:
    original = strict_json(read_regular(CONTRACT))
    mutations = []
    for index in range(7):
        value = copy.deepcopy(original)
        if index == 0:
            value["identity"]["artifact_profile_code"] = 5
        elif index == 1:
            value["code5_boundary"]["current_engine"] = True
        elif index == 2:
            value["admission"]["default_enabled"] = True
        elif index == 3:
            value["admission"]["authority_offers"] = 1
        elif index == 4:
            value["durability"]["ordinary_loader_accepts_code7"] = True
        elif index == 5:
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
        print(f"C8.10-S4 verification: FAIL: {error}", file=sys.stderr)
        return 1
    print("C8.10-S4 admission/lifecycle verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
