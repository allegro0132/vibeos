#!/usr/bin/env python3
"""Verify the frozen C8.11-S2 executable SIMD implementation closure."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "acceptance/wasm-simd-target/artifacts/c811-simd-successor-implementation-v1-contract.json"
CONTRACT_BYTES = 3842
CONTRACT_SHA256 = "7b85b9324409d7cc4484ca9e661a44fce2275e70407338a4f4326f71809a40a1"
DESIGN_COMMIT = "6e4934d88837465da6a256e741bc13185ecd77f7"
DESIGN_TREE = "4dc7235b529724fae4ea0b3a656e4cce7203cecc"
POSITION = "c811-s2-simd-executable-implemented-pre-fixed-qemu"
COMMANDS = (
    "python3 -B scripts/verify-c811-simd-successor-implementation.py --check-contract",
    "python3 -O -B scripts/verify-c811-simd-successor-implementation.py --check-contract",
    "python3 -B scripts/verify-c811-simd-successor-implementation.py --selftest",
    "python3 -O -B scripts/verify-c811-simd-successor-implementation.py --selftest",
    "python3 -B scripts/verify-c811-s2-supply-chain.py",
    "python3 -O -B scripts/verify-c811-s2-supply-chain.py --self-test",
    "python3 -B scripts/verify-c811-s2-riscv-object.py",
)


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
        require(len(data) == opened.st_size, f"short or growing input: {path}")
        return data
    finally:
        os.close(descriptor)


def strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, f"duplicate contract key: {key}")
            value[key] = item
        return value
    result = json.loads(raw, object_pairs_hook=pairs)
    require(type(result) is dict, "contract root is not an object")
    return result


def validate(contract: dict[str, Any]) -> None:
    require(contract.get("schema") == "vibeos.c811.simd-successor-implementation-v1.contract", "schema drift")
    require(contract.get("version") == 1, "version drift")
    require(contract.get("status") == "c811-s2-implemented-not-fixed-qemu-qualified-not-released", "status drift")
    require(contract.get("basis") == {
        "design_commit": DESIGN_COMMIT,
        "design_contract": "acceptance/wasm-simd-target/artifacts/c811-simd-successor-design-v1-contract.json",
        "design_contract_bytes": 8267,
        "design_contract_sha256": "5995b8513f182d891c30d95530d31f6b571c14b0649c39c438f99990f58133ee",
        "design_tree": DESIGN_TREE,
    }, "design basis drift")
    require(contract.get("identity") == {
        "artifact_abi": 8, "artifact_profile_code": 8, "component_profile": 5,
        "core_profile": 5, "name": "PROFILE_5_SYNC_SIMD_EXECUTABLE",
        "runtime_abi": 8, "stage": "executable", "world": "vibe:simd/runtime@1.0.0",
    }, "code-8 identity drift")
    engine = contract.get("engine", {})
    require(engine.get("package") == "vibeos-wasmi-simd-executable-softfloat" and engine.get("version") == "1.1.0-vibeos-simd2.1", "engine identity drift")
    require(engine.get("base_fork_files") == 168 and engine.get("facade_files") == 2, "engine closure drift")
    require(engine.get("facade_sha256") == "99c4953c437aff9c4e40710cb373c54bf419aac1029d93bf9596c82c21be4615", "facade digest drift")
    require(engine.get("libm_reachable") is False and engine.get("relaxed_simd") is False, "engine widened")
    boundary = contract.get("boundaries", {})
    require(boundary.get("code5_inert_permanent") is True and boundary.get("code5_current_engine") is False and boundary.get("code5_migration_authorized") is False, "code 5 boundary drift")
    require(boundary.get("code7_stage") == "validation-only" and boundary.get("code7_current_engine") is False and boundary.get("code7_execution_authorized") is False and boundary.get("code7_migration_authorized") is False, "code 7 boundary drift")
    authority = contract.get("authority", {})
    require(authority.get("current_engine_bound") is True and authority.get("implementation_complete") is True and authority.get("admission_scope") == "exact-image-pinned-authority-free-volatile-only", "S2 authority missing")
    for key in ("command_authorized", "durable_publication_authorized", "migration_authorized", "production_authorized", "release_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")
    implementation = contract.get("implementation", {})
    require(implementation.get("maximum_instances") == 1 and implementation.get("memory_bytes") == 65536 and implementation.get("durable_and_command_conversion") is False, "implementation containment drift")
    require(all(implementation.get(key) == 0 for key in ("riscv64imac_f_d_v_opcodes", "riscv64imac_fp_helpers", "riscv64imac_semantic_llvm_fp")), "RISC-V result drift")
    hardware = contract.get("hardware_policy", {})
    require(hardware.get("duo_inputs_required") == 0 and hardware.get("duo_inputs_permitted") == 0 and hardware.get("duo_gate_effect") is False and hardware.get("fixed_qemu_is_hardware_equivalent") is False, "hardware policy drift")
    qualification = contract.get("qualification", {})
    require(qualification.get("fixed_qemu") == "not-started-c811-s3" and qualification.get("release") == "not-authorized" and qualification.get("production") == "not-authorized", "qualification promoted early")
    require(contract.get("roadmap") == {"completed_node": "C8.11-S2", "current_position": POSITION, "next_node": "C8.11-S3"}, "roadmap drift")


def git(*arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=ROOT, check=False, capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(ROOT), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C"})
    require(result.returncode == 0, f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def sha256(relative: str) -> str:
    return hashlib.sha256(read_regular(ROOT / relative)).hexdigest()


def verify_repository(contract: dict[str, Any]) -> None:
    require(git("rev-parse", f"{DESIGN_COMMIT}^{{tree}}") == DESIGN_TREE, "design tree drift")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", DESIGN_COMMIT, "HEAD"], cwd=ROOT, check=False).returncode == 0, "design commit is not an ancestor")
    implementation = contract["implementation"]
    require(sha256("wasm-simd-executable/Cargo.toml") == implementation["wrapper_manifest_sha256"], "wrapper manifest drift")
    require(sha256("wasm-simd-executable/src/lib.rs") == implementation["wrapper_source_sha256"], "wrapper source drift")
    facade = read_regular(ROOT / "wasmi-simd-executable-softfloat/src/lib.rs").decode()
    require("pub use wasmi_simd_base::*;" in facade, "facade re-export missing")
    engine = read_regular(ROOT / "component-format/src/engine.rs").decode()
    require("PROFILE_5_SYNC_SIMD_EXECUTABLE" in engine and "for_c811_simd_contract" in engine, "code-8 current engine missing")
    require("PROFILE_2_SYNC_FLOAT {\n        None" in engine, "code 5 became current")
    require("PROFILE_4_SYNC_SIMD_VALIDATION {\n        None" in engine, "code 7 became current")
    runtime = read_regular(ROOT / "wasm-runtime/src/lib.rs").decode()
    require("PROFILE_5_SYNC_SIMD_EXECUTABLE" in runtime and "current_profile_required_compile_bytes" in runtime, "code-8 Core runtime missing")
    admission = read_regular(ROOT / "services/component-admission/src/simd_executable.rs").decode()
    for marker in ("ImagePinned", "caller.offers.is_empty()", "has_exact_simd_candidate_execution_binding", "durable"):
        require(marker in admission, f"admission marker missing: {marker}")
    lock = tomllib.loads(read_regular(ROOT / "Cargo.lock").decode())
    matches = [item for item in lock.get("package", []) if item.get("name") == "vibeos-wasmi-simd-executable-softfloat"]
    require(len(matches) == 1 and matches[0].get("version") == "1.1.0-vibeos-simd2.1" and "source" not in matches[0], "lock identity drift")
    documents = [read_regular(ROOT / path).decode() for path in ("docs/WASM_ROADMAP.md", "docs/WASM_SIMD_EXECUTABLE_PROFILE.md", "TESTING.md")]
    require(all(POSITION in document for document in documents), "live position missing")
    testing = documents[-1]
    ci = read_regular(ROOT / ".github/workflows/ci.yml").decode()
    require("## C8.11-S2 executable SIMD implementation" in testing and "Verify the C8.11-S2 executable SIMD implementation" in ci, "S2 integration missing")
    for command in COMMANDS:
        require(testing.count(command) == 1 and ci.count(command) == 1, f"command integration drift: {command}")


def check() -> None:
    raw = read_regular(CONTRACT, 64 * 1024)
    require(len(raw) == CONTRACT_BYTES, f"contract byte drift: {len(raw)}")
    require(hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256, "contract digest drift")
    contract = strict_json(raw)
    require(raw == (json.dumps(contract, sort_keys=True, indent=2) + "\n").encode(), "contract is not canonical JSON")
    validate(contract)
    verify_repository(contract)


def selftest() -> None:
    contract = strict_json(read_regular(CONTRACT, 64 * 1024))
    mutations = (
        ("identity.artifact_profile_code", 7), ("identity.stage", "validation-only"),
        ("engine.relaxed_simd", True), ("boundaries.code5_current_engine", True),
        ("boundaries.code7_execution_authorized", True), ("authority.release_authorized", True),
        ("authority.durable_publication_authorized", True), ("implementation.maximum_instances", 2),
        ("implementation.riscv64imac_f_d_v_opcodes", 1), ("hardware_policy.duo_inputs_required", 1),
        ("qualification.fixed_qemu", "passed"), ("roadmap.next_node", "released"),
    )
    rejected = 0
    for path, value in mutations:
        changed = copy.deepcopy(contract)
        target: Any = changed
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
        try:
            validate(changed)
        except Failure:
            rejected += 1
    require(rejected == len(mutations), "mutation self-test accepted drift")


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-contract", action="store_true")
    group.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        selftest() if args.selftest else check()
        print("C8.11-S2 SIMD successor implementation verification: PASS")
        return 0
    except (Failure, OSError, UnicodeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"C8.11-S2 implementation verification: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
