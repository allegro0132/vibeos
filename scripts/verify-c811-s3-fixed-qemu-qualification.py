#!/usr/bin/env python3
"""Verify the published C8.11-S3 fixed-QEMU qualification and release."""

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
CONTRACT = ROOT / "acceptance/wasm-simd-target/artifacts/c811-s3-fixed-qemu-qualification-v1-contract.json"
BYTES = 3309
SHA256 = "68b2e3933784f1b81f2f45fb173a24131797c6b86e305ee12ccbc78b2ecb677b"
POSITION = "c811-s3-qualified-sealed-simd-runtime-released"

class Failure(RuntimeError): pass
def require(value: bool, message: str) -> None:
    if not value: raise Failure(message)

def read(path: Path) -> bytes:
    info = path.lstat(); require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), f"non-regular input: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try: return os.read(descriptor, info.st_size + 1)
    finally: os.close(descriptor)

def canonical(value: object) -> bytes: return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

def validate(value: dict[str, Any]) -> None:
    require(value.get("schema") == "vibeos.c811.s3.fixed-qemu-qualification-v1.contract" and value.get("version") == 1, "contract identity drift")
    require(value.get("status") == "c811-s3-fixed-qemu-qualified-code8-sealed-runtime-released", "status drift")
    require(value.get("identity") == {"artifact_abi": 8, "artifact_profile_code": 8, "component_profile": 5, "core_profile": 5, "name": "PROFILE_5_SYNC_SIMD_EXECUTABLE", "runtime_abi": 8, "stage": "executable"}, "code-8 identity drift")
    basis = value.get("basis", {})
    require(basis.get("source_commit") == "90f95df4503a3992067fa68dbcd7d9dd9485ef10" and basis.get("source_tree") == "2ab8ca62c1a37dd766c86d2fd8fd9d5f873927cd", "source basis drift")
    evidence = value.get("evidence", {})
    require(evidence.get("records") == 7 and evidence.get("semantic_sha256") == "ddab9d539744523b332787be6f8a101de00108479c9644136538524f20cd4514", "semantic evidence drift")
    require(evidence.get("run_id") == "c7404023823bea9027e0c55bd564a062dc591974dd7385bd8957a4b4c3d61de8", "run identity drift")
    qualification = value.get("qualification", {})
    require(qualification == {"elf_no_native_float_helpers": True, "elf_no_riscv_f_d_or_v": True, "normal_verified": True, "optimized_verified": True, "platform": "qemu-virt-rv64-tcg-icount-v1", "qemu_boots": 1}, "qualification drift")
    hardware = value.get("hardware_policy", {})
    require(hardware.get("duo_inputs") == 0 and hardware.get("duo_gate_effect") is False and hardware.get("fixed_qemu_is_hardware_equivalent") is False and hardware.get("physical_provenance") == "not-claimed", "hardware claim drift")
    boundaries = value.get("boundaries", {})
    require(boundaries.get("code5_permanently_inert") is True and boundaries.get("code5_current_engine") is False and boundaries.get("code7_current_engine") is False and boundaries.get("code7_execution_authorized") is False and boundaries.get("code7_migration_authorized") is False, "legacy boundary drift")
    authority = value.get("authority", {})
    require(authority.get("code8_production_authorized") is True and authority.get("code8_sealed_volatile_admission_released") is True and authority.get("durable_publication_authorized") is False and authority.get("ordinary_command_authorized") is False, "release scope drift")
    require(value.get("roadmap") == {"completed_node": "C8.11-S3", "current_position": POSITION, "next_node": "unallocated-next-wasm-widening"}, "roadmap drift")

def verify_files(value: dict[str, Any]) -> None:
    evidence = value["evidence"]
    for key in ("normal_receipt", "optimized_receipt", "release_decision"):
        record = evidence[key]; payload = read(ROOT / record["path"])
        require(len(payload) == record["bytes"] and hashlib.sha256(payload).hexdigest() == record["sha256"], f"{key} identity drift")
        require(canonical(json.loads(payload)) == payload, f"{key} not canonical")
    manifest = read(ROOT / evidence["manifest_path"])
    require(len(manifest) == evidence["manifest_bytes"] and hashlib.sha256(manifest).hexdigest() == evidence["manifest_sha256"], "manifest drift")
    result = subprocess.run(["git", "rev-parse", f"{value['basis']['source_commit']}^{{tree}}"], cwd=ROOT, capture_output=True, text=True)
    require(result.returncode == 0 and result.stdout.strip() == value["basis"]["source_tree"], "source tree is unavailable or drifted")
    engine = read(ROOT / "component-format/src/engine.rs").decode()
    require("PROFILE_2_SYNC_FLOAT {\n        None" in engine and "PROFILE_4_SYNC_SIMD_VALIDATION {\n        None" in engine, "code 5 or code 7 became current")
    for path in ("docs/WASM_ROADMAP.md", "docs/WASM_SIMD_EXECUTABLE_PROFILE.md", "TESTING.md"):
        require(POSITION in read(ROOT / path).decode(), f"live position missing: {path}")
    ci = read(ROOT / ".github/workflows/ci.yml").decode()
    require("Verify the C8.11-S3 fixed-QEMU qualification decision" in ci, "CI step missing")

def check() -> None:
    raw = read(CONTRACT); require(len(raw) == BYTES and hashlib.sha256(raw).hexdigest() == SHA256, "contract identity drift")
    value = json.loads(raw); require(canonical(value) == raw, "contract not canonical"); validate(value); verify_files(value)

def selftest() -> None:
    value = json.loads(read(CONTRACT)); mutations = [("identity.artifact_profile_code", 7), ("qualification.optimized_verified", False), ("hardware_policy.duo_inputs", 1), ("boundaries.code5_current_engine", True), ("boundaries.code7_execution_authorized", True), ("authority.durable_publication_authorized", True), ("roadmap.next_node", "released")]
    rejected = 0
    for path, replacement in mutations:
        changed = copy.deepcopy(value); target: Any = changed; parts = path.split(".")
        for part in parts[:-1]: target = target[part]
        target[parts[-1]] = replacement
        try: validate(changed)
        except Failure: rejected += 1
    require(rejected == len(mutations), "mutation accepted")

def main() -> int:
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True); group.add_argument("--check-contract", action="store_true"); group.add_argument("--selftest", action="store_true"); args = parser.parse_args()
    try: selftest() if args.selftest else check(); print("C8.11-S3 fixed-QEMU qualification verification: PASS"); return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error: print(f"C8.11-S3 verification: FAIL: {error}", file=sys.stderr); return 1

if __name__ == "__main__": raise SystemExit(main())
