#!/usr/bin/env python3
"""Verify the published C8.12-R3 fixed-QEMU qualification and review decision."""

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
    "c812-r3-fixed-qemu-qualification-v1-contract.json"
)
BYTES = 3_322
SHA256 = "83a78e8fe9a02f9a7b32ab509a7895a89bfca10ce6c76f78d2499b8fac5671f7"
POSITION = "c812-r3-qualified-reference-validation-successor-review-eligible"
LIVE_POSITION = "c813-e3-qualified-sealed-reference-runtime-released"


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
        value.get("schema")
        == "vibeos.c812.r3.fixed-qemu-qualification-v1.contract"
        and value.get("version") == 1,
        "contract identity drift",
    )
    require(
        value.get("status")
        == "c812-r3-fixed-qemu-qualified-code9-inert-successor-review-eligible",
        "status drift",
    )
    require(
        value.get("identity")
        == {
            "artifact_abi": 9,
            "artifact_profile_code": 9,
            "component_profile": 6,
            "core_profile": 6,
            "engine": "vibeos-wasmi-reference-validation@1.1.0-vibeos-ref1.1",
            "name": "PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION",
            "runtime_abi": 9,
            "stage": "validation-only",
        },
        "code-9 identity drift",
    )
    basis = value.get("basis", {})
    require(
        basis.get("source_commit") == "43516cd6fe4d88c583f681714950884dc8660d4c"
        and basis.get("source_tree") == "89ca3d099ef3981cc2d760a8993d47d5a6585cc7",
        "source basis drift",
    )
    evidence = value.get("evidence", {})
    require(
        evidence.get("records") == 9
        and evidence.get("rejected_mutations") == 208
        and evidence.get("accepted_inert_mutations") == 48
        and evidence.get("semantic_sha256")
        == "bf33470617822af905ab8877797416e79aed3cde5a257689b3bbdda4df156279",
        "semantic evidence drift",
    )
    require(
        evidence.get("run_id")
        == "fc40fbd874b274e786ad96f1f88b1b27251c7d9037654599bd30cefa623a8a2e",
        "run identity drift",
    )
    require(
        value.get("qualification")
        == {
            "elf_no_native_float_helpers": True,
            "elf_no_riscv_f_d_or_v": True,
            "normal_verified": True,
            "optimized_verified": True,
            "platform": "qemu-virt-rv64-tcg-icount-v1",
            "qemu_boots": 1,
        },
        "qualification drift",
    )
    require(
        value.get("hardware_policy")
        == {
            "duo_gate_effect": False,
            "duo_inputs": 0,
            "fixed_qemu_is_hardware_equivalent": False,
            "physical_provenance": "not-claimed",
        },
        "hardware claim drift",
    )
    boundaries = value.get("boundaries", {})
    require(
        boundaries.get("code5_permanently_inert") is True
        and boundaries.get("code5_current_engine") is False
        and boundaries.get("code7_current_engine") is False
        and boundaries.get("code8_scope_changed") is False
        and boundaries.get("code9_current_engine") is False
        and boundaries.get("code9_execution_authorized") is False
        and boundaries.get("code9_migration_authorized") is False
        and boundaries.get("code9_promoted") is False,
        "legacy or code-9 boundary drift",
    )
    authority = value.get("authority", {})
    require(
        authority
        == {
            "code9_production_authorized": False,
            "durable_publication_authorized": False,
            "execution_authorized": False,
            "migration_authorized": False,
            "ordinary_command_authorized": False,
            "release_authorized": False,
            "successor_design_review_eligible": True,
        },
        "review scope drift",
    )
    require(
        value.get("review")
        == {
            "allocated_successor": False,
            "eligible_scope": "independently-numbered-reference-executable-successor-design-only",
            "in_place_promotion": False,
        },
        "successor review boundary drift",
    )
    require(
        value.get("roadmap")
        == {
            "completed_node": "C8.12-R3",
            "current_position": POSITION,
            "next_node": "unallocated-reference-executable-successor-design",
        },
        "roadmap drift",
    )


def verify_receipt(
    raw: bytes, mode: str, value: dict[str, Any], evidence: dict[str, Any]
) -> None:
    receipt = json.loads(raw)
    require(canonical(receipt) == raw, f"{mode} receipt not canonical")
    require(
        receipt.get("schema") == "vibeos.c812.r3.reference-fixed-qemu.receipt"
        and receipt.get("version") == 1
        and receipt.get("status") == "pass"
        and receipt.get("mode") == mode,
        f"{mode} receipt identity drift",
    )
    require(
        receipt.get("source_commit") == value["basis"]["source_commit"]
        and receipt.get("source_tree") == value["basis"]["source_tree"]
        and receipt.get("challenge") == evidence["challenge"]
        and receipt.get("run_id") == evidence["run_id"]
        and receipt.get("semantic_sha256") == evidence["semantic_sha256"]
        and receipt.get("records") == 9,
        f"{mode} receipt evidence drift",
    )
    require(
        receipt.get("physical_inputs") == 0
        and receipt.get("physical_provenance") == "not-claimed"
        and receipt.get("uart_bytes") == 5_648
        and receipt.get("uart_sha256")
        == "183df517ddbd94a1607f51edd80f19f2e734d542c880333f7b212c396eb727de",
        f"{mode} receipt target boundary drift",
    )


def verify_files(value: dict[str, Any]) -> None:
    evidence = value["evidence"]
    for key, mode in (("normal_receipt", "normal"), ("optimized_receipt", "optimized")):
        record = evidence[key]
        payload = read(ROOT / record["path"])
        require(
            len(payload) == record["bytes"]
            and hashlib.sha256(payload).hexdigest() == record["sha256"],
            f"{key} identity drift",
        )
        verify_receipt(payload, mode, value, evidence)
    decision_record = evidence["review_decision"]
    decision_raw = read(ROOT / decision_record["path"])
    require(
        len(decision_raw) == decision_record["bytes"]
        and hashlib.sha256(decision_raw).hexdigest() == decision_record["sha256"]
        and canonical(json.loads(decision_raw)) == decision_raw,
        "review decision identity drift",
    )
    decision = json.loads(decision_raw)
    require(
        decision.get("decision")
        == "open-independent-reference-executable-successor-design-review"
        and decision.get("authority", {}).get("successor_design_review_eligible") is True
        and decision.get("review") == value["review"]
        and decision.get("code5", {}).get("permanently_inert") is True
        and decision.get("code9", {}).get("promoted") is False,
        "review decision scope drift",
    )
    manifest = read(ROOT / evidence["manifest_path"])
    require(
        len(manifest) == evidence["manifest_bytes"]
        and hashlib.sha256(manifest).hexdigest() == evidence["manifest_sha256"]
        and canonical(json.loads(manifest)) == manifest,
        "manifest drift",
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
        "source tree is unavailable or drifted",
    )
    engine = read(ROOT / "component-format/src/engine.rs").decode()
    require(
        "PROFILE_2_SYNC_FLOAT {\n        None" in engine
        and "PROFILE_4_SYNC_SIMD_VALIDATION {\n        None" in engine
        and "PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION {\n        None" in engine,
        "code 5, code 7, or code 9 became current",
    )
    for path in (
        "docs/WASM_ROADMAP.md",
        "docs/WASM_REFERENCE_TYPES_PROFILE.md",
        "TESTING.md",
    ):
        require(POSITION in read(ROOT / path).decode(), f"live position missing: {path}")
    for path in (
        "docs/WASM_ROADMAP.md",
        "docs/WASM_REFERENCE_TYPES_EXECUTABLE_PROFILE.md",
        "TESTING.md",
    ):
        require(LIVE_POSITION in read(ROOT / path).decode(), f"successor position missing: {path}")
    ci = read(ROOT / ".github/workflows/ci.yml").decode()
    require(
        "Verify the C8.12-R3 fixed-QEMU qualification decision" in ci,
        "CI decision step missing",
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
        ("identity.artifact_profile_code", 5),
        ("qualification.optimized_verified", False),
        ("hardware_policy.duo_inputs", 1),
        ("boundaries.code5_current_engine", True),
        ("boundaries.code9_execution_authorized", True),
        ("boundaries.code9_promoted", True),
        ("authority.execution_authorized", True),
        ("authority.successor_design_review_eligible", False),
        ("review.allocated_successor", True),
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
        print("C8.12-R3 fixed-QEMU qualification verification: PASS")
        return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.12-R3 verification: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
