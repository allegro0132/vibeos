#!/usr/bin/env python3
"""Verify the published C8.10-S5 qualification and review-only decision."""

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
CONTRACT = ROOT / "acceptance/wasm-simd-target/artifacts/c810-s5-fixed-qemu-qualification-v1-contract.json"
CONTRACT_BYTES = 5_518
CONTRACT_SHA256 = "824bfe30eca3fb923ea5eeecd96963aa134364f0acc56a3db43cb26eb52ad6c8"
SOURCE_COMMIT = "4b2add7ccf9dee18891b89548ee24a3e6d828f98"
SOURCE_TREE = "f7ad8fba9912ddfda878ebf974266bf8befc19bb"
RUN_ID = "ca57bdf2af07484ef48e8ef09e51700e1f5b7a169de04c58594b66a96c7c8b61"
SEMANTIC_SHA256 = "6b34b541a42fdf838eccd55e43473a4154421eadc0e3b4292a5a89fde54ae1c6"
POSITION = "c810-s5-fixed-qemu-qualified-successor-review-eligible"


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
    require(type(value) is dict, "JSON root is not an object")
    return value


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
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
    return result.stdout.strip()


def validate(value: dict[str, Any]) -> None:
    require(value.get("schema") == "vibeos.c810.s5.fixed-qemu-qualification-v1.contract", "schema drift")
    require(value.get("version") == 1 and value.get("status") == "qualified-successor-review-eligible-not-released", "status drift")
    campaign = value.get("campaign", {})
    require(campaign.get("source_commit") == SOURCE_COMMIT and campaign.get("source_tree") == SOURCE_TREE, "source drift")
    require(campaign.get("run_id") == RUN_ID and campaign.get("semantic_sha256") == SEMANTIC_SHA256, "campaign identity drift")
    require(campaign.get("normal_verified") is True and campaign.get("optimized_verified") is True and campaign.get("records") == 7, "verification drift")
    require(campaign.get("platform") == "qemu-virt-rv64-tcg-icount-v1" and campaign.get("physical_equivalence_claimed") is False, "platform drift")
    require(campaign.get("physical_inputs_required") == 0 and campaign.get("physical_inputs_permitted") == 0 and campaign.get("physical_provenance") == "not-claimed", "physical input drift")
    code5 = value.get("code5_boundary", {})
    require(code5.get("profile_code") == 5 and code5.get("permanent") is True and code5.get("inert") is True, "code 5 drift")
    require(code5.get("current_engine") is False and code5.get("executable") is False and code5.get("migration_authorized") is False and code5.get("promotion_authorized") is False, "code 5 promoted")
    code7 = value.get("code7_boundary", {})
    require(code7.get("profile_code") == 7 and code7.get("artifact_abi") == 7 and code7.get("runtime_abi") == 7, "code 7 identity drift")
    require(code7.get("stage") == "validation-only" and code7.get("current_engine") is False and code7.get("default_off_acceptance_only") is True, "code 7 stage drift")
    for key in ("durable_authorized", "production_authorized", "release_authorized"):
        require(code7.get(key) is False, f"code 7 authority widened: {key}")
    authority = value.get("authority", {})
    require(authority.get("successor_design_review_eligible") is True, "review eligibility lost")
    for key in ("admission_authorized", "current_engine_authorized", "design_authorized", "durable_publication_authorized", "implementation_authorized", "production_authorized", "profile_allocation_authorized", "release_authorized"):
        require(authority.get(key) is False, f"authority widened: {key}")
    require([item.get("complete") for item in value.get("implementation_plan", [])] == [True] * 5, "plan drift")
    roadmap = value.get("roadmap", {})
    require(roadmap.get("completed_node") == "C8.10-S5" and roadmap.get("current_position") == POSITION and roadmap.get("next_node") == "unallocated-successor-design-review", "roadmap drift")


def verify_identity(record: dict[str, Any]) -> None:
    path = ROOT / record["path"]
    raw = read_regular(path)
    require(len(raw) == record["bytes"], f"byte drift: {record['path']}")
    require(hashlib.sha256(raw).hexdigest() == record["sha256"], f"hash drift: {record['path']}")


def verify_repository() -> None:
    raw = read_regular(CONTRACT)
    require(len(raw) == CONTRACT_BYTES, "contract byte length drift")
    require(hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256, "contract digest drift")
    value = strict_json(raw)
    require(raw == (json.dumps(value, sort_keys=True, indent=2) + "\n").encode(), "contract is not canonical JSON")
    validate(value)
    require(git("rev-parse", f"{SOURCE_COMMIT}^{{tree}}") == SOURCE_TREE, "source tree drift")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", SOURCE_COMMIT, "HEAD"], cwd=ROOT, check=False).returncode == 0, "source is not an ancestor")
    for group in ("harness", "published_artifacts"):
        for record in value[group].values():
            verify_identity(record)
    normal = strict_json(read_regular(ROOT / value["published_artifacts"]["normal_receipt"]["path"]))
    optimized = strict_json(read_regular(ROOT / value["published_artifacts"]["optimized_receipt"]["path"]))
    decision = strict_json(read_regular(ROOT / value["published_artifacts"]["review_decision"]["path"]))
    require(normal.get("mode") == "normal-python" and optimized.get("mode") == "optimized-python", "receipt modes drift")
    for receipt in (normal, optimized):
        require(receipt.get("status") == "pass" and receipt.get("run_id") == RUN_ID and receipt.get("semantic_sha256") == SEMANTIC_SHA256, "receipt drift")
        require(receipt.get("physical_inputs") == 0 and receipt.get("physical_provenance") == "not-claimed", "receipt physical drift")
    require(decision.get("decision") == "successor-design-review-eligible-code7-remains-validation-only", "decision drift")
    require(decision.get("authority", {}).get("successor_design_review_eligible") is True and decision.get("authority", {}).get("release_authorized") is False, "decision authority drift")
    docs = read_regular(ROOT / "docs/WASM_ROADMAP.md").decode()
    simd = read_regular(ROOT / "docs/WASM_SIMD_PROFILE.md").decode()
    ci = read_regular(ROOT / ".github/workflows/ci.yml").decode()
    testing = read_regular(ROOT / "TESTING.md").decode()
    for text, label in ((docs, "roadmap"), (simd, "SIMD profile"), (testing, "TESTING")):
        require(POSITION in text, f"missing live position: {label}")
    require("Verify the C8.10-S5 fixed-QEMU qualification decision" in ci, "missing CI decision step")


def selftest() -> None:
    original = strict_json(read_regular(CONTRACT))
    mutations = []
    for index in range(8):
        value = copy.deepcopy(original)
        if index == 0:
            value["campaign"]["physical_inputs_required"] = 1
        elif index == 1:
            value["campaign"]["normal_verified"] = False
        elif index == 2:
            value["code5_boundary"]["current_engine"] = True
        elif index == 3:
            value["code7_boundary"]["stage"] = "executable"
        elif index == 4:
            value["authority"]["release_authorized"] = True
        elif index == 5:
            value["authority"]["design_authorized"] = True
        elif index == 6:
            value["authority"]["successor_design_review_eligible"] = False
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
    try:
        if arguments.selftest:
            selftest()
        if arguments.check_contract or not arguments.selftest:
            verify_repository()
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"C8.10-S5 qualification verification: FAIL: {error}", file=sys.stderr)
        return 1
    print("C8.10-S5 fixed-QEMU qualification verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
