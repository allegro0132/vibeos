#!/usr/bin/env python3
"""Verify the published C8.9-S3 fixed-QEMU qualification and release boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "acceptance/wasm-float-target/artifacts/c89-s3-fixed-qemu-qualification-v1-contract.json"
CONTRACT_BYTES = 4_457
CONTRACT_SHA256 = "f105699b87c4f05eb90c2afe22a2a46002b7f5a1d32a1bac7cc46878a81edbb8"
HARNESS_COMMIT = "2e9bc0c3648656cca8e4d198cbb6a7350975090a"
HARNESS_TREE = "3de024ef329db9d15678a5f9d98ad152e28fa5d4"
RUN_ID = "d627c608da149a1324eea5a605ebd5caf4020fde48d75f0a21bea98d1873bd72"
SEMANTIC_SHA256 = "44cb0a12c01906b31a42fc6550d485496206ea23a08bc073a685e1b893fb94b8"


class VerificationFailure(RuntimeError):
    pass


class View:
    def __init__(self, overlays: Mapping[str, bytes] | None = None) -> None:
        self.overlays = dict(overlays or {})

    def read(self, rel: str) -> bytes:
        if rel in self.overlays:
            return self.overlays[rel]
        path = ROOT / rel
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise VerificationFailure(f"non-regular input: {rel}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise VerificationFailure(f"raced input: {rel}")
            data = bytearray()
            while len(data) < opened.st_size:
                chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - len(data)))
                if not chunk:
                    raise VerificationFailure(f"short input: {rel}")
                data.extend(chunk)
            if os.read(descriptor, 1):
                raise VerificationFailure(f"growing input: {rel}")
            return bytes(data)
        finally:
            os.close(descriptor)

    def text(self, rel: str) -> str:
        return self.read(rel).decode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationFailure(message)


def git(*args: str) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(ROOT),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        },
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise VerificationFailure(
            f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def strict_json(raw: bytes, label: str) -> dict[str, object]:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise VerificationFailure(f"duplicate key in {label}: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate)
    except json.JSONDecodeError as error:
        raise VerificationFailure(f"invalid {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must be one object")
    return value


def exact_file(view: View, record: object, label: str) -> dict[str, object]:
    require(isinstance(record, dict), f"{label} identity missing")
    assert isinstance(record, dict)
    require(set(record) == {"path", "bytes", "sha256"}, f"{label} identity keys drift")
    raw = view.read(str(record["path"]))
    require(len(raw) == record["bytes"], f"{label} byte length drift")
    require(digest(raw) == record["sha256"], f"{label} SHA-256 drift")
    return strict_json(raw, label)


def verify(view: View, *, history: bool = True) -> None:
    raw = view.read(CONTRACT)
    require(len(raw) == CONTRACT_BYTES, "S3 contract byte length drift")
    require(digest(raw) == CONTRACT_SHA256, "S3 contract SHA-256 drift")
    contract = strict_json(raw, "S3 contract")
    require(
        contract.get("schema") == "vibeos.c89.s3.fixed-qemu-qualification-v1.contract"
        and contract.get("version") == 1
        and contract.get("status") == "qualified-released-sealed-float-runtime"
        and contract.get("node") == "C8.9-S3",
        "S3 contract identity/status drift",
    )
    predecessors = contract["predecessors"]
    require(
        isinstance(predecessors, dict)
        and predecessors.get("harness_commit") == HARNESS_COMMIT
        and predecessors.get("harness_tree") == HARNESS_TREE
        and predecessors.get("implementation_commit")
        == "23fb452a6b3a026b0846c60a2c2c383a0fd2b6ba",
        "S3 predecessor boundary drift",
    )
    identity = contract["identity"]
    require(
        isinstance(identity, dict)
        and identity.get("profile_code") == 6
        and identity.get("artifact_abi") == 6
        and identity.get("runtime_abi") == 6
        and identity.get("component_profile") == 3
        and identity.get("core_profile") == 3
        and identity.get("stage") == "executable"
        and identity.get("world") == "vibe:float/runtime@1.0.0",
        "code-6 identity drift",
    )
    campaign = contract["campaign"]
    require(
        isinstance(campaign, dict)
        and campaign.get("platform") == "qemu-virt-rv64-tcg-icount-v1"
        and campaign.get("run_id") == RUN_ID
        and campaign.get("records") == 1_176
        and campaign.get("semantic_sha256") == SEMANTIC_SHA256
        and campaign.get("normal_verified") is True
        and campaign.get("optimized_verified") is True
        and campaign.get("physical_inputs_required") == 0
        and campaign.get("physical_inputs_permitted") == 0
        and campaign.get("physical_provenance") == "not-claimed"
        and campaign.get("physical_equivalence_claimed") is False,
        "fixed-QEMU campaign drift",
    )

    published = contract["published_artifacts"]
    require(isinstance(published, dict), "published artifacts missing")
    manifest = exact_file(view, published["manifest"], "S3 manifest")
    normal = exact_file(view, published["normal_receipt"], "normal receipt")
    optimized = exact_file(view, published["optimized_receipt"], "optimized receipt")
    decision = exact_file(view, published["release_decision"], "release decision")
    require(manifest.get("artifact_profile_code") == 6, "manifest profile drift")
    for receipt, mode, optimized_flag in (
        (normal, "normal", False),
        (optimized, "optimized", True),
    ):
        require(
            receipt.get("status") == "pass"
            and receipt.get("optimization_mode") == mode
            and receipt.get("python_optimized") is optimized_flag
            and receipt.get("run_id") == RUN_ID
            and receipt.get("semantic_sha256") == SEMANTIC_SHA256
            and receipt.get("records") == 1_176
            and receipt.get("physical_inputs") == 0,
            f"{mode} receipt drift",
        )
    require(
        decision.get("decision") == "release-code6-sealed-float-runtime"
        and decision.get("status") == "pass",
        "release decision drift",
    )
    authority = contract["authority"]
    require(
        isinstance(authority, dict)
        and authority.get("sealed_authority_free_float_admission_released") is True
        and authority.get("code6_release_authorized") is True
        and authority.get("code6_production_authorized") is True
        and authority.get("ordinary_command_admission_authorized") is False
        and authority.get("durable_publication_authorized") is False
        and authority.get("aot_authorized") is False
        and authority.get("jit_authorized") is False
        and authority.get("native_bytes_authorized") is False
        and authority.get("rwx_authorized") is False,
        "release authority drift",
    )
    code5 = contract["code5_boundary"]
    require(
        isinstance(code5, dict)
        and code5.get("profile_code") == 5
        and code5.get("stage") == "validation-only"
        and code5.get("permanently_inert") is True
        and code5.get("current_engine") is False
        and code5.get("executable") is False
        and code5.get("promotion_authorized") is False
        and code5.get("migration_authorized") is False,
        "code-5 boundary drift",
    )
    duo = contract["physical_duo"]
    require(
        duo
        == {
            "status": "paused-optional",
            "gate_effect": False,
            "completion_effect": False,
            "release_effect": False,
        },
        "physical Duo boundary drift",
    )

    format_source = view.text("component-format/src/engine.rs")
    require(
        "profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT {\n        None"
        in format_source,
        "code 5 entered the current engine resolver",
    )
    loader_test = view.text("services/component-loader/src/tests.rs")
    require("PROFILE_3_SYNC_FLOAT_EXECUTABLE" in loader_test, "durable code-6 rejection missing")
    for rel in (
        "docs/WASM_ROADMAP.md",
        "docs/WASM_FLOAT_PROFILE.md",
        "docs/WASM_AOT_DECISION.md",
        "TESTING.md",
    ):
        require(
            "c89-s3-qualified-sealed-float-runtime-released" in view.text(rel),
            f"S3 completion marker missing: {rel}",
        )

    if history:
        require(
            git("rev-parse", f"{HARNESS_COMMIT}^{{tree}}").decode().strip()
            == HARNESS_TREE,
            "harness tree drift",
        )
        require(
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", HARNESS_COMMIT, "HEAD"],
                cwd=ROOT,
                check=False,
                capture_output=True,
            ).returncode
            == 0,
            "harness source is not an ancestor of HEAD",
        )
        for record in contract["harness"].values():
            require(isinstance(record, dict), "harness identity missing")
            assert isinstance(record, dict)
            historical = git("show", f"{HARNESS_COMMIT}:{record['path']}")
            require(
                len(historical) == record["bytes"]
                and digest(historical) == record["sha256"],
                f"historical harness drift: {record['path']}",
            )


def selftest() -> None:
    base = View()
    verify(base)
    contract = strict_json(base.read(CONTRACT), "S3 contract")
    mutations = 0
    for section, key, value in (
        ("campaign", "normal_verified", False),
        ("campaign", "physical_inputs_permitted", 1),
        ("authority", "durable_publication_authorized", True),
        ("authority", "code6_release_authorized", False),
        ("code5_boundary", "current_engine", True),
        ("physical_duo", "gate_effect", True),
    ):
        changed = json.loads(json.dumps(contract))
        changed[section][key] = value
        overlay = (json.dumps(changed, indent=2) + "\n").encode()
        try:
            verify(View({CONTRACT: overlay}), history=False)
        except VerificationFailure:
            mutations += 1
        else:
            raise RuntimeError(f"selftest accepted mutation: {section}.{key}")
    print(f"selftest PASS: {mutations} S3 authority/evidence mutations rejected")


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
            verify(View())
        print("C8.9-S3 fixed-QEMU qualification verification: PASS")
        return 0
    except (OSError, UnicodeDecodeError, VerificationFailure, RuntimeError) as error:
        print(f"C8.9-S3 fixed-QEMU qualification verification: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
