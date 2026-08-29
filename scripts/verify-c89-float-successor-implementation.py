#!/usr/bin/env python3
"""Verify the completed C8.9-S2 code-6 implementation boundary.

This verifier is host-only and offline. It runs no QEMU and accepts no
physical-hardware input. C8.9-S3 owns all target qualification evidence.
"""

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
CONTRACT = "acceptance/wasm-float-target/artifacts/c89-float-successor-implementation-v1-contract.json"
CONTRACT_BYTES = 6866
CONTRACT_SHA256 = "e25e0150fd65937ae82bebdfdb24fb1d1cb08f33709893abdaeddf339a90cd50"
DESIGN_COMMIT = "f2976a0ae0a88ea2e834c4eedb6f7221bdc6b2e3"
DESIGN_TREE = "928ae4c343f22dd59448eed64511474f808a5e61"
DESIGN_CONTRACT = "acceptance/wasm-float-target/artifacts/c89-float-successor-design-v1-contract.json"
DESIGN_BYTES = 8766
DESIGN_SHA256 = "8a48c52201f60d05274abadb92d5249761f7852e42209a1d6e80ce94b86a5380"
IMPLEMENTATION_COMMIT = "23fb452a6b3a026b0846c60a2c2c383a0fd2b6ba"
IMPLEMENTATION_TREE = "2a194bda15c45493278acc2c818c44c245efa785"


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
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise VerificationFailure(f"raced input: {rel}")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    raise VerificationFailure(f"short input: {rel}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise VerificationFailure(f"growing input: {rel}")
            after = os.fstat(fd)
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise VerificationFailure(f"changed input: {rel}")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def text(self, rel: str) -> str:
        return self.read(rel).decode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationFailure(message)


def git(*args: str) -> bytes:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(ROOT),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "LC_ALL": "C",
    }
    result = subprocess.run(
        ["git", *args], cwd=ROOT, env=env, check=False, capture_output=True
    )
    if result.returncode != 0:
        raise VerificationFailure(
            f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def publication_read(view: View, rel: str) -> bytes:
    if rel in view.overlays:
        return view.read(rel)
    return git("show", f"{IMPLEMENTATION_COMMIT}:{rel}")


def publication_text(view: View, rel: str) -> str:
    return publication_read(view, rel).decode("utf-8")


def verify(view: View, *, history: bool = True) -> None:
    raw = view.read(CONTRACT)
    require(len(raw) == CONTRACT_BYTES, "implementation contract byte length drift")
    require(sha256(raw) == CONTRACT_SHA256, "implementation contract SHA-256 drift")
    try:
        contract = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VerificationFailure(f"invalid implementation contract JSON: {exc}") from exc
    canonical = (json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    require(raw == canonical, "implementation contract is not canonical JSON")
    require(
        contract.get("schema") == "vibeos.c89.float-successor-implementation-v1.contract"
        and contract.get("version") == 1,
        "implementation schema/version drift",
    )
    require(
        contract.get("status") == "c89-s2-implemented-not-qualified-not-released",
        "implementation status drift",
    )
    identity = contract["identity"]
    require(
        identity
        == {
            "artifact_abi": 6,
            "artifact_profile_code": 6,
            "canonical_abi_revision": "component-model-0.255.0-sync-float-values-deterministic-software-float-v1-c89-exec-v1",
            "component_model_revision": "wasmparser-component-model-0.255.0-c89-sync-float-exec-v1",
            "component_profile": 3,
            "core_profile": 3,
            "core_wasm_revision": "webassembly-core-2.0-scalar-f32-f64-deterministic-software-float-v1-c89-exec-v1",
            "name": "PROFILE_3_SYNC_FLOAT_EXECUTABLE",
            "runtime_abi": 6,
            "stage": "executable",
            "wasi_revision": "wasi-not-selected-c89-sync-float",
            "wasm_tools_revision": "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380",
        },
        "code-6 identity drift",
    )
    authority = contract["authority"]
    require(authority["code6_current_engine_bound"] is True, "code-6 engine not bound")
    require(
        authority["sealed_authority_free_float_admission_authorized"] is True,
        "sealed Float admission drift",
    )
    for field in (
        "aot_authorized",
        "durable_publication_authorized",
        "jit_authorized",
        "native_bytes_authorized",
        "ordinary_command_admission_authorized",
        "production_authorized",
        "release_authorized",
        "rwx_authorized",
    ):
        require(authority[field] is False, f"unauthorized authority enabled: {field}")
    require(authority["physical_duo_inputs_permitted"] == 0, "physical input admitted")
    code5 = contract["code5_boundary"]
    require(
        code5["artifact_profile_code"] == 5
        and code5["stage"] == "validation-only"
        and code5["permanent"] is True
        and code5["inert"] is True
        and code5["current_engine"] is False
        and code5["executable"] is False,
        "code-5 permanent inert boundary drift",
    )
    next_gate = contract["next_gate"]
    require(
        next_gate["node"] == "C8.9-S3"
        and next_gate["baseline"] == "qemu-virt-rv64-tcg-icount-v1"
        and next_gate["normal_and_optimized_required"] is True
        and next_gate["physical_duo_required"] is False
        and next_gate["qualification_complete"] is False
        and next_gate["release_authorized"] is False,
        "S3 boundary drift",
    )

    pins = contract["implementation_sources"]
    require(len(pins) == 25, "implementation source pin count drift")
    for rel, expected in pins.items():
        require(
            sha256(publication_read(view, rel)) == expected,
            f"implementation source drift: {rel}",
        )

    format_source = publication_text(view, "component-format/src/lib.rs")
    engine_source = publication_text(view, "component-format/src/engine.rs")
    artifact_source = publication_text(view, "component-format/src/artifact.rs")
    runtime_source = publication_text(view, "component-runtime/src/decode.rs")
    admission_source = publication_text(view, "services/component-admission/src/lib.rs")
    require("PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE: u16 = 6" in format_source, "code-6 profile constant missing")
    require("pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE: Self" in format_source, "code-6 identity missing")
    require("PROFILE_2_SYNC_FLOAT_PROFILE_CODE: u16 = 5" in format_source, "code-5 constant drift")
    require("profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT {\n        None" in engine_source, "code 5 entered current resolver")
    require("Some(&PROFILE_3_SYNC_FLOAT_EXECUTABLE_ENGINE)" in engine_source, "code-6 engine resolver missing")
    require("PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE =>" in artifact_source, "code-6 codec missing")
    require("ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE" in runtime_source, "code-6 Component runtime missing")
    require("pub fn admit_float_executable" in admission_source, "code-6 admission missing")
    require("ordinary command admission/durable path remains closed" in publication_text(view, "services/component-admission/tests/c89_float_executable.rs"), "durable rejection test missing")
    require("PROFILE_3_SYNC_FLOAT_EXECUTABLE" in publication_text(view, "services/component-loader/src/tests.rs"), "production loader code-6 rejection test missing")

    for rel in ("docs/WASM_ROADMAP.md", "docs/WASM_FLOAT_PROFILE.md", "docs/WASM_AOT_DECISION.md", "TESTING.md"):
        text = publication_text(view, rel)
        require("c89-s2-implemented-pre-fixed-qemu-qualification" in text, f"S2 roadmap marker missing: {rel}")
    ci = publication_text(view, ".github/workflows/ci.yml")
    require("verify-c89-float-successor-implementation.py --check-contract" in ci, "S2 CI check missing")
    require("--features c89-float-executable --test c89_float_executable" in ci, "S2 Rust CI gate missing")

    if history:
        require(
            git("rev-parse", f"{IMPLEMENTATION_COMMIT}^{{tree}}").decode().strip()
            == IMPLEMENTATION_TREE,
            "S2 publication tree drift",
        )
        require(
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", IMPLEMENTATION_COMMIT, "HEAD"],
                cwd=ROOT,
                env={"PATH": os.environ.get("PATH", ""), "HOME": str(ROOT), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
                check=False,
                capture_output=True,
            ).returncode == 0,
            "S2 publication is not an ancestor of HEAD",
        )
        require(git("rev-parse", f"{DESIGN_COMMIT}^{{tree}}").decode().strip() == DESIGN_TREE, "S1 publication tree drift")
        design = git("show", f"{DESIGN_COMMIT}:{DESIGN_CONTRACT}")
        require(len(design) == DESIGN_BYTES and sha256(design) == DESIGN_SHA256, "S1 design contract history drift")
        require(
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", DESIGN_COMMIT, "HEAD"],
                cwd=ROOT,
                env={"PATH": os.environ.get("PATH", ""), "HOME": str(ROOT), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
                check=False,
                capture_output=True,
            ).returncode == 0,
            "S1 publication is not an ancestor of HEAD",
        )


def selftest() -> None:
    base = View()
    verify(base)
    contract = json.loads(base.read(CONTRACT))
    mutations = 0
    for path, value in (
        (("identity", "artifact_profile_code"), 5),
        (("authority", "release_authorized"), True),
        (("authority", "physical_duo_inputs_permitted"), 1),
        (("code5_boundary", "current_engine"), True),
        (("next_gate", "qualification_complete"), True),
        (("roadmap", "implementation_node_complete"), False),
    ):
        changed = json.loads(json.dumps(contract))
        changed[path[0]][path[1]] = value
        overlay = (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode()
        try:
            verify(View({CONTRACT: overlay}), history=False)
        except VerificationFailure:
            mutations += 1
        else:
            raise RuntimeError(f"self-test accepted contract mutation: {path}")
    for rel in contract["implementation_sources"]:
        changed = base.read(rel) + b"\n"
        try:
            verify(View({rel: changed}), history=False)
        except VerificationFailure:
            mutations += 1
        else:
            raise RuntimeError(f"self-test accepted source mutation: {rel}")
    print(f"self-test PASS: {mutations} contract/source mutations rejected")


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
        print("C8.9-S2 Float successor implementation verification: PASS")
        return 0
    except (OSError, UnicodeDecodeError, VerificationFailure, RuntimeError) as exc:
        print(f"C8.9-S2 Float successor implementation verification: FAIL\n{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
