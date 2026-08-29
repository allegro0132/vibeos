#!/usr/bin/env python3
"""Offline C8.12-R2 Reference Types facade and dependency audit."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FACADE_FILES = (
    "wasmi-reference-validation/Cargo.toml",
    "wasmi-reference-validation/src/lib.rs",
)
EXPECTED_FACADE_SHA256 = "dfe572e3a02987a8b9cdb4b542de35d77394ede5da5a47b1a8e4d9b3b9fc4991"
FACADE_VERSION = "1.1.0-vibeos-ref1.1"
BASE_VERSION = "1.1.0-vibeos-f2.1"
BASE_TREE = "c55904f72c70f9a0d807a13e678fec01b7c78f5a"
BASE_PROVENANCE_SHA256 = "7a3ddc2ae720d4fe8a9ebf8d016f2983f7a48dad6003799437a47020b9be9359"


class Failure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def files() -> dict[str, bytes]:
    return {path: (ROOT / path).read_bytes() for path in FACADE_FILES}


def digest(values: dict[str, bytes]) -> str:
    state = hashlib.sha256()
    for path, payload in sorted(values.items()):
        state.update(path.encode())
        state.update(b"\0")
        state.update(payload)
        state.update(b"\n")
    return state.hexdigest()


def verify(values: dict[str, bytes]) -> None:
    require(digest(values) == EXPECTED_FACADE_SHA256, "facade content drift")
    manifest = tomllib.loads(values[FACADE_FILES[0]].decode())
    package = manifest.get("package", {})
    require(package.get("name") == "vibeos-wasmi-reference-validation" and package.get("version") == FACADE_VERSION, "facade identity drift")
    require(package.get("publish") is False and manifest.get("features", {}).get("default") == [], "facade publication/default drift")
    require("simd" not in manifest.get("features", {}), "SIMD feature leaked into facade")
    dependency = manifest.get("dependencies", {}).get("wasmi-reference-base")
    require(dependency == {"package": "vibeos-wasmi-softfloat", "path": "../vendor/wasmi-softfloat/crates/wasmi", "version": f"={BASE_VERSION}", "default-features": False}, "base dependency drift")
    source = values[FACADE_FILES[1]].decode()
    require("pub use wasmi_reference_base::*;" in source and "unsafe" not in source and "libm" not in source, "facade is not a pure safe re-export")

    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    members = root.get("workspace", {}).get("members", [])
    require("wasmi-reference-validation" in members and "wasm-reference-candidate" in members, "workspace member missing")
    candidate = tomllib.loads((ROOT / "wasm-reference-candidate/Cargo.toml").read_text())
    require(candidate.get("features", {}).get("default") == [] and candidate.get("features", {}).get("c812-r2-acceptance") == ["dep:wasmi-reference", "dep:wasmparser"], "candidate feature gate drift")
    edge = candidate.get("dependencies", {}).get("wasmi-reference")
    require(edge == {"package": "vibeos-wasmi-reference-validation", "path": "../wasmi-reference-validation", "version": f"={FACADE_VERSION}", "default-features": False, "features": ["extra-checks", "prefer-btree-collections"], "optional": True}, "candidate engine edge drift")
    parser = candidate.get("dependencies", {}).get("wasmparser")
    require(parser.get("version") == "=0.239.0" and parser.get("optional") is True, "candidate parser pin drift")

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    locked = [item for item in lock.get("package", []) if item.get("name") == "vibeos-wasmi-reference-validation"]
    require(len(locked) == 1 and locked[0].get("version") == FACADE_VERSION and "source" not in locked[0] and "checksum" not in locked[0], "facade lock identity drift")
    provenance = (ROOT / "vendor/wasmi-softfloat/PROVENANCE.toml").read_bytes()
    require(hashlib.sha256(provenance).hexdigest() == BASE_PROVENANCE_SHA256, "base provenance drift")


def selftest(values: dict[str, bytes]) -> None:
    changed = dict(values)
    changed[FACADE_FILES[1]] += b"\n// drift\n"
    try:
        verify(changed)
    except Failure:
        return
    raise Failure("source mutation was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    try:
        values = files()
        verify(values)
        if arguments.self_test:
            selftest(values)
        print(f"C8.12-R2 supply-chain audit: PASS (base-tree={BASE_TREE}; facade-sha256={digest(values)})")
        return 0
    except (Failure, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        print(f"C8.12-R2 supply-chain audit: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
