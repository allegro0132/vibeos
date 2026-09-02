#!/usr/bin/env python3
"""Offline C8.11-S2 executable-SIMD provenance and isolation audit."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts/verify-c810-s2-supply-chain.py"
FACADE_FILES = (
    "wasmi-simd-executable-softfloat/Cargo.toml",
    "wasmi-simd-executable-softfloat/src/lib.rs",
)
EXPECTED_FACADE_SHA256 = "99c4953c437aff9c4e40710cb373c54bf419aac1029d93bf9596c82c21be4615"
FACADE_VERSION = "1.1.0-vibeos-simd2.1"
BASE_VERSION = "1.1.0-vibeos-simd1.1"


class Failure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Failure(message)


def load_base():
    spec = importlib.util.spec_from_file_location("c810_supply", BASE_SCRIPT)
    if spec is None or spec.loader is None:
        fail("cannot load C8.10 supply-chain verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def facade_files() -> dict[str, bytes]:
    return {path: (ROOT / path).read_bytes() for path in FACADE_FILES}


def facade_digest(files: dict[str, bytes]) -> str:
    state = hashlib.sha256()
    for path, payload in sorted(files.items()):
        state.update(path.encode())
        state.update(b"\0")
        state.update(payload)
        state.update(b"\n")
    return state.hexdigest()


def verify_facade(files: dict[str, bytes], expected: str) -> None:
    actual = facade_digest(files)
    if actual != expected:
        fail(f"executable facade digest mismatch: expected {expected}, found {actual}")
    manifest = tomllib.loads(files[FACADE_FILES[0]].decode())
    package = manifest.get("package", {})
    if package.get("name") != "vibeos-wasmi-simd-executable-softfloat" or package.get("version") != FACADE_VERSION:
        fail("executable facade package identity drifted")
    if package.get("publish") is not False or manifest.get("features", {}).get("default") != []:
        fail("executable facade became publishable or default-enabled")
    dependency = manifest.get("dependencies", {}).get("wasmi-simd-base")
    if dependency != {
        "package": "vibeos-wasmi-simd-softfloat",
        "path": "../vendor/wasmi-simd-softfloat/crates/wasmi",
        "version": f"={BASE_VERSION}",
        "default-features": False,
    }:
        fail("executable facade base edge drifted")
    source = files[FACADE_FILES[1]].decode()
    if "pub use wasmi_simd_base::*;" not in source or "unsafe" in source or "libm" in source:
        fail("facade is no longer a pure safe re-export")


def verify_repository() -> None:
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    members = root.get("workspace", {}).get("members", [])
    for member in ("wasm-simd-executable", "wasmi-simd-executable-softfloat"):
        if member not in members:
            fail(f"workspace member missing: {member}")
    wrapper = tomllib.loads((ROOT / "wasm-simd-executable/Cargo.toml").read_text())
    if wrapper.get("features", {}).get("default") != [] or wrapper.get("features", {}).get("c811-s2-acceptance") != ["dep:wasmi-simd-executable"]:
        fail("code-8 wrapper feature gate drifted")
    dependency = wrapper.get("dependencies", {}).get("wasmi-simd-executable")
    if dependency != {
        "package": "vibeos-wasmi-simd-executable-softfloat",
        "path": "../wasmi-simd-executable-softfloat",
        "version": f"={FACADE_VERSION}",
        "default-features": False,
        "features": ["extra-checks", "prefer-btree-collections", "simd"],
        "optional": True,
    }:
        fail("code-8 wrapper engine edge drifted")
    source = (ROOT / "wasm-simd-executable/src/lib.rs").read_text()
    required = ("profile_code: 8", "production_ready: false", ".wasm_simd(true)", ".wasm_relaxed_simd(false)")
    if any(marker not in source for marker in required):
        fail("code-8 wrapper semantics or pre-qualification boundary drifted")
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    matches = [item for item in lock.get("package", []) if item.get("name") == "vibeos-wasmi-simd-executable-softfloat"]
    if len(matches) != 1 or matches[0].get("version") != FACADE_VERSION or "source" in matches[0] or "checksum" in matches[0]:
        fail("locked executable facade identity drifted")


def selftest(files: dict[str, bytes]) -> None:
    changed = dict(files)
    changed[FACADE_FILES[1]] += b"\n// drift\n"
    try:
        verify_facade(changed, EXPECTED_FACADE_SHA256)
    except Failure:
        pass
    else:
        fail("source-drift self-test was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        base = load_base()
        base_files = base.fork_files()
        base.verify_fork(base_files, base.EXPECTED_FORK_SHA256)
        base.verify_repository()
        files = facade_files()
        verify_facade(files, EXPECTED_FACADE_SHA256)
        verify_repository()
        if args.self_test:
            selftest(files)
        print(f"C8.11-S2 supply-chain audit: PASS (base={len(base_files)} files; facade={len(files)} files; sha256={facade_digest(files)})")
        return 0
    except (Failure, OSError, UnicodeError, tomllib.TOMLDecodeError, RuntimeError) as error:
        print(f"C8.11-S2 supply-chain audit: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
