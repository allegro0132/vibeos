#!/usr/bin/env python3
"""Offline C8.10-S2 SIMD-fork provenance and inertness verifier."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORK = ROOT / "vendor/wasmi-simd-softfloat"
DOMAIN = b"vibeos-c810-s2-simd-fork-sha256-v1\0"
EXPECTED_FORK_SHA256 = "8f8113e46b928204e957ebcdb472cec13c7aee0b0acebc34c4883d27d9b751cb"
EXPECTED_VERSION = "1.1.0-vibeos-simd1.1"
FORK_PACKAGES = {
    "crates/wasmi/Cargo.toml": "vibeos-wasmi-simd-softfloat",
    "crates/core/Cargo.toml": "vibeos-wasmi-core-simd-softfloat",
    "crates/ir/Cargo.toml": "vibeos-wasmi-ir-simd-softfloat",
    "crates/collections/Cargo.toml": "vibeos-wasmi-collections-simd-softfloat",
}


class Failure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Failure(message)


def fork_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(FORK.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(FORK).as_posix()
        if (
            "/target/" in f"/{relative}/"
            or relative.endswith("/Cargo.lock")
            or relative in {"PROVENANCE.md", "PROVENANCE.toml", "UPSTREAM_FILES.sha256"}
        ):
            continue
        files[relative] = path.read_bytes()
    if not files:
        fail("SIMD fork is empty")
    return files


def digest(files: dict[str, bytes]) -> str:
    state = hashlib.sha256(DOMAIN)
    for path, payload in sorted(files.items()):
        state.update(path.encode())
        state.update(b"\0")
        state.update(hashlib.sha256(payload).digest())
    return state.hexdigest()


def parse_toml(files: dict[str, bytes], path: str) -> dict:
    try:
        return tomllib.loads(files[path].decode())
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"invalid fork manifest {path}: {error}")


def verify_fork(files: dict[str, bytes], expected_digest: str) -> None:
    actual = digest(files)
    if actual != expected_digest:
        fail(f"SIMD fork digest mismatch: expected {expected_digest}, found {actual}")
    for path, package in FORK_PACKAGES.items():
        manifest = parse_toml(files, path)
        identity = manifest.get("package", {})
        if identity.get("name") != package or identity.get("version") != EXPECTED_VERSION:
            fail(f"fork package identity drifted: {path}")
        if identity.get("publish") is not False:
            fail(f"fork package became publishable: {path}")
    core = parse_toml(files, "crates/core/Cargo.toml")
    if core.get("features", {}).get("simd") != []:
        fail("core SIMD feature must have no external arithmetic edge")
    for path, payload in files.items():
        text = payload.decode(errors="ignore")
        if "libm" in text:
            fail(f"libm reference escaped into SIMD fork: {path}")
    simd = files["crates/core/src/simd.rs"].decode()
    required = (
        "f32x4_add(lhs: V128, rhs: V128) -> V128 = wasm::f32_add",
        "f64x2_div(lhs: V128, rhs: V128) -> V128 = wasm::f64_div",
        "f32x4_sqrt(v128: V128) -> V128 = wasm::f32_sqrt",
        "f64x2_ge(lhs: V128, rhs: V128) -> V128 = wasm::f64_ge",
        "wasm::f32_add(wasm::f32_mul(a, b), c)",
        "wasm::f64_add(wasm::f64_neg(wasm::f64_mul(a, b)), c)",
    )
    if any(item not in simd for item in required):
        fail("deterministic fixed/compiled-relaxed SIMD mapping drifted")
    forbidden = (".mul_add(", "libm::", "|a: f32, b: f32| a + b", "|a: f64, b: f64| a * b")
    if any(item in simd for item in forbidden):
        fail("host float arithmetic returned to SIMD implementation")
    value = files["crates/core/src/value.rs"].decode()
    if "u128::from_le_bytes(self.0)" not in value or "from_ne_bytes" in value:
        fail("V128 bit boundary is not explicitly little-endian")


def root_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def verify_repository() -> None:
    root = tomllib.loads(root_text("Cargo.toml"))
    if "patch" in root:
        fail("workspace must not contain a Cargo patch table")
    if "wasm-simd-candidate" not in root.get("workspace", {}).get("members", []):
        fail("SIMD candidate is not a workspace member")

    candidate = tomllib.loads(root_text("wasm-simd-candidate/Cargo.toml"))
    if candidate.get("features", {}).get("default") != []:
        fail("SIMD candidate default feature set must remain empty")
    if candidate.get("features", {}).get("c810-s2-acceptance") != [
        "dep:wasmi-simd-softfloat"
    ]:
        fail("SIMD candidate acceptance gate drifted")
    dependency = candidate.get("dependencies", {}).get("wasmi-simd-softfloat")
    expected = {
        "package": "vibeos-wasmi-simd-softfloat",
        "path": "../vendor/wasmi-simd-softfloat/crates/wasmi",
        "default-features": False,
        "features": ["extra-checks", "prefer-btree-collections", "simd"],
        "optional": True,
    }
    if dependency != expected:
        fail("SIMD candidate path/feature identity drifted")

    source = root_text("wasm-simd-candidate/src/lib.rs")
    if "production_ready: false" not in source or "wasm_relaxed_simd(false)" not in source:
        fail("candidate became production-ready or relaxed-SIMD-enabled")
    engine = root_text("component-format/src/engine.rs")
    if "PROFILE_4_SYNC_SIMD_VALIDATION" not in engine or "runtime_ready: false" not in engine:
        fail("code-7 validation-only contract drifted")
    resolver = engine.split("pub fn current_validation_engine_identity", 1)[1]
    if "PROFILE_4_SYNC_SIMD_VALIDATION {\n        None" not in resolver:
        fail("code 7 became current")
    if "PROFILE_2_SYNC_FLOAT {\n        None" not in resolver:
        fail("permanently inert code 5 changed")

    lock = tomllib.loads(root_text("Cargo.lock"))
    packages = lock.get("package", [])
    for name in FORK_PACKAGES.values():
        matches = [item for item in packages if item.get("name") == name]
        if len(matches) != 1 or matches[0].get("version") != EXPECTED_VERSION:
            fail(f"lock identity drifted for {name}")
        if "source" in matches[0] or "checksum" in matches[0]:
            fail(f"fork package is not path-only in lock: {name}")
    core = next(item for item in packages if item.get("name") == "vibeos-wasmi-core-simd-softfloat")
    if "libm" in core.get("dependencies", []):
        fail("libm is reachable through the locked SIMD core")


def self_test(files: dict[str, bytes]) -> None:
    cases: list[tuple[str, dict[str, bytes], str]] = []
    changed = dict(files)
    changed["crates/core/src/simd.rs"] += b"\n// drift\n"
    cases.append(("source drift", changed, "digest mismatch"))
    changed = dict(files)
    changed["crates/core/Cargo.toml"] = changed["crates/core/Cargo.toml"].replace(
        b"simd = []", b'simd = ["dep:libm"]'
    )
    cases.append(("libm edge", changed, "digest mismatch"))
    changed = dict(files)
    changed["crates/core/src/value.rs"] = changed["crates/core/src/value.rs"].replace(
        b"from_le_bytes", b"from_ne_bytes"
    )
    cases.append(("native endian", changed, "digest mismatch"))
    for name, changed, expected in cases:
        try:
            verify_fork(changed, EXPECTED_FORK_SHA256)
        except Failure as error:
            if expected not in str(error):
                fail(f"self-test {name} failed for the wrong reason: {error}")
        else:
            fail(f"self-test did not reject {name}")
    print(f"self-tests: {len(cases)} mutation cases rejected")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--print-digest", action="store_true")
    args = parser.parse_args()
    try:
        files = fork_files()
        actual = digest(files)
        if args.print_digest:
            print(actual)
            return 0
        verify_fork(files, EXPECTED_FORK_SHA256)
        verify_repository()
        if args.self_test:
            self_test(files)
        print(f"C8.10-S2 supply-chain audit: PASS ({len(files)} files; sha256={actual})")
        return 0
    except (Failure, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        print(f"C8.10-S2 supply-chain audit: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
