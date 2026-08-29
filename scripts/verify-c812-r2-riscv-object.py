#!/usr/bin/env python3
"""C8.12-R2 RISC-V object audit for the Reference Types candidate closure."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts/verify-c810-s2-riscv-object.py"
SELECTED = {
    "vibeos-wasm-reference-candidate": ROOT / "wasm-reference-candidate/Cargo.toml",
    "vibeos-wasmi-reference-validation": ROOT / "wasmi-reference-validation/Cargo.toml",
    "vibeos-wasmi-softfloat": ROOT / "vendor/wasmi-softfloat/crates/wasmi/Cargo.toml",
    "vibeos-wasmi-core-softfloat": ROOT / "vendor/wasmi-softfloat/crates/core/Cargo.toml",
    "vibeos-wasmi-ir-softfloat": ROOT / "vendor/wasmi-softfloat/crates/ir/Cargo.toml",
    "vibeos-wasmi-collections-softfloat": ROOT / "vendor/wasmi-softfloat/crates/collections/Cargo.toml",
    "rustc_apfloat": None,
}
FEATURES = {
    "vibeos-wasm-reference-candidate": {"c812-r2-acceptance", "default"},
    "vibeos-wasmi-reference-validation": {"default", "extra-checks", "prefer-btree-collections"},
    "vibeos-wasmi-softfloat": {"extra-checks", "prefer-btree-collections"},
    "vibeos-wasmi-core-softfloat": set(),
    "vibeos-wasmi-ir-softfloat": set(),
    "vibeos-wasmi-collections-softfloat": {"prefer-btree-collections"},
    "rustc_apfloat": set(),
}


def load_base():
    spec = importlib.util.spec_from_file_location("c810_object", BASE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load RISC-V object verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def metadata(base, toolchain, target_dir):
    result = base.run([
        toolchain.cargo, "metadata", "--offline", "--locked", "--format-version", "1",
        "--features", "vibeos-wasm-reference-candidate/c812-r2-acceptance",
        "--filter-platform", base.TARGET,
    ], env=base.cargo_environment(toolchain, target_dir))
    raw = json.loads(result.stdout)
    packages = {
        item["id"]: base.Package(item["id"], item["name"], item["version"], item.get("source"), Path(item["manifest_path"]).resolve())
        for item in raw["packages"]
    }
    return raw, packages


def select_closure(base, raw, packages):
    root = base.unique_package(packages, "vibeos-wasm-reference-candidate", "0.1.0")
    reachable = base.reachable_package_ids(raw, root.package_id)
    nodes = {node["id"]: node for node in raw["resolve"]["nodes"]}
    selected = {}
    for name, manifest in SELECTED.items():
        version = base.APFLOAT_VERSION if name == "rustc_apfloat" else None
        package = base.unique_package(packages, name, version)
        if package.package_id not in reachable:
            base.fail(f"Reference Types closure does not reach {name}")
        if manifest is not None and (package.source is not None or package.manifest_path != manifest.resolve()):
            base.fail(f"path provenance mismatch for {name}")
        if manifest is None and package.source != base.REGISTRY_SOURCE:
            base.fail("rustc_apfloat registry provenance drifted")
        actual = set(nodes[package.package_id].get("features", []))
        if actual != FEATURES[name]:
            base.fail(f"resolved feature drift for {name}: {sorted(actual)}")
        selected[name] = package
    if any(packages[item].name == "libm" for item in reachable):
        base.fail("libm is reachable from Reference Types closure")
    return selected


def build(base, toolchain, target_dir, selected):
    result = base.run([
        toolchain.cargo, "build", "--offline", "--locked", "-p", "vibeos-wasm-reference-candidate",
        "--features", "c812-r2-acceptance", "--target", base.TARGET, "--release",
        "--message-format=json-render-diagnostics",
    ], env=base.cargo_environment(toolchain, target_dir))
    ids = {package.package_id: name for name, package in selected.items()}
    artifacts = {}
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact" or message.get("package_id") not in ids:
            continue
        rlibs = [Path(item).resolve() for item in message.get("filenames", []) if item.endswith(".rlib")]
        if len(rlibs) == 1:
            artifacts[ids[message["package_id"]]] = rlibs[0]
    missing = sorted(set(SELECTED) - set(artifacts))
    if missing:
        base.fail(f"Cargo omitted Reference Types closure rlibs: {missing}")
    return artifacts


def main() -> int:
    base = load_base()
    try:
        base.audit_detector_patterns()
        toolchain = base.locate_toolchain()
        target_features = base.audit_target_configuration(toolchain)
        with tempfile.TemporaryDirectory(prefix="vibeos-c812-r2-riscv-object-") as temporary:
            audit_root = Path(temporary)
            target_dir = audit_root / "cargo-target"
            extraction = audit_root / "objects"
            target_dir.mkdir(mode=0o700)
            extraction.mkdir(mode=0o700)
            raw, packages = metadata(base, toolchain, target_dir)
            selected = select_closure(base, raw, packages)
            artifacts = build(base, toolchain, target_dir, selected)
            reports = [base.audit_rlib(toolchain, name, artifacts[name], extraction) for name in sorted(artifacts)]
        print("C8.12-R2 RISC-V object audit: PASS")
        print(f"target: {base.TARGET}; features={','.join(sorted(target_features))}; f/d/v=absent")
        for report in reports:
            print(f"artifact: {report.package}; objects={report.objects}; semantic-fp=0; fp-helpers=0; f/d/v-opcodes=0")
        print("isolation: code-9 facade exact; libm unreachable; Reference Types validation only")
        return 0
    except (base.AuditFailure, OSError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        print(f"C8.12-R2 RISC-V object audit: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
