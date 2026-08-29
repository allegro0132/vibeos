#!/usr/bin/env python3
"""Fail-closed C8.10-S2 RISC-V software-float object audit.

The audit is deliberately offline.  It resolves the repository-pinned Rust
toolchain, performs a locked release build in a temporary target directory,
uses Cargo JSON package IDs to bind the reviewed fork closure, and scans both
LLVM IR and lowered ``riscv64imac`` assembly.

The fork may contain LLVM ``fneg``, ``fabs`` and ``copysign`` operations: for
Wasm these are sign-bit transformations.  They are accepted only when the
same module lowers without an F/D instruction and without a floating-point
runtime helper.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = "nightly-2026-08-01"
TARGET = "riscv64imac-unknown-none-elf"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

EXPECTED_RUSTC_COMMIT = "ad3d0bc141a02cf446e384136d250a1f6950fed5"
EXPECTED_CARGO_COMMIT = "7c83d4cc0953b81d823e47d640c64da9b8bd4fac"
EXPECTED_LLVM_VERSION = "22.1.8"
FORK_VERSION = "1.1.0-vibeos-simd1.1"

EXPECTED_ARTIFACTS = {
    "vibeos-wasm-simd-candidate": ROOT / "wasm-simd-candidate/Cargo.toml",
    "vibeos-wasmi-simd-softfloat": ROOT
    / "vendor/wasmi-simd-softfloat/crates/wasmi/Cargo.toml",
    "vibeos-wasmi-core-simd-softfloat": ROOT
    / "vendor/wasmi-simd-softfloat/crates/core/Cargo.toml",
    "vibeos-wasmi-ir-simd-softfloat": ROOT
    / "vendor/wasmi-simd-softfloat/crates/ir/Cargo.toml",
    "vibeos-wasmi-collections-simd-softfloat": ROOT
    / "vendor/wasmi-simd-softfloat/crates/collections/Cargo.toml",
    "rustc_apfloat": None,
}

EXPECTED_FORK_FEATURES = {
    "vibeos-wasmi-simd-softfloat": {"extra-checks", "prefer-btree-collections", "simd"},
    "vibeos-wasmi-core-simd-softfloat": {"simd"},
    "vibeos-wasmi-ir-simd-softfloat": {"simd"},
    "vibeos-wasmi-collections-simd-softfloat": {"prefer-btree-collections"},
    "rustc_apfloat": set(),
}

STOCK_CHECKSUMS = {
    "wasmi": "2300d0f78cba12f14e29e8dd157ea64050c0a688179aefdb2050105805594a0c",
    "wasmi_core": "9013136083d988725953390bf668b64b7a218fabf26f8b913bbc59546b97ee27",
    "wasmi_ir": "ba1fa003f79156f406d62ef0e1464dc03e11ace37170e9fa7524299a75ad8f68",
    "wasmi_collections": "f8a8c42a2a76148d43097b1d7cc2a5bf33d5c23bd4dd69015fc887e311767884",
}

APFLOAT_VERSION = "0.2.3+llvm-462a31f5a5ab"
APFLOAT_CHECKSUM = (
    "486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad"
)

# LLVM operations whose presence would mean host/target floating-point
# semantics escaped the integer/software-float boundary.
SEMANTIC_LLVM_RE = re.compile(
    r"\b(?:fadd|fsub|fmul|fdiv|frem|fcmp|fptrunc|fpext|fptoui|fptosi|"
    r"uitofp|sitofp)\b|"
    r"@llvm\.(?!(?:fabs|copysign)\.f(?:32|64)\b)"
    r"[A-Za-z0-9_.]+\.(?:v[0-9]+)?f(?:32|64)\b"
)
SIGN_ONLY_LLVM_RE = re.compile(
    r"\bfneg\b|@llvm\.(?:fabs|copysign)\.f(?:32|64)\b"
)

# Reject the complete compiler-rt/libgcc soft-float naming family, including
# arithmetic/comparison (`__addsf3`, `__unorddf2`) and conversion helpers
# (`__fixsfdi`, `__floatundidf`, `__extendsfdf2`, `__truncdfsf2`).
FLOAT_HELPER_NAME = r"__[A-Za-z0-9_]*(?:sf|df)[A-Za-z0-9_]*"
FLOAT_LIBCALL_NAME = (
    r"(?:ceil|floor|trunc|round|roundeven|rint|nearbyint|sqrt|fmin|fmax|"
    r"fma|fmod|remainder|copysign)f?"
)
LLVM_FLOAT_HELPER_RE = re.compile(
    rf"\b(?:call|invoke)\b[^@\n]*@({FLOAT_HELPER_NAME})\b|"
    rf"\bdeclare\b[^@\n]*@({FLOAT_HELPER_NAME})\b|"
    rf"\b(?:call|invoke)\b[^@\n]*@({FLOAT_LIBCALL_NAME})\b|"
    rf"\bdeclare\b[^@\n]*@({FLOAT_LIBCALL_NAME})\b"
)
ASM_FLOAT_HELPER_RE = re.compile(
    rf"^\s*(?:call|tail)\s+({FLOAT_HELPER_NAME}|{FLOAT_LIBCALL_NAME})\b"
)

# Complete scalar F/D instruction families relevant to this target.  Matching
# is anchored at the assembly opcode so debug strings cannot trigger it.
RISCV_FORBIDDEN_OPCODE_RE = re.compile(
    r"^\s*(?:"
    r"flw|fld|fsw|fsd|c\.f(?:lw|ld|sw|sd)(?:sp)?|"
    r"fmadd\.[sd]|fmsub\.[sd]|fnmsub\.[sd]|fnmadd\.[sd]|"
    r"fadd\.[sd]|fsub\.[sd]|fmul\.[sd]|fdiv\.[sd]|fsqrt\.[sd]|"
    r"fsgnj(?:n|x)?\.[sd]|fmin\.[sd]|fmax\.[sd]|"
    r"fcvt\.[A-Za-z0-9_.]+|fmv\.[A-Za-z0-9_.]+|"
    r"feq\.[sd]|flt\.[sd]|fle\.[sd]|fclass\.[sd]"
    r"|v[a-z0-9_.]+"
    r")\b"
)


class AuditFailure(RuntimeError):
    """A fail-closed audit failure."""


@dataclass(frozen=True)
class Toolchain:
    rustc: Path
    cargo: Path
    llvm_ar: Path
    llvm_dis: Path
    llc: Path
    host: str


@dataclass(frozen=True)
class Package:
    package_id: str
    name: str
    version: str
    source: str | None
    manifest_path: Path


@dataclass
class ObjectReport:
    package: str
    rlib: Path
    objects: int = 0
    sign_only: Counter[str] | None = None

    def __post_init__(self) -> None:
        if self.sign_only is None:
            self.sign_only = Counter()


def fail(message: str) -> None:
    raise AuditFailure(message)


def audit_detector_patterns() -> None:
    semantic_fixtures = (
        "%x = fadd float %a, %b",
        "%x = fptosi double %a to i64",
        "%x = call float @llvm.sqrt.f32(float %a)",
        "%x = call double @llvm.ceil.f64(double %a)",
        "%x = call float @llvm.experimental.constrained.fmul.f32(float %a, float %b)",
        "%x = call <4 x float> @llvm.minimum.v4f32(<4 x float> %a, <4 x float> %b)",
    )
    for fixture in semantic_fixtures:
        if SEMANTIC_LLVM_RE.search(fixture) is None:
            fail(f"LLVM semantic-FP detector missed its self-test fixture: {fixture}")
    sign_only_fixtures = (
        "%x = fneg float %a",
        "%x = call float @llvm.fabs.f32(float %a)",
        "%x = call double @llvm.copysign.f64(double %a, double %b)",
    )
    for fixture in sign_only_fixtures:
        if SIGN_ONLY_LLVM_RE.search(fixture) is None:
            fail(f"LLVM sign-only detector missed its self-test fixture: {fixture}")
        if SEMANTIC_LLVM_RE.search(fixture) is not None:
            fail(f"LLVM semantic-FP detector rejected a sign-only fixture: {fixture}")
    ir_helper_fixtures = (
        "declare i32 @__unordsf2(float, float)",
        "%x = call i64 @__fixsfdi(float %a)",
        "%x = call float @ceilf(float %a)",
        "%x = call float @fmaf(float %a, float %b, float %c)",
    )
    for fixture in ir_helper_fixtures:
        if LLVM_FLOAT_HELPER_RE.search(fixture) is None:
            fail(f"LLVM FP-helper detector missed its self-test fixture: {fixture}")
    asm_helper_fixtures = ("call\t__extendsfdf2", "tail\tsqrt")
    for fixture in asm_helper_fixtures:
        if ASM_FLOAT_HELPER_RE.search(fixture) is None:
            fail(f"assembly FP-helper detector missed its self-test fixture: {fixture}")
    opcode_fixtures = (
        "\tfadd.s\tfa0, fa1, fa2",
        "\tfcvt.w.d\ta0, fa0",
        "\tc.fldsp\tfa0, 8(sp)",
    )
    for fixture in opcode_fixtures:
        if RISCV_FORBIDDEN_OPCODE_RE.search(fixture) is None:
            fail(f"RISC-V F/D/V detector missed its self-test fixture: {fixture}")
    if RISCV_FORBIDDEN_OPCODE_RE.search("\tvadd.vv\tv0, v1, v2") is None:
        fail("RISC-V V detector missed its self-test fixture")


def run(
    command: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    rendered = [os.fspath(part) for part in command]
    result = subprocess.run(
        rendered,
        cwd=cwd,
        env=None if env is None else dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostics"
        fail(f"command failed ({result.returncode}): {' '.join(rendered)}\n{detail}")
    return result


def rustup_which(rustup: Path, binary: str) -> Path:
    result = run([rustup, "which", "--toolchain", TOOLCHAIN, binary])
    path = Path(result.stdout.strip()).resolve()
    if not path.is_file():
        fail(f"rustup resolved missing {binary}: {path}")
    return path


def parse_key_value_lines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key] = value
    return values


def locate_toolchain() -> Toolchain:
    rustup_name = shutil.which("rustup")
    if rustup_name is None:
        fail("rustup is required to resolve the repository-pinned toolchain")
    rustup = Path(rustup_name).resolve()
    rustc = rustup_which(rustup, "rustc")
    cargo = rustup_which(rustup, "cargo")

    rustc_info = parse_key_value_lines(run([rustc, "-Vv"]).stdout)
    if rustc_info.get("commit-hash") != EXPECTED_RUSTC_COMMIT:
        fail(
            "pinned rustc identity mismatch: "
            f"expected {EXPECTED_RUSTC_COMMIT}, found {rustc_info.get('commit-hash')}"
        )
    if rustc_info.get("LLVM version") != EXPECTED_LLVM_VERSION:
        fail(
            "pinned LLVM identity mismatch: "
            f"expected {EXPECTED_LLVM_VERSION}, found {rustc_info.get('LLVM version')}"
        )
    host = rustc_info.get("host")
    if not host:
        fail("pinned rustc did not report its host triple")

    cargo_info = parse_key_value_lines(run([cargo, "-Vv"]).stdout)
    if cargo_info.get("commit-hash") != EXPECTED_CARGO_COMMIT:
        fail(
            "pinned Cargo identity mismatch: "
            f"expected {EXPECTED_CARGO_COMMIT}, found {cargo_info.get('commit-hash')}"
        )

    sysroot_text = run([rustc, "--print", "sysroot"]).stdout.strip()
    sysroot = Path(sysroot_text).resolve()
    llvm_bin = sysroot / "lib" / "rustlib" / host / "bin"
    tools = {name: llvm_bin / name for name in ("llvm-ar", "llvm-dis", "llc")}
    missing = [f"{name} ({path})" for name, path in tools.items() if not path.is_file()]
    if missing:
        fail("pinned llvm-tools component is incomplete: " + ", ".join(missing))
    return Toolchain(
        rustc=rustc,
        cargo=cargo,
        llvm_ar=tools["llvm-ar"],
        llvm_dis=tools["llvm-dis"],
        llc=tools["llc"],
        host=host,
    )


def audit_target_configuration(toolchain: Toolchain) -> set[str]:
    cfg = run([toolchain.rustc, "--target", TARGET, "--print", "cfg"]).stdout
    if 'target_arch="riscv64"' not in cfg or 'target_os="none"' not in cfg:
        fail(f"unexpected target configuration for {TARGET}")
    features = set(re.findall(r'^target_feature="([^"]+)"$', cfg, re.MULTILINE))
    forbidden = features & {"f", "d", "v"}
    if forbidden:
        fail(f"{TARGET} unexpectedly enables hardware FP features: {sorted(forbidden)}")
    if not {"m", "a", "c"}.issubset(features):
        fail(f"{TARGET} is missing expected IMAC features: {sorted(features)}")
    target_libdir = Path(
        run(
            [toolchain.rustc, "--target", TARGET, "--print", "target-libdir"]
        ).stdout.strip()
    )
    if not target_libdir.is_dir():
        fail(f"Rust target is not installed: {TARGET} ({target_libdir})")
    return features


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read TOML {path}: {error}")


def lock_package(
    lock: Mapping[str, Any], name: str, version: str
) -> Mapping[str, Any]:
    matches = [
        package
        for package in lock.get("package", [])
        if package.get("name") == name and package.get("version") == version
    ]
    if len(matches) != 1:
        fail(f"Cargo.lock must contain exactly one {name} {version}, found {len(matches)}")
    return matches[0]


def audit_static_manifests() -> None:
    root_manifest = load_toml(ROOT / "Cargo.toml")
    if "patch" in root_manifest:
        fail("workspace Cargo.toml must not contain a [patch] table")

    runtime = load_toml(ROOT / "wasm-runtime/Cargo.toml")
    stock_dep = runtime.get("dependencies", {}).get("wasmi")
    expected_stock_dep = {
        "version": "=1.1.0",
        "default-features": False,
        "features": ["extra-checks", "prefer-btree-collections"],
    }
    if stock_dep != expected_stock_dep:
        fail(f"Profile-1 stock Wasmi dependency drifted: {stock_dep!r}")

    candidate = load_toml(ROOT / "wasm-simd-candidate/Cargo.toml")
    candidate_dep = candidate.get("dependencies", {}).get("wasmi-simd-softfloat")
    expected_candidate_dep = {
        "package": "vibeos-wasmi-simd-softfloat",
        "path": "../vendor/wasmi-simd-softfloat/crates/wasmi",
        "default-features": False,
        "features": ["extra-checks", "prefer-btree-collections", "simd"],
        "optional": True,
    }
    if candidate_dep != expected_candidate_dep:
        fail(f"candidate fork dependency drifted: {candidate_dep!r}")

    core = load_toml(ROOT / "vendor/wasmi-simd-softfloat/crates/core/Cargo.toml")
    core_dependencies = core.get("dependencies", {})
    if "libm" in core_dependencies:
        fail("SIMD fork must not retain any libm edge")
    if core.get("features", {}).get("simd") != []:
        fail("fork core SIMD feature must be dependency-free")
    expected_apfloat = {"version": "=0.2.3", "default-features": False}
    if core_dependencies.get("rustc_apfloat") != expected_apfloat:
        fail("fork rustc_apfloat dependency identity drifted")

    lock = load_toml(ROOT / "Cargo.lock")
    for name, checksum in STOCK_CHECKSUMS.items():
        package = lock_package(lock, name, "1.1.0")
        if package.get("source") != REGISTRY_SOURCE or package.get("checksum") != checksum:
            fail(f"stock {name} 1.1.0 source/checksum drifted")
    apfloat = lock_package(lock, "rustc_apfloat", APFLOAT_VERSION)
    if (
        apfloat.get("source") != REGISTRY_SOURCE
        or apfloat.get("checksum") != APFLOAT_CHECKSUM
    ):
        fail("rustc_apfloat source/checksum drifted")


def cargo_environment(toolchain: Toolchain, target_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "RUSTC": os.fspath(toolchain.rustc),
            "CARGO_TARGET_DIR": os.fspath(target_dir),
            "CARGO_NET_OFFLINE": "true",
            "RUSTUP_TOOLCHAIN": TOOLCHAIN,
        }
    )
    return environment


def cargo_metadata(
    toolchain: Toolchain, target_dir: Path
) -> tuple[dict[str, Any], dict[str, Package]]:
    result = run(
        [
            toolchain.cargo,
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
            "--features",
            "vibeos-wasm-simd-candidate/c810-s2-acceptance",
            "--filter-platform",
            TARGET,
        ],
        env=cargo_environment(toolchain, target_dir),
    )
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"Cargo metadata was not valid JSON: {error}")
    packages: dict[str, Package] = {}
    for raw in metadata.get("packages", []):
        package = Package(
            package_id=raw["id"],
            name=raw["name"],
            version=raw["version"],
            source=raw.get("source"),
            manifest_path=Path(raw["manifest_path"]).resolve(),
        )
        packages[package.package_id] = package
    if not packages or metadata.get("resolve") is None:
        fail("Cargo metadata omitted the resolved package graph")
    return metadata, packages


def unique_package(
    packages: Mapping[str, Package], name: str, version: str | None = None
) -> Package:
    matches = [
        package
        for package in packages.values()
        if package.name == name and (version is None or package.version == version)
    ]
    if len(matches) != 1:
        suffix = "" if version is None else f" {version}"
        fail(f"resolved graph must contain exactly one {name}{suffix}, found {len(matches)}")
    return matches[0]


def non_dev_dependencies(node: Mapping[str, Any]) -> Iterable[str]:
    for dependency in node.get("deps", []):
        kinds = dependency.get("dep_kinds", [])
        if any(kind.get("kind") != "dev" for kind in kinds):
            yield dependency["pkg"]


def reachable_package_ids(
    metadata: Mapping[str, Any], root_package_id: str
) -> set[str]:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    if root_package_id not in nodes:
        fail("candidate package is absent from Cargo's resolved nodes")
    reachable: set[str] = set()
    queue = deque([root_package_id])
    while queue:
        package_id = queue.popleft()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        node = nodes.get(package_id)
        if node is None:
            fail(f"resolved dependency node is missing: {package_id}")
        queue.extend(non_dev_dependencies(node))
    return reachable


def audit_resolved_graph(
    metadata: Mapping[str, Any], packages: Mapping[str, Package]
) -> tuple[dict[str, Package], set[str]]:
    candidate = unique_package(packages, "vibeos-wasm-simd-candidate", "0.1.0")
    reachable = reachable_package_ids(metadata, candidate.package_id)
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}

    selected: dict[str, Package] = {}
    for name, expected_manifest in EXPECTED_ARTIFACTS.items():
        version = APFLOAT_VERSION if name == "rustc_apfloat" else None
        package = unique_package(packages, name, version)
        if package.package_id not in reachable:
            fail(f"candidate artifact is not reachable through non-dev edges: {name}")
        if expected_manifest is not None:
            if package.source is not None or package.manifest_path != expected_manifest.resolve():
                fail(f"candidate path provenance mismatch for {name}: {package.manifest_path}")
        elif package.source != REGISTRY_SOURCE:
            fail(f"rustc_apfloat must resolve from crates.io, found {package.source!r}")
        selected[name] = package

    for name, expected_features in EXPECTED_FORK_FEATURES.items():
        package = selected[name]
        actual = set(nodes[package.package_id].get("features", []))
        if actual != expected_features:
            fail(
                f"resolved features drifted for {name}: "
                f"expected {sorted(expected_features)}, found {sorted(actual)}"
            )
        if "std" in actual:
            fail(f"forbidden fork feature enabled for {name}: {sorted(actual)}")

    fork_core = selected["vibeos-wasmi-core-simd-softfloat"]
    fork_core_deps = {
        packages[package_id].name
        for package_id in non_dev_dependencies(nodes[fork_core.package_id])
    }
    if fork_core_deps != {"rustc_apfloat"}:
        fail(f"fork core dependency closure drifted: {sorted(fork_core_deps)}")

    if any(packages[package_id].name == "libm" for package_id in reachable):
        fail("libm is reachable from the fixed-SIMD candidate")
    if any(
        packages[package_id].name in STOCK_CHECKSUMS
        and packages[package_id].source == REGISTRY_SOURCE
        for package_id in reachable
    ):
        fail("stock Wasmi escaped into the isolated SIMD candidate closure")
    return selected, reachable


def cargo_build_artifacts(
    toolchain: Toolchain,
    target_dir: Path,
    selected: Mapping[str, Package],
    packages: Mapping[str, Package],
) -> dict[str, Path]:
    result = run(
        [
            toolchain.cargo,
            "build",
            "--offline",
            "--locked",
            "-p",
            "vibeos-wasm-simd-candidate",
            "--features",
            "c810-s2-acceptance",
            "--target",
            TARGET,
            "--release",
            "--message-format=json-render-diagnostics",
        ],
        env=cargo_environment(toolchain, target_dir),
    )
    selected_ids = {package.package_id: name for name, package in selected.items()}
    candidate_rlibs: dict[str, Path] = {}
    for number, line in enumerate(result.stdout.splitlines(), 1):
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            fail(f"Cargo build stdout line {number} was not JSON: {error}")
        if message.get("reason") != "compiler-artifact":
            continue
        package_id = message.get("package_id")
        filenames = [
            Path(filename).resolve()
            for filename in message.get("filenames", [])
            if filename.endswith(".rlib")
        ]
        if package_id in selected_ids and filenames:
            name = selected_ids[package_id]
            if len(filenames) != 1 or name in candidate_rlibs:
                fail(f"ambiguous candidate rlib artifact for {name}: {filenames}")
            candidate_rlibs[name] = filenames[0]

    missing = sorted(set(EXPECTED_ARTIFACTS) - set(candidate_rlibs))
    if missing:
        fail(f"Cargo JSON omitted candidate rlibs: {missing}")
    target_root = (target_dir / TARGET / "release").resolve()
    for name, path in candidate_rlibs.items():
        if not path.is_file() or not path.is_relative_to(target_root):
            fail(f"untrusted or missing Cargo artifact for {name}: {path}")
    return candidate_rlibs


def safe_archive_members(toolchain: Toolchain, rlib: Path) -> list[str]:
    members = run([toolchain.llvm_ar, "t", rlib]).stdout.splitlines()
    if not members or len(members) != len(set(members)):
        fail(f"empty archive or duplicate members in {rlib}")
    for member in members:
        pure = PurePosixPath(member)
        if pure.is_absolute() or ".." in pure.parts or len(pure.parts) != 1:
            fail(f"unsafe archive member in {rlib}: {member!r}")
    objects = [member for member in members if member.endswith(".o")]
    if not objects:
        fail(f"candidate rlib contains no object/bitcode members: {rlib}")
    return objects


def matching_lines(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str, str]]:
    matches: list[tuple[int, str, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            for number, line in enumerate(handle, 1):
                match = pattern.search(line)
                if match is not None:
                    token = next(
                        (group for group in match.groups() if group is not None),
                        match.group(0),
                    )
                    matches.append((number, token, line.rstrip()))
    except (OSError, UnicodeError) as error:
        fail(f"cannot scan generated text {path}: {error}")
    return matches


def describe_matches(
    package: str, member: str, kind: str, matches: Sequence[tuple[int, str, str]]
) -> str:
    examples = "\n".join(
        f"  {member}:{line}: {text}" for line, _token, text in matches[:12]
    )
    extra = "" if len(matches) <= 12 else f"\n  ... {len(matches) - 12} more"
    return f"{package}: forbidden {kind} ({len(matches)} matches)\n{examples}{extra}"


def audit_rlib(
    toolchain: Toolchain, package: str, rlib: Path, extraction_root: Path
) -> ObjectReport:
    package_dir = extraction_root / package
    package_dir.mkdir(mode=0o700)
    object_members = safe_archive_members(toolchain, rlib)
    run([toolchain.llvm_ar, "x", rlib], cwd=package_dir)

    report = ObjectReport(package=package, rlib=rlib)
    failures: list[str] = []
    for index, member in enumerate(object_members):
        object_path = package_dir / member
        if not object_path.is_file():
            fail(f"llvm-ar did not extract expected object: {object_path}")
        ir_path = package_dir / f"object-{index}.ll"
        asm_path = package_dir / f"object-{index}.s"
        run([toolchain.llvm_dis, object_path, "-o", ir_path])
        run([toolchain.llc, "-filetype=asm", object_path, "-o", asm_path])
        report.objects += 1

        semantic = matching_lines(ir_path, SEMANTIC_LLVM_RE)
        ir_helpers = matching_lines(ir_path, LLVM_FLOAT_HELPER_RE)
        fp_opcodes = matching_lines(asm_path, RISCV_FORBIDDEN_OPCODE_RE)
        asm_helpers = matching_lines(asm_path, ASM_FLOAT_HELPER_RE)
        if semantic:
            failures.append(describe_matches(package, member, "LLVM FP", semantic))
        if ir_helpers:
            failures.append(
                describe_matches(package, member, "LLVM FP helper", ir_helpers)
            )
        if fp_opcodes:
            failures.append(
                describe_matches(package, member, "RISC-V F/D/V opcode", fp_opcodes)
            )
        if asm_helpers:
            failures.append(
                describe_matches(package, member, "RISC-V FP helper", asm_helpers)
            )

        sign_only = matching_lines(ir_path, SIGN_ONLY_LLVM_RE)
        for _line, token, _text in sign_only:
            report.sign_only[token] += 1
        # This is the object-level proof for accepted sign operations: the
        # exact module containing them was lowered above, and neither an F/D
        # opcode nor an FP helper is allowed in that module's assembly.
        if sign_only and (fp_opcodes or asm_helpers):
            failures.append(
                f"{package}:{member}: sign-only LLVM operations did not lower "
                "to an integer-only assembly path"
            )

    if failures:
        fail("\n".join(failures))
    return report


def main() -> int:
    try:
        audit_detector_patterns()
        toolchain = locate_toolchain()
        target_features = audit_target_configuration(toolchain)
        audit_static_manifests()
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c810-s2-riscv-object-"
        ) as temporary:
            audit_root = Path(temporary).resolve()
            target_dir = audit_root / "cargo-target"
            extraction_root = audit_root / "objects"
            target_dir.mkdir(mode=0o700)
            extraction_root.mkdir(mode=0o700)

            metadata, packages = cargo_metadata(toolchain, target_dir)
            selected, _reachable = audit_resolved_graph(metadata, packages)
            candidate_rlibs = cargo_build_artifacts(
                toolchain, target_dir, selected, packages
            )
            reports = [
                audit_rlib(
                    toolchain,
                    name,
                    candidate_rlibs[name],
                    extraction_root,
                )
                for name in sorted(candidate_rlibs)
            ]

        print("C8.10-S2 RISC-V object audit: PASS")
        print(
            "toolchain: "
            f"{TOOLCHAIN} rustc={EXPECTED_RUSTC_COMMIT[:12]} "
            f"cargo={EXPECTED_CARGO_COMMIT[:12]} LLVM={EXPECTED_LLVM_VERSION}"
        )
        print(f"target: {TARGET}; features={','.join(sorted(target_features))}; f/d/v=absent")
        for report in reports:
            sign_summary = ", ".join(
                f"{name}={count}" for name, count in sorted(report.sign_only.items())
            )
            if not sign_summary:
                sign_summary = "none"
            print(
                f"artifact: {report.package}; objects={report.objects}; "
                f"semantic-fp=0; fp-helpers=0; f/d/v-opcodes=0; "
                f"sign-only={sign_summary}; asm-proof=integer-only"
            )
        print("isolation: stock Wasmi and libm unreachable; stock lock checksums verified")
        return 0
    except AuditFailure as error:
        print(f"C8.10-S2 RISC-V object audit: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
