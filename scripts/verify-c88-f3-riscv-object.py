#!/usr/bin/env python3
"""Fail-closed C8.8-F3 RISC-V Canonical-ABI float object audit.

This verifier is deliberately offline. It resolves the repository-pinned
nightly toolchain, builds ``vibeos-component-runtime`` with only the
``c88-f3-acceptance`` feature for ``riscv64imac-unknown-none-elf`` in a fresh
target directory, binds the resulting target dependency closure, and scans
the emitted LLVM IR, symbols, and lowered assembly.

The complete target closure must contain no RISC-V F/D instructions. The
workspace-owned part of the closure (where the F3 bit codec lives) must also
contain no LLVM floating-point semantics and no compiler-rt/libm float helper
references. Stock Profile-1 Wasmi and libm already contain software-float
code; those unchanged external artifacts are inventoried as an inherited
baseline rather than attributed to the dependency-free F3 feature.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = "nightly-2026-08-01"
TARGET = "riscv64imac-unknown-none-elf"
ROOT_PACKAGE = "vibeos-component-runtime"
ROOT_VERSION = "0.1.0"
ACCEPTANCE_FEATURE = "c88-f3-acceptance"

EXPECTED_RUSTC_COMMIT = "ad3d0bc141a02cf446e384136d250a1f6950fed5"
EXPECTED_CARGO_COMMIT = "7c83d4cc0953b81d823e47d640c64da9b8bd4fac"
EXPECTED_LLVM_VERSION = "22.1.8"

EXPECTED_LOCAL_ARTIFACTS = {
    "vibeos-component-format": ROOT / "component-format/Cargo.toml",
    "vibeos-component-runtime": ROOT / "component-runtime/Cargo.toml",
    "vibeos-wasm-runtime": ROOT / "wasm-runtime/Cargo.toml",
}

# These packages are an independently frozen Profile-1 baseline. They are
# reachable with or without the dependency-free F3 feature and are expected to
# contain stock software-float semantics/helpers. No other external package may
# introduce such code without updating and re-reviewing this audit.
INHERITED_FP_BASELINE = {
    ("libm", "0.2.16"),
    ("wasmi", "1.1.0"),
    ("wasmi_core", "1.1.0"),
    ("wasmi_ir", "1.1.0"),
}

# Filled after resolving the locked, target-only release artifact closure. It
# binds package name, version, and registry/path provenance, not temporary
# build paths or nondeterministic object bytes.
EXPECTED_TARGET_CLOSURE_SHA256 = (
    "c2295c33c17e489953cf014cb7f5acef9b0f674b4fd09142ba2dcc492736f618"
)
CLOSURE_DIGEST_DOMAIN = b"vibeos-c88-f3-riscv-target-closure-v1\0"


# F3 permits integer bit transport only. Unlike F2, even sign-only LLVM float
# operations are forbidden because Canonical ABI NaN handling is integer-based.
SEMANTIC_LLVM_RE = re.compile(
    r"\b(?:fadd|fsub|fmul|fdiv|frem|fcmp|fneg|fptrunc|fpext|fptoui|fptosi|"
    r"uitofp|sitofp)\b|"
    r"@llvm\.[A-Za-z0-9_.]+\.(?:v[0-9]+)?f(?:32|64)\b"
)

# Reject every host-LLVM floating type in workspace-owned executable IR, even
# when it is used only for transport (load/store/phi/select/bitcast/call/ret).
# Canonical ABI F3 must carry these values as integer bits throughout. Matching
# is performed after removing comments, quoted strings/identifiers, metadata,
# and sigil-prefixed SSA/global names so a symbol named `float` is not evidence
# of a host floating type.
LLVM_FLOAT_TYPE_RE = re.compile(
    r"(?<![-A-Za-z$._0-9])"
    r"(half|bfloat|float|double|fp128|x86_fp80)"
    r"(?![-A-Za-z$._0-9])"
)
LLVM_SIGIL_IDENTIFIER_RE = re.compile(r"[%@$!#][-A-Za-z$._0-9]+")
LLVM_LEADING_LABEL_RE = re.compile(r"^\s*[-A-Za-z$._0-9]+:\s*")

FLOAT_HELPER_NAME = r"__[A-Za-z0-9_]*(?:sf|df)[A-Za-z0-9_]*"
FLOAT_LIBCALL_NAME = (
    r"(?:acos|acosh|asin|asinh|atan|atan2|atanh|cbrt|ceil|copysign|cos|cosh|"
    r"erf|erfc|exp|exp2|expm1|fabs|fdim|floor|fma|fmax|fmin|fmod|frexp|"
    r"hypot|ilogb|ldexp|lgamma|log|log10|log1p|log2|modf|nearbyint|"
    r"nextafter|pow|remainder|remquo|rint|round|roundeven|scalbn|sin|sinh|"
    r"sqrt|tan|tanh|tgamma|trunc)f?"
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
FLOAT_SYMBOL_RE = re.compile(
    rf"(?<![A-Za-z0-9_])({FLOAT_HELPER_NAME}|{FLOAT_LIBCALL_NAME})(?![A-Za-z0-9_])"
)

RISCV_FP_OPCODE = (
    r"(?:flw|fld|fsw|fsd|c\.f(?:lw|ld|sw|sd)(?:sp)?|"
    r"fmadd\.[sd]|fmsub\.[sd]|fnmsub\.[sd]|fnmadd\.[sd]|"
    r"fadd\.[sd]|fsub\.[sd]|fmul\.[sd]|fdiv\.[sd]|fsqrt\.[sd]|"
    r"fsgnj(?:n|x)?\.[sd]|fmin\.[sd]|fmax\.[sd]|"
    r"fcvt\.[A-Za-z0-9_.]+|fmv\.[A-Za-z0-9_.]+|"
    r"feq\.[sd]|flt\.[sd]|fle\.[sd]|fclass\.[sd]|"
    r"frcsr|fscsr|frrm|fsrm|frflags|fsflags)"
)
ASM_FP_OPCODE_RE = re.compile(rf"^\s*({RISCV_FP_OPCODE})\b")
OBJDUMP_FP_OPCODE_RE = re.compile(
    rf"^\s*[0-9a-f]+:\s+({RISCV_FP_OPCODE})\b", re.IGNORECASE
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
    llvm_nm: Path
    llvm_objdump: Path
    host: str


@dataclass(frozen=True)
class Package:
    package_id: str
    name: str
    version: str
    source: str | None
    manifest_path: Path

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True)
class Artifact:
    package: Package
    rlib: Path


@dataclass
class ObjectReport:
    package: Package
    rlib: Path
    objects: int = 0
    bitcode_objects: int = 0
    native_objects: int = 0
    semantic_fp: int = 0
    host_float_transport: int = 0
    fp_opcodes: int = 0
    helpers: Counter[str] = field(default_factory=Counter)


def fail(message: str) -> None:
    raise AuditFailure(message)


def fixture_token(match: re.Match[str]) -> str:
    return next(
        (group for group in match.groups() if group is not None), match.group(0)
    )


def llvm_code_without_names_strings_or_metadata(line: str) -> str:
    """Return only LLVM code tokens relevant to type detection.

    LLVM quoted strings and quoted identifiers share the same escape syntax.
    Comments begin at an unquoted semicolon. Debug/named metadata records are
    non-executable and begin with ``!`` after whitespace, so they are ignored
    entirely; inline metadata operands are removed as sigil identifiers.
    """

    if line.lstrip().startswith("!"):
        return ""

    output: list[str] = []
    quoted = False
    escaped = False
    for character in line:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
            output.append(" ")
            continue
        if character == ";":
            break
        output.append(character)

    code = "".join(output)
    code = LLVM_LEADING_LABEL_RE.sub("", code)
    return LLVM_SIGIL_IDENTIFIER_RE.sub(" ", code)


def llvm_float_transport_matches(
    lines: Iterable[str],
) -> list[tuple[int, str, str]]:
    matches: list[tuple[int, str, str]] = []
    for number, line in enumerate(lines, 1):
        code = llvm_code_without_names_strings_or_metadata(line)
        match = LLVM_FLOAT_TYPE_RE.search(code)
        if match is not None:
            matches.append((number, match.group(1), line))
    return matches


def audit_detector_patterns() -> dict[str, int]:
    semantic_fixtures = (
        "%x = fadd float %a, %b",
        "%x = fcmp uno double %a, 0.0",
        "%x = fneg float %a",
        "%x = fptosi double %a to i64",
        "%x = call float @llvm.sqrt.f32(float %a)",
        "%x = call i1 @llvm.is.fpclass.f64(double %a, i32 3)",
        "%x = call <4 x float> @llvm.minimum.v4f32(<4 x float> %a, <4 x float> %b)",
    )
    for fixture in semantic_fixtures:
        if SEMANTIC_LLVM_RE.search(fixture) is None:
            fail(f"LLVM semantic-FP detector missed self-test fixture: {fixture}")

    host_float_transport_fixtures = (
        "define float @lift(float %value) {",
        "%x = load double, ptr %memory, align 8",
        "store half %value, ptr %memory, align 2",
        "%x = bitcast i16 %bits to bfloat",
        "%x = phi fp128 [ %a, %left ], [ %b, %right ]",
        "%x = select i1 %condition, x86_fp80 %a, x86_fp80 %b",
        "ret <4 x float> %values",
        "%x = call <vscale x 2 x double> @callee(<vscale x 2 x double> %v)",
        "%slot = alloca { i32, [2 x half] }, align 4",
    )
    for fixture in host_float_transport_fixtures:
        if not llvm_float_transport_matches((fixture,)):
            fail(f"LLVM host-float transport detector missed fixture: {fixture}")

    non_type_float_text_fixtures = (
        "%float = add i32 %double, 1",
        "@double = global i32 0",
        '%"half" = alloca i32, align 4',
        '@"fp128" = global i32 0',
        "$x86_fp80 = comdat any",
        '!12 = !DICompositeType(name: "float", identifier: "double")',
        '@.str = private constant [6 x i8] c"float\\00"',
        "; load double, ptr %memory",
        'source_filename = "float_candidate.rs"',
        "float:",
        "%x = call i32 @float(i32 %double)",
        "%x = call i32 @canonical_float_bits(i32 %bits), !dbg !42",
    )
    for fixture in non_type_float_text_fixtures:
        if llvm_float_transport_matches((fixture,)):
            fail(f"LLVM host-float transport detector false positive: {fixture}")

    ir_helper_fixtures = (
        "declare i32 @__unordsf2(float, float)",
        "%x = call i64 @__fixsfdi(float %a)",
        "%x = call double @__floatundidf(i64 %a)",
        "%x = call float @ceilf(float %a)",
        "%x = call float @fmaf(float %a, float %b, float %c)",
        "%x = call double @pow(double %a, double %b)",
    )
    for fixture in ir_helper_fixtures:
        if LLVM_FLOAT_HELPER_RE.search(fixture) is None:
            fail(f"LLVM FP-helper detector missed self-test fixture: {fixture}")

    asm_helper_fixtures = (
        "call\t__extendsfdf2",
        "tail\t__unorddf2",
        "call\tsqrt",
        "tail\tfmaf",
    )
    for fixture in asm_helper_fixtures:
        if ASM_FLOAT_HELPER_RE.search(fixture) is None:
            fail(f"assembly FP-helper detector missed self-test fixture: {fixture}")

    symbol_fixtures = (
        "                 U __addsf3",
        "0000000000000000 T __fixunsdfdi",
        "                 U remainderf",
        "0000000000000000 T nextafter",
    )
    for fixture in symbol_fixtures:
        if FLOAT_SYMBOL_RE.search(fixture) is None:
            fail(f"FP-symbol detector missed self-test fixture: {fixture}")

    asm_opcode_fixtures = (
        "\tfadd.s\tfa0, fa1, fa2",
        "\tfcvt.w.d\ta0, fa0",
        "\tc.fldsp\tfa0, 8(sp)",
        "\tfrflags\ta0",
    )
    for fixture in asm_opcode_fixtures:
        if ASM_FP_OPCODE_RE.search(fixture) is None:
            fail(f"RISC-V F/D detector missed assembly fixture: {fixture}")
    objdump_opcode_fixtures = (
        "0000000000000010: fmul.d fa0, fa1, fa2",
        "      2c: fsd fa0, 8(sp)",
    )
    for fixture in objdump_opcode_fixtures:
        if OBJDUMP_FP_OPCODE_RE.search(fixture) is None:
            fail(f"RISC-V F/D detector missed objdump fixture: {fixture}")

    integer_codec_fixtures = (
        "%x = load i32, ptr %p, align 4",
        "store i64 %bits, ptr %p, align 8",
        "%x = call i32 @llvm.bswap.i32(i32 %bits)",
        "%nan = icmp eq i32 %exponent_bits, 255",
        "\tsrli\ta0, a0, 23",
        "\tor\ta0, a0, a1",
        "0000000000000010: lw a0, 4(a1)",
        "0000000000000014: sd a0, 8(a1)",
        "0000000000000000 T canonical_f32_bits",
    )
    for fixture in integer_codec_fixtures:
        rejected = (
            SEMANTIC_LLVM_RE.search(fixture)
            or llvm_float_transport_matches((fixture,))
            or LLVM_FLOAT_HELPER_RE.search(fixture)
            or ASM_FLOAT_HELPER_RE.search(fixture)
            or FLOAT_SYMBOL_RE.search(fixture)
            or ASM_FP_OPCODE_RE.search(fixture)
            or OBJDUMP_FP_OPCODE_RE.search(fixture)
        )
        if rejected is not None:
            fail(f"scanner rejected integer-only codec fixture: {fixture}")

    return {
        "semantic-llvm": len(semantic_fixtures),
        "ir-helper": len(ir_helper_fixtures),
        "asm-helper": len(asm_helper_fixtures),
        "symbol": len(symbol_fixtures),
        "riscv-fd": len(asm_opcode_fixtures) + len(objdump_opcode_fixtures),
        "integer-codec": len(integer_codec_fixtures),
        "host-float-transport": len(host_float_transport_fixtures),
        "host-float-text-negative": len(non_type_float_text_fixtures),
    }


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


def try_run(
    command: Sequence[str | os.PathLike[str]], *, cwd: Path = ROOT
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [os.fspath(part) for part in command],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def rustup_which(rustup: Path, binary: str) -> Path:
    path = Path(
        run([rustup, "which", "--toolchain", TOOLCHAIN, binary]).stdout.strip()
    ).resolve()
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

    sysroot = Path(run([rustc, "--print", "sysroot"]).stdout.strip()).resolve()
    llvm_bin = sysroot / "lib" / "rustlib" / host / "bin"
    paths = {
        name: llvm_bin / name
        for name in ("llvm-ar", "llvm-dis", "llc", "llvm-nm", "llvm-objdump")
    }
    missing = [f"{name} ({path})" for name, path in paths.items() if not path.is_file()]
    if missing:
        fail("pinned llvm-tools component is incomplete: " + ", ".join(missing))
    return Toolchain(
        rustc=rustc,
        cargo=cargo,
        llvm_ar=paths["llvm-ar"],
        llvm_dis=paths["llvm-dis"],
        llc=paths["llc"],
        llvm_nm=paths["llvm-nm"],
        llvm_objdump=paths["llvm-objdump"],
        host=host,
    )


def audit_target_configuration(toolchain: Toolchain) -> set[str]:
    cfg = run([toolchain.rustc, "--target", TARGET, "--print", "cfg"]).stdout
    if 'target_arch="riscv64"' not in cfg or 'target_os="none"' not in cfg:
        fail(f"unexpected target configuration for {TARGET}")
    features = set(re.findall(r'^target_feature="([^"]+)"$', cfg, re.MULTILINE))
    forbidden = features & {"f", "d"}
    if forbidden:
        fail(f"{TARGET} unexpectedly enables hardware FP: {sorted(forbidden)}")
    if not {"m", "a", "c"}.issubset(features):
        fail(f"{TARGET} is missing expected IMAC features: {sorted(features)}")

    target_libdir = Path(
        run(
            [toolchain.rustc, "--target", TARGET, "--print", "target-libdir"]
        ).stdout.strip()
    )
    if not target_libdir.is_dir() or not any(target_libdir.glob("libcore-*.rlib")):
        fail(f"Rust target is not installed or lacks core: {TARGET} ({target_libdir})")
    return features


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read TOML {path}: {error}")


def audit_static_contract() -> None:
    workspace = load_toml(ROOT / "Cargo.toml")
    release = workspace.get("profile", {}).get("release", {})
    if release.get("lto") is not True or release.get("panic") != "abort":
        fail("release profile must retain LTO and panic=abort for object auditing")

    manifest = load_toml(ROOT / "component-runtime/Cargo.toml")
    features = manifest.get("features", {})
    if features.get(ACCEPTANCE_FEATURE) != []:
        fail(f"{ACCEPTANCE_FEATURE} must remain a dependency-free feature")
    if features.get("default") != []:
        fail("component-runtime default features must remain empty")

    dependencies = manifest.get("dependencies", {})
    expected_direct = {
        "vibeos-component-format",
        "vibeos-wasm-runtime",
        "wasmparser",
        "wit-parser",
    }
    if set(dependencies) != expected_direct:
        fail(f"component-runtime dependency surface drifted: {sorted(dependencies)}")

    lib_source = (ROOT / "component-runtime/src/lib.rs").read_text(encoding="utf-8")
    codec_source = (ROOT / "component-runtime/src/abi_value.rs").read_text(
        encoding="utf-8"
    )
    if "#![no_std]" not in lib_source:
        fail("component-runtime lost its no_std boundary")
    gate = '#[cfg(feature = "c88-f3-acceptance")]\npub mod float_candidate;'
    if gate not in codec_source:
        fail("F3 candidate codec lost its structural feature gate")


def cargo_environment(toolchain: Toolchain, target_dir: Path) -> dict[str, str]:
    ambient = (
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL",
    )
    present = [name for name in ambient if os.environ.get(name)]
    if present:
        fail(f"ambient Rust build overrides are forbidden: {present}")
    environment = os.environ.copy()
    environment.update(
        {
            "RUSTC": os.fspath(toolchain.rustc),
            "CARGO_TARGET_DIR": os.fspath(target_dir),
            "CARGO_NET_OFFLINE": "true",
            "RUSTUP_TOOLCHAIN": TOOLCHAIN,
            "CARGO_INCREMENTAL": "0",
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
            "--no-default-features",
            "--features",
            f"{ROOT_PACKAGE}/{ACCEPTANCE_FEATURE}",
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
        fail(
            f"resolved graph must contain exactly one {name}{suffix}, found {len(matches)}"
        )
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
        fail("component-runtime is absent from Cargo's resolved nodes")
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


def cargo_build_artifacts(
    toolchain: Toolchain,
    target_dir: Path,
    packages: Mapping[str, Package],
) -> list[Artifact]:
    result = run(
        [
            toolchain.cargo,
            "build",
            "--offline",
            "--locked",
            "-p",
            ROOT_PACKAGE,
            "--no-default-features",
            "--features",
            ACCEPTANCE_FEATURE,
            "--target",
            TARGET,
            "--release",
            "--message-format=json-render-diagnostics",
        ],
        env=cargo_environment(toolchain, target_dir),
    )
    target_root = (target_dir / TARGET / "release").resolve()
    artifacts: dict[str, Artifact] = {}
    for number, line in enumerate(result.stdout.splitlines(), 1):
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            fail(f"Cargo build stdout line {number} was not JSON: {error}")
        if message.get("reason") != "compiler-artifact":
            continue
        package_id = message.get("package_id")
        if package_id not in packages:
            fail(f"Cargo emitted an unknown package ID: {package_id}")
        rlibs = [
            Path(filename).resolve()
            for filename in message.get("filenames", [])
            if filename.endswith(".rlib")
            and Path(filename).resolve().is_relative_to(target_root)
        ]
        if not rlibs:
            continue
        if len(rlibs) != 1 or package_id in artifacts:
            fail(f"ambiguous target rlib for {package_id}: {rlibs}")
        rlib = rlibs[0]
        if not rlib.is_file():
            fail(f"Cargo reported a missing target artifact: {rlib}")
        artifacts[package_id] = Artifact(packages[package_id], rlib)

    root = unique_package(packages, ROOT_PACKAGE, ROOT_VERSION)
    if root.package_id not in artifacts:
        fail("Cargo JSON omitted the F3 component-runtime target artifact")
    if not artifacts:
        fail("Cargo emitted no target rlib closure")
    return sorted(artifacts.values(), key=lambda item: item.package.label)


def canonical_package_identity(package: Package) -> str:
    if package.source is not None:
        provenance = package.source
    else:
        try:
            manifest = package.manifest_path.relative_to(ROOT).as_posix()
        except ValueError:
            fail(
                f"untrusted path package outside the workspace: {package.manifest_path}"
            )
        provenance = f"workspace:{manifest}"
    return f"{package.name}\0{package.version}\0{provenance}"


def closure_digest(artifacts: Sequence[Artifact]) -> str:
    digest = hashlib.sha256()
    digest.update(CLOSURE_DIGEST_DOMAIN)
    identities = [
        canonical_package_identity(artifact.package) for artifact in artifacts
    ]
    if len(identities) != len(set(identities)):
        fail("target artifact closure contains duplicate canonical identities")
    for identity in sorted(identities):
        digest.update(identity.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def audit_artifact_closure(
    metadata: Mapping[str, Any],
    packages: Mapping[str, Package],
    artifacts: Sequence[Artifact],
) -> str:
    root = unique_package(packages, ROOT_PACKAGE, ROOT_VERSION)
    reachable = reachable_package_ids(metadata, root.package_id)
    artifact_ids = {artifact.package.package_id for artifact in artifacts}
    if not artifact_ids.issubset(reachable):
        unexpected = sorted(packages[item].label for item in artifact_ids - reachable)
        fail(f"Cargo built target artifacts outside the root closure: {unexpected}")

    local = {
        artifact.package.name: artifact.package.manifest_path
        for artifact in artifacts
        if artifact.package.source is None
    }
    expected_local = {
        name: path.resolve() for name, path in EXPECTED_LOCAL_ARTIFACTS.items()
    }
    if local != expected_local:
        rendered = {name: os.fspath(path) for name, path in sorted(local.items())}
        fail(f"workspace-owned target artifact closure drifted: {rendered}")

    built_names = {artifact.package.name for artifact in artifacts}
    forbidden_dev = {
        "dlr-wasm-interpreter",
        "wasm-encoder",
        "wasmtime",
        "wat",
    }
    leaked = sorted(built_names & forbidden_dev)
    if leaked:
        fail(f"dev/reference engines leaked into the target closure: {leaked}")

    computed = closure_digest(artifacts)
    if EXPECTED_TARGET_CLOSURE_SHA256 == "TO_BE_FROZEN":
        fail(f"freeze EXPECTED_TARGET_CLOSURE_SHA256 as {computed}")
    if computed != EXPECTED_TARGET_CLOSURE_SHA256:
        fail(
            "target artifact closure drifted: "
            f"expected {EXPECTED_TARGET_CLOSURE_SHA256}, found {computed}"
        )
    return computed


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
        fail(f"target rlib contains no object/bitcode members: {rlib}")
    return objects


def text_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        fail(f"cannot scan generated text {path}: {error}")


def regex_matches(
    lines: Iterable[str], pattern: re.Pattern[str]
) -> list[tuple[int, str, str]]:
    matches: list[tuple[int, str, str]] = []
    for number, line in enumerate(lines, 1):
        match = pattern.search(line)
        if match is not None:
            matches.append((number, fixture_token(match), line))
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
    toolchain: Toolchain,
    artifact: Artifact,
    extraction_root: Path,
    index: int,
) -> ObjectReport:
    package = artifact.package
    package_dir = extraction_root / f"{index:03d}-{package.name}-{package.version}"
    package_dir.mkdir(mode=0o700)
    members = safe_archive_members(toolchain, artifact.rlib)
    run([toolchain.llvm_ar, "x", artifact.rlib], cwd=package_dir)

    owned = package.source is None
    report = ObjectReport(package=package, rlib=artifact.rlib)
    failures: list[str] = []
    for object_index, member in enumerate(members):
        object_path = package_dir / member
        if not object_path.is_file():
            fail(f"llvm-ar did not extract expected object: {object_path}")
        report.objects += 1

        nm_result = try_run([toolchain.llvm_nm, object_path], cwd=package_dir)
        if nm_result.returncode != 0:
            detail = nm_result.stderr.decode("utf-8", errors="replace").strip()
            fail(f"llvm-nm could not inspect {package.label}:{member}: {detail}")
        nm_lines = nm_result.stdout.decode("utf-8", errors="replace").splitlines()
        symbol_helpers = regex_matches(nm_lines, FLOAT_SYMBOL_RE)

        ir_path = package_dir / f"object-{object_index}.ll"
        dis_result = try_run(
            [toolchain.llvm_dis, object_path, "-o", ir_path], cwd=package_dir
        )
        semantic: list[tuple[int, str, str]] = []
        host_float_transport: list[tuple[int, str, str]] = []
        ir_helpers: list[tuple[int, str, str]] = []
        if dis_result.returncode == 0 and ir_path.is_file():
            report.bitcode_objects += 1
            ir_lines = text_lines(ir_path)
            semantic = regex_matches(ir_lines, SEMANTIC_LLVM_RE)
            host_float_transport = llvm_float_transport_matches(ir_lines)
            ir_helpers = regex_matches(ir_lines, LLVM_FLOAT_HELPER_RE)
            asm_path = package_dir / f"object-{object_index}.s"
            llc_result = try_run(
                [toolchain.llc, "-filetype=asm", object_path, "-o", asm_path],
                cwd=package_dir,
            )
            if llc_result.returncode != 0 or not asm_path.is_file():
                detail = llc_result.stderr.decode("utf-8", errors="replace").strip()
                fail(f"llc could not lower {package.label}:{member}: {detail}")
            asm_lines = text_lines(asm_path)
            fp_opcodes = regex_matches(asm_lines, ASM_FP_OPCODE_RE)
            asm_helpers = regex_matches(asm_lines, ASM_FLOAT_HELPER_RE)
            asm_symbol_helpers: list[tuple[int, str, str]] = []
        else:
            report.native_objects += 1
            objdump_result = try_run(
                [
                    toolchain.llvm_objdump,
                    "--disassemble",
                    "--reloc",
                    "--no-show-raw-insn",
                    object_path,
                ],
                cwd=package_dir,
            )
            if objdump_result.returncode != 0:
                detail = objdump_result.stderr.decode("utf-8", errors="replace").strip()
                fail(
                    f"llvm-objdump could not inspect {package.label}:{member}: {detail}"
                )
            asm_lines = objdump_result.stdout.decode(
                "utf-8", errors="replace"
            ).splitlines()
            fp_opcodes = regex_matches(asm_lines, OBJDUMP_FP_OPCODE_RE)
            asm_helpers = []
            asm_symbol_helpers = regex_matches(asm_lines, FLOAT_SYMBOL_RE)

        report.semantic_fp += len(semantic)
        report.host_float_transport += len(host_float_transport)
        report.fp_opcodes += len(fp_opcodes)
        for _line, token, _text in (
            ir_helpers + asm_helpers + symbol_helpers + asm_symbol_helpers
        ):
            report.helpers[token] += 1

        if fp_opcodes:
            failures.append(
                describe_matches(package.label, member, "RISC-V F/D opcode", fp_opcodes)
            )
        if owned and semantic:
            failures.append(
                describe_matches(package.label, member, "LLVM FP semantics", semantic)
            )
        if owned and host_float_transport:
            failures.append(
                describe_matches(
                    package.label,
                    member,
                    "LLVM host-float type/transport",
                    host_float_transport,
                )
            )
        owned_helpers = ir_helpers + asm_helpers + symbol_helpers + asm_symbol_helpers
        if owned and owned_helpers:
            failures.append(
                describe_matches(
                    package.label, member, "FP helper/symbol", owned_helpers
                )
            )

    if report.bitcode_objects + report.native_objects != report.objects:
        fail(f"not every object was classified for {package.label}")
    if owned and report.native_objects != 0:
        fail(
            f"workspace-owned artifact lost LLVM type-audit coverage: "
            f"{package.label} has {report.native_objects} native object(s)"
        )
    if failures:
        fail("\n".join(failures))
    return report


def audit_inherited_baseline(reports: Sequence[ObjectReport]) -> None:
    observed = {
        (report.package.name, report.package.version)
        for report in reports
        if report.package.source is not None
        and (report.semantic_fp != 0 or bool(report.helpers))
    }
    unexpected = observed - INHERITED_FP_BASELINE
    if unexpected:
        fail(f"unreviewed external FP semantics/helper packages: {sorted(unexpected)}")
    missing = INHERITED_FP_BASELINE - {
        (report.package.name, report.package.version) for report in reports
    }
    if missing:
        fail(f"frozen Profile-1 baseline packages left the closure: {sorted(missing)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run only deterministic scanner fixtures; do not invoke Cargo",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        fixture_counts = audit_detector_patterns()
        if args.self_test:
            summary = ",".join(
                f"{name}={fixture_counts[name]}" for name in sorted(fixture_counts)
            )
            print("C8.8-F3 RISC-V object scanner self-test: PASS")
            print(f"fixtures: {summary}")
            return 0

        toolchain = locate_toolchain()
        target_features = audit_target_configuration(toolchain)
        audit_static_contract()
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c88-f3-riscv-object-"
        ) as temporary:
            audit_root = Path(temporary).resolve()
            target_dir = audit_root / "cargo-target"
            extraction_root = audit_root / "objects"
            target_dir.mkdir(mode=0o700)
            extraction_root.mkdir(mode=0o700)

            metadata, packages = cargo_metadata(toolchain, target_dir)
            artifacts = cargo_build_artifacts(toolchain, target_dir, packages)
            digest = audit_artifact_closure(metadata, packages, artifacts)
            reports = [
                audit_rlib(toolchain, artifact, extraction_root, index)
                for index, artifact in enumerate(artifacts)
            ]
            audit_inherited_baseline(reports)

        owned = [report for report in reports if report.package.source is None]
        inherited = [
            report
            for report in reports
            if (report.package.name, report.package.version) in INHERITED_FP_BASELINE
        ]
        print("C8.8-F3 RISC-V object audit: PASS")
        print(
            "toolchain: "
            f"{TOOLCHAIN} rustc={EXPECTED_RUSTC_COMMIT[:12]} "
            f"cargo={EXPECTED_CARGO_COMMIT[:12]} LLVM={EXPECTED_LLVM_VERSION}"
        )
        print(
            f"target: {TARGET}; features={','.join(sorted(target_features))}; f/d=absent"
        )
        print(
            f"closure: artifacts={len(reports)}; sha256={digest}; "
            f"objects={sum(report.objects for report in reports)}; f/d-opcodes=0"
        )
        print(
            "F3-owned: artifacts="
            + ",".join(report.package.label for report in owned)
            + f"; objects={sum(report.objects for report in owned)}; "
            f"llvm-bitcode={sum(report.bitcode_objects for report in owned)}; "
            "semantic-fp=0; host-float-transport=0; fp-helpers/symbols=0; "
            "integer-bit-codec=allowed"
        )
        inherited_summary = ",".join(
            f"{report.package.label}(semantic={report.semantic_fp},helpers={sum(report.helpers.values())})"
            for report in inherited
        )
        print(
            "inherited Profile-1 baseline: "
            f"{inherited_summary}; feature-dependency-edge=empty"
        )
        return 0
    except (AuditFailure, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        print(f"C8.8-F3 RISC-V object audit: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
