#!/usr/bin/env python3
"""Verify the C8.8-F2 software-float candidate supply-chain boundary.

The verifier is intentionally offline.  It binds the pristine crates.io
archives through their registry checksums, binds the selected upstream files
through UPSTREAM_FILES.sha256, and binds the reviewed fork through a
domain-separated content-manifest digest.  ``--self-test`` mutates inputs in
memory and proves that the important guards fail closed without touching the
worktree.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
VENDOR_REL = PurePosixPath("vendor/wasmi-softfloat")
VENDOR = ROOT / VENDOR_REL
PROVENANCE_REL = VENDOR_REL / "PROVENANCE.toml"
UPSTREAM_FILES_REL = VENDOR_REL / "UPSTREAM_FILES.sha256"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
FORK_VERSION = "1.1.0-vibeos-f2.1"
WASMI_COMMIT = "8273dfb09d493971b7bb12fe614d740cdc857175"
RUSTC_APFLOAT_GIT = "eeaacad81247af65d4043cb3e32d023a652d7951"
LLVM_BASELINE = "462a31f5a5abb905869ea93cc49b096079b11aa4"

HASH_MANIFEST_DOMAIN = b"vibeos-c88-f2-content-manifest-sha256-v1\0"
PATCH_DELTA_DOMAIN = b"vibeos-c88-f2-patch-delta-sha256-v1\0"

# Frozen only after the full fork source is stable. These constants prevent a
# provenance-file-only edit from blessing unreviewed source drift.
EXPECTED_UPSTREAM_FILES_SHA256 = (
    "2ed5dc8e1548b3b84f74fcb713d45583bfecd123fcccd41782bdacc782873f0a"
)
EXPECTED_PRISTINE_MANIFEST_SHA256 = (
    "7abb362a9de9a40e24e7626ccea7a2954afdd9114e211a191a76132db6ecdbc9"
)
EXPECTED_PATCHED_MANIFEST_SHA256 = (
    "2d94218e4fa5eea30b8e516e055fae8f72465dbc1ef75f8b1df3495cbcd0432f"
)
EXPECTED_PATCH_DELTA_SHA256 = (
    "3d2aec1d7e510fc3b3edb87dcacb2d4ed34eb448356704a027841b047938ec64"
)
EXPECTED_FORK_MANIFESTS_SHA256 = (
    "f78a26c86b00068d1bb9b8f7d499697d3a0f9b638c6d2051df249362a0006dfd"
)

EXPECTED_CHANGED_FILES = [
    "crates/collections/README.md",
    "crates/core/README.md",
    "crates/core/src/float.rs",
    "crates/core/src/lib.rs",
    "crates/core/src/softfloat.rs",
    "crates/core/src/value.rs",
    "crates/core/src/wasm.rs",
    "crates/ir/README.md",
    "crates/ir/src/immeditate.rs",
    "crates/ir/src/primitive.rs",
    "crates/wasmi/README.md",
    "crates/wasmi/src/engine/executor/instrs/branch.rs",
    "crates/wasmi/src/func/into_func.rs",
]

WASMI_ARCHIVES = {
    "wasmi": "2300d0f78cba12f14e29e8dd157ea64050c0a688179aefdb2050105805594a0c",
    "wasmi_core": "9013136083d988725953390bf668b64b7a218fabf26f8b913bbc59546b97ee27",
    "wasmi_ir": "ba1fa003f79156f406d62ef0e1464dc03e11ace37170e9fa7524299a75ad8f68",
    "wasmi_collections": "f8a8c42a2a76148d43097b1d7cc2a5bf33d5c23bd4dd69015fc887e311767884",
}

WASMI_VCS_PATHS = {
    "wasmi": "crates/wasmi",
    "wasmi_core": "crates/core",
    "wasmi_ir": "crates/ir",
    "wasmi_collections": "crates/collections",
}

FORKS = {
    "collections": (
        "vibeos-wasmi-collections-softfloat",
        "wasmi_collections",
        "wasmi_collections",
    ),
    "core": ("vibeos-wasmi-core-softfloat", "wasmi_core", "wasmi_core"),
    "ir": ("vibeos-wasmi-ir-softfloat", "wasmi_ir", "wasmi_ir"),
    "wasmi": ("vibeos-wasmi-softfloat", "wasmi", "wasmi"),
}

SELECTED_EXTERNAL = {
    "rustc_apfloat": (
        "0.2.3+llvm-462a31f5a5ab",
        "486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad",
    ),
    "bitflags": (
        "2.13.1",
        "b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da",
    ),
    "smallvec": (
        "1.15.2",
        "8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90",
    ),
    "wasmparser": (
        "0.239.0",
        "8c9d90bb93e764f6beabf1d02028c70a2156a6583e63ac4218dd07ef733368b0",
    ),
    "spin": (
        "0.9.9",
        "3763264f6b73151db08c50ff20d7d8a0b8796e021cdea7ceedad07b80155fa0e",
    ),
}

MANIFEST_ONLY_EXTERNAL = {
    "libm": {
        "version_requirement": "=0.2.16",
        "archive_sha256": "b6d2cec3eae94f9f509c767b45932f1ada8350c4bdb85af2fcab4a3c14807981",
        "selected": False,
        "reason": "optional compatibility edge for the forbidden SIMD feature",
    }
}

LICENSES = {
    "vendor/wasmi-softfloat/LICENSE-MIT": (
        "172bc1497507c1c363496bc23b0f16de8fa8e94befa85db6c8d9fa790e0a8657"
    ),
    "vendor/wasmi-softfloat/LICENSE-APACHE": (
        "f031c1608e4a19e8cbcc3394cdba838067e79189610227459e8ffcd669e6f52d"
    ),
    "vendor/wasmi-softfloat/third-party/rustc_apfloat/LICENSE.txt": (
        "981f4155fbd55dcf13745e2ed508e6fa30aa90f9f668c4ef0f7686980e5d8521"
    ),
    "vendor/wasmi-softfloat/third-party/rustc_apfloat/LICENSE-DETAILS.md": (
        "5998f303e26191363f591e04bdd0f829b2000afc843c67326a9b7efd66850416"
    ),
}


class VerificationFailure(RuntimeError):
    def __init__(self, errors: Iterable[str]):
        self.errors = tuple(errors)
        super().__init__("\n".join(self.errors))


@dataclass(frozen=True)
class View:
    root: Path
    overlay: Mapping[str, bytes] = field(default_factory=dict)

    def read(self, rel: str | PurePosixPath) -> bytes:
        key = PurePosixPath(rel).as_posix()
        if key in self.overlay:
            return self.overlay[key]
        return (self.root / key).read_bytes()

    def text(self, rel: str | PurePosixPath) -> str:
        return self.read(rel).decode("utf-8")

    def toml(self, rel: str | PurePosixPath) -> dict[str, Any]:
        return tomllib.loads(self.text(rel))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def hash_manifest_digest(entries: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    digest.update(HASH_MANIFEST_DOMAIN)
    for path, file_hash in sorted(entries.items()):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_hash))
    return digest.hexdigest()


def patch_delta_digest(pristine: Mapping[str, str], patched: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    digest.update(PATCH_DELTA_DOMAIN)
    zero = bytes(32)
    for path in sorted(set(pristine) | set(patched)):
        before = pristine.get(path)
        after = patched.get(path)
        if before == after:
            continue
        state = b"A" if before is None else b"D" if after is None else b"M"
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(state)
        digest.update(b"\0")
        digest.update(zero if before is None else bytes.fromhex(before))
        digest.update(zero if after is None else bytes.fromhex(after))
    return digest.hexdigest()


def parse_upstream_files(view: View) -> dict[str, str]:
    result: dict[str, str] = {}
    lines = view.text(UPSTREAM_FILES_REL).splitlines()
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if match is None:
            raise VerificationFailure(
                [f"UPSTREAM_FILES.sha256:{number}: malformed record"]
            )
        file_hash, path = match.groups()
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts:
            raise VerificationFailure(
                [f"UPSTREAM_FILES.sha256:{number}: unsafe path {path!r}"]
            )
        if path in result:
            raise VerificationFailure(
                [f"UPSTREAM_FILES.sha256:{number}: duplicate path {path!r}"]
            )
        result[path] = file_hash
    if lines != sorted(lines):
        raise VerificationFailure(["UPSTREAM_FILES.sha256 is not bytewise sorted"])
    return result


def vendor_tree_files(view: View) -> set[str]:
    files: set[str] = set()
    for path in VENDOR.rglob("*"):
        if path.is_symlink():
            raise VerificationFailure(
                [f"vendored tree must not contain a symlink: {path.relative_to(ROOT)}"]
            )
        if path.is_file():
            files.add(path.relative_to(VENDOR).as_posix())
    prefix = VENDOR_REL.as_posix() + "/"
    for path in view.overlay:
        if path.startswith(prefix):
            files.add(path[len(prefix) :])
    return files


def expected_vendor_tree_files(view: View) -> set[str]:
    files = set(parse_upstream_files(view))
    files.update(EXPECTED_CHANGED_FILES)
    files.update(f"crates/{crate}/Cargo.toml" for crate in FORKS)
    files.update(
        {
            "LICENSE-APACHE",
            "LICENSE-MIT",
            "PROVENANCE.md",
            "PROVENANCE.toml",
            "UPSTREAM_FILES.sha256",
            "third-party/rustc_apfloat/LICENSE-DETAILS.md",
            "third-party/rustc_apfloat/LICENSE.txt",
        }
    )
    return files


def fork_content_entries(view: View) -> dict[str, str]:
    entries: dict[str, str] = {}
    for crate in sorted(FORKS):
        base = VENDOR / "crates" / crate
        candidates = [base / "README.md"]
        candidates.extend(sorted((base / "src").rglob("*")))
        for path in candidates:
            if path.is_symlink():
                raise VerificationFailure(
                    [f"vendored content must not be a symlink: {path.relative_to(ROOT)}"]
                )
            if not path.is_file():
                continue
            rel = path.relative_to(VENDOR).as_posix()
            entries[rel] = sha256(view.read(path.relative_to(ROOT).as_posix()))
    return entries


def fork_manifest_entries(view: View) -> dict[str, str]:
    return {
        f"crates/{crate}/Cargo.toml": sha256(
            view.read(f"vendor/wasmi-softfloat/crates/{crate}/Cargo.toml")
        )
        for crate in sorted(FORKS)
    }


def computed_digests(view: View) -> dict[str, str]:
    pristine = parse_upstream_files(view)
    patched = fork_content_entries(view)
    manifests = fork_manifest_entries(view)
    return {
        "upstream_files_sha256": sha256(view.read(UPSTREAM_FILES_REL)),
        "pristine_manifest_sha256": hash_manifest_digest(pristine),
        "patched_manifest_sha256": hash_manifest_digest(patched),
        "patch_delta_sha256": patch_delta_digest(pristine, patched),
        "fork_manifests_sha256": hash_manifest_digest(manifests),
    }


def dependency_tables(manifest: Mapping[str, Any]) -> Iterable[tuple[str, Any]]:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(section, {})
        if isinstance(table, dict):
            yield from table.items()
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(section, {})
                if isinstance(table, dict):
                    yield from table.items()


def lock_package(
    errors: list[str], lock: Mapping[str, Any], name: str, version: str
) -> Mapping[str, Any]:
    found = [
        package
        for package in lock.get("package", [])
        if package.get("name") == name and package.get("version") == version
    ]
    require(errors, len(found) == 1, f"Cargo.lock must contain exactly one {name} {version}")
    return found[0] if found else {}


def verify_provenance(view: View, errors: list[str]) -> None:
    try:
        provenance = view.toml(PROVENANCE_REL)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse {PROVENANCE_REL}: {exc}")
        return

    require(errors, provenance.get("format_version") == 1, "provenance format_version drift")
    require(errors, provenance.get("roadmap_node") == "C8.8-F2", "provenance node drift")
    wasmi = provenance.get("wasmi_upstream", {})
    require(errors, wasmi.get("repository") == "https://github.com/wasmi-labs/wasmi", "Wasmi repository drift")
    require(errors, wasmi.get("commit") == WASMI_COMMIT, "Wasmi upstream commit drift")
    require(errors, wasmi.get("version") == "1.1.0", "Wasmi upstream version drift")
    require(errors, wasmi.get("license_expression") == "MIT OR Apache-2.0", "Wasmi license expression drift")
    require(errors, wasmi.get("license_mit_url") == f"https://raw.githubusercontent.com/wasmi-labs/wasmi/{WASMI_COMMIT}/LICENSE-MIT", "Wasmi MIT license origin drift")
    require(errors, wasmi.get("license_apache_url") == f"https://raw.githubusercontent.com/wasmi-labs/wasmi/{WASMI_COMMIT}/LICENSE-APACHE", "Wasmi Apache license origin drift")

    recorded_archives = {
        entry.get("package"): (
            entry.get("version"),
            entry.get("path_in_vcs"),
            entry.get("archive_sha256"),
        )
        for entry in provenance.get("wasmi_archive", [])
        if isinstance(entry, dict)
    }
    expected_archives = {
        package: ("1.1.0", WASMI_VCS_PATHS[package], checksum)
        for package, checksum in WASMI_ARCHIVES.items()
    }
    require(errors, recorded_archives == expected_archives, "Wasmi archive identity/checksum set drift")

    apfloat = provenance.get("rustc_apfloat", {})
    require(errors, apfloat.get("repository") == "https://github.com/rust-lang/rustc_apfloat", "rustc_apfloat repository drift")
    require(errors, apfloat.get("version") == "0.2.3+llvm-462a31f5a5ab", "rustc_apfloat version drift")
    require(errors, apfloat.get("manifest_requirement") == "=0.2.3", "rustc_apfloat manifest pin drift")
    require(errors, apfloat.get("archive_sha256") == SELECTED_EXTERNAL["rustc_apfloat"][1], "rustc_apfloat archive checksum drift")
    require(errors, apfloat.get("git_revision") == RUSTC_APFLOAT_GIT, "rustc_apfloat Git revision drift")
    require(errors, apfloat.get("llvm_baseline_revision") == LLVM_BASELINE, "rustc_apfloat LLVM baseline drift")
    require(errors, apfloat.get("license_expression") == "Apache-2.0 WITH LLVM-exception", "rustc_apfloat license expression drift")
    require(errors, apfloat.get("license_file") == "third-party/rustc_apfloat/LICENSE.txt", "rustc_apfloat license path drift")
    require(errors, apfloat.get("license_details_file") == "third-party/rustc_apfloat/LICENSE-DETAILS.md", "rustc_apfloat license-details path drift")
    require(errors, apfloat.get("direct_normal_dependencies") == ["bitflags 2.13.1", "smallvec 1.15.2"], "rustc_apfloat direct dependency closure drift")
    require(errors, apfloat.get("smallvec_features") == ["const_generics", "union"], "rustc_apfloat smallvec feature closure drift")

    selected = {
        entry.get("package"): (entry.get("version"), entry.get("checksum"))
        for entry in provenance.get("selected_external", [])
        if isinstance(entry, dict)
    }
    require(errors, selected == SELECTED_EXTERNAL, "selected external closure drift")
    require(
        errors,
        provenance.get("manifest_only_external") == MANIFEST_ONLY_EXTERNAL,
        "manifest-only external pin set drift",
    )

    tree = provenance.get("tree", {})
    expected_tree = {
        "algorithm": "sha256-content-manifest-v1",
        "upstream_files_sha256": EXPECTED_UPSTREAM_FILES_SHA256,
        "pristine_manifest_sha256": EXPECTED_PRISTINE_MANIFEST_SHA256,
        "patched_manifest_sha256": EXPECTED_PATCHED_MANIFEST_SHA256,
        "patch_delta_sha256": EXPECTED_PATCH_DELTA_SHA256,
        "fork_manifests_sha256": EXPECTED_FORK_MANIFESTS_SHA256,
    }
    require(errors, tree == expected_tree, "recorded pristine/patched tree identity drift")

    try:
        actual_vendor_files = vendor_tree_files(view)
        expected_vendor_files = expected_vendor_tree_files(view)
        require(
            errors,
            actual_vendor_files == expected_vendor_files,
            "vendored tree file allowlist drift: "
            f"unexpected={sorted(actual_vendor_files - expected_vendor_files)}, "
            f"missing={sorted(expected_vendor_files - actual_vendor_files)}",
        )
        actual = computed_digests(view)
    except (OSError, UnicodeDecodeError, VerificationFailure) as exc:
        errors.append(f"cannot compute fork digests: {exc}")
        return
    require(errors, actual == {k: v for k, v in expected_tree.items() if k != "algorithm"}, "vendored fork content or manifest drift")
    pristine = parse_upstream_files(view)
    patched = fork_content_entries(view)
    actual_changed = sorted(
        path
        for path in set(pristine) | set(patched)
        if pristine.get(path) != patched.get(path)
    )
    require(errors, actual_changed == EXPECTED_CHANGED_FILES, "reviewed fork delta path set drift")
    require(errors, provenance.get("reviewed_delta_paths") == EXPECTED_CHANGED_FILES, "recorded fork delta path set drift")

    recorded_licenses = provenance.get("license_file", {})
    require(errors, recorded_licenses == LICENSES, "recorded license checksum set drift")
    for path, expected in LICENSES.items():
        try:
            actual_hash = sha256(view.read(path))
        except OSError as exc:
            errors.append(f"missing license file {path}: {exc}")
            continue
        require(errors, actual_hash == expected, f"license text drift: {path}")


def verify_lock_and_profile1(view: View, errors: list[str]) -> None:
    try:
        root_manifest = view.toml("Cargo.toml")
        runtime_manifest = view.toml("wasm-runtime/Cargo.toml")
        lock = view.toml("Cargo.lock")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse workspace manifests/lock: {exc}")
        return

    patch = root_manifest.get("patch", {})
    require(errors, not (isinstance(patch, dict) and "crates-io" in patch), "workspace [patch.crates-io] is forbidden")
    require(errors, "vendor/wasmi-softfloat" in root_manifest.get("workspace", {}).get("exclude", []), "vendored fork must remain outside the root workspace")
    require(errors, "wasm-float-candidate" in root_manifest.get("workspace", {}).get("members", []), "acceptance candidate workspace member missing")

    stock_dep = runtime_manifest.get("dependencies", {}).get("wasmi", {})
    require(errors, isinstance(stock_dep, dict), "wasm-runtime stock Wasmi dependency missing")
    if isinstance(stock_dep, dict):
        require(errors, stock_dep.get("version") == "=1.1.0", "Profile 1 Wasmi version pin drift")
        require(errors, stock_dep.get("default-features") is False, "Profile 1 Wasmi default features must stay disabled")
        require(errors, set(stock_dep.get("features", [])) == {"extra-checks", "prefer-btree-collections"}, "Profile 1 Wasmi feature vector drift")
        require(errors, not ({"path", "git", "registry", "package"} & set(stock_dep)), "Profile 1 Wasmi must remain a direct crates.io dependency")

    for package, checksum in WASMI_ARCHIVES.items():
        entry = lock_package(errors, lock, package, "1.1.0")
        if entry:
            require(errors, entry.get("source") == REGISTRY_SOURCE, f"Profile 1 {package} source drift")
            require(errors, entry.get("checksum") == checksum, f"Profile 1 {package} checksum drift")

    for package, (version, checksum) in SELECTED_EXTERNAL.items():
        entry = lock_package(errors, lock, package, version)
        if entry:
            require(errors, entry.get("source") == REGISTRY_SOURCE, f"selected {package} source drift")
            require(errors, entry.get("checksum") == checksum, f"selected {package} checksum drift")

    rustc = lock_package(errors, lock, "rustc_apfloat", SELECTED_EXTERNAL["rustc_apfloat"][0])
    if rustc:
        require(errors, rustc.get("dependencies") == ["bitflags 2.13.1", "smallvec"], "rustc_apfloat locked direct dependency closure drift")

    expected_lock_dependencies = {
        "vibeos-wasmi-collections-softfloat": [],
        "vibeos-wasmi-core-softfloat": ["rustc_apfloat"],
        "vibeos-wasmi-ir-softfloat": ["vibeos-wasmi-core-softfloat"],
        "vibeos-wasmi-softfloat": [
            "spin",
            "vibeos-wasmi-collections-softfloat",
            "vibeos-wasmi-core-softfloat",
            "vibeos-wasmi-ir-softfloat",
            "wasmparser 0.239.0",
        ],
    }
    for package, dependencies in expected_lock_dependencies.items():
        entry = lock_package(errors, lock, package, FORK_VERSION)
        if entry:
            require(errors, "source" not in entry and "checksum" not in entry, f"{package} must remain a local path package")
            require(errors, entry.get("dependencies", []) == dependencies, f"{package} locked dependency closure drift")


def check_dep(
    errors: list[str],
    table: Mapping[str, Any],
    name: str,
    *,
    version: str,
    default_features: bool,
    features: Iterable[str] = (),
    optional: bool | None = None,
) -> None:
    dep = table.get(name)
    require(errors, isinstance(dep, dict), f"missing dependency {name}")
    if not isinstance(dep, dict):
        return
    require(errors, dep.get("version") == version, f"{name} version pin drift")
    require(errors, dep.get("default-features") is default_features, f"{name} default-features drift")
    require(errors, set(dep.get("features", [])) == set(features), f"{name} feature vector drift")
    if optional is not None:
        require(errors, dep.get("optional", False) is optional, f"{name} optional flag drift")


def verify_fork_manifests(view: View, errors: list[str]) -> None:
    manifests: dict[str, Mapping[str, Any]] = {}
    for crate, (fork_name, _upstream_name, lib_name) in FORKS.items():
        rel = f"vendor/wasmi-softfloat/crates/{crate}/Cargo.toml"
        try:
            manifest = view.toml(rel)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"cannot parse {rel}: {exc}")
            continue
        manifests[crate] = manifest
        package = manifest.get("package", {})
        require(errors, package.get("name") == fork_name, f"{crate} fork package name drift")
        require(errors, package.get("version") == FORK_VERSION, f"{crate} fork version drift")
        require(errors, package.get("publish") is False, f"{crate} fork must stay publish=false")
        require(errors, package.get("license") == "MIT OR Apache-2.0", f"{crate} fork license drift")
        require(errors, package.get("repository") == "https://github.com/wasmi-labs/wasmi", f"{crate} fork repository drift")
        require(errors, manifest.get("lib", {}).get("name") == lib_name, f"{crate} Rust lib identity drift")

    internal = {
        ("wasmi", "wasmi_collections"): ("collections", "../collections"),
        ("wasmi", "wasmi_core"): ("core", "../core"),
        ("wasmi", "wasmi_ir"): ("ir", "../ir"),
        ("ir", "wasmi_core"): ("core", "../core"),
    }
    for (owner, key), (target, expected_path) in internal.items():
        dep = manifests.get(owner, {}).get("dependencies", {}).get(key, {})
        require(errors, isinstance(dep, dict), f"missing internal path dependency {owner}:{key}")
        if not isinstance(dep, dict):
            continue
        require(errors, dep.get("package") == FORKS[target][0], f"{owner}:{key} package rename drift")
        require(errors, dep.get("path") == expected_path, f"{owner}:{key} path isolation drift")
        require(errors, dep.get("version") == f"={FORK_VERSION}", f"{owner}:{key} version drift")
        require(errors, dep.get("default-features") is False, f"{owner}:{key} default features drift")
        require(errors, not ({"git", "registry"} & set(dep)), f"{owner}:{key} must be path-only")

    wasmi_deps = manifests.get("wasmi", {}).get("dependencies", {})
    check_dep(errors, wasmi_deps, "spin", version="=0.9.9", default_features=False, features=("mutex", "spin_mutex", "rwlock"))
    check_dep(errors, wasmi_deps, "wasmparser", version="=0.239.0", default_features=False, features=("validate", "features"))
    check_dep(errors, wasmi_deps, "wat", version="=1.239.0", default_features=False, optional=True)
    core_deps = manifests.get("core", {}).get("dependencies", {})
    check_dep(errors, core_deps, "libm", version="=0.2.16", default_features=False, optional=True)
    check_dep(errors, core_deps, "rustc_apfloat", version="=0.2.3", default_features=False)
    require(errors, manifests.get("core", {}).get("features", {}).get("simd") == ["dep:libm"], "SIMD-only libm edge drift")

    collections_deps = manifests.get("collections", {}).get("dependencies", {})
    check_dep(errors, collections_deps, "hashbrown", version="=0.15.5", default_features=False, features=("default-hasher", "inline-more"), optional=True)
    check_dep(errors, collections_deps, "string-interner", version="=0.19.0", default_features=False, features=("inline-more", "backends"), optional=True)


def verify_isolation_and_inertness(view: View, errors: list[str]) -> None:
    fork_names = {fork[0] for fork in FORKS.values()}
    candidate_package = "vibeos-wasm-float-candidate"
    allowed_consumer = PurePosixPath("wasm-float-candidate/Cargo.toml")
    try:
        root_manifest = view.toml("Cargo.toml")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse root workspace manifest: {exc}")
        return
    workspace_manifests = [PurePosixPath("Cargo.toml")]
    workspace_manifests.extend(
        PurePosixPath(member) / "Cargo.toml"
        for member in root_manifest.get("workspace", {}).get("members", [])
    )
    for rel in sorted(set(workspace_manifests), key=str):
        manifest_path = ROOT / rel
        try:
            manifest = tomllib.loads(view.text(rel))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"cannot parse {rel}: {exc}")
            continue
        for alias, spec in dependency_tables(manifest):
            package = spec.get("package", alias) if isinstance(spec, dict) else alias
            require(errors, package != candidate_package, f"acceptance candidate consumed by workspace package: {rel}:{alias}")
            if isinstance(spec, dict) and "path" in spec:
                actual_path = (manifest_path.parent / spec["path"]).resolve()
                vendor_crates = (VENDOR / "crates").resolve()
                require(errors, actual_path != (ROOT / "wasm-float-candidate").resolve(), f"acceptance candidate path consumed by workspace package: {rel}:{alias}")
                if actual_path.is_relative_to(vendor_crates):
                    require(errors, rel == allowed_consumer, f"vendored path consumed outside acceptance crate: {rel}:{alias}")
                    require(errors, package in fork_names, f"vendored path dependency lacks a renamed package identity: {rel}:{alias}")
            if package not in fork_names:
                continue
            require(errors, rel == allowed_consumer, f"vendored fork consumed outside acceptance crate: {rel}:{alias}")
            if isinstance(spec, dict):
                expected_dir = next(
                    crate for crate, identities in FORKS.items() if identities[0] == package
                )
                expected = (ROOT / VENDOR_REL / "crates" / expected_dir).resolve()
                actual = (manifest_path.parent / spec.get("path", "")).resolve()
                require(errors, actual == expected, f"candidate path escape for {alias}")

    try:
        candidate = view.toml("wasm-float-candidate/Cargo.toml")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse acceptance candidate manifest: {exc}")
        candidate = {}
    require(errors, candidate.get("package", {}).get("name") == candidate_package, "acceptance candidate identity drift")
    require(errors, candidate.get("package", {}).get("publish") is False, "acceptance candidate must stay publish=false")
    require(errors, candidate.get("features", {}).get("default") == [], "acceptance candidate must be inert by default")
    require(errors, candidate.get("features", {}).get("c88-f2-acceptance") == ["dep:vibeos-wasm-runtime", "dep:wasmi-softfloat"], "acceptance feature gate drift")
    candidate_dep = candidate.get("dependencies", {}).get("wasmi-softfloat", {})
    require(errors, candidate_dep.get("package") == "vibeos-wasmi-softfloat", "candidate fork package identity drift")
    require(errors, candidate_dep.get("path") == "../vendor/wasmi-softfloat/crates/wasmi", "candidate fork path drift")
    require(errors, candidate_dep.get("optional") is True, "candidate fork must stay optional")
    require(errors, candidate_dep.get("default-features") is False, "candidate fork defaults must stay disabled")
    require(errors, set(candidate_dep.get("features", [])) == {"extra-checks", "prefer-btree-collections"}, "candidate fork feature vector drift")
    for alias, spec in candidate.get("dependencies", {}).items():
        if isinstance(spec, dict) and spec.get("package", alias) in fork_names:
            require(errors, spec.get("optional") is True, f"normal fork dependency must be feature-gated: {alias}")
    test_core = candidate.get("dev-dependencies", {}).get("softfloat-core", {})
    require(errors, test_core.get("package") == "vibeos-wasmi-core-softfloat", "test-only core fork identity drift")
    require(errors, test_core.get("path") == "../vendor/wasmi-softfloat/crates/core", "test-only core fork path drift")
    require(errors, test_core.get("default-features") is False, "test-only core fork defaults must stay disabled")

    root_text = view.text("Cargo.toml")
    patch_header = re.compile(r"(?m)^\s*\[patch\.crates-io\]\s*$")
    require(errors, patch_header.search(root_text) is None, "workspace [patch.crates-io] header is forbidden")
    for rel in workspace_manifests:
        require(errors, patch_header.search(view.text(rel)) is None, f"[patch.crates-io] is forbidden in {rel}")

    component = view.text("component-format/src/lib.rs")
    engine = view.text("component-format/src/engine.rs")
    require(errors, "pub const PROFILE_2_SYNC_FLOAT_PROFILE_CODE: u16 = 5;" in component, "code-5 profile constant drift")
    require(errors, "pub const PROFILE_2_SYNC_FLOAT_ARTIFACT_ABI_VERSION: u16 = 5;" in component, "code-5 artifact ABI drift")
    require(errors, "pub const PROFILE_2_SYNC_FLOAT_RUNTIME_ABI_VERSION: u16 = 5;" in component, "code-5 runtime ABI drift")
    profile_block = re.search(r"pub const PROFILE_2_SYNC_FLOAT: Self = Self \{(?P<body>.*?)\n    \};", component, re.DOTALL)
    require(errors, profile_block is not None and "stage: ProfileStage::ValidationOnly" in profile_block.group("body"), "code 5 must remain ValidationOnly")
    require(errors, "runtime_ready: false," in engine, "code-5 validation contract must remain runtime_ready=false")
    resolver = re.search(r"pub fn current_validation_engine_identity\(.*?\n\}", engine, re.DOTALL)
    require(errors, resolver is not None, "current engine resolver missing")
    if resolver is not None:
        require(errors, re.search(r"if profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT \{\s*None", resolver.group(0)) is not None, "code 5 entered the current engine resolver")

    runtime_manifest = view.text("wasm-runtime/Cargo.toml")
    for fork_name in fork_names:
        require(errors, fork_name not in runtime_manifest, f"production wasm-runtime depends on {fork_name}")

    candidate_source = view.text("wasm-float-candidate/src/lib.rs")
    require(errors, "#![no_std]" in candidate_source, "acceptance candidate lost no_std")
    require(errors, '#[cfg(feature = "c88-f2-acceptance")]' in candidate_source, "candidate runtime lost acceptance feature gate")
    require(errors, 'upstream_revision: "8273dfb09d493971b7bb12fe614d740cdc857175",' in candidate_source, "candidate Wasmi revision identity drift")
    require(errors, f'patched_manifest_sha256: "{EXPECTED_PATCHED_MANIFEST_SHA256}",' in candidate_source, "candidate patched-tree identity drift")
    require(errors, f'patch_delta_sha256: "{EXPECTED_PATCH_DELTA_SHA256}",' in candidate_source, "candidate patch-delta identity drift")
    require(errors, 'backend_archive_sha256: "486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad",' in candidate_source, "candidate backend archive identity drift")
    require(errors, "production_ready: false," in candidate_source, "acceptance candidate became production-ready")


def verify(view: View) -> None:
    errors: list[str] = []
    verify_provenance(view, errors)
    verify_lock_and_profile1(view, errors)
    verify_fork_manifests(view, errors)
    verify_isolation_and_inertness(view, errors)
    if errors:
        raise VerificationFailure(errors)


def replace_once(data: bytes, before: bytes, after: bytes, label: str) -> bytes:
    if data.count(before) != 1:
        raise RuntimeError(f"self-test fixture {label!r} is not unique")
    return data.replace(before, after, 1)


def self_test(base: View) -> None:
    mutations = [
        (
            "fork source drift",
            "vendor/wasmi-softfloat/crates/core/README.md",
            lambda data: data + b"\nself-test drift\n",
        ),
        (
            "Profile 1 checksum drift",
            "Cargo.lock",
            lambda data: replace_once(
                data,
                WASMI_ARCHIVES["wasmi"].encode(),
                ("0" * 64).encode(),
                "stock Wasmi checksum",
            ),
        ),
        (
            "workspace patch injection",
            "Cargo.toml",
            lambda data: data
            + b'\n[patch.crates-io]\nwasmi = { path = "vendor/wasmi-softfloat/crates/wasmi" }\n',
        ),
        (
            "code-5 activation",
            "component-format/src/engine.rs",
            lambda data: replace_once(
                data,
                b"runtime_ready: false,",
                b"runtime_ready: true,",
                "code-5 runtime_ready",
            ),
        ),
        (
            "fork package identity drift",
            "vendor/wasmi-softfloat/crates/core/Cargo.toml",
            lambda data: replace_once(
                data,
                b'name = "vibeos-wasmi-core-softfloat"',
                b'name = "wasmi_core"',
                "fork package name",
            ),
        ),
    ]
    for label, path, mutate in mutations:
        overlay = {path: mutate(base.read(path))}
        try:
            verify(View(base.root, overlay))
        except VerificationFailure:
            print(f"self-test PASS: rejected {label}")
        else:
            raise RuntimeError(f"self-test FAILED: accepted {label}")
    label = "unbound Cargo build script injection"
    build_script = "vendor/wasmi-softfloat/crates/core/build.rs"
    try:
        verify(
            View(
                base.root,
                {
                    build_script: (
                        b'fn main() { println!("cargo:rustc-cfg=f2_supply_chain_bypass"); }\n'
                    )
                },
            )
        )
    except VerificationFailure:
        print(f"self-test PASS: rejected {label}")
    else:
        raise RuntimeError(f"self-test FAILED: accepted {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="also prove fail-closed behavior with in-memory mutations")
    parser.add_argument("--print-digests", action="store_true", help="print the current deterministic fork digests without verifying")
    args = parser.parse_args()
    view = View(ROOT)
    if args.print_digests:
        for key, value in computed_digests(view).items():
            print(f'{key} = "{value}"')
        pristine = parse_upstream_files(view)
        patched = fork_content_entries(view)
        print("changed_files = [")
        for path in sorted(set(pristine) | set(patched)):
            if pristine.get(path) != patched.get(path):
                print(f'  "{path}",')
        print("]")
        return 0
    try:
        verify(view)
        print("C8.8-F2 supply-chain verification: PASS")
        if args.self_test:
            self_test(view)
    except (OSError, RuntimeError, VerificationFailure) as exc:
        print(f"C8.8-F2 supply-chain verification: FAIL\n{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
