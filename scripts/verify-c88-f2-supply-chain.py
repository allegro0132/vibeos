#!/usr/bin/env python3
"""Verify the C8.8-F2 software-float candidate supply-chain boundary.

The verifier is intentionally offline.  It binds the pristine crates.io
archives through their registry checksums, binds the selected upstream files
through UPSTREAM_FILES.sha256, and binds the reviewed fork through a
domain-separated content-manifest digest.  ``--self-test`` mutates inputs in
memory and proves that the source, current F4/F5 direct-consumer, feature-edge,
vendor-isolation, and code-5 inertness guards fail closed without touching the
worktree.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import posixpath
import re
import sys
import tomllib
from collections import deque
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
CANDIDATE_PACKAGE = "vibeos-wasm-float-candidate"
CANDIDATE_MANIFEST = PurePosixPath("wasm-float-candidate/Cargo.toml")
CANDIDATE_FEATURE_REFS = frozenset(
    {
        "dep:vibeos-wasm-float-candidate",
        "vibeos-wasm-float-candidate/c88-f2-acceptance",
    }
)
MAX_LOCAL_MANIFESTS = 256
ALLOWED_VENDOR_PATH_EDGES = {
    (
        CANDIDATE_MANIFEST,
        "dependencies",
        "wasmi-softfloat",
    ): {
        "target": PurePosixPath("vendor/wasmi-softfloat/crates/wasmi/Cargo.toml"),
        "spec": {
            "package": "vibeos-wasmi-softfloat",
            "path": "../vendor/wasmi-softfloat/crates/wasmi",
            "default-features": False,
            "features": ["extra-checks", "prefer-btree-collections"],
            "optional": True,
        },
    },
    (
        CANDIDATE_MANIFEST,
        "dev-dependencies",
        "softfloat-core",
    ): {
        "target": PurePosixPath("vendor/wasmi-softfloat/crates/core/Cargo.toml"),
        "spec": {
            "package": "vibeos-wasmi-core-softfloat",
            "path": "../vendor/wasmi-softfloat/crates/core",
            "default-features": False,
        },
    },
    (
        PurePosixPath("vendor/wasmi-softfloat/crates/wasmi/Cargo.toml"),
        "dependencies",
        "wasmi_collections",
    ): {
        "target": PurePosixPath(
            "vendor/wasmi-softfloat/crates/collections/Cargo.toml"
        ),
        "spec": {
            "package": "vibeos-wasmi-collections-softfloat",
            "path": "../collections",
            "version": "=1.1.0-vibeos-f2.1",
            "default-features": False,
        },
    },
    (
        PurePosixPath("vendor/wasmi-softfloat/crates/wasmi/Cargo.toml"),
        "dependencies",
        "wasmi_core",
    ): {
        "target": PurePosixPath("vendor/wasmi-softfloat/crates/core/Cargo.toml"),
        "spec": {
            "package": "vibeos-wasmi-core-softfloat",
            "path": "../core",
            "version": "=1.1.0-vibeos-f2.1",
            "default-features": False,
        },
    },
    (
        PurePosixPath("vendor/wasmi-softfloat/crates/wasmi/Cargo.toml"),
        "dependencies",
        "wasmi_ir",
    ): {
        "target": PurePosixPath("vendor/wasmi-softfloat/crates/ir/Cargo.toml"),
        "spec": {
            "package": "vibeos-wasmi-ir-softfloat",
            "path": "../ir",
            "version": "=1.1.0-vibeos-f2.1",
            "default-features": False,
        },
    },
    (
        PurePosixPath("vendor/wasmi-softfloat/crates/ir/Cargo.toml"),
        "dependencies",
        "wasmi_core",
    ): {
        "target": PurePosixPath("vendor/wasmi-softfloat/crates/core/Cargo.toml"),
        "spec": {
            "package": "vibeos-wasmi-core-softfloat",
            "path": "../core",
            "version": "=1.1.0-vibeos-f2.1",
            "default-features": False,
        },
    },
}
ALLOWED_CANDIDATE_CONSUMERS = {
    PurePosixPath("component-runtime/Cargo.toml"): {
        "path": "../wasm-float-candidate",
        "features": frozenset({"c88-f4-acceptance"}),
    },
    PurePosixPath("acceptance/wasm-float-target/Cargo.toml"): {
        "path": "../../wasm-float-candidate",
        "features": frozenset(
            {"c88-f5-acceptance", "c88-f5-duo-compile-readiness"}
        ),
    },
}

# Exact, current acceptance-only feature routes which may reach the F2
# candidate feature.  The policy marker is part of the reviewed route shape,
# but is intentionally not itself candidate-reachable.
EXPECTED_FLOAT_FEATURE_ROUTES = {
    PurePosixPath("component-runtime/Cargo.toml"): {
        "c88-f4-acceptance": (
            "c88-f3-acceptance",
            "dep:vibeos-wasm-float-candidate",
            "vibeos-wasm-float-candidate/c88-f2-acceptance",
        ),
    },
    PurePosixPath("services/component-admission/Cargo.toml"): {
        "c88-f4-acceptance": (
            "vibeos-component-runtime/c88-f4-acceptance",
        ),
    },
    PurePosixPath("services/component-image-adapter/Cargo.toml"): {
        "c88-f4-float-candidate-core": (
            "dep:vibeos-component-admission",
            "dep:vibeos-component-format",
            "dep:vibeos-component-runtime",
            "dep:vibeos-image-policy",
            "vibeos-component-admission/c88-f4-acceptance",
            "vibeos-component-runtime/c88-f4-acceptance",
            "vibeos-image-policy/c88-f4-float-candidate",
        ),
        "c88-f4-float-candidate": (
            "c88-f4-float-candidate-core",
            "vibeos-image-policy/qemu-default",
        ),
        "c88-f4-float-candidate-duo": (
            "c88-f4-float-candidate-core",
            "vibeos-image-policy/milkv-duo-sd",
        ),
    },
    PurePosixPath("policy/image/Cargo.toml"): {
        "c88-f4-float-candidate": (),
    },
    PurePosixPath("acceptance/wasm-float-target/Cargo.toml"): {
        "c88-f5-acceptance": (
            "dep:sha2",
            "dep:vibeos-component-format",
            "dep:vibeos-component-image-adapter",
            "dep:vibeos-component-runtime",
            "dep:vibeos-image-policy",
            "dep:vibeos-wasm-float-candidate",
            "dep:vibeos-wasm-runtime",
            "dep:wat",
            "vibeos-component-image-adapter/c88-f4-float-candidate",
            "vibeos-component-runtime/c88-f4-acceptance",
            "vibeos-image-policy/c88-f4-float-candidate",
            "vibeos-image-policy/qemu-default",
            "vibeos-wasm-float-candidate/c88-f2-acceptance",
        ),
        "c88-f5-duo-compile-readiness": (
            "dep:sha2",
            "dep:vibeos-component-format",
            "dep:vibeos-component-image-adapter",
            "dep:vibeos-component-runtime",
            "dep:vibeos-image-policy",
            "dep:vibeos-wasm-float-candidate",
            "dep:vibeos-wasm-runtime",
            "dep:wat",
            "vibeos-component-image-adapter/c88-f4-float-candidate-duo",
            "vibeos-component-runtime/c88-f4-acceptance",
            "vibeos-image-policy/c88-f4-float-candidate",
            "vibeos-image-policy/milkv-duo-sd",
            "vibeos-wasm-float-candidate/c88-f2-acceptance",
        ),
    },
    PurePosixPath("kernel/Cargo.toml"): {
        "wasm-c88-f5-float-qemu-acceptance": (
            "dep:sha2",
            "dep:vibeos-component-format",
            "dep:vibeos-component-runtime",
            "dep:vibeos-wasm-float-target",
            "vibeos-wasm-float-target/c88-f5-acceptance",
        ),
        "wasm-c88-f5-float-duo-compile-readiness": (
            "dep:sha2",
            "dep:vibeos-component-format",
            "dep:vibeos-component-runtime",
            "dep:vibeos-wasm-float-target",
            "vibeos-wasm-float-target/c88-f5-duo-compile-readiness",
        ),
    },
    PurePosixPath("firmware/qemu-virt/Cargo.toml"): {
        "wasm-c88-f5-float-qemu-acceptance": (
            "vibeos-kernel/wasm-c88-f5-float-qemu-acceptance",
        ),
    },
    PurePosixPath("firmware/milkv-duo/Cargo.toml"): {
        "wasm-c88-f5-float-duo-compile-readiness": (
            "vibeos-kernel/wasm-c88-f5-float-duo-compile-readiness",
        ),
    },
}

EXPECTED_FLOAT_DEFAULTS = {
    CANDIDATE_MANIFEST: (),
    PurePosixPath("component-runtime/Cargo.toml"): (),
    PurePosixPath("services/component-admission/Cargo.toml"): (),
    PurePosixPath("services/component-image-adapter/Cargo.toml"): (),
    PurePosixPath("policy/image/Cargo.toml"): ("qemu-default",),
    PurePosixPath("acceptance/wasm-float-target/Cargo.toml"): (),
    PurePosixPath("kernel/Cargo.toml"): (
        "qemu-virt",
        "qemu-default-image",
    ),
    PurePosixPath("firmware/qemu-virt/Cargo.toml"): (),
    PurePosixPath("firmware/milkv-duo/Cargo.toml"): ("milkv-ssh",),
}

EXPECTED_CANDIDATE_REACHERS = frozenset(
    {
        (PurePosixPath("component-runtime/Cargo.toml"), "c88-f4-acceptance"),
        (
            PurePosixPath("services/component-admission/Cargo.toml"),
            "c88-f4-acceptance",
        ),
        (
            PurePosixPath("services/component-image-adapter/Cargo.toml"),
            "c88-f4-float-candidate-core",
        ),
        (
            PurePosixPath("services/component-image-adapter/Cargo.toml"),
            "c88-f4-float-candidate",
        ),
        (
            PurePosixPath("services/component-image-adapter/Cargo.toml"),
            "c88-f4-float-candidate-duo",
        ),
        (
            PurePosixPath("acceptance/wasm-float-target/Cargo.toml"),
            "c88-f5-acceptance",
        ),
        (
            PurePosixPath("acceptance/wasm-float-target/Cargo.toml"),
            "c88-f5-duo-compile-readiness",
        ),
        (
            PurePosixPath("kernel/Cargo.toml"),
            "wasm-c88-f5-float-qemu-acceptance",
        ),
        (
            PurePosixPath("kernel/Cargo.toml"),
            "wasm-c88-f5-float-duo-compile-readiness",
        ),
        (
            PurePosixPath("firmware/qemu-virt/Cargo.toml"),
            "wasm-c88-f5-float-qemu-acceptance",
        ),
        (
            PurePosixPath("firmware/milkv-duo/Cargo.toml"),
            "wasm-c88-f5-float-duo-compile-readiness",
        ),
    }
)

# Dependencies which carry the approved transitive path. Effective Cargo
# flags are frozen, including implicit true/false values, so dependency-level
# feature injection cannot bypass the feature-table route review.
EXPECTED_FLOAT_ROUTE_DEPENDENCIES = {
    PurePosixPath("component-runtime/Cargo.toml"): {
        "vibeos-wasm-float-candidate": (
            "../wasm-float-candidate",
            True,
            False,
            (),
        ),
    },
    PurePosixPath("services/component-admission/Cargo.toml"): {
        "vibeos-component-runtime": ("../../component-runtime", False, True, ()),
    },
    PurePosixPath("services/component-image-adapter/Cargo.toml"): {
        "vibeos-component-admission": ("../component-admission", True, True, ()),
        "vibeos-component-runtime": ("../../component-runtime", True, True, ()),
        "vibeos-image-policy": ("../../policy/image", True, False, ()),
    },
    PurePosixPath("acceptance/wasm-float-target/Cargo.toml"): {
        "vibeos-component-image-adapter": (
            "../../services/component-image-adapter",
            True,
            False,
            (),
        ),
        "vibeos-component-runtime": ("../../component-runtime", True, True, ()),
        "vibeos-image-policy": ("../../policy/image", True, False, ()),
        "vibeos-wasm-float-candidate": (
            "../../wasm-float-candidate",
            True,
            False,
            (),
        ),
    },
    PurePosixPath("kernel/Cargo.toml"): {
        "vibeos-component-runtime": ("../component-runtime", True, True, ()),
        "vibeos-wasm-float-target": (
            "../acceptance/wasm-float-target",
            True,
            False,
            (),
        ),
    },
    PurePosixPath("firmware/qemu-virt/Cargo.toml"): {
        "vibeos-kernel": (
            "../../kernel",
            False,
            False,
            ("qemu-virt", "qemu-default-image"),
        ),
    },
    PurePosixPath("firmware/milkv-duo/Cargo.toml"): {
        "vibeos-kernel": (
            "../../kernel",
            False,
            False,
            ("milkv-duo", "milkv-duo-sd-image"),
        ),
    },
}

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

    def exists(self, rel: str | PurePosixPath) -> bool:
        key = PurePosixPath(rel).as_posix()
        return key in self.overlay or (self.root / key).is_file()


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


def dependency_entries(
    manifest: Mapping[str, Any],
) -> Iterable[tuple[str, str, Any]]:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(section, {})
        if isinstance(table, dict):
            for alias, spec in table.items():
                yield section, alias, spec
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(section, {})
                if isinstance(table, dict):
                    for alias, spec in table.items():
                        yield f"target.{target_name}.{section}", alias, spec


def lexical_dependency_manifest(
    source_manifest: PurePosixPath,
    raw_path: Any,
) -> PurePosixPath | None:
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or "\\" in raw_path
        or "\x00" in raw_path
        or re.match(r"^[A-Za-z]:", raw_path)
        or PurePosixPath(raw_path).is_absolute()
    ):
        return None
    raw_parts = PurePosixPath(raw_path).parts
    saw_non_parent = False
    for part in raw_parts:
        if part in {"", "."}:
            continue
        if part == "..":
            # Prefix parents are required by ordinary sibling dependencies.
            # A parent after a real component (``link/../target``) can hide a
            # symlink traversal before normalization and is never needed by
            # the reviewed repository manifests.
            if saw_non_parent:
                return None
            continue
        saw_non_parent = True
    source_directory = source_manifest.parent.as_posix()
    combined = posixpath.normpath(posixpath.join(source_directory, raw_path))
    directory = PurePosixPath(combined)
    if directory.is_absolute() or ".." in directory.parts:
        return None
    return directory / "Cargo.toml"


def manifest_symlink_component(rel: PurePosixPath) -> PurePosixPath | None:
    current = ROOT
    walked = PurePosixPath()
    for part in rel.parts:
        current /= part
        walked /= part
        if current.is_symlink():
            return walked
    return None


def raw_path_symlink_component(
    source_manifest: PurePosixPath,
    raw_path: Any,
) -> PurePosixPath | None:
    if not isinstance(raw_path, str):
        return None
    walked = list(source_manifest.parent.parts)
    for part in PurePosixPath(raw_path).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if walked:
                walked.pop()
            continue
        walked.append(part)
        candidate = ROOT.joinpath(*walked)
        if candidate.is_symlink():
            return PurePosixPath(*walked)
    return None


def validate_local_manifest(
    view: View,
    source_manifest: PurePosixPath,
    raw_path: Any,
    errors: list[str],
    label: str,
) -> PurePosixPath | None:
    raw_symlink = raw_path_symlink_component(source_manifest, raw_path)
    require(
        errors,
        raw_symlink is None,
        f"repo-local path dependency traverses a symlink before normalization: "
        f"{label}:{raw_symlink}",
    )
    if raw_symlink is not None:
        return None
    target = lexical_dependency_manifest(source_manifest, raw_path)
    require(
        errors,
        target is not None,
        f"repo-local path dependency escapes or is malformed: {label}",
    )
    if target is None:
        return None
    symlink = manifest_symlink_component(target)
    require(
        errors,
        symlink is None,
        f"repo-local path dependency traverses a symlink: {label}:{symlink}",
    )
    if symlink is not None:
        return None
    require(
        errors,
        view.exists(target),
        f"repo-local path dependency manifest missing: {label}:{target}",
    )
    return target if view.exists(target) else None


def dependency_table_maps(
    manifest: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(section)
        if isinstance(table, dict):
            yield section, table
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(section)
                if isinstance(table, dict):
                    yield f"target.{target_name}.{section}", table


def dependency_table_spec(spec: Any) -> dict[str, Any] | None:
    if isinstance(spec, str):
        return {"version": spec}
    if isinstance(spec, dict):
        return copy.deepcopy(spec)
    return None


def feature_list(
    value: Any,
    errors: list[str],
    label: str,
) -> list[str]:
    require(
        errors,
        isinstance(value, list) and all(isinstance(item, str) for item in value),
        f"workspace dependency feature vector is malformed: {label}",
    )
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def effective_package_edition(
    view: View,
    manifest: Mapping[str, Any],
    manifest_rel: PurePosixPath,
    workspace_root: PurePosixPath,
    errors: list[str],
) -> str | None:
    """Resolve a literal edition or Cargo's `edition.workspace = true` form."""

    package = manifest.get("package", {})
    require(
        errors,
        isinstance(package, dict),
        f"package table is malformed for workspace inheritance: {manifest_rel}",
    )
    if not isinstance(package, dict):
        return None
    edition: Any = package.get("edition", "2015")
    if isinstance(edition, dict):
        valid_selector = set(edition) == {"workspace"} and edition.get(
            "workspace"
        ) is True
        require(
            errors,
            valid_selector,
            f"package edition workspace selector must be exactly true: {manifest_rel}",
        )
        if not valid_selector:
            return None
        try:
            workspace_manifest = view.toml(workspace_root)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            errors.append(
                f"cannot parse workspace package edition source "
                f"{workspace_root}: {exc}"
            )
            return None
        workspace = workspace_manifest.get("workspace", {})
        workspace_package = (
            workspace.get("package", {}) if isinstance(workspace, dict) else {}
        )
        edition = (
            workspace_package.get("edition")
            if isinstance(workspace_package, dict)
            else None
        )
        require(
            errors,
            isinstance(edition, str),
            f"workspace package edition is missing or malformed: {workspace_root}",
        )
        if not isinstance(edition, str):
            return None
    require(
        errors,
        isinstance(edition, str)
        and edition in {"2015", "2018", "2021", "2024"},
        f"package edition is malformed for workspace inheritance: {manifest_rel}",
    )
    return edition if isinstance(edition, str) else None


def expand_workspace_dependencies(
    view: View,
    manifest: Mapping[str, Any],
    manifest_rel: PurePosixPath,
    workspace_root: PurePosixPath,
    workspace_dependencies: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    effective = copy.deepcopy(dict(manifest))
    edition = effective_package_edition(
        view,
        manifest,
        manifest_rel,
        workspace_root,
        errors,
    )
    for section, table in dependency_table_maps(effective):
        for alias, member_value in list(table.items()):
            if not (
                isinstance(member_value, dict)
                and member_value.get("workspace") is True
            ):
                if isinstance(member_value, dict) and "workspace" in member_value:
                    errors.append(
                        f"workspace dependency selector must be true: "
                        f"{manifest_rel}:{section}:{alias}"
                    )
                continue
            require(
                errors,
                not (
                    manifest_rel in ALLOWED_CANDIDATE_CONSUMERS
                    and alias == CANDIDATE_PACKAGE
                ),
                f"reviewed direct candidate dependency cannot use workspace inheritance: "
                f"{manifest_rel}:{section}:{alias}",
            )
            template_value = workspace_dependencies.get(alias)
            template = dependency_table_spec(template_value)
            require(
                errors,
                template is not None,
                f"workspace dependency template missing: "
                f"{manifest_rel}:{section}:{alias}",
            )
            if template is None:
                table[alias] = {key: value for key, value in member_value.items() if key != "workspace"}
                continue
            require(
                errors,
                "workspace" not in template,
                f"workspace dependency template cannot inherit another template: "
                f"{workspace_root}:{alias}",
            )
            forbidden_member_keys = set(member_value) - {
                "workspace",
                "features",
                "optional",
                "default-features",
            }
            require(
                errors,
                not forbidden_member_keys,
                f"workspace dependency member overrides package/source identity: "
                f"{manifest_rel}:{section}:{alias}",
            )
            require(
                errors,
                "optional" not in template,
                f"workspace dependency template cannot set optional: "
                f"{workspace_root}:{alias}",
            )

            merged = {
                key: value
                for key, value in template.items()
                if key not in {"workspace", "features", "optional", "default-features"}
            }
            workspace_features = feature_list(
                template.get("features", []),
                errors,
                f"{workspace_root}:{alias}",
            )
            member_features = feature_list(
                member_value.get("features", []),
                errors,
                f"{manifest_rel}:{section}:{alias}",
            )
            merged_features: list[str] = []
            for feature in workspace_features + member_features:
                if feature not in merged_features:
                    merged_features.append(feature)
            if merged_features:
                merged["features"] = merged_features

            member_optional = member_value.get("optional", False)
            require(
                errors,
                isinstance(member_optional, bool),
                f"workspace dependency member optional flag is malformed: "
                f"{manifest_rel}:{section}:{alias}",
            )
            if member_optional is True:
                merged["optional"] = True

            workspace_defaults = template.get("default-features", True)
            member_defaults = member_value.get("default-features", False)
            require(
                errors,
                isinstance(workspace_defaults, bool)
                and isinstance(member_defaults, bool),
                f"workspace dependency default-features flag is malformed: "
                f"{manifest_rel}:{section}:{alias}",
            )
            # An omitted member flag inherits the workspace setting. A member
            # may re-enable defaults. Before edition 2024, an explicit false
            # cannot disable workspace-enabled defaults; edition 2024 rejects
            # that contradictory declaration instead of only warning.
            require(
                errors,
                not (
                    edition == "2024"
                    and workspace_defaults is True
                    and member_value.get("default-features") is False
                ),
                f"edition 2024 workspace dependency cannot disable defaults "
                f"enabled by its template: {manifest_rel}:{section}:{alias}",
            )
            merged["default-features"] = not (
                workspace_defaults is False and member_defaults is False
            )

            if isinstance(template.get("path"), str):
                workspace_target = validate_workspace_path_template(
                    view,
                    workspace_root,
                    alias,
                    template,
                    errors,
                )
                if workspace_target is not None:
                    merged["path"] = posixpath.relpath(
                        workspace_target.parent.as_posix(),
                        manifest_rel.parent.as_posix(),
                    )
            table[alias] = merged
    return effective


def validate_workspace_path_template(
    view: View,
    workspace_root: PurePosixPath,
    alias: str,
    template: Mapping[str, Any],
    errors: list[str],
) -> PurePosixPath | None:
    """Validate a path template when a discovered member actually inherits it."""

    label = f"{workspace_root}:workspace.dependencies:{alias}"
    require(
        errors,
        "workspace" not in template,
        f"workspace dependency template cannot inherit another template: {label}",
    )
    require(
        errors,
        not ({"git", "registry"} & set(template)),
        f"workspace path dependency template has conflicting source keys: {label}",
    )
    require(
        errors,
        "optional" not in template,
        f"workspace dependency template cannot set optional: {label}",
    )
    defaults = template.get("default-features", True)
    require(
        errors,
        isinstance(defaults, bool),
        f"workspace dependency default-features flag is malformed: {label}",
    )
    feature_list(template.get("features", []), errors, label)
    target = validate_local_manifest(
        view,
        workspace_root,
        template.get("path"),
        errors,
        label,
    )
    if target is None:
        return None
    try:
        target_manifest = view.toml(target)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse workspace dependency target {target}: {exc}")
        return target
    package = target_manifest.get("package", {})
    target_package = package.get("name") if isinstance(package, dict) else None
    declared_package = template.get("package", alias)
    require(
        errors,
        isinstance(declared_package, str)
        and isinstance(target_package, str)
        and declared_package == target_package,
        f"workspace dependency template package/target identity mismatch: "
        f"{label}:{declared_package!r}:{target}:{target_package!r}",
    )
    consumes_candidate = (
        declared_package == CANDIDATE_PACKAGE
        or target_package == CANDIDATE_PACKAGE
        or target == CANDIDATE_MANIFEST
    )
    require(
        errors,
        not consumes_candidate,
        f"acceptance candidate consumed outside the reviewed F4/F5 closure: {label}",
    )
    fork_names = {fork[0] for fork in FORKS.values()}
    targets_vendor = target.is_relative_to(VENDOR_REL / "crates")
    require(
        errors,
        not (
            targets_vendor
            or declared_package in fork_names
            or target_package in fork_names
        ),
        f"vendored fork consumed outside its frozen candidate entry: {label}",
    )
    return target


def workspace_excludes_manifest(
    workspace_root: PurePosixPath,
    workspace: Mapping[str, Any],
    target: PurePosixPath,
    errors: list[str],
) -> bool:
    """Apply workspace excludes to an automatic/implicit path member."""

    excludes = workspace.get("exclude", [])
    if not isinstance(excludes, list):
        errors.append(f"workspace.exclude must be a list: {workspace_root}")
        return True
    try:
        relative_directory = target.parent.relative_to(workspace_root.parent)
    except ValueError:
        return True
    if relative_directory == PurePosixPath("."):
        return False
    candidates = [relative_directory, *relative_directory.parents]
    for entry in excludes:
        normalized = PurePosixPath(entry) if isinstance(entry, str) else None
        valid = (
            isinstance(entry, str)
            and bool(entry)
            and "\\" not in entry
            and "\x00" not in entry
            and not re.match(r"^[A-Za-z]:", entry)
            and normalized is not None
            and not normalized.is_absolute()
            and ".." not in normalized.parts
            and not any(character in entry for character in "*?[]")
            and normalized != PurePosixPath(".")
        )
        require(
            errors,
            valid,
            f"workspace.exclude entry is malformed: {workspace_root}:{entry!r}",
        )
        if not valid:
            return True
        if normalized in candidates:
            return True
    return False


def cached_repo_manifest(
    view: View,
    rel: PurePosixPath,
    cache: dict[PurePosixPath, Mapping[str, Any] | None],
    errors: list[str],
) -> Mapping[str, Any] | None:
    if rel in cache:
        return cache[rel]
    try:
        cache[rel] = view.toml(rel)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse repo-local manifest {rel}: {exc}")
        cache[rel] = None
    return cache[rel]


def resolve_workspace_scope(
    view: View,
    manifest_rel: PurePosixPath,
    manifest_cache: dict[PurePosixPath, Mapping[str, Any] | None],
    scope_cache: dict[
        tuple[PurePosixPath, PurePosixPath | None],
        PurePosixPath | None,
    ],
    errors: list[str],
    invocation_scope: PurePosixPath | None = None,
) -> PurePosixPath | None:
    """Resolve invocation-root first, then nearest ancestors from the target."""

    cache_key = (manifest_rel, invocation_scope)
    if cache_key in scope_cache:
        return scope_cache[cache_key]
    target_manifest = cached_repo_manifest(
        view,
        manifest_rel,
        manifest_cache,
        errors,
    )
    if target_manifest is None:
        scope_cache[cache_key] = None
        return None
    if invocation_scope is not None:
        scope_manifest = cached_repo_manifest(
            view,
            invocation_scope,
            manifest_cache,
            errors,
        )
        workspace = (
            scope_manifest.get("workspace")
            if isinstance(scope_manifest, Mapping)
            else None
        )
        require(
            errors,
            isinstance(workspace, dict),
            f"invocation workspace scope is unavailable: {invocation_scope}",
        )
        invocation_can_claim = (
            isinstance(workspace, dict)
            and not workspace_excludes_manifest(
                invocation_scope,
                workspace,
                manifest_rel,
                errors,
            )
        )
        if invocation_can_claim:
            invocation_conflicts = (
                invocation_scope != manifest_rel
                and "package" in target_manifest
                and "workspace" in target_manifest
            )
            require(
                errors,
                not invocation_conflicts,
                f"invocation workspace cannot claim a package that is also a "
                f"workspace root: {manifest_rel}",
            )
            scope_cache[cache_key] = invocation_scope
            return invocation_scope

    directory = manifest_rel.parent
    while True:
        candidate = directory / "Cargo.toml"
        if view.exists(candidate):
            symlink = manifest_symlink_component(candidate)
            require(
                errors,
                symlink is None,
                f"workspace scope manifest traverses a symlink: "
                f"{candidate}:{symlink}",
            )
            if symlink is not None:
                scope_cache[cache_key] = None
                return None
            raw = cached_repo_manifest(view, candidate, manifest_cache, errors)
            if raw is None:
                scope_cache[cache_key] = None
                return None
            if "workspace" in raw:
                workspace = raw.get("workspace")
                require(
                    errors,
                    isinstance(workspace, dict),
                    f"workspace table must be a table: {candidate}",
                )
                if not isinstance(workspace, dict):
                    scope_cache[cache_key] = None
                    return None
                excluded = (
                    candidate != manifest_rel
                    and workspace_excludes_manifest(
                        candidate,
                        workspace,
                        manifest_rel,
                        errors,
                    )
                )
                if not excluded:
                    scope_cache[cache_key] = candidate
                    return candidate
                # Cargo continues looking outward when the nearest workspace
                # excludes this package; an enclosing workspace may still
                # claim it and supply its inherited dependency templates.
        if not directory.parts:
            break
        directory = directory.parent
    scope_cache[cache_key] = None
    return None


def discover_local_manifests(
    view: View,
    root_manifest: Mapping[str, Any],
    errors: list[str],
) -> dict[PurePosixPath, Mapping[str, Any]]:
    root_rel = PurePosixPath("Cargo.toml")
    root_workspace = root_manifest.get("workspace", {})
    require(errors, isinstance(root_workspace, dict), "root workspace table missing")
    if not isinstance(root_workspace, dict):
        return {root_rel: root_manifest}
    root_dependencies = root_workspace.get("dependencies", {})
    require(
        errors,
        isinstance(root_dependencies, dict),
        "root workspace.dependencies must be a table",
    )
    scopes: dict[PurePosixPath, Mapping[str, Any]] = {
        root_rel: root_dependencies if isinstance(root_dependencies, dict) else {}
    }
    manifest_cache: dict[PurePosixPath, Mapping[str, Any] | None] = {
        root_rel: root_manifest
    }
    scope_cache: dict[
        tuple[PurePosixPath, PurePosixPath | None],
        PurePosixPath | None,
    ] = {}
    pending: deque[
        tuple[PurePosixPath, PurePosixPath | None]
    ] = deque([(root_rel, root_rel)])
    declared_root_members: set[PurePosixPath] = set()
    members = root_workspace.get("members", [])
    require(errors, isinstance(members, list), "root workspace.members must be a list")
    if isinstance(members, list):
        for member in members:
            require(
                errors,
                isinstance(member, str)
                and not any(character in member for character in "*?[]"),
                f"workspace member must be a literal repo-local path: {member!r}",
            )
            if not isinstance(member, str) or any(
                character in member for character in "*?[]"
            ):
                continue
            target = validate_local_manifest(
                view,
                root_rel,
                member,
                errors,
                f"workspace member {member}",
            )
            if target is None:
                continue
            require(
                errors,
                not target.is_relative_to(VENDOR_REL / "crates"),
                f"vendored Wasmi fork cannot be a workspace member: {target}",
            )
            if not target.is_relative_to(VENDOR_REL / "crates"):
                declared_root_members.add(target)
                pending.append((target, root_rel))

    parsed: dict[PurePosixPath, Mapping[str, Any]] = {}
    manifest_scopes: dict[PurePosixPath, PurePosixPath | None] = {}
    package_names: dict[str, PurePosixPath] = {}
    while pending:
        rel, invocation_scope = pending.popleft()
        if len(parsed) >= MAX_LOCAL_MANIFESTS and rel not in parsed:
            errors.append(
                f"repo-local path dependency closure exceeds {MAX_LOCAL_MANIFESTS} manifests"
            )
            break
        symlink = manifest_symlink_component(rel)
        require(
            errors,
            symlink is None,
            f"repo-local manifest traverses a symlink: {rel}:{symlink}",
        )
        if symlink is not None:
            continue
        raw = cached_repo_manifest(view, rel, manifest_cache, errors)
        if raw is None:
            continue

        raw_package = raw.get("package", {})
        require(
            errors,
            not (isinstance(raw_package, dict) and "workspace" in raw_package),
            f"explicit [package].workspace is forbidden in the audited closure: {rel}",
        )
        active_scope = resolve_workspace_scope(
            view,
            rel,
            manifest_cache,
            scope_cache,
            errors,
            invocation_scope,
        )
        if rel in declared_root_members:
            require(
                errors,
                active_scope == root_rel,
                f"declared root workspace member resolves outside the root scope: "
                f"{rel}:{active_scope}",
            )
        if active_scope is not None and active_scope not in scopes:
            scope_manifest = cached_repo_manifest(
                view,
                active_scope,
                manifest_cache,
                errors,
            )
            workspace = (
                scope_manifest.get("workspace")
                if isinstance(scope_manifest, Mapping)
                else None
            )
            require(
                errors,
                isinstance(workspace, dict),
                f"workspace scope unavailable for repo-local manifest: {rel}",
            )
            scope_dependencies = (
                workspace.get("dependencies", {})
                if isinstance(workspace, dict)
                else {}
            )
            require(
                errors,
                isinstance(scope_dependencies, dict),
                f"workspace.dependencies must be a table: {active_scope}",
            )
            scopes[active_scope] = (
                scope_dependencies if isinstance(scope_dependencies, dict) else {}
            )
        if active_scope is None:
            effective = copy.deepcopy(dict(raw))
            for section, alias, spec in dependency_entries(effective):
                require(
                    errors,
                    not (isinstance(spec, dict) and "workspace" in spec),
                    f"workspace dependency selector has no resolved scope: "
                    f"{rel}:{section}:{alias}",
                )
        else:
            effective = expand_workspace_dependencies(
                view,
                raw,
                rel,
                active_scope,
                scopes.get(active_scope, {}),
                errors,
            )
        if rel in parsed:
            require(
                errors,
                manifest_scopes[rel] == active_scope,
                f"repo-local manifest reached through multiple workspace scopes: {rel}",
            )
            require(
                errors,
                parsed[rel] == effective,
                f"repo-local manifest has non-deterministic effective dependencies: {rel}",
            )
            continue
        parsed[rel] = effective
        manifest_scopes[rel] = active_scope

        package = effective.get("package", {})
        if rel != root_rel or package:
            package_name = package.get("name") if isinstance(package, dict) else None
            require(
                errors,
                isinstance(package_name, str) and bool(package_name),
                f"repo-local dependency manifest lacks a package identity: {rel}",
            )
            if isinstance(package_name, str) and package_name:
                previous = package_names.get(package_name)
                require(
                    errors,
                    previous is None or previous == rel,
                    f"duplicate repo-local package identity {package_name!r}: "
                    f"{previous} and {rel}",
                )
                package_names.setdefault(package_name, rel)

        alias_targets: dict[str, PurePosixPath] = {}
        for section, alias, spec in dependency_entries(effective):
            if not isinstance(spec, dict) or "path" not in spec:
                continue
            target = validate_local_manifest(
                view,
                rel,
                spec.get("path"),
                errors,
                f"{rel}:{section}:{alias}",
            )
            if target is None:
                continue
            previous_target = alias_targets.get(alias)
            require(
                errors,
                previous_target is None or previous_target == target,
                f"repo-local dependency alias resolves to multiple targets: "
                f"{rel}:{alias}:{previous_target}:{target}",
            )
            alias_targets.setdefault(alias, target)
            pending.append((target, invocation_scope))
    return parsed


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


def candidate_feature_references(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    prefix = f"{CANDIDATE_PACKAGE}/"
    weak_prefix = f"{CANDIDATE_PACKAGE}?/"
    return {
        value
        for value in values
        if isinstance(value, str)
        and (
            value == CANDIDATE_PACKAGE
            or value == f"dep:{CANDIDATE_PACKAGE}"
            or value.startswith(prefix)
            or value.startswith(weak_prefix)
        )
    }


def feature_reaches_candidate(features: Mapping[str, Any], start: str) -> bool:
    pending = [start]
    seen: set[str] = set()
    while pending:
        feature = pending.pop()
        if feature in seen:
            continue
        seen.add(feature)
        values = features.get(feature, [])
        if candidate_feature_references(values):
            return True
        if not isinstance(values, list):
            continue
        pending.extend(
            value
            for value in values
            if isinstance(value, str) and value in features and value not in seen
        )
    return False


def resolved_workspace_dependencies(
    parsed_manifests: Mapping[PurePosixPath, Mapping[str, Any]],
) -> dict[
    PurePosixPath,
    dict[str, list[tuple[PurePosixPath, Mapping[str, Any]]]],
]:
    result: dict[
        PurePosixPath,
        dict[str, list[tuple[PurePosixPath, Mapping[str, Any]]]],
    ] = {}
    for rel, manifest in parsed_manifests.items():
        aliases: dict[str, list[tuple[PurePosixPath, Mapping[str, Any]]]] = {}
        for _section, alias, spec in dependency_entries(manifest):
            if not isinstance(spec, dict) or not isinstance(spec.get("path"), str):
                continue
            target = lexical_dependency_manifest(rel, spec["path"])
            if target is not None and target in parsed_manifests:
                aliases.setdefault(alias, []).append((target, spec))
        result[rel] = aliases
    return result


def candidate_reachable_features(
    parsed_manifests: Mapping[PurePosixPath, Mapping[str, Any]],
) -> tuple[
    set[tuple[PurePosixPath, str]],
    set[PurePosixPath],
]:
    dependencies = resolved_workspace_dependencies(parsed_manifests)
    node = tuple[PurePosixPath, str | None]
    adjacency: dict[node, set[node]] = {}

    def activate_dependency(
        source: PurePosixPath,
        alias: str,
        explicit_feature: str | None = None,
    ) -> set[node]:
        activated: set[node] = set()
        for target, spec in dependencies.get(source, {}).get(alias, []):
            activated.add((target, None))
            if spec.get("default-features", True) is not False:
                activated.add((target, "default"))
            dep_features = spec.get("features", [])
            if isinstance(dep_features, list):
                activated.update(
                    (target, feature)
                    for feature in dep_features
                    if isinstance(feature, str)
                )
            if explicit_feature is not None:
                activated.add((target, explicit_feature))
        return activated

    for rel, manifest in parsed_manifests.items():
        features = manifest.get("features", {})
        if not isinstance(features, dict):
            features = {}
        base = (rel, None)
        base_edges: set[node] = set()
        for _section, alias, spec in dependency_entries(manifest):
            if isinstance(spec, dict) and spec.get("optional", False) is not True:
                base_edges.update(activate_dependency(rel, alias))
        adjacency[base] = base_edges

        # Cargo has an implicit empty default when the table omits one. Keeping
        # that virtual node lets the verifier prove default non-reachability for
        # every workspace package, not only packages which spell it explicitly.
        for feature in set(features) | {"default"}:
            feature_node = (rel, feature)
            edges: set[node] = {base}
            values = features.get(feature, [])
            if isinstance(values, list):
                for value in values:
                    if not isinstance(value, str):
                        continue
                    if value.startswith("dep:"):
                        edges.update(activate_dependency(rel, value[4:]))
                    elif "/" in value:
                        alias, dependency_feature = value.split("/", 1)
                        # A weak edge is conservatively considered reachable:
                        # another item in the same additive feature set may
                        # activate it, and such a route must still be reviewed.
                        edges.update(
                            activate_dependency(
                                rel,
                                alias.removesuffix("?"),
                                dependency_feature,
                            )
                        )
                    elif value in features:
                        edges.add((rel, value))
                    else:
                        # Cargo's implicit optional-dependency feature form.
                        edges.update(activate_dependency(rel, value))
            adjacency[feature_node] = edges

    reverse: dict[node, set[node]] = {}
    for source, targets in adjacency.items():
        for target in targets:
            reverse.setdefault(target, set()).add(source)
    sink: node = (CANDIDATE_MANIFEST, "c88-f2-acceptance")
    reaches_sink: set[node] = {sink}
    pending = [sink]
    while pending:
        target = pending.pop()
        for source in reverse.get(target, set()):
            if source not in reaches_sink:
                reaches_sink.add(source)
                pending.append(source)

    reachable_features = {
        (rel, feature)
        for rel, manifest in parsed_manifests.items()
        for feature in (
            manifest.get("features", {})
            if isinstance(manifest.get("features", {}), dict)
            else {}
        )
        if (rel, feature) in reaches_sink and (rel, feature) != sink
    }
    reachable_defaults = {
        rel for rel in parsed_manifests if (rel, "default") in reaches_sink
    }
    return reachable_features, reachable_defaults


def verify_float_feature_closure(
    parsed_manifests: Mapping[PurePosixPath, Mapping[str, Any]],
    errors: list[str],
) -> None:
    for rel, expected_features in EXPECTED_FLOAT_FEATURE_ROUTES.items():
        manifest = parsed_manifests.get(rel, {})
        features = manifest.get("features", {})
        require(errors, isinstance(features, dict), f"Float route features missing: {rel}")
        if not isinstance(features, dict):
            continue
        for feature, expected_values in expected_features.items():
            require(
                errors,
                features.get(feature) == list(expected_values),
                f"exact Float feature route drift: {rel}:{feature}",
            )

    for rel, expected_default in EXPECTED_FLOAT_DEFAULTS.items():
        manifest = parsed_manifests.get(rel, {})
        features = manifest.get("features", {})
        actual = features.get("default") if isinstance(features, dict) else None
        require(
            errors,
            actual == list(expected_default),
            f"Float closure default feature drift: {rel}",
        )

    for rel, expected_dependencies in EXPECTED_FLOAT_ROUTE_DEPENDENCIES.items():
        manifest = parsed_manifests.get(rel, {})
        for alias, (
            expected_path,
            expected_optional,
            expected_default_features,
            expected_features,
        ) in expected_dependencies.items():
            found = [
                (section, spec)
                for section, found_alias, spec in dependency_entries(manifest)
                if found_alias == alias
            ]
            require(
                errors,
                len(found) == 1,
                f"Float route dependency must occur exactly once: {rel}:{alias}",
            )
            if len(found) != 1:
                continue
            section, spec = found[0]
            require(
                errors,
                section == "dependencies" and isinstance(spec, dict),
                f"Float route dependency must be a normal table dependency: {rel}:{alias}",
            )
            if not isinstance(spec, dict):
                continue
            require(
                errors,
                spec.get("package", alias) == alias,
                f"Float route dependency package drift: {rel}:{alias}",
            )
            require(
                errors,
                spec.get("path") == expected_path,
                f"Float route dependency path drift: {rel}:{alias}",
            )
            require(
                errors,
                spec.get("optional", False) is expected_optional,
                f"Float route dependency optional flag drift: {rel}:{alias}",
            )
            require(
                errors,
                isinstance(spec.get("default-features", True), bool)
                and spec.get("default-features", True)
                is expected_default_features,
                f"Float route dependency default-features drift: {rel}:{alias}",
            )
            require(
                errors,
                spec.get("features", []) == list(expected_features),
                f"Float route dependency feature injection: {rel}:{alias}",
            )
            require(
                errors,
                not ({"git", "registry", "version"} & set(spec)),
                f"Float route dependency must stay path-only: {rel}:{alias}",
            )

    protected_features = EXPECTED_CANDIDATE_REACHERS | {
        (CANDIDATE_MANIFEST, "c88-f2-acceptance")
    }
    for source, aliases in resolved_workspace_dependencies(parsed_manifests).items():
        for alias, dependencies in aliases.items():
            for target, spec in dependencies:
                dep_features = spec.get("features", [])
                if not isinstance(dep_features, list):
                    continue
                injected = sorted(
                    feature
                    for feature in dep_features
                    if isinstance(feature, str)
                    and (target, feature) in protected_features
                )
                require(
                    errors,
                    not injected,
                    f"dependency-level activation bypasses the Float feature route: "
                    f"{source}:{alias} -> {target}:"
                    + ",".join(injected),
                )

    reachable_features, reachable_defaults = candidate_reachable_features(
        parsed_manifests
    )
    missing = sorted(EXPECTED_CANDIDATE_REACHERS - reachable_features, key=str)
    extra = sorted(reachable_features - EXPECTED_CANDIDATE_REACHERS, key=str)
    require(
        errors,
        not missing,
        "approved candidate-reachable feature missing: "
        + ", ".join(f"{rel}:{feature}" for rel, feature in missing),
    )
    require(
        errors,
        not extra,
        "unapproved candidate-reachable feature: "
        + ", ".join(f"{rel}:{feature}" for rel, feature in extra),
    )
    require(
        errors,
        not reachable_defaults,
        "workspace package default reaches the F2 candidate: "
        + ", ".join(str(rel) for rel in sorted(reachable_defaults, key=str)),
    )


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
    try:
        root_manifest = view.toml("Cargo.toml")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse root workspace manifest: {exc}")
        return
    parsed_manifests = discover_local_manifests(view, root_manifest, errors)
    candidate_consumer_count = {
        rel: 0 for rel in ALLOWED_CANDIDATE_CONSUMERS
    }
    seen_vendor_edges: set[tuple[PurePosixPath, str, str]] = set()
    vendor_manifest_cache: dict[PurePosixPath, Mapping[str, Any]] = {}
    for rel, manifest in sorted(parsed_manifests.items(), key=lambda item: str(item[0])):
        for section, alias, spec in dependency_entries(manifest):
            package = spec.get("package", alias) if isinstance(spec, dict) else alias
            target_rel: PurePosixPath | None = None
            if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                target_rel = lexical_dependency_manifest(rel, spec["path"])
            target_manifest = parsed_manifests.get(target_rel, {})
            if (
                target_rel is not None
                and not target_manifest
                and target_rel.is_relative_to(VENDOR_REL / "crates")
            ):
                if target_rel not in vendor_manifest_cache:
                    try:
                        vendor_manifest_cache[target_rel] = view.toml(target_rel)
                    except (
                        OSError,
                        UnicodeDecodeError,
                        tomllib.TOMLDecodeError,
                    ) as exc:
                        errors.append(
                            f"cannot parse vendored dependency manifest {target_rel}: {exc}"
                        )
                target_manifest = vendor_manifest_cache.get(target_rel, {})
            target_package = target_manifest.get("package", {})
            target_package_name = (
                target_package.get("name") if isinstance(target_package, dict) else None
            )
            if target_rel is not None:
                require(
                    errors,
                    isinstance(target_package_name, str),
                    f"repo-local dependency target has no package identity: "
                    f"{rel}:{section}:{alias}:{target_rel}",
                )
                require(
                    errors,
                    package == target_package_name,
                    f"repo-local dependency alias/package does not match its target: "
                    f"{rel}:{section}:{alias}:{target_rel}",
                )
            consumes_candidate = (
                package == CANDIDATE_PACKAGE
                or target_rel == CANDIDATE_MANIFEST
            )
            if consumes_candidate:
                policy = ALLOWED_CANDIDATE_CONSUMERS.get(rel)
                require(
                    errors,
                    policy is not None,
                    f"acceptance candidate consumed outside the reviewed F4/F5 closure: {rel}:{section}:{alias}",
                )
                if policy is not None:
                    candidate_consumer_count[rel] += 1
                    require(
                        errors,
                        section == "dependencies",
                        f"candidate dependency must be a normal optional dependency: {rel}:{section}:{alias}",
                    )
                    require(
                        errors,
                        alias == CANDIDATE_PACKAGE and package == CANDIDATE_PACKAGE,
                        f"candidate dependency package identity drift: {rel}:{alias}",
                    )
                    require(
                        errors,
                        isinstance(spec, dict),
                        f"candidate dependency must use an exact table: {rel}:{alias}",
                    )
                    if isinstance(spec, dict):
                        require(
                            errors,
                            spec.get("path") == policy["path"],
                            f"candidate dependency path drift: {rel}:{alias}",
                        )
                        require(
                            errors,
                            target_rel == CANDIDATE_MANIFEST,
                            f"candidate dependency path escape: {rel}:{alias}",
                        )
                        require(
                            errors,
                            spec.get("optional") is True,
                            f"candidate dependency must stay optional: {rel}:{alias}",
                        )
                        require(
                            errors,
                            spec.get("default-features") is False,
                            f"candidate dependency defaults must stay disabled: {rel}:{alias}",
                        )
                        require(
                            errors,
                            spec.get("features", []) == [],
                            f"candidate dependency features must be enabled only by reviewed feature edges: {rel}:{alias}",
                        )
                        require(
                            errors,
                            not ({"git", "registry", "version"} & set(spec)),
                            f"candidate dependency must stay path-only: {rel}:{alias}",
                        )

            source_is_vendor = rel.is_relative_to(VENDOR_REL / "crates")
            targets_vendor = target_rel is not None and target_rel.is_relative_to(
                VENDOR_REL / "crates"
            )
            edge_key = (rel, section, alias)
            allowed_edge = edge_key in ALLOWED_VENDOR_PATH_EDGES
            touches_vendor = (
                (source_is_vendor and target_rel is not None)
                or targets_vendor
                or package in fork_names
            )
            if allowed_edge or touches_vendor:
                require(
                    errors,
                    allowed_edge,
                    f"vendored fork path edge outside its frozen closure: "
                    f"{rel}:{section}:{alias}",
                )
                if allowed_edge:
                    seen_vendor_edges.add(edge_key)
                    edge_policy = ALLOWED_VENDOR_PATH_EDGES[edge_key]
                    require(
                        errors,
                        edge_policy["target"] == target_rel,
                        f"vendored fork path edge outside its frozen closure: "
                        f"{rel}:{section}:{alias}",
                    )
                    require(
                        errors,
                        spec == edge_policy["spec"],
                        f"vendored fork dependency spec drift: "
                        f"{rel}:{section}:{alias}",
                    )
                if targets_vendor:
                    require(
                        errors,
                        package in fork_names,
                        f"vendored path dependency lacks a renamed package identity: "
                        f"{rel}:{section}:{alias}",
                    )

    missing_vendor_edges = set(ALLOWED_VENDOR_PATH_EDGES) - seen_vendor_edges
    require(
        errors,
        not missing_vendor_edges,
        "frozen vendored fork dependency edge missing: "
        + ", ".join(
            f"{rel}:{section}:{alias}"
            for rel, section, alias in sorted(
                missing_vendor_edges,
                key=lambda edge: (str(edge[0]), edge[1], edge[2]),
            )
        ),
    )

    verify_float_feature_closure(parsed_manifests, errors)

    for rel, policy in ALLOWED_CANDIDATE_CONSUMERS.items():
        require(
            errors,
            candidate_consumer_count.get(rel) == 1,
            f"reviewed candidate consumer must have exactly one direct dependency: {rel}",
        )
        manifest = parsed_manifests.get(rel, {})
        features = manifest.get("features", {})
        require(errors, isinstance(features, dict), f"candidate consumer features missing: {rel}")
        if not isinstance(features, dict):
            continue
        allowed_features = policy["features"]
        require(
            errors,
            allowed_features <= set(features),
            f"reviewed candidate consumer feature missing: {rel}",
        )
        for feature, values in features.items():
            require(
                errors,
                isinstance(values, list) and all(isinstance(value, str) for value in values),
                f"malformed feature vector: {rel}:{feature}",
            )
            references = candidate_feature_references(values)
            if feature in allowed_features:
                require(
                    errors,
                    references == CANDIDATE_FEATURE_REFS,
                    f"candidate feature edge drift: {rel}:{feature}",
                )
            else:
                require(
                    errors,
                    not references,
                    f"candidate feature edge leaked outside the reviewed feature: {rel}:{feature}",
                )
                require(
                    errors,
                    not feature_reaches_candidate(features, feature),
                    f"feature reaches the candidate outside the reviewed feature: {rel}:{feature}",
                )

    try:
        candidate = view.toml("wasm-float-candidate/Cargo.toml")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot parse acceptance candidate manifest: {exc}")
        candidate = {}
    require(errors, candidate.get("package", {}).get("name") == CANDIDATE_PACKAGE, "acceptance candidate identity drift")
    require(errors, candidate.get("package", {}).get("publish") is False, "acceptance candidate must stay publish=false")
    require(errors, candidate.get("features", {}).get("default") == [], "acceptance candidate must be inert by default")
    require(errors, set(candidate.get("features", {})) == {"default", "c88-f2-acceptance"}, "acceptance candidate feature surface drift")
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
    for rel in parsed_manifests:
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


def expect_rejected(
    base: View,
    label: str,
    overlay: Mapping[str, bytes],
    expected_diagnostics: str | Iterable[str],
) -> None:
    if isinstance(expected_diagnostics, str):
        expected = (expected_diagnostics,)
    else:
        expected = tuple(expected_diagnostics)
    try:
        verify(View(base.root, overlay))
    except VerificationFailure as exc:
        diagnostics = str(exc)
        missing = [item for item in expected if item not in diagnostics]
        if missing:
            raise RuntimeError(
                f"self-test FAILED: {label} missed intended diagnostics "
                f"{missing!r}; got:\n{diagnostics}"
            ) from exc
        print(f"self-test PASS: rejected {label}")
    else:
        raise RuntimeError(f"self-test FAILED: accepted {label}")


def expect_accepted(
    base: View,
    label: str,
    overlay: Mapping[str, bytes],
) -> None:
    try:
        verify(View(base.root, overlay))
    except VerificationFailure as exc:
        raise RuntimeError(
            f"self-test FAILED: rejected {label}:\n{exc}"
        ) from exc
    print(f"self-test PASS: accepted {label}")


def verify_recursive_closure_self_test(base: View) -> None:
    errors: list[str] = []
    parsed = discover_local_manifests(base, base.toml("Cargo.toml"), errors)
    if errors:
        raise RuntimeError(
            "self-test FAILED: baseline recursive manifest discovery:\n"
            + "\n".join(errors)
        )
    packages = {
        rel
        for rel, manifest in parsed.items()
        if isinstance(manifest.get("package"), dict)
        and isinstance(manifest["package"].get("name"), str)
    }
    required_implicit = {
        PurePosixPath("vendor/jitterentropy-rs/Cargo.toml"),
        PurePosixPath("vendor/sunset/Cargo.toml"),
        PurePosixPath("vendor/sunset/sshwire-derive/Cargo.toml"),
        PurePosixPath("vendor/wasmi-softfloat/crates/collections/Cargo.toml"),
        PurePosixPath("vendor/wasmi-softfloat/crates/core/Cargo.toml"),
        PurePosixPath("vendor/wasmi-softfloat/crates/ir/Cargo.toml"),
        PurePosixPath("vendor/wasmi-softfloat/crates/wasmi/Cargo.toml"),
    }
    if len(parsed) != 64 or len(packages) != 63 or not required_implicit <= packages:
        missing = sorted(required_implicit - packages, key=str)
        raise RuntimeError(
            "self-test FAILED: recursive manifest closure drift: "
            f"manifests={len(parsed)}, packages={len(packages)}, missing={missing}"
        )
    print(
        "self-test PASS: recursive repo-local closure covers "
        "64 manifests and 63 packages"
    )

    scope_errors: list[str] = []
    manifest_cache: dict[PurePosixPath, Mapping[str, Any] | None] = {
        PurePosixPath("Cargo.toml"): base.toml("Cargo.toml")
    }
    scope_cache: dict[
        tuple[PurePosixPath, PurePosixPath | None],
        PurePosixPath | None,
    ] = {}
    expected_scopes = {
        PurePosixPath("component-runtime/Cargo.toml"): PurePosixPath("Cargo.toml"),
        PurePosixPath("vendor/jitterentropy-rs/Cargo.toml"): PurePosixPath(
            "Cargo.toml"
        ),
        PurePosixPath("vendor/sunset/Cargo.toml"): PurePosixPath(
            "vendor/sunset/Cargo.toml"
        ),
        PurePosixPath("vendor/sunset/sshwire-derive/Cargo.toml"): PurePosixPath(
            "vendor/sunset/Cargo.toml"
        ),
        PurePosixPath("vendor/wasmi-softfloat/crates/collections/Cargo.toml"): None,
        PurePosixPath("vendor/wasmi-softfloat/crates/core/Cargo.toml"): None,
        PurePosixPath("vendor/wasmi-softfloat/crates/ir/Cargo.toml"): None,
        PurePosixPath("vendor/wasmi-softfloat/crates/wasmi/Cargo.toml"): None,
    }
    actual_scopes = {
        rel: resolve_workspace_scope(
            base,
            rel,
            manifest_cache,
            scope_cache,
            scope_errors,
            PurePosixPath("Cargo.toml"),
        )
        for rel in expected_scopes
    }
    if scope_errors or actual_scopes != expected_scopes:
        raise RuntimeError(
            "self-test FAILED: baseline workspace scope resolution drift: "
            f"errors={scope_errors!r}, actual={actual_scopes!r}"
        )
    print("self-test PASS: root, nested, and excluded workspace scopes are exact")

    dotted_root = replace_once(
        base.read("Cargo.toml"),
        b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
        b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", "./orphan"]',
        "dotted workspace exclude",
    )
    dotted_view = View(
        base.root,
        {
            "Cargo.toml": dotted_root,
            "orphan/Cargo.toml": b'''[package]
name = "vibeos-dotted-exclude-selftest"
version = "0.0.0"
edition = "2021"
''',
        },
    )
    dotted_errors: list[str] = []
    dotted_scope = resolve_workspace_scope(
        dotted_view,
        PurePosixPath("orphan/Cargo.toml"),
        {PurePosixPath("Cargo.toml"): dotted_view.toml("Cargo.toml")},
        {},
        dotted_errors,
        PurePosixPath("Cargo.toml"),
    )
    if dotted_errors or dotted_scope is not None:
        raise RuntimeError(
            "self-test FAILED: dotted workspace.exclude normalization drift: "
            f"errors={dotted_errors!r}, scope={dotted_scope!r}"
        )
    print("self-test PASS: dotted workspace.exclude normalization is exact")


def verify_workspace_inheritance_self_test(base: View) -> None:
    def expanded(defaults: bool, member_defaults: bool | None) -> Mapping[str, Any]:
        member: dict[str, Any] = {
            "workspace": True,
            "optional": True,
            "features": ["member-marker"],
        }
        if member_defaults is not None:
            member["default-features"] = member_defaults
        errors: list[str] = []
        manifest = {
            "package": {
                "name": "selftest-workspace-member",
                "edition": "2021",
            },
            "dependencies": {"runtime-template": member},
        }
        templates = {
            "runtime-template": {
                "package": "vibeos-component-runtime",
                "path": "component-runtime",
                "default-features": defaults,
                "features": ["workspace-marker"],
            }
        }
        effective = expand_workspace_dependencies(
            base,
            manifest,
            PurePosixPath("selftest/member/Cargo.toml"),
            PurePosixPath("Cargo.toml"),
            templates,
            errors,
        )
        if errors:
            raise RuntimeError(
                "self-test FAILED: workspace inheritance expansion:\n"
                + "\n".join(errors)
            )
        return effective["dependencies"]["runtime-template"]

    inherited_false = expanded(False, None)
    reenabled = expanded(False, True)
    cannot_disable = expanded(True, False)
    if inherited_false != {
        "package": "vibeos-component-runtime",
        "path": "../../component-runtime",
        "features": ["workspace-marker", "member-marker"],
        "optional": True,
        "default-features": False,
    }:
        raise RuntimeError(
            "self-test FAILED: workspace false/default omission inheritance drift: "
            f"{inherited_false!r}"
        )
    if reenabled.get("default-features") is not True:
        raise RuntimeError(
            "self-test FAILED: member true did not re-enable workspace defaults"
        )
    if cannot_disable.get("default-features") is not True:
        raise RuntimeError(
            "self-test FAILED: member false disabled workspace-enabled defaults"
        )
    print("self-test PASS: workspace dependency inheritance semantics")


def self_test(base: View) -> None:
    verify_recursive_closure_self_test(base)
    verify_workspace_inheritance_self_test(base)
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
        (
            "production candidate consumer",
            "wasm-runtime/Cargo.toml",
            lambda data: replace_once(
                data,
                b'vibeos-component-format = { path = "../component-format" }\n',
                b'vibeos-component-format = { path = "../component-format" }\n'
                b'vibeos-wasm-float-candidate = { path = "../wasm-float-candidate", '
                b'default-features = false, optional = true }\n',
                "production dependency anchor",
            ),
        ),
        (
            "non-optional candidate consumer",
            "component-runtime/Cargo.toml",
            lambda data: replace_once(
                data,
                b'vibeos-wasm-float-candidate = { path = "../wasm-float-candidate", '
                b'default-features = false, optional = true }',
                b'vibeos-wasm-float-candidate = { path = "../wasm-float-candidate", '
                b'default-features = false, optional = false }',
                "component candidate optional flag",
            ),
        ),
        (
            "candidate dependency default-feature leak",
            "component-runtime/Cargo.toml",
            lambda data: replace_once(
                data,
                b'vibeos-wasm-float-candidate = { path = "../wasm-float-candidate", '
                b'default-features = false, optional = true }',
                b'vibeos-wasm-float-candidate = { path = "../wasm-float-candidate", '
                b'default-features = true, optional = true }',
                "component candidate default-features flag",
            ),
        ),
        (
            "default feature reaches the candidate",
            "component-runtime/Cargo.toml",
            lambda data: replace_once(
                data,
                b"default = []",
                b'default = ["c88-f4-acceptance"]',
                "component default feature",
            ),
        ),
        (
            "candidate feature edge leak",
            "component-runtime/Cargo.toml",
            lambda data: replace_once(
                data,
                b"c84-profile-hooks = []",
                b'c84-profile-hooks = [\n'
                b'    "dep:vibeos-wasm-float-candidate",\n'
                b'    "vibeos-wasm-float-candidate/c88-f2-acceptance",\n'
                b"]",
                "unreviewed component feature",
            ),
        ),
        (
            "admission default reaches runtime F4",
            "services/component-admission/Cargo.toml",
            lambda data: replace_once(
                data,
                b"default = []",
                b'default = ["c88-f4-acceptance"]',
                "admission default feature",
            ),
        ),
        (
            "image-adapter default reaches its F4 route",
            "services/component-image-adapter/Cargo.toml",
            lambda data: replace_once(
                data,
                b"default = []",
                b'default = ["c88-f4-float-candidate"]',
                "image-adapter default feature",
            ),
        ),
        (
            "kernel default reaches its QEMU F5 gate",
            "kernel/Cargo.toml",
            lambda data: replace_once(
                data,
                b'default = ["qemu-virt", "qemu-default-image"]',
                b'default = ["qemu-virt", "qemu-default-image", '
                b'"wasm-c88-f5-float-qemu-acceptance"]',
                "kernel default feature",
            ),
        ),
        (
            "QEMU firmware default reaches its F5 entry",
            "firmware/qemu-virt/Cargo.toml",
            lambda data: replace_once(
                data,
                b"default = []",
                b'default = ["wasm-c88-f5-float-qemu-acceptance"]',
                "QEMU firmware default feature",
            ),
        ),
        (
            "Duo firmware default reaches its F5 entry",
            "firmware/milkv-duo/Cargo.toml",
            lambda data: replace_once(
                data,
                b'default = ["milkv-ssh"]',
                b'default = ["milkv-ssh", '
                b'"wasm-c88-f5-float-duo-compile-readiness"]',
                "Duo firmware default feature",
            ),
        ),
        (
            "dependency-level F4 feature bypass",
            "services/component-admission/Cargo.toml",
            lambda data: replace_once(
                data,
                b'vibeos-component-runtime = { path = "../../component-runtime" }',
                b'vibeos-component-runtime = { path = "../../component-runtime", '
                b'features = ["c88-f4-acceptance"] }',
                "admission runtime dependency",
            ),
        ),
        (
            "QEMU route swapped to the Duo gate",
            "firmware/qemu-virt/Cargo.toml",
            lambda data: replace_once(
                data,
                b'"vibeos-kernel/wasm-c88-f5-float-qemu-acceptance",',
                b'"vibeos-kernel/wasm-c88-f5-float-duo-compile-readiness",',
                "QEMU Float route",
            ),
        ),
        (
            "Duo route gains a QEMU edge",
            "firmware/milkv-duo/Cargo.toml",
            lambda data: replace_once(
                data,
                b'    "vibeos-kernel/wasm-c88-f5-float-duo-compile-readiness",\n',
                b'    "vibeos-kernel/wasm-c88-f5-float-duo-compile-readiness",\n'
                b'    "vibeos-kernel/wasm-c88-f5-float-qemu-acceptance",\n',
                "Duo Float route",
            ),
        ),
        (
            "direct vendored-fork bypass",
            "wasm-runtime/Cargo.toml",
            lambda data: replace_once(
                data,
                b'vibeos-component-format = { path = "../component-format" }\n',
                b'vibeos-component-format = { path = "../component-format" }\n'
                b'wasmi-softfloat-bypass = { package = "vibeos-wasmi-softfloat", '
                b'path = "../vendor/wasmi-softfloat/crates/wasmi", '
                b'default-features = false, optional = true }\n',
                "production dependency anchor",
            ),
        ),
        (
            "candidate normal fork gains an extra version source",
            "wasm-float-candidate/Cargo.toml",
            lambda data: replace_once(
                data,
                b'path = "../vendor/wasmi-softfloat/crates/wasmi", '
                b"default-features = false,",
                b'path = "../vendor/wasmi-softfloat/crates/wasmi", '
                b'version = "=1.1.0-vibeos-f2.1", default-features = false,',
                "candidate fork version insertion",
            ),
        ),
        (
            "candidate dev fork gains a SIMD feature",
            "wasm-float-candidate/Cargo.toml",
            lambda data: replace_once(
                data,
                b'path = "../vendor/wasmi-softfloat/crates/core", '
                b"default-features = false }",
                b'path = "../vendor/wasmi-softfloat/crates/core", '
                b'default-features = false, features = ["simd"] }',
                "candidate dev fork SIMD insertion",
            ),
        ),
    ]
    expected_by_label = {
        "fork source drift": "vendored fork content or manifest drift",
        "Profile 1 checksum drift": "Profile 1 wasmi checksum drift",
        "workspace patch injection": "workspace [patch.crates-io] is forbidden",
        "code-5 activation": "code-5 validation contract must remain runtime_ready=false",
        "fork package identity drift": "core fork package name drift",
        "production candidate consumer": "acceptance candidate consumed outside the reviewed F4/F5 closure",
        "non-optional candidate consumer": "candidate dependency must stay optional",
        "candidate dependency default-feature leak": "candidate dependency defaults must stay disabled",
        "default feature reaches the candidate": "workspace package default reaches the F2 candidate",
        "candidate feature edge leak": "candidate feature edge leaked outside the reviewed feature",
        "admission default reaches runtime F4": "workspace package default reaches the F2 candidate",
        "image-adapter default reaches its F4 route": "workspace package default reaches the F2 candidate",
        "kernel default reaches its QEMU F5 gate": "workspace package default reaches the F2 candidate",
        "QEMU firmware default reaches its F5 entry": "workspace package default reaches the F2 candidate",
        "Duo firmware default reaches its F5 entry": "workspace package default reaches the F2 candidate",
        "dependency-level F4 feature bypass": "dependency-level activation bypasses the Float feature route",
        "QEMU route swapped to the Duo gate": "exact Float feature route drift",
        "Duo route gains a QEMU edge": "exact Float feature route drift",
        "direct vendored-fork bypass": "vendored fork path edge outside its frozen closure",
        "candidate normal fork gains an extra version source": "vendored fork dependency spec drift",
        "candidate dev fork gains a SIMD feature": "vendored fork dependency spec drift",
    }
    for label, path, mutate in mutations:
        expect_rejected(
            base,
            label,
            {path: mutate(base.read(path))},
            expected_by_label[label],
        )

    wrapper_manifest = b'''[package]
name = "vibeos-float-selftest-wrapper"
version = "0.0.0"
edition = "2021"

[features]
default = []

[dependencies]
vibeos-wasm-float-candidate = { path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
'''
    duplicate_manifest = b'''[package]
name = "vibeos-component-runtime"
version = "0.0.0"
edition = "2021"
'''
    root = base.read("Cargo.toml")
    runtime = base.read("wasm-runtime/Cargo.toml")
    component_runtime = base.read("component-runtime/Cargo.toml")
    random_manifest = base.read("random/Cargo.toml")
    jitter_manifest = base.read("vendor/jitterentropy-rs/Cargo.toml")
    sunset_manifest = base.read("vendor/sunset/Cargo.toml")
    host_manifest = base.read("services/component-host/Cargo.toml")
    candidates_manifest = base.read("wasm-candidates/Cargo.toml")

    def nested_priority_overlay(exclude_wrapper: bool) -> dict[str, bytes]:
        outer_workspace = b'''[workspace]
members = ["source"]
'''
        if exclude_wrapper:
            outer_workspace += b'exclude = ["C/wrapper"]\n'
        outer_workspace += b'''
[workspace.dependencies]
scope-nested-priority-route = { package = "vibeos-component-format", path = "../../component-format", default-features = false }
'''
        return {
            "Cargo.toml": replace_once(
                root,
                b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
                b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", '
                b'"selftest-fixtures/scope-nested-priority-A"]',
                "nested-priority fixture exclude",
            ),
            "random/Cargo.toml": replace_once(
                random_manifest,
                b"[dependencies]\n",
                b"[dependencies]\n"
                b'scope-nested-priority-source = { package = "vibeos-scope-nested-priority-source", '
                b'path = "../selftest-fixtures/scope-nested-priority-A/source" }\n',
                "nested-priority source insertion",
            ),
            "selftest-fixtures/scope-nested-priority-A/Cargo.toml": outer_workspace,
            "selftest-fixtures/scope-nested-priority-A/source/Cargo.toml": b'''[package]
name = "vibeos-scope-nested-priority-source"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-nested-priority-wrapper = { package = "vibeos-scope-nested-priority-wrapper", path = "../C/wrapper" }
''',
            "selftest-fixtures/scope-nested-priority-A/C/Cargo.toml": b'''[workspace]
members = ["wrapper"]

[workspace.dependencies]
scope-nested-priority-route = { package = "vibeos-wasm-float-candidate", path = "../../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
            "selftest-fixtures/scope-nested-priority-A/C/wrapper/Cargo.toml": b'''[package]
name = "vibeos-scope-nested-priority-wrapper"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-nested-priority-route = { workspace = true }
''',
        }

    overlay_mutations: list[
        tuple[str, Mapping[str, bytes], str | Iterable[str]]
    ] = [
        (
            "nearest nested workspace overrides a benign source workspace",
            nested_priority_overlay(False),
            (
                "selftest-fixtures/scope-nested-priority-A/C/Cargo.toml:workspace.dependencies:scope-nested-priority-route",
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-nested-priority-A/C/wrapper/Cargo.toml:dependencies:scope-nested-priority-route",
            ),
        ),
        (
            "nearest nested workspace wins when its outer ancestor excludes the target",
            nested_priority_overlay(True),
            (
                "selftest-fixtures/scope-nested-priority-A/C/Cargo.toml:workspace.dependencies:scope-nested-priority-route",
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-nested-priority-A/C/wrapper/Cargo.toml:dependencies:scope-nested-priority-route",
            ),
        ),
        (
            "implicit jitter member candidate consumer",
            {
                "vendor/jitterentropy-rs/Cargo.toml": replace_once(
                    jitter_manifest,
                    b"[dev-dependencies]\n",
                    b'jitter-float-bypass = { package = "vibeos-wasm-float-candidate", '
                    b'path = "../../wasm-float-candidate", default-features = false, '
                    b'features = ["c88-f2-acceptance"] }\n\n[dev-dependencies]\n',
                    "jitter dependency insertion",
                )
            },
            (
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "vendor/jitterentropy-rs/Cargo.toml:dependencies:jitter-float-bypass",
            ),
        ),
        (
            "implicit jitter member vendored-fork bypass",
            {
                "vendor/jitterentropy-rs/Cargo.toml": replace_once(
                    jitter_manifest,
                    b"[dev-dependencies]\n",
                    b'jitter-wasmi-bypass = { package = "vibeos-wasmi-softfloat", '
                    b'path = "../wasmi-softfloat/crates/wasmi", '
                    b'default-features = false, optional = true }\n\n'
                    b"[dev-dependencies]\n",
                    "jitter fork insertion",
                )
            },
            (
                "vendored fork path edge outside its frozen closure",
                "vendor/jitterentropy-rs/Cargo.toml:dependencies:jitter-wasmi-bypass",
            ),
        ),
        (
            "renamed vendored fork through a git dependency",
            {
                "services/component-host/Cargo.toml": replace_once(
                    host_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'fork-git-bypass = { package = "vibeos-wasmi-softfloat", '
                    b'git = "https://invalid.example/wasmi-softfloat", '
                    b'rev = "0123456789abcdef0123456789abcdef01234567", '
                    b'default-features = false, optional = true }\n',
                    "git fork bypass insertion",
                )
            },
            (
                "vendored fork path edge outside its frozen closure",
                "services/component-host/Cargo.toml:dependencies:fork-git-bypass",
            ),
        ),
        (
            "renamed vendored fork through a registry dependency",
            {
                "services/component-host/Cargo.toml": replace_once(
                    host_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'fork-registry-bypass = { package = "vibeos-wasmi-softfloat", '
                    b'version = "=1.1.0-vibeos-f2.1", registry = "crates-io", '
                    b'default-features = false, optional = true }\n',
                    "registry fork bypass insertion",
                )
            },
            (
                "vendored fork path edge outside its frozen closure",
                "services/component-host/Cargo.toml:dependencies:fork-registry-bypass",
            ),
        ),
        (
            "edition-2024 inherited default-feature contradiction",
            {
                "vendor/sunset/Cargo.toml": replace_once(
                    replace_once(
                        sunset_manifest,
                        b'edition = "2024"',
                        b"edition.workspace = true",
                        "Sunset inherited package edition",
                    ),
                    b"sunset-sshwire-derive = { workspace = true }",
                    b"sunset-sshwire-derive = { workspace = true, "
                    b"default-features = false }",
                    "Sunset inherited default-features",
                )
                + b'''\n[workspace.package]
edition = "2024"
'''
            },
            "edition 2024 workspace dependency cannot disable defaults enabled by its template",
        ),
        (
            "malformed package edition workspace selector",
            {
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b'edition = "2021"',
                    b"edition = { workspace = false }",
                    "random malformed inherited package edition",
                )
            },
            "package edition workspace selector must be exactly true: random/Cargo.toml",
        ),
        (
            "explicit package.workspace nested-scope candidate attack",
            {
                "Cargo.toml": replace_once(
                    root,
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", '
                    b'"selftest-fixtures/scope-explicit"]',
                    "explicit nested workspace exclude",
                )
                + b'''\n[workspace.dependencies]
scope-confused-dependency = { package = "vibeos-component-format", path = "component-format", default-features = false }
''',
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'scope-explicit-wrapper = { package = "vibeos-scope-explicit-wrapper", '
                    b'path = "../selftest-fixtures/scope-explicit/wrapper" }\n',
                    "explicit scope wrapper insertion",
                ),
                "selftest-fixtures/scope-explicit/Cargo.toml": b'''[workspace]
members = ["wrapper"]

[workspace.dependencies]
scope-confused-dependency = { package = "vibeos-wasm-float-candidate", path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
                "selftest-fixtures/scope-explicit/wrapper/Cargo.toml": b'''[package]
name = "vibeos-scope-explicit-wrapper"
version = "0.0.0"
edition = "2021"
workspace = ".."

[dependencies]
scope-confused-dependency = { workspace = true }
''',
            },
            (
                "explicit [package].workspace is forbidden in the audited closure",
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-explicit/wrapper/Cargo.toml:dependencies:scope-confused-dependency",
            ),
        ),
        (
            "implicit ancestor nested-workspace candidate attack",
            {
                "Cargo.toml": replace_once(
                    root,
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", '
                    b'"selftest-fixtures/scope-implicit"]',
                    "implicit nested workspace exclude",
                )
                + b'''\n[workspace.dependencies]
scope-confused-dependency = { package = "vibeos-component-format", path = "component-format", default-features = false }
''',
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'scope-implicit-wrapper = { package = "vibeos-scope-implicit-wrapper", '
                    b'path = "../selftest-fixtures/scope-implicit/wrapper" }\n',
                    "implicit scope wrapper insertion",
                ),
                "selftest-fixtures/scope-implicit/Cargo.toml": b'''[workspace]
members = ["wrapper"]

[workspace.dependencies]
scope-confused-dependency = { package = "vibeos-wasm-float-candidate", path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
                "selftest-fixtures/scope-implicit/wrapper/Cargo.toml": b'''[package]
name = "vibeos-scope-implicit-wrapper"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-confused-dependency = { workspace = true }
''',
            },
            (
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-implicit/wrapper/Cargo.toml:dependencies:scope-confused-dependency",
            ),
        ),
        (
            "outer workspace claim overrides nested benign scope",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
scope-shadow-route = { package = "vibeos-wasm-float-candidate", path = "wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'scope-shadow-wrapper = { package = "vibeos-scope-shadow-wrapper", '
                    b'path = "../selftest-fixtures/scope-outer/nested/wrapper" }\n',
                    "outer scope-shadow wrapper insertion",
                ),
                "selftest-fixtures/scope-outer/nested/Cargo.toml": b'''[workspace]
members = ["wrapper"]

[workspace.dependencies]
scope-shadow-route = { package = "vibeos-component-format", path = "../../../component-format", default-features = false }
''',
                "selftest-fixtures/scope-outer/nested/wrapper/Cargo.toml": b'''[package]
name = "vibeos-scope-shadow-wrapper"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-shadow-route = { workspace = true }
''',
            },
            (
                "Cargo.toml:workspace.dependencies:scope-shadow-route",
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-outer/nested/wrapper/Cargo.toml:dependencies:scope-shadow-route",
            ),
        ),
        (
            "invocation root claim persists across two path edges",
            {
                "Cargo.toml": replace_once(
                    root,
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", '
                    b'"selftest-fixtures/scope-two-hop/nested/source"]',
                    "two-hop nested source exclude",
                )
                + b'''\n[workspace.dependencies]
scope-two-hop-route = { package = "vibeos-wasm-float-candidate", path = "wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'scope-two-hop-source = { package = "vibeos-scope-two-hop-source", '
                    b'path = "../selftest-fixtures/scope-two-hop/nested/source" }\n',
                    "two-hop source insertion",
                ),
                "selftest-fixtures/scope-two-hop/nested/Cargo.toml": b'''[workspace]
members = ["source", "wrapper"]

[workspace.dependencies]
scope-two-hop-route = { package = "vibeos-component-format", path = "../../../component-format", default-features = false }
''',
                "selftest-fixtures/scope-two-hop/nested/source/Cargo.toml": b'''[package]
name = "vibeos-scope-two-hop-source"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-two-hop-bridge = { package = "vibeos-scope-two-hop-bridge", path = "../bridge" }
''',
                "selftest-fixtures/scope-two-hop/nested/bridge/Cargo.toml": b'''[package]
name = "vibeos-scope-two-hop-bridge"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-two-hop-wrapper = { package = "vibeos-scope-two-hop-wrapper", path = "../wrapper" }
''',
                "selftest-fixtures/scope-two-hop/nested/wrapper/Cargo.toml": b'''[package]
name = "vibeos-scope-two-hop-wrapper"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-two-hop-route = { workspace = true }
''',
            },
            (
                "Cargo.toml:workspace.dependencies:scope-two-hop-route",
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-two-hop/nested/wrapper/Cargo.toml:dependencies:scope-two-hop-route",
            ),
        ),
        (
            "excluded nearest workspace falls back outward across two path edges",
            {
                "Cargo.toml": replace_once(
                    root,
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
                    b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", '
                    b'"selftest-fixtures/scope-nearest-outer"]',
                    "nearest-fallback fixture exclude",
                ),
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'scope-nearest-source = { package = "vibeos-scope-nearest-source", '
                    b'path = "../selftest-fixtures/scope-nearest-outer/inner/source" }\n',
                    "nearest-fallback source insertion",
                ),
                "selftest-fixtures/scope-nearest-outer/Cargo.toml": b'''[workspace]
members = ["inner/bridge"]

[workspace.dependencies]
scope-nearest-route = { package = "vibeos-wasm-float-candidate", path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
                "selftest-fixtures/scope-nearest-outer/inner/Cargo.toml": b'''[workspace]
members = ["source", "wrapper"]
exclude = ["bridge", "wrapper"]

[workspace.dependencies]
scope-nearest-route = { package = "vibeos-component-format", path = "../../../component-format", default-features = false }
''',
                "selftest-fixtures/scope-nearest-outer/inner/source/Cargo.toml": b'''[package]
name = "vibeos-scope-nearest-source"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-nearest-bridge = { package = "vibeos-scope-nearest-bridge", path = "../bridge" }
''',
                "selftest-fixtures/scope-nearest-outer/inner/bridge/Cargo.toml": b'''[package]
name = "vibeos-scope-nearest-bridge"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-nearest-wrapper = { package = "vibeos-scope-nearest-wrapper", path = "../wrapper" }
''',
                "selftest-fixtures/scope-nearest-outer/inner/wrapper/Cargo.toml": b'''[package]
name = "vibeos-scope-nearest-wrapper"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-nearest-route = { workspace = true }
''',
            },
            (
                "selftest-fixtures/scope-nearest-outer/Cargo.toml:workspace.dependencies:scope-nearest-route",
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/scope-nearest-outer/inner/wrapper/Cargo.toml:dependencies:scope-nearest-route",
            ),
        ),
        (
            "outer workspace claims a nested package workspace root",
            {
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'workspace-root-collision = { package = "vibeos-workspace-root-collision", '
                    b'path = "../selftest-fixtures/workspace-root-collision" }\n',
                    "nested package workspace insertion",
                ),
                "selftest-fixtures/workspace-root-collision/Cargo.toml": b'''[package]
name = "vibeos-workspace-root-collision"
version = "0.0.0"
edition = "2021"

[workspace]
members = []
''',
            },
            "invocation workspace cannot claim a package that is also a workspace root",
        ),
        (
            "renamed workspace candidate inherited by production",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
float-workspace-candidate = { package = "vibeos-wasm-float-candidate", path = "wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b"float-workspace-candidate = { workspace = true }\n",
                    "runtime workspace dependency insertion",
                ),
            },
            (
                "Cargo.toml:workspace.dependencies:float-workspace-candidate",
                "wasm-runtime/Cargo.toml:dependencies:float-workspace-candidate",
                "workspace package default reaches the F2 candidate",
            ),
        ),
        (
            "reviewed candidate consumer uses workspace inheritance",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
vibeos-wasm-float-candidate = { path = "wasm-float-candidate", default-features = false }
''',
                "component-runtime/Cargo.toml": replace_once(
                    component_runtime,
                    b'vibeos-wasm-float-candidate = { path = "../wasm-float-candidate", '
                    b"default-features = false, optional = true }",
                    b"vibeos-wasm-float-candidate = { workspace = true, optional = true }",
                    "reviewed consumer workspace inheritance",
                ),
            },
            "reviewed direct candidate dependency cannot use workspace inheritance",
        ),
        (
            "root workspace template package-target mismatch",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
runtime-template-mismatch = { package = "vibeos-random", path = "component-runtime", default-features = false }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b"runtime-template-mismatch = { workspace = true }\n",
                    "template mismatch consumer",
                ),
            },
            "workspace dependency template package/target identity mismatch",
        ),
        (
            "root workspace path template recursively inherits",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
runtime-template-loop = { package = "vibeos-component-runtime", path = "component-runtime", workspace = false }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b"runtime-template-loop = { workspace = true }\n",
                    "recursive template consumer",
                ),
            },
            "workspace dependency template cannot inherit another template",
        ),
        (
            "root workspace path template has conflicting source",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
runtime-source-conflict = { package = "vibeos-component-runtime", path = "component-runtime", git = "https://invalid.example/runtime" }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b"runtime-source-conflict = { workspace = true }\n",
                    "source-conflict template consumer",
                ),
            },
            "workspace path dependency template has conflicting source keys",
        ),
        (
            "root workspace path template sets optional",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
runtime-template-optional = { package = "vibeos-component-runtime", path = "component-runtime", optional = true }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b"runtime-template-optional = { workspace = true }\n",
                    "optional template consumer",
                ),
            },
            "workspace dependency template cannot set optional",
        ),
        (
            "root workspace template vendored-fork bypass",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
fork-template-bypass = { package = "vibeos-wasmi-softfloat", path = "vendor/wasmi-softfloat/crates/wasmi", default-features = false }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b"fork-template-bypass = { workspace = true }\n",
                    "fork template consumer",
                ),
            },
            "vendored fork consumed outside its frozen candidate entry",
        ),
        (
            "unlisted path wrapper default reaches candidate",
            {
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'float-wrapper = { package = "vibeos-float-selftest-wrapper", '
                    b'path = "../selftest-fixtures/float-wrapper" }\n',
                    "random wrapper insertion",
                ),
                "selftest-fixtures/float-wrapper/Cargo.toml": wrapper_manifest,
            },
            (
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "workspace package default reaches the F2 candidate",
                "selftest-fixtures/float-wrapper/Cargo.toml",
            ),
        ),
        (
            "unpinned cross-package feature forwarder",
            {
                "services/component-host/Cargo.toml": replace_once(
                    host_manifest,
                    b"[dependencies]\n",
                    b'''[features]
default = []
float-forwarder = ["vibeos-component-runtime/c88-f4-acceptance"]

[dependencies]
''',
                    "host feature insertion",
                )
            },
            (
                "unapproved candidate-reachable feature",
                "services/component-host/Cargo.toml:float-forwarder",
            ),
        ),
        (
            "weak alias dependency feature forwarder",
            {
                "wasm-candidates/Cargo.toml": replace_once(
                    candidates_manifest,
                    b'c0-static-probes = ["dep:vibeos-component-runtime"]\n',
                    b'c0-static-probes = ["dep:vibeos-component-runtime"]\n'
                    b'weak-float-forwarder = ["dep:vibeos-component-runtime", '
                    b'"vibeos-component-runtime?/c88-f4-acceptance"]\n',
                    "weak dependency feature insertion",
                )
            },
            (
                "unapproved candidate-reachable feature",
                "wasm-candidates/Cargo.toml:weak-float-forwarder",
            ),
        ),
        (
            "target dependency direct-candidate bypass",
            {
                "services/component-host/Cargo.toml": host_manifest
                + b'''\n[target.'cfg(any())'.dependencies]
float-target-bypass = { package = "vibeos-wasm-float-candidate", path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
'''
            },
            (
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "dependency-level activation bypasses the Float feature route",
                "workspace package default reaches the F2 candidate",
                "services/component-host/Cargo.toml:float-target-bypass",
            ),
        ),
        (
            "dev dependency direct-candidate bypass",
            {
                "services/component-host/Cargo.toml": replace_once(
                    host_manifest,
                    b"[dev-dependencies]\n",
                    b"[dev-dependencies]\n"
                    b'float-dev-bypass = { package = "vibeos-wasm-float-candidate", '
                    b'path = "../../wasm-float-candidate", default-features = false, '
                    b'features = ["c88-f2-acceptance"] }\n',
                    "host dev dependency insertion",
                )
            },
            (
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "dependency-level activation bypasses the Float feature route",
                "workspace package default reaches the F2 candidate",
                "services/component-host/Cargo.toml:float-dev-bypass",
            ),
        ),
        (
            "build dependency direct-candidate bypass",
            {
                "services/component-host/Cargo.toml": host_manifest
                + b'''\n[build-dependencies]
float-build-bypass = { package = "vibeos-wasm-float-candidate", path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
'''
            },
            (
                "acceptance candidate consumed outside the reviewed F4/F5 closure",
                "dependency-level activation bypasses the Float feature route",
                "workspace package default reaches the F2 candidate",
                "services/component-host/Cargo.toml:float-build-bypass",
            ),
        ),
        (
            "workspace additive feature injection",
            {
                "Cargo.toml": root
                + b'''\n[workspace.dependencies]
runtime-workspace-route = { package = "vibeos-component-runtime", path = "component-runtime", default-features = false, features = ["c88-f4-acceptance"] }
''',
                "wasm-runtime/Cargo.toml": replace_once(
                    runtime,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'runtime-workspace-route = { workspace = true, '
                    b'features = ["c84-profile-hooks"] }\n',
                    "runtime additive workspace dependency insertion",
                ),
            },
            (
                "dependency-level activation bypasses the Float feature route",
                "wasm-runtime/Cargo.toml:runtime-workspace-route",
            ),
        ),
        (
            "non-prefix parent path normalization bypass",
            {
                "vendor/jitterentropy-rs/Cargo.toml": replace_once(
                    jitter_manifest,
                    b"[dev-dependencies]\n",
                    b'float-path-bypass = { package = "vibeos-wasm-float-candidate", '
                    b'path = "../../shadow/../wasm-float-candidate", '
                    b'default-features = false, optional = true }\n\n'
                    b"[dev-dependencies]\n",
                    "non-prefix parent path insertion",
                )
            },
            "repo-local path dependency escapes or is malformed",
        ),
        (
            "duplicate repo-local package identity",
            {
                "random/Cargo.toml": replace_once(
                    random_manifest,
                    b"[dependencies]\n",
                    b"[dependencies]\n"
                    b'duplicate-runtime = { package = "vibeos-component-runtime", '
                    b'path = "../selftest-fixtures/duplicate-runtime" }\n',
                    "duplicate package insertion",
                ),
                "selftest-fixtures/duplicate-runtime/Cargo.toml": duplicate_manifest,
            },
            "duplicate repo-local package identity 'vibeos-component-runtime'",
        ),
        (
            "same alias resolves to distinct target dependencies",
            {
                "services/component-host/Cargo.toml": host_manifest
                + b'''\n[target.'cfg(any())'.dependencies]
vibeos-component-runtime = { package = "vibeos-random", path = "../../random" }
'''
            },
            "repo-local dependency alias resolves to multiple targets",
        ),
    ]
    for label, overlay, expected in overlay_mutations:
        expect_rejected(base, label, overlay, expected)

    def nested_self_root_overlay(exclude_target: bool) -> dict[str, bytes]:
        nested_workspace = b'''[workspace]
members = ["source"]
'''
        if exclude_target:
            nested_workspace += b'exclude = ["B"]\n'
        nested_workspace += b'''
[workspace.dependencies]
scope-self-root-route = { package = "vibeos-wasm-float-candidate", path = "../../wasm-float-candidate", default-features = false, features = ["c88-f2-acceptance"] }
'''
        return {
            "Cargo.toml": replace_once(
                root,
                b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat"]',
                b'exclude = ["vendor/sunset", "vendor/wasmi-softfloat", '
                b'"selftest-fixtures/scope-self-root-A"]',
                "nested self-root fixture exclude",
            ),
            "random/Cargo.toml": replace_once(
                random_manifest,
                b"[dependencies]\n",
                b"[dependencies]\n"
                b'scope-self-root-source = { package = "vibeos-scope-self-root-source", '
                b'path = "../selftest-fixtures/scope-self-root-A/source" }\n',
                "nested self-root source insertion",
            ),
            "selftest-fixtures/scope-self-root-A/Cargo.toml": nested_workspace,
            "selftest-fixtures/scope-self-root-A/source/Cargo.toml": b'''[package]
name = "vibeos-scope-self-root-source"
version = "0.0.0"
edition = "2021"

[dependencies]
scope-self-root-target = { package = "vibeos-scope-self-root-target", path = "../B" }
''',
            "selftest-fixtures/scope-self-root-A/B/Cargo.toml": b'''[package]
name = "vibeos-scope-self-root-target"
version = "0.0.0"
edition = "2021"

[workspace]
members = []

[workspace.dependencies]
scope-self-root-route = { package = "vibeos-component-format", path = "../../../component-format", default-features = false }

[dependencies]
scope-self-root-route = { workspace = true }
''',
        }

    expect_accepted(
        base,
        "excluded invocation root permits target self-workspace as nearest",
        nested_self_root_overlay(False),
    )
    expect_accepted(
        base,
        "target self-workspace remains exact when an outer ancestor excludes it",
        nested_self_root_overlay(True),
    )

    expect_accepted(
        base,
        "unused workspace path template remains outside the closure",
        {
            "Cargo.toml": root
            + b'''\n[workspace.dependencies]
float-unused-wrapper = { package = "vibeos-float-selftest-wrapper", path = "selftest-fixtures/float-wrapper" }
''',
            "selftest-fixtures/float-wrapper/Cargo.toml": wrapper_manifest,
        },
    )

    expect_accepted(
        base,
        "package edition inherits from its active workspace",
        {
            "Cargo.toml": root
            + b'''\n[workspace.package]
edition = "2021"
''',
            "random/Cargo.toml": replace_once(
                random_manifest,
                b'edition = "2021"',
                b"edition.workspace = true",
                "random inherited package edition",
            ),
        },
    )

    label = "unbound Cargo build script injection"
    build_script = "vendor/wasmi-softfloat/crates/core/build.rs"
    expect_rejected(
        base,
        label,
        {
            build_script: (
                b'fn main() { println!("cargo:rustc-cfg=f2_supply_chain_bypass"); }\n'
            )
        },
        "vendored tree file allowlist drift",
    )


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
