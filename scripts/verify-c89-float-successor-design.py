#!/usr/bin/env python3
"""Verify the C8.9-S1 independent Float successor design allocation.

This checker preserves the published S1 design checkpoint. It proves from the
S1 Git publication that code 5 was inert and code 6 had not yet been
materialized at that node. Later S2 source is verified by its own contract.
This checker consumes no physical input and runs no emulator.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import Any, NoReturn


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT_PATH = (
    ROOT
    / "acceptance/wasm-float-target/artifacts/"
    "c89-float-successor-design-v1-contract.json"
)
EXPECTED_CONTRACT_BYTES = 8_766
EXPECTED_CONTRACT_SHA256 = (
    "8a48c52201f60d05274abadb92d5249761f7852e42209a1d6e80ce94b86a5380"
)
MAX_CONTRACT_BYTES = 64 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
S1_PUBLICATION_COMMIT = "f2976a0ae0a88ea2e834c4eedb6f7221bdc6b2e3"
S1_PUBLICATION_TREE = "928ae4c343f22dd59448eed64511474f808a5e61"

ROOT_KEYS = {
    "allocation_authority",
    "authority",
    "code5_boundary",
    "contract_verifier",
    "engine_selection",
    "evidence_policy",
    "hardware_policy",
    "identity",
    "implementation_plan",
    "predecessor",
    "roadmap",
    "schema",
    "semantics",
    "status",
    "target_policy",
    "version",
}

EXPECTED_PATHS: list[tuple[tuple[str | int, ...], Any]] = [
    (("schema",), "vibeos.c89.float-successor-design-v1.contract"),
    (("version",), 1),
    (("status",), "c89-s1-design-frozen-not-implemented-not-qualified"),
    (("allocation_authority", "basis_commit"), "33a694d4118ae33c37116b964a99056ef263b345"),
    (("allocation_authority", "basis_tree"), "a3e79f81a76157e74b16fca58e1ba9f98058860f"),
    (("allocation_authority", "source"), "explicit-user-authorization"),
    (("allocation_authority", "user_selected_physical_duo_gate"), False),
    (("allocation_authority", "user_selected_profile5_promotion"), False),
    (("roadmap", "allocated_node"), "C8.9"),
    (("roadmap", "design_node"), "C8.9-S1"),
    (("roadmap", "implementation_node"), "C8.9-S2"),
    (("roadmap", "qualification_node"), "C8.9-S3"),
    (("roadmap", "current_position"), "c89-s1-design-frozen-pre-implementation"),
    (("roadmap", "successor_state"), "allocated-design-frozen"),
    (("roadmap", "unrelated_c88_widenings_complete"), False),
    (("identity", "name"), "PROFILE_3_SYNC_FLOAT_EXECUTABLE"),
    (("identity", "artifact_profile_code"), 6),
    (("identity", "artifact_abi"), 6),
    (("identity", "runtime_abi"), 6),
    (("identity", "component_profile"), 3),
    (("identity", "core_profile"), 3),
    (("identity", "execution_stage"), "executable"),
    (("identity", "core_wasm_revision"), "webassembly-core-2.0-scalar-f32-f64-deterministic-software-float-v1-c89-exec-v1"),
    (("identity", "component_model_revision"), "wasmparser-component-model-0.255.0-c89-sync-float-exec-v1"),
    (("identity", "canonical_abi_revision"), "component-model-0.255.0-sync-float-values-deterministic-software-float-v1-c89-exec-v1"),
    (("identity", "wasm_tools_revision"), "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380"),
    (("identity", "wasi_revision"), "wasi-not-selected-c89-sync-float"),
    (("identity", "canonical_features"), ["utf8", "sync-lift-lower", "resources", "float-values"]),
    (("identity", "wit_world", "identity"), "vibe:float/runtime@1.0.0"),
    (("identity", "wit_world", "imports"), []),
    (("identity", "wit_world", "exports"), ["run(mode: u32, left: f32, right: f64) -> f64"]),
    (("engine_selection", "package"), "vibeos-wasmi-softfloat"),
    (("engine_selection", "version"), "1.1.0-vibeos-f2.1"),
    (("engine_selection", "upstream_revision"), "8273dfb09d493971b7bb12fe614d740cdc857175"),
    (("engine_selection", "feature_set"), "default-features=false,extra-checks,prefer-btree-collections;simd=false"),
    (("engine_selection", "patched_manifest_sha256"), "2d94218e4fa5eea30b8e516e055fae8f72465dbc1ef75f8b1df3495cbcd0432f"),
    (("engine_selection", "patch_delta_sha256"), "3d2aec1d7e510fc3b3edb87dcacb2d4ed34eb448356704a027841b047938ec64"),
    (("engine_selection", "fork_manifests_sha256"), "f78a26c86b00068d1bb9b8f7d499697d3a0f9b638c6d2051df249362a0006dfd"),
    (("engine_selection", "production_binding_status"), "selected-for-c89-s2-not-yet-bound"),
    (("engine_selection", "source_tree", "git_tree"), "c55904f72c70f9a0d807a13e678fec01b7c78f5a"),
    (("engine_selection", "backend", "package"), "rustc_apfloat"),
    (("engine_selection", "backend", "version"), "0.2.3+llvm-462a31f5a5ab"),
    (("engine_selection", "backend", "archive_sha256"), "486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad"),
    (("semantics", "software_float_required"), True),
    (("semantics", "numeric_nan_policy"), "deterministic-canonical-v1"),
    (("semantics", "core_transport_nan_policy"), "preserve-all-bits"),
    (("semantics", "component_boundary_nan_policy"), "canonicalize-to-fixed-positive-quiet-nan"),
    (("semantics", "canonical_nan_f32_bits"), "0x7fc00000"),
    (("semantics", "canonical_nan_f64_bits"), "0x7ff8000000000000"),
    (("semantics", "adjacent_features_enabled"), []),
    (("evidence_policy", "c88_f1_through_f5_evidence_satisfies_c89_gate"), False),
    (("evidence_policy", "code5_artifacts_eligible_for_c89_execution"), False),
    (("evidence_policy", "fresh_c89_implementation_evidence_required"), True),
    (("evidence_policy", "fresh_c89_source_bound_fixed_qemu_evidence_required"), True),
    (("evidence_policy", "predecessor_receipts_relabeling_forbidden"), True),
    (("target_policy", "baseline"), "qemu-virt-rv64-tcg-icount-v1"),
    (("target_policy", "normal_and_optimized_required"), True),
    (("target_policy", "fresh_source_commit_and_tree_required"), True),
    (("target_policy", "physical_duo_required"), False),
    (("target_policy", "qualification_status"), "not-started"),
    (("target_policy", "release_status"), "not-authorized"),
    (("hardware_policy", "duo_inputs_required"), 0),
    (("hardware_policy", "duo_inputs_permitted"), 0),
    (("hardware_policy", "duo_gate_effect"), False),
    (("hardware_policy", "fixed_qemu_is_hardware_equivalent"), False),
    (("hardware_policy", "physical_provenance"), "not-claimed"),
    (("code5_boundary", "artifact_profile_code"), 5),
    (("code5_boundary", "stage"), "validation-only"),
    (("code5_boundary", "permanent"), True),
    (("code5_boundary", "inert"), True),
    (("code5_boundary", "executable"), False),
    (("code5_boundary", "current_engine"), False),
    (("code5_boundary", "in_place_promotion_authorized"), False),
    (("authority", "design_authorized"), True),
    (("authority", "implementation_authorized"), True),
    (("authority", "test_execution_authorized_for_s2"), True),
    (("authority", "current_engine_bound"), False),
    (("authority", "admission_authorized"), False),
    (("authority", "production_authorized"), False),
    (("authority", "release_authorized"), False),
    (("authority", "in_place_promotion_authorized"), False),
    (("authority", "aot_authorized"), False),
    (("authority", "jit_authorized"), False),
    (("authority", "rwx_authorized"), False),
]

ROADMAP_STATUS = (
    "**C8.9 status (2026-08-29): C8.9-S1 design freeze complete; "
    "C8.9-S2 and C8.9-S3 incomplete.**"
)
CURRENT_POSITION = "`c89-s1-design-frozen-pre-implementation`"
FLOAT_HEADING = "## 9. C8.9 executable Float successor"
TESTING_HEADING = "## C8.9-S1 Float successor design contract"
CI_STEP_NAME = "Verify the C8.9-S1 Float successor design"
CHECK_COMMANDS = (
    "python3 -B scripts/verify-c89-float-successor-design.py --check-contract",
    "python3 -O -B scripts/verify-c89-float-successor-design.py --check-contract",
    "python3 -B scripts/verify-c89-float-successor-design.py --selftest",
    "python3 -O -B scripts/verify-c89-float-successor-design.py --selftest",
)
SOURCE_BOUNDARY_FILES = (
    "component-format/src/lib.rs",
    "component-format/src/artifact.rs",
    "component-format/src/engine.rs",
    "component-runtime/src/decode.rs",
    "wasm-runtime/src/lib.rs",
    "services/component-admission/src/lib.rs",
    "services/component-loader/src/lib.rs",
)


class VerificationError(Exception):
    pass


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_float(value: str) -> NoReturn:
    fail(f"non-integer JSON number {value!r}")


def strict_json_loads(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not ASCII: {exc}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=duplicate_reject,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (json.JSONDecodeError, VerificationError) as exc:
        fail(f"{label} is not strict JSON: {exc}")
    require(type(value) is dict, f"{label} root is not an object")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "ascii"
    )


def read_bounded(path: pathlib.Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        fail(f"cannot stat {label}: {exc}")
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode), f"opened {label} is not regular")
        require(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            f"{label} changed before open",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, f"{label} exceeds byte limit")
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
            f"{label} changed during read",
        )
        data = b"".join(chunks)
        require(len(data) == opened.st_size, f"{label} size changed during read")
        return data
    finally:
        os.close(descriptor)


def at_path(value: Any, path: tuple[str | int, ...]) -> Any:
    current = value
    for part in path:
        if isinstance(part, int):
            require(type(current) is list, f"{path!r} crosses non-list")
            require(0 <= part < len(current), f"{path!r} index is absent")
            current = current[part]
        else:
            require(type(current) is dict, f"{path!r} crosses non-object")
            require(part in current, f"{path!r} key is absent")
            current = current[part]
    return current


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    require(type(actual) is type(expected), f"{label} type differs")
    require(actual == expected, f"{label} differs")


def verify_semantics(contract: dict[str, Any]) -> None:
    strict_equal(set(contract), ROOT_KEYS, "contract root keys")
    for path, expected in EXPECTED_PATHS:
        strict_equal(at_path(contract, path), expected, ".".join(map(str, path)))

    plan = contract["implementation_plan"]
    require(type(plan) is list and len(plan) == 3, "implementation plan differs")
    strict_equal(
        [(item.get("id"), item.get("complete")) for item in plan],
        [("C8.9-S1", True), ("C8.9-S2", False), ("C8.9-S3", False)],
        "implementation plan completion",
    )
    forbidden = contract["semantics"]["forbidden_adjacent_features"]
    strict_equal(
        forbidden,
        [
            "simd",
            "relaxed-simd",
            "reference-types",
            "exceptions",
            "memory64",
            "multiple-memories",
            "gc",
            "threads",
            "shared-memory",
            "saturating-float-to-int",
        ],
        "forbidden adjacent features",
    )
    require(
        contract["identity"]["artifact_profile_code"]
        == contract["identity"]["artifact_abi"]
        == contract["identity"]["runtime_abi"]
        == 6,
        "code-6 ABI axes are not exact",
    )
    require(
        contract["code5_boundary"]["artifact_profile_code"]
        != contract["identity"]["artifact_profile_code"],
        "successor aliases code 5",
    )


def run_git(*args: str) -> bytes:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(
            f"git {' '.join(args)} failed: "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return result.stdout


def verify_commit_tree(commit: str, tree: str, label: str) -> None:
    actual = run_git("rev-parse", f"{commit}^{{tree}}").decode("ascii").strip()
    strict_equal(actual, tree, f"{label} tree")
    run_git("merge-base", "--is-ancestor", commit, "HEAD")


def verify_historical_file(commit: str, identity: dict[str, Any], label: str) -> None:
    path = identity["path"]
    listing = run_git("ls-tree", commit, "--", path).decode("ascii").strip()
    parts = listing.split(None, 3)
    require(len(parts) == 4, f"{label} tree entry is absent")
    strict_equal(parts[0], "100644", f"{label} mode")
    strict_equal(parts[1], "blob", f"{label} type")
    strict_equal(parts[2], identity["git_blob"], f"{label} blob")
    data = run_git("show", f"{commit}:{path}")
    strict_equal(len(data), identity["bytes"], f"{label} bytes")
    strict_equal(hashlib.sha256(data).hexdigest(), identity["sha256"], f"{label} SHA-256")


def verify_predecessors(contract: dict[str, Any]) -> None:
    predecessor = contract["predecessor"]
    for name in ("review_charter", "fixed_qemu_policy"):
        item = predecessor[name]
        publication = item["publication"]
        verify_commit_tree(publication["commit"], publication["tree"], name)
        verify_historical_file(publication["commit"], item["contract"], f"{name} contract")
        verify_historical_file(publication["commit"], item["verifier"], f"{name} verifier")

    basis = contract["allocation_authority"]
    verify_commit_tree(basis["basis_commit"], basis["basis_tree"], "allocation basis")
    engine = contract["engine_selection"]
    tree = run_git(
        "rev-parse",
        f"{engine['source_tree']['commit']}:{engine['source_tree']['path']}",
    ).decode("ascii").strip()
    strict_equal(tree, engine["source_tree"]["git_tree"], "engine source tree")


def read_text(relative: str, label: str) -> str:
    data = read_bounded(ROOT / relative, MAX_TEXT_BYTES, label)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not UTF-8: {exc}")


def verify_source_boundary(contract: dict[str, Any]) -> None:
    provenance = contract["engine_selection"]["provenance_file"]
    data = read_bounded(ROOT / provenance["path"], 64 * 1024, "engine provenance")
    strict_equal(len(data), provenance["bytes"], "engine provenance bytes")
    strict_equal(
        hashlib.sha256(data).hexdigest(), provenance["sha256"], "engine provenance SHA-256"
    )

    basis_commit = contract["allocation_authority"]["basis_commit"]
    verify_commit_tree(S1_PUBLICATION_COMMIT, S1_PUBLICATION_TREE, "S1 publication")
    for relative in SOURCE_BOUNDARY_FILES:
        published = run_git("show", f"{S1_PUBLICATION_COMMIT}:{relative}")
        historical = run_git("show", f"{basis_commit}:{relative}")
        strict_equal(published, historical, f"published pre-S2 source boundary {relative}")

    source = read_text("component-format/src/lib.rs", "component profile source")
    for marker in (
        "pub const PROFILE_2_SYNC_FLOAT_PROFILE_CODE: u16 = 5;",
        "stage: ProfileStage::ValidationOnly,",
        "assert!(!ProfileIdentity::PROFILE_2_SYNC_FLOAT.execution_enabled());",
    ):
        require(marker in source, f"code-5 boundary marker absent: {marker!r}")

    rust_roots = (
        "component-format",
        "component-runtime",
        "wasm-runtime",
        "wasm-float-candidate",
        "services/component-admission",
        "services/component-loader",
        "kernel",
    )
    published_files = run_git("ls-tree", "-r", "--name-only", S1_PUBLICATION_COMMIT).decode("utf-8").splitlines()
    for relative in rust_roots:
        prefix = relative + "/"
        for path in (path for path in published_files if path.startswith(prefix) and path.endswith(".rs")):
            text = run_git("show", f"{S1_PUBLICATION_COMMIT}:{path}").decode("utf-8")
            require(
                "PROFILE_3_SYNC_FLOAT_EXECUTABLE" not in text,
                f"C8.9 identity materialized in S1 publication: {path}",
            )


def verify_integration() -> None:
    roadmap = run_git("show", f"{S1_PUBLICATION_COMMIT}:docs/WASM_ROADMAP.md").decode("utf-8")
    float_doc = run_git("show", f"{S1_PUBLICATION_COMMIT}:docs/WASM_FLOAT_PROFILE.md").decode("utf-8")
    testing = run_git("show", f"{S1_PUBLICATION_COMMIT}:TESTING.md").decode("utf-8")
    ci = run_git("show", f"{S1_PUBLICATION_COMMIT}:.github/workflows/ci.yml").decode("utf-8")

    require(roadmap.count(ROADMAP_STATUS) == 1, "roadmap C8.9 status differs")
    require(roadmap.count(CURRENT_POSITION) >= 1, "roadmap current position differs")
    require(float_doc.count(FLOAT_HEADING) == 1, "Float successor heading differs")
    require(float_doc.count(CURRENT_POSITION) >= 1, "Float document current position differs")
    require(testing.count(TESTING_HEADING) == 1, "TESTING C8.9 heading differs")
    for command in CHECK_COMMANDS:
        strict_equal(testing.count(command), 1, f"TESTING command {command}")
        strict_equal(ci.count(command), 1, f"CI command {command}")
    strict_equal(ci.count(f"- name: {CI_STEP_NAME}"), 1, "CI C8.9 step")


def load_and_verify_live() -> dict[str, Any]:
    data = read_bounded(CONTRACT_PATH, MAX_CONTRACT_BYTES, "C8.9 contract")
    strict_equal(len(data), EXPECTED_CONTRACT_BYTES, "contract bytes")
    strict_equal(hashlib.sha256(data).hexdigest(), EXPECTED_CONTRACT_SHA256, "contract SHA-256")
    contract = strict_json_loads(data, "C8.9 contract")
    strict_equal(data, canonical_json_bytes(contract), "contract canonical encoding")
    verify_semantics(contract)
    verify_predecessors(contract)
    verify_source_boundary(contract)
    verify_integration()
    return contract


def replacement(expected: Any) -> Any:
    if type(expected) is bool:
        return not expected
    if type(expected) is int:
        return expected + 1
    if type(expected) is str:
        return expected + "-drift"
    if type(expected) is list:
        return [*expected, "drift"]
    fail("unsupported selftest value")


def set_path(value: dict[str, Any], path: tuple[str | int, ...], replacement_value: Any) -> None:
    current: Any = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement_value


def expect_rejected(label: str, value: dict[str, Any]) -> None:
    try:
        verify_semantics(value)
    except VerificationError:
        return
    fail(f"selftest mutation accepted: {label}")


def run_selftest(contract: dict[str, Any]) -> int:
    cases = 0
    for path, expected in EXPECTED_PATHS:
        mutated = copy.deepcopy(contract)
        set_path(mutated, path, replacement(expected))
        expect_rejected(".".join(map(str, path)), mutated)
        cases += 1

    mutated = copy.deepcopy(contract)
    mutated["unexpected"] = True
    expect_rejected("extra root key", mutated)
    cases += 1

    mutated = copy.deepcopy(contract)
    del mutated["target_policy"]
    expect_rejected("missing root key", mutated)
    cases += 1

    for index in range(3):
        mutated = copy.deepcopy(contract)
        mutated["implementation_plan"][index]["complete"] = not mutated[
            "implementation_plan"
        ][index]["complete"]
        expect_rejected(f"implementation completion {index}", mutated)
        cases += 1

    mutated = copy.deepcopy(contract)
    mutated["semantics"]["forbidden_adjacent_features"].remove("threads")
    expect_rejected("adjacent feature removal", mutated)
    cases += 1

    try:
        strict_json_loads(b'{"schema":1,"schema":2}\n', "duplicate selftest")
    except VerificationError:
        cases += 1
    else:
        fail("duplicate-key JSON selftest was accepted")

    try:
        strict_json_loads(b'{"value":1.5}\n', "float selftest")
    except VerificationError:
        cases += 1
    else:
        fail("floating JSON number selftest was accepted")
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-contract", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        contract = load_and_verify_live()
        if args.selftest:
            cases = run_selftest(contract)
            print(
                "PASS verify-c89-float-successor-design "
                f"mode=selftest cases={cases} position=c89-s1-design-frozen-pre-implementation"
            )
        else:
            print(
                "PASS verify-c89-float-successor-design "
                "mode=check-contract position=c89-s1-design-frozen-pre-implementation"
            )
        return 0
    except VerificationError as exc:
        print(f"FAIL verify-c89-float-successor-design: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
