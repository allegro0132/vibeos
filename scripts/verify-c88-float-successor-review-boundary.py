#!/usr/bin/env python3
"""Verify the post-F5 Float successor design-review boundary.

This checker proves only that a deliberately non-effective review charter is
intact and that its F5 predecessor references are exact Git members of the
published F5 closure.  It allocates no successor identity, selects no engine,
authorizes no implementation or execution, and consumes no physical input.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT_PATH = (
    ROOT
    / "acceptance/wasm-float-target/artifacts/"
    "float-successor-review-boundary-v1-contract.json"
)
SCRIPT_PATH = pathlib.Path(__file__).resolve()

EXPECTED_CONTRACT_SHA256 = (
    "963c776ec5c1e6a7fa60f97b89b52a78a1857c6154718fbff906c5e59d8b2fe8"
)
EXPECTED_CONTRACT_BYTES = 9_885
MAX_CONTRACT_BYTES = 64 * 1024
MAX_GIT_BLOB_BYTES = 512 * 1024
MAX_JSON_INTEGER_DIGITS = 20
READ_CHUNK_BYTES = 64 * 1024

F5_SOURCE_COMMIT = "0f06212f890077b2a3d1b4405a128058cb07c55e"
F5_SOURCE_TREE = "a3a3ef403b80eb51e60dd3cb6a2a5b5a6d3aed6d"
F5_PUBLICATION_COMMIT = "5a6e88407056fdfed0974586479b42b5bd1470fb"
F5_PUBLICATION_TREE = "d296000b1ba170aaafcbd7e8ca4f689c119b9921"
REVIEW_BASIS_COMMIT = "25111e04d3d1aa55e52bb29d05b66d0bfde087a3"
REVIEW_BASIS_TREE = "800952738c5d2a0a547163cfa7e77acd48656479"
F5_DECISION_ID = (
    "1841ae06e4c8bef4842a59bbc65362fa860e37d6d8a1d79cc68e3fc5a87004f9"
)
F5_SEMANTIC_SHA256 = (
    "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1"
)

ROOT_KEYS = {
    "authority",
    "code5_boundary",
    "contract_verifier",
    "effectivity",
    "f5_predecessor",
    "hardware_policy",
    "limitations",
    "review_basis",
    "review_questions",
    "roadmap_position",
    "roadmap_status",
    "schema",
    "scope",
    "status",
    "successor_evidence_policy",
    "successor_identity",
    "version",
}

EXPECTED_EFFECTIVITY = {
    "can_become_effective": False,
    "design_selected": False,
    "effective": False,
    "implementation_gate_open": False,
    "review_passed": False,
}

EXPECTED_SUCCESSOR_IDENTITY = {
    "artifact_abi_allocated": False,
    "command_contract_selected": False,
    "component_model_revision_selected": False,
    "core_wasm_revision_selected": False,
    "durable_schema_selected": False,
    "engine_identity_selected": False,
    "engine_supply_chain_selected": False,
    "execution_stage_selected": False,
    "profile_code_allocated": False,
    "roadmap_node_allocated": False,
    "runtime_abi_allocated": False,
    "state": "unallocated",
    "target_policy_selected": False,
    "wit_world_selected": False,
}

EXPECTED_AUTHORITY = {
    "admission_authorized": False,
    "aot_authorized": False,
    "command_authorized": False,
    "current_engine_authorized": False,
    "design_authorized": False,
    "durable_publication_authorized": False,
    "execution_authorized": False,
    "implementation_authorized": False,
    "in_place_promotion_authorized": False,
    "jit_authorized": False,
    "migration_authorized": False,
    "native_bytes_authorized": False,
    "production_authorized": False,
    "prototype_authorized": False,
    "release_authorized": False,
    "rwx_authorized": False,
}

EXPECTED_CODE5_BOUNDARY = {
    "activation_authorized": False,
    "admission_authorized": False,
    "artifact_profile_code": 5,
    "current_engine": False,
    "durable_publication_authorized": False,
    "executable": False,
    "in_place_promotion_authorized": False,
    "inert": True,
    "permanent": True,
    "stage": "validation-only",
}

EXPECTED_HARDWARE_POLICY = {
    "duo_contracts_retained": True,
    "duo_roadmap_blocking": False,
    "duo_testing_status": "paused-retained-nonblocking-non-evidence",
    "duo_tooling_retained": True,
    "fixed_qemu_formally_replaced_physical_duo_gate_for_f5": True,
    "fixed_qemu_replacement_scope": "c88-f5-only",
    "other_hardware_gates_unchanged": True,
    "physical_equivalence_claimed": False,
    "physical_inputs_permitted": 0,
    "physical_inputs_required": 0,
    "physical_provenance": "not-claimed",
}

EXPECTED_SUCCESSOR_EVIDENCE_POLICY = {
    "activation_evidence_inherited_from_f5": False,
    "admission_evidence_inherited_from_f5": False,
    "engine_evidence_inherited_from_f5": False,
    "f5_evidence_closes_only_f5": True,
    "fresh_successor_gate_required": True,
    "release_evidence_inherited_from_f5": False,
    "successor_gate_selected": False,
}

EXPECTED_OTHER_WIDENINGS = {
    "broader_wasi": False,
    "exceptions": False,
    "gc": False,
    "memory64": False,
    "multiple_memories": False,
    "reference_types": False,
    "simd": False,
    "threads": False,
}

EXPECTED_ROADMAP_STATUS = {
    "c85_c87": "deferred-unallocated-unauthorized",
    "c85_complete": False,
    "c86_complete": False,
    "c87_complete": False,
    "c88_f5_float_complete": True,
    "other_c88_feature_widenings": EXPECTED_OTHER_WIDENINGS,
    "successor_implementation_node_allocated": False,
}

EXPECTED_CONTRACT_VERIFIER = {
    "contract_identity_binding": "one-way-sha256-and-bytes-pin-in-verifier",
    "path": "scripts/verify-c88-float-successor-review-boundary.py",
    "success_only_means": (
        "review-charter-integrity-not-review-passage-not-implementation-authority"
    ),
}

EXPECTED_REVIEW_BASIS = {
    "commit": REVIEW_BASIS_COMMIT,
    "role": "historical-fixed-qemu-publication-audit-precedent-only",
    "self_binding_claimed": False,
    "tree": REVIEW_BASIS_TREE,
}

EXPECTED_REVIEW_QUESTIONS = [
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "identity_version_allocation",
        "order": 1,
        "question": (
            "Which separately numbered roadmap node, profile code, artifact ABI, "
            "runtime ABI, Core Wasm revision, Component Model revision, and "
            "execution stage are allocated?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "engine_supply_chain_selection",
        "order": 2,
        "question": (
            "Which exact engine implementation, source revision, package version, "
            "checksum, feature set, and supply-chain policy are selected?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "semantic_evidence_inheritance",
        "order": 3,
        "question": (
            "Which F5 semantics may be inherited, which claims require fresh "
            "evidence, and how is evidence non-promotion enforced?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "production_authority",
        "order": 4,
        "question": (
            "Which explicit authority path can open current-engine, admission, "
            "command, release, and production gates?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "durability_upgrade_rollback",
        "order": 5,
        "question": (
            "Which durable schema, upgrade compatibility, migration, rollback, "
            "and in-place promotion policy is selected?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "accounting_concurrency_lifecycle",
        "order": 6,
        "question": (
            "Which global resource accounting, concurrency, cancellation, "
            "ownership, and lifecycle invariants are required?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "target_release_evidence",
        "order": 7,
        "question": (
            "Which targets, environments, optimization modes, release artifacts, "
            "and fresh qualification evidence are required?"
        ),
        "state": "unresolved",
    },
    {
        "answer_selected": False,
        "blocking": True,
        "candidate_value_present": False,
        "id": "final_authorization_rollout",
        "order": 8,
        "question": (
            "Which independent review approves implementation, execution, "
            "rollout, observability, and rollback readiness?"
        ),
        "state": "unresolved",
    },
]

EXPECTED_PINNED_PUBLICATION_FILES = {
    "contract": {
        "bytes": 14_364,
        "git_blob": "c8751d541269b485ea0786a66ced506d2902caf1",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-contract.json"
        ),
        "sha256": (
            "93b10e8311ce7794a923425018f834b3cc8b62eddf664285e8dc2a29aaedd1d9"
        ),
    },
    "decision": {
        "bytes": 16_608,
        "git_blob": "1f43528cbb95c5f5d9d3731db7aa19997bee3ca8",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-decision.json"
        ),
        "sha256": (
            "1d118cdb4f5709f4ce93331b1cd6b60435e6c530eb800e9c21e0a3e8569030d4"
        ),
    },
    "normal_receipt": {
        "bytes": 2_991,
        "git_blob": "9c130c15dfaaab29000f5bfbf64598d87fe86b99",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-normal-receipt.json"
        ),
        "sha256": (
            "4d70865a6a665829457ee0e9ec34c9fa38de51ed6ee2bcb2be1356d752355c1a"
        ),
    },
    "optimized_receipt": {
        "bytes": 3_000,
        "git_blob": "970cbaf51c5960c374654a78d6051da6efe4ce44",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-optimized-receipt.json"
        ),
        "sha256": (
            "4f95fcd2b4d2524b1d27fce7bbf77846f4f7d0030da8ebe277ffc062e53550e0"
        ),
    },
    "verifier": {
        "bytes": 164_132,
        "git_blob": "6a41c789612a1ba9136b85ba488f1eed941eaabb",
        "git_mode": "100644",
        "path": "scripts/verify-c88-f5-qemu-target-gate.py",
        "sha256": (
            "cc3c486dfe4cb13d7cb0767dbce9f97f005e976bbeed05dc66a17dee405a9a87"
        ),
    },
}

EXPECTED_F5_PREDECESSOR = {
    "closure_scope": "c88-f5-float-widening-only",
    "decision_id": F5_DECISION_ID,
    "pinned_publication_files": EXPECTED_PINNED_PUBLICATION_FILES,
    "publication": {
        "commit": F5_PUBLICATION_COMMIT,
        "must_be_ancestor_of_checked_head": True,
        "tree": F5_PUBLICATION_TREE,
    },
    "semantic_sha256": F5_SEMANTIC_SHA256,
    "source": {"commit": F5_SOURCE_COMMIT, "tree": F5_SOURCE_TREE},
    "status": "complete-by-formal-fixed-qemu-evidence",
}

EXPECTED_LIMITATIONS = [
    (
        "This contract is a review charter, not a design decision, "
        "implementation gate, execution grant, or evidence artifact."
    ),
    (
        "No successor identity, version axis, execution stage, engine, supply "
        "chain, target policy, command contract, or durable schema is allocated "
        "or selected."
    ),
    (
        "F5 evidence closes only C8.8-F5 Float and does not become successor "
        "engine, admission, release, activation, or production evidence."
    ),
    (
        "Artifact profile code 5 remains permanently validation-only and inert; "
        "it cannot be promoted in place."
    ),
    (
        "Milk-V Duo testing remains paused; retained Duo contracts and tooling "
        "are nonblocking non-evidence and contribute zero physical inputs."
    ),
    (
        "C8.5 through C8.7 remain deferred and every non-Float C8.8 feature "
        "widening remains incomplete."
    ),
    (
        "Successful verification proves only this frozen charter's integrity "
        "and historical F5 publication membership; review_passed remains false."
    ),
]

CHECK_OUTPUT = (
    "PASS verify-c88-float-successor-review-boundary\n"
    "check_scope=review-charter-integrity-only\n"
    "review_passed=false\n"
    "identity_state=unallocated\n"
    "implementation_authorized=false\n"
    "physical_inputs_required=0\n"
    "physical_inputs_permitted=0\n"
)


class VerificationError(RuntimeError):
    """A fail-closed contract or provenance violation."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_integer(text: str) -> int:
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        fail("JSON integer exceeds digit limit")
    return int(text)


def _reject_float(text: str) -> NoReturn:
    fail(f"JSON floating-point number is forbidden: {text}")


def _reject_constant(text: str) -> NoReturn:
    fail(f"non-finite JSON constant is forbidden: {text}")


def strict_json_loads(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not UTF-8: {exc}")
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except VerificationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"{label} is not strict JSON: {exc}")


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def stable_single_link_read(path: pathlib.Path, maximum: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        fail(f"cannot lstat {label}: {exc}")
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a regular file")
    if before.st_nlink != 1:
        fail(f"{label} must have exactly one hard link")
    if before.st_size > maximum:
        fail(f"{label} exceeds byte limit")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot securely open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            fail(f"{label} changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeds byte limit")
            chunks.append(chunk)
        after_fd = os.fstat(descriptor)
        if _stat_identity(after_fd) != _stat_identity(opened):
            fail(f"{label} changed while read")
    finally:
        os.close(descriptor)
    try:
        after_path = os.lstat(path)
    except OSError as exc:
        fail(f"cannot re-lstat {label}: {exc}")
    if _stat_identity(after_path) != _stat_identity(before):
        fail(f"{label} changed after read")
    return b"".join(chunks)


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    if type(actual) is not type(expected):
        fail(
            f"{label} has type {type(actual).__name__}, expected "
            f"{type(expected).__name__}"
        )
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            fail(f"{label} keys differ: missing={missing}, extra={extra}")
        for key in expected:
            strict_equal(actual[key], expected[key], f"{label}.{key}")
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):
            fail(f"{label} length differs")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            strict_equal(actual_item, expected_item, f"{label}[{index}]")
        return
    if actual != expected:
        fail(f"{label} differs")


def validate_contract_object(contract: Any) -> None:
    if type(contract) is not dict:
        fail("contract root must be an object")
    if set(contract) != ROOT_KEYS:
        missing = sorted(ROOT_KEYS - set(contract))
        extra = sorted(set(contract) - ROOT_KEYS)
        fail(f"contract root keys differ: missing={missing}, extra={extra}")

    strict_equal(
        contract["schema"],
        "vibeos.c88.float-successor-review-boundary-v1.contract",
        "contract.schema",
    )
    strict_equal(contract["version"], 1, "contract.version")
    strict_equal(
        contract["scope"],
        "float-successor-design-review-boundary-only",
        "contract.scope",
    )
    strict_equal(
        contract["roadmap_position"],
        "post-c88-f5-pre-allocation",
        "contract.roadmap_position",
    )
    strict_equal(
        contract["status"],
        "review-charter-not-design-decision-not-evidence",
        "contract.status",
    )
    strict_equal(contract["effectivity"], EXPECTED_EFFECTIVITY, "effectivity")
    strict_equal(
        contract["successor_identity"],
        EXPECTED_SUCCESSOR_IDENTITY,
        "successor_identity",
    )
    strict_equal(contract["authority"], EXPECTED_AUTHORITY, "authority")
    strict_equal(
        contract["code5_boundary"], EXPECTED_CODE5_BOUNDARY, "code5_boundary"
    )
    strict_equal(
        contract["successor_evidence_policy"],
        EXPECTED_SUCCESSOR_EVIDENCE_POLICY,
        "successor_evidence_policy",
    )
    strict_equal(
        contract["hardware_policy"],
        EXPECTED_HARDWARE_POLICY,
        "hardware_policy",
    )
    strict_equal(
        contract["roadmap_status"], EXPECTED_ROADMAP_STATUS, "roadmap_status"
    )
    strict_equal(
        contract["review_questions"],
        EXPECTED_REVIEW_QUESTIONS,
        "review_questions",
    )
    strict_equal(
        contract["f5_predecessor"], EXPECTED_F5_PREDECESSOR, "f5_predecessor"
    )
    strict_equal(contract["review_basis"], EXPECTED_REVIEW_BASIS, "review_basis")
    strict_equal(
        contract["contract_verifier"],
        EXPECTED_CONTRACT_VERIFIER,
        "contract_verifier",
    )
    strict_equal(contract["limitations"], EXPECTED_LIMITATIONS, "limitations")


def decode_contract_bytes(data: bytes, require_identity: bool) -> dict[str, Any]:
    if require_identity:
        if len(data) != EXPECTED_CONTRACT_BYTES:
            fail("contract byte count differs from verifier pin")
        if hashlib.sha256(data).hexdigest() != EXPECTED_CONTRACT_SHA256:
            fail("contract SHA-256 differs from verifier pin")
    contract = strict_json_loads(data, "contract")
    if canonical_json_bytes(contract) != data:
        fail("contract is not canonical sorted indented JSON")
    validate_contract_object(contract)
    return contract


def _git_environment() -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    if "PATH" in os.environ:
        environment["PATH"] = os.environ["PATH"]
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def git_run(
    arguments: list[str],
    *,
    allowed_codes: set[int] = {0},
    maximum_stdout: int = MAX_GIT_BLOB_BYTES,
) -> tuple[int, bytes]:
    git = shutil.which("git", path=os.environ.get("PATH"))
    if git is None:
        fail("git executable not found")
    command = [
        git,
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(ROOT),
        *arguments,
    ]
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            completed = subprocess.run(
                command,
                check=False,
                env=_git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            fail(f"Git command failed to execute: {exc}")
        stdout_size = stdout_file.tell()
        stderr_size = stderr_file.tell()
        if stdout_size > maximum_stdout:
            fail("Git stdout exceeds byte limit")
        if stderr_size > 64 * 1024:
            fail("Git stderr exceeds byte limit")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()
    if completed.returncode not in allowed_codes:
        detail = stderr.decode("utf-8", "replace").strip()
        fail(
            f"Git command exited {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    return completed.returncode, stdout


def git_line(arguments: list[str], label: str) -> str:
    _, output = git_run(arguments, maximum_stdout=4096)
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} Git output is not ASCII")
    if not text.endswith("\n") or text.count("\n") != 1:
        fail(f"{label} Git output is not one line")
    return text[:-1]


def verify_commit_tree(commit: str, expected_tree: str, label: str) -> None:
    resolved_commit = git_line(
        ["rev-parse", "--verify", f"{commit}^{{commit}}"], f"{label} commit"
    )
    if resolved_commit != commit:
        fail(f"{label} commit identity differs")
    resolved_tree = git_line(
        ["rev-parse", "--verify", f"{commit}^{{tree}}"], f"{label} tree"
    )
    if resolved_tree != expected_tree:
        fail(f"{label} tree identity differs")


def verify_ancestor(ancestor: str, descendant: str, label: str) -> None:
    code, output = git_run(
        ["merge-base", "--is-ancestor", ancestor, descendant],
        allowed_codes={0, 1},
        maximum_stdout=0,
    )
    if output:
        fail(f"{label} ancestry check produced stdout")
    if code != 0:
        fail(f"{label} is not an ancestor")


def git_blob_at_commit(commit: str, identity: dict[str, Any], label: str) -> bytes:
    path = identity["path"]
    _, tree_entry = git_run(
        ["ls-tree", "-z", commit, "--", path], maximum_stdout=4096
    )
    expected_entry = (
        f"{identity['git_mode']} blob {identity['git_blob']}\t{path}\0"
    ).encode("utf-8")
    if tree_entry != expected_entry:
        fail(f"{label} Git mode/blob membership differs")
    blob = git_line(
        ["rev-parse", "--verify", f"{commit}:{path}"], f"{label} blob"
    )
    if blob != identity["git_blob"]:
        fail(f"{label} Git blob identity differs")
    object_type = git_line(["cat-file", "-t", blob], f"{label} object type")
    if object_type != "blob":
        fail(f"{label} object is not a blob")
    _, data = git_run(
        ["cat-file", "blob", blob], maximum_stdout=identity["bytes"] + 1
    )
    if len(data) != identity["bytes"]:
        fail(f"{label} byte count differs")
    if hashlib.sha256(data).hexdigest() != identity["sha256"]:
        fail(f"{label} SHA-256 differs")
    framed = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    if hashlib.sha1(framed).hexdigest() != identity["git_blob"]:
        fail(f"{label} computed Git blob differs")
    return data


def expect_path(value: Any, path: list[str], expected: Any, label: str) -> None:
    current = value
    for key in path:
        if type(current) is not dict or key not in current:
            fail(f"{label} is missing {'.'.join(path)}")
        current = current[key]
    strict_equal(current, expected, f"{label}.{'.'.join(path)}")


def verify_f5_decision(data: bytes, identities: dict[str, dict[str, Any]]) -> None:
    decision = strict_json_loads(data, "F5 decision")
    if canonical_json_bytes(decision) != data:
        fail("F5 decision blob is not canonical JSON")
    checks = [
        (["schema"], "vibeos.c88.f5.float-target.qemu-target-gate-v1.decision"),
        (["version"], 1),
        (["status"], "closed"),
        (["content", "decision_id"], F5_DECISION_ID),
        (["content", "decision_id_fields", "source_commit"], F5_SOURCE_COMMIT),
        (["content", "decision_id_fields", "source_tree"], F5_SOURCE_TREE),
        (
            ["content", "decision_id_fields", "semantic_sha256"],
            F5_SEMANTIC_SHA256,
        ),
        (["content", "evidence", "physical_inputs"], 0),
        (["content", "completion", "f5_complete"], True),
        (["content", "completion", "float_complete"], True),
        (["content", "completion", "target_gate_satisfied"], True),
        (["content", "completion", "code5_stage"], "validation-only"),
        (["content", "completion", "code5_activation_authorized"], False),
        (["content", "completion", "successor_design_review_eligible"], True),
        (["content", "completion", "successor_profile_code_allocated"], False),
        (["content", "completion", "successor_implementation_authorized"], False),
        (["content", "completion", "successor_execution_authorized"], False),
        (["content", "completion", "successor_production_authorized"], False),
        (["content", "completion", "other_c88_feature_widenings_complete"], False),
        (
            ["content", "contract", "sha256"],
            identities["contract"]["sha256"],
        ),
        (["content", "contract", "bytes"], identities["contract"]["bytes"]),
        (
            ["content", "decision_verifier", "sha256"],
            identities["verifier"]["sha256"],
        ),
        (
            ["content", "decision_verifier", "bytes"],
            identities["verifier"]["bytes"],
        ),
        (
            ["content", "verification_matrix", "normal_receipt", "sha256"],
            identities["normal_receipt"]["sha256"],
        ),
        (
            ["content", "verification_matrix", "normal_receipt", "bytes"],
            identities["normal_receipt"]["bytes"],
        ),
        (
            ["content", "verification_matrix", "optimized_receipt", "sha256"],
            identities["optimized_receipt"]["sha256"],
        ),
        (
            ["content", "verification_matrix", "optimized_receipt", "bytes"],
            identities["optimized_receipt"]["bytes"],
        ),
        (["content", "verification_matrix", "physical_inputs"], 0),
        (["content", "verification_matrix", "status"], "pass"),
    ]
    for path, expected in checks:
        expect_path(decision, path, expected, "F5 decision")


def verify_f5_receipt(data: bytes, mode: str, level: int) -> dict[str, Any]:
    receipt = strict_json_loads(data, f"F5 {mode} receipt")
    if canonical_json_bytes(receipt) != data:
        fail(f"F5 {mode} receipt blob is not canonical JSON")
    checks = [
        (["schema"], "vibeos.c88.f5.float-target.qemu-target-gate-v1.mode-receipt"),
        (["version"], 1),
        (["status"], "pass"),
        (["content", "candidate_decision_id"], F5_DECISION_ID),
        (["content", "optimization_mode"], mode),
        (["content", "optimization_level"], level),
        (["content", "physical_inputs"], 0),
        (["content", "source", "commit"], F5_SOURCE_COMMIT),
        (["content", "source", "tree"], F5_SOURCE_TREE),
        (["content", "shared_verifier", "semantic_sha256"], F5_SEMANTIC_SHA256),
        (["content", "shared_verifier", "records"], 1176),
        (["content", "shared_verifier", "status"], "pass"),
        (["content", "elf_auditor", "status"], "pass"),
    ]
    for path, expected in checks:
        expect_path(receipt, path, expected, f"F5 {mode} receipt")
    return receipt


def verify_git_membership(contract: dict[str, Any]) -> str:
    initial_head = git_line(["rev-parse", "--verify", "HEAD^{commit}"], "HEAD")
    verify_commit_tree(F5_SOURCE_COMMIT, F5_SOURCE_TREE, "F5 source")
    verify_commit_tree(F5_PUBLICATION_COMMIT, F5_PUBLICATION_TREE, "F5 publication")
    verify_commit_tree(REVIEW_BASIS_COMMIT, REVIEW_BASIS_TREE, "review basis")
    verify_ancestor(F5_SOURCE_COMMIT, F5_PUBLICATION_COMMIT, "F5 source/publication")
    verify_ancestor(F5_PUBLICATION_COMMIT, REVIEW_BASIS_COMMIT, "publication/review basis")
    verify_ancestor(REVIEW_BASIS_COMMIT, initial_head, "review basis/HEAD")
    verify_ancestor(F5_PUBLICATION_COMMIT, initial_head, "F5 publication/HEAD")

    identities = contract["f5_predecessor"]["pinned_publication_files"]
    blobs = {
        name: git_blob_at_commit(F5_PUBLICATION_COMMIT, identity, f"F5 {name}")
        for name, identity in identities.items()
    }
    verify_f5_decision(blobs["decision"], identities)
    normal = verify_f5_receipt(blobs["normal_receipt"], "normal", 0)
    optimized = verify_f5_receipt(blobs["optimized_receipt"], "optimized", 1)
    for path in (
        ["content", "candidate"],
        ["content", "candidate_content_sha256"],
        ["content", "publisher_challenge_sha256"],
    ):
        left = normal
        right = optimized
        for key in path:
            left = left[key]
            right = right[key]
        strict_equal(left, right, f"F5 receipt parity.{'.'.join(path)}")

    final_head = git_line(["rev-parse", "--verify", "HEAD^{commit}"], "final HEAD")
    if final_head != initial_head:
        fail("HEAD changed during verification")
    return initial_head


def check_contract() -> dict[str, Any]:
    data = stable_single_link_read(CONTRACT_PATH, MAX_CONTRACT_BYTES, "contract")
    contract = decode_contract_bytes(data, require_identity=True)
    verify_git_membership(contract)
    return contract


def expect_rejected(action: Any, label: str) -> None:
    try:
        action()
    except VerificationError:
        return
    fail(f"selftest accepted forbidden mutation: {label}")


def validate_mutation(base: dict[str, Any], mutate: Any) -> None:
    candidate = copy.deepcopy(base)
    mutate(candidate)
    validate_contract_object(candidate)


def subprocess_check_output(optimized: bool) -> bytes:
    command = [sys.executable]
    if optimized:
        command.append("-O")
    command.extend([str(SCRIPT_PATH), "--check-contract"])
    environment = {
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    if "PATH" in os.environ:
        environment["PATH"] = os.environ["PATH"]
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"selftest mode subprocess failed: {exc}")
    if len(completed.stdout) > 64 * 1024 or len(completed.stderr) > 64 * 1024:
        fail("selftest mode subprocess output exceeds limit")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        fail(f"selftest mode subprocess rejected baseline: {detail}")
    if completed.stderr:
        fail("selftest mode subprocess produced stderr")
    return completed.stdout


def run_selftest(base: dict[str, Any], baseline_bytes: bytes) -> None:
    for key, value in EXPECTED_EFFECTIVITY.items():
        if type(value) is bool and value is False:
            expect_rejected(
                lambda key=key: validate_mutation(
                    base, lambda item: item["effectivity"].__setitem__(key, True)
                ),
                f"effectivity or selection flag {key}",
            )
    for key, value in EXPECTED_SUCCESSOR_IDENTITY.items():
        if type(value) is bool and value is False:
            expect_rejected(
                lambda key=key: validate_mutation(
                    base, lambda value: value["successor_identity"].__setitem__(key, True)
                ),
                f"successor identity flag {key}",
            )
    for key in EXPECTED_AUTHORITY:
        expect_rejected(
            lambda key=key: validate_mutation(
                base, lambda value: value["authority"].__setitem__(key, True)
            ),
            f"authority flag {key}",
        )
    for key, value in EXPECTED_CODE5_BOUNDARY.items():
        if type(value) is bool:
            expect_rejected(
                lambda key=key, value=value: validate_mutation(
                    base,
                    lambda item: item["code5_boundary"].__setitem__(key, not value),
                ),
                f"code 5 boundary flag {key}",
            )
    for key, value in EXPECTED_SUCCESSOR_EVIDENCE_POLICY.items():
        if type(value) is bool:
            expect_rejected(
                lambda key=key, value=value: validate_mutation(
                    base,
                    lambda item: item["successor_evidence_policy"].__setitem__(
                        key, not value
                    ),
                ),
                f"successor evidence policy flag {key}",
            )

    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["successor_identity"].__setitem__(
                "candidate_profile_code", 6
            ),
        ),
        "candidate identity value",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["code5_boundary"].__setitem__("stage", "executable"),
        ),
        "code 5 executable stage",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["code5_boundary"].__setitem__("current_engine", True),
        ),
        "code 5 current engine",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["f5_predecessor"]["publication"].__setitem__(
                "commit", "0" * 40
            ),
        ),
        "F5 commit drift",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["f5_predecessor"]["pinned_publication_files"][
                "decision"
            ].__setitem__("sha256", "0" * 64),
        ),
        "F5 hash drift",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["successor_evidence_policy"].__setitem__(
                "activation_evidence_inherited_from_f5", True
            ),
        ),
        "F5 evidence promotion",
    )
    expect_rejected(
        lambda: validate_mutation(
            base, lambda value: value["review_questions"].pop()
        ),
        "review question deletion",
    )
    expect_rejected(
        lambda: validate_mutation(
            base, lambda value: value["review_questions"].reverse()
        ),
        "review question reordering",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["review_questions"][0].__setitem__(
                "answer_selected", True
            ),
        ),
        "review question answered",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["review_questions"][0].__setitem__(
                "candidate_value_present", True
            ),
        ),
        "review candidate present",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["review_questions"][0].__setitem__(
                "blocking", False
            ),
        ),
        "review question nonblocking",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["hardware_policy"].__setitem__(
                "physical_inputs_required", 1
            ),
        ),
        "physical input requirement",
    )
    expect_rejected(
        lambda: validate_mutation(
            base,
            lambda value: value["hardware_policy"].__setitem__(
                "physical_inputs_permitted", 1
            ),
        ),
        "physical input permission",
    )
    for widening in EXPECTED_OTHER_WIDENINGS:
        expect_rejected(
            lambda widening=widening: validate_mutation(
                base,
                lambda value: value["roadmap_status"][
                    "other_c88_feature_widenings"
                ].__setitem__(widening, True),
            ),
            f"other widening completion {widening}",
        )
    expect_rejected(
        lambda: validate_mutation(
            base, lambda value: value.__setitem__("unexpected", False)
        ),
        "extra root field",
    )
    expect_rejected(
        lambda: strict_json_loads(b'{"x": 1, "x": 1}\n', "duplicate fixture"),
        "duplicate JSON key",
    )
    expect_rejected(
        lambda: strict_json_loads(b'{"version": 1.0}\n', "float fixture"),
        "floating-point JSON",
    )
    expect_rejected(
        lambda: validate_mutation(
            base, lambda value: value.__setitem__("version", True)
        ),
        "boolean used as integer",
    )
    expect_rejected(
        lambda: decode_contract_bytes(baseline_bytes + b" ", require_identity=False),
        "noncanonical JSON",
    )

    with tempfile.TemporaryDirectory(prefix="c88-float-review-boundary-") as name:
        directory = pathlib.Path(name)
        regular = directory / "regular"
        regular.write_bytes(b"fixture\n")
        symlink = directory / "symlink"
        symlink.symlink_to(regular)
        expect_rejected(
            lambda: stable_single_link_read(symlink, 64, "symlink fixture"),
            "symlink input",
        )
        hardlink = directory / "hardlink"
        os.link(regular, hardlink)
        expect_rejected(
            lambda: stable_single_link_read(regular, 64, "hardlink fixture"),
            "hardlink input",
        )
        fifo = directory / "fifo"
        os.mkfifo(fifo)
        expect_rejected(
            lambda: stable_single_link_read(fifo, 64, "FIFO fixture"),
            "FIFO input",
        )

        raced = directory / "raced"
        raced.write_bytes(b"fixture\n")
        original_lstat = os.lstat
        original_open = os.open
        race_swapped = False

        def race_lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            nonlocal race_swapped
            result = original_lstat(path, *args, **kwargs)
            if not race_swapped and os.fspath(path) == os.fspath(raced):
                raced.unlink()
                os.mkfifo(raced)
                race_swapped = True
            return result

        def race_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if (
                os.fspath(path) == os.fspath(raced)
                and not flags & getattr(os, "O_NONBLOCK", 0)
            ):
                fail("FIFO replacement fixture open omitted O_NONBLOCK")
            return original_open(path, flags, *args, **kwargs)

        race_error: str | None = None
        try:
            os.lstat = race_lstat
            os.open = race_open
            try:
                stable_single_link_read(raced, 64, "FIFO replacement fixture")
            except VerificationError as exc:
                race_error = str(exc)
        finally:
            os.lstat = original_lstat
            os.open = original_open
        if race_error != "FIFO replacement fixture changed before open":
            fail(f"FIFO replacement fixture failed closed incorrectly: {race_error}")

    normal = subprocess_check_output(False)
    optimized = subprocess_check_output(True)
    if normal != optimized:
        fail("normal and optimized checker output differs")
    if normal != CHECK_OUTPUT.encode("utf-8"):
        fail("checker output contract differs")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the non-authorizing Float successor review boundary.",
        allow_abbrev=False,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check-contract",
        action="store_true",
        help="check the frozen review charter and historical F5 Git membership",
    )
    mode.add_argument(
        "--selftest",
        action="store_true",
        help="exercise fail-closed mutations and normal/-O parity",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        contract_bytes = stable_single_link_read(
            CONTRACT_PATH, MAX_CONTRACT_BYTES, "contract"
        )
        contract = decode_contract_bytes(contract_bytes, require_identity=True)
        verify_git_membership(contract)
        if arguments.selftest:
            run_selftest(contract, contract_bytes)
    except VerificationError as exc:
        print(f"FAIL verify-c88-float-successor-review-boundary: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(CHECK_OUTPUT)
    if arguments.selftest:
        sys.stdout.write("selftest=pass\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
