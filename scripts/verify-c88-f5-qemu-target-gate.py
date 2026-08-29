#!/usr/bin/env python3
"""Derive the C8.8-F5 fixed-QEMU target-gate decision.

The checked-in contract is policy, not evidence.  The matrix publisher consumes
the four already-produced QEMU artifacts, privately stages immutable copies and
an unpublished random challenge, directly executes normal and optimized
verification workers, and writes one canonical no-clobber decision last.  The
decision is the publication barrier for the otherwise non-atomic inputs.

This verifier never opens a serial or device path, packages or flashes an
image, resets a board, or claims physical or Milk-V Duo provenance.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import types
from typing import Any, NoReturn, NamedTuple


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT_PATH = (
    ROOT / "acceptance/wasm-float-target/artifacts/"
    "qualification-qemu-target-gate-v1-contract.json"
)
DECISION_VERIFIER_PATH = pathlib.Path(__file__).resolve()
EXPECTED_CONTRACT_SHA256 = (
    "93b10e8311ce7794a923425018f834b3cc8b62eddf664285e8dc2a29aaedd1d9"
)
EXPECTED_CONTRACT_BYTES = 14_364
EXPECTED_SEMANTIC_SHA256 = (
    "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1"
)
DECISION_DOMAIN = b"vibeos.c88.f5.float-target.qemu-target-gate-v1.decision.v1\0"
CONTENT_DOMAIN = b"vibeos.c88.f5.float-target.qemu-target-gate-v1.content.v1\0"
CANDIDATE_CONTENT_DOMAIN = (
    b"vibeos.c88.f5.float-target.qemu-target-gate-v1.candidate-content.v1\0"
)
MODE_RECEIPT_CONTENT_DOMAIN = (
    b"vibeos.c88.f5.float-target.qemu-target-gate-v1.mode-receipt.v1\0"
)
PUBLISHER_CHALLENGE_DOMAIN = (
    b"vibeos.c88.f5.float-target.qemu-target-gate-v1.publisher-challenge.v1\0"
)

MAX_CONTRACT_BYTES = 64 * 1024
MAX_ENVIRONMENT_BYTES = 4 * 1024 * 1024
MAX_UART_BYTES = 16 * 1024 * 1024
MAX_KERNEL_BYTES = 256 * 1024 * 1024
MAX_ELF_AUDIT_BYTES = 4 * 1024 * 1024
MAX_DECISION_BYTES = 512 * 1024
MAX_WORKER_OUTPUT_BYTES = 2 * MAX_DECISION_BYTES + 64 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_JSON_INTEGER_DIGITS = 20
READ_CHUNK_BYTES = 64 * 1024

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

CONTRACT_ROOT_KEYS = {
    "schema",
    "version",
    "suite_id",
    "scope",
    "status",
    "effectivity",
    "decision_id",
    "policy",
    "precedence",
    "source_provenance",
    "publication",
    "verification",
    "decision_verifier",
    "pinned_files",
    "retained_duo_files",
    "platform",
    "qualification",
    "required_verified_decision_outcome",
    "limitations",
}

DECISION_ID_FIELDS = [
    "source_commit",
    "source_tree",
    "challenge",
    "run_id",
    "contract_sha256",
    "decision_verifier_sha256",
    "qualification_manifest_sha256",
    "runner_sha256",
    "shared_verifier_sha256",
    "elf_auditor_sha256",
    "kernel_sha256",
    "uart_sha256",
    "elf_audit_sha256",
    "environment_sha256",
    "environment_evidence_sha256",
    "semantic_sha256",
]

PINNED_FILES = {
    "qualification_manifest": {
        "path": "acceptance/wasm-float-target/artifacts/qualification-manifest.json",
        "sha256": "39abd7d8bf25f2da2dfe76109e0811202ba05a9dbc17501ef7a6c2a905c81d76",
        "bytes": 2_090,
    },
    "runner": {
        "path": "scripts/qemu-c88-f5-float-target.py",
        "sha256": "8b4391524511550d8a0e9fd0722c697ddc8b6e8d1ebc349fc283708370cf2180",
        "bytes": 89_050,
    },
    "shared_verifier": {
        "path": "scripts/verify-c88-f5-float-target.py",
        "sha256": "36451c3c614486a714b3466b77b329fee8a1368603ffaa9d2925b75b3f666686",
        "bytes": 134_348,
    },
    "elf_auditor": {
        "path": "scripts/verify-c88-f5-riscv-elf.py",
        "sha256": "3e7d9670c020de2e7ab274eb74b46d13153a0ca553f04d92134bde191e289f1b",
        "bytes": 92_051,
    },
    "producer": {
        "path": "kernel/src/wasm_float_target.rs",
        "sha256": "f524ba72d904ce123bab3a5d2e14c8f5ea36885051cd4008d6c0bfa29eb5d06a",
        "bytes": 34_986,
    },
    "qualification": {
        "path": "acceptance/wasm-float-target/src/lib.rs",
        "sha256": "b24b7e6e48c96f36264e81bb936dda9ed82954f893a7b8b44dea486fa0b06167",
        "bytes": 71_473,
    },
    "rust_toolchain": {
        "path": "rust-toolchain.toml",
        "sha256": "aac4c0b9d7f8d6677de6b396d51beac9adf7847af968d2e8aa376fadec961c9a",
        "bytes": 214,
    },
}

RETAINED_DUO_FILES = {
    "readiness_manifest": {
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-duo-v1-manifest.json"
        ),
        "sha256": "1c85f22cacee7c8eb7693578052fe0452169eace99f1dab06e08aa0e42771b11",
        "bytes": 4_159,
        "git_mode": "100644",
    },
    "readiness_transcript_schema": {
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-duo-v1-transcript-schema.json"
        ),
        "sha256": "e25d9a38d194993906b7fe5ec9708654ea31e2386ac61f0fa360ed8ad1eb7439",
        "bytes": 4_692,
        "git_mode": "100644",
    },
    "readiness_verifier": {
        "path": "scripts/verify-c88-f5-duo-readiness.py",
        "sha256": "b7f0d56f323eb7b155202e1ae33cd0952f772c26a615badcff1596fd75bb46c0",
        "bytes": 102_229,
        "git_mode": "100644",
    },
    "physical_contract": {
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-duo-physical-v1-contract.json"
        ),
        "sha256": "01284fa4bb76a24e0a40e39fddec109e98ff36ec8912bb806f7a52a520a6617e",
        "bytes": 5_605,
        "git_mode": "100644",
    },
    "physical_transcript_schema": {
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-duo-physical-v1-transcript-schema.json"
        ),
        "sha256": "08007a5e68e53181592dd9eaecf124a630b2eddfdc20c146504ff1d4df8811f5",
        "bytes": 5_923,
        "git_mode": "100644",
    },
    "physical_verifier": {
        "path": "scripts/verify-c88-f5-duo-physical-transcript.py",
        "sha256": "09a98255b9deb8c5d14b19ecb4c0c5725cfbef25a60b1d84f2f4bbfbda649928",
        "bytes": 56_129,
        "git_mode": "100755",
    },
}

EXPECTED_DECISION_VERIFIER = {
    "path": "scripts/verify-c88-f5-qemu-target-gate.py",
    "identity_binding": "runtime-sha256-bytes-and-source-commit-blob-in-decision",
}

EXPECTED_EFFECTIVITY = {
    "effective": False,
    "contract_alone_satisfies_gate": False,
    "fresh_formal_evidence_required": True,
    "canonical_no_clobber_decision_required": True,
    "decision_verifier_acceptance_required": True,
    "verification_matrix_completion_required": True,
    "condition": (
        "effective-only-after-the-required-matrix-accepts-one-canonical-"
        "no-clobber-decision"
    ),
}

EXPECTED_POLICY = {
    "replacement": "fixed-qemu-formally-replaces-c88-f5-physical-duo-roadmap-gate",
    "replacement_scope": "c88-f5-only",
    "other_hardware_gates_unchanged": True,
    "duo_tooling_retained": True,
    "duo_testing_status": "paused-retained-non-blocking",
    "duo_roadmap_blocking": False,
    "physical_inputs_required": 0,
    "physical_inputs_permitted": 0,
    "physical_provenance": "not-claimed",
    "physical_equivalence_claimed": False,
}

EXPECTED_PRECEDENCE = {
    "decision_scope": "c88-f5-float-target-exit-status-only",
    "normative_exit_gate": "formal-fixed-qemu-target-gate-v1",
    "physical_duo_exit_requirement_replaced": True,
    "retained_duo_false_completion_fields_scope": (
        "their-own-readiness-or-physical-non-evidence-artifacts-only"
    ),
    "retained_duo_artifacts_may_override_this_decision": False,
    "unrelated_hardware_gate_precedence": "unchanged",
}

EXPECTED_SOURCE_PROVENANCE = {
    "required_branch": "codex/wasm",
    "required_local_tracking_ref": "refs/remotes/origin/codex/wasm",
    "claim": "clean-head-equals-local-origin-tracking-ref",
    "remote_advertised_oid_proven": False,
    "operator_fetch_before_formal_run_required": True,
    "complete_remote_publication_proof_claimed": False,
}

EXPECTED_PUBLICATION = {
    "input_artifacts": ["kernel", "elf_audit", "uart", "environment"],
    "input_bundle_atomic_publication": False,
    "stable_final_reread_required": True,
    "decision_canonical_json_required": True,
    "decision_no_clobber_required": True,
    "decision_is_publication_barrier": True,
    "formal_outputs_are_non_effective_candidates": True,
    "matrix_publisher_is_only_closure_path": True,
    "matrix_publisher_directly_executes_both_modes": True,
    "caller_supplied_candidates_or_receipts_authorize_closure": False,
    "publisher_private_stage_required": True,
    "publisher_private_stage_exact_entries_required": True,
    "publisher_private_stage_full_metadata_seal_required": True,
    "publisher_private_challenge_required": True,
    "publisher_challenge_bytes_published": False,
    "mode_receipts_are_publisher_outputs_only": True,
    "worker_candidate_and_receipt_transport": (
        "publisher-controlled-bounded-stdout-only"
    ),
    "worker_executes_verified_private_verifier_copy": True,
    "worker_accepts_candidate_or_receipt_inputs": False,
    "worker_accepts_output_paths": False,
    "private_stage_cleanup_before_publication_required": True,
    "publication_triplet_terminal_reread_required": True,
    "publication_output_parent_full_metadata_required": True,
    "publication_output_parent_exact_entry_set_required": True,
    "closed_decision_requires_two_mode_receipts": True,
    "decision_retains_hash_summary_only": True,
    "checked_in_decision_retains_full_input_bytes": False,
    "offline_replay_requires_all_four_input_artifacts": True,
}

EXPECTED_VERIFICATION = {
    "python_interpreter_identity_same_required": True,
    "required_optimization_modes": ["normal", "optimized"],
    "successful_exit_code": 0,
    "shared_verifier_both_modes_required": True,
    "shared_verifier_result_byte_equality_required": True,
    "elf_auditor_both_modes_required": True,
    "elf_audit_report_byte_equality_required": True,
    "elf_auditor_verified_private_copy_required": True,
    "elf_auditor_private_input_directory_seal_required": True,
    "cross_stage_full_metadata_identity_required": True,
    "live_input_parent_full_metadata_identity_required": True,
    "decision_verifier_both_modes_required": True,
    "candidate_payload_byte_equality_required": True,
    "mode_receipts_required": True,
    "matrix_publisher_required": True,
    "publisher_owned_worker_exit_and_output_validation_required": True,
    "publisher_owned_worker_stderr_empty_required": True,
    "publisher_owned_worker_stdout_canonical_required": True,
    "publisher_candidate_matches_caller_evidence_required": True,
    "checked_receipt_replays_evidence": False,
    "checked_receipt_proves_publisher_execution": False,
    "matrix_publisher_completion_required_before_effectivity": True,
}

EXPECTED_PLATFORM = {
    "id": "qemu-virt-rv64-tcg-icount-v1",
    "class": "emulator",
    "target": "riscv64imac-unknown-none-elf",
    "physical_provenance": "not-claimed",
    "qemu": {
        "path": "/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-riscv64",
        "sha256": "ef5c714232320c22561daa0998546b73672e21a2801404714dfbd4982ac7b3c0",
        "bytes": 13_511_488,
        "version": (
            "QEMU emulator version 11.0.3\n"
            "Copyright (c) 2003-2026 Fabrice Bellard and the QEMU Project developers"
        ),
    },
    "opensbi": {
        "path": (
            "/opt/homebrew/Cellar/qemu/11.0.3/share/qemu/"
            "opensbi-riscv64-generic-fw_dynamic.bin"
        ),
        "sha256": "49bdf7b939bda11321132d1042bf99d7324fb190f1feef423171fed3573f8705",
        "bytes": 273_048,
    },
    "argv_semantics": [
        "-no-user-config",
        "-machine=virt",
        "-cpu=rv64",
        "-smp=1",
        "-m=128M",
        "-accel=tcg,thread=single",
        "-icount=shift=0,align=off,sleep=off",
        "-nographic",
        "-nic=none",
        "-bios=pinned-opensbi",
        "-kernel=measured-kernel",
    ],
    "runtime_custody": {
        "qemu_main_binary_frozen": True,
        "opensbi_frozen": True,
        "argv_frozen": True,
        "macos_dyld_recursive_closure_verified": False,
        "qemu_module_recursive_closure_verified": False,
        "ambient_macos_dyld_runtime_is_trusted_tcb": True,
        "complete_runtime_closure_claimed": False,
    },
}

EXPECTED_RECORDS = {
    "core": 146,
    "canonical_abi": 13,
    "component_vectors": 12,
    "fuel": 1_000,
    "lifecycle": 5,
    "total": 1_176,
}

EXPECTED_ELF_REQUIREMENTS = {
    "status": "pass",
    "static_no_relocations": True,
    "section_and_segment_wx": True,
    "forbidden_opcodes": 0,
    "undefined_symbols": 0,
    "forbidden_float_helpers": 0,
    "trusted_native_control_flow_only": True,
    "canonical_decoder_boundaries_only": True,
    "arbitrary_pc_redirection_claimed": False,
    "hardware_nx_claimed": False,
}

EXPECTED_QUALIFICATION = {
    "suite_id": "vibeos.c88.f5.float-target",
    "mode": "formal-qemu",
    "target": "riscv64imac-unknown-none-elf",
    "semantic_sha256": EXPECTED_SEMANTIC_SHA256,
    "records": EXPECTED_RECORDS,
    "artifact_profile_code": 5,
    "artifact_abi": 5,
    "component_profile": 2,
    "core_profile": 2,
    "runtime_abi": 5,
    "stage": "validation-only",
    "runtime_ready": False,
    "native_async_runtime_ready": False,
    "execution_enabled": False,
    "current_validation_engine": False,
    "current_component_engine": False,
    "candidate_production_ready": False,
    "elf_requirements": EXPECTED_ELF_REQUIREMENTS,
}

EXPECTED_OUTCOME = {
    "target_gate_satisfied": True,
    "target_gate_basis": "formal-fixed-qemu-replacement-v1",
    "f5_complete": True,
    "float_complete": True,
    "c88_complete": True,
    "c88_completion_scope": "float-widening-only",
    "other_c88_feature_widenings_complete": False,
    "float_execution_available": False,
    "duo_roadmap_blocking": False,
    "duo_physical_gate_satisfied": False,
    "duo_physical_evidence_present": False,
    "physical_provenance": "not-claimed",
    "code5_stage": "validation-only",
    "code5_activation_authorized": False,
    "code5_promotion_in_place_authorized": False,
    "code5_current_validation_engine": False,
    "code5_current_component_engine": False,
    "code5_production_admission_authorized": False,
    "code5_durable_publication_authorized": False,
    "successor_design_review_eligible": True,
    "successor_profile_code_allocated": False,
    "successor_artifact_abi_allocated": False,
    "successor_runtime_abi_allocated": False,
    "successor_engine_identity_selected": False,
    "successor_implementation_authorized": False,
    "successor_execution_authorized": False,
    "successor_production_authorized": False,
    "executable_successor_authorized": False,
    "aot_authorized_by_this_decision": False,
    "native_bytes_accepted_by_this_decision": False,
}

EXPECTED_LIMITATIONS = [
    (
        "This contract is not evidence and is ineffective until the required "
        "normal/optimized matrix accepts one canonical no-clobber decision."
    ),
    (
        "This decision closes only the C8.8-F5 Float target gate; every unrelated "
        "hardware gate is unchanged."
    ),
    (
        "This is emulator evidence and makes no Milk-V Duo, physical-hardware, "
        "or cold-boot provenance claim."
    ),
    (
        "The source claim proves clean HEAD equality with the local "
        "origin/codex/wasm tracking ref, not a remotely advertised OID."
    ),
    (
        "The fixed QEMU main binary, OpenSBI bytes, and argv are bound; ambient "
        "macOS dyld, dynamic-library, and QEMU module closure remains trusted TCB."
    ),
    (
        "The four input artifacts are not atomically published; stable final "
        "rereads followed by no-clobber DECISION.json form the publication barrier."
    ),
    (
        "The matrix publisher privately stages the four evidence inputs and an "
        "unpublished random challenge, directly executes normal and optimized "
        "verifier workers, treats their candidates and receipts only as outputs, "
        "and is the sole path that may publish a closed decision."
    ),
    (
        "The retained Duo readiness and physical-v1 artifacts remain scoped "
        "non-evidence; their false completion fields cannot override this C8.8-F5 "
        "fixed-QEMU decision."
    ),
    (
        "The checked-in decision retains hashes and summaries only; complete "
        "offline replay requires retaining the kernel, ELF-audit report, UART "
        "transcript, and environment envelope."
    ),
    (
        "Checking the checked-in decision and mode receipts proves only "
        "structure, source membership, and hash integrity; it neither replays "
        "the four evidence artifacts nor proves that the publisher executed."
    ),
    (
        "C8.8 completion in this decision means the Float widening only; no other "
        "C8.8 feature widening is claimed complete."
    ),
    (
        "Completion keeps artifact profile code 5 permanently validation-only "
        "and opens design review for an unallocated separately numbered successor "
        "only."
    ),
]


class GateError(RuntimeError):
    """A fail-closed contract, evidence, or publication rejection."""


class StableFile(NamedTuple):
    path: pathlib.Path
    raw: bytes
    device: int
    inode: int
    metadata: tuple[int, ...]


def fail(message: str) -> NoReturn:
    raise GateError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def identity_for(raw: bytes) -> dict[str, object]:
    return {"sha256": sha256_bytes(raw), "bytes": len(raw)}


def canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        fail(f"value is not canonical JSON: {error}")


def compact_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        fail(f"value is not compact canonical JSON: {error}")


def compact_json_line(value: object) -> bytes:
    return compact_json(value) + b"\n"


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, member in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = member
    return value


def reject_json_number(token: str) -> NoReturn:
    raise ValueError(f"non-integer JSON number is forbidden: {token}")


def parse_json_integer(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError(
            f"JSON integer exceeds the {MAX_JSON_INTEGER_DIGITS}-digit bound"
        )
    return int(token, 10)


def strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_members,
            parse_int=parse_json_integer,
            parse_float=reject_json_number,
            parse_constant=reject_json_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        fail(f"invalid {label} JSON: {error}")
    if type(value) is not dict:
        fail(f"{label} must be one JSON object")
    return value


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"{label} must be one object")
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def exact_literal(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        fail(f"{label} differs")


def canonical_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        fail(f"{label} is not canonical lowercase hex")
    if not any(character != "0" for character in value):
        fail(f"{label} must be nonzero")
    return value


def positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be one positive integer")
    return value


def identity_record(value: object, label: str) -> dict[str, object]:
    record = exact_keys(value, {"path", "sha256", "bytes"}, label)
    if type(record["path"]) is not str or not record["path"]:
        fail(f"{label}.path must be nonempty text")
    canonical_hex(record["sha256"], HEX64, f"{label}.sha256")
    positive_integer(record["bytes"], f"{label}.bytes")
    return record


def retained_identity_record(value: object, label: str) -> dict[str, object]:
    record = exact_keys(value, {"path", "sha256", "bytes", "git_mode"}, label)
    if type(record["path"]) is not str or not record["path"]:
        fail(f"{label}.path must be nonempty text")
    canonical_hex(record["sha256"], HEX64, f"{label}.sha256")
    positive_integer(record["bytes"], f"{label}.bytes")
    if record["git_mode"] not in ("100644", "100755"):
        fail(f"{label}.git_mode is not an allowed regular-file mode")
    return record


def role_identity(value: object, label: str) -> dict[str, object]:
    record = identity_record(value, label)
    return {"sha256": record["sha256"], "bytes": record["bytes"]}


def identity_summary(value: object, label: str) -> dict[str, object]:
    record = exact_keys(value, {"sha256", "bytes"}, label)
    canonical_hex(record["sha256"], HEX64, f"{label}.sha256")
    positive_integer(record["bytes"], f"{label}.bytes")
    return record


def absolute_path(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        encoded = os.fspath(path)
    except TypeError as error:
        fail(f"{label} path is invalid: {error}")
    if not encoded or "\0" in encoded:
        fail(f"{label} path is empty or contains NUL")
    return pathlib.Path(os.path.abspath(encoded))


def configure_internal_repository_root(path: pathlib.Path) -> None:
    global ROOT, CONTRACT_PATH
    selected, descriptor = open_directory_chain(path, "internal repository root")
    try:
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("internal repository root is not one direct directory")
    ROOT = selected
    CONTRACT_PATH = (
        ROOT / "acceptance/wasm-float-target/artifacts/"
        "qualification-qemu-target-gate-v1-contract.json"
    )


def open_directory_chain(path: pathlib.Path, label: str) -> tuple[pathlib.Path, int]:
    selected = absolute_path(path, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open("/", flags)
        for part in selected.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} must be one direct directory")
        result = descriptor
        descriptor = None
        return selected, result
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
    )


def snapshot_directories(
    paths: list[pathlib.Path], label: str
) -> dict[pathlib.Path, tuple[tuple[int, ...], tuple[str, ...]]]:
    result: dict[pathlib.Path, tuple[tuple[int, ...], tuple[str, ...]]] = {}
    for path in paths:
        selected = absolute_path(path, label)
        if selected in result:
            continue
        _opened, descriptor = open_directory_chain(selected, label)
        try:
            result[selected] = (
                metadata_identity(os.fstat(descriptor)),
                tuple(sorted(os.listdir(descriptor))),
            )
        finally:
            os.close(descriptor)
    return result


def reread_directories(
    snapshot: dict[pathlib.Path, tuple[tuple[int, ...], tuple[str, ...]]],
    label: str,
) -> None:
    for path, expected in sorted(snapshot.items(), key=lambda item: str(item[0])):
        _opened, descriptor = open_directory_chain(path, label)
        try:
            observed = (
                metadata_identity(os.fstat(descriptor)),
                tuple(sorted(os.listdir(descriptor))),
            )
        finally:
            os.close(descriptor)
        if observed != expected:
            fail(f"{label} directory changed: {path}")


def stable_regular_file(path: pathlib.Path, label: str, *, maximum: int) -> StableFile:
    if maximum <= 0:
        fail(f"{label} maximum must be positive")
    selected = absolute_path(path, label)
    if not selected.name or selected.name in (".", ".."):
        fail(f"{label} basename is invalid")
    parent_descriptor: int | None = None
    descriptor: int | None = None
    reopened_parent: int | None = None
    try:
        _parent, parent_descriptor = open_directory_chain(
            selected.parent, f"{label} parent"
        )
        parent_before = os.fstat(parent_descriptor)
        path_before = os.stat(
            selected.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if not stat.S_ISREG(path_before.st_mode) or path_before.st_nlink != 1:
            fail(f"{label} must be a direct singly-linked regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOCTTY", 0)
        )
        descriptor = os.open(selected.name, flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{label} opened object must be singly-linked and regular")
        if not 0 < before.st_size <= maximum:
            fail(f"{label} byte length is outside (0, {maximum}]")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"{label} grew beyond {maximum} bytes while read")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(
            selected.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        _reopened_path, reopened_parent = open_directory_chain(
            selected.parent, f"{label} parent recheck"
        )
        parent_after = os.fstat(reopened_parent)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if reopened_parent is not None:
            os.close(reopened_parent)
    if metadata_identity(parent_before) != metadata_identity(parent_after):
        fail(f"{label} ancestor path changed while read")
    identities = {
        metadata_identity(path_before),
        metadata_identity(before),
        metadata_identity(after),
        metadata_identity(path_after),
    }
    if len(identities) != 1:
        fail(f"{label} changed while read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"{label} byte length changed while read")
    return StableFile(
        selected,
        raw,
        before.st_dev,
        before.st_ino,
        metadata_identity(before),
    )


def reread_exact(snapshot: StableFile, label: str, *, maximum: int) -> None:
    observed = stable_regular_file(snapshot.path, label, maximum=maximum)
    if (
        observed.raw != snapshot.raw
        or observed.device != snapshot.device
        or observed.inode != snapshot.inode
        or observed.metadata != snapshot.metadata
    ):
        fail(f"{label} changed after its verified snapshot")


def ensure_distinct_files(snapshots: dict[str, StableFile], *, label: str) -> None:
    identities = [(item.device, item.inode) for item in snapshots.values()]
    if len(identities) != len(set(identities)):
        fail(f"{label} must use distinct direct file inodes")


def write_json_no_clobber(path: pathlib.Path, value: object) -> bytes:
    rendered = canonical_json(value)
    if not 0 < len(rendered) <= MAX_DECISION_BYTES:
        fail("derived decision exceeds its byte bound")
    selected = absolute_path(path, "decision output")
    if not selected.name or selected.name in (".", ".."):
        fail("decision output basename is invalid")
    directory_descriptor: int | None = None
    descriptor: int | None = None
    temporary = ""
    try:
        _parent, directory_descriptor = open_directory_chain(
            selected.parent, "decision output parent"
        )
        parent_before = os.fstat(directory_descriptor)
        try:
            os.stat(selected.name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"refusing to clobber existing decision output: {selected}")
        for _attempt in range(128):
            candidate = f".{selected.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_NOCTTY", 0),
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            temporary = candidate
            break
        if descriptor is None or not temporary:
            fail("cannot allocate a private decision temporary file")
        written = 0
        while written < len(rendered):
            count = os.write(descriptor, rendered[written:])
            if count <= 0:
                fail("short write while publishing the decision")
            written += count
        os.fsync(descriptor)
        temporary_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_nlink != 1
            or temporary_metadata.st_size != len(rendered)
        ):
            fail("decision temporary file identity differs")
        os.close(descriptor)
        descriptor = None
        try:
            os.link(
                temporary,
                selected.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            fail(f"refusing to clobber existing decision output: {selected}")
        os.unlink(temporary, dir_fd=directory_descriptor)
        temporary = ""
        os.fsync(directory_descriptor)
        _reopened, reopened_descriptor = open_directory_chain(
            selected.parent, "decision output parent recheck"
        )
        try:
            if directory_identity(parent_before) != directory_identity(
                os.fstat(reopened_descriptor)
            ):
                fail("decision output parent changed during publication")
        finally:
            os.close(reopened_descriptor)
    except OSError as error:
        fail(f"cannot publish decision output: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
            os.close(directory_descriptor)
    published = stable_regular_file(
        selected, "published decision output", maximum=MAX_DECISION_BYTES
    )
    if published.raw != rendered:
        fail("published decision differs from the canonical derived bytes")
    return rendered


def write_private_blob_no_clobber(
    path: pathlib.Path,
    raw: bytes,
    *,
    mode: int,
    label: str,
    maximum: int = MAX_SOURCE_BYTES,
) -> StableFile:
    if not raw or len(raw) > maximum:
        fail(f"{label} bytes are outside the private-copy bound")
    if mode not in (0o400, 0o500, 0o600, 0o700):
        fail(f"{label} private mode is not allowed")
    selected = absolute_path(path, label)
    directory_descriptor: int | None = None
    descriptor: int | None = None
    try:
        _parent, directory_descriptor = open_directory_chain(
            selected.parent, f"{label} parent"
        )
        descriptor = os.open(
            selected.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOCTTY", 0),
            mode,
            dir_fd=directory_descriptor,
        )
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                fail(f"short write while creating {label}")
            written += count
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            fail(f"{label} private copy identity differs")
        os.fsync(directory_descriptor)
    except OSError as error:
        fail(f"cannot create {label}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    snapshot = stable_regular_file(selected, label, maximum=maximum)
    if snapshot.raw != raw or stat.S_IMODE(snapshot.metadata[2]) != mode:
        fail(f"{label} private copy bytes or mode differ")
    return snapshot


def validate_contract_value(value: object) -> dict[str, object]:
    contract = exact_keys(value, CONTRACT_ROOT_KEYS, "target-gate contract")
    exact_literal(
        contract["schema"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1.contract",
        "contract.schema",
    )
    exact_literal(contract["version"], 1, "contract.version")
    exact_literal(
        contract["suite_id"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1",
        "contract.suite_id",
    )
    exact_literal(
        contract["scope"],
        "c88-f5-formal-fixed-qemu-target-gate-replacement-only",
        "contract.scope",
    )
    exact_literal(
        contract["status"], "decision-contract-not-evidence", "contract.status"
    )
    exact_literal(contract["effectivity"], EXPECTED_EFFECTIVITY, "contract.effectivity")
    decision_id = exact_keys(
        contract["decision_id"],
        {"algorithm", "domain_ascii", "domain_nul_terminated", "nul_separated_fields"},
        "contract.decision_id",
    )
    exact_literal(decision_id["algorithm"], "sha256", "contract decision algorithm")
    exact_literal(
        decision_id["domain_ascii"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1.decision.v1",
        "contract decision domain",
    )
    exact_literal(decision_id["domain_nul_terminated"], True, "contract decision NUL")
    exact_literal(
        decision_id["nul_separated_fields"],
        DECISION_ID_FIELDS,
        "contract decision fields",
    )
    exact_literal(contract["policy"], EXPECTED_POLICY, "contract.policy")
    exact_literal(contract["precedence"], EXPECTED_PRECEDENCE, "contract.precedence")
    exact_literal(
        contract["source_provenance"],
        EXPECTED_SOURCE_PROVENANCE,
        "contract.source_provenance",
    )
    exact_literal(contract["publication"], EXPECTED_PUBLICATION, "contract.publication")
    exact_literal(
        contract["verification"], EXPECTED_VERIFICATION, "contract.verification"
    )
    exact_literal(
        contract["decision_verifier"],
        EXPECTED_DECISION_VERIFIER,
        "contract.decision_verifier",
    )
    exact_literal(contract["pinned_files"], PINNED_FILES, "contract.pinned_files")
    exact_literal(
        contract["retained_duo_files"],
        RETAINED_DUO_FILES,
        "contract.retained_duo_files",
    )
    exact_literal(contract["platform"], EXPECTED_PLATFORM, "contract.platform")
    exact_literal(
        contract["qualification"], EXPECTED_QUALIFICATION, "contract.qualification"
    )
    exact_literal(
        contract["required_verified_decision_outcome"],
        EXPECTED_OUTCOME,
        "contract.required_verified_decision_outcome",
    )
    exact_literal(contract["limitations"], EXPECTED_LIMITATIONS, "contract.limitations")
    return contract


def load_contract() -> tuple[dict[str, object], StableFile]:
    snapshot = stable_regular_file(
        CONTRACT_PATH, "target-gate contract", maximum=MAX_CONTRACT_BYTES
    )
    if identity_for(snapshot.raw) != {
        "sha256": EXPECTED_CONTRACT_SHA256,
        "bytes": EXPECTED_CONTRACT_BYTES,
    }:
        fail("target-gate contract bytes differ from the verifier pin")
    contract = validate_contract_value(
        strict_json(snapshot.raw, "target-gate contract")
    )
    return contract, snapshot


def load_pinned_files(
    contract: dict[str, object],
) -> dict[str, StableFile]:
    pinned = exact_keys(
        contract["pinned_files"], set(PINNED_FILES), "contract.pinned_files"
    )
    snapshots: dict[str, StableFile] = {}
    for role in sorted(PINNED_FILES):
        record = identity_record(pinned[role], f"contract.pinned_files.{role}")
        relative = pathlib.PurePosixPath(str(record["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            fail(f"contract pinned path is not repository-relative: {role}")
        snapshot = stable_regular_file(
            ROOT / pathlib.Path(*relative.parts),
            f"pinned {role}",
            maximum=MAX_SOURCE_BYTES,
        )
        if identity_for(snapshot.raw) != {
            "sha256": record["sha256"],
            "bytes": record["bytes"],
        }:
            fail(f"pinned {role} bytes differ from the target-gate contract")
        snapshots[role] = snapshot
    ensure_distinct_files(snapshots, label="pinned target-gate files")
    return snapshots


def load_retained_duo_files(
    contract: dict[str, object],
) -> dict[str, StableFile]:
    retained = exact_keys(
        contract["retained_duo_files"],
        set(RETAINED_DUO_FILES),
        "contract.retained_duo_files",
    )
    snapshots: dict[str, StableFile] = {}
    for role in sorted(RETAINED_DUO_FILES):
        record = retained_identity_record(
            retained[role], f"contract.retained_duo_files.{role}"
        )
        relative = pathlib.PurePosixPath(str(record["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            fail(f"retained Duo path is not repository-relative: {role}")
        snapshot = stable_regular_file(
            ROOT / pathlib.Path(*relative.parts),
            f"retained Duo {role}",
            maximum=MAX_SOURCE_BYTES,
        )
        if identity_for(snapshot.raw) != {
            "sha256": record["sha256"],
            "bytes": record["bytes"],
        }:
            fail(f"retained Duo {role} bytes differ from the contract")
        snapshots[role] = snapshot
    ensure_distinct_files(snapshots, label="retained Duo contract files")
    return snapshots


def load_shared_verifier(snapshot: StableFile) -> types.ModuleType:
    expected = PINNED_FILES["shared_verifier"]
    if identity_for(snapshot.raw) != {
        "sha256": expected["sha256"],
        "bytes": expected["bytes"],
    }:
        fail("shared verifier bytes differ before module loading")
    name = "_vibeos_c88_f5_qemu_target_gate_shared_oracle"
    sys.modules.pop(name, None)
    module = types.ModuleType(name)
    module.__file__ = str(snapshot.path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(snapshot.raw, str(snapshot.path), "exec")
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    for symbol in (
        "VerificationError",
        "verify_uart_bytes",
        "run_bounded_command",
        "synthetic_fixture",
        "refresh_uart_identity",
        "refresh_evidence_identity",
        "refresh_elf_audit_identity",
    ):
        if not hasattr(module, symbol):
            fail(f"byte-pinned shared verifier omits required symbol: {symbol}")
    exact_literal(
        getattr(module, "EXPECTED_SEMANTIC_SHA256", None),
        EXPECTED_SEMANTIC_SHA256,
        "shared verifier semantic pin",
    )
    exact_literal(
        getattr(module, "EXPECTED_MANIFEST_SHA256", None),
        PINNED_FILES["qualification_manifest"]["sha256"],
        "shared verifier manifest pin",
    )
    return module


def git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def git_output(arguments: list[str], label: str, *, maximum: int = 4 << 20) -> bytes:
    command = [
        "/usr/bin/git",
        "--no-pager",
        "-c",
        "color.ui=false",
        "-c",
        "core.fsmonitor=false",
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"cannot run sanitized Git for {label}: {error}")
    if len(completed.stdout) + len(completed.stderr) > maximum:
        fail(f"sanitized Git {label} exceeded its output bound")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"sanitized Git {label} failed: {detail or completed.returncode}")
    return completed.stdout


def git_line(arguments: list[str], label: str) -> str:
    raw = git_output(arguments, label, maximum=64 * 1024)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        fail(f"sanitized Git {label} did not emit one line")
    try:
        return raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"sanitized Git {label} output is not ASCII: {error}")


def git_blob_oid(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def verify_git_blob(
    source_commit: str,
    relative: str,
    raw: bytes,
    label: str,
    *,
    expected_mode: str = "100644",
) -> None:
    if (
        not relative
        or relative.startswith("/")
        or ".." in pathlib.PurePosixPath(relative).parts
    ):
        fail(f"{label} source path is not repository-relative")
    listing = git_output(
        ["ls-tree", "-z", source_commit, "--", relative],
        f"{label} source membership",
        maximum=64 * 1024,
    )
    suffix = f"\t{relative}\0".encode("utf-8")
    if listing.count(b"\0") != 1 or not listing.endswith(suffix):
        fail(f"{label} is not one exact source-commit blob")
    header = listing[: -len(suffix)].decode("ascii", errors="strict").split(" ")
    if len(header) != 3 or header[0] != expected_mode or header[1] != "blob":
        fail(f"{label} source mode or object kind differs")
    if header[2] != git_blob_oid(raw):
        fail(f"{label} bytes differ from the source-commit blob")


def verify_live_source(
    source: dict[str, object],
    contract_snapshot: StableFile,
    pinned: dict[str, StableFile],
    retained_duo: dict[str, StableFile],
    decision_verifier_snapshot: StableFile,
) -> dict[str, object]:
    source_commit = canonical_hex(source.get("commit"), HEX40, "source.commit")
    source_tree = canonical_hex(source.get("tree"), HEX40, "source.tree")
    exact_literal(source.get("clean"), True, "source.clean")
    exact_literal(source.get("branch"), "codex/wasm", "source.branch")
    exact_literal(
        source.get("remote_ref"),
        "refs/remotes/origin/codex/wasm",
        "source.remote_ref",
    )
    exact_literal(source.get("remote_commit"), source_commit, "source.remote_commit")
    exact_literal(
        git_line(["rev-parse", "--verify", "HEAD^{commit}"], "live HEAD"),
        source_commit,
        "live HEAD",
    )
    exact_literal(
        git_line(["rev-parse", "--verify", "HEAD^{tree}"], "live HEAD tree"),
        source_tree,
        "live HEAD tree",
    )
    exact_literal(
        git_line(
            ["rev-parse", "--verify", f"{source_commit}^{{tree}}"],
            "recorded source tree",
        ),
        source_tree,
        "recorded source tree",
    )
    exact_literal(
        git_line(["symbolic-ref", "--quiet", "--short", "HEAD"], "live branch"),
        "codex/wasm",
        "live source branch",
    )
    exact_literal(
        git_line(
            [
                "rev-parse",
                "--verify",
                "refs/remotes/origin/codex/wasm^{commit}",
            ],
            "local origin tracking ref",
        ),
        source_commit,
        "local origin tracking ref",
    )
    if git_output(
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "live repository status",
    ):
        fail("formal target-gate publication requires a clean repository")
    files: list[tuple[str, str, bytes, str]] = [
        (
            "target-gate contract",
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-contract.json",
            contract_snapshot.raw,
            "100644",
        ),
        (
            "target-gate verifier",
            "scripts/verify-c88-f5-qemu-target-gate.py",
            decision_verifier_snapshot.raw,
            "100644",
        ),
    ]
    for role, snapshot in sorted(pinned.items()):
        files.append(
            (
                f"pinned {role}",
                str(PINNED_FILES[role]["path"]),
                snapshot.raw,
                "100644",
            )
        )
    for role, snapshot in sorted(retained_duo.items()):
        files.append(
            (
                f"retained Duo {role}",
                str(RETAINED_DUO_FILES[role]["path"]),
                snapshot.raw,
                str(RETAINED_DUO_FILES[role]["git_mode"]),
            )
        )
    for label, relative, raw, mode in files:
        verify_git_blob(source_commit, relative, raw, label, expected_mode=mode)
    return {
        "commit": source_commit,
        "tree": source_tree,
        "clean": True,
        "branch": "codex/wasm",
        "local_tracking_ref": "refs/remotes/origin/codex/wasm",
        "local_tracking_ref_commit": source_commit,
        "claim": "clean-head-equals-local-origin-tracking-ref",
        "remote_advertised_oid_proven": False,
    }


def match_actual_role(
    environment: dict[str, object], role: str, snapshot: StableFile, label: str
) -> dict[str, object]:
    expected = role_identity(environment.get(role), f"environment.{role}")
    actual = identity_for(snapshot.raw)
    if actual != expected:
        fail(f"actual relocated {label} identity differs from environment role")
    return actual


def match_pinned_environment_roles(
    environment: dict[str, object], contract: dict[str, object]
) -> dict[str, dict[str, object]]:
    role_map = {
        "qualification_manifest": "manifest",
        "runner": "runner",
        "shared_verifier": "verifier",
        "elf_auditor": "elf_auditor",
        "producer": "producer",
        "qualification": "qualification",
    }
    pinned = exact_keys(
        contract["pinned_files"], set(PINNED_FILES), "contract.pinned_files"
    )
    result: dict[str, dict[str, object]] = {}
    for contract_role, environment_role in role_map.items():
        expected = identity_record(
            pinned[contract_role], f"contract.pinned_files.{contract_role}"
        )
        observed = role_identity(
            environment.get(environment_role), f"environment.{environment_role}"
        )
        exact_literal(
            observed,
            {"sha256": expected["sha256"], "bytes": expected["bytes"]},
            f"environment pinned role {environment_role}",
        )
        result[contract_role] = observed
    return result


def validate_verified_transcript(
    verified: object,
    environment: dict[str, object],
    *,
    expected_semantic_sha256: str,
) -> dict[str, object]:
    semantic = getattr(verified, "semantic_sha256", None)
    exact_literal(semantic, expected_semantic_sha256, "verified semantic digest")
    records = getattr(verified, "records", None)
    if type(records) is not tuple or len(records) != EXPECTED_RECORDS["total"]:
        fail("verified transcript does not contain exactly 1,176 records")
    metadata = getattr(verified, "metadata", None)
    if type(metadata) is not dict:
        fail("verified transcript metadata is absent")
    expected_meta = {
        "artifact_profile_code": 5,
        "artifact_abi": 5,
        "component_profile": 2,
        "core_profile": 2,
        "runtime_abi": 5,
        "stage": "validation-only",
        "runtime_ready": False,
        "native_async_runtime_ready": False,
        "execution_enabled": False,
        "current_validation_engine": False,
        "current_component_engine": False,
        "candidate_production_ready": False,
        "core_cases": 146,
        "f3_cases": 13,
        "f4_vectors": 12,
        "fuel_records": 1_000,
        "lifecycle_records": 5,
        "records": 1_176,
        "physical_provenance": "not-claimed",
    }
    for key, expected in expected_meta.items():
        exact_literal(metadata.get(key), expected, f"verified META.{key}")
    exact_literal(
        metadata.get("source_commit"),
        exact_keys(
            environment.get("source"),
            {"commit", "tree", "clean", "branch", "remote_ref", "remote_commit"},
            "environment.source",
        )["commit"],
        "verified META.source_commit",
    )
    return metadata


def validate_platform_and_audit(
    environment: dict[str, object], contract: dict[str, object]
) -> dict[str, object]:
    platform = exact_keys(
        environment.get("platform"),
        {"id", "class", "target", "physical_provenance"},
        "environment.platform",
    )
    expected_platform = exact_keys(
        contract["platform"],
        {
            "id",
            "class",
            "target",
            "physical_provenance",
            "qemu",
            "opensbi",
            "argv_semantics",
            "runtime_custody",
        },
        "contract.platform",
    )
    exact_literal(
        platform,
        {
            "id": expected_platform["id"],
            "class": expected_platform["class"],
            "target": expected_platform["target"],
            "physical_provenance": expected_platform["physical_provenance"],
        },
        "formal QEMU platform",
    )
    qemu = exact_keys(
        environment.get("qemu"),
        {"path", "sha256", "bytes", "version", "argv"},
        "environment.qemu",
    )
    expected_qemu = exact_keys(
        expected_platform["qemu"],
        {"path", "sha256", "bytes", "version"},
        "contract.platform.qemu",
    )
    exact_literal(qemu.get("sha256"), expected_qemu["sha256"], "QEMU SHA-256")
    exact_literal(qemu.get("bytes"), expected_qemu["bytes"], "QEMU bytes")
    exact_literal(qemu.get("version"), expected_qemu["version"], "QEMU version")
    bios = identity_record(environment.get("bios"), "environment.bios")
    expected_bios = identity_record(
        expected_platform["opensbi"], "contract.platform.opensbi"
    )
    exact_literal(
        {"sha256": bios["sha256"], "bytes": bios["bytes"]},
        {"sha256": expected_bios["sha256"], "bytes": expected_bios["bytes"]},
        "OpenSBI identity",
    )
    exact_literal(
        expected_platform["runtime_custody"],
        EXPECTED_PLATFORM["runtime_custody"],
        "platform runtime-custody limitations",
    )
    audit = exact_keys(
        environment.get("elf_audit"),
        {
            "checks",
            "elf",
            "execution_scope",
            "mode",
            "schema",
            "schema_version",
            "status",
            "target",
            "toolchain",
        },
        "environment.elf_audit",
    )
    elf = exact_keys(
        audit["elf"],
        {
            "bytes",
            "control_flow",
            "e_flags",
            "entry",
            "executable_sections",
            "forbidden_opcodes",
            "program_headers",
            "riscv_arch",
            "sections",
            "sha256",
            "symbols",
        },
        "environment.elf_audit.elf",
    )
    symbols = exact_keys(
        elf["symbols"],
        {
            "code_symbols",
            "defined",
            "forbidden_helpers",
            "raw_symtab_entries",
            "undefined",
        },
        "environment.elf_audit.elf.symbols",
    )
    exact_literal(audit["status"], "pass", "ELF audit status")
    exact_literal(elf["forbidden_opcodes"], [], "ELF forbidden opcodes")
    exact_literal(symbols["undefined"], 0, "ELF undefined symbols")
    exact_literal(symbols["forbidden_helpers"], [], "ELF forbidden helpers")
    checks = audit["checks"]
    if type(checks) is not list:
        fail("ELF audit checks must be one list")
    for required in ("static-no-relocations", "section-and-segment-wx"):
        if required not in checks:
            fail(f"ELF audit omits required check: {required}")
    exact_literal(
        audit["execution_scope"],
        [
            "trusted-native-control-flow",
            "canonical-decoder-boundaries",
            "arbitrary-PC-redirection-not-claimed",
            "hardware-NX-not-claimed",
        ],
        "ELF audit execution scope",
    )
    control_flow = exact_keys(
        elf["control_flow"],
        {"canonical_boundaries", "direct_targets"},
        "environment.elf_audit.elf.control_flow",
    )
    return {
        "status": "pass",
        "static_no_relocations": True,
        "section_and_segment_wx": True,
        "forbidden_opcodes": 0,
        "undefined_symbols": 0,
        "forbidden_float_helpers": 0,
        "decoded_instructions": sum(
            positive_integer(section["instructions"], "ELF section instructions")
            for section in elf["executable_sections"]
        ),
        "canonical_boundaries": positive_integer(
            control_flow["canonical_boundaries"], "ELF canonical boundaries"
        ),
        "direct_targets": positive_integer(
            control_flow["direct_targets"], "ELF direct targets"
        ),
        "code_symbols": positive_integer(symbols["code_symbols"], "ELF code symbols"),
        "trusted_native_control_flow_only": True,
        "canonical_decoder_boundaries_only": True,
        "arbitrary_pc_redirection_claimed": False,
        "hardware_nx_claimed": False,
    }


def decision_id(fields: dict[str, str]) -> str:
    if list(fields) != DECISION_ID_FIELDS:
        fail("decision ID fields are missing or reordered")
    encoded: list[bytes] = []
    for name in DECISION_ID_FIELDS:
        value = fields[name]
        pattern = HEX40 if name in ("source_commit", "source_tree") else HEX64
        canonical_hex(value, pattern, f"decision ID {name}")
        encoded.append(value.encode("ascii"))
    return sha256_bytes(DECISION_DOMAIN + b"\0".join(encoded))


def qualification_summary(
    metadata: dict[str, object], semantic_sha256: str, audit: dict[str, object]
) -> dict[str, object]:
    return {
        "suite_id": "vibeos.c88.f5.float-target",
        "mode": "formal-qemu",
        "target": "riscv64imac-unknown-none-elf",
        "semantic_sha256": semantic_sha256,
        "records": copy.deepcopy(EXPECTED_RECORDS),
        "artifact_profile_code": metadata["artifact_profile_code"],
        "artifact_abi": metadata["artifact_abi"],
        "component_profile": metadata["component_profile"],
        "core_profile": metadata["core_profile"],
        "runtime_abi": metadata["runtime_abi"],
        "stage": metadata["stage"],
        "runtime_ready": metadata["runtime_ready"],
        "native_async_runtime_ready": metadata["native_async_runtime_ready"],
        "execution_enabled": metadata["execution_enabled"],
        "current_validation_engine": metadata["current_validation_engine"],
        "current_component_engine": metadata["current_component_engine"],
        "candidate_production_ready": metadata["candidate_production_ready"],
        "elf_audit": audit,
    }


def derive_candidate(
    *,
    contract: dict[str, object],
    contract_snapshot: StableFile,
    decision_verifier_snapshot: StableFile,
    python_snapshot: StableFile,
    source_proof: dict[str, object],
    environment: dict[str, object],
    evidence: dict[str, dict[str, object]],
    metadata: dict[str, object],
    semantic_sha256: str,
    audit_summary: dict[str, object],
) -> dict[str, object]:
    source = exact_keys(
        environment["source"],
        {"commit", "tree", "clean", "branch", "remote_ref", "remote_commit"},
        "environment.source",
    )
    challenge = canonical_hex(environment.get("challenge"), HEX64, "challenge")
    run_id = canonical_hex(environment.get("run_id"), HEX64, "run_id")
    environment_evidence_sha256 = canonical_hex(
        environment.get("evidence_sha256"), HEX64, "environment.evidence_sha256"
    )
    verifier_identity = identity_for(decision_verifier_snapshot.raw)
    contract_identity = identity_for(contract_snapshot.raw)
    pinned = exact_keys(
        contract["pinned_files"], set(PINNED_FILES), "contract.pinned_files"
    )
    fields = {
        "source_commit": str(source["commit"]),
        "source_tree": str(source["tree"]),
        "challenge": challenge,
        "run_id": run_id,
        "contract_sha256": str(contract_identity["sha256"]),
        "decision_verifier_sha256": str(verifier_identity["sha256"]),
        "qualification_manifest_sha256": str(
            identity_record(
                pinned["qualification_manifest"],
                "contract.pinned_files.qualification_manifest",
            )["sha256"]
        ),
        "runner_sha256": str(
            identity_record(pinned["runner"], "contract.pinned_files.runner")["sha256"]
        ),
        "shared_verifier_sha256": str(
            identity_record(
                pinned["shared_verifier"], "contract.pinned_files.shared_verifier"
            )["sha256"]
        ),
        "elf_auditor_sha256": str(
            identity_record(pinned["elf_auditor"], "contract.pinned_files.elf_auditor")[
                "sha256"
            ]
        ),
        "kernel_sha256": str(evidence["kernel"]["sha256"]),
        "uart_sha256": str(evidence["uart"]["sha256"]),
        "elf_audit_sha256": str(evidence["elf_audit"]["sha256"]),
        "environment_sha256": str(evidence["environment"]["sha256"]),
        "environment_evidence_sha256": environment_evidence_sha256,
        "semantic_sha256": semantic_sha256,
    }
    content = {
        "suite_id": "vibeos.c88.f5.float-target.qemu-target-gate-v1",
        "scope": "c88-f5-formal-fixed-qemu-target-gate-replacement-only",
        "decision_id": decision_id(fields),
        "decision_id_fields": fields,
        "source": copy.deepcopy(source_proof),
        "challenge": challenge,
        "run_id": run_id,
        "contract": {
            "path": (
                "acceptance/wasm-float-target/artifacts/"
                "qualification-qemu-target-gate-v1-contract.json"
            ),
            **contract_identity,
            "contract_status": "decision-contract-not-evidence",
        },
        "decision_verifier": {
            "path": "scripts/verify-c88-f5-qemu-target-gate.py",
            **verifier_identity,
            "source_commit_blob_verified": True,
        },
        "python_interpreter": identity_for(python_snapshot.raw),
        "pinned_files": copy.deepcopy(pinned),
        "retained_duo_files": copy.deepcopy(contract["retained_duo_files"]),
        "platform": copy.deepcopy(contract["platform"]),
        "precedence": copy.deepcopy(contract["precedence"]),
        "evidence": {
            **copy.deepcopy(evidence),
            "environment_evidence_sha256": environment_evidence_sha256,
            "recorded_input_paths_trusted": False,
            "relocated_role_hashes_verified": True,
            "physical_inputs": 0,
        },
        "qualification": qualification_summary(
            metadata, semantic_sha256, audit_summary
        ),
        "publication": {
            "input_bundle_atomic_publication": False,
            "stable_final_reread_required": True,
            "decision_no_clobber_publication_barrier": True,
            "required_verification_matrix": copy.deepcopy(contract["verification"]),
            "matrix_completion_required_before_effectivity": True,
        },
        "required_verified_decision_outcome": copy.deepcopy(
            contract["required_verified_decision_outcome"]
        ),
        "limitations": copy.deepcopy(contract["limitations"]),
    }
    return {
        "schema": "vibeos.c88.f5.float-target.qemu-target-gate-v1.candidate",
        "version": 1,
        "status": "candidate-not-effective",
        "content_sha256": sha256_bytes(
            CANDIDATE_CONTENT_DOMAIN + compact_json(content)
        ),
        "content": content,
    }


def _validate_gate_record(
    value: object, contract: dict[str, object], *, final: bool
) -> dict[str, object]:
    label = "target-gate decision" if final else "target-gate candidate"
    decision = exact_keys(
        value,
        {"schema", "version", "status", "content_sha256", "content"},
        label,
    )
    exact_literal(
        decision["schema"],
        (
            "vibeos.c88.f5.float-target.qemu-target-gate-v1.decision"
            if final
            else "vibeos.c88.f5.float-target.qemu-target-gate-v1.candidate"
        ),
        f"{label}.schema",
    )
    exact_literal(decision["version"], 1, f"{label}.version")
    exact_literal(
        decision["status"],
        "closed" if final else "candidate-not-effective",
        f"{label}.status",
    )
    outcome_key = "completion" if final else "required_verified_decision_outcome"
    content_keys = {
        "suite_id",
        "scope",
        "decision_id",
        "decision_id_fields",
        "source",
        "challenge",
        "run_id",
        "contract",
        "decision_verifier",
        "python_interpreter",
        "pinned_files",
        "retained_duo_files",
        "platform",
        "precedence",
        "evidence",
        "qualification",
        "publication",
        outcome_key,
        "limitations",
    }
    if final:
        content_keys.add("verification_matrix")
    content = exact_keys(
        decision["content"],
        content_keys,
        f"{label} content",
    )
    canonical_hex(decision["content_sha256"], HEX64, "decision.content_sha256")
    exact_literal(
        decision["content_sha256"],
        sha256_bytes(
            (CONTENT_DOMAIN if final else CANDIDATE_CONTENT_DOMAIN)
            + compact_json(content)
        ),
        "decision content address",
    )
    fields = exact_keys(
        content["decision_id_fields"], set(DECISION_ID_FIELDS), "decision ID fields"
    )
    ordered_fields = {name: fields[name] for name in DECISION_ID_FIELDS}
    exact_literal(content["decision_id"], decision_id(ordered_fields), "decision ID")
    challenge = canonical_hex(content["challenge"], HEX64, "decision challenge")
    run_id = canonical_hex(content["run_id"], HEX64, "decision run ID")
    exact_literal(fields["challenge"], challenge, "decision challenge binding")
    exact_literal(fields["run_id"], run_id, "decision run-ID binding")
    exact_literal(
        content["suite_id"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1",
        "decision suite",
    )
    exact_literal(
        content["scope"],
        "c88-f5-formal-fixed-qemu-target-gate-replacement-only",
        "decision scope",
    )
    exact_literal(content["platform"], contract["platform"], "decision platform")
    exact_literal(content["precedence"], contract["precedence"], "decision precedence")
    contract_record = exact_keys(
        content["contract"],
        {"path", "sha256", "bytes", "contract_status"},
        "decision contract identity",
    )
    exact_literal(
        contract_record["path"],
        (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-contract.json"
        ),
        "decision contract path",
    )
    exact_literal(
        contract_record["contract_status"],
        "decision-contract-not-evidence",
        "decision contract status",
    )
    identity_summary(
        {"sha256": contract_record["sha256"], "bytes": contract_record["bytes"]},
        "decision contract identity",
    )
    exact_literal(
        {"sha256": contract_record["sha256"], "bytes": contract_record["bytes"]},
        {"sha256": EXPECTED_CONTRACT_SHA256, "bytes": EXPECTED_CONTRACT_BYTES},
        "decision contract pin",
    )
    exact_literal(
        fields["contract_sha256"],
        contract_record["sha256"],
        "decision contract field binding",
    )
    verifier_record = exact_keys(
        content["decision_verifier"],
        {"path", "sha256", "bytes", "source_commit_blob_verified"},
        "decision verifier identity",
    )
    exact_literal(
        verifier_record["path"],
        "scripts/verify-c88-f5-qemu-target-gate.py",
        "decision verifier path",
    )
    exact_literal(
        verifier_record["source_commit_blob_verified"],
        True,
        "decision verifier source membership",
    )
    identity_summary(
        {"sha256": verifier_record["sha256"], "bytes": verifier_record["bytes"]},
        "decision verifier identity",
    )
    exact_literal(
        fields["decision_verifier_sha256"],
        verifier_record["sha256"],
        "decision verifier field binding",
    )
    identity_summary(content["python_interpreter"], "decision Python interpreter")
    exact_literal(
        content["pinned_files"], contract["pinned_files"], "decision pinned files"
    )
    exact_literal(
        content["retained_duo_files"],
        contract["retained_duo_files"],
        "decision retained Duo files",
    )
    pinned_field_map = {
        "qualification_manifest_sha256": "qualification_manifest",
        "runner_sha256": "runner",
        "shared_verifier_sha256": "shared_verifier",
        "elf_auditor_sha256": "elf_auditor",
    }
    for field_name, role in pinned_field_map.items():
        exact_literal(
            fields[field_name],
            contract["pinned_files"][role]["sha256"],
            f"decision pinned {role} field binding",
        )
    evidence = exact_keys(
        content["evidence"],
        {
            "kernel",
            "uart",
            "elf_audit",
            "environment",
            "environment_evidence_sha256",
            "recorded_input_paths_trusted",
            "relocated_role_hashes_verified",
            "physical_inputs",
        },
        "decision evidence",
    )
    exact_literal(evidence["recorded_input_paths_trusted"], False, "recorded paths")
    exact_literal(evidence["relocated_role_hashes_verified"], True, "role relocation")
    exact_literal(evidence["physical_inputs"], 0, "decision physical inputs")
    evidence_field_map = {
        "kernel": "kernel_sha256",
        "uart": "uart_sha256",
        "elf_audit": "elf_audit_sha256",
        "environment": "environment_sha256",
    }
    for role, field_name in evidence_field_map.items():
        record = identity_summary(evidence[role], f"decision evidence.{role}")
        exact_literal(
            fields[field_name], record["sha256"], f"decision {role} field binding"
        )
    environment_evidence_sha256 = canonical_hex(
        evidence["environment_evidence_sha256"],
        HEX64,
        "decision environment evidence digest",
    )
    exact_literal(
        fields["environment_evidence_sha256"],
        environment_evidence_sha256,
        "decision environment evidence field binding",
    )
    exact_literal(
        content[outcome_key],
        contract["required_verified_decision_outcome"],
        "decision outcome truth table",
    )
    exact_literal(
        content["limitations"], contract["limitations"], "decision limitations"
    )
    publication = exact_keys(
        content["publication"],
        {
            "input_bundle_atomic_publication",
            "stable_final_reread_required",
            "decision_no_clobber_publication_barrier",
            "required_verification_matrix",
            "matrix_completion_required_before_effectivity",
        },
        "decision publication",
    )
    exact_literal(
        publication["input_bundle_atomic_publication"], False, "bundle atomicity"
    )
    exact_literal(
        publication["stable_final_reread_required"], True, "stable final reread"
    )
    exact_literal(
        publication["decision_no_clobber_publication_barrier"],
        True,
        "decision publication barrier",
    )
    exact_literal(
        publication["required_verification_matrix"],
        contract["verification"],
        "decision verification matrix",
    )
    exact_literal(
        publication["matrix_completion_required_before_effectivity"],
        True,
        "decision matrix effectivity",
    )
    source = exact_keys(
        content["source"],
        {
            "commit",
            "tree",
            "clean",
            "branch",
            "local_tracking_ref",
            "local_tracking_ref_commit",
            "claim",
            "remote_advertised_oid_proven",
        },
        "decision source",
    )
    source_commit = canonical_hex(source["commit"], HEX40, "decision source commit")
    source_tree = canonical_hex(source["tree"], HEX40, "decision source tree")
    exact_literal(source["clean"], True, "decision source cleanliness")
    exact_literal(source["branch"], "codex/wasm", "decision source branch")
    exact_literal(
        source["local_tracking_ref"],
        "refs/remotes/origin/codex/wasm",
        "decision local tracking ref",
    )
    exact_literal(
        source["local_tracking_ref_commit"],
        source_commit,
        "decision local tracking ref commit",
    )
    exact_literal(
        source["claim"], "clean-head-equals-local-origin-tracking-ref", "source claim"
    )
    exact_literal(source["remote_advertised_oid_proven"], False, "remote OID claim")
    exact_literal(
        fields["source_commit"], source_commit, "decision source-commit field"
    )
    exact_literal(fields["source_tree"], source_tree, "decision source-tree field")
    qualification = exact_keys(
        content["qualification"],
        {
            "suite_id",
            "mode",
            "target",
            "semantic_sha256",
            "records",
            "artifact_profile_code",
            "artifact_abi",
            "component_profile",
            "core_profile",
            "runtime_abi",
            "stage",
            "runtime_ready",
            "native_async_runtime_ready",
            "execution_enabled",
            "current_validation_engine",
            "current_component_engine",
            "candidate_production_ready",
            "elf_audit",
        },
        "decision qualification",
    )
    expected_qualification = {
        key: value
        for key, value in EXPECTED_QUALIFICATION.items()
        if key != "elf_requirements"
    }
    expected_qualification["elf_audit"] = qualification["elf_audit"]
    exact_literal(
        qualification, expected_qualification, "decision qualification contract"
    )
    exact_literal(
        fields["semantic_sha256"],
        EXPECTED_SEMANTIC_SHA256,
        "decision semantic field binding",
    )
    audit_summary = exact_keys(
        qualification["elf_audit"],
        {
            "status",
            "static_no_relocations",
            "section_and_segment_wx",
            "forbidden_opcodes",
            "undefined_symbols",
            "forbidden_float_helpers",
            "decoded_instructions",
            "canonical_boundaries",
            "direct_targets",
            "code_symbols",
            "trusted_native_control_flow_only",
            "canonical_decoder_boundaries_only",
            "arbitrary_pc_redirection_claimed",
            "hardware_nx_claimed",
        },
        "decision ELF-audit summary",
    )
    for key, expected in EXPECTED_ELF_REQUIREMENTS.items():
        exact_literal(audit_summary[key], expected, f"decision ELF-audit {key}")
    for key in (
        "decoded_instructions",
        "canonical_boundaries",
        "direct_targets",
        "code_symbols",
    ):
        positive_integer(audit_summary[key], f"decision ELF-audit {key}")
    if final:
        validate_matrix_summary(content["verification_matrix"], content, contract)
    return decision


def validate_candidate_safety(
    value: object, contract: dict[str, object]
) -> dict[str, object]:
    return _validate_gate_record(value, contract, final=False)


def validate_decision_safety(
    value: object, contract: dict[str, object]
) -> dict[str, object]:
    return _validate_gate_record(value, contract, final=True)


def actual_interpreter_snapshot() -> StableFile:
    try:
        path = pathlib.Path(sys.executable).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve Python interpreter: {error}")
    return stable_regular_file(path, "Python interpreter", maximum=MAX_KERNEL_BYTES)


def optimization_mode() -> tuple[str, int]:
    level = sys.flags.optimize
    if level == 0:
        return "normal", 0
    if level == 1:
        return "optimized", 1
    fail("target-gate matrix permits Python normal and -O modes only")


def rerun_elf_auditor_in_current_mode(
    *,
    shared: types.ModuleType,
    kernel_snapshot: StableFile,
    expected_report: bytes,
    environment: dict[str, object],
    auditor_snapshot: StableFile,
    toolchain_snapshot: StableFile,
) -> dict[str, object]:
    mode, level = optimization_mode()
    build_tools = environment.get("build_tools")
    if type(build_tools) is not dict:
        fail("environment.build_tools is not one object for matrix audit")
    rustup = identity_record(
        build_tools.get("rustup"), "environment.build_tools.rustup"
    )
    rustup_path = pathlib.Path(str(rustup["path"]))
    home = os.environ.get("HOME")
    if not home or not os.path.isabs(home):
        fail("matrix ELF auditor requires the unchanged absolute process HOME")
    audit_environment = {
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join((str(rustup_path.parent), "/usr/bin", "/bin")),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    with tempfile.TemporaryDirectory(
        prefix=f"vibeos-c88-f5-target-gate-{mode}-audit-", dir="/private/tmp"
    ) as temporary_name:
        private_root = pathlib.Path(temporary_name)
        private_inputs_root = private_root / "inputs"
        private_scripts = private_inputs_root / "scripts"
        private_output_root = private_root / "output"
        try:
            os.chmod(private_root, 0o700)
            os.mkdir(private_inputs_root, 0o700)
            os.mkdir(private_scripts, 0o700)
            os.mkdir(private_output_root, 0o700)
        except OSError as error:
            fail(f"cannot create private {mode} auditor directory: {error}")
        private_auditor = write_private_blob_no_clobber(
            private_scripts / "verify-c88-f5-riscv-elf.py",
            auditor_snapshot.raw,
            mode=0o500,
            label=f"private {mode} ELF auditor",
        )
        private_toolchain = write_private_blob_no_clobber(
            private_inputs_root / "rust-toolchain.toml",
            toolchain_snapshot.raw,
            mode=0o400,
            label=f"private {mode} rust-toolchain contract",
        )
        try:
            root_seal = os.stat(private_root, follow_symlinks=False)
            inputs_seal = os.stat(private_inputs_root, follow_symlinks=False)
            scripts_seal = os.stat(private_scripts, follow_symlinks=False)
        except OSError as error:
            fail(f"cannot seal private {mode} auditor inputs: {error}")
        verify_private_stage(
            private_root,
            root_seal,
            {"inputs", "output"},
            f"sealed private {mode} auditor root",
        )
        verify_private_stage(
            private_inputs_root,
            inputs_seal,
            {"scripts", "rust-toolchain.toml"},
            f"sealed private {mode} auditor inputs",
        )
        verify_private_stage(
            private_scripts,
            scripts_seal,
            {"verify-c88-f5-riscv-elf.py"},
            f"sealed private {mode} auditor scripts",
        )
        command = [
            str(pathlib.Path(sys.executable).resolve(strict=True)),
            "-I",
            "-B",
        ]
        if level == 1:
            command.append("-O")
        command.extend(
            [
                str(private_auditor.path),
                "--elf",
                str(kernel_snapshot.path),
            ]
        )
        output = private_output_root / "audit.json"
        command.extend(("--output", str(output)))
        try:
            completed = shared.run_bounded_command(
                command,
                cwd=ROOT,
                environment=audit_environment,
                maximum_output=MAX_ELF_AUDIT_BYTES,
                timeout_seconds=600.0,
            )
        except shared.VerificationError as error:
            fail(f"{mode} matrix ELF auditor could not run: {error}")
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).decode(
                "utf-8", errors="replace"
            )
            fail(f"{mode} matrix ELF auditor rejected the kernel: {detail.strip()}")
        if completed.stdout or completed.stderr:
            fail(f"successful {mode} matrix ELF auditor emitted process output")
        verify_private_stage(
            private_root,
            root_seal,
            {"inputs", "output"},
            f"final sealed private {mode} auditor root",
        )
        verify_private_stage(
            private_inputs_root,
            inputs_seal,
            {"scripts", "rust-toolchain.toml"},
            f"final sealed private {mode} auditor inputs",
        )
        verify_private_stage(
            private_scripts,
            scripts_seal,
            {"verify-c88-f5-riscv-elf.py"},
            f"final sealed private {mode} auditor scripts",
        )
        replay = stable_regular_file(
            output, f"{mode} matrix ELF-audit replay", maximum=MAX_ELF_AUDIT_BYTES
        )
        if replay.raw != expected_report:
            fail(f"{mode} matrix ELF-audit replay differs from retained report")
        reread_exact(
            private_auditor,
            f"final private {mode} ELF auditor",
            maximum=MAX_SOURCE_BYTES,
        )
        reread_exact(
            private_toolchain,
            f"final private {mode} rust-toolchain contract",
            maximum=MAX_SOURCE_BYTES,
        )
        try:
            output_seal = os.stat(private_output_root, follow_symlinks=False)
        except OSError as error:
            fail(f"cannot seal private {mode} auditor output: {error}")
        verify_private_stage(
            private_output_root,
            output_seal,
            {"audit.json"},
            f"final private {mode} auditor output",
        )
        reread_exact(
            replay,
            f"final private {mode} ELF-audit replay",
            maximum=MAX_ELF_AUDIT_BYTES,
        )
    return {
        "status": "pass",
        "report": identity_for(expected_report),
        "kernel": identity_for(kernel_snapshot.raw),
        "optimization_mode": mode,
        "optimization_level": level,
    }


def derive_mode_receipt(
    *,
    candidate_raw: bytes,
    candidate: dict[str, object],
    decision_verifier_snapshot: StableFile,
    python_snapshot: StableFile,
    pinned: dict[str, StableFile],
    evidence: dict[str, dict[str, object]],
    semantic_sha256: str,
    records: int,
    audit_result: dict[str, object],
    publisher_challenge_sha256: str,
) -> dict[str, object]:
    mode, level = optimization_mode()
    candidate_content = candidate.get("content")
    if type(candidate_content) is not dict:
        fail("mode receipt candidate content is not one object")
    source = candidate_content.get("source")
    if type(source) is not dict:
        fail("mode receipt candidate source is not one object")
    content = {
        "suite_id": "vibeos.c88.f5.float-target.qemu-target-gate-v1",
        "optimization_mode": mode,
        "optimization_level": level,
        "publisher_challenge_sha256": canonical_hex(
            publisher_challenge_sha256,
            HEX64,
            "publisher challenge digest",
        ),
        "candidate": identity_for(candidate_raw),
        "candidate_decision_id": candidate_content["decision_id"],
        "candidate_content_sha256": candidate["content_sha256"],
        "source": {"commit": source["commit"], "tree": source["tree"]},
        "decision_verifier": identity_for(decision_verifier_snapshot.raw),
        "python_interpreter": identity_for(python_snapshot.raw),
        "shared_verifier": {
            "identity": identity_for(pinned["shared_verifier"].raw),
            "status": "pass",
            "semantic_sha256": semantic_sha256,
            "records": records,
            "uart": copy.deepcopy(evidence["uart"]),
            "environment": copy.deepcopy(evidence["environment"]),
            "optimization_mode": mode,
            "optimization_level": level,
        },
        "elf_auditor": {
            "identity": identity_for(pinned["elf_auditor"].raw),
            **copy.deepcopy(audit_result),
        },
        "evidence": copy.deepcopy(evidence),
        "physical_inputs": 0,
    }
    return {
        "schema": "vibeos.c88.f5.float-target.qemu-target-gate-v1.mode-receipt",
        "version": 1,
        "status": "pass",
        "content_sha256": sha256_bytes(
            MODE_RECEIPT_CONTENT_DOMAIN + compact_json(content)
        ),
        "content": content,
    }


def validate_mode_receipt(
    value: object,
    *,
    contract: dict[str, object],
    candidate_raw: bytes,
    candidate: dict[str, object],
    expected_mode: str,
    expected_challenge_sha256: str | None = None,
) -> dict[str, object]:
    expected_level = {"normal": 0, "optimized": 1}.get(expected_mode)
    if expected_level is None:
        fail("mode receipt expected mode is invalid")
    receipt = exact_keys(
        value,
        {"schema", "version", "status", "content_sha256", "content"},
        f"{expected_mode} mode receipt",
    )
    exact_literal(
        receipt["schema"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1.mode-receipt",
        f"{expected_mode} receipt schema",
    )
    exact_literal(receipt["version"], 1, f"{expected_mode} receipt version")
    exact_literal(receipt["status"], "pass", f"{expected_mode} receipt status")
    content = exact_keys(
        receipt["content"],
        {
            "suite_id",
            "optimization_mode",
            "optimization_level",
            "publisher_challenge_sha256",
            "candidate",
            "candidate_decision_id",
            "candidate_content_sha256",
            "source",
            "decision_verifier",
            "python_interpreter",
            "shared_verifier",
            "elf_auditor",
            "evidence",
            "physical_inputs",
        },
        f"{expected_mode} mode receipt content",
    )
    exact_literal(
        receipt["content_sha256"],
        sha256_bytes(MODE_RECEIPT_CONTENT_DOMAIN + compact_json(content)),
        f"{expected_mode} receipt content address",
    )
    exact_literal(
        content["suite_id"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1",
        f"{expected_mode} receipt suite",
    )
    exact_literal(
        content["optimization_mode"], expected_mode, f"{expected_mode} receipt mode"
    )
    exact_literal(
        content["optimization_level"],
        expected_level,
        f"{expected_mode} receipt optimization level",
    )
    observed_challenge = canonical_hex(
        content["publisher_challenge_sha256"],
        HEX64,
        f"{expected_mode} receipt publisher challenge digest",
    )
    if expected_challenge_sha256 is not None:
        exact_literal(
            observed_challenge,
            canonical_hex(
                expected_challenge_sha256,
                HEX64,
                "expected publisher challenge digest",
            ),
            f"{expected_mode} receipt publisher challenge binding",
        )
    exact_literal(
        content["candidate"],
        identity_for(candidate_raw),
        f"{expected_mode} receipt candidate identity",
    )
    candidate_content = candidate.get("content")
    if type(candidate_content) is not dict:
        fail("mode receipt candidate content is not one object")
    exact_literal(
        content["candidate_decision_id"],
        candidate_content["decision_id"],
        f"{expected_mode} receipt decision ID",
    )
    exact_literal(
        content["candidate_content_sha256"],
        candidate["content_sha256"],
        f"{expected_mode} receipt candidate content address",
    )
    source = exact_keys(
        content["source"], {"commit", "tree"}, f"{expected_mode} receipt source"
    )
    exact_literal(
        source,
        {
            "commit": candidate_content["source"]["commit"],
            "tree": candidate_content["source"]["tree"],
        },
        f"{expected_mode} receipt source binding",
    )
    exact_literal(
        content["decision_verifier"],
        {
            "sha256": candidate_content["decision_verifier"]["sha256"],
            "bytes": candidate_content["decision_verifier"]["bytes"],
        },
        f"{expected_mode} receipt verifier identity",
    )
    exact_literal(
        content["python_interpreter"],
        candidate_content["python_interpreter"],
        f"{expected_mode} receipt Python identity",
    )
    exact_literal(
        content["evidence"],
        {
            role: candidate_content["evidence"][role]
            for role in ("kernel", "elf_audit", "uart", "environment")
        },
        f"{expected_mode} receipt evidence identities",
    )
    exact_literal(content["physical_inputs"], 0, f"{expected_mode} physical inputs")
    shared_result = exact_keys(
        content["shared_verifier"],
        {
            "identity",
            "status",
            "semantic_sha256",
            "records",
            "uart",
            "environment",
            "optimization_mode",
            "optimization_level",
        },
        f"{expected_mode} shared-verifier receipt",
    )
    exact_literal(
        shared_result["identity"],
        {
            "sha256": contract["pinned_files"]["shared_verifier"]["sha256"],
            "bytes": contract["pinned_files"]["shared_verifier"]["bytes"],
        },
        f"{expected_mode} shared-verifier identity",
    )
    exact_literal(shared_result["status"], "pass", f"{expected_mode} shared status")
    exact_literal(
        shared_result["semantic_sha256"],
        EXPECTED_SEMANTIC_SHA256,
        f"{expected_mode} shared semantic digest",
    )
    exact_literal(
        shared_result["records"], EXPECTED_RECORDS["total"], f"{expected_mode} records"
    )
    exact_literal(
        shared_result["uart"],
        candidate_content["evidence"]["uart"],
        f"{expected_mode} shared UART identity",
    )
    exact_literal(
        shared_result["environment"],
        candidate_content["evidence"]["environment"],
        f"{expected_mode} shared environment identity",
    )
    exact_literal(
        shared_result["optimization_mode"],
        expected_mode,
        f"{expected_mode} shared mode",
    )
    exact_literal(
        shared_result["optimization_level"],
        expected_level,
        f"{expected_mode} shared optimization level",
    )
    audit_result = exact_keys(
        content["elf_auditor"],
        {
            "identity",
            "status",
            "report",
            "kernel",
            "optimization_mode",
            "optimization_level",
        },
        f"{expected_mode} ELF-auditor receipt",
    )
    exact_literal(
        audit_result["identity"],
        {
            "sha256": contract["pinned_files"]["elf_auditor"]["sha256"],
            "bytes": contract["pinned_files"]["elf_auditor"]["bytes"],
        },
        f"{expected_mode} ELF-auditor identity",
    )
    exact_literal(audit_result["status"], "pass", f"{expected_mode} audit status")
    exact_literal(
        audit_result["report"],
        candidate_content["evidence"]["elf_audit"],
        f"{expected_mode} audit report identity",
    )
    exact_literal(
        audit_result["kernel"],
        candidate_content["evidence"]["kernel"],
        f"{expected_mode} audited kernel identity",
    )
    exact_literal(
        audit_result["optimization_mode"], expected_mode, f"{expected_mode} audit mode"
    )
    exact_literal(
        audit_result["optimization_level"],
        expected_level,
        f"{expected_mode} audit optimization level",
    )
    return receipt


def candidate_from_final_content(content: dict[str, object]) -> dict[str, object]:
    candidate_content = copy.deepcopy(content)
    matrix = candidate_content.pop("verification_matrix", None)
    if type(matrix) is not dict:
        fail("closed decision omits its verification matrix")
    completion = candidate_content.pop("completion", None)
    if type(completion) is not dict:
        fail("closed decision omits its completion outcome")
    candidate_content["required_verified_decision_outcome"] = completion
    return {
        "schema": "vibeos.c88.f5.float-target.qemu-target-gate-v1.candidate",
        "version": 1,
        "status": "candidate-not-effective",
        "content_sha256": sha256_bytes(
            CANDIDATE_CONTENT_DOMAIN + compact_json(candidate_content)
        ),
        "content": candidate_content,
    }


def validate_matrix_summary(
    value: object,
    final_content: dict[str, object],
    contract: dict[str, object],
) -> dict[str, object]:
    matrix = exact_keys(
        value,
        {
            "schema",
            "version",
            "status",
            "modes",
            "publisher_challenge_sha256",
            "candidate",
            "normal_receipt",
            "optimized_receipt",
            "candidate_payload_byte_equal",
            "python_interpreter_identity_same",
            "shared_verifier_result_byte_equal",
            "elf_audit_report_byte_equal",
            "decision_verifier_both_modes",
            "shared_verifier_both_modes",
            "elf_auditor_both_modes",
            "physical_inputs",
        },
        "decision verification matrix",
    )
    exact_literal(
        matrix["schema"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1.matrix",
        "matrix schema",
    )
    exact_literal(matrix["version"], 1, "matrix version")
    exact_literal(matrix["status"], "pass", "matrix status")
    exact_literal(
        matrix["modes"],
        [
            {"optimization_mode": "normal", "optimization_level": 0},
            {"optimization_mode": "optimized", "optimization_level": 1},
        ],
        "matrix modes",
    )
    canonical_hex(
        matrix["publisher_challenge_sha256"],
        HEX64,
        "matrix publisher challenge digest",
    )
    reconstructed = candidate_from_final_content(final_content)
    validate_candidate_safety(reconstructed, contract)
    exact_literal(
        matrix["candidate"],
        identity_for(canonical_json(reconstructed)),
        "matrix candidate identity",
    )
    identity_summary(matrix["normal_receipt"], "matrix normal receipt")
    identity_summary(matrix["optimized_receipt"], "matrix optimized receipt")
    if matrix["normal_receipt"] == matrix["optimized_receipt"]:
        fail("normal and optimized mode receipts must be distinct")
    for key in (
        "candidate_payload_byte_equal",
        "python_interpreter_identity_same",
        "shared_verifier_result_byte_equal",
        "elf_audit_report_byte_equal",
        "decision_verifier_both_modes",
        "shared_verifier_both_modes",
        "elf_auditor_both_modes",
    ):
        exact_literal(matrix[key], True, f"matrix {key}")
    exact_literal(matrix["physical_inputs"], 0, "matrix physical inputs")
    return matrix


def close_candidate(
    *,
    contract: dict[str, object],
    candidate: dict[str, object],
    candidate_raw: bytes,
    normal_receipt_raw: bytes,
    optimized_receipt_raw: bytes,
    publisher_challenge_sha256: str,
) -> dict[str, object]:
    validate_candidate_safety(candidate, contract)
    normal_receipt = strict_json(normal_receipt_raw, "closing normal mode receipt")
    optimized_receipt = strict_json(
        optimized_receipt_raw, "closing optimized mode receipt"
    )
    if normal_receipt_raw != canonical_json(normal_receipt):
        fail("closing normal mode receipt is not canonical JSON")
    if optimized_receipt_raw != canonical_json(optimized_receipt):
        fail("closing optimized mode receipt is not canonical JSON")
    validate_mode_receipt(
        normal_receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode="normal",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    validate_mode_receipt(
        optimized_receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode="optimized",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    if normal_receipt_raw == optimized_receipt_raw:
        fail("closing matrix receipts must be distinct")
    content = copy.deepcopy(candidate["content"])
    if type(content) is not dict:
        fail("candidate content is not one object")
    required_outcome = content.pop("required_verified_decision_outcome", None)
    if type(required_outcome) is not dict:
        fail("candidate omits its required verified outcome")
    content["completion"] = required_outcome
    content["verification_matrix"] = {
        "schema": "vibeos.c88.f5.float-target.qemu-target-gate-v1.matrix",
        "version": 1,
        "status": "pass",
        "modes": [
            {"optimization_mode": "normal", "optimization_level": 0},
            {"optimization_mode": "optimized", "optimization_level": 1},
        ],
        "publisher_challenge_sha256": canonical_hex(
            publisher_challenge_sha256,
            HEX64,
            "publisher challenge digest",
        ),
        "candidate": identity_for(candidate_raw),
        "normal_receipt": identity_for(normal_receipt_raw),
        "optimized_receipt": identity_for(optimized_receipt_raw),
        "candidate_payload_byte_equal": True,
        "python_interpreter_identity_same": True,
        "shared_verifier_result_byte_equal": True,
        "elf_audit_report_byte_equal": True,
        "decision_verifier_both_modes": True,
        "shared_verifier_both_modes": True,
        "elf_auditor_both_modes": True,
        "physical_inputs": 0,
    }
    decision = {
        "schema": "vibeos.c88.f5.float-target.qemu-target-gate-v1.decision",
        "version": 1,
        "status": "closed",
        "content_sha256": sha256_bytes(CONTENT_DOMAIN + compact_json(content)),
        "content": content,
    }
    validate_decision_safety(decision, contract)
    return decision


def verify_formal_evidence(
    *,
    kernel_path: pathlib.Path,
    elf_audit_path: pathlib.Path,
    uart_path: pathlib.Path,
    environment_path: pathlib.Path,
    publisher_challenge_path: pathlib.Path,
) -> tuple[dict[str, object], dict[str, object]]:
    contract, contract_snapshot = load_contract()
    pinned = load_pinned_files(contract)
    retained_duo = load_retained_duo_files(contract)
    shared = load_shared_verifier(pinned["shared_verifier"])
    decision_verifier_snapshot = stable_regular_file(
        DECISION_VERIFIER_PATH,
        "target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    python_snapshot = actual_interpreter_snapshot()
    evidence_snapshots = {
        "kernel": stable_regular_file(
            kernel_path, "relocated kernel evidence", maximum=MAX_KERNEL_BYTES
        ),
        "elf_audit": stable_regular_file(
            elf_audit_path,
            "relocated ELF-audit evidence",
            maximum=MAX_ELF_AUDIT_BYTES,
        ),
        "uart": stable_regular_file(
            uart_path, "relocated UART evidence", maximum=MAX_UART_BYTES
        ),
        "environment": stable_regular_file(
            environment_path,
            "relocated environment evidence",
            maximum=MAX_ENVIRONMENT_BYTES,
        ),
    }
    challenge_snapshot = stable_regular_file(
        publisher_challenge_path,
        "publisher private challenge",
        maximum=64,
    )
    if len(challenge_snapshot.raw) != 32:
        fail("publisher private challenge must contain exactly 32 bytes")
    publisher_challenge_sha256 = sha256_bytes(
        PUBLISHER_CHALLENGE_DOMAIN + challenge_snapshot.raw
    )
    ensure_distinct_files(
        {**evidence_snapshots, "publisher_challenge": challenge_snapshot},
        label="formal QEMU evidence and publisher challenge",
    )
    environment = strict_json(
        evidence_snapshots["environment"].raw, "formal environment"
    )
    if evidence_snapshots["environment"].raw != canonical_json(environment):
        fail("formal environment is not canonical JSON")
    match_pinned_environment_roles(environment, contract)
    actual_evidence = {
        "kernel": match_actual_role(
            environment, "kernel", evidence_snapshots["kernel"], "kernel"
        ),
        "uart": match_actual_role(
            environment, "uart", evidence_snapshots["uart"], "UART"
        ),
        "elf_audit": match_actual_role(
            environment,
            "elf_audit_report",
            evidence_snapshots["elf_audit"],
            "ELF audit",
        ),
        "environment": identity_for(evidence_snapshots["environment"].raw),
    }
    audit = exact_keys(
        environment.get("elf_audit"),
        {
            "checks",
            "elf",
            "execution_scope",
            "mode",
            "schema",
            "schema_version",
            "status",
            "target",
            "toolchain",
        },
        "environment.elf_audit",
    )
    if evidence_snapshots["elf_audit"].raw != compact_json_line(audit):
        fail("relocated ELF-audit evidence differs from the envelope audit object")
    try:
        verified = shared.verify_uart_bytes(
            evidence_snapshots["uart"].raw,
            environment,
            expected_semantic_sha256=EXPECTED_SEMANTIC_SHA256,
        )
    except shared.VerificationError as error:
        fail(f"byte-pinned shared verifier rejected formal evidence: {error}")
    metadata = validate_verified_transcript(
        verified,
        environment,
        expected_semantic_sha256=EXPECTED_SEMANTIC_SHA256,
    )
    audit_summary = validate_platform_and_audit(environment, contract)
    mode_audit_result = rerun_elf_auditor_in_current_mode(
        shared=shared,
        kernel_snapshot=evidence_snapshots["kernel"],
        expected_report=evidence_snapshots["elf_audit"].raw,
        environment=environment,
        auditor_snapshot=pinned["elf_auditor"],
        toolchain_snapshot=pinned["rust_toolchain"],
    )
    source = exact_keys(
        environment.get("source"),
        {"commit", "tree", "clean", "branch", "remote_ref", "remote_commit"},
        "environment.source",
    )
    source_proof = verify_live_source(
        source,
        contract_snapshot,
        pinned,
        retained_duo,
        decision_verifier_snapshot,
    )
    for role, snapshot in evidence_snapshots.items():
        maxima = {
            "kernel": MAX_KERNEL_BYTES,
            "elf_audit": MAX_ELF_AUDIT_BYTES,
            "uart": MAX_UART_BYTES,
            "environment": MAX_ENVIRONMENT_BYTES,
        }
        reread_exact(snapshot, f"final {role} evidence", maximum=maxima[role])
    reread_exact(
        challenge_snapshot,
        "final publisher private challenge",
        maximum=64,
    )
    reread_exact(
        contract_snapshot, "final target-gate contract", maximum=MAX_CONTRACT_BYTES
    )
    for role, snapshot in pinned.items():
        reread_exact(snapshot, f"final pinned {role}", maximum=MAX_SOURCE_BYTES)
    for role, snapshot in retained_duo.items():
        reread_exact(snapshot, f"final retained Duo {role}", maximum=MAX_SOURCE_BYTES)
    reread_exact(
        decision_verifier_snapshot,
        "final target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    reread_exact(python_snapshot, "final Python interpreter", maximum=MAX_KERNEL_BYTES)
    final_source_proof = verify_live_source(
        source,
        contract_snapshot,
        pinned,
        retained_duo,
        decision_verifier_snapshot,
    )
    exact_literal(final_source_proof, source_proof, "final live source proof")
    derived = derive_candidate(
        contract=contract,
        contract_snapshot=contract_snapshot,
        decision_verifier_snapshot=decision_verifier_snapshot,
        python_snapshot=python_snapshot,
        source_proof=source_proof,
        environment=environment,
        evidence=actual_evidence,
        metadata=metadata,
        semantic_sha256=EXPECTED_SEMANTIC_SHA256,
        audit_summary=audit_summary,
    )
    validate_candidate_safety(derived, contract)
    derived_raw = canonical_json(derived)
    mode_receipt = derive_mode_receipt(
        candidate_raw=derived_raw,
        candidate=derived,
        decision_verifier_snapshot=decision_verifier_snapshot,
        python_snapshot=python_snapshot,
        pinned=pinned,
        evidence=actual_evidence,
        semantic_sha256=EXPECTED_SEMANTIC_SHA256,
        records=len(verified.records),
        audit_result=mode_audit_result,
        publisher_challenge_sha256=publisher_challenge_sha256,
    )
    mode_name, _level = optimization_mode()
    validate_mode_receipt(
        mode_receipt,
        contract=contract,
        candidate_raw=derived_raw,
        candidate=derived,
        expected_mode=mode_name,
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    return derived, mode_receipt


def publisher_worker_environment() -> dict[str, str]:
    home = os.environ.get("HOME")
    if not home or not os.path.isabs(home):
        fail("matrix publisher requires the unchanged absolute process HOME")
    return {
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }


def verify_private_stage(
    path: pathlib.Path,
    sealed_metadata: os.stat_result,
    expected_entries: set[str],
    label: str,
) -> None:
    descriptor: int | None = None
    try:
        _selected, descriptor = open_directory_chain(path, label)
        observed = os.fstat(descriptor)
        entries = os.listdir(descriptor)
    except OSError as error:
        fail(f"cannot verify {label}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        metadata_identity(observed) != metadata_identity(sealed_metadata)
        or not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o700
        or observed.st_uid != os.geteuid()
    ):
        fail(f"{label} identity, mode, or ownership changed")
    if len(entries) != len(set(entries)) or set(entries) != expected_entries:
        fail(f"{label} entry set differs from its closed private roles")


def worker_result_envelope(
    candidate: dict[str, object], receipt: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "vibeos.c88.f5.float-target.qemu-target-gate-v1.worker-result",
        "version": 1,
        "status": "pass",
        "candidate": candidate,
        "mode_receipt": receipt,
    }


def run_publisher_owned_worker(
    *,
    shared: types.ModuleType,
    contract: dict[str, object],
    worker_verifier_snapshot: StableFile,
    python_snapshot: StableFile,
    repository_root: pathlib.Path,
    private_inputs: dict[str, StableFile],
    expected_mode: str,
    publisher_challenge_sha256: str,
) -> tuple[bytes, dict[str, object], bytes, dict[str, object]]:
    if expected_mode not in ("normal", "optimized"):
        fail("publisher-owned worker mode is invalid")
    command = [str(python_snapshot.path), "-I", "-B"]
    if expected_mode == "optimized":
        command.append("-O")
    command.extend(
        [
            str(worker_verifier_snapshot.path),
            "--internal-matrix-worker",
            "--repository-root",
            str(repository_root),
            "--kernel",
            str(private_inputs["kernel"].path),
            "--elf-audit",
            str(private_inputs["elf_audit"].path),
            "--uart",
            str(private_inputs["uart"].path),
            "--environment",
            str(private_inputs["environment"].path),
            "--publisher-challenge-file",
            str(private_inputs["publisher_challenge"].path),
        ]
    )
    try:
        completed = shared.run_bounded_command(
            command,
            cwd=ROOT,
            environment=publisher_worker_environment(),
            maximum_output=MAX_WORKER_OUTPUT_BYTES,
            timeout_seconds=900.0,
        )
    except shared.VerificationError as error:
        fail(f"publisher-owned {expected_mode} worker could not run: {error}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        fail(
            f"publisher-owned {expected_mode} worker rejected the evidence: "
            f"{detail.strip()}"
        )
    if completed.stderr:
        fail(f"successful publisher-owned {expected_mode} worker emitted stderr")
    envelope = exact_keys(
        strict_json(completed.stdout, f"publisher-owned {expected_mode} worker result"),
        {"schema", "version", "status", "candidate", "mode_receipt"},
        f"publisher-owned {expected_mode} worker result",
    )
    exact_literal(
        envelope["schema"],
        "vibeos.c88.f5.float-target.qemu-target-gate-v1.worker-result",
        f"publisher-owned {expected_mode} worker result schema",
    )
    exact_literal(
        envelope["version"], 1, f"publisher-owned {expected_mode} worker result version"
    )
    exact_literal(
        envelope["status"],
        "pass",
        f"publisher-owned {expected_mode} worker result status",
    )
    if completed.stdout != canonical_json(envelope):
        fail(f"publisher-owned {expected_mode} worker result is not canonical JSON")
    candidate = envelope["candidate"]
    receipt = envelope["mode_receipt"]
    if type(candidate) is not dict or type(receipt) is not dict:
        fail(f"publisher-owned {expected_mode} worker payload is not two objects")
    candidate_raw = canonical_json(candidate)
    receipt_raw = canonical_json(receipt)
    validate_candidate_safety(candidate, contract)
    validate_mode_receipt(
        receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode=expected_mode,
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    return candidate_raw, candidate, receipt_raw, receipt


def validate_owned_matrix_pair(
    *,
    contract: dict[str, object],
    normal_candidate_raw: bytes,
    normal_candidate: dict[str, object],
    normal_receipt_raw: bytes,
    normal_receipt: dict[str, object],
    optimized_candidate_raw: bytes,
    optimized_candidate: dict[str, object],
    optimized_receipt_raw: bytes,
    optimized_receipt: dict[str, object],
    publisher_challenge_sha256: str,
) -> None:
    if normal_candidate_raw != optimized_candidate_raw:
        fail("normal and optimized candidate payloads are not byte-identical")
    exact_literal(
        optimized_candidate,
        normal_candidate,
        "normal and optimized candidate value equality",
    )
    candidate_raw = normal_candidate_raw
    validate_mode_receipt(
        normal_receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=normal_candidate,
        expected_mode="normal",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    validate_mode_receipt(
        optimized_receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=normal_candidate,
        expected_mode="optimized",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    normal_content = normal_receipt["content"]
    optimized_content = optimized_receipt["content"]
    if type(normal_content) is not dict or type(optimized_content) is not dict:
        fail("matrix mode receipt content is not one object")
    exact_literal(
        normal_content["python_interpreter"],
        optimized_content["python_interpreter"],
        "matrix Python interpreter identity equality",
    )
    exact_literal(
        normal_content["decision_verifier"],
        optimized_content["decision_verifier"],
        "matrix decision-verifier identity equality",
    )
    normal_shared = copy.deepcopy(normal_content["shared_verifier"])
    optimized_shared = copy.deepcopy(optimized_content["shared_verifier"])
    for result in (normal_shared, optimized_shared):
        if type(result) is not dict:
            fail("matrix shared-verifier result is not one object")
        result.pop("optimization_mode", None)
        result.pop("optimization_level", None)
    exact_literal(
        normal_shared,
        optimized_shared,
        "matrix shared-verifier result byte equality",
    )
    normal_audit = copy.deepcopy(normal_content["elf_auditor"])
    optimized_audit = copy.deepcopy(optimized_content["elf_auditor"])
    for result in (normal_audit, optimized_audit):
        if type(result) is not dict:
            fail("matrix ELF-auditor result is not one object")
        result.pop("optimization_mode", None)
        result.pop("optimization_level", None)
    exact_literal(
        normal_audit, optimized_audit, "matrix ELF-audit report byte equality"
    )
    if normal_receipt_raw == optimized_receipt_raw:
        fail("normal and optimized publisher receipts must be distinct")


def publish_verified_matrix(
    *,
    kernel_path: pathlib.Path,
    elf_audit_path: pathlib.Path,
    uart_path: pathlib.Path,
    environment_path: pathlib.Path,
    normal_receipt_out_path: pathlib.Path,
    optimized_receipt_out_path: pathlib.Path,
    decision_out_path: pathlib.Path,
) -> dict[str, object]:
    mode, level = optimization_mode()
    if (mode, level) != ("normal", 0):
        fail("the final matrix publisher must run under normal Python mode")
    output_paths = {
        "normal_receipt": absolute_path(
            normal_receipt_out_path, "normal receipt output"
        ),
        "optimized_receipt": absolute_path(
            optimized_receipt_out_path, "optimized receipt output"
        ),
        "decision": absolute_path(decision_out_path, "decision output"),
    }
    if len(set(output_paths.values())) != 3:
        fail("matrix publisher outputs must be three distinct paths")
    evidence_snapshots = {
        "kernel": stable_regular_file(
            kernel_path, "publisher kernel evidence", maximum=MAX_KERNEL_BYTES
        ),
        "elf_audit": stable_regular_file(
            elf_audit_path,
            "publisher ELF-audit evidence",
            maximum=MAX_ELF_AUDIT_BYTES,
        ),
        "uart": stable_regular_file(
            uart_path, "publisher UART evidence", maximum=MAX_UART_BYTES
        ),
        "environment": stable_regular_file(
            environment_path,
            "publisher environment evidence",
            maximum=MAX_ENVIRONMENT_BYTES,
        ),
    }
    ensure_distinct_files(evidence_snapshots, label="matrix publisher evidence")
    evidence_paths = {snapshot.path for snapshot in evidence_snapshots.values()}
    if evidence_paths.intersection(output_paths.values()):
        fail("matrix publisher outputs must differ from all evidence inputs")
    contract, contract_snapshot = load_contract()
    pinned = load_pinned_files(contract)
    retained_duo = load_retained_duo_files(contract)
    shared = load_shared_verifier(pinned["shared_verifier"])
    verifier_snapshot = stable_regular_file(
        DECISION_VERIFIER_PATH,
        "target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    python_snapshot = actual_interpreter_snapshot()
    custody_files = [
        *evidence_snapshots.values(),
        contract_snapshot,
        *pinned.values(),
        *retained_duo.values(),
        verifier_snapshot,
        python_snapshot,
    ]
    custody_directory_paths = {
        ROOT,
        ROOT.parent,
        python_snapshot.path.parent,
        python_snapshot.path.parent.parent,
        *[snapshot.path.parent for snapshot in custody_files],
    }
    for snapshot in custody_files:
        if snapshot.path.is_relative_to(ROOT):
            parent = snapshot.path.parent
            while parent != ROOT:
                custody_directory_paths.add(parent)
                parent = parent.parent
    custody_directories = snapshot_directories(
        list(custody_directory_paths), "publisher live-input custody"
    )
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c88-f5-qemu-target-gate-publisher-", dir="/private/tmp"
    ) as temporary_name:
        private_root = pathlib.Path(temporary_name)
        try:
            os.chmod(private_root, 0o700)
            stage_before = os.stat(private_root, follow_symlinks=False)
        except OSError as error:
            fail(f"cannot establish private publisher stage: {error}")
        if (
            not stat.S_ISDIR(stage_before.st_mode)
            or stat.S_IMODE(stage_before.st_mode) != 0o700
            or stage_before.st_uid != os.geteuid()
        ):
            fail("publisher stage is not one owned 0700 directory")
        private_inputs: dict[str, StableFile] = {}
        maxima = {
            "kernel": MAX_KERNEL_BYTES,
            "elf_audit": MAX_ELF_AUDIT_BYTES,
            "uart": MAX_UART_BYTES,
            "environment": MAX_ENVIRONMENT_BYTES,
        }
        private_names = {
            "kernel": "kernel.elf",
            "elf_audit": "elf-audit.json",
            "uart": "qemu-uart.log",
            "environment": "environment.json",
        }
        for role, snapshot in evidence_snapshots.items():
            private_inputs[role] = write_private_blob_no_clobber(
                private_root / private_names[role],
                snapshot.raw,
                mode=0o400,
                label=f"private publisher {role} evidence",
                maximum=maxima[role],
            )
        challenge_raw = secrets.token_bytes(32)
        private_inputs["publisher_challenge"] = write_private_blob_no_clobber(
            private_root / "publisher-challenge.bin",
            challenge_raw,
            mode=0o400,
            label="private publisher challenge",
            maximum=64,
        )
        private_worker_verifier = write_private_blob_no_clobber(
            private_root / "worker-verifier.py",
            verifier_snapshot.raw,
            mode=0o500,
            label="private publisher worker verifier",
            maximum=MAX_SOURCE_BYTES,
        )
        publisher_challenge_sha256 = sha256_bytes(
            PUBLISHER_CHALLENGE_DOMAIN + challenge_raw
        )
        ensure_distinct_files(
            {**private_inputs, "worker_verifier": private_worker_verifier},
            label="private publisher inputs and verifier",
        )
        expected_stage_entries = set(private_names.values()) | {
            "publisher-challenge.bin",
            "worker-verifier.py",
        }
        try:
            stage_sealed = os.stat(private_root, follow_symlinks=False)
        except OSError as error:
            fail(f"cannot seal private publisher stage: {error}")
        verify_private_stage(
            private_root,
            stage_sealed,
            expected_stage_entries,
            "private publisher stage before workers",
        )
        reread_directories(
            custody_directories, "publisher custody before normal worker"
        )
        (
            normal_candidate_raw,
            normal_candidate,
            normal_receipt_raw,
            normal_receipt,
        ) = run_publisher_owned_worker(
            shared=shared,
            contract=contract,
            worker_verifier_snapshot=private_worker_verifier,
            python_snapshot=python_snapshot,
            repository_root=ROOT,
            private_inputs=private_inputs,
            expected_mode="normal",
            publisher_challenge_sha256=publisher_challenge_sha256,
        )
        for role, snapshot in private_inputs.items():
            reread_exact(
                snapshot,
                f"post-normal private publisher {role}",
                maximum=64 if role == "publisher_challenge" else maxima[role],
            )
        reread_exact(
            private_worker_verifier,
            "post-normal private publisher worker verifier",
            maximum=MAX_SOURCE_BYTES,
        )
        verify_private_stage(
            private_root,
            stage_sealed,
            expected_stage_entries,
            "private publisher stage between workers",
        )
        reread_directories(custody_directories, "publisher custody between workers")
        (
            optimized_candidate_raw,
            optimized_candidate,
            optimized_receipt_raw,
            optimized_receipt,
        ) = run_publisher_owned_worker(
            shared=shared,
            contract=contract,
            worker_verifier_snapshot=private_worker_verifier,
            python_snapshot=python_snapshot,
            repository_root=ROOT,
            private_inputs=private_inputs,
            expected_mode="optimized",
            publisher_challenge_sha256=publisher_challenge_sha256,
        )
        verify_private_stage(
            private_root,
            stage_sealed,
            expected_stage_entries,
            "private publisher stage after workers",
        )
        reread_exact(
            private_worker_verifier,
            "post-optimized private publisher worker verifier",
            maximum=MAX_SOURCE_BYTES,
        )
        reread_directories(
            custody_directories, "publisher custody after optimized worker"
        )
        validate_owned_matrix_pair(
            contract=contract,
            normal_candidate_raw=normal_candidate_raw,
            normal_candidate=normal_candidate,
            normal_receipt_raw=normal_receipt_raw,
            normal_receipt=normal_receipt,
            optimized_candidate_raw=optimized_candidate_raw,
            optimized_candidate=optimized_candidate,
            optimized_receipt_raw=optimized_receipt_raw,
            optimized_receipt=optimized_receipt,
            publisher_challenge_sha256=publisher_challenge_sha256,
        )
        candidate_raw = normal_candidate_raw
        if any(
            challenge_raw in public_raw
            for public_raw in (
                normal_candidate_raw,
                normal_receipt_raw,
                optimized_candidate_raw,
                optimized_receipt_raw,
            )
        ):
            fail("raw publisher challenge escaped into a worker result")
        candidate_content = normal_candidate["content"]
        if type(candidate_content) is not dict:
            fail("matrix candidate content is not one object")
        candidate_evidence = candidate_content.get("evidence")
        if type(candidate_evidence) is not dict:
            fail("matrix candidate evidence is not one object")
        for role, snapshot in evidence_snapshots.items():
            exact_literal(
                candidate_evidence.get(role),
                identity_for(snapshot.raw),
                f"matrix candidate caller {role} evidence binding",
            )
        exact_literal(
            candidate_content["decision_verifier"],
            {
                "path": "scripts/verify-c88-f5-qemu-target-gate.py",
                **identity_for(verifier_snapshot.raw),
                "source_commit_blob_verified": True,
            },
            "matrix candidate live verifier identity",
        )
        exact_literal(
            candidate_content["python_interpreter"],
            identity_for(python_snapshot.raw),
            "matrix candidate live Python identity",
        )
        candidate_source = candidate_content["source"]
        if type(candidate_source) is not dict:
            fail("matrix candidate source is not one object")
        environment_source = {
            "commit": candidate_source["commit"],
            "tree": candidate_source["tree"],
            "clean": candidate_source["clean"],
            "branch": candidate_source["branch"],
            "remote_ref": candidate_source["local_tracking_ref"],
            "remote_commit": candidate_source["local_tracking_ref_commit"],
        }
        source_proof = verify_live_source(
            environment_source,
            contract_snapshot,
            pinned,
            retained_duo,
            verifier_snapshot,
        )
        for role, snapshot in evidence_snapshots.items():
            reread_exact(
                snapshot, f"final publisher {role} evidence", maximum=maxima[role]
            )
        for role, snapshot in private_inputs.items():
            reread_exact(
                snapshot,
                f"final private publisher {role}",
                maximum=64 if role == "publisher_challenge" else maxima[role],
            )
        reread_exact(
            private_worker_verifier,
            "final private publisher worker verifier",
            maximum=MAX_SOURCE_BYTES,
        )
        reread_exact(
            contract_snapshot,
            "final target-gate contract",
            maximum=MAX_CONTRACT_BYTES,
        )
        for role, snapshot in pinned.items():
            reread_exact(snapshot, f"final pinned {role}", maximum=MAX_SOURCE_BYTES)
        for role, snapshot in retained_duo.items():
            reread_exact(
                snapshot, f"final retained Duo {role}", maximum=MAX_SOURCE_BYTES
            )
        reread_exact(
            verifier_snapshot,
            "final target-gate verifier",
            maximum=MAX_SOURCE_BYTES,
        )
        reread_exact(
            python_snapshot,
            "final matrix Python interpreter",
            maximum=MAX_KERNEL_BYTES,
        )
        exact_literal(
            verify_live_source(
                environment_source,
                contract_snapshot,
                pinned,
                retained_duo,
                verifier_snapshot,
            ),
            source_proof,
            "final publisher live source proof",
        )
        reread_directories(custody_directories, "final publisher live-input custody")
        verify_private_stage(
            private_root,
            stage_sealed,
            expected_stage_entries,
            "final private publisher stage",
        )
        decision = close_candidate(
            contract=contract,
            candidate=normal_candidate,
            candidate_raw=candidate_raw,
            normal_receipt_raw=normal_receipt_raw,
            optimized_receipt_raw=optimized_receipt_raw,
            publisher_challenge_sha256=publisher_challenge_sha256,
        )
        retained_normal_receipt_raw = normal_receipt_raw
        retained_optimized_receipt_raw = optimized_receipt_raw
    try:
        os.lstat(private_root)
    except FileNotFoundError:
        pass
    except OSError as error:
        fail(f"cannot confirm private publisher stage cleanup: {error}")
    else:
        fail("private publisher stage survived cleanup before publication")
    for role, snapshot in evidence_snapshots.items():
        reread_exact(
            snapshot,
            f"post-cleanup publisher {role} evidence",
            maximum=maxima[role],
        )
    reread_exact(
        contract_snapshot,
        "post-cleanup target-gate contract",
        maximum=MAX_CONTRACT_BYTES,
    )
    for role, snapshot in pinned.items():
        reread_exact(snapshot, f"post-cleanup pinned {role}", maximum=MAX_SOURCE_BYTES)
    for role, snapshot in retained_duo.items():
        reread_exact(
            snapshot,
            f"post-cleanup retained Duo {role}",
            maximum=MAX_SOURCE_BYTES,
        )
    reread_exact(
        verifier_snapshot,
        "post-cleanup target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    reread_exact(
        python_snapshot,
        "post-cleanup matrix Python interpreter",
        maximum=MAX_KERNEL_BYTES,
    )
    exact_literal(
        verify_live_source(
            environment_source,
            contract_snapshot,
            pinned,
            retained_duo,
            verifier_snapshot,
        ),
        source_proof,
        "post-cleanup publisher live source proof",
    )
    reread_directories(custody_directories, "post-cleanup publisher live-input custody")
    written_normal = write_json_no_clobber(
        output_paths["normal_receipt"], normal_receipt
    )
    if written_normal != retained_normal_receipt_raw:
        fail("published normal receipt differs from its owned worker output")
    written_optimized = write_json_no_clobber(
        output_paths["optimized_receipt"], optimized_receipt
    )
    if written_optimized != retained_optimized_receipt_raw:
        fail("published optimized receipt differs from its owned worker output")
    written_decision = write_json_no_clobber(output_paths["decision"], decision)
    if written_decision != canonical_json(decision):
        fail("published closed decision differs from verified owned matrix")
    output_directory_seal = snapshot_directories(
        [path.parent for path in output_paths.values()],
        "published target-gate output directories",
    )
    published_snapshots = {
        "normal_receipt": stable_regular_file(
            output_paths["normal_receipt"],
            "final published normal receipt",
            maximum=MAX_DECISION_BYTES,
        ),
        "optimized_receipt": stable_regular_file(
            output_paths["optimized_receipt"],
            "final published optimized receipt",
            maximum=MAX_DECISION_BYTES,
        ),
        "decision": stable_regular_file(
            output_paths["decision"],
            "final published decision",
            maximum=MAX_DECISION_BYTES,
        ),
    }
    ensure_distinct_files(
        published_snapshots, label="final published target-gate triplet"
    )
    exact_literal(
        published_snapshots["normal_receipt"].raw,
        retained_normal_receipt_raw,
        "final published normal receipt bytes",
    )
    exact_literal(
        published_snapshots["optimized_receipt"].raw,
        retained_optimized_receipt_raw,
        "final published optimized receipt bytes",
    )
    exact_literal(
        published_snapshots["decision"].raw,
        canonical_json(decision),
        "final published decision bytes",
    )
    for role, snapshot in published_snapshots.items():
        reread_exact(
            snapshot,
            f"terminal published {role}",
            maximum=MAX_DECISION_BYTES,
        )
    reread_directories(
        output_directory_seal, "terminal published target-gate output directories"
    )
    return decision


def check_decision_receipt(
    path: pathlib.Path,
    normal_receipt_path: pathlib.Path,
    optimized_receipt_path: pathlib.Path,
) -> dict[str, object]:
    """Check the canonical checked-in receipt without claiming artifact replay."""

    contract, contract_snapshot = load_contract()
    pinned = load_pinned_files(contract)
    retained_duo = load_retained_duo_files(contract)
    verifier_snapshot = stable_regular_file(
        DECISION_VERIFIER_PATH,
        "target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    receipt_snapshot = stable_regular_file(
        path, "target-gate decision receipt", maximum=MAX_DECISION_BYTES
    )
    normal_mode_snapshot = stable_regular_file(
        normal_receipt_path,
        "checked-in normal mode receipt",
        maximum=MAX_DECISION_BYTES,
    )
    optimized_mode_snapshot = stable_regular_file(
        optimized_receipt_path,
        "checked-in optimized mode receipt",
        maximum=MAX_DECISION_BYTES,
    )
    ensure_distinct_files(
        {
            "decision": receipt_snapshot,
            "normal_receipt": normal_mode_snapshot,
            "optimized_receipt": optimized_mode_snapshot,
        },
        label="checked-in target-gate receipts",
    )
    receipt = strict_json(receipt_snapshot.raw, "target-gate decision receipt")
    if receipt_snapshot.raw != canonical_json(receipt):
        fail("target-gate decision receipt is not canonical JSON")
    validate_decision_safety(receipt, contract)
    content = receipt["content"]
    if type(content) is not dict:
        fail("target-gate decision receipt content is not one object")
    candidate = candidate_from_final_content(content)
    candidate_raw = canonical_json(candidate)
    normal_mode = strict_json(
        normal_mode_snapshot.raw, "checked-in normal mode receipt"
    )
    optimized_mode = strict_json(
        optimized_mode_snapshot.raw, "checked-in optimized mode receipt"
    )
    if normal_mode_snapshot.raw != canonical_json(normal_mode):
        fail("checked-in normal mode receipt is not canonical JSON")
    if optimized_mode_snapshot.raw != canonical_json(optimized_mode):
        fail("checked-in optimized mode receipt is not canonical JSON")
    normal_mode_content = normal_mode.get("content")
    if type(normal_mode_content) is not dict:
        fail("checked-in normal mode receipt content is not one object")
    publisher_challenge_sha256 = canonical_hex(
        normal_mode_content.get("publisher_challenge_sha256"),
        HEX64,
        "checked-in publisher challenge digest",
    )
    validate_mode_receipt(
        normal_mode,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode="normal",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    validate_mode_receipt(
        optimized_mode,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode="optimized",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    matrix = content["verification_matrix"]
    if type(matrix) is not dict:
        fail("checked-in decision matrix is not one object")
    exact_literal(
        matrix["publisher_challenge_sha256"],
        publisher_challenge_sha256,
        "checked-in matrix publisher challenge binding",
    )
    exact_literal(
        matrix["normal_receipt"],
        identity_for(normal_mode_snapshot.raw),
        "checked-in normal receipt identity",
    )
    exact_literal(
        matrix["optimized_receipt"],
        identity_for(optimized_mode_snapshot.raw),
        "checked-in optimized receipt identity",
    )
    exact_literal(
        content["contract"],
        {
            "path": (
                "acceptance/wasm-float-target/artifacts/"
                "qualification-qemu-target-gate-v1-contract.json"
            ),
            **identity_for(contract_snapshot.raw),
            "contract_status": "decision-contract-not-evidence",
        },
        "receipt live contract identity",
    )
    exact_literal(
        content["decision_verifier"],
        {
            "path": "scripts/verify-c88-f5-qemu-target-gate.py",
            **identity_for(verifier_snapshot.raw),
            "source_commit_blob_verified": True,
        },
        "receipt live verifier identity",
    )
    source = content["source"]
    if type(source) is not dict:
        fail("receipt source is not one object")
    source_commit = canonical_hex(source.get("commit"), HEX40, "receipt source commit")
    source_tree = canonical_hex(source.get("tree"), HEX40, "receipt source tree")
    exact_literal(
        git_line(
            ["rev-parse", "--verify", f"{source_commit}^{{tree}}"],
            "receipt source tree",
        ),
        source_tree,
        "receipt source tree",
    )
    source_files: list[tuple[str, str, bytes, str]] = [
        (
            "target-gate contract",
            (
                "acceptance/wasm-float-target/artifacts/"
                "qualification-qemu-target-gate-v1-contract.json"
            ),
            contract_snapshot.raw,
            "100644",
        ),
        (
            "target-gate verifier",
            "scripts/verify-c88-f5-qemu-target-gate.py",
            verifier_snapshot.raw,
            "100644",
        ),
    ]
    for role, snapshot in sorted(pinned.items()):
        source_files.append(
            (
                f"pinned {role}",
                str(PINNED_FILES[role]["path"]),
                snapshot.raw,
                "100644",
            )
        )
    for role, snapshot in sorted(retained_duo.items()):
        source_files.append(
            (
                f"retained Duo {role}",
                str(RETAINED_DUO_FILES[role]["path"]),
                snapshot.raw,
                str(RETAINED_DUO_FILES[role]["git_mode"]),
            )
        )
    for label, relative, raw, mode in source_files:
        verify_git_blob(source_commit, relative, raw, label, expected_mode=mode)
    reread_exact(
        receipt_snapshot,
        "final target-gate decision receipt",
        maximum=MAX_DECISION_BYTES,
    )
    reread_exact(
        normal_mode_snapshot,
        "final checked-in normal mode receipt",
        maximum=MAX_DECISION_BYTES,
    )
    reread_exact(
        optimized_mode_snapshot,
        "final checked-in optimized mode receipt",
        maximum=MAX_DECISION_BYTES,
    )
    reread_exact(
        contract_snapshot, "final target-gate contract", maximum=MAX_CONTRACT_BYTES
    )
    reread_exact(
        verifier_snapshot, "final target-gate verifier", maximum=MAX_SOURCE_BYTES
    )
    for role, snapshot in pinned.items():
        reread_exact(snapshot, f"final pinned {role}", maximum=MAX_SOURCE_BYTES)
    for role, snapshot in retained_duo.items():
        reread_exact(snapshot, f"final retained Duo {role}", maximum=MAX_SOURCE_BYTES)
    return receipt


def expect_rejection(label: str, operation: Any) -> None:
    try:
        operation()
    except (GateError, OSError, ValueError):
        return
    fail(f"selftest mutation was accepted: {label}")


def refresh_gate_addresses(decision: dict[str, object]) -> None:
    content = decision.get("content")
    if type(content) is not dict:
        fail("selftest decision content is not one object")
    fields = content.get("decision_id_fields")
    if type(fields) is not dict:
        fail("selftest decision fields are not one object")
    ordered = {name: fields[name] for name in DECISION_ID_FIELDS}
    content["decision_id"] = decision_id(ordered)
    schema = decision.get("schema")
    if schema == "vibeos.c88.f5.float-target.qemu-target-gate-v1.decision":
        domain = CONTENT_DOMAIN
    elif schema == "vibeos.c88.f5.float-target.qemu-target-gate-v1.candidate":
        domain = CANDIDATE_CONTENT_DOMAIN
    else:
        fail("selftest gate record has an unknown schema")
    decision["content_sha256"] = sha256_bytes(domain + compact_json(content))


def selftest() -> dict[str, object]:
    contract, contract_snapshot = load_contract()
    pinned = load_pinned_files(contract)
    retained_duo = load_retained_duo_files(contract)
    shared = load_shared_verifier(pinned["shared_verifier"])
    verifier_snapshot = stable_regular_file(
        DECISION_VERIFIER_PATH,
        "selftest target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    python_snapshot = actual_interpreter_snapshot()
    rejected = 0

    def reject(label: str, operation: Any) -> None:
        nonlocal rejected
        expect_rejection(label, operation)
        rejected += 1

    fixture_uart, fixture_environment = shared.synthetic_fixture()
    fixture_semantic = canonical_hex(
        fixture_environment.get("expected_semantic_sha256"),
        HEX64,
        "selftest fixture semantic digest",
    )
    try:
        verified = shared.verify_uart_bytes(
            fixture_uart,
            fixture_environment,
            verify_self_identity=False,
            expected_semantic_sha256=fixture_semantic,
        )
    except shared.VerificationError as error:
        fail(f"selftest shared semantic oracle rejected its fixture: {error}")
    metadata = validate_verified_transcript(
        verified,
        fixture_environment,
        expected_semantic_sha256=fixture_semantic,
    )
    audit_environment = copy.deepcopy(fixture_environment)
    audit_value = audit_environment.get("elf_audit")
    if type(audit_value) is not dict:
        fail("selftest ELF audit is not one object")
    audit_elf = audit_value.get("elf")
    if type(audit_elf) is not dict:
        fail("selftest audited ELF is not one object")
    audit_control_flow = audit_elf.get("control_flow")
    if type(audit_control_flow) is not dict:
        fail("selftest ELF control flow is not one object")
    audit_control_flow["direct_targets"] = 1
    audit_summary = validate_platform_and_audit(audit_environment, contract)

    reject(
        "duplicate JSON member",
        lambda: strict_json(b'{"value":1,"value":2}\n', "duplicate fixture"),
    )
    reject(
        "floating JSON number",
        lambda: strict_json(b'{"value":1.0}\n', "float fixture"),
    )
    reject(
        "oversized JSON integer",
        lambda: strict_json(b'{"value":123456789012345678901}\n', "integer fixture"),
    )
    for label, path, update in (
        (
            "physical equivalence",
            ("policy", "physical_equivalence_claimed"),
            True,
        ),
        (
            "premature effectivity",
            ("effectivity", "effective"),
            True,
        ),
        (
            "Duo becomes blocking",
            ("policy", "duo_roadmap_blocking"),
            True,
        ),
        (
            "Duo overrides QEMU precedence",
            ("precedence", "retained_duo_artifacts_may_override_this_decision"),
            True,
        ),
        (
            "code 5 activation",
            ("required_verified_decision_outcome", "code5_activation_authorized"),
            True,
        ),
        (
            "other C8.8 widenings",
            (
                "required_verified_decision_outcome",
                "other_c88_feature_widenings_complete",
            ),
            True,
        ),
        (
            "AOT authorization",
            ("required_verified_decision_outcome", "aot_authorized_by_this_decision"),
            True,
        ),
    ):
        mutated = copy.deepcopy(contract)
        container = mutated[path[0]]
        if type(container) is not dict:
            fail(f"selftest contract container is not one object: {label}")
        container[path[1]] = update
        reject(label, lambda value=mutated: validate_contract_value(value))

    source = exact_keys(
        fixture_environment["source"],
        {"commit", "tree", "clean", "branch", "remote_ref", "remote_commit"},
        "selftest environment source",
    )
    source_proof = {
        "commit": source["commit"],
        "tree": source["tree"],
        "clean": True,
        "branch": "codex/wasm",
        "local_tracking_ref": "refs/remotes/origin/codex/wasm",
        "local_tracking_ref_commit": source["commit"],
        "claim": "clean-head-equals-local-origin-tracking-ref",
        "remote_advertised_oid_proven": False,
    }
    evidence = {
        "kernel": role_identity(fixture_environment["kernel"], "fixture kernel"),
        "uart": identity_for(fixture_uart),
        "elf_audit": role_identity(
            fixture_environment["elf_audit_report"], "fixture ELF audit"
        ),
        "environment": identity_for(canonical_json(fixture_environment)),
    }
    candidate = derive_candidate(
        contract=contract,
        contract_snapshot=contract_snapshot,
        decision_verifier_snapshot=verifier_snapshot,
        python_snapshot=python_snapshot,
        source_proof=source_proof,
        environment=fixture_environment,
        evidence=evidence,
        metadata=metadata,
        semantic_sha256=EXPECTED_SEMANTIC_SHA256,
        audit_summary=audit_summary,
    )
    validate_candidate_safety(candidate, contract)
    candidate_raw = canonical_json(candidate)
    selftest_challenge_raw = bytes(range(32))
    publisher_challenge_sha256 = sha256_bytes(
        PUBLISHER_CHALLENGE_DOMAIN + selftest_challenge_raw
    )
    current_mode, current_level = optimization_mode()
    current_receipt = derive_mode_receipt(
        candidate_raw=candidate_raw,
        candidate=candidate,
        decision_verifier_snapshot=verifier_snapshot,
        python_snapshot=python_snapshot,
        pinned=pinned,
        evidence=evidence,
        semantic_sha256=EXPECTED_SEMANTIC_SHA256,
        records=EXPECTED_RECORDS["total"],
        audit_result={
            "status": "pass",
            "report": evidence["elf_audit"],
            "kernel": evidence["kernel"],
            "optimization_mode": current_mode,
            "optimization_level": current_level,
        },
        publisher_challenge_sha256=publisher_challenge_sha256,
    )

    def receipt_for(mode: str, level: int) -> dict[str, object]:
        receipt = copy.deepcopy(current_receipt)
        content = receipt.get("content")
        if type(content) is not dict:
            fail("selftest mode receipt content is not one object")
        content["optimization_mode"] = mode
        content["optimization_level"] = level
        for role in ("shared_verifier", "elf_auditor"):
            result = content.get(role)
            if type(result) is not dict:
                fail(f"selftest {role} receipt is not one object")
            result["optimization_mode"] = mode
            result["optimization_level"] = level
        receipt["content_sha256"] = sha256_bytes(
            MODE_RECEIPT_CONTENT_DOMAIN + compact_json(content)
        )
        return receipt

    normal_receipt = receipt_for("normal", 0)
    optimized_receipt = receipt_for("optimized", 1)
    validate_mode_receipt(
        normal_receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode="normal",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    validate_mode_receipt(
        optimized_receipt,
        contract=contract,
        candidate_raw=candidate_raw,
        candidate=candidate,
        expected_mode="optimized",
        expected_challenge_sha256=publisher_challenge_sha256,
    )
    normal_receipt_raw = canonical_json(normal_receipt)
    optimized_receipt_raw = canonical_json(optimized_receipt)
    validate_owned_matrix_pair(
        contract=contract,
        normal_candidate_raw=candidate_raw,
        normal_candidate=candidate,
        normal_receipt_raw=normal_receipt_raw,
        normal_receipt=normal_receipt,
        optimized_candidate_raw=candidate_raw,
        optimized_candidate=copy.deepcopy(candidate),
        optimized_receipt_raw=optimized_receipt_raw,
        optimized_receipt=optimized_receipt,
        publisher_challenge_sha256=publisher_challenge_sha256,
    )
    reject(
        "single-mode receipt replay cannot close matrix",
        lambda: validate_owned_matrix_pair(
            contract=contract,
            normal_candidate_raw=candidate_raw,
            normal_candidate=candidate,
            normal_receipt_raw=normal_receipt_raw,
            normal_receipt=normal_receipt,
            optimized_candidate_raw=candidate_raw,
            optimized_candidate=copy.deepcopy(candidate),
            optimized_receipt_raw=normal_receipt_raw,
            optimized_receipt=copy.deepcopy(normal_receipt),
            publisher_challenge_sha256=publisher_challenge_sha256,
        ),
    )
    wrong_challenge_receipt = copy.deepcopy(normal_receipt)
    wrong_challenge_content = wrong_challenge_receipt.get("content")
    if type(wrong_challenge_content) is not dict:
        fail("selftest wrong-challenge receipt content is not one object")
    wrong_challenge_content["publisher_challenge_sha256"] = "0" * 64
    wrong_challenge_receipt["content_sha256"] = sha256_bytes(
        MODE_RECEIPT_CONTENT_DOMAIN + compact_json(wrong_challenge_content)
    )
    reject(
        "caller-supplied receipt without publisher challenge",
        lambda: validate_mode_receipt(
            wrong_challenge_receipt,
            contract=contract,
            candidate_raw=candidate_raw,
            candidate=candidate,
            expected_mode="normal",
            expected_challenge_sha256=publisher_challenge_sha256,
        ),
    )
    decision = close_candidate(
        contract=contract,
        candidate=candidate,
        candidate_raw=candidate_raw,
        normal_receipt_raw=normal_receipt_raw,
        optimized_receipt_raw=optimized_receipt_raw,
        publisher_challenge_sha256=publisher_challenge_sha256,
    )
    validate_decision_safety(decision, contract)
    if any(
        selftest_challenge_raw in public_raw
        for public_raw in (
            candidate_raw,
            normal_receipt_raw,
            optimized_receipt_raw,
            canonical_json(decision),
        )
    ):
        fail("selftest raw publisher challenge escaped into a public artifact")

    candidate_status = copy.deepcopy(candidate)
    candidate_status["status"] = "closed"
    reject(
        "candidate cannot close gate",
        lambda: validate_candidate_safety(candidate_status, contract),
    )

    def decision_mutation(label: str, update: Any) -> None:
        mutated = copy.deepcopy(decision)
        update(mutated)
        refresh_gate_addresses(mutated)
        reject(label, lambda value=mutated: validate_decision_safety(value, contract))

    decision_mutation(
        "decision physical input",
        lambda value: value["content"]["evidence"].update(physical_inputs=1),
    )
    decision_mutation(
        "decision remote advertisement",
        lambda value: value["content"]["source"].update(
            remote_advertised_oid_proven=True
        ),
    )
    decision_mutation(
        "decision semantic digest",
        lambda value: value["content"]["qualification"].update(
            semantic_sha256="f" * 64
        ),
    )
    decision_mutation(
        "decision contract identity",
        lambda value: (
            value["content"]["contract"].update(sha256="e" * 64),
            value["content"]["decision_id_fields"].update(contract_sha256="e" * 64),
        ),
    )
    decision_mutation(
        "decision executable successor",
        lambda value: value["content"]["completion"].update(
            executable_successor_authorized=True
        ),
    )
    decision_mutation(
        "decision matrix incomplete",
        lambda value: value["content"]["verification_matrix"].update(
            elf_auditor_both_modes=False
        ),
    )

    with tempfile.TemporaryDirectory(
        prefix="vibeos-c88-f5-qemu-target-gate-selftest-", dir="/private/tmp"
    ) as temporary_name:
        temporary = pathlib.Path(temporary_name)
        sealed = temporary / "sealed"
        os.mkdir(sealed, 0o700)
        sealed_blob = write_private_blob_no_clobber(
            sealed / "worker.py",
            b"private-worker-fixture\n",
            mode=0o500,
            label="selftest sealed worker",
            maximum=1024,
        )
        sealed_metadata = os.stat(sealed, follow_symlinks=False)
        verify_private_stage(
            sealed,
            sealed_metadata,
            {"worker.py"},
            "selftest sealed worker directory",
        )
        displaced = temporary / "displaced-worker.py"
        os.rename(sealed_blob.path, displaced)
        os.rename(displaced, sealed_blob.path)
        reject(
            "sealed worker rename and restore",
            lambda: verify_private_stage(
                sealed,
                sealed_metadata,
                {"worker.py"},
                "mutated selftest sealed worker directory",
            ),
        )
        output = temporary / "DECISION.json"
        written = write_json_no_clobber(output, decision)
        exact_literal(written, canonical_json(decision), "selftest published decision")
        reject("decision no-clobber", lambda: write_json_no_clobber(output, decision))
        hardlink = temporary / "decision-hardlink.json"
        os.link(output, hardlink)
        reject(
            "hard-linked input",
            lambda: stable_regular_file(
                output, "hard-linked selftest file", maximum=MAX_DECISION_BYTES
            ),
        )
        os.unlink(hardlink)
        symlink = temporary / "decision-symlink.json"
        os.symlink(output.name, symlink)
        reject(
            "symbolic-link input",
            lambda: stable_regular_file(
                symlink, "symlink selftest file", maximum=MAX_DECISION_BYTES
            ),
        )
        fifo = temporary / "decision.fifo"
        os.mkfifo(fifo, 0o600)
        reject(
            "FIFO input",
            lambda: stable_regular_file(
                fifo, "FIFO selftest file", maximum=MAX_DECISION_BYTES
            ),
        )

    reread_exact(
        contract_snapshot, "selftest final contract", maximum=MAX_CONTRACT_BYTES
    )
    for role, snapshot in pinned.items():
        reread_exact(
            snapshot, f"selftest final pinned {role}", maximum=MAX_SOURCE_BYTES
        )
    for role, snapshot in retained_duo.items():
        reread_exact(
            snapshot, f"selftest final retained Duo {role}", maximum=MAX_SOURCE_BYTES
        )
    reread_exact(verifier_snapshot, "selftest final verifier", maximum=MAX_SOURCE_BYTES)
    return {
        "status": "pass",
        "suite_id": "vibeos.c88.f5.float-target.qemu-target-gate-v1",
        "contract": identity_for(contract_snapshot.raw),
        "shared_oracle_records": len(verified.records),
        "shared_oracle_fixture_semantic_sha256": fixture_semantic,
        "formal_semantic_sha256": EXPECTED_SEMANTIC_SHA256,
        "mutations_rejected": rejected,
        "matrix_modes": ["normal", "optimized"],
        "physical_inputs": 0,
    }


def contract_summary() -> dict[str, object]:
    contract, snapshot = load_contract()
    pinned = load_pinned_files(contract)
    retained_duo = load_retained_duo_files(contract)
    verifier = stable_regular_file(
        DECISION_VERIFIER_PATH,
        "target-gate verifier",
        maximum=MAX_SOURCE_BYTES,
    )
    reread_exact(snapshot, "final target-gate contract", maximum=MAX_CONTRACT_BYTES)
    for role, pinned_snapshot in pinned.items():
        reread_exact(pinned_snapshot, f"final pinned {role}", maximum=MAX_SOURCE_BYTES)
    for role, retained_snapshot in retained_duo.items():
        reread_exact(
            retained_snapshot,
            f"final retained Duo {role}",
            maximum=MAX_SOURCE_BYTES,
        )
    reread_exact(verifier, "final target-gate verifier", maximum=MAX_SOURCE_BYTES)
    return {
        "status": "pass",
        "suite_id": contract["suite_id"],
        "contract": identity_for(snapshot.raw),
        "decision_verifier": identity_for(verifier.raw),
        "pinned_file_count": len(pinned),
        "retained_duo_file_count": len(retained_duo),
        "contract_effective": contract["effectivity"]["effective"],
        "physical_inputs": contract["policy"]["physical_inputs_required"],
    }


def decision_summary(decision: dict[str, object]) -> dict[str, object]:
    content = decision["content"]
    if type(content) is not dict:
        fail("decision summary content is not one object")
    completion = content["completion"]
    if type(completion) is not dict:
        fail("decision summary completion is not one object")
    return {
        "status": "pass",
        "suite_id": content["suite_id"],
        "decision_id": content["decision_id"],
        "content_sha256": decision["content_sha256"],
        "source_commit": content["source"]["commit"],
        "run_id": content["run_id"],
        "semantic_sha256": content["qualification"]["semantic_sha256"],
        "target_gate_satisfied": completion["target_gate_satisfied"],
        "physical_inputs": content["evidence"]["physical_inputs"],
        "physical_provenance": completion["physical_provenance"],
        "executable_successor_authorized": completion[
            "executable_successor_authorized"
        ],
    }


def checked_receipt_summary(decision: dict[str, object]) -> dict[str, object]:
    content = decision["content"]
    if type(content) is not dict:
        fail("checked receipt summary content is not one object")
    completion = content["completion"]
    if type(completion) is not dict:
        fail("checked receipt completion is not one object")
    return {
        "status": "pass",
        "suite_id": content["suite_id"],
        "check_scope": "structure-and-hash-integrity-only-no-evidence-replay",
        "publisher_execution_replayed": False,
        "formal_closure_reestablished": False,
        "decision_id": content["decision_id"],
        "content_sha256": decision["content_sha256"],
        "receipt_claim_target_gate_satisfied": completion["target_gate_satisfied"],
        "physical_provenance": completion["physical_provenance"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the C8.8-F5 fixed-QEMU replacement policy or derive its "
            "canonical no-clobber decision from four formal evidence artifacts."
        )
    )
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--check-decision",
        type=pathlib.Path,
        help="check one canonical hash-summary receipt without replaying evidence",
    )
    parser.add_argument("--publish-matrix", action="store_true")
    parser.add_argument(
        "--internal-matrix-worker",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--kernel", type=pathlib.Path)
    parser.add_argument("--elf-audit", type=pathlib.Path)
    parser.add_argument("--uart", type=pathlib.Path)
    parser.add_argument("--environment", type=pathlib.Path)
    parser.add_argument(
        "--publisher-challenge-file", type=pathlib.Path, help=argparse.SUPPRESS
    )
    parser.add_argument("--repository-root", type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument("--normal-receipt", type=pathlib.Path)
    parser.add_argument("--optimized-receipt", type=pathlib.Path)
    parser.add_argument("--normal-receipt-out", type=pathlib.Path)
    parser.add_argument("--optimized-receipt-out", type=pathlib.Path)
    parser.add_argument(
        "--decision-out",
        type=pathlib.Path,
        help="matrix publisher's final no-clobber closed decision output",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    all_path_arguments = (
        arguments.kernel,
        arguments.elf_audit,
        arguments.uart,
        arguments.environment,
        arguments.publisher_challenge_file,
        arguments.repository_root,
        arguments.normal_receipt,
        arguments.optimized_receipt,
        arguments.normal_receipt_out,
        arguments.optimized_receipt_out,
        arguments.decision_out,
    )
    selected_modes = sum(
        (
            int(arguments.check_contract),
            int(arguments.selftest),
            int(arguments.check_decision is not None),
            int(arguments.publish_matrix),
            int(arguments.internal_matrix_worker),
        )
    )
    if selected_modes != 1:
        fail(
            "select exactly one of --check-contract, --selftest, "
            "--check-decision, or --publish-matrix"
        )
    if arguments.check_contract:
        if any(value is not None for value in all_path_arguments):
            fail("--check-contract does not accept artifact path arguments")
        result = contract_summary()
    elif arguments.selftest:
        if any(value is not None for value in all_path_arguments):
            fail("--selftest does not accept artifact path arguments")
        result = selftest()
    elif arguments.check_decision is not None:
        forbidden = (
            arguments.kernel,
            arguments.elf_audit,
            arguments.uart,
            arguments.environment,
            arguments.publisher_challenge_file,
            arguments.repository_root,
            arguments.normal_receipt_out,
            arguments.optimized_receipt_out,
            arguments.decision_out,
        )
        if any(value is not None for value in forbidden):
            fail("--check-decision received a publisher or formal-only argument")
        if arguments.normal_receipt is None or arguments.optimized_receipt is None:
            fail("--check-decision requires --normal-receipt and --optimized-receipt")
        result = checked_receipt_summary(
            check_decision_receipt(
                arguments.check_decision,
                arguments.normal_receipt,
                arguments.optimized_receipt,
            )
        )
    elif arguments.publish_matrix:
        publisher_values = (
            arguments.kernel,
            arguments.elf_audit,
            arguments.uart,
            arguments.environment,
            arguments.normal_receipt_out,
            arguments.optimized_receipt_out,
            arguments.decision_out,
        )
        if any(value is None for value in publisher_values):
            fail(
                "--publish-matrix requires all four evidence inputs, both receipt "
                "outputs, and --decision-out"
            )
        publisher_forbidden = (
            arguments.publisher_challenge_file,
            arguments.repository_root,
            arguments.normal_receipt,
            arguments.optimized_receipt,
        )
        if any(value is not None for value in publisher_forbidden):
            fail("--publish-matrix does not accept worker or receipt input paths")
        result = decision_summary(
            publish_verified_matrix(
                kernel_path=arguments.kernel,
                elf_audit_path=arguments.elf_audit,
                uart_path=arguments.uart,
                environment_path=arguments.environment,
                normal_receipt_out_path=arguments.normal_receipt_out,
                optimized_receipt_out_path=arguments.optimized_receipt_out,
                decision_out_path=arguments.decision_out,
            )
        )
    else:
        worker_values = (
            arguments.kernel,
            arguments.elf_audit,
            arguments.uart,
            arguments.environment,
            arguments.publisher_challenge_file,
            arguments.repository_root,
        )
        if any(value is None for value in worker_values):
            fail("internal matrix worker is missing one publisher-owned input")
        worker_forbidden = (
            arguments.normal_receipt,
            arguments.optimized_receipt,
            arguments.normal_receipt_out,
            arguments.optimized_receipt_out,
            arguments.decision_out,
        )
        if any(value is not None for value in worker_forbidden):
            fail("internal matrix worker received a publisher output argument")
        configure_internal_repository_root(arguments.repository_root)
        candidate, receipt = verify_formal_evidence(
            kernel_path=arguments.kernel,
            elf_audit_path=arguments.elf_audit,
            uart_path=arguments.uart,
            environment_path=arguments.environment,
            publisher_challenge_path=arguments.publisher_challenge_file,
        )
        result = worker_result_envelope(candidate, receipt)
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as error:
        print(f"C8.8-F5 QEMU target gate: FAIL\n{error}", file=sys.stderr)
        raise SystemExit(1)
