#!/usr/bin/env python3
"""Audit the checked-in C8.4 fixed-QEMU publication without replaying it.

The contract checked by this program is neutral policy and integrity metadata,
not evidence.  This program reads fixed repository paths, proves historical Git
membership and cross-file hash/structure consistency, and performs no QEMU,
publisher, execution, physical-device, or Milk-V Duo operation.
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
import tempfile
from typing import Any, NoReturn, NamedTuple


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT_PATH = (
    ROOT
    / "benchmarks/wasm-aot-decision/"
    "qemu-v1-publication-integrity-contract.json"
)
EXPECTED_CONTRACT_SHA256 = (
    "bb93cc7d72ff9d2e0425b1a7a105de9243b5ae0e3f08a232d35ea0c2eec6d745"
)
EXPECTED_CONTRACT_BYTES = 6_017

MAX_CONTRACT_BYTES = 64 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 20 * 1024 * 1024
MAX_JSON_INTEGER_DIGITS = 20
READ_CHUNK_BYTES = 64 * 1024

EXPECTED_SOURCE = {
    "commit": "e950a2facb6a6c230e67becb186bddf34a5924bb",
    "tree": "235541126f0e8445ee5a884985db4ccd9bb24104",
}
EXPECTED_PUBLICATION = {
    "commit": "cbb1d0fb0261377b848b218c9a31f862f7ec42ed",
    "source_is_ancestor": True,
    "tree": "72a21b59dc563e193185aa8a2d60f4ee0c6df850",
}
EXPECTED_BUNDLE = {
    "decision": {
        "bytes": 354_846,
        "git_blob": "97f9e4877a355b4e12b2f386c99eac62922d3391",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/qemu-v1/DECISION.json",
        "sha256": (
            "f2e9180569d43939a11e25e4d91cf9223447a141c8b7d8b5d75c756c6ae0569e"
        ),
    },
    "environment": {
        "bytes": 348_501,
        "git_blob": "136ebe26a9794c156792f452467e50a379cb5859",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/qemu-v1/environment.json",
        "sha256": (
            "af738cb939c847aec337350ed82ad6064085f72bc0b112ae011fee60a5d92697"
        ),
    },
    "summary": {
        "bytes": 5_083,
        "git_blob": "97fa47cf2063338c3c0022d4736cf5cb7a6268fa",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/qemu-v1/summary.json",
        "sha256": (
            "ca04d0b4fb89b40bdfc0f7028147e6b7e27c80cc0f5e3fbdba0e9a23f67f4354"
        ),
    },
    "uart": {
        "bytes": 12_158_825,
        "git_blob": "9a8d2b33fabddbf6481e50421bed985c1b932891",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/qemu-v1/uart.log",
        "sha256": (
            "bc22610248db679a89336302f93a6fef760ae886d32121dce320961ddda8c112"
        ),
    },
}
EXPECTED_HISTORICAL_BLOBS = {
    "build_rs": {
        "bytes": 40_171,
        "git_blob": "dbb0bd27796d65b4cecd8ca091a6d954f7978d42",
        "git_mode": "100644",
        "path": "policy/image/build.rs",
        "required_at": ["source", "publication"],
        "sha256": (
            "ca0d4f100d136d26c0ac1e1beeb0919b12c8f8a9e2345d15b6284b041e6ed74e"
        ),
    },
    "evidence_schema": {
        "bytes": 53_287,
        "git_blob": "25cf70e0a2d55098f17f8ea6d60a62d6042ea479",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/evidence-schema-qemu-v1.json",
        "required_at": ["source", "publication"],
        "sha256": (
            "6239f8fb2e71a0195d8efccb445badbd8f6cad04a755440be93c08131e7cd22e"
        ),
    },
    "manifest": {
        "bytes": 20_229,
        "git_blob": "2f6036d3c09183413a73619cf54b175ebd60ce27",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/workloads-qemu-v1.json",
        "required_at": ["source", "publication"],
        "sha256": (
            "339bb27af9a4d24cf5440349777a2113c7ac815bc0289c2fc233426aac3402ef"
        ),
    },
    "physical_helper": {
        "bytes": 139_509,
        "git_blob": "925a31cc95a570aae8b8ed6b6c71da7d1c527046",
        "git_mode": "100644",
        "path": "scripts/verify-c84-aot-decision.py",
        "required_at": ["source", "publication"],
        "sha256": (
            "e40bd89b478de57ce893167ac754676d32032ff1553f0a4cdbd8a3f6b2d82b52"
        ),
    },
    "policy_lib": {
        "bytes": 91_547,
        "git_blob": "5eb7cdbceccfc90d76c47c0d030039716dabef70",
        "git_mode": "100644",
        "path": "policy/image/src/lib.rs",
        "required_at": ["source", "publication"],
        "sha256": (
            "d4912916f8407ddcb4ae7914186f6d567468896c72a39da0ddbbe957d1a7b2e0"
        ),
    },
    "qemu_verifier": {
        "bytes": 339_405,
        "git_blob": "1169b293ff1976f0204028ba0eac789b5ddfaa79",
        "git_mode": "100755",
        "path": "scripts/verify-c84-qemu-aot-decision.py",
        "required_at": ["source", "publication"],
        "sha256": (
            "fe67fee3e299d9110f6405fdee83df085cf110ebbc18c6bbf0576a021f3bdc6a"
        ),
    },
    "transcript_schema": {
        "bytes": 8_188,
        "git_blob": "5d9a6fee8865c5ba784c0c1549d860959f2214c2",
        "git_mode": "100644",
        "path": "benchmarks/wasm-aot-decision/schema-qemu-v1.json",
        "required_at": ["source", "publication"],
        "sha256": (
            "0df879bea905ac1967685fdb411f017acf0136a69999ee031f71af76509eb520"
        ),
    },
}
EXPECTED_DECISION = {
    "aot_authorized": False,
    "budget_miss": True,
    "budget_ticks": 1_000_000,
    "candidate_for_c85_design_review": False,
    "interpretation_attribution": False,
    "native_code_accepted": False,
    "outcome": "aot-not-justified-on-fixed-qemu",
}
EXPECTED_EFFECTIVITY = {
    "contract_is_evidence": False,
    "formal_closure_reestablished": False,
    "publisher_execution_replayed": False,
    "qemu_execution_replayed": False,
    "scope": "historical-structure-and-hash-integrity-only-no-evidence-replay",
}
EXPECTED_POLICY = {
    "aot_authorized": False,
    "native_code_accepted": False,
    "other_hardware_gates_unchanged": True,
    "physical_duo_gate_replaced": True,
    "physical_inputs_permitted": 0,
    "physical_inputs_required": 0,
    "physical_provenance": "not-claimed",
    "physical_tooling_retained": True,
    "physical_tooling_status": "retained-non-blocking-non-evidence",
    "replacement": "fixed-qemu-formally-replaces-c84-physical-duo-roadmap-gate",
    "replacement_scope": "c84-only",
}
EXPECTED_VERIFICATION = {
    "check_published_writes_outputs": False,
    "cli_modes": ["--check-published", "--selftest"],
    "fixed_paths_only": True,
    "git_access": "sanitized-local-no-lazy-fetch",
    "json_policy": "duplicate-free-integer-only-canonical-json",
    "selftest_writes_temporary_fixtures": True,
    "writes_repository_outputs": False,
}
EXPECTED_LIMITATIONS = [
    (
        "Passing this audit proves only checked-in structure, hashes, Git "
        "ancestry, and historical blob membership."
    ),
    (
        "The audit does not rerun QEMU, replay the publisher or execution, or "
        "reestablish the original formal closure."
    ),
    (
        "No physical Milk-V Duo provenance or physical-hardware equivalence "
        "is claimed."
    ),
]

CONTRACT_ROOT_KEYS = {
    "bundle",
    "decision_semantics",
    "effectivity",
    "historical_blobs",
    "limitations",
    "policy",
    "publication",
    "schema",
    "scope",
    "source",
    "status",
    "suite_id",
    "verification",
    "version",
}
DECISION_ROOT_KEYS = {
    "challenge",
    "contract",
    "decision",
    "environment_identity",
    "evidence",
    "limitations",
    "mode",
    "next_node",
    "physical_provenance",
    "platform",
    "platform_class",
    "population",
    "run_id",
    "schema",
    "scope",
    "source_commit",
    "statistics",
    "suite_id",
    "version",
}
ENVIRONMENT_ROOT_KEYS = {
    "bios",
    "challenge",
    "contract",
    "ended_at_utc",
    "executed_peer_sources",
    "execution_custody",
    "helpers",
    "host_key_evidence",
    "kernel_elf",
    "mode",
    "openssh",
    "physical_provenance",
    "platform",
    "platform_class",
    "python_runtime",
    "qemu",
    "repository",
    "run_id",
    "runner",
    "schema",
    "source_commit",
    "source_materialization",
    "started_at_utc",
    "suite_id",
    "summary",
    "toolchain",
    "transcript",
    "verifier",
    "version",
}
SUMMARY_ROOT_KEYS = {
    "capture_mode",
    "challenge",
    "decision",
    "end_accumulator",
    "fresh_qemu_processes",
    "manifest_sha256",
    "physical_provenance",
    "platform",
    "platform_class",
    "raw_transcript_bytes",
    "raw_transcript_sha256",
    "retained",
    "retained_samples",
    "run_id",
    "schema",
    "scope",
    "source_commit",
    "statistics",
    "suite_id",
    "timebase_hz",
    "transcript_schema_sha256",
    "version",
    "warmups",
}


class AuditError(RuntimeError):
    """Fail-closed publication-integrity rejection."""


class StableFile(NamedTuple):
    path: pathlib.Path
    raw: bytes
    metadata: tuple[int, ...]


def fail(message: str) -> NoReturn:
    raise AuditError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob_oid(raw: bytes) -> str:
    header = b"blob " + str(len(raw)).encode("ascii") + b"\0"
    return hashlib.sha1(header + raw).hexdigest()


def canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        fail(f"value is not canonical JSON: {error}")


def compact_json_line(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeError) as error:
        fail(f"value is not compact canonical JSON: {error}")


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_json_number(token: str) -> NoReturn:
    raise ValueError(f"non-integer JSON number is forbidden: {token}")


def parse_json_integer(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError(
            f"JSON integer exceeds the {MAX_JSON_INTEGER_DIGITS}-digit bound"
        )
    return int(token, 10)


def strict_json(raw: bytes, label: str, *, require_canonical: bool = True) -> dict[str, Any]:
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
    if require_canonical and raw != canonical_json(value):
        fail(f"{label} is not canonical JSON")
    return value


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} must be one object")
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def strict_equal(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected):
        fail(f"{label} type differs")
    if type(expected) is dict:
        actual_object = actual
        expected_object = expected
        if set(actual_object) != set(expected_object):
            fail(f"{label} keys differ")
        for key in sorted(expected_object):
            strict_equal(actual_object[key], expected_object[key], f"{label}.{key}")
        return
    if type(expected) is list:
        actual_list = actual
        expected_list = expected
        if len(actual_list) != len(expected_list):
            fail(f"{label} length differs")
        for index, member in enumerate(expected_list):
            strict_equal(actual_list[index], member, f"{label}[{index}]")
        return
    if actual != expected:
        fail(f"{label} differs")


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


def absolute_path(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        encoded = os.fspath(path)
    except TypeError as error:
        fail(f"{label} path is invalid: {error}")
    if not encoded or "\0" in encoded:
        fail(f"{label} path is empty or contains NUL")
    return pathlib.Path(os.path.abspath(encoded))


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


def stable_regular_file(path: pathlib.Path, label: str, *, maximum: int) -> StableFile:
    if maximum <= 0:
        fail(f"{label} maximum must be positive")
    selected = absolute_path(path, label)
    if not selected.name or selected.name in (".", ".."):
        fail(f"{label} basename is invalid")
    parent_descriptor: int | None = None
    reopened_parent: int | None = None
    descriptor: int | None = None
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
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or opened_before.st_nlink != 1:
            fail(f"{label} opened object must be singly-linked and regular")
        if not 0 < opened_before.st_size <= maximum:
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
        opened_after = os.fstat(descriptor)
        path_after = os.stat(
            selected.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        _parent_again, reopened_parent = open_directory_chain(
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
        metadata_identity(opened_before),
        metadata_identity(opened_after),
        metadata_identity(path_after),
    }
    if len(identities) != 1:
        fail(f"{label} changed while read")
    raw = b"".join(chunks)
    if len(raw) != opened_before.st_size:
        fail(f"{label} byte length changed while read")
    return StableFile(selected, raw, metadata_identity(opened_before))


def reread_exact(snapshot: StableFile, label: str, *, maximum: int) -> None:
    current = stable_regular_file(snapshot.path, label, maximum=maximum)
    if current.metadata != snapshot.metadata or current.raw != snapshot.raw:
        fail(f"{label} changed after its initial read")


def validate_contract_object(contract: object) -> dict[str, Any]:
    value = exact_keys(contract, CONTRACT_ROOT_KEYS, "integrity contract")
    strict_equal(value["bundle"], EXPECTED_BUNDLE, "integrity contract.bundle")
    strict_equal(
        value["decision_semantics"],
        EXPECTED_DECISION,
        "integrity contract.decision_semantics",
    )
    strict_equal(
        value["effectivity"], EXPECTED_EFFECTIVITY, "integrity contract.effectivity"
    )
    strict_equal(
        value["historical_blobs"],
        EXPECTED_HISTORICAL_BLOBS,
        "integrity contract.historical_blobs",
    )
    strict_equal(value["limitations"], EXPECTED_LIMITATIONS, "integrity contract.limitations")
    strict_equal(value["policy"], EXPECTED_POLICY, "integrity contract.policy")
    strict_equal(
        value["publication"], EXPECTED_PUBLICATION, "integrity contract.publication"
    )
    strict_equal(
        value["schema"],
        "vibeos.c84.qemu-published-evidence-integrity-contract",
        "integrity contract.schema",
    )
    strict_equal(
        value["scope"],
        "c84-fixed-qemu-published-bundle-historical-integrity",
        "integrity contract.scope",
    )
    strict_equal(value["source"], EXPECTED_SOURCE, "integrity contract.source")
    strict_equal(
        value["status"],
        "neutral-integrity-audit-contract-not-evidence",
        "integrity contract.status",
    )
    strict_equal(
        value["suite_id"],
        "vibeos.c84.qemu-published-evidence-integrity",
        "integrity contract.suite_id",
    )
    strict_equal(
        value["verification"], EXPECTED_VERIFICATION, "integrity contract.verification"
    )
    strict_equal(value["version"], 1, "integrity contract.version")
    return value


def load_contract() -> tuple[dict[str, Any], StableFile]:
    snapshot = stable_regular_file(
        CONTRACT_PATH, "publication integrity contract", maximum=MAX_CONTRACT_BYTES
    )
    if len(snapshot.raw) != EXPECTED_CONTRACT_BYTES:
        fail("publication integrity contract byte length differs")
    if sha256_bytes(snapshot.raw) != EXPECTED_CONTRACT_SHA256:
        fail("publication integrity contract SHA-256 differs")
    contract = strict_json(snapshot.raw, "publication integrity contract")
    return validate_contract_object(contract), snapshot


def sanitized_git(arguments: list[str], label: str, *, allowed_codes: set[int] = {0}) -> bytes:
    executable = "/usr/bin/git"
    command = [
        executable,
        "--no-pager",
        "--no-replace-objects",
        "--literal-pathspecs",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=",
        "-C",
        os.fspath(ROOT),
        *arguments,
    ]
    environment = {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    try:
        completed = subprocess.run(
            command,
            check=False,
            cwd=os.fspath(ROOT),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"sanitized local Git failed for {label}: {error}")
    if completed.returncode not in allowed_codes:
        detail = completed.stderr[:4096].decode("utf-8", errors="replace").strip()
        fail(
            f"sanitized local Git rejected {label} with status "
            f"{completed.returncode}: {detail}"
        )
    if len(completed.stdout) + len(completed.stderr) > MAX_GIT_OUTPUT_BYTES:
        fail(f"sanitized local Git output is too large for {label}")
    return completed.stdout


def git_text(arguments: list[str], label: str) -> str:
    raw = sanitized_git(arguments, label)
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError as error:
        fail(f"sanitized local Git output is not ASCII for {label}: {error}")
    if not text.endswith("\n") or "\n" in text[:-1]:
        fail(f"sanitized local Git output is not one line for {label}")
    return text[:-1]


def verify_commit_identity(role: str, record: dict[str, Any]) -> None:
    commit = record["commit"]
    tree = record["tree"]
    observed_commit = git_text(
        ["rev-parse", "--verify", f"{commit}^{{commit}}"], f"{role} commit"
    )
    if observed_commit != commit:
        fail(f"{role} commit identity differs")
    observed_tree = git_text(
        ["rev-parse", "--verify", f"{commit}^{{tree}}"], f"{role} tree"
    )
    if observed_tree != tree:
        fail(f"{role} tree identity differs")


def verify_git_blob(
    commit: str, record: dict[str, Any], label: str
) -> bytes:
    path = record["path"]
    listing = sanitized_git(
        ["ls-tree", "-z", commit, "--", path], f"{label} tree entry"
    )
    expected_listing = (
        f"{record['git_mode']} blob {record['git_blob']}\t{path}\0".encode("utf-8")
    )
    if listing != expected_listing:
        fail(f"{label} Git tree entry differs")
    revision_blob = git_text(
        ["rev-parse", "--verify", f"{commit}:{path}"], f"{label} blob identity"
    )
    if revision_blob != record["git_blob"]:
        fail(f"{label} Git blob identity differs")
    raw = sanitized_git(
        ["cat-file", "blob", record["git_blob"]], f"{label} Git blob"
    )
    if len(raw) != record["bytes"]:
        fail(f"{label} Git blob byte length differs")
    if sha256_bytes(raw) != record["sha256"]:
        fail(f"{label} Git blob SHA-256 differs")
    if git_blob_oid(raw) != record["git_blob"]:
        fail(f"{label} recomputed Git blob identity differs")
    return raw


def verify_repository_history(
    contract: dict[str, Any],
) -> tuple[dict[str, bytes], str]:
    source = contract["source"]
    publication = contract["publication"]
    verify_commit_identity("source", source)
    verify_commit_identity("publication", publication)
    ancestor_result = sanitized_git(
        ["merge-base", "--is-ancestor", source["commit"], publication["commit"]],
        "source/publication ancestry",
    )
    if ancestor_result or publication["source_is_ancestor"] is not True:
        fail("source/publication ancestry output differs")
    # Independently require that the exact source commit is the merge base.
    merge_base = git_text(
        ["merge-base", source["commit"], publication["commit"]],
        "source/publication merge base",
    )
    if merge_base != source["commit"]:
        fail("source commit is not the publication ancestor")
    head_commit = git_text(
        ["rev-parse", "--verify", "HEAD^{commit}"], "current HEAD commit"
    )
    head_ancestry = sanitized_git(
        ["merge-base", "--is-ancestor", publication["commit"], head_commit],
        "publication/current HEAD ancestry",
    )
    if head_ancestry:
        fail("publication/current HEAD ancestry output differs")

    for role, record in contract["historical_blobs"].items():
        for point in record["required_at"]:
            commit = contract[point]["commit"]
            verify_git_blob(commit, record, f"historical {role} at {point}")

    publication_blobs: dict[str, bytes] = {}
    for role, record in contract["bundle"].items():
        publication_blobs[role] = verify_git_blob(
            publication["commit"], record, f"published bundle {role}"
        )
    return publication_blobs, head_commit


def load_live_bundle(
    contract: dict[str, Any], publication_blobs: dict[str, bytes], head_commit: str
) -> dict[str, StableFile]:
    snapshots: dict[str, StableFile] = {}
    for role, record in contract["bundle"].items():
        head_blob = verify_git_blob(
            head_commit, record, f"current checked-in bundle {role}"
        )
        if head_blob != publication_blobs[role]:
            fail(f"current checked-in bundle {role} differs from publication bytes")
        snapshot = stable_regular_file(
            ROOT / record["path"],
            f"live published bundle {role}",
            maximum=MAX_BUNDLE_BYTES,
        )
        if len(snapshot.raw) != record["bytes"]:
            fail(f"live published bundle {role} byte length differs")
        if sha256_bytes(snapshot.raw) != record["sha256"]:
            fail(f"live published bundle {role} SHA-256 differs")
        if snapshot.raw != publication_blobs[role]:
            fail(f"live published bundle {role} differs from publication bytes")
        live_executable = bool(snapshot.metadata[2] & 0o111)
        expected_executable = record["git_mode"] == "100755"
        if live_executable != expected_executable:
            fail(f"live published bundle {role} executable mode differs")
        snapshots[role] = snapshot
    return snapshots


def identity(record: dict[str, Any]) -> dict[str, object]:
    return {"bytes": record["bytes"], "sha256": record["sha256"]}


def path_identity(record: dict[str, Any]) -> dict[str, object]:
    return {
        "bytes": record["bytes"],
        "path": record["path"],
        "sha256": record["sha256"],
    }


def verify_retained_summary(
    summary: dict[str, Any], decision_semantics: dict[str, Any]
) -> None:
    samples = summary.get("retained_samples")
    if type(samples) is not list or len(samples) != 21:
        fail("summary must contain exactly 21 retained samples")
    values: dict[str, list[int]] = {
        "total_ticks": [],
        "interpretation_ticks": [],
        "non_interpretation_ticks": [],
    }
    for offset, sample in enumerate(samples):
        row = exact_keys(
            sample,
            {
                "interpretation_ticks",
                "non_interpretation_ticks",
                "sample_index",
                "total_ticks",
            },
            f"summary retained sample {offset}",
        )
        strict_equal(
            row["sample_index"], offset + 3, f"summary retained sample {offset} index"
        )
        for field in values:
            value = row[field]
            if type(value) is not int or value <= 0:
                fail(f"summary retained sample {offset} {field} is not positive")
            values[field].append(value)
        strict_equal(
            row["total_ticks"],
            row["interpretation_ticks"] + row["non_interpretation_ticks"],
            f"summary retained sample {offset} phase partition",
        )

    def distribution(field: str) -> dict[str, int]:
        observed = values[field]
        ordered = sorted(observed)
        return {
            "max": max(observed),
            "mean": sum(observed) // len(observed),
            "min": min(observed),
            "p50": ordered[10],
            "p95": ordered[19],
        }

    derived_statistics: dict[str, object] = {
        "interpretation_ticks": distribution("interpretation_ticks"),
        "nearest_rank_sorted_indices": {
            "p50": 10,
            "p95": 19,
            "population": 21,
        },
        "non_interpretation_ticks": distribution("non_interpretation_ticks"),
        "stability": {
            "criterion": "p95(total_ticks) * 100 <= p50(total_ticks) * 110",
            "passed": (
                distribution("total_ticks")["p95"] * 100
                <= distribution("total_ticks")["p50"] * 110
            ),
        },
        "total_ticks": distribution("total_ticks"),
    }
    strict_equal(
        summary.get("statistics"), derived_statistics, "summary derived statistics"
    )
    strict_equal(
        derived_statistics["stability"]["passed"],
        True,
        "derived retained stability gate",
    )
    total_p95 = derived_statistics["total_ticks"]["p95"]
    non_interpretation_p95 = derived_statistics["non_interpretation_ticks"]["p95"]
    budget = decision_semantics["budget_ticks"]
    budget_miss = total_p95 > budget
    interpretation_attribution = non_interpretation_p95 <= budget
    candidate = budget_miss and interpretation_attribution
    strict_equal(
        decision_semantics["budget_miss"], budget_miss, "derived budget miss"
    )
    strict_equal(
        decision_semantics["interpretation_attribution"],
        interpretation_attribution,
        "derived interpretation attribution",
    )
    strict_equal(
        decision_semantics["candidate_for_c85_design_review"],
        candidate,
        "derived C8.5 design-review candidacy",
    )
    strict_equal(
        decision_semantics["outcome"],
        (
            "aot-eligible-for-c85-design-review-on-fixed-qemu"
            if candidate
            else "aot-not-justified-on-fixed-qemu"
        ),
        "derived fixed-QEMU outcome",
    )


def verify_published_semantics(
    contract: dict[str, Any], snapshots: dict[str, StableFile]
) -> None:
    decision = strict_json(snapshots["decision"].raw, "published decision")
    environment = strict_json(
        snapshots["environment"].raw, "published environment"
    )
    summary = strict_json(snapshots["summary"].raw, "published summary")
    exact_keys(decision, DECISION_ROOT_KEYS, "published decision")
    exact_keys(environment, ENVIRONMENT_ROOT_KEYS, "published environment")
    exact_keys(summary, SUMMARY_ROOT_KEYS, "published summary")

    strict_equal(decision["decision"], contract["decision_semantics"], "decision semantics")
    strict_equal(summary["decision"], contract["decision_semantics"], "summary decision")
    strict_equal(decision["schema"], "vibeos.c84.qemu-aot-decision.evidence", "decision schema")
    strict_equal(
        environment["schema"],
        "vibeos.c84.qemu-aot-decision.environment",
        "environment schema",
    )
    strict_equal(summary["schema"], "vibeos.c84.qemu-aot-decision.summary", "summary schema")
    for label, document in (
        ("decision", decision),
        ("environment", environment),
        ("summary", summary),
    ):
        strict_equal(document["version"], 1, f"{label} version")
        strict_equal(
            document["suite_id"], "vibeos.c84.qemu-aot-decision", f"{label} suite"
        )
        strict_equal(
            document["source_commit"], contract["source"]["commit"], f"{label} source"
        )
        strict_equal(
            document["physical_provenance"], "not-claimed", f"{label} physical provenance"
        )
        strict_equal(
            document["platform"], "qemu-virt-rv64-tcg-icount-v1", f"{label} platform"
        )
        strict_equal(document["platform_class"], "emulator", f"{label} platform class")

    strict_equal(decision["mode"], "formal-publication", "decision mode")
    strict_equal(environment["mode"], "formal-publication", "environment mode")
    strict_equal(summary["capture_mode"], "formal-publication", "summary capture mode")
    strict_equal(
        decision["scope"],
        "one-fresh-fixed-qemu-process-no-physical-claim",
        "decision scope",
    )
    strict_equal(summary["scope"], decision["scope"], "summary scope")
    strict_equal(
        decision["next_node"], "C8.8-skip-or-defer-C8.5-C8.7", "decision next node"
    )
    strict_equal(
        decision["limitations"],
        [
            "This is a fixed-QEMU decision and makes no physical-hardware or cold-boot claim.",
            "Neither outcome authorizes AOT, JIT, RWX, external native bytes, or policy bypass.",
            "An eligible outcome opens C8.5 design review only; it does not accept native code.",
        ],
        "decision limitations",
    )

    for field in ("challenge", "run_id"):
        strict_equal(environment[field], decision[field], f"environment {field}")
        strict_equal(summary[field], decision[field], f"summary {field}")
        value = decision[field]
        if type(value) is not str or len(value) != 64:
            fail(f"decision {field} is not one SHA-256-shaped identity")
        try:
            decoded = bytes.fromhex(value)
        except ValueError as error:
            fail(f"decision {field} is not lowercase hexadecimal: {error}")
        if len(decoded) != 32 or value != value.lower():
            fail(f"decision {field} is not canonical lowercase hexadecimal")

    evidence_expected = {
        "environment": identity(contract["bundle"]["environment"]),
        "summary": identity(contract["bundle"]["summary"]),
        "transcript": identity(contract["bundle"]["uart"]),
    }
    strict_equal(decision["evidence"], evidence_expected, "decision evidence identities")
    strict_equal(
        environment["summary"],
        identity(contract["bundle"]["summary"]),
        "environment summary identity",
    )
    strict_equal(
        environment["transcript"],
        identity(contract["bundle"]["uart"]),
        "environment transcript identity",
    )
    strict_equal(
        summary["raw_transcript_bytes"],
        contract["bundle"]["uart"]["bytes"],
        "summary raw transcript bytes",
    )
    strict_equal(
        summary["raw_transcript_sha256"],
        contract["bundle"]["uart"]["sha256"],
        "summary raw transcript SHA-256",
    )

    contract_expected = {
        "evidence_schema": path_identity(contract["historical_blobs"]["evidence_schema"]),
        "manifest": path_identity(contract["historical_blobs"]["manifest"]),
        "transcript_schema": path_identity(contract["historical_blobs"]["transcript_schema"]),
    }
    strict_equal(decision["contract"], contract_expected, "decision contract identities")
    strict_equal(
        summary["manifest_sha256"],
        contract["historical_blobs"]["manifest"]["sha256"],
        "summary manifest SHA-256",
    )
    strict_equal(
        summary["transcript_schema_sha256"],
        contract["historical_blobs"]["transcript_schema"]["sha256"],
        "summary transcript schema SHA-256",
    )
    strict_equal(
        environment["verifier"],
        path_identity(contract["historical_blobs"]["qemu_verifier"]),
        "environment historical QEMU verifier",
    )
    helpers = environment["helpers"]
    if type(helpers) is not dict:
        fail("environment helpers must be one object")
    strict_equal(
        helpers.get("physical_contract_verifier"),
        path_identity(contract["historical_blobs"]["physical_helper"]),
        "environment historical physical helper",
    )

    environment_identity_keys = {
        "bios",
        "executed_peer_sources",
        "execution_custody",
        "helpers",
        "host_key_evidence",
        "kernel_elf",
        "openssh",
        "python_runtime",
        "qemu",
        "source_materialization",
        "toolchain",
    }
    environment_identity = exact_keys(
        decision["environment_identity"],
        environment_identity_keys,
        "decision environment identity",
    )
    exact_identity_keys = environment_identity_keys - {
        "bios",
        "kernel_elf",
        "openssh",
        "qemu",
        "toolchain",
    }
    for key in sorted(exact_identity_keys):
        strict_equal(
            environment_identity[key], environment[key], f"environment identity {key}"
        )
    for key in ("bios", "kernel_elf", "openssh", "qemu"):
        identity_value = environment_identity[key]
        environment_value = environment[key]
        if type(identity_value) is not dict or type(environment_value) is not dict:
            fail(f"environment identity {key} must be one object")
        strict_equal(
            identity_value,
            {member: environment_value[member] for member in identity_value},
            f"environment identity {key}",
        )
    toolchain_identity = environment_identity["toolchain"]
    toolchain = environment["toolchain"]
    if type(toolchain_identity) is not dict or type(toolchain) is not dict:
        fail("environment toolchain identities must be objects")
    strict_equal(
        toolchain_identity,
        {
            "build_input_closure": toolchain["build_input_closure"],
            "channel": toolchain["channel"],
            "linker_sha256": toolchain["linker"]["sha256"],
            "pinned_rustc_commit": toolchain["pinned_rustc_commit"],
            "rustc_sha256": toolchain["rustc"]["sha256"],
        },
        "environment identity toolchain",
    )
    materialization = environment["source_materialization"]
    if type(materialization) is not dict:
        fail("environment source materialization must be one object")
    strict_equal(
        materialization.get("superproject"),
        {
            "commit": contract["source"]["commit"],
            "entries": 786,
            "inventory_sha256": (
                "e65c739456d616c124dda6757feb792bb250fbe839bc5d815892d51e873ab897"
            ),
            "tree": contract["source"]["tree"],
        },
        "environment source materialization superproject",
    )
    strict_equal(materialization.get("decision_eligible"), True, "materialization eligibility")
    strict_equal(
        materialization.get("method"),
        "exact-commit-raw-blob-export-v1",
        "materialization method",
    )

    expected_run_contract = {
        "budget_ticks": 1_000_000,
        "fresh_qemu_processes": 1,
        "retained": 21,
        "timebase_hz": 10_000_000,
        "warmups": 3,
    }
    strict_equal(environment["contract"], expected_run_contract, "environment run contract")
    strict_equal(
        decision["population"],
        {
            "audit_inputs": 0,
            "fresh_qemu_processes": 1,
            "p50_sorted_index": 10,
            "p95_sorted_index": 19,
            "physical_inputs": 0,
            "retained": 21,
            "warmups": 3,
        },
        "decision population",
    )
    for field, expected in (
        ("fresh_qemu_processes", 1),
        ("retained", 21),
        ("timebase_hz", 10_000_000),
        ("warmups", 3),
    ):
        strict_equal(summary[field], expected, f"summary {field}")
    verify_retained_summary(summary, contract["decision_semantics"])
    strict_equal(decision["statistics"], summary["statistics"], "decision/summary statistics")

    if contract["policy"]["aot_authorized"] is not False:
        fail("contract unexpectedly authorizes AOT")
    if contract["policy"]["native_code_accepted"] is not False:
        fail("contract unexpectedly accepts native code")
    if decision["decision"]["aot_authorized"] is not False:
        fail("published decision unexpectedly authorizes AOT")
    if decision["decision"]["native_code_accepted"] is not False:
        fail("published decision unexpectedly accepts native code")


def audit_published() -> dict[str, object]:
    contract, contract_snapshot = load_contract()
    publication_blobs, head_commit = verify_repository_history(contract)
    snapshots = load_live_bundle(contract, publication_blobs, head_commit)
    verify_published_semantics(contract, snapshots)
    reread_exact(
        contract_snapshot,
        "final publication integrity contract",
        maximum=MAX_CONTRACT_BYTES,
    )
    for role, snapshot in snapshots.items():
        reread_exact(
            snapshot,
            f"final live published bundle {role}",
            maximum=MAX_BUNDLE_BYTES,
        )
    final_head_commit = git_text(
        ["rev-parse", "--verify", "HEAD^{commit}"], "final current HEAD commit"
    )
    if final_head_commit != head_commit:
        fail("current HEAD changed during the publication audit")
    return {
        "aot_authorized": False,
        "bundle_files": 4,
        "check_scope": "historical-structure-and-hash-integrity-only",
        "contract_is_evidence": False,
        "execution_replayed": False,
        "fixed_qemu_replaces_physical_duo_gate": True,
        "formal_closure_reestablished": False,
        "native_code_accepted": False,
        "other_hardware_gates_unchanged": True,
        "physical_inputs": 0,
        "physical_provenance": "not-claimed",
        "physical_provenance_claimed": False,
        "physical_tooling": "retained-non-blocking-non-evidence",
        "publication_commit": contract["publication"]["commit"],
        "publisher_execution_replayed": False,
        "qemu_execution_replayed": False,
        "replacement": contract["policy"]["replacement"],
        "replacement_scope": contract["policy"]["replacement_scope"],
        "status": "pass",
        "suite_id": contract["suite_id"],
    }


def expect_rejection(label: str, operation: Any, rejected: list[str]) -> None:
    try:
        operation()
    except AuditError:
        rejected.append(label)
        return
    fail(f"selftest mutation was accepted: {label}")


def run_selftest() -> dict[str, object]:
    summary = audit_published()
    contract, _snapshot = load_contract()
    rejected: list[str] = []

    def contract_mutation(label: str, mutate: Any) -> None:
        candidate = copy.deepcopy(contract)
        mutate(candidate)
        expect_rejection(
            label, lambda: validate_contract_object(candidate), rejected
        )

    contract_mutation(
        "authorization",
        lambda value: value["policy"].update(aot_authorized=True),
    )
    contract_mutation(
        "physical-input",
        lambda value: value["policy"].update(physical_inputs_permitted=1),
    )
    contract_mutation(
        "native-code-authorization",
        lambda value: value["policy"].update(native_code_accepted=True),
    )
    contract_mutation(
        "unrelated-hardware-gate-change",
        lambda value: value["policy"].update(other_hardware_gates_unchanged=False),
    )
    contract_mutation(
        "replacement-scope-widening",
        lambda value: value["policy"].update(replacement_scope="all-hardware"),
    )
    contract_mutation(
        "source-commit",
        lambda value: value["source"].update(commit="f" * 40),
    )
    contract_mutation(
        "bundle-hash",
        lambda value: value["bundle"]["summary"].update(sha256="f" * 64),
    )
    contract_mutation("extra-member", lambda value: value.update(extra=False))
    contract_mutation("bool-as-int", lambda value: value.update(version=True))

    bad_source = copy.deepcopy(contract["source"])
    bad_source["commit"] = "f" * 40
    expect_rejection(
        "git-source-commit",
        lambda: verify_commit_identity("mutated source", bad_source),
        rejected,
    )
    bad_bundle = copy.deepcopy(contract["bundle"]["summary"])
    bad_bundle["git_mode"] = "100755"
    expect_rejection(
        "git-bundle-tree-entry",
        lambda: verify_git_blob(
            contract["publication"]["commit"],
            bad_bundle,
            "mutated published summary",
        ),
        rejected,
    )

    float_candidate = copy.deepcopy(contract)
    float_candidate["version"] = 1.0
    expect_rejection(
        "float",
        lambda: strict_json(canonical_json(float_candidate), "float mutation"),
        rejected,
    )
    expect_rejection(
        "duplicate-member",
        lambda: strict_json(b'{"schema":1,"schema":1}\n', "duplicate mutation"),
        rejected,
    )
    expect_rejection(
        "noncanonical-json",
        lambda: strict_json(b'{"schema":1}\n', "noncanonical mutation"),
        rejected,
    )

    summary_snapshot = stable_regular_file(
        ROOT / contract["bundle"]["summary"]["path"],
        "selftest published summary",
        maximum=MAX_JSON_BYTES,
    )
    summary_value = strict_json(summary_snapshot.raw, "selftest published summary")
    missing_samples = copy.deepcopy(summary_value)
    missing_samples["retained_samples"] = []
    expect_rejection(
        "retained-sample-removal",
        lambda: verify_retained_summary(
            missing_samples, contract["decision_semantics"]
        ),
        rejected,
    )
    forged_statistics = copy.deepcopy(summary_value)
    forged_statistics["statistics"]["total_ticks"]["p95"] += 1
    expect_rejection(
        "derived-statistics-forgery",
        lambda: verify_retained_summary(
            forged_statistics, contract["decision_semantics"]
        ),
        rejected,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c84-qemu-published-selftest-"
        ) as temporary_name:
            temporary = pathlib.Path(temporary_name)
            fixture = temporary / "fixture"
            descriptor = os.open(
                fixture,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                fixture_raw = b"publication-integrity-selftest\n"
                if os.write(descriptor, fixture_raw) != len(fixture_raw):
                    fail("selftest fixture write was incomplete")
            finally:
                os.close(descriptor)

            symlink = temporary / "fixture-symlink"
            os.symlink(fixture.name, symlink)
            expect_rejection(
                "symlink",
                lambda: stable_regular_file(
                    symlink, "symlink mutation", maximum=1024
                ),
                rejected,
            )

            hardlink = temporary / "fixture-hardlink"
            os.link(fixture, hardlink)
            expect_rejection(
                "hardlink",
                lambda: stable_regular_file(
                    fixture, "hardlink mutation", maximum=1024
                ),
                rejected,
            )
            os.unlink(hardlink)

            fifo = temporary / "fixture-fifo"
            os.mkfifo(fifo, 0o600)
            expect_rejection(
                "fifo-nonblocking",
                lambda: stable_regular_file(
                    fifo, "FIFO mutation", maximum=1024
                ),
                rejected,
            )
    except OSError as error:
        fail(f"cannot create portable selftest fixtures: {error}")

    expected_rejections = [
        "authorization",
        "physical-input",
        "native-code-authorization",
        "unrelated-hardware-gate-change",
        "replacement-scope-widening",
        "source-commit",
        "bundle-hash",
        "extra-member",
        "bool-as-int",
        "git-source-commit",
        "git-bundle-tree-entry",
        "float",
        "duplicate-member",
        "noncanonical-json",
        "retained-sample-removal",
        "derived-statistics-forgery",
        "symlink",
        "hardlink",
        "fifo-nonblocking",
    ]
    strict_equal(rejected, expected_rejections, "selftest rejected mutations")
    summary["selftest_mutations_rejected"] = rejected
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Audit the fixed-path C8.4 fixed-QEMU publication's historical "
            "structure and hashes without replaying evidence."
        )
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check-published", action="store_true")
    modes.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        if arguments.check_published:
            result = audit_published()
        else:
            result = run_selftest()
        print(compact_json_line(result))
        return 0
    except AuditError as error:
        print(f"FAIL verify-c84-qemu-published-evidence: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
