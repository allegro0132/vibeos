#!/usr/bin/env python3
"""Independent powered-off C7.4 Component-publication verifier.

The verifier reads the raw block image after QEMU has stopped. It reuses the
independent frozen Storage V2 physical parser and the independent C7.3
artifact/signature verifier, but imports no production Rust and does not trust
the guest's serial PASS marker. The only admitted logical successor is the
exact inline evidence -> inline artifact -> Component root transaction.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VECTORS = ROOT / "policy/image/artifacts/c73-authenticated-admission.vectors"
BLOCK = 512
PAYLOAD = 0x50
COMPONENT_SPACE = 0x5649_4245_4F53_2D43_4F4D_504F_4E45_4E54
EVIDENCE_KIND = 0x434D_4531
ARTIFACT_KIND = 0x434D_5031
STORED_OBJECT_RESOURCE_KIND = 0x5354_4F52
READ = 0x01
ROOT_FLAG = 0x01
EVIDENCE_LEN = 112
ARTIFACT_HEADER_LEN = 352
MAX_C71_ARTIFACT_BYTES = 1_442_144

POLICY_V2 = (
    b"vibeos.storage-v2.external-policy.v2\0"
    b"persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0"
    b"program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0"
    b"component-space=0x564942454f532d434f4d504f4e454e54,slot=0,generation=0,rights=r,kind=0x434d5031\0"
    b"component-evidence=exact-root-relative,kind=0x434d4531,len=112,inline=1,ungranted=1\0"
    b"sealed-singleton-optional=0x53534801"
)
POLICY_V1 = (
    b"vibeos.storage-v2.external-policy.v1\0"
    b"persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0"
    b"program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0"
    b"sealed-singleton-optional=0x53534801"
)


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_module(filename: str, name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


migration = load_module(
    "verify-storage-v2-migration.py", "vibeos_c74_storage_v2_verifier"
)
c73 = load_module(
    "verify-c73-authenticated-admission.py", "vibeos_c74_artifact_verifier"
)
legacy = migration.legacy_codec


def u16(data: bytes, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def u64(data: bytes, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


def u128(data: bytes, at: int) -> int:
    return int.from_bytes(data[at : at + 16], "little")


def validate_evidence(encoded: bytes) -> None:
    evidence = c73.decode_evidence(encoded)
    require(any(evidence.key), "operator evidence uses the zero public-key sentinel")
    require(any(evidence.signature), "operator evidence uses the zero signature sentinel")
    require(c73.encode_evidence(evidence.key, evidence.signature) == encoded,
            "operator evidence is not the exact canonical 112-byte encoding")


def exact_policy_objects(state: Any) -> dict[int, tuple[int, bytes, int]]:
    """Narrow policy-v2 object selection used by the physical parser.

    The empty native floor remains valid. A non-empty current generation must
    be exactly one C7.4 initial Component bundle: the artifact is the sole CAS
    binding, while the exact root-relative inline evidence remains retained in
    the logical checkpoint only. There are no persistent/program/SSH roots,
    tombstones, or objects selected by kind or recency.
    """

    require(state.formatted, "logical authority stream is not formatted")
    if not state.objects and not state.grants and not state.tombstones:
        require(not state.live and not state.slots, "empty floor retains authority")
        return {}

    require(len(state.objects) == 2, "C7.4 authority does not contain exactly two objects")
    require(len(state.grants) == 1, "C7.4 authority does not contain exactly one grant")
    require(not state.tombstones, "C7.4 initial publication contains a tombstone")
    require(len(state.live) == 1, "C7.4 root is not the sole live derivation")
    require(len(state.slots) == 1, "C7.4 publication contains foreign slot history")

    grant = state.grants[0]
    base = grant.derivation - 5
    require(base > 0, "C7.4 root derivation cannot identify a valid base")
    evidence_id = base + 1
    artifact_id = base + 3
    evidence = state.objects.get(evidence_id)
    artifact = state.objects.get(artifact_id)
    require(evidence is not None and artifact is not None,
            "C7.4 evidence/artifact IDs do not match exact base arithmetic")
    evidence_kind, evidence_bytes, evidence_commit = evidence
    artifact_kind, artifact_bytes, artifact_commit = artifact
    validate_evidence(evidence_bytes)
    require(evidence_kind == EVIDENCE_KIND, "C7.4 evidence ObjectKind differs from CME1")
    require(artifact_kind == ARTIFACT_KIND, "C7.4 artifact ObjectKind differs from CMP1")
    require(ARTIFACT_HEADER_LEN <= len(artifact_bytes) <= MAX_C71_ARTIFACT_BYTES,
            "C7.4 inline artifact length is outside the C7.1 profile")
    require(
        (
            grant.derivation,
            grant.parent,
            grant.object_id,
            grant.space,
            grant.slot,
            grant.generation,
            grant.rights,
            grant.resource_kind,
            grant.flags,
        )
        == (
            base + 5,
            0,
            artifact_id,
            COMPONENT_SPACE,
            0,
            0,
            READ,
            STORED_OBJECT_RESOURCE_KIND,
            ROOT_FLAG,
        ),
        "C7.4 root grant shape differs from the exact policy-v2 root",
    )
    require(evidence_commit < artifact_commit < grant.commit_sequence,
            "C7.4 evidence/artifact/root commit order differs")
    require(state.high_water == max(base + 6, COMPONENT_SPACE + 1),
            "C7.4 sole high-water reservation differs")
    require(state.live.get(grant.derivation) == grant,
            "C7.4 exact root is not live")
    require(state.slots == {(COMPONENT_SPACE, 0): (0, grant.derivation)},
            "C7.4 Component slot identity differs")
    # Evidence is deliberately not materializable and must never acquire a V2
    # ObjectId/token merely because policy retains its exact logical record.
    return {artifact_id: artifact}


def decoded_records(record_stream: bytes) -> list[Any]:
    require(record_stream and len(record_stream) % BLOCK == 0,
            "C7.4 record stream is not 512-byte aligned")
    records = []
    for index in range(0, len(record_stream), BLOCK):
        raw = record_stream[index : index + BLOCK]
        decoded = legacy.decode_sector(raw, migration.M4_FIRST + index // BLOCK)
        require(decoded is not None, "C7.4 stream contains an empty or torn logical record")
        records.append(decoded)
    require([record.sequence for record in records] == list(range(1, len(records) + 1)),
            "C7.4 logical sequences are not exact and dense")
    return records


def authenticate_artifact(artifact: bytes, evidence: bytes, vectors_path: Path) -> str:
    vectors = c73.load_vectors(vectors_path)
    # The target acceptance installs exactly operator_p1()[0], not merely any
    # artifact which happens to authenticate under one checked-in operator
    # policy. Bind the powered-off bytes to that same frozen fixture before
    # repeating the independent signature/policy verification.
    require(
        artifact == vectors["operator_a_p1_artifact"],
        "durable artifact differs from the exact C7.4 QEMU fixture",
    )
    require(
        evidence == vectors["operator_a_p1_evidence"],
        "durable evidence differs from the exact C7.4 QEMU fixture",
    )
    c73.authenticate(artifact, vectors["policy_p1"], evidence)
    return "p1"


def validate_exact_logical(record_stream: bytes, vectors_path: Path) -> dict[str, Any]:
    # The legacy module is used only as an independent parser for the frozen
    # 512-byte *logical* record ABI. No production M4 media append is involved.
    state = migration.recover_record_stream(record_stream)
    selected = exact_policy_objects(state)
    records = decoded_records(record_stream)
    require(len(records) >= 11, "C7.4 logical stream is too short for one complete bundle")
    require(records[0].kind == legacy.FORMAT, "C7.4 stream does not start with Format")
    require(records[1].kind == legacy.HIGH_WATER and records[1].transaction == 0,
            "C7.4 sole high-water record is absent or misplaced")
    require(sum(record.kind == legacy.HIGH_WATER for record in records) == 1,
            "C7.4 stream contains more than one high-water reservation")

    evidence_prepare = records[2]
    require(evidence_prepare.kind == legacy.OBJECT_PREPARE,
            "C7.4 evidence prepare is not first after reservation")
    base = evidence_prepare.transaction
    require(base > 0, "C7.4 evidence transaction is zero")
    evidence_object = base + 1
    artifact_transaction = base + 2
    artifact_object = base + 3
    root_transaction = base + 4
    root_derivation = base + 5
    require(u128(records[1].raw, PAYLOAD) == max(base + 6, COMPONENT_SPACE + 1),
            "C7.4 high-water value does not cover exact IDs and fixed Component SpaceId")
    require(
        (
            u128(evidence_prepare.raw, PAYLOAD),
            u32(evidence_prepare.raw, PAYLOAD + 16),
            u64(evidence_prepare.raw, PAYLOAD + 24),
            u32(evidence_prepare.raw, PAYLOAD + 32),
        )
        == (evidence_object, EVIDENCE_KIND, EVIDENCE_LEN, 1),
        "C7.4 evidence prepare metadata differs",
    )
    evidence_chunk = records[3]
    evidence_commit = records[4]
    require(
        evidence_chunk.kind == legacy.OBJECT_CHUNK
        and evidence_chunk.transaction == base
        and u128(evidence_chunk.raw, PAYLOAD) == evidence_object
        and u32(evidence_chunk.raw, PAYLOAD + 16) == 0
        and u16(evidence_chunk.raw, PAYLOAD + 20) == EVIDENCE_LEN,
        "C7.4 evidence chunk differs",
    )
    evidence_bytes = evidence_chunk.raw[PAYLOAD + 24 : PAYLOAD + 24 + EVIDENCE_LEN]
    require(
        evidence_commit.kind == legacy.OBJECT_COMMIT
        and evidence_commit.transaction == base
        and u128(evidence_commit.raw, PAYLOAD) == evidence_object
        and evidence_commit.sequence == evidence_prepare.sequence + 2,
        "C7.4 evidence transaction is not exact",
    )
    validate_evidence(evidence_bytes)

    artifact_prepare = records[5]
    require(
        artifact_prepare.kind == legacy.OBJECT_PREPARE
        and artifact_prepare.transaction == artifact_transaction
        and u128(artifact_prepare.raw, PAYLOAD) == artifact_object
        and u32(artifact_prepare.raw, PAYLOAD + 16) == ARTIFACT_KIND
        and evidence_commit.sequence + 1 == artifact_prepare.sequence,
        "C7.4 artifact prepare does not immediately follow evidence commit",
    )
    artifact_len = u64(artifact_prepare.raw, PAYLOAD + 24)
    artifact_chunks = u32(artifact_prepare.raw, PAYLOAD + 32)
    require(
        ARTIFACT_HEADER_LEN <= artifact_len <= MAX_C71_ARTIFACT_BYTES
        and artifact_chunks == (artifact_len + 359) // 360,
        "C7.4 artifact inline geometry differs",
    )
    artifact_chunk_records = records[6 : 6 + artifact_chunks]
    require(len(artifact_chunk_records) == artifact_chunks,
            "C7.4 artifact chunks are truncated")
    artifact_bytes = bytearray()
    for index, record in enumerate(artifact_chunk_records):
        expected_len = min(360, artifact_len - index * 360)
        require(
            record.kind == legacy.OBJECT_CHUNK
            and record.transaction == artifact_transaction
            and u128(record.raw, PAYLOAD) == artifact_object
            and u32(record.raw, PAYLOAD + 16) == index
            and u16(record.raw, PAYLOAD + 20) == expected_len,
            "C7.4 artifact chunk ordering or binding differs",
        )
        artifact_bytes.extend(record.raw[PAYLOAD + 24 : PAYLOAD + 24 + expected_len])
    artifact_commit_index = 6 + artifact_chunks
    artifact_commit = records[artifact_commit_index]
    require(
        artifact_commit.kind == legacy.OBJECT_COMMIT
        and artifact_commit.transaction == artifact_transaction
        and u128(artifact_commit.raw, PAYLOAD) == artifact_object,
        "C7.4 artifact commit differs",
    )
    root_prepare = records[artifact_commit_index + 1]
    root_commit = records[artifact_commit_index + 2]
    require(artifact_commit_index + 3 == len(records),
            "C7.4 stream contains history after initial root publication")
    require(
        root_prepare.kind == legacy.GRANT_PREPARE
        and root_prepare.transaction == root_transaction
        and artifact_commit.sequence + 1 == root_prepare.sequence,
        "C7.4 root prepare does not immediately follow artifact commit",
    )
    require(
        (
            u128(root_prepare.raw, PAYLOAD),
            u128(root_prepare.raw, PAYLOAD + 16),
            u128(root_prepare.raw, PAYLOAD + 32),
            u128(root_prepare.raw, PAYLOAD + 48),
            u32(root_prepare.raw, PAYLOAD + 64),
            u64(root_prepare.raw, PAYLOAD + 72),
            u32(root_prepare.raw, PAYLOAD + 68),
            u32(root_prepare.raw, PAYLOAD + 80),
            u32(root_prepare.raw, PAYLOAD + 84),
        )
        == (
            root_derivation,
            0,
            artifact_object,
            COMPONENT_SPACE,
            0,
            0,
            READ,
            STORED_OBJECT_RESOURCE_KIND,
            ROOT_FLAG,
        ),
        "C7.4 root prepare shape differs",
    )
    require(
        root_commit.kind == legacy.GRANT_COMMIT
        and root_commit.transaction == root_transaction
        and u128(root_commit.raw, PAYLOAD + 16) == root_derivation
        and root_commit.sequence == root_prepare.sequence + 1,
        "C7.4 root commit differs",
    )
    require(set(selected) == {artifact_object},
            "C7.4 physical selection is not the sole artifact root")
    require(state.objects[evidence_object][1] == evidence_bytes,
            "C7.4 retained logical evidence differs from its exact chunk")
    require(selected[artifact_object][1] == bytes(artifact_bytes),
            "C7.4 recovered artifact differs from its exact chunks")
    policy = authenticate_artifact(bytes(artifact_bytes), evidence_bytes, vectors_path)
    return {
        "record_count": len(records),
        "evidence_bytes": len(evidence_bytes),
        "artifact_bytes": len(artifact_bytes),
        "operator_policy": policy,
        "policy_v2": True,
    }


def configure_physical_parser() -> None:
    # The shared parser deliberately defaults to the pre-C7.4 v1 policy. Set
    # its externally supplied policy input and exact selector before parsing;
    # no v1 bytes are reinterpreted as v2.
    migration.EXTERNAL_POLICY = POLICY_V2
    migration.exact_policy_objects = exact_policy_objects


def verify_image(image: bytes, vectors_path: Path) -> dict[str, Any]:
    configure_physical_parser()
    require(len(image) % BLOCK == 0, "powered-off image is not block aligned")
    # C7.4 acceptance starts from a blank native V2 disk. Enforce both the
    # unmanaged prefix and frozen M4 range as all-zero, rather than accepting a
    # caller-provided baseline that could conceal an M4 write.
    require(not any(image[: migration.M4_FIRST * BLOCK]),
            "C7.4 native image changed the unmanaged prefix")
    m4_start = migration.M4_FIRST * BLOCK
    m4_end = (migration.M4_FIRST + migration.M4_COUNT) * BLOCK
    require(not any(image[m4_start:m4_end]),
            "C7.4 production publication wrote the frozen M4 range")
    physical = migration.verify_image(
        image,
        bytes(migration.M4_FIRST * BLOCK),
        expect_native=True,
    )
    status, evidence = migration.probe_v2(image)
    require(status == "valid" and evidence is not None,
            "C7.4 Storage V2 authority is not independently recoverable")
    recovered = evidence["recovered"]
    authority = recovered["authority"]
    require(authority is not None, "C7.4 selected checkpoint has no authority payload")
    require(
        bytes.fromhex(physical["control"]["selected"]["store_uuid"])
        == migration.NATIVE_STORE_UUID,
        "C7.4 selector does not bind the native Storage V2 UUID",
    )
    logical = validate_exact_logical(authority["record_stream"], vectors_path)
    bindings = authority["objects"]
    require(len(bindings) == 1 and not authority["external_roots"],
            "C7.4 authority binding table is not exactly one inline artifact")
    require(bindings[0]["object_kind"] == ARTIFACT_KIND,
            "C7.4 physical binding differs from the sole CMP1 artifact")
    return {
        "schema": "vibeos.c74.crash-safe-publication-verifier",
        "version": 1,
        "status": "ok",
        "storage": {
            "mode": physical["mode"],
            "m4_zero": True,
            "selected_checkpoint_generation": evidence[
                "selected_checkpoint_generation"
            ],
            "authority_generation": evidence["authority_generation"],
            "verified_checkpoint_copies": evidence["verified_checkpoint_copies"],
        },
        "logical": logical,
        "physical_bindings": len(bindings),
        "guest_marker_trusted": False,
    }


class LogicalBuilder:
    """Selftest-only encoder for the frozen logical 512-byte ABI."""

    def __init__(self) -> None:
        self.records: list[bytes] = []
        self.previous_sequence = 0
        self.previous_crc = 0

    def append(self, kind: int, payload: bytes, transaction: int = 0) -> Any:
        sequence = len(self.records) + 1
        raw = legacy.encode_record(
            kind,
            payload,
            sequence,
            self.previous_sequence,
            self.previous_crc,
            transaction,
        )
        record = legacy.decode_sector(raw, migration.M4_FIRST + sequence - 1)
        require(record is not None, "selftest encoder produced no record")
        self.records.append(raw)
        self.previous_sequence = sequence
        self.previous_crc = record.crc
        return record


def append_object(builder: LogicalBuilder, transaction: int, object_id: int,
                  kind: int, content: bytes) -> None:
    chunks = (len(content) + 359) // 360
    prepare_payload = bytearray(40)
    prepare_payload[:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<I", prepare_payload, 16, kind)
    struct.pack_into("<Q", prepare_payload, 24, len(content))
    struct.pack_into("<I", prepare_payload, 32, chunks)
    struct.pack_into("<I", prepare_payload, 36, legacy.crc32c(content))
    prepare = builder.append(legacy.OBJECT_PREPARE, bytes(prepare_payload), transaction)
    chunk_crcs = bytearray()
    first_chunk_sequence = 0
    for index in range(chunks):
        data = content[index * 360 : (index + 1) * 360]
        chunk_payload = bytearray(384)
        chunk_payload[:16] = object_id.to_bytes(16, "little")
        struct.pack_into("<I", chunk_payload, 16, index)
        struct.pack_into("<H", chunk_payload, 20, len(data))
        chunk_payload[24 : 24 + len(data)] = data
        record = builder.append(legacy.OBJECT_CHUNK, bytes(chunk_payload), transaction)
        if index == 0:
            first_chunk_sequence = record.sequence
        chunk_crcs.extend(struct.pack("<I", record.crc))
    commit_payload = bytearray(48)
    commit_payload[:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<Q", commit_payload, 16, prepare.sequence)
    struct.pack_into("<I", commit_payload, 24, prepare.crc)
    struct.pack_into("<I", commit_payload, 28, chunks)
    struct.pack_into("<Q", commit_payload, 32, first_chunk_sequence)
    struct.pack_into("<I", commit_payload, 40, legacy.crc32c(bytes(chunk_crcs)))
    struct.pack_into("<I", commit_payload, 44, legacy.crc32c(content))
    builder.append(legacy.OBJECT_COMMIT, bytes(commit_payload), transaction)


def append_grant(
    builder: LogicalBuilder,
    transaction: int,
    derivation: int,
    object_id: int,
    *,
    parent: int = 0,
    space: int = COMPONENT_SPACE,
    slot: int = 0,
    generation: int = 0,
    rights: int = READ,
    resource_kind: int = STORED_OBJECT_RESOURCE_KIND,
    flags: int = ROOT_FLAG,
) -> None:
    grant_payload = bytearray(88)
    grant_payload[:16] = derivation.to_bytes(16, "little")
    grant_payload[16:32] = parent.to_bytes(16, "little")
    grant_payload[32:48] = object_id.to_bytes(16, "little")
    grant_payload[48:64] = space.to_bytes(16, "little")
    struct.pack_into("<I", grant_payload, 64, slot)
    struct.pack_into("<I", grant_payload, 68, rights)
    struct.pack_into("<Q", grant_payload, 72, generation)
    struct.pack_into("<I", grant_payload, 80, resource_kind)
    struct.pack_into("<I", grant_payload, 84, flags)
    prepare = builder.append(legacy.GRANT_PREPARE, bytes(grant_payload), transaction)
    commit_payload = bytearray(32)
    struct.pack_into("<Q", commit_payload, 0, prepare.sequence)
    struct.pack_into("<I", commit_payload, 8, prepare.crc)
    commit_payload[16:32] = derivation.to_bytes(16, "little")
    builder.append(legacy.GRANT_COMMIT, bytes(commit_payload), transaction)


def logical_fixture(
    artifact: bytes,
    evidence: bytes,
    *,
    base: int = 1,
    grant_object_delta: int = 3,
    evidence_kind: int = EVIDENCE_KIND,
    artifact_kind: int = ARTIFACT_KIND,
    evidence_transaction_delta: int = 0,
    evidence_object_delta: int = 1,
    artifact_transaction_delta: int = 2,
    artifact_object_delta: int = 3,
    root_transaction_delta: int = 4,
    root_derivation_delta: int = 5,
    artifact_first: bool = False,
    root_parent_delta: int | None = None,
    root_space: int = COMPONENT_SPACE,
    root_slot: int = 0,
    root_generation: int = 0,
    root_rights: int = READ,
    root_resource_kind: int = STORED_OBJECT_RESOURCE_KIND,
    root_flags: int = ROOT_FLAG,
    extra_evidence_grant: bool = False,
    high_water: int | None = None,
) -> bytes:
    builder = LogicalBuilder()
    builder.append(legacy.FORMAT, b"")
    reservation = high_water if high_water is not None else max(base + 8, COMPONENT_SPACE + 1)
    builder.append(legacy.HIGH_WATER, reservation.to_bytes(16, "little"))
    if artifact_first:
        append_object(
            builder,
            base + artifact_transaction_delta,
            base + artifact_object_delta,
            artifact_kind,
            artifact,
        )
        append_object(
            builder,
            base + evidence_transaction_delta,
            base + evidence_object_delta,
            evidence_kind,
            evidence,
        )
    else:
        append_object(
            builder,
            base + evidence_transaction_delta,
            base + evidence_object_delta,
            evidence_kind,
            evidence,
        )
        append_object(
            builder,
            base + artifact_transaction_delta,
            base + artifact_object_delta,
            artifact_kind,
            artifact,
        )
    append_grant(
        builder,
        base + root_transaction_delta,
        base + root_derivation_delta,
        base + grant_object_delta,
        parent=(0 if root_parent_delta is None else base + root_parent_delta),
        space=root_space,
        slot=root_slot,
        generation=root_generation,
        rights=root_rights,
        resource_kind=root_resource_kind,
        flags=root_flags,
    )
    if extra_evidence_grant:
        append_grant(builder, base + 6, base + 7, base + 1, slot=1)
    return b"".join(builder.records)


def selftest(vectors_path: Path) -> dict[str, Any]:
    vectors = c73.load_vectors(vectors_path)
    artifact = vectors["operator_a_p1_artifact"]
    evidence = vectors["operator_a_p1_evidence"]
    valid = logical_fixture(artifact, evidence)
    result = validate_exact_logical(valid, vectors_path)
    cases = 1

    invalid = [
        logical_fixture(artifact, evidence, evidence_kind=ARTIFACT_KIND),
        logical_fixture(artifact, evidence, artifact_kind=0x7F00_0001),
        logical_fixture(artifact, evidence, evidence_transaction_delta=8),
        logical_fixture(artifact, evidence, evidence_object_delta=8),
        logical_fixture(artifact, evidence, artifact_transaction_delta=8),
        logical_fixture(artifact, evidence, artifact_object_delta=8),
        logical_fixture(artifact, evidence, root_transaction_delta=8),
        logical_fixture(artifact, evidence, root_derivation_delta=8),
        logical_fixture(artifact, evidence, grant_object_delta=1),
        logical_fixture(artifact, evidence, artifact_first=True),
        logical_fixture(artifact, evidence, root_parent_delta=7),
        logical_fixture(artifact, evidence, root_space=0x1234),
        logical_fixture(artifact, evidence, root_slot=1),
        logical_fixture(artifact, evidence, root_generation=1),
        logical_fixture(artifact, evidence, root_rights=READ | 0x10),
        logical_fixture(artifact, evidence, root_resource_kind=0x1234),
        logical_fixture(artifact, evidence, root_flags=0),
        logical_fixture(artifact, evidence, extra_evidence_grant=True),
        logical_fixture(artifact, evidence[:-1]),
        logical_fixture(artifact, evidence, high_water=6),
        logical_fixture(artifact, vectors["wrong_signer_evidence"]),
        logical_fixture(vectors["operator_b_p1_artifact"], evidence),
        logical_fixture(
            vectors["operator_b_p1_artifact"],
            vectors["operator_b_p1_evidence"],
        ),
        logical_fixture(
            vectors["operator_a_p2_artifact"],
            vectors["operator_a_p2_evidence"],
        ),
    ]
    for candidate in invalid:
        try:
            validate_exact_logical(candidate, vectors_path)
        except (ValueError, struct.error, c73.VerificationError):
            cases += 1
        else:
            raise VerificationError("C7.4 logical selftest mutation was accepted")
    require(result["operator_policy"] == "p1", "C7.4 valid selftest policy differs")
    configure_physical_parser()
    canonical = bytearray(migration.canonical_empty_authority_payload(2))
    canonical[0x18:0x38] = hashlib.sha256(POLICY_V1).digest()
    try:
        migration.parse_authority_snapshot(bytes(canonical), 2)
    except ValueError:
        cases += 1
    else:
        raise VerificationError("policy-v1 authority was reinterpreted as policy-v2")
    return {
        "schema": "vibeos.c74.crash-safe-publication-selftest",
        "version": 1,
        "status": "ok",
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    args = parser.parse_args()
    if args.image is None and not args.selftest:
        parser.error("provide a powered-off image and/or --selftest")
    try:
        outputs = []
        if args.selftest:
            outputs.append(selftest(args.vectors))
        if args.image is not None:
            outputs.append(verify_image(args.image.read_bytes(), args.vectors))
        for output in outputs:
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    except (
        OSError,
        UnicodeError,
        ValueError,
        struct.error,
        c73.VerificationError,
    ) as error:
        print(f"FAIL verify-c74-crash-safe-publication: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
