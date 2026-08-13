#!/usr/bin/env python3
"""Rust-independent powered-off verifier for the M7.7 migration selector."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Any

BLOCK = 512
PAGE = 4096
M4_FIRST = 64
M4_COUNT = 512
CONTROL_FIRST = 576
CONTROL_COUNT = 32
V2_FIRST = 2048
V2_COUNT = 65664
CONTROL_PAGES = 4

VERSION = 1
HEADER_LEN = 0x100
BODY_MAGIC = b"VIBEMG2\0"
SEAL_MAGIC = b"VIBEMS2\0"
TERMINAL = b"VIBEMG2-COMMIT!!"
BODY_DIGEST_AT = 0x20
SEAL_DIGEST_AT = 0x20
TERMINAL_AT = PAGE - len(TERMINAL)

FROZEN = 1
STAGED = 2
ACTIVE = 3
CLOSED = 4
STATE_NAMES = {FROZEN: "frozen_m4", STAGED: "v2_staged", ACTIVE: "v2_active", CLOSED: "rollback_closed"}
M4_MAGIC = b"VIBECAP\0"
V2_MAGIC = b"VIBESG2\0"

CAS_DELTA_HEADER_LEN = 0xA0
CAS_DELTA_REUSE_LEN = CAS_DELTA_HEADER_LEN + 0x60
CAS_DELTA_NEW_BLOB_LEN = CAS_DELTA_REUSE_LEN + 0xA0
CAS_KIND_DELTA = 2
DELTA_FLAG_NEW_BLOB = 1
EXTENT_CATALOG_DELTA = 5

AUTHORITY_MAGIC = b"VIBEAUT2"
AUTHORITY_VERSION = 1
AUTHORITY_HEADER_LEN = 0x80
AUTHORITY_OBJECT_LEN = 0x30
AUTHORITY_PRINCIPAL_LEN = 0x40
MAX_AUTHORITY_BYTES = 256 * PAGE
MAX_PRINCIPALS = 256
EXTERNAL_POLICY = b"vibeos.storage-v2.external-policy.v1\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0sealed-singleton-optional=0x53534801"
PERSISTENT_SPACE = 0x5053
PROGRAM_SPACE = 0x50524F47
STORED_OBJECT_RESOURCE_KIND = 0x53544F52
PERSISTENT_OBJECT_KIND = 0x43535043
PROGRAM_OBJECT_KIND = 0x50524731
SSH_OBJECT_KIND = 0x53534801
SYSTEM_PRINCIPAL = b"VIBE-M4-SYSTEM!!"
NATIVE_STORE_UUID = b"VIBEOS-STOR-V2!!"
PERSISTENT_ROOT_RIGHTS = 0x01 | 0x10 | 0x20
PROGRAM_ROOT_RIGHTS = 0x01


class Violation(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Violation(message)


def load_module(filename: str, name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses consult sys.modules while the persistent-CSpace module is
    # executing. Keep the independent verifier import conventional.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


legacy_codec = load_module(
    "persistent-cspace-image.py", "vibeos_migration_legacy_codec"
)
gc_verifier = load_module(
    "verify-storage-v2-gc.py", "vibeos_migration_storage_v2_gc"
)
storage_codec = gc_verifier.storage
program_codec = load_module(
    "program-image.py", "vibeos_migration_program_codec"
)


def u16(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def u32(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def u64(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


def u128(data: bytes | bytearray, at: int) -> int:
    low, high = struct.unpack_from("<QQ", data, at)
    return low | high << 64


def put_u16(data: bytearray, at: int, value: int) -> None:
    struct.pack_into("<H", data, at, value)


def put_u64(data: bytearray, at: int, value: int) -> None:
    struct.pack_into("<Q", data, at, value)


def offset(first_block: int, relative_page: int = 0) -> int:
    return first_block * BLOCK + relative_page * PAGE


def page_at(image: bytes | bytearray, first: int, relative: int) -> bytes:
    start = offset(first, relative)
    require(start + PAGE <= len(image), "image is shorter than a declared range")
    return bytes(image[start:start + PAGE])


def parse_control(body: bytes, seal: bytes) -> dict[str, Any]:
    if not any(body) and not any(seal):
        return {"status": "empty"}
    expected_seal = canonical_seal(body)
    if (
        not any(seal)
        or canonical_write_prefix(seal, expected_seal)
        or canonical_clear_prefix(seal, expected_seal)
    ):
        return {"status": "torn"}
    require(body[:8] == BODY_MAGIC and seal[:8] == SEAL_MAGIC, "bad control magic")
    require(u16(body, 0x08) == VERSION and u16(seal, 0x08) == VERSION, "unsupported control version")
    require(u16(body, 0x0A) == HEADER_LEN, "bad control header length")
    state = body[0x0C]
    require(state in STATE_NAMES, "bad control state")
    require(not any(body[0x0D:0x10]) and not any(body[0x18:0x20]), "non-zero body header reserved bytes")
    require(not any(body[0xA8:0x100]) and not any(body[0x100:]), "non-zero body reserved bytes")
    require(not any(seal[0x0A:0x10]) and not any(seal[0x18:0x20]), "non-zero seal header reserved bytes")
    require(not any(seal[0x40:TERMINAL_AT]), "non-zero seal reserved bytes")
    require(seal[TERMINAL_AT:] == TERMINAL, "control terminal marker is invalid")
    payload_digest = hashlib.sha256(body[0x40:]).digest()
    body_digest = hashlib.sha256(body).digest()
    require(body[BODY_DIGEST_AT:BODY_DIGEST_AT + 32] == payload_digest, "payload digest mismatch")
    require(seal[SEAL_DIGEST_AT:SEAL_DIGEST_AT + 32] == body_digest, "body digest mismatch")
    generation = u64(body, 0x10)
    require(generation > 0 and generation == u64(seal, 0x10), "bad control generation")
    record = {
        "state": STATE_NAMES[state],
        "generation": generation,
        "device_id": body[0x40:0x50].hex(),
        "m4_first_logical_block": u64(body, 0x50),
        "m4_logical_block_count": u64(body, 0x58),
        "v2_first_logical_block": u64(body, 0x60),
        "v2_logical_block_count": u64(body, 0x68),
        "store_uuid": body[0x70:0x80].hex(),
        "activation_checkpoint_generation": u64(body, 0x80),
        "activation_authority_sha256": body[0x88:0xA8].hex(),
    }
    require(bytes.fromhex(record["device_id"]) != bytes(16), "zero device id")
    require(record["m4_logical_block_count"] > 0 and record["v2_logical_block_count"] > 0, "empty data range")
    require(
        record["m4_first_logical_block"] == M4_FIRST
        and record["m4_logical_block_count"] == M4_COUNT
        and record["v2_first_logical_block"] == V2_FIRST
        and record["v2_logical_block_count"] == V2_COUNT,
        "selector differs from the platform migration ranges",
    )
    m4_end = record["m4_first_logical_block"] + record["m4_logical_block_count"]
    v2_end = record["v2_first_logical_block"] + record["v2_logical_block_count"]
    require(m4_end <= v2_end and not (record["m4_first_logical_block"] < v2_end and record["v2_first_logical_block"] < m4_end), "data ranges overlap")
    fields_present = (
        bytes.fromhex(record["store_uuid"]) != bytes(16),
        record["activation_checkpoint_generation"] > 0,
        bytes.fromhex(record["activation_authority_sha256"]) != bytes(32),
    )
    require(
        (state == FROZEN and not any(fields_present))
        or (state != FROZEN and all(fields_present)),
        "state publication fields disagree",
    )
    return {"status": "sealed", "record": record}


def canonical_seal(body: bytes) -> bytes:
    seal = bytearray(PAGE)
    seal[:8] = SEAL_MAGIC
    put_u16(seal, 0x08, VERSION)
    seal[0x10:0x18] = body[0x10:0x18]
    seal[SEAL_DIGEST_AT:SEAL_DIGEST_AT + 32] = hashlib.sha256(body).digest()
    seal[TERMINAL_AT:] = TERMINAL
    return bytes(seal)


def canonical_write_prefix(observed: bytes, expected: bytes) -> bool:
    nonzero = [index for index, byte in enumerate(observed) if byte]
    if not nonzero:
        return True
    last = nonzero[-1]
    return last < PAGE - 1 and observed[:last + 1] == expected[:last + 1]


def canonical_clear_prefix(observed: bytes, expected: bytes) -> bool:
    first = next((index for index, byte in enumerate(observed) if byte), None)
    if first is None:
        return True
    return first > 0 and observed[first:] == expected[first:]


def same_stable_binding(left: dict[str, Any], right: dict[str, Any]) -> bool:
    fields = ("device_id", "m4_first_logical_block", "m4_logical_block_count", "v2_first_logical_block", "v2_logical_block_count")
    return all(left[name] == right[name] for name in fields)


def valid_adjacent_transition(left: dict[str, Any], right: dict[str, Any]) -> bool:
    older, newer = sorted((left, right), key=lambda item: item["generation"])
    if newer["generation"] != older["generation"] + 1 or not same_stable_binding(older, newer):
        return False
    allowed = {("frozen_m4", "v2_staged"), ("v2_staged", "v2_active"), ("v2_staged", "frozen_m4"), ("v2_active", "rollback_closed")}
    if (older["state"], newer["state"]) not in allowed:
        return False
    if newer["state"] in ("v2_active", "rollback_closed"):
        fields = (
            "store_uuid",
            "activation_checkpoint_generation",
            "activation_authority_sha256",
        )
        return all(older[name] == newer[name] for name in fields)
    return True


def select_control(slots: list[dict[str, Any]]) -> dict[str, Any] | None:
    sealed = []
    for slot_index, slot in enumerate(slots):
        if slot["status"] == "sealed":
            record = slot["record"]
            require(
                (record["generation"] - 1) & 1 == slot_index,
                "sealed control is in the wrong alternating slot",
            )
            sealed.append(record)
    if not sealed:
        return None
    if len(sealed) == 2:
        if sealed[0]["generation"] == sealed[1]["generation"]:
            require(sealed[0] == sealed[1], "same-generation controls disagree")
        else:
            require(valid_adjacent_transition(sealed[0], sealed[1]), "sealed controls are not one valid adjacent transition")
    return max(sealed, key=lambda item: item["generation"])


def probe_m4(image: bytes | bytearray) -> str:
    region = image[M4_FIRST * BLOCK:(M4_FIRST + M4_COUNT) * BLOCK]
    if not any(region):
        return "absent"
    try:
        # The frozen durable-format ABI permanently ignores an unsealed
        # append, even when a later physical sector contains the next valid
        # chain record. Sealed malformed records and every semantic/chain
        # violation still reject the complete journal.
        state = legacy_codec.recover(bytes(image[:(M4_FIRST + M4_COUNT) * BLOCK]))
        return "valid" if state.formatted else "absent"
    except Exception:
        return "corrupt"


def canonical_m4_stream(image: bytes | bytearray) -> tuple[bytes, Any]:
    records = bytearray()
    for relative in range(M4_COUNT):
        start = (M4_FIRST + relative) * BLOCK
        sector = bytes(image[start:start + BLOCK])
        decoded = legacy_codec.decode_sector(sector, M4_FIRST + relative)
        if decoded is not None:
            records.extend(sector)
    state = legacy_codec.recover(bytes(image[:(M4_FIRST + M4_COUNT) * BLOCK]))
    require(state.formatted and records, "M4 record stream is not formatted")
    return bytes(records), state


def recover_record_stream(record_stream: bytes) -> Any:
    require(
        record_stream
        and len(record_stream) % BLOCK == 0
        and len(record_stream) <= M4_COUNT * BLOCK,
        "persistent authority record stream length is invalid",
    )
    journal = bytearray((M4_FIRST + M4_COUNT) * BLOCK)
    for index in range(0, len(record_stream), BLOCK):
        sector = record_stream[index:index + BLOCK]
        require(
            legacy_codec.decode_sector(sector, M4_FIRST + index // BLOCK)
            is not None,
            "persistent authority record stream contains a non-canonical record",
        )
        at = M4_FIRST * BLOCK + index
        journal[at:at + BLOCK] = sector
    state = legacy_codec.recover(bytes(journal))
    require(state.formatted, "persistent authority record stream is not formatted")
    return state


def classify_post_activation_stream(
    m4_stream: bytes, current_stream: bytes
) -> tuple[str, int]:
    # A maintenance-only authority publication (for example GC relocation)
    # may advance the authority checkpoint without appending a logical record.
    # Both paths still bind the complete frozen M4 byte stream: shortening or
    # forking that prefix is never a valid post-activation publication.
    require(
        len(current_stream) >= len(m4_stream)
        and current_stream.startswith(m4_stream),
        "post-activation authority stream is not a canonical M4 continuation",
    )
    extension_records = (len(current_stream) - len(m4_stream)) // BLOCK
    if extension_records == 0:
        return "canonical_maintenance_relocation", 0
    return "strict_m4_extension", extension_records


def validate_production_authority(state: Any) -> None:
    persistent_grants = [
        grant for grant in state.grants if grant.space == PERSISTENT_SPACE
    ]
    persistent_live = [
        grant for grant in state.live.values() if grant.space == PERSISTENT_SPACE
    ]
    persistent_slots = {
        slot: value
        for (space, slot), value in state.slots.items()
        if space == PERSISTENT_SPACE
    }
    grants_by_derivation = {grant.derivation: grant for grant in state.grants}
    persistent_tombstones = {
        derivation
        for derivation in state.tombstones
        if grants_by_derivation[derivation].space == PERSISTENT_SPACE
    }
    if not persistent_slots:
        require(
            not persistent_grants
            and not persistent_live
            and not persistent_tombstones,
            "persistent CSpace has history without a slot",
        )
    else:
        by_slot_generation = {
            (grant.slot, grant.generation): grant for grant in persistent_grants
        }
        require(
            len(by_slot_generation) == len(persistent_grants),
            "persistent CSpace repeats one slot generation",
        )
        root = by_slot_generation.get((0, 0))
        require(root is not None, "persistent CSpace fixed root is absent")
        require(
            root.parent == 0
            and root.rights == PERSISTENT_ROOT_RIGHTS
            and root.resource_kind == STORED_OBJECT_RESOURCE_KIND
            and root.flags == 1,
            "persistent CSpace root shape is not exact",
        )
        root_object = state.objects.get(root.object_id)
        require(
            root_object is not None
            and root_object[0] == PERSISTENT_OBJECT_KIND
            and root_object[2] < root.commit_sequence,
            "persistent CSpace root object binding is not exact",
        )
        child = by_slot_generation.get((1, 0))
        grandchild = by_slot_generation.get((2, 0))
        replacement = by_slot_generation.get((1, 1))
        expected_keys = [(0, 0)]
        if child is not None:
            expected_keys.append((1, 0))
            require(
                child.parent == root.derivation
                and child.object_id == root.object_id
                and child.rights == legacy_codec.CHILD_RIGHTS
                and child.resource_kind == STORED_OBJECT_RESOURCE_KIND
                and child.flags == 0,
                "persistent CSpace child shape is not exact",
            )
        if grandchild is not None:
            expected_keys.append((2, 0))
            require(
                child is not None
                and grandchild.parent == child.derivation
                and grandchild.object_id == root.object_id
                and grandchild.rights == legacy_codec.GRANDCHILD_RIGHTS
                and grandchild.resource_kind == STORED_OBJECT_RESOURCE_KIND
                and grandchild.flags == 0,
                "persistent CSpace descendant shape is not exact",
            )
        if replacement is not None:
            expected_keys.append((1, 1))
            require(
                child is not None
                and grandchild is not None
                and replacement.parent == root.derivation
                and replacement.object_id == root.object_id
                and replacement.rights == legacy_codec.CHILD_RIGHTS
                and replacement.resource_kind == STORED_OBJECT_RESOURCE_KIND
                and replacement.flags == 0,
                "persistent CSpace replacement shape is not exact",
            )
        require(
            set(by_slot_generation) == set(expected_keys),
            "persistent CSpace history exceeds the fixed graph",
        )
        live_derivations = {grant.derivation for grant in persistent_live}
        if replacement is not None:
            allowed = (
                ({root.derivation, replacement.derivation}, {child.derivation}),
                (set(), {root.derivation, child.derivation}),
            )
            expected_slots = {
                0: (0, root.derivation if live_derivations else None),
                1: (1, replacement.derivation if live_derivations else None),
                2: (0, None),
            }
        elif grandchild is not None:
            allowed = (
                ({root.derivation, child.derivation, grandchild.derivation}, set()),
                ({root.derivation}, {child.derivation}),
                (set(), {root.derivation}),
            )
            expected_slots = {
                0: (0, root.derivation if root.derivation in live_derivations else None),
                1: (0, child.derivation if child.derivation in live_derivations else None),
                2: (
                    0,
                    grandchild.derivation
                    if grandchild.derivation in live_derivations
                    else None,
                ),
            }
        elif child is not None:
            allowed = (
                ({root.derivation, child.derivation}, set()),
                (set(), {root.derivation}),
            )
            expected_slots = {
                0: (0, root.derivation if live_derivations else None),
                1: (0, child.derivation if live_derivations else None),
            }
        else:
            allowed = (({root.derivation}, set()), (set(), {root.derivation}))
            expected_slots = {
                0: (0, root.derivation if live_derivations else None),
            }
        require(
            any(
                live_derivations == expected_live
                and persistent_tombstones == expected_tombstones
                for expected_live, expected_tombstones in allowed
            )
            and persistent_slots == expected_slots,
            "persistent CSpace live/tombstone/slot shape is not an allowed fixed prefix",
        )

    has_program = any(
        grant.space == PROGRAM_SPACE for grant in state.grants
    ) or any(space == PROGRAM_SPACE for space, _slot in state.slots)
    if has_program:
        try:
            program_codec.verify_acceptance(state)
        except Exception as error:
            raise Violation(f"saved-program production policy failed: {error}") from error


def exact_policy_objects(state: Any) -> dict[int, tuple[int, bytes, int]]:
    roots = []
    grants_by_derivation = {grant.derivation: grant for grant in state.grants}
    require(
        len(grants_by_derivation) == len(state.grants),
        "authority history repeats a derivation",
    )
    require(
        all(grant.space in (PERSISTENT_SPACE, PROGRAM_SPACE) for grant in state.grants),
        "authority history escapes the external policy spaces",
    )
    require(
        all(derivation in grants_by_derivation for derivation in state.tombstones),
        "authority history contains an unattributed tombstone",
    )
    validate_production_authority(state)
    for grant in state.live.values():
        require(
            grant.space in (PERSISTENT_SPACE, PROGRAM_SPACE),
            "live authority escapes the external policy spaces",
        )
        if grant.flags != 1:
            continue
        object_entry = state.objects.get(grant.object_id)
        require(object_entry is not None, "live root has no committed object")
        object_kind, _content, commit_sequence = object_entry
        shape = (
            grant.parent,
            grant.slot,
            grant.generation,
            grant.rights,
            grant.resource_kind,
            object_kind,
        )
        allowed = {
            PERSISTENT_SPACE: (
                0,
                0,
                0,
                PERSISTENT_ROOT_RIGHTS,
                STORED_OBJECT_RESOURCE_KIND,
                PERSISTENT_OBJECT_KIND,
            ),
            PROGRAM_SPACE: (
                0,
                0,
                0,
                PROGRAM_ROOT_RIGHTS,
                STORED_OBJECT_RESOURCE_KIND,
                PROGRAM_OBJECT_KIND,
            ),
        }
        require(shape == allowed[grant.space], "live root is outside the exact external policy")
        require(commit_sequence < grant.commit_sequence, "root predates no committed object")
        roots.append(grant)
    require(
        len({root.space for root in roots}) == len(roots),
        "external root policy is ambiguous",
    )
    for space in (PERSISTENT_SPACE, PROGRAM_SPACE):
        has_live_slot = any(
            slot_space == space and derivation is not None
            for (slot_space, _slot), (_generation, derivation) in state.slots.items()
        )
        require(
            has_live_slot == any(root.space == space for root in roots),
            "external root policy does not cover one live policy space",
        )
    require(
        all(space in (PERSISTENT_SPACE, PROGRAM_SPACE) for space, _slot in state.slots),
        "slot history escapes the external policy spaces",
    )

    selected_ids = {grant.object_id for grant in state.live.values()}
    ssh = [
        (object_id, value)
        for object_id, value in state.objects.items()
        if value[0] == SSH_OBJECT_KIND
    ]
    if ssh:
        selected_ids.add(max(ssh, key=lambda item: item[1][2])[0])
    require(
        selected_ids.issubset(state.objects),
        "external policy selected an object absent from the journal",
    )
    return {object_id: state.objects[object_id] for object_id in sorted(selected_ids)}


def parse_authority_snapshot(payload: bytes, checkpoint_generation: int) -> dict[str, Any]:
    require(
        AUTHORITY_HEADER_LEN <= len(payload) <= MAX_AUTHORITY_BYTES,
        "persistent authority payload length is invalid",
    )
    require(payload[:8] == AUTHORITY_MAGIC, "persistent authority magic is invalid")
    require(
        u16(payload, 0x08) == AUTHORITY_VERSION
        and u16(payload, 0x0A) == AUTHORITY_HEADER_LEN,
        "persistent authority version/header is invalid",
    )
    require(not any(payload[0x0C:0x10]) and not any(payload[0x70:0x80]), "persistent authority reserved header is non-zero")
    generation = u64(payload, 0x10)
    policy_sha256 = bytes(payload[0x18:0x38])
    object_count = u32(payload, 0x38)
    principal_count = u32(payload, 0x3C)
    record_count = u32(payload, 0x40)
    require(
        generation == checkpoint_generation
        and policy_sha256 == hashlib.sha256(EXTERNAL_POLICY).digest(),
        "persistent authority generation or external policy commitment differs",
    )
    require(
        principal_count <= MAX_PRINCIPALS
        and u32(payload, 0x44) == AUTHORITY_OBJECT_LEN
        and u32(payload, 0x48) == AUTHORITY_PRINCIPAL_LEN
        and u32(payload, 0x4C) == BLOCK,
        "persistent authority table geometry is invalid",
    )
    object_offset = u64(payload, 0x50)
    principal_offset = u64(payload, 0x58)
    record_offset = u64(payload, 0x60)
    encoded_len = u64(payload, 0x68)
    require(object_offset == AUTHORITY_HEADER_LEN, "persistent authority object offset is invalid")
    require(
        principal_offset == object_offset + object_count * AUTHORITY_OBJECT_LEN
        and record_offset == principal_offset + principal_count * AUTHORITY_PRINCIPAL_LEN
        and encoded_len == record_offset + record_count * BLOCK
        and encoded_len == len(payload),
        "persistent authority tables are non-canonical",
    )

    objects = []
    previous_stable = 0
    v2_object_ids: set[int] = set()
    for index in range(object_count):
        at = object_offset + index * AUTHORITY_OBJECT_LEN
        binding = {
            "stable_object_id": u128(payload, at),
            "v2_object_id": u128(payload, at + 0x10),
            "commit_generation": u64(payload, at + 0x20),
            "object_kind": u32(payload, at + 0x28),
        }
        require(u32(payload, at + 0x2C) == 0, "persistent authority object reserved word is non-zero")
        require(
            binding["stable_object_id"] > previous_stable
            and binding["v2_object_id"] != 0
            and binding["v2_object_id"] not in v2_object_ids
            and 0 < binding["commit_generation"] <= generation
            and binding["object_kind"] != 0,
            "persistent authority object bindings are invalid, unsorted, or duplicate",
        )
        previous_stable = binding["stable_object_id"]
        v2_object_ids.add(binding["v2_object_id"])
        objects.append(binding)

    principals = []
    previous_principal = bytes(16)
    for index in range(principal_count):
        at = principal_offset + index * AUTHORITY_PRINCIPAL_LEN
        principal = bytes(payload[at:at + 0x10])
        logical_limit = u64(payload, at + 0x10)
        physical_limit = u64(payload, at + 0x18)
        committed_logical = u64(payload, at + 0x20)
        committed_physical = u64(payload, at + 0x28)
        require(
            principal > previous_principal
            and logical_limit > 0
            and physical_limit > 0
            and committed_logical <= logical_limit
            and committed_physical <= physical_limit
            and payload[at + 0x30] in (0, 1)
            and not any(payload[at + 0x31:at + 0x40]),
            "persistent principal table is invalid or unsorted",
        )
        previous_principal = principal
        principals.append(
            {
                "principal": principal,
                "logical_limit": logical_limit,
                "physical_limit": physical_limit,
                "committed_logical": committed_logical,
                "committed_physical": committed_physical,
                "admission_revoked": payload[at + 0x30] != 0,
            }
        )

    record_stream = bytes(payload[record_offset:])
    require(record_stream, "persistent authority record stream is empty")
    return {
        "objects": objects,
        "principals": principals,
        "record_stream": record_stream,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def canonical_object_physical_bytes(exact_len: int) -> int:
    geometry = gc_verifier.canonical_blob_geometry(exact_len)
    record_overhead = 2 * PAGE

    def record(payload_len: int) -> int:
        return ((payload_len + PAGE - 1) // PAGE) * PAGE + record_overhead

    total = record(0x80)
    remaining = exact_len
    while remaining:
        length = min(remaining, gc_verifier.CANONICAL_CONTENT_EXTENT_LEN)
        total += record(length)
        remaining -= length
    total += record(geometry["tree_len"])
    content_count = (exact_len + gc_verifier.CANONICAL_CONTENT_EXTENT_LEN - 1) // gc_verifier.CANONICAL_CONTENT_EXTENT_LEN
    extent_count = content_count + 2
    manifest_len = gc_verifier.BLOB_MANIFEST_HEADER_LEN + extent_count * gc_verifier.MANIFEST_EXTENT_LEN
    total += record(manifest_len)
    return total + gc_verifier.OBJECT_MAPPING_LEN + gc_verifier.BLOB_MAPPING_LEN


def parse_cas_delta_v2(payload: bytes, context: dict[str, Any]) -> dict[str, Any]:
    require(
        len(payload) in (CAS_DELTA_REUSE_LEN, CAS_DELTA_NEW_BLOB_LEN),
        "CAS delta length is invalid",
    )
    require(payload[:8] == gc_verifier.CAS_MAGIC, "CAS delta magic is invalid")
    codec_version = u16(payload, 0x08)
    require(
        codec_version
        in (gc_verifier.CAS_CODEC_VERSION, gc_verifier.CAS_GC_CODEC_VERSION),
        "CAS delta codec version is invalid",
    )
    require(
        u16(payload, 0x0A) == CAS_KIND_DELTA
        and u32(payload, 0x0C) == CAS_DELTA_HEADER_LEN,
        "CAS delta kind/header is invalid",
    )
    generation = u64(payload, 0x10)
    chain_count = u32(payload, 0x18)
    flags = u32(payload, 0x1C)
    require(generation > 0 and chain_count > 0, "CAS delta generation/depth is zero")
    require(
        u32(payload, 0x20) == gc_verifier.OBJECT_MAPPING_LEN
        and u32(payload, 0x24) == gc_verifier.BLOB_MAPPING_LEN
        and not any(payload[0x28:0x30])
        and not any(payload[0x98:0xA0])
        and u64(payload, 0x90) == len(payload),
        "CAS delta geometry or reserved bytes are invalid",
    )
    has_blob = flags == DELTA_FLAG_NEW_BLOB and len(payload) == CAS_DELTA_NEW_BLOB_LEN
    require(
        has_blob or (flags == 0 and len(payload) == CAS_DELTA_REUSE_LEN),
        "CAS delta flags and length disagree",
    )
    if chain_count == 1:
        require(not any(payload[0x30:0x90]), "first CAS delta has a predecessor")
        previous = {"status": "null"}
    else:
        previous = gc_verifier.parse_context_pointer(
            payload[0x30:0x90],
            context,
            EXTENT_CATALOG_DELTA,
            "CAS delta predecessor",
        )
        require(
            previous["exact_byte_len"]
            in (CAS_DELTA_REUSE_LEN, CAS_DELTA_NEW_BLOB_LEN),
            "CAS delta predecessor length is invalid",
        )
    obj = gc_verifier.parse_object_mapping_v2(
        payload[CAS_DELTA_HEADER_LEN:CAS_DELTA_REUSE_LEN],
        generation,
        codec_version,
    )
    require(obj["commit_generation"] == generation, "CAS delta object generation differs")
    new_blob = None
    if has_blob:
        new_blob = gc_verifier.parse_blob_mapping_v2(
            payload[CAS_DELTA_REUSE_LEN:CAS_DELTA_NEW_BLOB_LEN],
            context,
            "CAS delta new Blob",
        )
        require(
            gc_verifier.blob_key_identity(new_blob["blob_key"])
            == gc_verifier.blob_key_identity(obj["blob_key"]),
            "CAS delta object and Blob keys differ",
        )
        if previous["status"] == "value":
            require(
                not storage_codec.ranges_overlap(previous, new_blob["manifest"]),
                "CAS delta predecessor and manifest overlap",
            )
    return {
        "checkpoint_generation": generation,
        "chain_count": chain_count,
        "previous": previous,
        "object": obj,
        "new_blob": new_blob,
    }


def add_physical_pointer(
    pointers: list[dict[str, Any]], pointer: dict[str, Any], label: str
) -> None:
    require(pointer["status"] == "value", f"{label} is Null")
    require(
        all(not storage_codec.ranges_overlap(previous, pointer) for previous in pointers),
        f"{label} overlaps another current physical pointer",
    )
    pointers.append(pointer)


def require_dense_snapshot_binding(
    snapshot_generation: int,
    extent_target_generation: int,
    checkpoint_generation: int,
) -> None:
    # Authority-only checkpoints intentionally retain the previous immutable
    # CAS snapshot.  The snapshot may therefore predate the selected
    # checkpoint, but its payload generation must still bind exactly to the
    # catalog extent that carries it and it may never point into the future.
    require(
        snapshot_generation <= checkpoint_generation
        and snapshot_generation == extent_target_generation,
        "dense CAS snapshot does not bind its catalog extent/checkpoint",
    )


def validate_authoritative_segments(
    region: memoryview,
    checkpoint: dict[str, Any],
    structural: dict[str, Any],
    allocation: dict[str, Any],
) -> None:
    record = checkpoint["record"]
    segments = structural["segments"]
    segment_errors = structural["segment_errors"]
    require(
        len(segments) == len(segment_errors)
        and allocation["admitted_segments"] <= len(segments),
        "allocation exceeds the physical V2 slice",
    )
    for segment_no, state in enumerate(allocation["states"]):
        if state == gc_verifier.SEGMENT_FREE:
            continue
        segment = segments[segment_no]
        require(
            segment.get("status") == "sealed" and not segment_errors[segment_no],
            "an authoritative V2 segment is not structurally sealed",
        )
        require(
            segment.get("_generation", (1 << 64) - 1)
            < allocation["next_segment_generation"]
            and segment["header"]["record"]["binding"]["store_uuid"]
            == record["binding"]["store_uuid"]
            and segment["final_seal"]["record"]["target_checkpoint_generation"]
            <= record["binding"]["generation"],
            "an authoritative V2 segment escapes the selected checkpoint",
        )
        for extent in segment["extents"]:
            extent_record = extent["record"]
            used = extent_record["payload_byte_len"] % PAGE
            if used == 0:
                continue
            final_page = (
                storage_codec.segment_base_page(segment_no)
                + extent_record["payload_first_relative_page"]
                + extent_record["payload_pages"]
                - 1
            )
            page = storage_codec.page_at(region, final_page)
            require(
                page is not None and not any(page[used:]),
                "an authoritative V2 extent has non-zero page padding",
            )


def parse_checkpoint_allocation(
    payload: bytes,
    extent: dict[str, Any],
    checkpoint: dict[str, Any],
    pointer: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """Decode the exact allocation ABI used by one retained checkpoint.

    A pre-allocation-v2 checkpoint remains a valid fallback after its G+1
    successor publishes the first v2 bitmap. Mirror production recovery by
    strictly decoding the frozen v1 prefix and converting only that exact
    prefix to Allocated states; never reinterpret a malformed v2 payload as
    legacy data.
    """

    require(len(payload) >= 0x0A, "allocation payload is too short for a version")
    record = checkpoint["record"]
    generation = record["binding"]["generation"]
    version = u16(payload, 0x08)
    if version == 1:
        legacy = storage_codec.parse_allocation_payload(payload, extent)
        admitted = legacy["admitted_segments"]
        allocated_prefix = legacy["allocated_prefix_segments"]
        reserve = legacy["cleaner_reserve_segments"]
        require(
            generation > 0
            and 0 < admitted
            and legacy["next_segment_generation"] > 0
            and 0 < reserve < admitted
            and 0 < allocated_prefix <= admitted
            and allocated_prefix + reserve <= admitted,
            "legacy allocation-v1 fields are invalid",
        )
        require(
            pointer["segment_no"] + 1 == allocated_prefix,
            "legacy allocation-v1 root is not the final allocated prefix segment",
        )
        states = [gc_verifier.SEGMENT_ALLOCATED] * allocated_prefix
        states.extend([gc_verifier.SEGMENT_FREE] * (admitted - allocated_prefix))
        allocation = {
            "checkpoint_generation": legacy["checkpoint_generation"],
            "admitted_segments": admitted,
            "next_segment_generation": legacy["next_segment_generation"],
            "cleaner_reserve_segments": reserve,
            "states": states,
            "retired": [],
            "counts": {
                "free": admitted - allocated_prefix,
                "allocated": allocated_prefix,
                "retired": 0,
            },
        }
    elif version == gc_verifier.ALLOCATION_VERSION:
        allocation = gc_verifier.parse_allocation_v2(payload)
    else:
        raise Violation("allocation payload version is unsupported")
    require(
        allocation["checkpoint_generation"] == generation
        == extent["binding"]["target_checkpoint_generation"]
        and allocation["admitted_segments"] == record["admitted_segments"]
        and allocation["next_segment_generation"] == record["next_segment_generation"]
        and allocation["cleaner_reserve_segments"]
        == record["cleaner_reserve_segments"],
        "allocation does not exactly bind its retained checkpoint",
    )
    root_segment = pointer["segment_no"]
    require(
        0 <= root_segment < allocation["admitted_segments"]
        and allocation["states"][root_segment]
        == gc_verifier.SEGMENT_ALLOCATED,
        "allocation root is not in an Allocated segment",
    )
    return allocation, version


def reconstruct_v2_checkpoint(
    region: memoryview,
    structural: dict[str, Any],
    *,
    require_authority: bool,
) -> dict[str, Any]:
    checkpoint = structural["checkpoint"]
    require(checkpoint is not None, "V2 has no selected checkpoint")
    record = checkpoint["record"]
    generation = record["binding"]["generation"]
    context = {
        "store_uuid": record["binding"]["store_uuid"],
        "admitted_segments": record["admitted_segments"],
        "next_segment_generation": record["next_segment_generation"],
    }
    resolver = gc_verifier.RawImageResolver(
        region, checkpoint, structural["segments"]
    )
    allocation_pointer = record["allocation_root"]
    if allocation_pointer["status"] == "null":
        require(
            generation == 1
            and record["catalog_root"]["status"] == "null"
            and record["authority_root"]["status"] == "null"
            and record["replay_tail"]["status"] == "null"
            and record["replay_count"] == 0,
            "only the empty initial checkpoint may omit allocation-v2",
        )
        allocation = {
            "checkpoint_generation": generation,
            "admitted_segments": record["admitted_segments"],
            "next_segment_generation": record["next_segment_generation"],
            "cleaner_reserve_segments": record["cleaner_reserve_segments"],
            "states": [gc_verifier.SEGMENT_FREE] * record["admitted_segments"],
            "retired": [],
            "counts": {
                "free": record["admitted_segments"],
                "allocated": 0,
                "retired": 0,
            },
        }
        allocation_version = 1
    else:
        require(allocation_pointer["status"] == "value", "V2 allocation root status is invalid")
        allocation_extent, allocation_payload = resolver.resolve(
            allocation_pointer,
            gc_verifier.EXTENT_ALLOCATION,
            "allocation-v2 root",
            metadata=True,
            current=False,
        )
        require(
            hashlib.sha256(allocation_payload).digest()
            == allocation_pointer["payload_sha256"],
            "allocation payload digest mismatch",
        )
        allocation, allocation_version = parse_checkpoint_allocation(
            allocation_payload,
            allocation_extent,
            checkpoint,
            allocation_pointer,
        )
        resolver.allocation = allocation
        require(
            allocation["states"][allocation_pointer["segment_no"]]
            == gc_verifier.SEGMENT_ALLOCATED,
            "allocation-v2 root is not in an Allocated segment",
        )
        resolver.current_identities.add(storage_codec.pointer_identity(allocation_pointer))
    validate_authoritative_segments(region, checkpoint, structural, allocation)

    authority_pointer = record["authority_root"]
    authority = None
    authority_payload = b""
    authority_generation = 0
    authority_state = None
    authority_objects: dict[int, tuple[int, bytes, int]] = {}
    if authority_pointer["status"] == "value":
        authority_extent, authority_payload = resolver.resolve(
            authority_pointer,
            gc_verifier.EXTENT_AUTHORITY,
            "persistent authority root",
            metadata=True,
        )
        require(
            hashlib.sha256(authority_payload).digest()
            == authority_pointer["payload_sha256"],
            "V2 authority payload digest mismatch",
        )
        authority_generation = authority_extent["binding"]["target_checkpoint_generation"]
        require(authority_generation <= generation, "V2 authority targets a future checkpoint")
        authority = parse_authority_snapshot(authority_payload, authority_generation)
        authority_state = recover_record_stream(authority["record_stream"])
        authority_objects = exact_policy_objects(authority_state)
    else:
        require(
            authority_pointer["status"] == "null" and not require_authority,
            "V2 has no persistent authority root",
        )

    physical_pointers: list[dict[str, Any]] = []
    if allocation_pointer["status"] == "value":
        add_physical_pointer(physical_pointers, allocation_pointer, "allocation-v2 root")
    if authority_pointer["status"] == "value":
        add_physical_pointer(physical_pointers, authority_pointer, "persistent authority root")

    objects: dict[int, dict[str, Any]] = {}
    blobs: dict[tuple[int, int, int, bytes], dict[str, Any]] = {}
    snapshot_generation = 0
    catalog_pointer = record["catalog_root"]
    if catalog_pointer["status"] == "value":
        # The CAS delta ABI is frozen for a later milestone, but the current
        # production VIBECAS2 mount path publishes and accepts only one dense
        # snapshot.  A powered-off verifier must never accept a state the
        # kernel itself would reject.
        require(
            record["replay_count"] == 0
            and record["replay_tail"]["status"] == "null",
            "current VIBECAS2 production requires a compact snapshot",
        )
        add_physical_pointer(physical_pointers, catalog_pointer, "CAS snapshot root")
        catalog_extent, catalog_payload = resolver.resolve(
            catalog_pointer,
            gc_verifier.EXTENT_CATALOG,
            "CAS snapshot root",
            metadata=True,
        )
        require(
            hashlib.sha256(catalog_payload).digest()
            == catalog_pointer["payload_sha256"],
            "CAS snapshot payload digest mismatch",
        )
        snapshot = gc_verifier.parse_cas_snapshot_v2(catalog_payload, context)
        snapshot_generation = snapshot["checkpoint_generation"]
        require_dense_snapshot_binding(
            snapshot_generation,
            catalog_extent["binding"]["target_checkpoint_generation"],
            generation,
        )
        objects.update((item["object_id"], item) for item in snapshot["objects"])
        blobs.update(
            (gc_verifier.blob_key_identity(item["blob_key"]), item)
            for item in snapshot["blobs"]
        )
    else:
        require(
            catalog_pointer["status"] == "null"
            and record["replay_count"] == 0
            and record["replay_tail"]["status"] == "null",
            "CAS snapshot/replay state is invalid",
        )

    reverse_deltas = []
    replay_pointer = record["replay_tail"]
    expected_depth = record["replay_count"]
    seen_deltas: set[tuple[int, int, int, int]] = set()
    while expected_depth:
        require(replay_pointer["status"] == "value", "CAS replay chain ended early")
        identity = storage_codec.pointer_identity(replay_pointer)
        require(identity not in seen_deltas, "CAS replay chain contains a cycle")
        seen_deltas.add(identity)
        add_physical_pointer(physical_pointers, replay_pointer, "CAS replay delta")
        extent, payload = resolver.resolve(
            replay_pointer,
            EXTENT_CATALOG_DELTA,
            f"CAS replay delta[{expected_depth}]",
            metadata=True,
        )
        require(
            hashlib.sha256(payload).digest() == replay_pointer["payload_sha256"],
            "CAS replay delta payload digest mismatch",
        )
        delta = parse_cas_delta_v2(payload, context)
        require(
            delta["chain_count"] == expected_depth
            and delta["checkpoint_generation"] <= generation
            and delta["checkpoint_generation"]
            == extent["binding"]["target_checkpoint_generation"],
            "CAS replay delta does not bind its selected checkpoint",
        )
        reverse_deltas.append(delta)
        replay_pointer = delta["previous"]
        expected_depth -= 1
    require(replay_pointer["status"] == "null", "CAS replay chain exceeds replay_count")

    previous_generation = snapshot_generation
    previous_object = max(objects, default=0)
    for delta in reversed(reverse_deltas):
        require(
            delta["checkpoint_generation"] > previous_generation,
            "CAS replay generations are not strictly increasing",
        )
        previous_generation = delta["checkpoint_generation"]
        obj = delta["object"]
        require(
            obj["object_id"] > previous_object and obj["object_id"] not in objects,
            "CAS replay object IDs are not strictly increasing",
        )
        key = gc_verifier.blob_key_identity(obj["blob_key"])
        new_blob = delta["new_blob"]
        if new_blob is None:
            require(key in blobs, "CAS replay reuse references a missing Blob")
        else:
            require(key not in blobs, "CAS replay republishes an existing Blob")
            blobs[key] = new_blob
        objects[obj["object_id"]] = obj
        previous_object = obj["object_id"]

    require(
        {gc_verifier.blob_key_identity(item["blob_key"]) for item in objects.values()}
        == set(blobs),
        "CAS BlobMappings do not exactly equal all ObjectMapping BlobKeys",
    )
    contents: dict[tuple[int, int, int, bytes], bytes] = {}
    for key in sorted(blobs):
        blob = blobs[key]
        manifest_pointer = blob["manifest"]
        add_physical_pointer(physical_pointers, manifest_pointer, "Blob manifest")
        manifest_extent, manifest_payload = resolver.resolve(
            manifest_pointer,
            gc_verifier.EXTENT_CATALOG,
            "Blob manifest",
            metadata=True,
        )
        require(
            hashlib.sha256(manifest_payload).digest()
            == manifest_pointer["payload_sha256"]
            and manifest_extent["binding"]["target_checkpoint_generation"] <= generation,
            "Blob manifest digest or checkpoint target is invalid",
        )
        manifest = gc_verifier.parse_blob_manifest_v2(manifest_payload, context)
        require(
            gc_verifier.blob_key_identity(manifest["blob_key"]) == key,
            "Blob mapping and manifest keys disagree",
        )
        encoded = bytearray()
        for item in manifest["extents"]:
            pointer = item["pointer"]
            add_physical_pointer(physical_pointers, pointer, "canonical Blob extent")
            extent, payload = resolver.resolve(
                pointer, gc_verifier.EXTENT_BLOB, "canonical Blob extent"
            )
            expected_shape = (
                blob["blob_key"]["object_kind"],
                item["extent_index"],
                item["extent_count"],
                blob["blob_key"]["exact_len"],
                manifest["encoded_blob_len"],
                item["encoded_offset"],
                item["payload_byte_len"],
                blob["blob_key"]["merkle_root"],
            )
            actual_shape = (
                extent["object_kind"],
                extent["extent_index"],
                extent["extent_count"],
                extent["content_byte_len"],
                extent["encoded_blob_len"],
                extent["encoded_offset"],
                extent["payload_byte_len"],
                extent["merkle_root"],
            )
            require(actual_shape == expected_shape, "canonical Blob descriptor binding differs")
            require(
                hashlib.sha256(payload).digest() == pointer["payload_sha256"],
                "canonical Blob extent payload digest mismatch",
            )
            encoded.extend(payload)
        require(
            len(encoded) == manifest["encoded_blob_len"],
            "canonical Blob extents do not cover the encoded Blob",
        )
        contents[key] = gc_verifier.verify_canonical_blob(
            bytes(encoded), blob["blob_key"]
        )

    roots = [] if authority is None else [
        {
            "object_id": binding["v2_object_id"],
            "commit_generation": binding["commit_generation"],
            "object_kind": binding["object_kind"],
        }
        for binding in authority["objects"]
    ]
    gc_verifier.validate_raw_object_graph(objects, contents, roots, [])
    return {
        "checkpoint_generation": generation,
        "authority_generation": authority_generation,
        "store_uuid": context["store_uuid"].hex(),
        "authority_sha256": (
            hashlib.sha256(authority_payload).hexdigest()
            if authority is not None
            else None
        ),
        "authority": authority,
        "authority_state": authority_state,
        "authority_objects": authority_objects,
        "objects": objects,
        "contents": contents,
        "allocation": allocation,
        "allocation_version": allocation_version,
    }


def selected_v2_superblock(region: memoryview) -> dict[str, Any]:
    errors: list[str] = []
    candidates = [
        storage_codec.decode_pair(
            region,
            0,
            1,
            1,
            "superblock copy A",
            errors,
            storage_codec.super_validator(0, 0),
        ),
        storage_codec.decode_pair(
            region,
            2,
            3,
            1,
            "superblock copy B",
            errors,
            storage_codec.super_validator(1, 2),
        ),
    ]
    selected = storage_codec.select_superblock(candidates, errors)
    require(
        not errors
        and selected is not None
        and all(candidate["status"] == "sealed" for candidate in candidates),
        "V2 does not retain two identical sealed superblocks",
    )
    return selected["record"]


def v2_checkpoint_slots(region: memoryview) -> list[dict[str, Any]]:
    errors: list[str] = []
    slots = [
        storage_codec.decode_pair(
            region,
            4,
            5,
            2,
            "checkpoint slot A",
            errors,
            storage_codec.checkpoint_validator(0, 4),
        ),
        storage_codec.decode_pair(
            region,
            6,
            7,
            2,
            "checkpoint slot B",
            errors,
            storage_codec.checkpoint_validator(1, 6),
        ),
    ]
    require(not errors, "a V2 checkpoint slot is corrupt")
    return slots


def validate_checkpoint_allocation_transition(
    older: dict[str, Any],
    newer: dict[str, Any],
    older_allocation: dict[str, Any],
    newer_allocation: dict[str, Any],
    older_allocation_version: int,
    newer_allocation_version: int,
) -> None:
    old = older["record"]
    new = newer["record"]
    require(
        new["binding"]["generation"] == old["binding"]["generation"] + 1
        and new["previous_generation"] == old["binding"]["generation"]
        and new["binding"]["store_uuid"] == old["binding"]["store_uuid"]
        and new["admitted_segments"] == old["admitted_segments"]
        and new["cleaner_reserve_segments"] == old["cleaner_reserve_segments"],
        "V2 checkpoint pair is not one fixed-range G+1 transition",
    )
    require(
        older_allocation_version in (1, gc_verifier.ALLOCATION_VERSION)
        and newer_allocation_version == gc_verifier.ALLOCATION_VERSION,
        "newer retained checkpoint did not complete allocation-v2 conversion",
    )
    allocate: list[int] = []
    retire: list[int] = []
    reclaim: list[int] = []
    require(
        len(older_allocation["states"]) == len(newer_allocation["states"]),
        "V2 checkpoint allocation maps have different lengths",
    )
    for segment_no, (before, after) in enumerate(
        zip(older_allocation["states"], newer_allocation["states"])
    ):
        if before == after:
            continue
        if before == gc_verifier.SEGMENT_FREE and after == gc_verifier.SEGMENT_ALLOCATED:
            allocate.append(segment_no)
        elif before == gc_verifier.SEGMENT_ALLOCATED and after == gc_verifier.SEGMENT_RETIRED:
            retire.append(segment_no)
        elif before == gc_verifier.SEGMENT_RETIRED and after == gc_verifier.SEGMENT_FREE:
            reclaim.append(segment_no)
        else:
            raise Violation("V2 checkpoint allocation contains an invalid state transition")
    gc_verifier.validate_allocation_transition(
        older_allocation,
        newer_allocation,
        allocate=allocate,
        retire=retire,
        reclaim=reclaim,
    )
    require(
        newer_allocation["next_segment_generation"]
        == older_allocation["next_segment_generation"] + len(allocate),
        "V2 checkpoint transition consumes the wrong segment generations",
    )
    if older_allocation_version == 1:
        older_root = old["allocation_root"]
        newer_root = new["allocation_root"]
        require(
            newer_root["status"] == "value"
            and newer_root != older_root
            and newer_root["segment_no"] in allocate
            and newer_root["segment_generation"]
            == older_allocation["next_segment_generation"],
            "allocation-v1 G+1 conversion is not carried by its fresh segment",
        )
    old_retired = older_allocation["retired"]
    if retire:
        require(
            not reclaim and not old_retired and allocate,
            "V2 relocation overlaps another retirement barrier",
        )
    elif reclaim:
        require(
            len(reclaim) == len(old_retired)
            and all(
                entry["retire_generation"] == old["binding"]["generation"]
                for entry in old_retired
            )
            and not newer_allocation["retired"]
            and len(allocate) == 1,
            "V2 reuse barrier is not exact",
        )
    else:
        require(not old_retired, "V2 checkpoint advanced a pending reuse barrier")


def verify_v2_checkpoint_fallbacks(
    region: memoryview,
    structural: dict[str, Any],
    superblock: dict[str, Any],
    selected_recovered: dict[str, Any],
) -> int:
    slots = v2_checkpoint_slots(region)
    sealed = sorted(
        (slot for slot in slots if slot["status"] == "sealed"),
        key=lambda item: item["record"]["binding"]["generation"],
    )
    require(sealed, "V2 has no sealed checkpoint")
    recovered_by_generation: dict[int, dict[str, Any]] = {
        selected_recovered["checkpoint_generation"]: selected_recovered
    }
    for checkpoint in sealed:
        errors: list[str] = []
        storage_codec.verify_checkpoint_against_superblock(
            checkpoint,
            {"record": superblock},
            structural["physical_segments"],
            structural["segments"],
            errors,
        )
        require(not errors, "a retained V2 checkpoint is not independently recoverable")
        generation = checkpoint["record"]["binding"]["generation"]
        if generation not in recovered_by_generation:
            candidate_structural = dict(structural)
            candidate_structural["checkpoint"] = checkpoint
            recovered_by_generation[generation] = reconstruct_v2_checkpoint(
                region, candidate_structural, require_authority=False
            )
    if len(sealed) == 2:
        older, newer = sealed
        validate_checkpoint_allocation_transition(
            older,
            newer,
            recovered_by_generation[older["record"]["binding"]["generation"]][
                "allocation"
            ],
            recovered_by_generation[newer["record"]["binding"]["generation"]][
                "allocation"
            ],
            recovered_by_generation[older["record"]["binding"]["generation"]][
                "allocation_version"
            ],
            recovered_by_generation[newer["record"]["binding"]["generation"]][
                "allocation_version"
            ],
        )
    return len(sealed)


def probe_v2(image: bytes | bytearray) -> tuple[str, dict[str, Any] | None]:
    first = V2_FIRST * BLOCK
    end = (V2_FIRST + V2_COUNT) * BLOCK
    region = memoryview(image)[first:end]
    if not any(region):
        return "absent", None
    try:
        structural = gc_verifier.parse_raw_structure(region)
        require(not structural["errors"], "V2 structural verification failed")
        checkpoint = structural["checkpoint"]
        require(checkpoint is not None, "V2 has no selected checkpoint")
        superblock = selected_v2_superblock(region)
        record = checkpoint["record"]
        require(
            len(superblock["device_id"]) == 16
            and superblock["device_id"] != bytes(16),
            "V2 stable device ID is invalid",
        )
        require(
            superblock["range_first_logical_block"] == V2_FIRST
            and superblock["initial_block_count"] == V2_COUNT
            and superblock["logical_block_size"] == BLOCK,
            "V2 superblock differs from the migration range",
        )
        base = {
            "device_id": superblock["device_id"].hex(),
            "store_uuid": record["binding"]["store_uuid"].hex(),
            "selected_checkpoint_generation": record["binding"]["generation"],
        }
        if record["authority_root"]["status"] == "null":
            require(
                record["catalog_root"]["status"] == "null"
                and record["replay_tail"]["status"] == "null"
                and record["replay_count"] == 0,
                "unpublished V2 has catalog or replay authority",
            )
            return "absent", base
        recovered = reconstruct_v2_checkpoint(
            region, structural, require_authority=True
        )
        fallback_copies = verify_v2_checkpoint_fallbacks(
            region, structural, superblock, recovered
        )
        return "valid", {
            **base,
            "authority_generation": recovered["authority_generation"],
            "authority_sha256": recovered["authority_sha256"],
            "recovered": recovered,
            "verified_checkpoint_copies": fallback_copies,
        }
    except Exception:
        return "corrupt", None


def verify_authority_bindings(v2: dict[str, Any]) -> dict[str, Any]:
    recovered = v2["recovered"]
    authority = recovered["authority"]
    expected = recovered["authority_objects"]
    bindings = {item["stable_object_id"]: item for item in authority["objects"]}
    require(
        len(bindings) == len(authority["objects"])
        and set(bindings) == set(expected),
        "persistent authority bindings are not the exact external-policy object set",
    )
    bound_v2_ids = {item["v2_object_id"] for item in authority["objects"]}
    require(
        len(bound_v2_ids) == len(authority["objects"]),
        "persistent authority binds one V2 ObjectId more than once",
    )
    logical = 0
    physical = 0
    for stable_id, (m4_kind, m4_bytes, _m4_commit_sequence) in expected.items():
        binding = bindings[stable_id]
        mapping = recovered["objects"].get(binding["v2_object_id"])
        require(mapping is not None, "persistent authority binding has no CAS ObjectMapping")
        require(
            mapping["commit_generation"] == binding["commit_generation"]
            and mapping["object_kind"] == binding["object_kind"] == m4_kind
            and mapping["reference_codec"] == gc_verifier.REFERENCE_CODEC_RAW,
            "persistent authority kind/commit/reference binding differs from CAS",
        )
        content = recovered["contents"].get(
            gc_verifier.blob_key_identity(mapping["blob_key"])
        )
        require(
            content == m4_bytes
            and mapping["exact_len"] == len(m4_bytes),
            "persistent authority object bytes differ from its canonical journal object",
        )
        logical += len(m4_bytes)
        physical += canonical_object_physical_bytes(len(m4_bytes))
    require(
        len(authority["principals"]) == 1
        and authority["principals"][0]["principal"] == SYSTEM_PRINCIPAL
        and authority["principals"][0]["logical_limit"] == (1 << 64) - 1
        and authority["principals"][0]["physical_limit"] == (1 << 64) - 1
        and not authority["principals"][0]["admission_revoked"],
        "migration did not preserve the exact fixed SYSTEM principal policy",
    )
    require(
        sum(item["committed_logical"] for item in authority["principals"])
        == logical
        and sum(item["committed_physical"] for item in authority["principals"])
        == physical,
        "persistent principal totals differ from the exact bound object set",
    )
    return {
        "verified": True,
        "authority_objects": len(bindings),
        "cas_objects": len(recovered["objects"]),
        "unique_blobs": len(recovered["contents"]),
        "logical_bytes": logical,
        "attributable_physical_bytes": physical,
    }


def canonical_empty_record_stream() -> bytes:
    return legacy_codec.encode_record(legacy_codec.FORMAT, b"", 1, 0, 0)


def canonical_empty_authority_payload(checkpoint_generation: int) -> bytes:
    record_stream = canonical_empty_record_stream()
    payload = bytearray(AUTHORITY_HEADER_LEN + AUTHORITY_PRINCIPAL_LEN + len(record_stream))
    payload[:8] = AUTHORITY_MAGIC
    put_u16(payload, 0x08, AUTHORITY_VERSION)
    put_u16(payload, 0x0A, AUTHORITY_HEADER_LEN)
    put_u64(payload, 0x10, checkpoint_generation)
    payload[0x18:0x38] = hashlib.sha256(EXTERNAL_POLICY).digest()
    struct.pack_into("<III", payload, 0x38, 0, 1, 1)
    struct.pack_into(
        "<III", payload, 0x44, AUTHORITY_OBJECT_LEN, AUTHORITY_PRINCIPAL_LEN, BLOCK
    )
    principal_at = AUTHORITY_HEADER_LEN
    record_at = principal_at + AUTHORITY_PRINCIPAL_LEN
    put_u64(payload, 0x50, AUTHORITY_HEADER_LEN)
    put_u64(payload, 0x58, principal_at)
    put_u64(payload, 0x60, record_at)
    put_u64(payload, 0x68, len(payload))
    payload[principal_at:principal_at + 16] = SYSTEM_PRINCIPAL
    put_u64(payload, principal_at + 0x10, (1 << 64) - 1)
    put_u64(payload, principal_at + 0x18, (1 << 64) - 1)
    payload[record_at:] = record_stream
    # Exercise the independent decoder too; hash construction alone must not
    # accidentally bless a malformed expected fixture.
    parsed = parse_authority_snapshot(bytes(payload), checkpoint_generation)
    require(not parsed["objects"], "canonical native authority selected an object")
    return bytes(payload)


def verify_image(
    image: bytes | bytearray,
    unmanaged_prefix_baseline: bytes,
    frozen_m4_baseline: bytes | None = None,
    expect_native: bool = False,
) -> dict[str, Any]:
    require(len(image) % BLOCK == 0, "image is not logical-block aligned")
    require(
        len(unmanaged_prefix_baseline) == M4_FIRST * BLOCK,
        "unmanaged-prefix baseline has the wrong length",
    )
    require(
        bytes(image[:M4_FIRST * BLOCK]) == unmanaged_prefix_baseline,
        "unmanaged prefix before the M4 range differs from its pre-migration baseline",
    )
    require(M4_FIRST + M4_COUNT <= CONTROL_FIRST, "M4 overlaps control")
    require(CONTROL_FIRST + CONTROL_COUNT <= V2_FIRST, "control overlaps V2")
    require(len(image) >= (V2_FIRST + V2_COUNT) * BLOCK, "image is shorter than the V2 range")
    require(
        not any(image[(CONTROL_FIRST + CONTROL_COUNT) * BLOCK:V2_FIRST * BLOCK]),
        "reserved range between migration control and V2 is non-zero",
    )
    require(
        not any(image[(V2_FIRST + V2_COUNT) * BLOCK:]),
        "unmanaged suffix after the fixed V2 range is non-zero",
    )
    slots = [
        parse_control(
            page_at(image, CONTROL_FIRST, 0),
            page_at(image, CONTROL_FIRST, 1),
        ),
        parse_control(
            page_at(image, CONTROL_FIRST, 2),
            page_at(image, CONTROL_FIRST, 3),
        ),
    ]
    selected = select_control(slots)
    m4 = probe_m4(image)
    v2, v2_evidence = probe_v2(image)
    native = (
        selected is not None
        and selected["state"] == "rollback_closed"
        and selected["generation"] == 1
        and m4 == "absent"
    )
    if expect_native:
        require(native, "image is not a generation-1 native rollback-closed store")
        require(frozen_m4_baseline is None, "native V2 verification must not use an M4 baseline")
    if (
        selected is not None
        and selected["state"] in ("v2_active", "rollback_closed")
        and not native
    ):
        require(
            frozen_m4_baseline is not None,
            "active migration verification requires the powered-off V2Staged M4 baseline",
        )
    if frozen_m4_baseline is not None:
        require(
            len(frozen_m4_baseline) == M4_COUNT * BLOCK,
            "frozen-M4 baseline has the wrong length",
        )
        require(
            bytes(image[M4_FIRST * BLOCK:(M4_FIRST + M4_COUNT) * BLOCK])
            == frozen_m4_baseline,
            "M4 rollback range differs from its powered-off V2Staged baseline",
        )
    formats = {"m4": m4, "v2": v2}
    require(m4 != "corrupt" and v2 != "corrupt", "a storage format is corrupt")
    equivalence: dict[str, Any] | None = None
    if selected is not None:
        if v2 == "valid" and v2_evidence is not None:
            require(
                selected["device_id"] == v2_evidence["device_id"],
                "selector device_id differs from independently decoded V2",
            )
        if native:
            require(v2 == "valid" and v2_evidence is not None, "native selector has no valid V2 checkpoint")
            require(
                not any(
                    image[
                        M4_FIRST * BLOCK:(M4_FIRST + M4_COUNT) * BLOCK
                    ]
                ),
                "native V2 initialization wrote into the legacy M4 range",
            )
            require(
                bytes.fromhex(selected["store_uuid"]) == NATIVE_STORE_UUID
                and selected["store_uuid"] == v2_evidence["store_uuid"],
                "native selector does not bind the fixed Storage V2 UUID",
            )
            floor = selected["activation_checkpoint_generation"]
            current = v2_evidence["authority_generation"]
            require(floor == 2, "native V2 initialization floor is not generation 2")
            require(current >= floor, "native V2 checkpoint predates its initialization floor")
            expected_floor = canonical_empty_authority_payload(floor)
            require(
                selected["activation_authority_sha256"]
                == hashlib.sha256(expected_floor).hexdigest(),
                "native selector floor is not the exact canonical empty authority",
            )
            if current == floor:
                require(
                    selected["activation_authority_sha256"] == v2_evidence["authority_sha256"],
                    "native selector floor differs from the selected authority",
                )
            equivalence = verify_authority_bindings(v2_evidence)
            empty_stream = canonical_empty_record_stream()
            empty_state = recover_record_stream(empty_stream)
            current_stream = v2_evidence["recovered"]["authority"]["record_stream"]
            current_state = v2_evidence["recovered"]["authority_state"]
            source, extension_records = classify_post_activation_stream(
                empty_stream, current_stream
            )
            require(
                not exact_policy_objects(empty_state),
                "canonical native authority unexpectedly confers object authority",
            )
            require(
                all(
                    current_state.objects.get(object_id) == value
                    for object_id, value in empty_state.objects.items()
                ),
                "native continuation changed the canonical empty prefix",
            )
            equivalence["source"] = (
                "native_empty_exact"
                if current == floor
                else f"native_empty_{source}"
            )
            equivalence["extension_records"] = extension_records
        else:
            require(m4 == "valid", "published migration control has no valid frozen M4 journal")
        if selected["state"] != "frozen_m4" and not native:
            require(v2 == "valid" and v2_evidence is not None, "published selector has no valid V2 checkpoint")
            require(
                selected["store_uuid"] == v2_evidence["store_uuid"],
                "selector store_uuid differs from independently decoded V2",
            )
            floor = selected["activation_checkpoint_generation"]
            current = v2_evidence["authority_generation"]
            require(current >= floor, "selected V2 checkpoint predates the activation floor")
            if selected["state"] == "v2_staged":
                require(
                    current == floor
                    == v2_evidence["selected_checkpoint_generation"],
                    "staged selector does not bind the exact current checkpoint",
                )
            if current == floor:
                require(
                    selected["activation_authority_sha256"]
                    == v2_evidence["authority_sha256"],
                    "activation-floor authority commitment differs from current V2",
                )
            equivalence = verify_authority_bindings(v2_evidence)
            m4_stream, m4_state = canonical_m4_stream(image)
            current_stream = v2_evidence["recovered"]["authority"]["record_stream"]
            current_state = v2_evidence["recovered"]["authority_state"]
            if selected["state"] == "v2_staged" or current == floor:
                require(
                    current_stream == m4_stream,
                    "activation-floor authority stream differs byte-for-byte from frozen M4",
                )
                require(
                    v2_evidence["recovered"]["authority_objects"]
                    == exact_policy_objects(m4_state),
                    "activation-floor object set differs from frozen M4",
                )
                equivalence["source"] = "frozen_m4_exact"
            else:
                source, extension_records = classify_post_activation_stream(
                    m4_stream, current_stream
                )
                require(
                    all(
                        current_state.objects.get(object_id) == value
                        for object_id, value in m4_state.objects.items()
                    ),
                    "post-activation extension changed a prior immutable object",
                )
                equivalence["source"] = source
                equivalence["extension_records"] = extension_records
    else:
        require(
            not (m4 == "absent" and v2 == "valid"),
            "V2 without an active selector is not boot-authoritative",
        )
    return {
        "schema": "vibeos.storage-v2-migration-verifier",
        "version": 1,
        "status": "ok",
        "mode": "native" if native else "migration",
        "formats": formats,
        "ranges": {
            "unmanaged_prefix": [0, M4_FIRST],
            "unmanaged_prefix_sha256": hashlib.sha256(
                unmanaged_prefix_baseline
            ).hexdigest(),
            "m4": [M4_FIRST, M4_FIRST + M4_COUNT],
            "frozen_m4_sha256": (
                hashlib.sha256(frozen_m4_baseline).hexdigest()
                if frozen_m4_baseline is not None
                else None
            ),
            "control": [CONTROL_FIRST, CONTROL_FIRST + CONTROL_COUNT],
            "v2": [V2_FIRST, V2_FIRST + V2_COUNT],
            "isolated": True,
        },
        "control": {"slots": slots, "selected": selected},
        "equivalence": equivalence,
    }


def encode_control(state: int, generation: int) -> tuple[bytes, bytes]:
    body = bytearray(PAGE)
    body[:8] = BODY_MAGIC
    put_u16(body, 0x08, VERSION)
    put_u16(body, 0x0A, HEADER_LEN)
    body[0x0C] = state
    put_u64(body, 0x10, generation)
    body[0x40:0x50] = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
    put_u64(body, 0x50, M4_FIRST)
    put_u64(body, 0x58, M4_COUNT)
    put_u64(body, 0x60, V2_FIRST)
    put_u64(body, 0x68, V2_COUNT)
    if state != FROZEN:
        body[0x70:0x80] = bytes.fromhex("00112233445566778899aabbccddeeff")
        put_u64(body, 0x80, 7)
        body[0x88:0xA8] = bytes.fromhex("44" * 32)
    body[BODY_DIGEST_AT:BODY_DIGEST_AT + 32] = hashlib.sha256(body[0x40:]).digest()
    seal = bytearray(PAGE)
    seal[:8] = SEAL_MAGIC
    put_u16(seal, 0x08, VERSION)
    put_u64(seal, 0x10, generation)
    seal[SEAL_DIGEST_AT:SEAL_DIGEST_AT + 32] = hashlib.sha256(body).digest()
    seal[TERMINAL_AT:] = TERMINAL
    return bytes(body), bytes(seal)


def write_page(image: bytearray, relative: int, data: bytes) -> None:
    at = offset(CONTROL_FIRST, relative)
    image[at:at + PAGE] = data


def fixture() -> bytearray:
    image = bytearray((V2_FIRST + V2_COUNT) * BLOCK)
    format_record = legacy_codec.encode_record(
        legacy_codec.FORMAT, b"", 1, 0, 0
    )
    image[offset(M4_FIRST):offset(M4_FIRST) + BLOCK] = format_record
    body, seal = encode_control(FROZEN, 1)
    write_page(image, 0, body)
    write_page(image, 1, seal)
    return image


def selftest() -> dict[str, Any]:
    image = fixture()
    unmanaged_prefix_baseline = bytes(image[:M4_FIRST * BLOCK])
    require(
        verify_image(image, unmanaged_prefix_baseline)["control"]["selected"][
            "state"
        ]
        == "frozen_m4",
        "frozen fixture was not selected",
    )
    old = parse_control(page_at(image, CONTROL_FIRST, 0), page_at(image, CONTROL_FIRST, 1))
    body, seal = encode_control(STAGED, 2)
    cases = 1
    for length in range(PAGE + 1):
        candidate = parse_control(body[:length] + bytes(PAGE - length), bytes(PAGE))
        require(select_control([old, candidate])["generation"] == 1, "body prefix selected V2")
        cases += 1
    for length in range(TERMINAL_AT + 1):
        candidate = parse_control(body, seal[:length] + bytes(PAGE - length))
        require(select_control([old, candidate])["generation"] == 1, "seal prefix selected V2")
        cases += 1
    corrupt = bytearray(body)
    corrupt[0x60] ^= 1
    try:
        parse_control(bytes(corrupt), seal)
    except Violation:
        cases += 1
    else:
        raise Violation("sealed body corruption was accepted")
    for target, label in ((body, "body"), (seal, "seal")):
        for index in range(PAGE):
            mutated = bytearray(target)
            mutated[index] ^= 1
            try:
                parse_control(
                    bytes(mutated) if label == "body" else body,
                    bytes(mutated) if label == "seal" else seal,
                )
            except Violation:
                cases += 1
            else:
                raise Violation(f"single-byte control {label} corruption was accepted")
    arbitrary = bytearray((V2_FIRST + V2_COUNT) * BLOCK)
    arbitrary[offset(M4_FIRST):offset(M4_FIRST) + 8] = b"NOTFMT!!"
    require(probe_m4(arbitrary) == "absent", "unsealed M4 append was not ignored")
    arbitrary[offset(M4_FIRST) + BLOCK - len(legacy_codec.SEAL):offset(M4_FIRST) + BLOCK] = legacy_codec.SEAL
    require(probe_m4(arbitrary) == "corrupt", "sealed malformed M4 bytes were accepted")
    cases += 1

    reserved = fixture()
    reserved[(CONTROL_FIRST + CONTROL_COUNT) * BLOCK] = 1
    try:
        verify_image(reserved, unmanaged_prefix_baseline)
    except Violation:
        cases += 1
    else:
        raise Violation("write into the reserved migration gap was accepted")

    suffix = fixture() + bytearray(BLOCK)
    suffix[-1] = 1
    try:
        verify_image(suffix, unmanaged_prefix_baseline)
    except Violation:
        cases += 1
    else:
        raise Violation("write outside the fixed V2 range was accepted")

    prefix = fixture()
    prefix[8 * BLOCK] = 1
    try:
        verify_image(prefix, unmanaged_prefix_baseline)
    except Violation:
        cases += 1
    else:
        raise Violation("write into the unmanaged prefix was accepted")

    frozen_m4_baseline = bytes(
        image[M4_FIRST * BLOCK:(M4_FIRST + M4_COUNT) * BLOCK]
    )
    changed_m4 = fixture()
    changed_m4[(M4_FIRST + 20) * BLOCK] = 1
    try:
        verify_image(changed_m4, unmanaged_prefix_baseline, frozen_m4_baseline)
    except Violation:
        cases += 1
    else:
        raise Violation("write into the frozen M4 rollback range was accepted")

    expected_seal = canonical_seal(body)
    for length in range(1, PAGE):
        candidate = parse_control(
            body, expected_seal[:length] + bytes(PAGE - length)
        )
        require(candidate["status"] == "torn", "canonical seal prefix was rejected")
        cases += 1
        candidate = parse_control(
            body, bytes(length) + expected_seal[length:]
        )
        require(candidate["status"] == "torn", "canonical seal clear prefix was rejected")
        cases += 1

    bad_slot = [
        {"status": "empty"},
        {"status": "sealed", "record": old["record"]},
    ]
    try:
        select_control(bad_slot)
    except Violation:
        cases += 1
    else:
        raise Violation("valid control record in wrong slot was accepted")

    frozen_body, _ = encode_control(FROZEN, 1)
    partial = bytearray(frozen_body)
    partial[0x70] = 1
    partial[BODY_DIGEST_AT:BODY_DIGEST_AT + 32] = hashlib.sha256(
        partial[0x40:]
    ).digest()
    partial_seal = canonical_seal(bytes(partial))
    try:
        parse_control(bytes(partial), partial_seal)
    except Violation:
        cases += 1
    else:
        raise Violation("partial FrozenM4 publication fields were accepted")

    format_record = bytes(image[offset(M4_FIRST):offset(M4_FIRST) + BLOCK])
    authority_payload = bytearray(AUTHORITY_HEADER_LEN + AUTHORITY_PRINCIPAL_LEN + BLOCK)
    authority_payload[:8] = AUTHORITY_MAGIC
    put_u16(authority_payload, 0x08, AUTHORITY_VERSION)
    put_u16(authority_payload, 0x0A, AUTHORITY_HEADER_LEN)
    put_u64(authority_payload, 0x10, 7)
    authority_payload[0x18:0x38] = hashlib.sha256(EXTERNAL_POLICY).digest()
    struct.pack_into("<III", authority_payload, 0x38, 0, 1, 1)
    struct.pack_into(
        "<III", authority_payload, 0x44, AUTHORITY_OBJECT_LEN, AUTHORITY_PRINCIPAL_LEN, BLOCK
    )
    put_u64(authority_payload, 0x50, AUTHORITY_HEADER_LEN)
    put_u64(authority_payload, 0x58, AUTHORITY_HEADER_LEN)
    put_u64(authority_payload, 0x60, AUTHORITY_HEADER_LEN + AUTHORITY_PRINCIPAL_LEN)
    put_u64(authority_payload, 0x68, len(authority_payload))
    principal_at = AUTHORITY_HEADER_LEN
    authority_payload[principal_at:principal_at + 16] = b"VIBE-M4-SYSTEM!!"
    put_u64(authority_payload, principal_at + 0x10, (1 << 64) - 1)
    put_u64(authority_payload, principal_at + 0x18, (1 << 64) - 1)
    authority_payload[-BLOCK:] = format_record
    parsed_authority = parse_authority_snapshot(bytes(authority_payload), 7)
    require(
        not exact_policy_objects(recover_record_stream(parsed_authority["record_stream"])),
        "empty authority fixture unexpectedly selected an object",
    )
    cases += 1

    native_authority = canonical_empty_authority_payload(2)
    parsed_native = parse_authority_snapshot(native_authority, 2)
    require(
        not parsed_native["objects"]
        and len(parsed_native["principals"]) == 1
        and parsed_native["record_stream"] == canonical_empty_record_stream(),
        "canonical native authority fixture is not exact",
    )
    cases += 1

    # Bindings are canonical by stable ObjectId. A delayed grant may allocate
    # its fresh, independently revocable V2 ObjectId after a later stable
    # object, so V2 IDs need global uniqueness but not the same sort order.
    two_binding_payload = bytearray(
        AUTHORITY_HEADER_LEN + 2 * AUTHORITY_OBJECT_LEN + AUTHORITY_PRINCIPAL_LEN + BLOCK
    )
    two_binding_payload[:AUTHORITY_HEADER_LEN] = authority_payload[:AUTHORITY_HEADER_LEN]
    struct.pack_into("<III", two_binding_payload, 0x38, 2, 1, 1)
    put_u64(two_binding_payload, 0x58, AUTHORITY_HEADER_LEN + 2 * AUTHORITY_OBJECT_LEN)
    put_u64(
        two_binding_payload,
        0x60,
        AUTHORITY_HEADER_LEN + 2 * AUTHORITY_OBJECT_LEN + AUTHORITY_PRINCIPAL_LEN,
    )
    put_u64(two_binding_payload, 0x68, len(two_binding_payload))
    for index, (stable_id, v2_id) in enumerate(((2, 11), (3, 7))):
        at = AUTHORITY_HEADER_LEN + index * AUTHORITY_OBJECT_LEN
        struct.pack_into("<QQ", two_binding_payload, at, stable_id, 0)
        struct.pack_into("<QQ", two_binding_payload, at + 0x10, v2_id, 0)
        put_u64(two_binding_payload, at + 0x20, 7)
        struct.pack_into("<I", two_binding_payload, at + 0x28, PERSISTENT_OBJECT_KIND)
    principal_at = AUTHORITY_HEADER_LEN + 2 * AUTHORITY_OBJECT_LEN
    two_binding_payload[
        principal_at:principal_at + AUTHORITY_PRINCIPAL_LEN
    ] = authority_payload[
        AUTHORITY_HEADER_LEN:AUTHORITY_HEADER_LEN + AUTHORITY_PRINCIPAL_LEN
    ]
    two_binding_payload[-BLOCK:] = format_record
    parsed = parse_authority_snapshot(bytes(two_binding_payload), 7)
    require(
        [binding["v2_object_id"] for binding in parsed["objects"]] == [11, 7],
        "delayed-grant V2 binding order was not preserved",
    )
    cases += 1
    duplicate_v2 = bytearray(two_binding_payload)
    struct.pack_into(
        "<QQ",
        duplicate_v2,
        AUTHORITY_HEADER_LEN + AUTHORITY_OBJECT_LEN + 0x10,
        11,
        0,
    )
    try:
        parse_authority_snapshot(bytes(duplicate_v2), 7)
    except Violation:
        cases += 1
    else:
        raise Violation("duplicate V2 authority binding was accepted")

    # A newer authority generation may be a physical maintenance relocation
    # with no logical journal extension.  The complete frozen M4 prefix still
    # cannot be shortened or forked.
    source, extension_records = classify_post_activation_stream(
        format_record, format_record
    )
    require(
        source == "canonical_maintenance_relocation" and extension_records == 0,
        "unchanged maintenance relocation was not classified canonically",
    )
    cases += 1
    for invalid_stream in (
        b"",
        bytes([format_record[0] ^ 1]) + format_record[1:],
    ):
        try:
            classify_post_activation_stream(format_record, invalid_stream)
        except Violation:
            cases += 1
        else:
            raise Violation("shortened or forked authority stream was accepted")

    # A retained v1 prefix checkpoint must remain independently recoverable
    # when its exact G+1 successor converts allocation to the v2 bitmap.
    # This is the format pair produced by the staged migration image.
    allocation_uuid = b"VIBEOS-STOR-V2!!"

    def allocation_pointer(segment_no: int, segment_generation: int) -> dict[str, Any]:
        return {
            "status": "value",
            "segment_no": segment_no,
            "segment_generation": segment_generation,
        }

    def allocation_checkpoint(
        generation: int,
        previous_generation: int,
        next_segment_generation: int,
        root: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "record": {
                "binding": {
                    "generation": generation,
                    "store_uuid": allocation_uuid,
                },
                "previous_generation": previous_generation,
                "admitted_segments": 8,
                "next_segment_generation": next_segment_generation,
                "cleaner_reserve_segments": 2,
                "allocation_root": root,
            }
        }

    def legacy_allocation_fixture() -> bytes:
        payload = bytearray(storage_codec.ALLOCATION_PAYLOAD_SIZE)
        payload[0x00:0x08] = storage_codec.ALLOCATION_MAGIC
        put_u16(payload, 0x08, 1)
        put_u16(payload, 0x0A, storage_codec.ALLOCATION_PAYLOAD_SIZE)
        put_u64(payload, 0x10, 3)
        put_u64(payload, 0x18, 8)
        put_u64(payload, 0x20, 4)
        put_u64(payload, 0x28, 5)
        struct.pack_into("<I", payload, 0x30, 2)
        return bytes(payload)

    older_root = allocation_pointer(3, 4)
    newer_root = allocation_pointer(4, 5)
    older_checkpoint = allocation_checkpoint(3, 2, 5, older_root)
    newer_checkpoint = allocation_checkpoint(4, 3, 6, newer_root)
    older_extent = {"binding": {"target_checkpoint_generation": 3}}
    newer_extent = {"binding": {"target_checkpoint_generation": 4}}
    legacy_payload = legacy_allocation_fixture()
    older_allocation, older_version = parse_checkpoint_allocation(
        legacy_payload, older_extent, older_checkpoint, older_root
    )
    require(
        older_version == 1
        and older_allocation["states"]
        == [gc_verifier.SEGMENT_ALLOCATED] * 4
        + [gc_verifier.SEGMENT_FREE] * 4
        and not older_allocation["retired"],
        "legacy allocation-v1 prefix did not convert exactly",
    )
    cases += 1
    newer_payload = gc_verifier.encode_allocation_fixture(
        4,
        6,
        [gc_verifier.SEGMENT_ALLOCATED] * 5
        + [gc_verifier.SEGMENT_FREE] * 3,
        [],
        reserve=2,
    )
    newer_allocation, newer_version = parse_checkpoint_allocation(
        newer_payload, newer_extent, newer_checkpoint, newer_root
    )
    require(
        newer_version == gc_verifier.ALLOCATION_VERSION,
        "G+1 allocation fixture did not decode as v2",
    )
    cases += 1
    validate_checkpoint_allocation_transition(
        older_checkpoint,
        newer_checkpoint,
        older_allocation,
        newer_allocation,
        older_version,
        newer_version,
    )
    cases += 1

    invalid_legacy_payloads = []
    invalid_legacy_payloads.append(legacy_payload + b"\0")
    invalid_reserved = bytearray(legacy_payload)
    invalid_reserved[0x34] = 1
    invalid_legacy_payloads.append(bytes(invalid_reserved))
    invalid_version = bytearray(legacy_payload)
    put_u16(invalid_version, 0x08, 3)
    invalid_legacy_payloads.append(bytes(invalid_version))
    invalid_prefix = bytearray(legacy_payload)
    put_u64(invalid_prefix, 0x20, 5)
    invalid_legacy_payloads.append(bytes(invalid_prefix))
    for invalid_payload in invalid_legacy_payloads:
        try:
            parse_checkpoint_allocation(
                invalid_payload, older_extent, older_checkpoint, older_root
            )
        except ValueError:
            cases += 1
        else:
            raise Violation("non-canonical legacy allocation-v1 fallback was accepted")

    try:
        validate_checkpoint_allocation_transition(
            older_checkpoint,
            newer_checkpoint,
            older_allocation,
            newer_allocation,
            older_version,
            1,
        )
    except Violation:
        cases += 1
    else:
        raise Violation("G+1 retained checkpoint remained allocation-v1")
    wrong_carrier = allocation_checkpoint(
        4, 3, 6, allocation_pointer(3, 5)
    )
    try:
        validate_checkpoint_allocation_transition(
            older_checkpoint,
            wrong_carrier,
            older_allocation,
            newer_allocation,
            older_version,
            newer_version,
        )
    except Violation:
        cases += 1
    else:
        raise Violation("allocation-v1 G+1 conversion used a stale carrier")

    # A persistent-authority-only publication may reuse a catalog snapshot
    # from an older checkpoint, while the catalog extent remains an exact
    # binding.  Future snapshots and mismatched extent bindings fail closed.
    require_dense_snapshot_binding(4, 4, 5)
    cases += 1
    for snapshot_generation, extent_generation, checkpoint_generation in (
        (6, 6, 5),
        (4, 5, 5),
    ):
        try:
            require_dense_snapshot_binding(
                snapshot_generation, extent_generation, checkpoint_generation
            )
        except Violation:
            cases += 1
        else:
            raise Violation("invalid dense CAS snapshot binding was accepted")
    return {"schema": "vibeos.storage-v2-migration-selftest", "version": 1, "status": "ok", "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--expect-native",
        action="store_true",
        help="require a generation-1 native rollback-closed V2 store with no M4 source",
    )
    parser.add_argument(
        "--unmanaged-prefix-baseline",
        type=Path,
        help="pre-migration image or exact [0,64) logical-block prefix",
    )
    parser.add_argument(
        "--frozen-m4-baseline",
        type=Path,
        help="powered-off V2Staged image or exact [64,576) rollback range",
    )
    args = parser.parse_args()
    try:
        if args.selftest:
            result = selftest()
        else:
            require(args.image is not None, "an image path or --selftest is required")
            require(
                args.unmanaged_prefix_baseline is not None,
                "--unmanaged-prefix-baseline is required for image verification",
            )
            baseline_image = args.unmanaged_prefix_baseline.read_bytes()
            require(
                len(baseline_image) >= M4_FIRST * BLOCK,
                "unmanaged-prefix baseline is shorter than [0,64)",
            )
            frozen_m4 = None
            if args.frozen_m4_baseline is not None:
                frozen_image = args.frozen_m4_baseline.read_bytes()
                exact_m4_bytes = M4_COUNT * BLOCK
                if len(frozen_image) == exact_m4_bytes:
                    frozen_m4 = frozen_image
                else:
                    require(
                        len(frozen_image) >= (M4_FIRST + M4_COUNT) * BLOCK,
                        "frozen-M4 baseline is shorter than [64,576)",
                    )
                    frozen_m4 = frozen_image[
                        M4_FIRST * BLOCK:(M4_FIRST + M4_COUNT) * BLOCK
                    ]
            result = verify_image(
                args.image.read_bytes(),
                baseline_image[:M4_FIRST * BLOCK],
                frozen_m4,
                expect_native=args.expect_native,
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({"schema": "vibeos.storage-v2-migration-verifier", "version": 1, "status": "error", "error": str(error)}, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
