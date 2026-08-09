#!/usr/bin/env python3
"""Independent M4.3 durable-CSpace image and strict-prefix verifier.

This parser intentionally shares no Rust recovery code and imports none of the
M4.2 host verifier.  It validates the canonical record envelope, unified ID and
transaction namespaces, object commit binding, derivation graph, root policy,
tombstone ordering, and slot-generation history directly from the raw disk.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
import sys
from pathlib import Path


SECTOR_SIZE = 512
STORE_FIRST_SECTOR = 64
STORE_END_SECTOR = 576
MAGIC = b"VIBECAP\0"
SEAL = b"VIBECAP-COMMIT!!"
CRC_OFFSET = 0x1D0
SEAL_OFFSET = 0x1F0
PAYLOAD_OFFSET = 0x50
STORE_ID = 0x5649_4245_4F53_2D53_544F_5245_2D4D_3401

FORMAT = 1
HIGH_WATER = 2
GRANT_PREPARE = 3
GRANT_COMMIT = 4
TOMBSTONE = 5
OBJECT_PREPARE = 6
OBJECT_CHUNK = 7
OBJECT_COMMIT = 8
PAYLOAD_LENGTH = {
    FORMAT: 0,
    HIGH_WATER: 16,
    GRANT_PREPARE: 88,
    GRANT_COMMIT: 32,
    TOMBSTONE: 16,
    OBJECT_PREPARE: 40,
    OBJECT_CHUNK: 384,
    OBJECT_COMMIT: 48,
}

PERSISTENT_SPACE_ID = 0x5053
STORED_OBJECT_RESOURCE_KIND = 0x5354_4F52
PERSISTENT_OBJECT_KIND = 0x4353_5043
ROOT_RIGHTS = 0x01 | 0x10 | 0x20
CHILD_RIGHTS = 0x01 | 0x10
GRANDCHILD_RIGHTS = 0x01
ROOT_SLOT = 0
CHILD_SLOT = 1
GRANDCHILD_SLOT = 2
MARKER = b"VIBEOS-PERSISTENT-CSPACE-v1"


def fail(message: str) -> "None":
    raise ValueError(message)


def crc32c(data: bytes) -> int:
    crc = 0xFFFF_FFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F6_3B78 if crc & 1 else 0)
    return (~crc) & 0xFFFF_FFFF


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def u128(data: bytes, offset: int) -> int:
    low, high = struct.unpack_from("<QQ", data, offset)
    return low | high << 64


@dataclass(frozen=True)
class Record:
    physical: int
    raw: bytes
    kind: int
    sequence: int
    previous_sequence: int
    previous_crc: int
    crc: int
    transaction: int


@dataclass(frozen=True)
class Grant:
    derivation: int
    parent: int
    object_id: int
    space: int
    slot: int
    generation: int
    rights: int
    resource_kind: int
    flags: int
    commit_sequence: int


@dataclass
class State:
    formatted: bool
    high_water: int
    objects: dict[int, tuple[int, bytes, int]]
    grants: list[Grant]
    tombstones: dict[int, int]
    live: dict[int, Grant]
    slots: dict[tuple[int, int], tuple[int, int | None]]

    def fingerprint(self) -> tuple:
        return (
            self.formatted,
            self.high_water,
            tuple(sorted((key, kind, content, sequence) for key, (kind, content, sequence) in self.objects.items())),
            tuple(self.grants),
            tuple(sorted(self.tombstones.items())),
            tuple(sorted((key, value.derivation) for key, value in self.live.items())),
            tuple(sorted(self.slots.items())),
        )


def decode_sector(sector: bytes, physical: int) -> Record | None:
    if sector == bytes(SECTOR_SIZE) or sector[SEAL_OFFSET:] != SEAL:
        return None
    if sector[:8] != MAGIC or u16(sector, 0x08) != 1:
        fail(f"sealed sector {physical}: bad magic/version")
    kind = u16(sector, 0x0A)
    if kind not in PAYLOAD_LENGTH:
        fail(f"sealed sector {physical}: unknown record kind {kind}")
    payload_len = PAYLOAD_LENGTH[kind]
    if u16(sector, 0x0C) != 80 or u16(sector, 0x0E) != payload_len:
        fail(f"sealed sector {physical}: non-canonical header")
    if u32(sector, 0x24) != 0 or any(sector[0x48:0x50]):
        fail(f"sealed sector {physical}: non-zero reserved header")
    if any(sector[PAYLOAD_OFFSET + payload_len : CRC_OFFSET]):
        fail(f"sealed sector {physical}: non-canonical payload padding")
    checksum = u32(sector, CRC_OFFSET)
    if crc32c(sector[:CRC_OFFSET]) != checksum:
        fail(f"sealed sector {physical}: bad CRC32C")
    if u32(sector, CRC_OFFSET + 4) != (~checksum & 0xFFFF_FFFF):
        fail(f"sealed sector {physical}: bad CRC complement")
    sequence = u64(sector, 0x10)
    transaction = u128(sector, 0x38)
    if sequence == 0 or u64(sector, CRC_OFFSET + 8) != sequence:
        fail(f"sealed sector {physical}: bad sequence copy")
    if u128(sector, CRC_OFFSET + 16) != transaction:
        fail(f"sealed sector {physical}: bad transaction copy")
    if u128(sector, 0x28) != STORE_ID:
        fail(f"sealed sector {physical}: wrong platform StoreId")
    transactional = kind in {
        GRANT_PREPARE,
        GRANT_COMMIT,
        TOMBSTONE,
        OBJECT_PREPARE,
        OBJECT_CHUNK,
        OBJECT_COMMIT,
    }
    if transactional != (transaction != 0):
        fail(f"sealed sector {physical}: non-canonical transaction id")
    return Record(
        physical,
        sector,
        kind,
        sequence,
        u64(sector, 0x18),
        u32(sector, 0x20),
        checksum,
        transaction,
    )


def records_from_image(image: bytes) -> list[Record]:
    if len(image) < STORE_END_SECTOR * SECTOR_SIZE or len(image) % SECTOR_SIZE:
        fail("raw image does not cover the aligned fixed journal region")
    records = []
    for physical in range(STORE_FIRST_SECTOR, STORE_END_SECTOR):
        start = physical * SECTOR_SIZE
        record = decode_sector(image[start : start + SECTOR_SIZE], physical)
        if record is not None:
            records.append(record)
    previous_sequence = 0
    previous_crc = 0
    for index, record in enumerate(records):
        if record.sequence != previous_sequence + 1:
            fail("valid journal records are not a consecutive sequence")
        if record.previous_sequence != previous_sequence or record.previous_crc != previous_crc:
            fail("journal previous-sequence/CRC chain is broken")
        if index == 0 and record.kind != FORMAT:
            fail("format is not the first valid record")
        if index != 0 and record.kind == FORMAT:
            fail("duplicate format record")
        previous_sequence = record.sequence
        previous_crc = record.crc
    return records


def recover(image: bytes) -> State:
    records = records_from_image(image)
    if not records:
        return State(False, 0, {}, [], {}, {}, {})

    high_water = 0
    id_classes: dict[int, str] = {}
    transactions: dict[int, dict] = {}
    seen_derivations: set[int] = set()
    seen_objects: set[int] = set()
    objects: dict[int, tuple[int, bytes, int]] = {}
    grants: list[Grant] = []
    tombstones: dict[int, int] = {}

    def reserved(value: int) -> bool:
        return value != 0 and value < high_water

    def claim(value: int, kind: str) -> None:
        old = id_classes.get(value)
        if old is not None and old != kind:
            fail(f"stable id {value} changed class from {old} to {kind}")
        id_classes[value] = kind

    for record in records:
        raw = record.raw
        tx = record.transaction
        sequence = record.sequence
        if record.kind == FORMAT:
            continue
        if record.kind == HIGH_WATER:
            value = u128(raw, PAYLOAD_OFFSET)
            if value <= high_water:
                fail("high-water reservation did not strictly increase")
            high_water = value
            continue

        if record.kind == GRANT_PREPARE:
            derivation = u128(raw, PAYLOAD_OFFSET)
            parent = u128(raw, PAYLOAD_OFFSET + 16)
            object_id = u128(raw, PAYLOAD_OFFSET + 32)
            space = u128(raw, PAYLOAD_OFFSET + 48)
            slot = u32(raw, PAYLOAD_OFFSET + 64)
            rights = u32(raw, PAYLOAD_OFFSET + 68)
            generation = u64(raw, PAYLOAD_OFFSET + 72)
            resource_kind = u32(raw, PAYLOAD_OFFSET + 80)
            flags = u32(raw, PAYLOAD_OFFSET + 84)
            ids = (tx, derivation, object_id, space)
            if not all(reserved(value) for value in ids) or (parent and not reserved(parent)):
                fail("grant prepare mentions an unreserved stable id")
            if rights & ~0x3F or resource_kind == 0 or flags & ~1:
                fail("grant prepare contains unknown rights/kind/flags")
            claim(tx, "transaction")
            claim(derivation, "derivation")
            claim(object_id, "object")
            claim(space, "space")
            if parent:
                claim(parent, "derivation")
            if (
                tx in transactions
                or derivation in seen_derivations
                or derivation in tombstones
            ):
                fail("duplicate grant transaction or derivation")
            seen_derivations.add(derivation)
            transactions[tx] = {
                "type": "grant",
                "grant": Grant(
                    derivation,
                    parent,
                    object_id,
                    space,
                    slot,
                    generation,
                    rights,
                    resource_kind,
                    flags,
                    0,
                ),
                "prepare_sequence": sequence,
                "prepare_crc": record.crc,
            }
            continue

        if record.kind == GRANT_COMMIT:
            prepare_sequence = u64(raw, PAYLOAD_OFFSET)
            if prepare_sequence == 0 or u32(raw, PAYLOAD_OFFSET + 12) != 0:
                fail("grant commit metadata is non-canonical")
            derivation = u128(raw, PAYLOAD_OFFSET + 16)
            if not reserved(tx) or not reserved(derivation):
                fail("grant commit mentions an unreserved stable id")
            claim(tx, "transaction")
            claim(derivation, "derivation")
            prepared = transactions.get(tx)
            if prepared is None:
                if derivation in seen_derivations:
                    fail("orphan commit reuses a derivation")
                seen_derivations.add(derivation)
                transactions[tx] = {"type": "finished"}
                continue
            if (
                prepared.get("type") != "grant"
                or prepared["grant"].derivation != derivation
                or prepared["prepare_sequence"] != prepare_sequence
                or prepared["prepare_crc"] != u32(raw, PAYLOAD_OFFSET + 8)
            ):
                fail("grant commit does not exactly bind its prepare")
            grant = prepared["grant"]
            grants.append(
                Grant(
                    grant.derivation,
                    grant.parent,
                    grant.object_id,
                    grant.space,
                    grant.slot,
                    grant.generation,
                    grant.rights,
                    grant.resource_kind,
                    grant.flags,
                    sequence,
                )
            )
            transactions[tx] = {"type": "finished"}
            continue

        if record.kind == TOMBSTONE:
            derivation = u128(raw, PAYLOAD_OFFSET)
            if not reserved(tx) or not reserved(derivation):
                fail("tombstone mentions an unreserved stable id")
            claim(tx, "transaction")
            claim(derivation, "derivation")
            if tx in transactions:
                fail("tombstone reused a transaction id")
            transactions[tx] = {"type": "finished"}
            tombstones.setdefault(derivation, sequence)
            continue

        if record.kind == OBJECT_PREPARE:
            object_id = u128(raw, PAYLOAD_OFFSET)
            object_kind = u32(raw, PAYLOAD_OFFSET + 16)
            byte_len = u64(raw, PAYLOAD_OFFSET + 24)
            chunks = u32(raw, PAYLOAD_OFFSET + 32)
            content_crc = u32(raw, PAYLOAD_OFFSET + 36)
            if not reserved(tx) or not reserved(object_id):
                fail("object prepare mentions an unreserved stable id")
            if (
                object_kind == 0
                or u32(raw, PAYLOAD_OFFSET + 20) != 0
                or byte_len > 360 * 1024
                or chunks != (byte_len + 359) // 360
            ):
                fail("object prepare metadata is non-canonical")
            claim(tx, "transaction")
            claim(object_id, "object")
            if tx in transactions or object_id in seen_objects:
                fail("duplicate object transaction or object")
            seen_objects.add(object_id)
            transactions[tx] = {
                "type": "object",
                "object_id": object_id,
                "object_kind": object_kind,
                "byte_len": byte_len,
                "chunk_count": chunks,
                "content_crc": content_crc,
                "prepare_sequence": sequence,
                "prepare_crc": record.crc,
                "chunks": [],
                "chunk_crcs": [],
                "first_chunk_sequence": 0,
            }
            continue

        if record.kind == OBJECT_CHUNK:
            object_id = u128(raw, PAYLOAD_OFFSET)
            index = u32(raw, PAYLOAD_OFFSET + 16)
            length = u16(raw, PAYLOAD_OFFSET + 20)
            state = transactions.get(tx)
            if not reserved(tx) or not reserved(object_id):
                fail("object chunk mentions an unreserved stable id")
            claim(tx, "transaction")
            claim(object_id, "object")
            if (
                state is None
                or state.get("type") != "object"
                or state["object_id"] != object_id
                or index != len(state["chunks"])
            ):
                fail("object chunk is not exactly bound to its prepare")
            expected = min(360, state["byte_len"] - index * 360)
            if u16(raw, PAYLOAD_OFFSET + 22) != 0 or length == 0 or length != expected:
                fail("object chunk length is non-canonical")
            content = raw[PAYLOAD_OFFSET + 24 : PAYLOAD_OFFSET + 24 + length]
            if any(raw[PAYLOAD_OFFSET + 24 + length : CRC_OFFSET]):
                fail("object chunk tail is non-canonical")
            if index == 0:
                state["first_chunk_sequence"] = sequence
            state["chunks"].append(content)
            state["chunk_crcs"].append(record.crc)
            continue

        if record.kind == OBJECT_COMMIT:
            object_id = u128(raw, PAYLOAD_OFFSET)
            state = transactions.get(tx)
            if not reserved(tx) or not reserved(object_id):
                fail("object commit mentions an unreserved stable id")
            claim(tx, "transaction")
            claim(object_id, "object")
            if state is None or state.get("type") != "object" or state["object_id"] != object_id:
                fail("object commit has no exact prepare")
            content = b"".join(state["chunks"])
            digest = crc32c(b"".join(struct.pack("<I", value) for value in state["chunk_crcs"]))
            expected_first = state["first_chunk_sequence"] if state["chunk_count"] else 0
            if (
                u64(raw, PAYLOAD_OFFSET + 16) != state["prepare_sequence"]
                or u32(raw, PAYLOAD_OFFSET + 24) != state["prepare_crc"]
                or u32(raw, PAYLOAD_OFFSET + 28) != state["chunk_count"]
                or u32(raw, PAYLOAD_OFFSET + 28) != len(state["chunks"])
                or u64(raw, PAYLOAD_OFFSET + 32) != expected_first
                or u32(raw, PAYLOAD_OFFSET + 40) != digest
                or u32(raw, PAYLOAD_OFFSET + 44) != state["content_crc"]
                or len(content) != state["byte_len"]
                or crc32c(content) != state["content_crc"]
            ):
                fail("object commit binding/content verification failed")
            objects[object_id] = (state["object_kind"], content, sequence)
            transactions[tx] = {"type": "finished"}

    graph: dict[int, Grant] = {}
    slot_history: dict[tuple[int, int], tuple[int, int]] = {}
    object_resource_kinds: dict[int, int] = {}

    def tombstoned(derivation: int, before: int | None = None) -> bool:
        seen: set[int] = set()
        current = derivation
        while current:
            if current in seen:
                fail("derivation ancestry cycle")
            seen.add(current)
            sequence = tombstones.get(current)
            if sequence is not None and (before is None or sequence < before):
                return True
            parent = graph.get(current)
            current = parent.parent if parent is not None else 0
        return False

    for grant in grants:
        previous_kind = object_resource_kinds.setdefault(
            grant.object_id, grant.resource_kind
        )
        if previous_kind != grant.resource_kind:
            fail("one ObjectId changed durable ResourceKind")
        if grant.flags == 1:
            if grant.parent:
                fail("ROOT grant has a parent")
        else:
            parent = graph.get(grant.parent)
            if parent is None:
                fail("derived grant has no committed parent")
            if not parent.rights & 0x10 or parent.rights & grant.rights != grant.rights:
                fail("derived grant amplifies or lacks parent GRANT")
            if parent.object_id != grant.object_id or parent.resource_kind != grant.resource_kind:
                fail("derived grant changed object/resource kind")
        # Acceptance deliberately tightens the inert preflight rule: this
        # single-purpose image may contain only typed StoredObject grants, so
        # even tombstoned history must name an object committed beforehand.
        if grant.object_id not in objects:
            fail("grant references no committed object")
        if objects[grant.object_id][2] >= grant.commit_sequence:
            fail("grant commit did not follow object commit")
        key = (grant.space, grant.slot)
        old = slot_history.get(key)
        if old is not None:
            old_generation, old_derivation = old
            if grant.generation <= old_generation or not tombstoned(old_derivation, grant.commit_sequence):
                fail("slot reuse lacks prior tombstone and increasing generation")
        slot_history[key] = (grant.generation, grant.derivation)
        graph[grant.derivation] = grant

    live = {derivation: grant for derivation, grant in graph.items() if not tombstoned(derivation)}
    slots = {
        key: (generation, derivation if derivation in live else None)
        for key, (generation, derivation) in slot_history.items()
    }
    return State(True, high_water, objects, grants, tombstones, live, slots)


def select_external_root(state: State) -> Grant | None:
    matches = []
    for grant in state.live.values():
        object_entry = state.objects.get(grant.object_id)
        if (
            grant.flags == 1
            and grant.parent == 0
            and grant.space == PERSISTENT_SPACE_ID
            and grant.slot == ROOT_SLOT
            and grant.generation == 0
            and grant.rights == ROOT_RIGHTS
            and grant.resource_kind == STORED_OBJECT_RESOURCE_KIND
            and object_entry is not None
            and object_entry[0] == PERSISTENT_OBJECT_KIND
            and object_entry[2] < grant.commit_sequence
        ):
            matches.append(grant)
    if len(matches) > 1:
        fail("external root constraint is ambiguous")
    return matches[0] if matches else None


def verify_acceptance(state: State) -> None:
    if not state.formatted:
        fail("journal is not formatted")
    if len(state.objects) != 1:
        fail(f"expected one committed persistent object, found {len(state.objects)}")
    object_id, (kind, content, _) = next(iter(state.objects.items()))
    if kind != PERSISTENT_OBJECT_KIND or content != MARKER:
        fail("persistent object kind/payload mismatch")
    root = select_external_root(state)
    if root is None:
        fail("exact externally constrained root is absent")
    if any(
        grant.flags == 1 and grant.derivation != root.derivation
        for grant in state.live.values()
    ):
        fail("live root exists outside the exact external policy")
    children = [
        grant
        for grant in state.grants
        if grant.parent == root.derivation and grant.slot == CHILD_SLOT
    ]
    if len(children) != 2:
        fail(f"expected original and replacement child, found {len(children)}")
    children.sort(key=lambda grant: grant.generation)
    old, replacement = children
    for grant, generation in ((old, 0), (replacement, 1)):
        if (
            grant.object_id != object_id
            or grant.space != PERSISTENT_SPACE_ID
            or grant.slot != CHILD_SLOT
            or grant.generation != generation
            or grant.rights != CHILD_RIGHTS
            or grant.resource_kind != STORED_OBJECT_RESOURCE_KIND
            or grant.flags != 0
        ):
            fail("child grant shape/generation is not exact")
    descendants = [grant for grant in state.grants if grant.parent == old.derivation]
    if len(descendants) != 1:
        fail("expected one descendant below the original child")
    descendant = descendants[0]
    if (
        descendant.object_id != object_id
        or descendant.space != PERSISTENT_SPACE_ID
        or descendant.slot != GRANDCHILD_SLOT
        or descendant.generation != 0
        or descendant.rights != GRANDCHILD_RIGHTS
        or descendant.resource_kind != STORED_OBJECT_RESOURCE_KIND
        or descendant.flags != 0
    ):
        fail("grandchild grant shape is not exact")
    tombstone_sequence = state.tombstones.get(old.derivation)
    if tombstone_sequence is None or tombstone_sequence <= old.commit_sequence:
        fail("original child lacks a later durable tombstone")
    if replacement.commit_sequence <= tombstone_sequence:
        fail("replacement child was committed before the tombstone")
    if (
        old.derivation in state.live
        or descendant.derivation in state.live
        or replacement.derivation not in state.live
    ):
        fail("ancestor tombstone did not remove the complete subtree")
    if state.slots.get((PERSISTENT_SPACE_ID, ROOT_SLOT)) != (0, root.derivation):
        fail("root slot history is wrong")
    if state.slots.get((PERSISTENT_SPACE_ID, CHILD_SLOT)) != (1, replacement.derivation):
        fail("child slot did not reuse generation 1")
    if state.slots.get((PERSISTENT_SPACE_ID, GRANDCHILD_SLOT)) != (0, None):
        fail("tombstoned descendant slot history is wrong")
    if any(space != PERSISTENT_SPACE_ID for space, _slot in state.slots):
        fail("foreign SpaceId history exists in the persistent-test image")
    if set(slot for _space, slot in state.slots) != {
        ROOT_SLOT,
        CHILD_SLOT,
        GRANDCHILD_SLOT,
    }:
        fail("persistent-test image contains an unexpected durable slot")
    if any(grant.rights & 0x02 for grant in state.grants):
        fail("persistent CSpace received forbidden WRITE authority")


def encode_record(
    kind: int,
    payload: bytes,
    sequence: int,
    previous_sequence: int,
    previous_crc: int,
    transaction: int = 0,
) -> bytes:
    if len(payload) != PAYLOAD_LENGTH[kind]:
        fail("fixture payload length drift")
    record = bytearray(SECTOR_SIZE)
    record[:8] = MAGIC
    struct.pack_into("<HHHHQQI", record, 0x08, 1, kind, 80, len(payload), sequence, previous_sequence, previous_crc)
    record[0x28:0x38] = STORE_ID.to_bytes(16, "little")
    record[0x38:0x48] = transaction.to_bytes(16, "little")
    record[PAYLOAD_OFFSET : PAYLOAD_OFFSET + len(payload)] = payload
    checksum = crc32c(record[:CRC_OFFSET])
    struct.pack_into("<IIQ", record, CRC_OFFSET, checksum, ~checksum & 0xFFFF_FFFF, sequence)
    record[CRC_OFFSET + 16 : CRC_OFFSET + 32] = transaction.to_bytes(16, "little")
    record[SEAL_OFFSET:] = SEAL
    return bytes(record)


def fixture_records() -> list[bytes]:
    base = PERSISTENT_SPACE_ID + 1
    object_tx, object_id = base, base + 1
    root_tx, root_id = base + 2, base + 3
    child_tx, child_id = base + 4, base + 5
    grandchild_tx, grandchild_id = base + 6, base + 7
    revoke_tx = base + 8
    replacement_tx, replacement_id = base + 9, base + 10
    records: list[bytes] = []
    previous_sequence = 0
    previous_crc = 0

    def append(kind: int, payload: bytes, transaction: int = 0) -> Record:
        nonlocal previous_sequence, previous_crc
        sequence = previous_sequence + 1
        encoded = encode_record(kind, payload, sequence, previous_sequence, previous_crc, transaction)
        decoded = decode_sector(encoded, STORE_FIRST_SECTOR + len(records))
        assert decoded is not None
        records.append(encoded)
        previous_sequence = sequence
        previous_crc = decoded.crc
        return decoded

    append(FORMAT, b"")
    append(HIGH_WATER, (base + 2).to_bytes(16, "little"))

    prepare = bytearray(40)
    prepare[0:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<I", prepare, 16, PERSISTENT_OBJECT_KIND)
    struct.pack_into("<QII", prepare, 24, len(MARKER), 1, crc32c(MARKER))
    object_prepare = append(OBJECT_PREPARE, bytes(prepare), object_tx)
    chunk = bytearray(384)
    chunk[0:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<IH", chunk, 16, 0, len(MARKER))
    chunk[24 : 24 + len(MARKER)] = MARKER
    object_chunk = append(OBJECT_CHUNK, bytes(chunk), object_tx)
    commit = bytearray(48)
    commit[0:16] = object_id.to_bytes(16, "little")
    struct.pack_into(
        "<QIIQII",
        commit,
        16,
        object_prepare.sequence,
        object_prepare.crc,
        1,
        object_chunk.sequence,
        crc32c(struct.pack("<I", object_chunk.crc)),
        crc32c(MARKER),
    )
    append(OBJECT_COMMIT, bytes(commit), object_tx)

    def append_grant(
        transaction: int,
        derivation: int,
        parent: int,
        slot: int,
        generation: int,
        rights: int,
        flags: int,
    ) -> None:
        grant = bytearray(88)
        grant[0:16] = derivation.to_bytes(16, "little")
        grant[16:32] = parent.to_bytes(16, "little")
        grant[32:48] = object_id.to_bytes(16, "little")
        grant[48:64] = PERSISTENT_SPACE_ID.to_bytes(16, "little")
        struct.pack_into("<IIQII", grant, 64, slot, rights, generation, STORED_OBJECT_RESOURCE_KIND, flags)
        prepared = append(GRANT_PREPARE, bytes(grant), transaction)
        committed = bytearray(32)
        struct.pack_into("<QI", committed, 0, prepared.sequence, prepared.crc)
        committed[16:32] = derivation.to_bytes(16, "little")
        append(GRANT_COMMIT, bytes(committed), transaction)

    append(HIGH_WATER, (base + 4).to_bytes(16, "little"))
    append_grant(root_tx, root_id, 0, ROOT_SLOT, 0, ROOT_RIGHTS, 1)
    append(HIGH_WATER, (base + 6).to_bytes(16, "little"))
    append_grant(child_tx, child_id, root_id, CHILD_SLOT, 0, CHILD_RIGHTS, 0)
    append(HIGH_WATER, (base + 8).to_bytes(16, "little"))
    append_grant(
        grandchild_tx,
        grandchild_id,
        child_id,
        GRANDCHILD_SLOT,
        0,
        GRANDCHILD_RIGHTS,
        0,
    )
    append(HIGH_WATER, (base + 9).to_bytes(16, "little"))
    append(TOMBSTONE, child_id.to_bytes(16, "little"), revoke_tx)
    append(HIGH_WATER, (base + 11).to_bytes(16, "little"))
    append_grant(replacement_tx, replacement_id, root_id, CHILD_SLOT, 1, CHILD_RIGHTS, 0)
    return records


def image_with(records: list[bytes], partial: bytes = b"") -> bytes:
    image = bytearray(STORE_END_SECTOR * SECTOR_SIZE)
    for index, record in enumerate(records):
        start = (STORE_FIRST_SECTOR + index) * SECTOR_SIZE
        image[start : start + SECTOR_SIZE] = record
    if partial:
        start = (STORE_FIRST_SECTOR + len(records)) * SECTOR_SIZE
        image[start : start + len(partial)] = partial
    return bytes(image)


def reencode(records: list[bytes], changes: dict[int, tuple[bytes | None, int | None]]) -> list[bytes]:
    rebuilt = []
    previous_sequence = 0
    previous_crc = 0
    for index, raw in enumerate(records):
        kind = u16(raw, 0x0A)
        payload = raw[PAYLOAD_OFFSET : PAYLOAD_OFFSET + PAYLOAD_LENGTH[kind]]
        transaction = u128(raw, 0x38)
        changed_payload, changed_transaction = changes.get(index, (None, None))
        if changed_payload is not None:
            payload = changed_payload
        if changed_transaction is not None:
            transaction = changed_transaction
        encoded = encode_record(
            kind,
            payload,
            previous_sequence + 1,
            previous_sequence,
            previous_crc,
            transaction,
        )
        decoded = decode_sector(encoded, STORE_FIRST_SECTOR + index)
        assert decoded is not None
        rebuilt.append(encoded)
        previous_sequence = decoded.sequence
        previous_crc = decoded.crc
    return rebuilt


def append_fixture_record(
    records: list[bytes], kind: int, payload: bytes, transaction: int = 0
) -> Record:
    if records:
        previous = decode_sector(records[-1], STORE_FIRST_SECTOR + len(records) - 1)
        assert previous is not None
        previous_sequence = previous.sequence
        previous_crc = previous.crc
    else:
        previous_sequence = 0
        previous_crc = 0
    encoded = encode_record(
        kind,
        payload,
        previous_sequence + 1,
        previous_sequence,
        previous_crc,
        transaction,
    )
    decoded = decode_sector(encoded, STORE_FIRST_SECTOR + len(records))
    assert decoded is not None
    records.append(encoded)
    return decoded


def grant_payload(
    derivation: int,
    parent: int,
    object_id: int,
    space: int,
    slot: int,
    generation: int,
    rights: int,
    resource_kind: int,
    flags: int,
) -> bytes:
    payload = bytearray(88)
    payload[0:16] = derivation.to_bytes(16, "little")
    payload[16:32] = parent.to_bytes(16, "little")
    payload[32:48] = object_id.to_bytes(16, "little")
    payload[48:64] = space.to_bytes(16, "little")
    struct.pack_into(
        "<IIQII", payload, 64, slot, rights, generation, resource_kind, flags
    )
    return bytes(payload)


def append_fixture_grant(
    records: list[bytes], transaction: int, payload: bytes
) -> None:
    prepared = append_fixture_record(records, GRANT_PREPARE, payload, transaction)
    commit = bytearray(32)
    struct.pack_into("<QI", commit, 0, prepared.sequence, prepared.crc)
    commit[16:32] = payload[0:16]
    append_fixture_record(records, GRANT_COMMIT, bytes(commit), transaction)


def rewrite_grant_prepare(
    records: list[bytes], index: int, payload: bytes
) -> list[bytes]:
    rebuilt = reencode(records, {index: (payload, None)})
    prepared = decode_sector(rebuilt[index], STORE_FIRST_SECTOR + index)
    assert prepared is not None and prepared.kind == GRANT_PREPARE
    commit = bytearray(
        rebuilt[index + 1][PAYLOAD_OFFSET : PAYLOAD_OFFSET + PAYLOAD_LENGTH[GRANT_COMMIT]]
    )
    struct.pack_into("<QI", commit, 0, prepared.sequence, prepared.crc)
    commit[16:32] = payload[0:16]
    return reencode(rebuilt, {index + 1: (bytes(commit), None)})


def expect_failure(
    name: str,
    records: list[bytes],
    fragment: str,
    *,
    final: bool = False,
) -> None:
    try:
        state = recover(image_with(records))
        if final:
            verify_acceptance(state)
    except ValueError as error:
        if fragment not in str(error):
            fail(f"negative fixture {name!r} failed for the wrong reason: {error}")
        return
    fail(f"negative fixture {name!r} was accepted")


def negative_selftest(records: list[bytes]) -> None:
    base = PERSISTENT_SPACE_ID + 1
    object_id = base + 1
    root_id = base + 3
    child_id = base + 5

    orphan_commit = list(records)
    append_fixture_record(
        orphan_commit, HIGH_WATER, (base + 13).to_bytes(16, "little")
    )
    zero_prepare = bytearray(32)
    zero_prepare[16:32] = (base + 12).to_bytes(16, "little")
    append_fixture_record(orphan_commit, GRANT_COMMIT, bytes(zero_prepare), base + 11)
    expect_failure(
        "orphan-commit-zero-prepare-sequence",
        orphan_commit,
        "metadata is non-canonical",
    )

    orphan_commit = list(records)
    append_fixture_record(
        orphan_commit, HIGH_WATER, (base + 13).to_bytes(16, "little")
    )
    nonzero_reserved = bytearray(32)
    struct.pack_into("<QI", nonzero_reserved, 0, 1, 0)
    struct.pack_into("<I", nonzero_reserved, 12, 1)
    nonzero_reserved[16:32] = (base + 12).to_bytes(16, "little")
    append_fixture_record(
        orphan_commit, GRANT_COMMIT, bytes(nonzero_reserved), base + 11
    )
    expect_failure(
        "orphan-commit-nonzero-reserved",
        orphan_commit,
        "metadata is non-canonical",
    )

    root_prepare = bytearray(records[6][PAYLOAD_OFFSET : PAYLOAD_OFFSET + 88])
    root_prepare[0:16] = object_id.to_bytes(16, "little")
    expect_failure(
        "cross-class-id",
        rewrite_grant_prepare(records, 6, bytes(root_prepare)),
        "changed class",
    )

    expect_failure(
        "transaction-reuse",
        reencode(records, {9: (None, base + 2)}),
        "duplicate grant transaction",
    )

    child_prepare = bytearray(records[9][PAYLOAD_OFFSET : PAYLOAD_OFFSET + 88])
    child_prepare[16:32] = (1).to_bytes(16, "little")
    expect_failure(
        "missing-parent",
        rewrite_grant_prepare(records, 9, bytes(child_prepare))[:11],
        "no committed parent",
    )

    child_prepare = bytearray(records[9][PAYLOAD_OFFSET : PAYLOAD_OFFSET + 88])
    struct.pack_into("<I", child_prepare, 68, CHILD_RIGHTS | 0x02)
    expect_failure(
        "rights-amplification",
        rewrite_grant_prepare(records, 9, bytes(child_prepare))[:11],
        "amplifies",
    )

    pre_tombstone = list(records[:8])
    append_fixture_record(
        pre_tombstone, HIGH_WATER, (base + 7).to_bytes(16, "little")
    )
    append_fixture_record(
        pre_tombstone, TOMBSTONE, child_id.to_bytes(16, "little"), base + 4
    )
    append_fixture_record(
        pre_tombstone,
        GRANT_PREPARE,
        records[9][PAYLOAD_OFFSET : PAYLOAD_OFFSET + 88],
        base + 6,
    )
    expect_failure(
        "pre-tombstoned-derivation",
        pre_tombstone,
        "duplicate grant transaction or derivation",
    )

    extra_root = list(records)
    append_fixture_record(
        extra_root, HIGH_WATER, (base + 13).to_bytes(16, "little")
    )
    append_fixture_grant(
        extra_root,
        base + 11,
        grant_payload(
            base + 12,
            0,
            object_id,
            PERSISTENT_SPACE_ID,
            3,
            0,
            ROOT_RIGHTS,
            STORED_OBJECT_RESOURCE_KIND,
            1,
        ),
    )
    expect_failure(
        "untrusted-live-root", extra_root, "outside the exact external policy", final=True
    )

    conflicting_kind = list(records)
    append_fixture_record(
        conflicting_kind, HIGH_WATER, (base + 13).to_bytes(16, "little")
    )
    append_fixture_grant(
        conflicting_kind,
        base + 11,
        grant_payload(
            base + 12,
            0,
            object_id,
            PERSISTENT_SPACE_ID,
            3,
            0,
            ROOT_RIGHTS,
            STORED_OBJECT_RESOURCE_KIND + 1,
            1,
        ),
    )
    expect_failure(
        "object-resource-kind", conflicting_kind, "changed durable ResourceKind"
    )

    replacement_prepare = bytearray(
        records[17][PAYLOAD_OFFSET : PAYLOAD_OFFSET + 88]
    )
    struct.pack_into("<Q", replacement_prepare, 72, 0)
    expect_failure(
        "non-increasing-generation",
        rewrite_grant_prepare(records, 17, bytes(replacement_prepare)),
        "increasing generation",
    )

    foreign_history = list(records)
    append_fixture_record(
        foreign_history, HIGH_WATER, (base + 13).to_bytes(16, "little")
    )
    append_fixture_grant(
        foreign_history,
        base + 11,
        grant_payload(
            base + 12,
            0,
            object_id,
            1,
            0,
            0,
            ROOT_RIGHTS,
            STORED_OBJECT_RESOURCE_KIND,
            1,
        ),
    )
    append_fixture_record(
        foreign_history, HIGH_WATER, (base + 14).to_bytes(16, "little")
    )
    append_fixture_record(
        foreign_history,
        TOMBSTONE,
        (base + 12).to_bytes(16, "little"),
        base + 13,
    )
    expect_failure(
        "foreign-slot-history", foreign_history, "foreign SpaceId", final=True
    )


def selftest() -> None:
    records = fixture_records()
    if len(records) != 19:
        fail(f"fixture record count drifted to {len(records)}")
    baselines = [recover(image_with(records[:count])) for count in range(len(records) + 1)]

    # Every strict byte prefix of every next sector lacks a complete final seal
    # and must recover exactly the previously flushed record boundary.
    for count, baseline in enumerate(baselines[:-1]):
        for cut in range(SECTOR_SIZE):
            observed = recover(image_with(records[:count], records[count][:cut]))
            if observed.fingerprint() != baseline.fingerprint():
                fail(f"record {count + 1} byte-prefix cut {cut} changed recovered state")

    if baselines[4].objects or baselines[4].grants:
        fail("object prepare/chunk prefix published an object or authority")
    if len(baselines[5].objects) != 1 or baselines[5].grants:
        fail("object commit boundary did not publish only the object")
    if len(baselines[7].live) != 0 or len(baselines[8].live) != 1:
        fail("root prepare/commit publication boundary is wrong")
    if len(baselines[10].live) != 1 or len(baselines[11].live) != 2:
        fail("child prepare/commit publication boundary is wrong")
    if len(baselines[13].live) != 2 or len(baselines[14].live) != 3:
        fail("grandchild prepare/commit publication boundary is wrong")
    if len(baselines[15].live) != 3 or len(baselines[16].live) != 1:
        fail("ancestor tombstone flush boundary is wrong")
    if len(baselines[18].live) != 1 or len(baselines[19].live) != 2:
        fail("replacement prepare/commit publication boundary is wrong")
    verify_acceptance(baselines[-1])
    negative_selftest(records)
    print(f"ok   persistent CSpace strict-prefix fixtures ({len(records)} records x {SECTOR_SIZE} cuts)")


def verify(path: Path) -> None:
    state = recover(path.read_bytes())
    verify_acceptance(state)
    print("ok   persistent CSpace backing (root, tombstone, and generation-1 reuse verified)")


def main() -> int:
    try:
        if sys.argv[1:] == ["--selftest"]:
            selftest()
        elif len(sys.argv) == 2:
            verify(Path(sys.argv[1]))
        else:
            print(f"usage: {Path(sys.argv[0]).name} [--selftest | DISK.raw]", file=sys.stderr)
            return 2
    except (OSError, ValueError) as error:
        print(f"FAIL persistent CSpace verifier: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
