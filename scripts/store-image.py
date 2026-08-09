#!/usr/bin/env python3
"""Strict host-side verifier for the M4.2 object-store acceptance image."""

from __future__ import annotations

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
MARKER = b"VIBEOS-STORE-OBJECT-v1"
STORE_ID = 0x5649_4245_4F53_2D53_544F_5245_2D4D_3401
EXPECTED_OBJECT_KIND = 1
PREFILL_OBJECT_KIND = 2
PREFILL_MARKER = b"VIBEOS-STORE-DENSE-PREFILL-v1"
# Leave exactly six slots for the acceptance put: high-water, prepare, three
# chunks, and commit. The seed itself therefore occupies 506 of 512 slots.
PREFILL_CHUNKS = (STORE_END_SECTOR - STORE_FIRST_SECTOR) - 6 - 4
PREFILL_LENGTH = PREFILL_CHUNKS * 360


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


def expected_payload() -> bytes:
    data = bytearray((index * 17 + 3) % 251 for index in range(900))
    data[: len(MARKER)] = MARKER
    return bytes(data)


def expected_prefill_payload() -> bytes:
    data = bytearray((index * 31 + 11) % 251 for index in range(PREFILL_LENGTH))
    data[: len(PREFILL_MARKER)] = PREFILL_MARKER
    return bytes(data)


def fail(message: str) -> "None":
    raise ValueError(message)


def decode_sector(sector: bytes, physical: int) -> dict | None:
    if sector == bytes(SECTOR_SIZE):
        return None
    if sector[SEAL_OFFSET:] != SEAL:
        # Prefix-torn slots are permanent holes and do not stop later scanning.
        return None
    if sector[:8] != MAGIC or u16(sector, 0x08) != 1:
        fail(f"sealed sector {physical}: bad magic/version")
    kind = u16(sector, 0x0A)
    payload_lengths = {1: 0, 2: 16, 3: 88, 4: 32, 5: 16, 6: 40, 7: 384, 8: 48}
    if kind not in payload_lengths:
        fail(f"sealed sector {physical}: unknown kind {kind}")
    payload_len = payload_lengths[kind]
    if u16(sector, 0x0C) != 80 or u16(sector, 0x0E) != payload_len:
        fail(f"sealed sector {physical}: non-canonical header")
    if u32(sector, 0x24) != 0 or any(sector[0x48:0x50]):
        fail(f"sealed sector {physical}: reserved header bits")
    if any(sector[PAYLOAD_OFFSET + payload_len : CRC_OFFSET]):
        fail(f"sealed sector {physical}: non-zero payload padding")
    crc = u32(sector, CRC_OFFSET)
    if crc32c(sector[:CRC_OFFSET]) != crc or u32(sector, CRC_OFFSET + 4) != (~crc & 0xFFFF_FFFF):
        fail(f"sealed sector {physical}: bad CRC")
    sequence = u64(sector, 0x10)
    transaction = u128(sector, 0x38)
    if sequence == 0 or u64(sector, CRC_OFFSET + 8) != sequence:
        fail(f"sealed sector {physical}: bad sequence copy")
    if u128(sector, CRC_OFFSET + 16) != transaction:
        fail(f"sealed sector {physical}: bad transaction copy")
    store_id = u128(sector, 0x28)
    if store_id != STORE_ID:
        fail(f"sealed sector {physical}: wrong platform store id")
    return {
        "physical": physical,
        "bytes": sector,
        "kind": kind,
        "sequence": sequence,
        "previous_sequence": u64(sector, 0x18),
        "previous_crc": u32(sector, 0x20),
        "crc": crc,
        "store_id": store_id,
        "transaction": transaction,
    }


def verify_image(
    image: bytes, expected_committed: list[tuple[int, bytes]] | None = None
) -> list[dict]:
    if len(image) % SECTOR_SIZE != 0:
        fail("image length is not sector aligned")
    if len(image) < STORE_END_SECTOR * SECTOR_SIZE:
        fail("image is smaller than the fixed object-store region")
    records = []
    for physical in range(STORE_FIRST_SECTOR, STORE_END_SECTOR):
        start = physical * SECTOR_SIZE
        decoded = decode_sector(image[start : start + SECTOR_SIZE], physical)
        if decoded is not None:
            records.append(decoded)
    if not records:
        fail("no sealed object-store records")

    previous_sequence = 0
    previous_crc = 0
    store_id = records[0]["store_id"]
    for index, record in enumerate(records):
        if record["store_id"] != store_id:
            fail("store id changed inside the chain")
        if record["sequence"] != previous_sequence + 1:
            fail("record sequence is not consecutive")
        if record["previous_sequence"] != previous_sequence or record["previous_crc"] != previous_crc:
            fail("record CRC chain is broken")
        if index == 0 and record["kind"] != 1:
            fail("format is not the first valid record")
        previous_sequence = record["sequence"]
        previous_crc = record["crc"]

    high_water = 0
    transactions: dict[int, dict] = {}
    id_classes: dict[int, str] = {}
    seen_derivations: set[int] = set()
    seen_objects: set[int] = set()
    tombstoned_derivations: set[int] = set()
    committed: list[tuple[int, bytes]] = []

    def reserved(value: int) -> bool:
        return value != 0 and value < high_water

    def claim(value: int, id_class: str) -> None:
        previous = id_classes.get(value)
        if previous is not None and previous != id_class:
            fail(f"stable id {value} changed class from {previous} to {id_class}")
        id_classes[value] = id_class

    for record in records:
        raw = record["bytes"]
        kind = record["kind"]
        tx = record["transaction"]
        if kind == 1:
            if record is not records[0] or tx != 0:
                fail("duplicate or transactional format")
        elif kind == 2:
            value = u128(raw, PAYLOAD_OFFSET)
            if tx != 0 or value <= high_water:
                fail("invalid high-water record")
            high_water = value
        elif kind == 3:
            derivation = u128(raw, PAYLOAD_OFFSET)
            parent = u128(raw, PAYLOAD_OFFSET + 16)
            object_id = u128(raw, PAYLOAD_OFFSET + 32)
            space = u128(raw, PAYLOAD_OFFSET + 48)
            rights = u32(raw, PAYLOAD_OFFSET + 68)
            resource_kind = u32(raw, PAYLOAD_OFFSET + 80)
            flags = u32(raw, PAYLOAD_OFFSET + 84)
            ids = (tx, derivation, object_id, space)
            if not all(reserved(value) for value in ids) or (parent and not reserved(parent)):
                fail("grant prepare uses an unreserved id")
            if rights & ~0x3F or resource_kind == 0 or flags & ~1:
                fail("grant prepare has non-canonical rights/kind/flags")
            claim(tx, "transaction")
            claim(derivation, "derivation")
            if parent:
                claim(parent, "derivation")
            claim(object_id, "object")
            claim(space, "space")
            if tx in transactions or derivation in seen_derivations or derivation in tombstoned_derivations:
                fail("duplicate authority transaction or derivation")
            seen_derivations.add(derivation)
            transactions[tx] = {
                "type": "grant",
                "derivation": derivation,
                "prepare_sequence": record["sequence"],
                "prepare_crc": record["crc"],
            }
        elif kind == 4:
            prepare_sequence = u64(raw, PAYLOAD_OFFSET)
            derivation = u128(raw, PAYLOAD_OFFSET + 16)
            if tx == 0 or not reserved(tx) or not reserved(derivation):
                fail("grant commit uses an unreserved id")
            if prepare_sequence == 0:
                fail("grant commit has zero prepare sequence")
            if u32(raw, PAYLOAD_OFFSET + 12) != 0:
                fail("grant commit has non-zero reserved bits")
            claim(tx, "transaction")
            claim(derivation, "derivation")
            state = transactions.get(tx)
            if state is None:
                if derivation in seen_derivations:
                    fail("orphan grant commit reuses a derivation")
                seen_derivations.add(derivation)
                transactions[tx] = {"type": "finished"}
            elif (
                state.get("type") != "grant"
                or state["derivation"] != derivation
                or state["prepare_sequence"] != prepare_sequence
                or state["prepare_crc"] != u32(raw, PAYLOAD_OFFSET + 8)
            ):
                fail("grant commit does not bind its prepare")
            else:
                transactions[tx] = {"type": "finished"}
        elif kind == 5:
            derivation = u128(raw, PAYLOAD_OFFSET)
            if tx == 0 or not reserved(tx) or not reserved(derivation):
                fail("tombstone uses an unreserved id")
            claim(tx, "transaction")
            claim(derivation, "derivation")
            if tx in transactions:
                fail("tombstone reuses a transaction")
            transactions[tx] = {"type": "finished"}
            tombstoned_derivations.add(derivation)
        elif kind == 6:
            object_id = u128(raw, PAYLOAD_OFFSET)
            if tx == 0 or object_id == 0 or tx >= high_water or object_id >= high_water:
                fail("prepare uses an unreserved id")
            object_kind = u32(raw, PAYLOAD_OFFSET + 16)
            length = u64(raw, PAYLOAD_OFFSET + 24)
            chunk_count = u32(raw, PAYLOAD_OFFSET + 32)
            expected_chunks = (length + 359) // 360
            if (
                u32(raw, PAYLOAD_OFFSET + 20) != 0
                or object_kind == 0
                or length > 360 * 1024
                or chunk_count != expected_chunks
            ):
                fail("invalid object prepare metadata")
            claim(tx, "transaction")
            claim(object_id, "object")
            if tx in transactions or object_id in seen_objects:
                fail("duplicate object transaction or object")
            seen_objects.add(object_id)
            transactions[tx] = {
                "type": "object",
                "object_id": object_id,
                "kind": object_kind,
                "length": length,
                "chunk_count": chunk_count,
                "content_crc": u32(raw, PAYLOAD_OFFSET + 36),
                "prepare_sequence": record["sequence"],
                "prepare_crc": record["crc"],
                "chunks": [],
                "chunk_crcs": [],
                "first_chunk_sequence": 0,
            }
        elif kind == 7:
            state = transactions.get(tx)
            object_id = u128(raw, PAYLOAD_OFFSET)
            index = u32(raw, PAYLOAD_OFFSET + 16)
            length = u16(raw, PAYLOAD_OFFSET + 20)
            if (
                state is None
                or state.get("type") != "object"
                or object_id != state["object_id"]
                or index != len(state["chunks"])
            ):
                fail("chunk is not exactly bound to its prepare")
            claim(tx, "transaction")
            claim(object_id, "object")
            expected_length = min(360, state["length"] - index * 360)
            if (
                u16(raw, PAYLOAD_OFFSET + 22) != 0
                or length == 0
                or length > 360
                or length != expected_length
            ):
                fail("invalid chunk length/reserved field")
            data = raw[PAYLOAD_OFFSET + 24 : PAYLOAD_OFFSET + 24 + length]
            if any(raw[PAYLOAD_OFFSET + 24 + length : CRC_OFFSET]):
                fail("non-canonical chunk tail")
            if not state["chunks"]:
                state["first_chunk_sequence"] = record["sequence"]
            state["chunks"].append(data)
            state["chunk_crcs"].append(record["crc"])
        elif kind == 8:
            state = transactions.get(tx)
            object_id = u128(raw, PAYLOAD_OFFSET)
            if state is None or state.get("type") != "object" or object_id != state["object_id"]:
                fail("orphan object commit")
            claim(tx, "transaction")
            claim(object_id, "object")
            chunk_count = u32(raw, PAYLOAD_OFFSET + 28)
            first_chunk = u64(raw, PAYLOAD_OFFSET + 32)
            digest_input = b"".join(struct.pack("<I", value) for value in state["chunk_crcs"])
            content = b"".join(state["chunks"])
            expected_first = state["first_chunk_sequence"] if chunk_count else 0
            if (
                u64(raw, PAYLOAD_OFFSET + 16) != state["prepare_sequence"]
                or u32(raw, PAYLOAD_OFFSET + 24) != state["prepare_crc"]
                or chunk_count != state["chunk_count"]
                or chunk_count != len(state["chunks"])
                or first_chunk != expected_first
                or u32(raw, PAYLOAD_OFFSET + 40) != crc32c(digest_input)
                or u32(raw, PAYLOAD_OFFSET + 44) != state["content_crc"]
                or len(content) != state["length"]
                or crc32c(content) != state["content_crc"]
            ):
                fail("commit binding/content verification failed")
            committed.append((state["kind"], content))
            transactions[tx] = {"type": "finished"}

    if expected_committed is None:
        expected_committed = [(EXPECTED_OBJECT_KIND, expected_payload())]
        if committed != expected_committed:
            fail(f"expected one exact 900-byte committed object, found {len(committed)}")
    elif committed != expected_committed:
        fail(f"committed object set mismatch: expected {len(expected_committed)}, found {len(committed)}")
    return records


def verify(path: Path) -> None:
    records = verify_image(
        path.read_bytes(),
        [
            (PREFILL_OBJECT_KIND, expected_prefill_payload()),
            (EXPECTED_OBJECT_KIND, expected_payload()),
        ],
    )
    if len(records) != STORE_END_SECTOR - STORE_FIRST_SECTOR:
        fail(f"expected a full 512-record journal, found {len(records)} valid records")

    tail = records[-6:]
    if [record["kind"] for record in tail] != [2, 6, 7, 7, 7, 8]:
        fail("final six records are not the exact acceptance transaction")
    if [record["sequence"] for record in tail] != list(range(507, 513)):
        fail("acceptance transaction does not occupy sequences 507 through 512")
    if u128(tail[0]["bytes"], PAYLOAD_OFFSET) != 102 or tail[0]["transaction"] != 0:
        fail("acceptance high-water mark is not the exact exclusive value 102")
    if any(record["transaction"] != 100 for record in tail[1:]):
        fail("acceptance object transaction does not use fresh transaction id 100")

    prepare = tail[1]["bytes"]
    if (
        u128(prepare, PAYLOAD_OFFSET) != 101
        or u32(prepare, PAYLOAD_OFFSET + 16) != EXPECTED_OBJECT_KIND
        or u64(prepare, PAYLOAD_OFFSET + 24) != len(expected_payload())
        or u32(prepare, PAYLOAD_OFFSET + 32) != 3
    ):
        fail("acceptance prepare does not bind fresh object id 101 and the exact payload")
    for index, record in enumerate(tail[2:5]):
        raw = record["bytes"]
        if u128(raw, PAYLOAD_OFFSET) != 101 or u32(raw, PAYLOAD_OFFSET + 16) != index:
            fail("acceptance chunks do not bind object id 101 in exact order")
    commit = tail[5]["bytes"]
    if (
        u128(commit, PAYLOAD_OFFSET) != 101
        or u64(commit, PAYLOAD_OFFSET + 16) != 508
        or u32(commit, PAYLOAD_OFFSET + 28) != 3
        or u64(commit, PAYLOAD_OFFSET + 32) != 509
    ):
        fail("acceptance commit does not bind the exact prepare and first chunk")
    print("ok   store backing (full 512-record chain and both objects verified)")


def encode_fixture_record(
    kind: int,
    payload: bytes,
    sequence: int,
    previous_sequence: int,
    previous_crc: int,
    transaction: int = 0,
    fixture_store_id: int = STORE_ID,
) -> bytes:
    record = bytearray(SECTOR_SIZE)
    record[:8] = MAGIC
    struct.pack_into("<HHHHQQI", record, 0x08, 1, kind, 80, len(payload), sequence, previous_sequence, previous_crc)
    record[0x28:0x38] = fixture_store_id.to_bytes(16, "little")
    record[0x38:0x48] = transaction.to_bytes(16, "little")
    record[PAYLOAD_OFFSET : PAYLOAD_OFFSET + len(payload)] = payload
    checksum = crc32c(record[:CRC_OFFSET])
    struct.pack_into("<IIQ", record, CRC_OFFSET, checksum, ~checksum & 0xFFFF_FFFF, sequence)
    record[CRC_OFFSET + 16 : CRC_OFFSET + 32] = transaction.to_bytes(16, "little")
    record[SEAL_OFFSET:] = SEAL
    return bytes(record)


def fixture_image(
    specs: list[tuple[int, bytes, int]], fixture_store_id: int = STORE_ID
) -> bytes:
    image = bytearray(STORE_END_SECTOR * SECTOR_SIZE)
    previous_sequence = 0
    previous_crc = 0
    for index, (kind, payload, transaction) in enumerate(specs, start=1):
        record = encode_fixture_record(
            kind,
            payload,
            index,
            previous_sequence,
            previous_crc,
            transaction,
            fixture_store_id,
        )
        start = (STORE_FIRST_SECTOR + index - 1) * SECTOR_SIZE
        image[start : start + SECTOR_SIZE] = record
        previous_sequence = index
        previous_crc = u32(record, CRC_OFFSET)
    return bytes(image)


def dense_prefill_image() -> bytes:
    payload = expected_prefill_payload()
    prepare = bytearray(40)
    prepare[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<I", prepare, 16, PREFILL_OBJECT_KIND)
    struct.pack_into(
        "<QII", prepare, 24, len(payload), PREFILL_CHUNKS, crc32c(payload)
    )
    specs: list[tuple[int, bytes, int]] = [
        (1, b"", 0),
        (2, (100).to_bytes(16, "little"), 0),
        (6, bytes(prepare), 10),
    ]
    for index, chunk_data in enumerate(
        payload[offset : offset + 360]
        for offset in range(0, len(payload), 360)
    ):
        chunk = bytearray(384)
        chunk[0:16] = (11).to_bytes(16, "little")
        struct.pack_into("<IH", chunk, 16, index, len(chunk_data))
        chunk[24 : 24 + len(chunk_data)] = chunk_data
        specs.append((7, bytes(chunk), 10))

    prefix = fixture_image(specs)

    def record_crc(spec_index: int) -> int:
        start = (STORE_FIRST_SECTOR + spec_index) * SECTOR_SIZE
        return u32(prefix[start : start + SECTOR_SIZE], CRC_OFFSET)

    chunk_crcs = [record_crc(index) for index in range(3, 3 + PREFILL_CHUNKS)]
    commit = bytearray(48)
    commit[0:16] = (11).to_bytes(16, "little")
    struct.pack_into(
        "<QIIQII",
        commit,
        16,
        3,
        record_crc(2),
        PREFILL_CHUNKS,
        4,
        crc32c(b"".join(struct.pack("<I", value) for value in chunk_crcs)),
        crc32c(payload),
    )
    specs.append((8, bytes(commit), 10))
    image = fixture_image(specs)
    if len(specs) != 506:
        fail(f"dense prefill record count drifted to {len(specs)}")
    # Validate the exact seed before handing it to QEMU. Use the explicit
    # expectation so this path does not depend on the final 900-byte append.
    verify_image(image, [(PREFILL_OBJECT_KIND, payload)])
    return image


def seed(path: Path) -> None:
    if path.stat().st_size < STORE_END_SECTOR * SECTOR_SIZE:
        fail("seed target is smaller than the fixed object-store region")
    image = dense_prefill_image()
    start = STORE_FIRST_SECTOR * SECTOR_SIZE
    end = STORE_END_SECTOR * SECTOR_SIZE
    with path.open("r+b") as disk:
        disk.seek(start)
        disk.write(image[start:end])


def expect_fixture_failure(
    name: str,
    specs: list[tuple[int, bytes, int]],
    fragment: str,
    fixture_store_id: int = STORE_ID,
) -> None:
    try:
        verify_image(fixture_image(specs, fixture_store_id))
    except ValueError as error:
        if fragment not in str(error):
            fail(f"negative fixture {name} failed for the wrong reason: {error}")
        return
    fail(f"negative fixture {name} was accepted")


def self_test() -> None:
    format_record = (1, b"", 0)
    high_water = (2, (100).to_bytes(16, "little"), 0)

    expect_fixture_failure(
        "store-trust-anchor",
        [format_record],
        "wrong platform store id",
        STORE_ID + 1,
    )

    collision_prepare = bytearray(40)
    collision_prepare[0:16] = (10).to_bytes(16, "little")
    struct.pack_into("<I", collision_prepare, 16, 1)
    expect_fixture_failure(
        "cross-class-id",
        [format_record, high_water, (6, bytes(collision_prepare), 10)],
        "changed class",
    )

    zero_prepare_commit = bytearray(32)
    zero_prepare_commit[16:32] = (11).to_bytes(16, "little")
    expect_fixture_failure(
        "grant-commit-zero-prepare-sequence",
        [format_record, high_water, (4, bytes(zero_prepare_commit), 10)],
        "zero prepare sequence",
    )

    reserved_prepare = bytearray(40)
    reserved_prepare[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<II", reserved_prepare, 16, 1, 1)
    expect_fixture_failure(
        "prepare-reserved",
        [format_record, high_water, (6, bytes(reserved_prepare), 10)],
        "invalid object prepare metadata",
    )

    one_byte_prepare = bytearray(40)
    one_byte_prepare[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<I", one_byte_prepare, 16, 1)
    struct.pack_into("<QII", one_byte_prepare, 24, 1, 1, crc32c(b"x"))
    zero_chunk = bytearray(384)
    zero_chunk[0:16] = (11).to_bytes(16, "little")
    expect_fixture_failure(
        "zero-chunk",
        [
            format_record,
            high_water,
            (6, bytes(one_byte_prepare), 10),
            (7, bytes(zero_chunk), 10),
        ],
        "invalid chunk length",
    )

    empty_prepare = bytearray(40)
    empty_prepare[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<I", empty_prepare, 16, 1)
    prefix = fixture_image([format_record, high_water, (6, bytes(empty_prepare), 10)])
    prepare_sector = prefix[(STORE_FIRST_SECTOR + 2) * SECTOR_SIZE : (STORE_FIRST_SECTOR + 3) * SECTOR_SIZE]
    empty_commit = bytearray(48)
    empty_commit[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<QI", empty_commit, 16, 3, u32(prepare_sector, CRC_OFFSET))
    extra_chunk = bytearray(384)
    extra_chunk[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<IH", extra_chunk, 16, 0, 1)
    extra_chunk[24] = ord("x")
    expect_fixture_failure(
        "chunk-after-commit",
        [
            format_record,
            high_water,
            (6, bytes(empty_prepare), 10),
            (8, bytes(empty_commit), 10),
            (7, bytes(extra_chunk), 10),
        ],
        "chunk is not exactly bound",
    )

    payload = expected_payload()
    wrong_kind_prepare = bytearray(40)
    wrong_kind_prepare[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<I", wrong_kind_prepare, 16, EXPECTED_OBJECT_KIND + 1)
    struct.pack_into("<QII", wrong_kind_prepare, 24, len(payload), 3, crc32c(payload))
    wrong_kind_specs = [format_record, high_water, (6, bytes(wrong_kind_prepare), 10)]
    for index, chunk_data in enumerate(
        (payload[0:360], payload[360:720], payload[720:900])
    ):
        chunk = bytearray(384)
        chunk[0:16] = (11).to_bytes(16, "little")
        struct.pack_into("<IH", chunk, 16, index, len(chunk_data))
        chunk[24 : 24 + len(chunk_data)] = chunk_data
        wrong_kind_specs.append((7, bytes(chunk), 10))
    prefix = fixture_image(wrong_kind_specs)
    record_crcs = [
        u32(
            prefix[
                (STORE_FIRST_SECTOR + index) * SECTOR_SIZE :
                (STORE_FIRST_SECTOR + index + 1) * SECTOR_SIZE
            ],
            CRC_OFFSET,
        )
        for index in range(2, 6)
    ]
    wrong_kind_commit = bytearray(48)
    wrong_kind_commit[0:16] = (11).to_bytes(16, "little")
    struct.pack_into("<QIIQII", wrong_kind_commit, 16, 3, record_crcs[0], 3, 4, crc32c(b"".join(struct.pack("<I", value) for value in record_crcs[1:])), crc32c(payload))
    wrong_kind_specs.append((8, bytes(wrong_kind_commit), 10))
    expect_fixture_failure(
        "object-kind",
        wrong_kind_specs,
        "expected one exact 900-byte committed object",
    )

    interleaved_prepare = bytearray(wrong_kind_prepare)
    struct.pack_into("<I", interleaved_prepare, 16, EXPECTED_OBJECT_KIND)
    tombstone = (13).to_bytes(16, "little")
    interleaved_specs = [
        format_record,
        high_water,
        (6, bytes(interleaved_prepare), 10),
        (5, tombstone, 12),
        *wrong_kind_specs[3:6],
    ]
    prefix = fixture_image(interleaved_specs)

    def fixture_crc(spec_index: int) -> int:
        start = (STORE_FIRST_SECTOR + spec_index) * SECTOR_SIZE
        return u32(prefix[start : start + SECTOR_SIZE], CRC_OFFSET)

    interleaved_commit = bytearray(48)
    interleaved_commit[0:16] = (11).to_bytes(16, "little")
    chunk_crcs = [fixture_crc(index) for index in range(4, 7)]
    struct.pack_into(
        "<QIIQII",
        interleaved_commit,
        16,
        3,
        fixture_crc(2),
        3,
        5,
        crc32c(b"".join(struct.pack("<I", value) for value in chunk_crcs)),
        crc32c(payload),
    )
    interleaved_specs.append((8, bytes(interleaved_commit), 10))
    verify_image(fixture_image(interleaved_specs))
    print("ok   store verifier negative parity fixtures")


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        try:
            self_test()
        except ValueError as error:
            print(f"FAIL store verifier selftest: {error}", file=sys.stderr)
            return 1
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--seed":
        try:
            seed(Path(sys.argv[2]))
        except (OSError, ValueError) as error:
            print(f"FAIL store prefill: {error}", file=sys.stderr)
            return 1
        return 0
    if len(sys.argv) != 2:
        print(
            f"usage: {Path(sys.argv[0]).name} [--seed] DISK.raw",
            file=sys.stderr,
        )
        return 2
    try:
        verify(Path(sys.argv[1]))
    except (OSError, ValueError) as error:
        print(f"FAIL store backing: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
