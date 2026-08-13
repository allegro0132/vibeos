#!/usr/bin/env python3
"""Rust-independent verifier for the frozen Storage V2 M7.5 GC and media ABI.

The verifier duplicates the canonical ``VIBEALC2`` allocation-v2,
``VIBERST2`` persistent-root, ``VIBEREF1`` typed-reference, ``VIBECAS2``,
``VIBEBMF2``, and canonical Blob layouts.  It imports only frozen physical
record/segment/checkpoint helpers from ``storage-v2-image.py`` and never uses
that script's legacy store-payload reconstruction.  The G/G+1/G+2 cleaner
sequence is a protocol over immutable checkpoints; this file deliberately
defines no additional on-media GC evidence format.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import mmap
import struct
from pathlib import Path
from typing import Any, Callable, Optional


def load_storage_v2_parser() -> Any:
    path = Path(__file__).with_name("storage-v2-image.py")
    spec = importlib.util.spec_from_file_location("vibeos_storage_v2_image_gc", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


storage = load_storage_v2_parser()
Violation = storage.FormatViolation

PAGE_SIZE = 4096
MAX_METADATA_PAYLOAD_LEN = 256 * PAGE_SIZE
POINTER_SIZE = 0x60
U64_MAX = (1 << 64) - 1

ALLOCATION_MAGIC = b"VIBEALC2"
ALLOCATION_VERSION = 2
ALLOCATION_HEADER_LEN = 0x80
RETIRED_ENTRY_LEN = 0x10
SEGMENT_STATE_BITS = 2
MAX_ALLOCATION_SEGMENTS = (MAX_METADATA_PAYLOAD_LEN - ALLOCATION_HEADER_LEN) * 4

SEGMENT_FREE = 0
SEGMENT_ALLOCATED = 1
SEGMENT_RETIRED = 2
SEGMENT_STATE_NAMES = {
    SEGMENT_FREE: "free",
    SEGMENT_ALLOCATED: "allocated",
    SEGMENT_RETIRED: "retired",
}

ROOT_MAGIC = b"VIBERST2"
ROOT_VERSION = 1
ROOT_HEADER_LEN = 0x40
ROOT_ENTRY_LEN = 0x20
MAX_ROOT_ENTRIES = (MAX_METADATA_PAYLOAD_LEN - ROOT_HEADER_LEN) // ROOT_ENTRY_LEN

TYPED_REFS_MAGIC = b"VIBEREF1"
TYPED_REFS_VERSION = 1
TYPED_REFS_HEADER_LEN = 0x60
TYPED_REFS_ENTRY_LEN = 0x28
TYPED_REFS_ADMISSION_TAG = b"vibe.refs-v1\0\0\0\0"
MAX_TYPED_REFS = (MAX_METADATA_PAYLOAD_LEN - TYPED_REFS_HEADER_LEN) // TYPED_REFS_ENTRY_LEN
GC_CHILD_BUDGET = 4096
MAX_TYPED_REFERENCE_KINDS = 64

OBJECT_MAPPING_LEN = 0x60
BLOB_KEY_LEN = 0x40
BLOB_MAPPING_LEN = 0xA0
BLOB_MANIFEST_HEADER_LEN = 0x80
MANIFEST_EXTENT_LEN = 0x80
CAS_SNAPSHOT_HEADER_LEN = 0x80
MAX_BLOB_CONTENT_LEN = 64 * 1024 * 1024
MAX_BLOB_EXTENTS = 66
CANONICAL_CONTENT_EXTENT_LEN = MAX_METADATA_PAYLOAD_LEN
HASH_ALGORITHM_SHA256 = 1
REFERENCE_CODEC_RAW = 0
REFERENCE_CODEC_TYPED_V1 = 1
BLOB_MAGIC = b"VIBEBLB\0"
BLOB_HEADER_LEN = 0x80
BLOB_VERSION = 1
BLOB_LEAF_LOG2 = 12
BLOB_LEAF_SIZE = 4096
LEAF_DOMAIN = b"VIBEBLOB-LEAF-v1\0"
EMPTY_DOMAIN = b"VIBEBLOB-EMPTY-v1\0"
NODE_DOMAIN = b"VIBEBLOB-NODE-v1\0"
ROOT_DOMAIN = b"VIBEBLOB-ROOT-v1\0"

CAS_MAGIC = b"VIBECAS2"
CAS_CODEC_VERSION = 1
CAS_GC_CODEC_VERSION = 2
CAS_KIND_SNAPSHOT = 1
BLOB_MANIFEST_MAGIC = b"VIBEBMF2"

EXTENT_BLOB = 1
EXTENT_CATALOG = 2
EXTENT_AUTHORITY = 3
EXTENT_ALLOCATION = 4


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Violation(message)


def zero(data: bytes | memoryview) -> bool:
    return not any(data)


def require_zero(data: bytes | memoryview, start: int, end: int, label: str) -> None:
    require(zero(data[start:end]), f"{label} must be zero")


def u16(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def u128(data: bytes | memoryview, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 16], "little")


def put_u16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def put_u64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


def canonical_blob_geometry(exact_len: int) -> dict[str, int]:
    require(0 <= exact_len <= MAX_BLOB_CONTENT_LEN, "BlobKey content length is out of range")
    leaf_count = 1 if exact_len == 0 else (exact_len + BLOB_LEAF_SIZE - 1) // BLOB_LEAF_SIZE
    padded_leaves = 1 << (leaf_count - 1).bit_length()
    node_count = padded_leaves * 2 - 1
    tree_len = node_count * 32
    tree_offset = BLOB_HEADER_LEN + exact_len
    return {
        "leaf_count": leaf_count,
        "padded_leaves": padded_leaves,
        "node_count": node_count,
        "height": padded_leaves.bit_length() - 1,
        "tree_len": tree_len,
        "tree_offset": tree_offset,
        "encoded_len": tree_offset + tree_len,
    }


def parse_blob_key(raw: bytes | memoryview, label: str = "BlobKey") -> dict[str, Any]:
    require(len(raw) == BLOB_KEY_LEN, f"{label} has a non-canonical length")
    key = {
        "hash_algorithm": u16(raw, 0x00),
        "object_kind": u32(raw, 0x04),
        "exact_len": u64(raw, 0x08),
        "merkle_root": bytes(raw[0x10:0x30]),
        "encoded": bytes(raw),
    }
    require(key["hash_algorithm"] == HASH_ALGORITHM_SHA256, f"{label} hash algorithm is invalid")
    require(u16(raw, 0x02) == 0, f"{label} reserved word must be zero")
    require(key["object_kind"] != 0, f"{label} object kind is zero")
    canonical_blob_geometry(key["exact_len"])
    require_zero(raw, 0x30, 0x40, f"{label} reserved bytes")
    return key


def blob_key_identity(key: dict[str, Any]) -> tuple[int, int, int, bytes]:
    return (
        key["hash_algorithm"],
        key["object_kind"],
        key["exact_len"],
        key["merkle_root"],
    )


def canonical_blob_root(object_kind: int, payload: bytes) -> bytes:
    require(object_kind != 0, "canonical Blob ObjectKind is zero")
    require(len(payload) <= MAX_BLOB_CONTENT_LEN, "canonical Blob payload is too large")
    leaf_count = 1 if not payload else (len(payload) + BLOB_LEAF_SIZE - 1) // BLOB_LEAF_SIZE
    padded_leaves = 1 << (leaf_count - 1).bit_length()
    tree: list[bytes] = []
    for index in range(padded_leaves):
        if index < leaf_count:
            chunk = payload[index * BLOB_LEAF_SIZE : (index + 1) * BLOB_LEAF_SIZE]
            tree.append(
                hashlib.sha256(
                    LEAF_DOMAIN
                    + struct.pack("<I", object_kind)
                    + struct.pack("<I", index)
                    + struct.pack("<I", len(chunk))
                    + chunk
                ).digest()
            )
        else:
            tree.append(
                hashlib.sha256(
                    EMPTY_DOMAIN + struct.pack("<I", object_kind) + struct.pack("<I", index)
                ).digest()
            )
    base = 0
    width = padded_leaves
    level = 1
    while width > 1:
        for offset in range(0, width, 2):
            tree.append(
                hashlib.sha256(
                    NODE_DOMAIN
                    + struct.pack("<I", level)
                    + tree[base + offset]
                    + tree[base + offset + 1]
                ).digest()
            )
        base += width
        width //= 2
        level += 1
    return hashlib.sha256(
        ROOT_DOMAIN
        + struct.pack("<I", object_kind)
        + struct.pack("<Q", len(payload))
        + struct.pack("<I", BLOB_LEAF_SIZE)
        + struct.pack("<I", leaf_count)
        + tree[-1]
    ).digest()


def parse_allocation_v2(payload: bytes) -> dict[str, Any]:
    require(
        ALLOCATION_HEADER_LEN <= len(payload) <= MAX_METADATA_PAYLOAD_LEN,
        "allocation-v2 payload length is out of bounds",
    )
    require(payload[0x00:0x08] == ALLOCATION_MAGIC, "allocation-v2 magic is invalid")
    require(u16(payload, 0x08) == ALLOCATION_VERSION, "allocation-v2 version is invalid")
    require(u16(payload, 0x0A) == ALLOCATION_HEADER_LEN, "allocation-v2 header length is invalid")
    require(u32(payload, 0x0C) == 0, "allocation-v2 flags must be zero")
    require(u16(payload, 0x2C) == SEGMENT_STATE_BITS, "allocation-v2 state width is invalid")
    require(u16(payload, 0x2E) == RETIRED_ENTRY_LEN, "allocation-v2 retired entry size is invalid")
    require(u64(payload, 0x30) == ALLOCATION_HEADER_LEN, "allocation-v2 bitmap offset is invalid")
    require_zero(payload, 0x70, 0x80, "allocation-v2 reserved bytes")

    checkpoint_generation = u64(payload, 0x10)
    admitted_segments = u64(payload, 0x18)
    next_segment_generation = u64(payload, 0x20)
    cleaner_reserve_segments = u32(payload, 0x28)
    require(checkpoint_generation > 0, "allocation-v2 checkpoint generation is zero")
    require(0 < admitted_segments <= MAX_ALLOCATION_SEGMENTS, "allocation-v2 admitted count is invalid")
    require(next_segment_generation > 0, "allocation-v2 next segment generation is zero")
    require(
        0 < cleaner_reserve_segments < admitted_segments,
        "allocation-v2 cleaner reserve is invalid",
    )

    bitmap_len = (admitted_segments + 3) // 4
    declared_bitmap_len = u64(payload, 0x38)
    retirement_offset = ALLOCATION_HEADER_LEN + bitmap_len
    retired_count = u64(payload, 0x48)
    encoded_len = retirement_offset + retired_count * RETIRED_ENTRY_LEN
    require(declared_bitmap_len == bitmap_len, "allocation-v2 bitmap length is non-canonical")
    require(u64(payload, 0x40) == retirement_offset, "allocation-v2 retirement offset is invalid")
    require(u64(payload, 0x68) == encoded_len, "allocation-v2 encoded length field is invalid")
    require(encoded_len <= MAX_METADATA_PAYLOAD_LEN, "allocation-v2 retirement table exceeds one extent")
    require(len(payload) == encoded_len, "allocation-v2 payload has a prefix or suffix")

    bitmap = payload[ALLOCATION_HEADER_LEN:retirement_offset]
    remainder = admitted_segments % 4
    if remainder:
        unused_mask = (~((1 << (remainder * 2)) - 1)) & 0xFF
        require(bitmap[-1] & unused_mask == 0, "allocation-v2 tail bits must be zero")

    states: list[int] = []
    counts = [0, 0, 0]
    for index in range(admitted_segments):
        state = (bitmap[index // 4] >> ((index % 4) * 2)) & 0x03
        require(state in SEGMENT_STATE_NAMES, f"allocation-v2 segment {index} has invalid state 3")
        states.append(state)
        counts[state] += 1
    require(sum(counts) == admitted_segments, "allocation-v2 state counts do not cover the map")
    require(
        counts[SEGMENT_FREE] + counts[SEGMENT_RETIRED] >= cleaner_reserve_segments,
        "allocation-v2 cleaner reserve is exhausted",
    )
    require(u64(payload, 0x50) == counts[SEGMENT_FREE], "allocation-v2 free count mismatch")
    require(u64(payload, 0x58) == counts[SEGMENT_ALLOCATED], "allocation-v2 allocated count mismatch")
    require(u64(payload, 0x60) == counts[SEGMENT_RETIRED], "allocation-v2 retired count mismatch")
    require(retired_count == counts[SEGMENT_RETIRED], "allocation-v2 retirement table count mismatch")

    retired: list[dict[str, int]] = []
    previous_segment: Optional[int] = None
    for index in range(retired_count):
        offset = retirement_offset + index * RETIRED_ENTRY_LEN
        segment_no = u64(payload, offset)
        retire_generation = u64(payload, offset + 8)
        require(
            previous_segment is None or previous_segment < segment_no,
            "allocation-v2 retirement table is not strictly ordered",
        )
        require(segment_no < admitted_segments, "allocation-v2 retired segment is out of range")
        require(states[segment_no] == SEGMENT_RETIRED, "allocation-v2 retirement entry is not retired")
        require(
            0 < retire_generation <= checkpoint_generation,
            "allocation-v2 retirement generation is invalid",
        )
        retired.append({"segment_no": segment_no, "retire_generation": retire_generation})
        previous_segment = segment_no

    return {
        "checkpoint_generation": checkpoint_generation,
        "admitted_segments": admitted_segments,
        "next_segment_generation": next_segment_generation,
        "cleaner_reserve_segments": cleaner_reserve_segments,
        "bitmap": bitmap,
        "states": states,
        "retired": retired,
        "counts": {
            "free": counts[SEGMENT_FREE],
            "allocated": counts[SEGMENT_ALLOCATED],
            "retired": counts[SEGMENT_RETIRED],
        },
    }


def parse_persistent_root_set(payload: bytes) -> dict[str, Any]:
    require(
        ROOT_HEADER_LEN <= len(payload) <= MAX_METADATA_PAYLOAD_LEN,
        "persistent root-set payload length is out of bounds",
    )
    require(payload[0x00:0x08] == ROOT_MAGIC, "persistent root-set magic is invalid")
    require(u16(payload, 0x08) == ROOT_VERSION, "persistent root-set version is invalid")
    require(u16(payload, 0x0A) == ROOT_HEADER_LEN, "persistent root-set header length is invalid")
    require(u32(payload, 0x0C) == 0, "persistent root-set flags must be zero")
    checkpoint_generation = u64(payload, 0x10)
    entry_count = u32(payload, 0x18)
    require(checkpoint_generation > 0, "persistent root-set checkpoint generation is zero")
    require(u32(payload, 0x1C) == ROOT_ENTRY_LEN, "persistent root-set entry size is invalid")
    require(u64(payload, 0x20) == ROOT_HEADER_LEN, "persistent root-set table offset is invalid")
    require_zero(payload, 0x30, 0x40, "persistent root-set reserved bytes")
    encoded_len = ROOT_HEADER_LEN + entry_count * ROOT_ENTRY_LEN
    require(entry_count <= MAX_ROOT_ENTRIES, "persistent root-set entry count is out of bounds")
    require(u64(payload, 0x28) == encoded_len, "persistent root-set encoded length field is invalid")
    require(len(payload) == encoded_len, "persistent root-set payload has a prefix or suffix")

    entries: list[dict[str, int]] = []
    previous_id: Optional[int] = None
    for index in range(entry_count):
        offset = ROOT_HEADER_LEN + index * ROOT_ENTRY_LEN
        object_id = u128(payload, offset)
        commit_generation = u64(payload, offset + 0x10)
        object_kind = u32(payload, offset + 0x18)
        require(u32(payload, offset + 0x1C) == 0, "persistent root-set entry flags must be zero")
        require(object_id != 0, "persistent root-set object ID is zero")
        require(
            0 < commit_generation <= checkpoint_generation,
            "persistent root-set commit generation is invalid",
        )
        require(object_kind != 0, "persistent root-set object kind is zero")
        require(
            previous_id is None or previous_id < object_id,
            "persistent root-set ObjectIds are not strictly ordered",
        )
        entries.append(
            {
                "object_id": object_id,
                "commit_generation": commit_generation,
                "object_kind": object_kind,
            }
        )
        previous_id = object_id
    return {"checkpoint_generation": checkpoint_generation, "entries": entries}


def parse_typed_refs_v1(payload: bytes) -> dict[str, Any]:
    require(
        TYPED_REFS_HEADER_LEN <= len(payload) <= MAX_METADATA_PAYLOAD_LEN,
        "refs-v1 payload length is out of bounds",
    )
    require(payload[0x00:0x08] == TYPED_REFS_MAGIC, "refs-v1 magic is invalid")
    require(u16(payload, 0x08) == TYPED_REFS_VERSION, "refs-v1 version is invalid")
    require(u16(payload, 0x0A) == TYPED_REFS_HEADER_LEN, "refs-v1 header length is invalid")
    require(u32(payload, 0x0C) == 0, "refs-v1 header flags must be zero")
    require(payload[0x10:0x20] == TYPED_REFS_ADMISSION_TAG, "refs-v1 admission tag is unknown")
    manifest_object_kind = u32(payload, 0x20)
    manifest_commit_generation = u64(payload, 0x28)
    reference_count = u32(payload, 0x30)
    require(manifest_object_kind != 0, "refs-v1 manifest object kind is zero")
    require(manifest_commit_generation > 0, "refs-v1 manifest commit generation is zero")
    require(u32(payload, 0x24) == 0, "refs-v1 header reserved word must be zero")
    require(u32(payload, 0x34) == TYPED_REFS_ENTRY_LEN, "refs-v1 entry size is invalid")
    require(u64(payload, 0x38) == TYPED_REFS_HEADER_LEN, "refs-v1 table offset is invalid")
    require_zero(payload, 0x48, 0x60, "refs-v1 header reserved bytes")
    encoded_len = TYPED_REFS_HEADER_LEN + reference_count * TYPED_REFS_ENTRY_LEN
    require(reference_count <= MAX_TYPED_REFS, "refs-v1 reference count is out of bounds")
    require(u64(payload, 0x40) == encoded_len, "refs-v1 encoded length field is invalid")
    require(len(payload) == encoded_len, "refs-v1 payload has a prefix or suffix")

    references: list[dict[str, int]] = []
    previous_id: Optional[int] = None
    for index in range(reference_count):
        offset = TYPED_REFS_HEADER_LEN + index * TYPED_REFS_ENTRY_LEN
        object_id = u128(payload, offset)
        commit_generation = u64(payload, offset + 0x10)
        object_kind = u32(payload, offset + 0x18)
        require(u32(payload, offset + 0x1C) == 0, "refs-v1 entry flags must be zero")
        require_zero(payload, offset + 0x20, offset + 0x28, "refs-v1 entry reserved bytes")
        require(object_id != 0, "refs-v1 child ObjectId is zero")
        require(
            0 < commit_generation <= manifest_commit_generation,
            "refs-v1 child commit generation is invalid",
        )
        require(object_kind != 0, "refs-v1 child object kind is zero")
        require(
            previous_id is None or previous_id < object_id,
            "refs-v1 child ObjectIds are not strictly ordered",
        )
        references.append(
            {
                "object_id": object_id,
                "commit_generation": commit_generation,
                "object_kind": object_kind,
            }
        )
        previous_id = object_id
    return {
        "manifest_object_kind": manifest_object_kind,
        "manifest_commit_generation": manifest_commit_generation,
        "references": references,
    }


def parse_object_mapping_v2(
    raw: bytes,
    checkpoint_generation: int,
    codec_version: int = CAS_GC_CODEC_VERSION,
) -> dict[str, Any]:
    """Parse the v2 ObjectMapping fields which select raw versus refs-v1."""

    require(len(raw) == OBJECT_MAPPING_LEN, "CAS v2 ObjectMapping has a non-canonical length")
    object_id = u128(raw, 0x00)
    blob_key = parse_blob_key(raw[0x10:0x50], "CAS v2 ObjectMapping BlobKey")
    object_kind = blob_key["object_kind"]
    exact_len = blob_key["exact_len"]
    content_sha256 = blob_key["merkle_root"]
    commit_generation = u64(raw, 0x50)
    if codec_version == CAS_CODEC_VERSION:
        require_zero(raw, 0x58, 0x60, "CAS v1 ObjectMapping reserved bytes")
        reference_codec = REFERENCE_CODEC_RAW
    else:
        require(codec_version == CAS_GC_CODEC_VERSION, "CAS ObjectMapping codec version is unknown")
        reference_codec = u16(raw, 0x58)
    require(object_id != 0, "CAS v2 ObjectMapping object ID is zero")
    require(
        0 < commit_generation <= checkpoint_generation,
        "CAS v2 ObjectMapping commit generation is invalid",
    )
    require(
        reference_codec in (REFERENCE_CODEC_RAW, REFERENCE_CODEC_TYPED_V1),
        "CAS v2 ObjectMapping reference codec is unknown",
    )
    if codec_version == CAS_GC_CODEC_VERSION:
        require_zero(raw, 0x5A, 0x60, "CAS v2 ObjectMapping reserved bytes")
    return {
        "object_id": object_id,
        "blob_key": blob_key,
        "object_kind": object_kind,
        "exact_len": exact_len,
        "content_sha256": content_sha256,
        "commit_generation": commit_generation,
        "reference_codec": reference_codec,
    }


def parse_context_pointer(
    raw: bytes | memoryview,
    context: dict[str, Any],
    expected_kind: int,
    label: str,
) -> dict[str, Any]:
    pointer = storage.parse_pointer(bytes(raw))
    require(pointer["status"] == "value", f"{label} is Null")
    require(pointer["store_uuid"] == context["store_uuid"], f"{label} UUID mismatch")
    require(pointer["segment_no"] < context["admitted_segments"], f"{label} is outside admitted segments")
    require(
        pointer["segment_generation"] < context["next_segment_generation"],
        f"{label} has an uncommitted segment generation",
    )
    require(pointer["extent_kind"] == expected_kind, f"{label} has the wrong extent kind")
    return pointer


def parse_blob_mapping_v2(
    raw: bytes | memoryview,
    context: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    require(len(raw) == BLOB_MAPPING_LEN, f"{label} has a non-canonical length")
    key = parse_blob_key(raw[0x00:0x40], f"{label} BlobKey")
    manifest = parse_context_pointer(raw[0x40:0xA0], context, EXTENT_CATALOG, f"{label} manifest")
    manifest_len = manifest["exact_byte_len"]
    require(
        BLOB_MANIFEST_HEADER_LEN < manifest_len <= MAX_METADATA_PAYLOAD_LEN
        and (manifest_len - BLOB_MANIFEST_HEADER_LEN) % MANIFEST_EXTENT_LEN == 0,
        f"{label} manifest pointer length is invalid",
    )
    count = (manifest_len - BLOB_MANIFEST_HEADER_LEN) // MANIFEST_EXTENT_LEN
    require(0 < count <= MAX_BLOB_EXTENTS, f"{label} manifest extent count is invalid")
    return {"blob_key": key, "manifest": manifest}


def parse_cas_snapshot_v2(payload: bytes, context: dict[str, Any]) -> dict[str, Any]:
    require(
        CAS_SNAPSHOT_HEADER_LEN <= len(payload) <= MAX_METADATA_PAYLOAD_LEN,
        "CAS snapshot length is invalid",
    )
    require(payload[0:8] == CAS_MAGIC, "CAS snapshot magic is invalid")
    codec_version = u16(payload, 0x08)
    require(
        codec_version in (CAS_CODEC_VERSION, CAS_GC_CODEC_VERSION),
        "CAS snapshot version is invalid",
    )
    require(u16(payload, 0x0A) == CAS_KIND_SNAPSHOT, "CAS snapshot kind is invalid")
    require(u32(payload, 0x0C) == CAS_SNAPSHOT_HEADER_LEN, "CAS snapshot header length is invalid")
    generation = u64(payload, 0x10)
    require(generation > 0, "CAS snapshot generation is zero")
    object_count = u32(payload, 0x18)
    blob_count = u32(payload, 0x1C)
    require(u32(payload, 0x20) == OBJECT_MAPPING_LEN, "CAS snapshot object entry size is invalid")
    require(u32(payload, 0x24) == BLOB_MAPPING_LEN, "CAS snapshot Blob entry size is invalid")
    object_offset = CAS_SNAPSHOT_HEADER_LEN
    blob_offset = object_offset + object_count * OBJECT_MAPPING_LEN
    encoded_len = blob_offset + blob_count * BLOB_MAPPING_LEN
    require(u64(payload, 0x28) == object_offset, "CAS snapshot object offset is invalid")
    require(u64(payload, 0x30) == blob_offset, "CAS snapshot Blob offset is invalid")
    require(u64(payload, 0x38) == encoded_len, "CAS snapshot encoded length field is invalid")
    require_zero(payload, 0x40, 0x80, "CAS snapshot reserved bytes")
    require(
        encoded_len <= MAX_METADATA_PAYLOAD_LEN and len(payload) == encoded_len,
        "CAS snapshot length is non-canonical",
    )
    objects = [
        parse_object_mapping_v2(
            payload[
                object_offset + index * OBJECT_MAPPING_LEN :
                object_offset + (index + 1) * OBJECT_MAPPING_LEN
            ],
            generation,
            codec_version,
        )
        for index in range(object_count)
    ]
    blobs = [
        parse_blob_mapping_v2(
            payload[
                blob_offset + index * BLOB_MAPPING_LEN :
                blob_offset + (index + 1) * BLOB_MAPPING_LEN
            ],
            context,
            f"CAS snapshot Blob[{index}]",
        )
        for index in range(blob_count)
    ]
    require(
        all(left["object_id"] < right["object_id"] for left, right in zip(objects, objects[1:])),
        "CAS snapshot object IDs are not strictly increasing",
    )
    require(
        all(
            blob_key_identity(left["blob_key"]) < blob_key_identity(right["blob_key"])
            for left, right in zip(blobs, blobs[1:])
        ),
        "CAS snapshot BlobKeys are not strictly increasing",
    )
    for left_index, left in enumerate(blobs):
        for right in blobs[left_index + 1 :]:
            require(
                not storage.ranges_overlap(left["manifest"], right["manifest"]),
                "CAS snapshot manifest pointers overlap",
            )
    available = {blob_key_identity(blob["blob_key"]) for blob in blobs}
    require(
        all(blob_key_identity(obj["blob_key"]) in available for obj in objects),
        "CAS snapshot object has no Blob mapping",
    )
    return {"checkpoint_generation": generation, "objects": objects, "blobs": blobs}


def parse_blob_manifest_v2(payload: bytes, context: dict[str, Any]) -> dict[str, Any]:
    require(
        BLOB_MANIFEST_HEADER_LEN <= len(payload) <= MAX_METADATA_PAYLOAD_LEN,
        "Blob manifest length is invalid",
    )
    require(payload[0:8] == BLOB_MANIFEST_MAGIC, "Blob manifest magic is invalid")
    require(u16(payload, 0x08) == CAS_CODEC_VERSION, "Blob manifest version is invalid")
    require(u16(payload, 0x0A) == BLOB_MANIFEST_HEADER_LEN, "Blob manifest header length is invalid")
    require(u16(payload, 0x0C) == MANIFEST_EXTENT_LEN, "Blob manifest entry size is invalid")
    require(u16(payload, 0x0E) == 0, "Blob manifest flags must be zero")
    key = parse_blob_key(payload[0x10:0x50], "Blob manifest BlobKey")
    encoded_blob_len = u64(payload, 0x50)
    count = u32(payload, 0x58)
    require(u32(payload, 0x5C) == 0, "Blob manifest reserved word must be zero")
    require(u64(payload, 0x60) == BLOB_MANIFEST_HEADER_LEN, "Blob manifest table offset is invalid")
    expected_len = BLOB_MANIFEST_HEADER_LEN + count * MANIFEST_EXTENT_LEN
    require(u64(payload, 0x68) == expected_len, "Blob manifest encoded length field is invalid")
    require_zero(payload, 0x70, 0x80, "Blob manifest reserved bytes")
    require(0 < count <= MAX_BLOB_EXTENTS and len(payload) == expected_len, "Blob manifest length is non-canonical")
    geometry = canonical_blob_geometry(key["exact_len"])
    require(encoded_blob_len == geometry["encoded_len"], "Blob manifest encoded length is not canonical")
    content_count = (key["exact_len"] + CANONICAL_CONTENT_EXTENT_LEN - 1) // CANONICAL_CONTENT_EXTENT_LEN
    require(count == content_count + 2, "Blob manifest extent count is not canonical")

    extents: list[dict[str, Any]] = []
    expected_offset = 0
    pointers: list[dict[str, Any]] = []
    for index in range(count):
        offset = BLOB_MANIFEST_HEADER_LEN + index * MANIFEST_EXTENT_LEN
        raw = payload[offset : offset + MANIFEST_EXTENT_LEN]
        require_zero(raw, 0x78, 0x80, f"Blob manifest extent[{index}] reserved bytes")
        pointer = parse_context_pointer(
            raw[0x18:0x78], context, EXTENT_BLOB, f"Blob manifest extent[{index}] pointer"
        )
        item = {
            "extent_index": u32(raw, 0x00),
            "extent_count": u32(raw, 0x04),
            "encoded_offset": u64(raw, 0x08),
            "payload_byte_len": u64(raw, 0x10),
            "pointer": pointer,
        }
        require(item["extent_index"] == index, f"Blob manifest extent[{index}] index is invalid")
        require(item["extent_count"] == count, f"Blob manifest extent[{index}] count is invalid")
        require(item["encoded_offset"] == expected_offset, f"Blob manifest extent[{index}] leaves a gap or overlap")
        require(
            item["payload_byte_len"] == _canonical_blob_extent_length(key, index, count),
            f"Blob manifest extent[{index}] split is not canonical",
        )
        require(pointer["exact_byte_len"] == item["payload_byte_len"], f"Blob manifest extent[{index}] pointer length mismatch")
        require(
            all(not storage.ranges_overlap(previous, pointer) for previous in pointers),
            "Blob manifest physical pointers overlap",
        )
        pointers.append(pointer)
        expected_offset += item["payload_byte_len"]
        extents.append(item)
    require(expected_offset == encoded_blob_len, "Blob manifest extents do not cover the canonical Blob")
    return {"blob_key": key, "encoded_blob_len": encoded_blob_len, "extents": extents}


def verify_canonical_blob(encoded: bytes, expected_key: dict[str, Any]) -> bytes:
    geometry = canonical_blob_geometry(expected_key["exact_len"])
    require(len(encoded) == geometry["encoded_len"], "canonical Blob byte length mismatch")
    header = encoded[:BLOB_HEADER_LEN]
    require(header[0:8] == BLOB_MAGIC, "canonical Blob magic is invalid")
    require(u16(header, 0x08) == BLOB_VERSION, "canonical Blob version is invalid")
    require(u16(header, 0x0A) == BLOB_HEADER_LEN, "canonical Blob header length is invalid")
    require(u16(header, 0x0C) == HASH_ALGORITHM_SHA256, "canonical Blob hash algorithm is invalid")
    require(header[0x0E] == BLOB_LEAF_LOG2 and header[0x0F] == 0, "canonical Blob leaf geometry or flags are invalid")
    require(u32(header, 0x10) == expected_key["object_kind"], "canonical Blob object kind differs from BlobKey")
    require_zero(header, 0x14, 0x18, "canonical Blob reserved word")
    require(u64(header, 0x18) == expected_key["exact_len"], "canonical Blob content length differs from BlobKey")
    require(u32(header, 0x20) == geometry["leaf_count"], "canonical Blob leaf count is invalid")
    require(u32(header, 0x24) == geometry["node_count"], "canonical Blob tree node count is invalid")
    declared_root = bytes(header[0x28:0x48])
    require(declared_root == expected_key["merkle_root"], "canonical Blob root differs from BlobKey")
    require(u64(header, 0x48) == BLOB_HEADER_LEN, "canonical Blob data offset is invalid")
    require(u64(header, 0x50) == geometry["tree_offset"], "canonical Blob tree offset is invalid")
    require(u64(header, 0x58) == geometry["encoded_len"], "canonical Blob encoded length is invalid")
    require_zero(header, 0x60, 0x80, "canonical Blob reserved bytes")

    content = encoded[BLOB_HEADER_LEN : geometry["tree_offset"]]
    tree: list[bytes] = []
    for index in range(geometry["padded_leaves"]):
        if index < geometry["leaf_count"]:
            chunk = content[index * BLOB_LEAF_SIZE : (index + 1) * BLOB_LEAF_SIZE]
            tree.append(
                hashlib.sha256(
                    LEAF_DOMAIN
                    + struct.pack("<I", expected_key["object_kind"])
                    + struct.pack("<I", index)
                    + struct.pack("<I", len(chunk))
                    + chunk
                ).digest()
            )
        else:
            tree.append(
                hashlib.sha256(
                    EMPTY_DOMAIN + struct.pack("<I", expected_key["object_kind"]) + struct.pack("<I", index)
                ).digest()
            )
    base = 0
    width = geometry["padded_leaves"]
    level = 1
    while width > 1:
        for offset in range(0, width, 2):
            tree.append(
                hashlib.sha256(
                    NODE_DOMAIN
                    + struct.pack("<I", level)
                    + tree[base + offset]
                    + tree[base + offset + 1]
                ).digest()
            )
        base += width
        width //= 2
        level += 1
    require(encoded[geometry["tree_offset"] :] == b"".join(tree), "canonical Blob Merkle tree bytes are invalid")
    require(canonical_blob_root(expected_key["object_kind"], content) == declared_root, "canonical Blob Merkle root is invalid")
    return content


def validate_raw_object_graph(
    objects: dict[int, dict[str, Any]],
    contents: dict[tuple[int, int, int, bytes], bytes],
    root_entries: list[dict[str, int]],
    typed_reference_kinds: list[int],
) -> dict[str, int]:
    """Validate persistent reachability without inventing durable runtime roots."""

    object_blob_keys = {blob_key_identity(mapping["blob_key"]) for mapping in objects.values()}
    require(
        object_blob_keys == set(contents),
        "CAS BlobMappings do not exactly equal all ObjectMapping BlobKeys",
    )

    # Trusted typed payloads are closed for every retained object, including
    # objects captured only by a runtime root which intentionally vanished on
    # power loss. Untagged and unregistered tagged objects remain opaque.
    children: dict[int, list[int]] = {}
    for object_id, mapping in objects.items():
        if (
            mapping["reference_codec"] != REFERENCE_CODEC_TYPED_V1
            or mapping["object_kind"] not in typed_reference_kinds
        ):
            children[object_id] = []
            continue
        content = contents[blob_key_identity(mapping["blob_key"])]
        refs = decode_admitted_typed_refs(mapping, content, mapping["object_kind"])
        child_ids = []
        for child in refs["references"]:
            child_mapping = objects.get(child["object_id"])
            require(child_mapping is not None, "typed reference points to a missing ObjectMapping")
            require(
                (child_mapping["commit_generation"], child_mapping["object_kind"])
                == (child["commit_generation"], child["object_kind"]),
                "typed child identity differs from ObjectMapping",
            )
            child_ids.append(child["object_id"])
        children[object_id] = child_ids

    work: list[int] = []
    for root in root_entries:
        mapping = objects.get(root["object_id"])
        require(mapping is not None, "persistent root references a missing ObjectMapping")
        require(
            (mapping["commit_generation"], mapping["object_kind"])
            == (root["commit_generation"], root["object_kind"]),
            "persistent root identity differs from ObjectMapping",
        )
        work.append(root["object_id"])
    reachable: set[int] = set()
    while work:
        object_id = work.pop()
        if object_id in reachable:
            continue
        reachable.add(object_id)
        work.extend(children[object_id])
    require(reachable.issubset(objects), "persistent root closure escapes the CAS Object table")
    return {
        "persistent_reachable_objects": len(reachable),
        "nonpersistent_objects": len(objects) - len(reachable),
    }


class RawImageResolver:
    def __init__(
        self,
        image: bytes | bytearray | mmap.mmap | memoryview,
        checkpoint: dict[str, Any],
        segments: list[dict[str, Any]],
        allocation: Optional[dict[str, Any]] = None,
    ) -> None:
        self.image = image
        self.checkpoint = checkpoint
        self.segments = segments
        self.allocation = allocation
        self.current_identities: set[tuple[int, int, int, int]] = set()

    def resolve(
        self,
        pointer: dict[str, Any],
        expected_kind: int,
        label: str,
        *,
        metadata: bool = False,
        current: bool = True,
    ) -> tuple[dict[str, Any], bytes]:
        require(pointer["status"] == "value", f"{label} is Null")
        errors: list[str] = []
        extent = storage.resolve_extent_pointer(
            self.checkpoint, label, pointer, self.segments, errors
        )
        require(not errors and extent is not None, errors[0] if errors else f"{label} cannot be resolved")
        require(extent["extent_kind"] == expected_kind, f"{label} resolves to the wrong extent kind")
        if metadata:
            storage.require_single_extent_payload(extent, label)
        if current:
            require(self.allocation is not None, f"{label} has no allocation-v2 context")
            require(
                self.allocation["states"][pointer["segment_no"]] == SEGMENT_ALLOCATED,
                f"{label} points into a non-Allocated segment",
            )
            self.current_identities.add(storage.pointer_identity(pointer))
        return extent, storage.read_exact_extent_payload(self.image, extent)


def parse_raw_structure(image: Any) -> dict[str, Any]:
    errors: list[str] = []
    page_count = len(image) // storage.PAGE_SIZE
    if len(image) % storage.PAGE_SIZE:
        errors.append("image length is not a multiple of 4096 bytes")
    if page_count < storage.ANCHOR_PAGES:
        errors.append("image is shorter than the 16-page anchor")
    superblocks = [
        storage.decode_pair(image, 0, 1, 1, "superblock copy A", errors, storage.super_validator(0, 0)),
        storage.decode_pair(image, 2, 3, 1, "superblock copy B", errors, storage.super_validator(1, 2)),
    ]
    checkpoints = [
        storage.decode_pair(image, 4, 5, 2, "checkpoint slot A", errors, storage.checkpoint_validator(0, 4)),
        storage.decode_pair(image, 6, 7, 2, "checkpoint slot B", errors, storage.checkpoint_validator(1, 6)),
    ]
    for page_no in range(8, min(storage.ANCHOR_PAGES, page_count)):
        page = storage.page_at(image, page_no)
        if page is not None and not storage.all_zero(page):
            errors.append(f"anchor reserved page {page_no} is non-zero")
    selected_superblock = storage.select_superblock(superblocks, errors)
    selected_checkpoint = storage.select_checkpoint(checkpoints, errors)
    physical_segments = max(0, (page_count - storage.ANCHOR_PAGES) // storage.SEGMENT_PAGES)
    trailing = max(0, page_count - storage.ANCHOR_PAGES) % storage.SEGMENT_PAGES
    if page_count >= storage.ANCHOR_PAGES and trailing:
        errors.append("image has a partial data segment")
    segment_errors: list[list[str]] = []
    segments = []
    for number in range(physical_segments):
        local_errors: list[str] = []
        segments.append(storage.parse_segment(image, number, local_errors))
        segment_errors.append(local_errors)
    if selected_superblock is None:
        errors.append("image has no selected sealed superblock")
    if selected_checkpoint is None:
        errors.append("image has no selected sealed checkpoint")
    elif selected_superblock is not None:
        # Only the selected checkpoint authorizes current bytes. Older sealed
        # checkpoints and unreachable extents may name Retired/Free bytes after
        # G+2 and are diagnostics, not a reason to reject a current image.
        storage.verify_checkpoint_against_superblock(
            selected_checkpoint, selected_superblock, physical_segments, segments, errors
        )
    return {
        "errors": errors,
        "checkpoint": selected_checkpoint,
        "segments": segments,
        "segment_errors": segment_errors,
        "physical_segments": physical_segments,
    }


def reconstruct_raw_gc(
    image: Any,
    checkpoint: dict[str, Any],
    segments: list[dict[str, Any]],
    typed_reference_kinds: list[int],
) -> dict[str, Any]:
    cp = checkpoint["record"]
    generation = cp["binding"]["generation"]
    require(cp["cleaner_reserve_segments"] >= 2, "selected GC image has fewer than two reserved segments")
    require(cp["replay_count"] == 0 and cp["replay_tail"]["status"] == "null", "selected GC image is not a compact CAS snapshot")
    require(cp["allocation_root"]["status"] == "value", "selected GC image has no allocation-v2 root")
    require(cp["catalog_root"]["status"] == "value", "selected GC image has no VIBECAS2 root")
    require(cp["authority_root"]["status"] == "value", "selected GC image has a Null authority root")

    resolver = RawImageResolver(image, checkpoint, segments)
    allocation_extent, allocation_payload = resolver.resolve(
        cp["allocation_root"], EXTENT_ALLOCATION, "allocation_root", metadata=True, current=False
    )
    allocation = parse_allocation_v2(allocation_payload)
    require(allocation["checkpoint_generation"] == generation, "allocation-v2 generation differs from checkpoint")
    require(allocation["admitted_segments"] == cp["admitted_segments"], "allocation-v2 admitted segments differ from checkpoint")
    require(allocation["next_segment_generation"] == cp["next_segment_generation"], "allocation-v2 next segment generation differs from checkpoint")
    require(allocation["cleaner_reserve_segments"] == cp["cleaner_reserve_segments"], "allocation-v2 cleaner reserve differs from checkpoint")
    require(
        allocation_extent["binding"]["target_checkpoint_generation"] == generation,
        "allocation-v2 extent does not target the selected checkpoint",
    )
    resolver.allocation = allocation
    require(
        allocation["states"][cp["allocation_root"]["segment_no"]] == SEGMENT_ALLOCATED,
        "allocation_root points into a non-Allocated segment",
    )
    resolver.current_identities.add(storage.pointer_identity(cp["allocation_root"]))

    authority_extent, authority_payload = resolver.resolve(
        cp["authority_root"], EXTENT_AUTHORITY, "authority_root", metadata=True
    )
    roots = parse_persistent_root_set(authority_payload)
    require(roots["checkpoint_generation"] <= generation, "persistent root-set is newer than checkpoint")
    require(
        roots["checkpoint_generation"] == authority_extent["binding"]["target_checkpoint_generation"],
        "persistent root-set generation differs from extent target",
    )

    catalog_extent, catalog_payload = resolver.resolve(
        cp["catalog_root"], EXTENT_CATALOG, "catalog_root", metadata=True
    )
    context = {
        "store_uuid": cp["binding"]["store_uuid"],
        "admitted_segments": cp["admitted_segments"],
        "next_segment_generation": cp["next_segment_generation"],
    }
    snapshot = parse_cas_snapshot_v2(catalog_payload, context)
    require(snapshot["checkpoint_generation"] <= generation, "CAS snapshot is newer than checkpoint")
    require(
        snapshot["checkpoint_generation"] == catalog_extent["binding"]["target_checkpoint_generation"],
        "CAS snapshot generation differs from extent target",
    )

    physical_pointers = [cp["allocation_root"], cp["authority_root"], cp["catalog_root"]]
    contents: dict[tuple[int, int, int, bytes], bytes] = {}
    for blob in snapshot["blobs"]:
        key_id = blob_key_identity(blob["blob_key"])
        manifest_pointer = blob["manifest"]
        require(
            all(not storage.ranges_overlap(previous, manifest_pointer) for previous in physical_pointers),
            "current physical pointers overlap",
        )
        physical_pointers.append(manifest_pointer)
        manifest_extent, manifest_payload = resolver.resolve(
            manifest_pointer, EXTENT_CATALOG, "Blob manifest", metadata=True
        )
        require(
            manifest_pointer["payload_sha256"] == hashlib.sha256(manifest_payload).digest(),
            "Blob manifest pointer SHA-256 mismatch",
        )
        require(
            manifest_extent["binding"]["target_checkpoint_generation"] <= generation,
            "Blob manifest targets a newer checkpoint",
        )
        manifest = parse_blob_manifest_v2(manifest_payload, context)
        require(blob_key_identity(manifest["blob_key"]) == key_id, "Blob mapping and manifest keys disagree")
        encoded = bytearray()
        for item in manifest["extents"]:
            pointer = item["pointer"]
            require(
                all(not storage.ranges_overlap(previous, pointer) for previous in physical_pointers),
                "current physical pointers overlap",
            )
            physical_pointers.append(pointer)
            extent, payload = resolver.resolve(pointer, EXTENT_BLOB, "canonical Blob extent")
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
            require(actual_shape == expected_shape, "canonical Blob extent descriptor binding mismatch")
            require(hashlib.sha256(payload).digest() == pointer["payload_sha256"], "canonical Blob extent payload SHA-256 mismatch")
            encoded.extend(payload)
        require(len(encoded) == manifest["encoded_blob_len"], "reconstructed canonical Blob length mismatch")
        contents[key_id] = verify_canonical_blob(bytes(encoded), blob["blob_key"])

    objects = {item["object_id"]: item for item in snapshot["objects"]}
    graph = validate_raw_object_graph(
        objects, contents, roots["entries"], typed_reference_kinds
    )
    return {
        "checkpoint_generation": generation,
        "segments": allocation["counts"],
        "persistent_roots": len(roots["entries"]),
        "objects": len(objects),
        "blobs": len(contents),
        **graph,
        "current_pointers": len(resolver.current_identities),
        "typed_reference_kinds": typed_reference_kinds,
    }


def verify_raw_image(image: Any, typed_reference_kinds: list[int]) -> dict[str, Any]:
    structural = parse_raw_structure(image)
    errors = list(structural["errors"])
    gc: Optional[dict[str, Any]] = None
    checkpoint = structural["checkpoint"]
    if checkpoint is not None and not errors:
        try:
            gc = reconstruct_raw_gc(
                image, checkpoint, structural["segments"], typed_reference_kinds
            )
        except Violation as exc:
            errors.append(f"GC: {exc}")
    return {
        "format": "vibeos-storage-v2-gc-raw",
        "version": 1,
        "status": "ok" if not errors else "corrupt",
        "image": {
            "byte_length": len(image),
            "physical_segment_count": structural["physical_segments"],
        },
        "gc": gc,
        "errors": sorted(set(errors)),
    }


def decode_admitted_typed_refs(
    mapping: dict[str, Any],
    payload: bytes,
    admitted_object_kind: int,
) -> dict[str, Any]:
    require(mapping["reference_codec"] == REFERENCE_CODEC_TYPED_V1, "object is not tagged refs-v1")
    require(admitted_object_kind != 0, "refs-v1 admission object kind is zero")
    require(
        mapping["object_kind"] == admitted_object_kind,
        "ObjectKind is not admitted for refs-v1",
    )
    require(mapping["exact_len"] == len(payload), "refs-v1 length does not match its BlobKey")
    require(
        mapping["content_sha256"] == canonical_blob_root(mapping["object_kind"], payload),
        "refs-v1 canonical Merkle root does not match its BlobKey",
    )
    refs = parse_typed_refs_v1(payload)
    require(
        len(refs["references"]) <= GC_CHILD_BUDGET,
        "refs-v1 exceeds the fixed GC child window",
    )
    require(
        refs["manifest_object_kind"] == mapping["object_kind"],
        "refs-v1 manifest ObjectKind does not match its ObjectMapping",
    )
    require(
        refs["manifest_commit_generation"] == mapping["commit_generation"],
        "refs-v1 manifest generation does not match its ObjectMapping",
    )
    return refs


def validate_current_pointer(
    raw: bytes,
    allocation: dict[str, Any],
    store_uuid: bytes,
    label: str,
    expected_kind: Optional[int] = None,
) -> dict[str, Any]:
    pointer = storage.parse_pointer(raw)
    require(pointer["status"] == "value", f"{label} is Null")
    require(pointer["store_uuid"] == store_uuid, f"{label} UUID mismatch")
    require(pointer["segment_no"] < allocation["admitted_segments"], f"{label} is outside admitted segments")
    require(
        pointer["segment_generation"] < allocation["next_segment_generation"],
        f"{label} has an uncommitted segment generation",
    )
    if expected_kind is not None:
        require(pointer["extent_kind"] == expected_kind, f"{label} has the wrong extent kind")
    state = allocation["states"][pointer["segment_no"]]
    require(state == SEGMENT_ALLOCATED, f"{label} points into a {SEGMENT_STATE_NAMES[state]} segment")
    return pointer


def admit_gc(
    authority_root_raw: bytes,
    root_payload: bytes,
    allocation: dict[str, Any],
    store_uuid: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    require(len(authority_root_raw) == POINTER_SIZE, "authority root pointer has the wrong size")
    parsed = storage.parse_pointer(authority_root_raw)
    require(parsed["status"] == "value", "Null authority root disables GC")
    pointer = validate_current_pointer(
        authority_root_raw,
        allocation,
        store_uuid,
        "authority root",
        EXTENT_AUTHORITY,
    )
    roots = parse_persistent_root_set(root_payload)
    require(
        roots["checkpoint_generation"] <= allocation["checkpoint_generation"],
        "persistent root-set generation is newer than allocation-v2",
    )
    require(pointer["exact_byte_len"] == len(root_payload), "authority root pointer length mismatch")
    require(
        pointer["payload_sha256"] == hashlib.sha256(root_payload).digest(),
        "authority root pointer SHA-256 mismatch",
    )
    return pointer, roots


def _canonical_segments(values: list[int], label: str, admitted_segments: int) -> None:
    require(all(isinstance(value, int) and not isinstance(value, bool) for value in values), f"{label} must contain integers")
    require(all(0 <= value < admitted_segments for value in values), f"{label} contains an out-of-range segment")
    require(all(left < right for left, right in zip(values, values[1:])), f"{label} is not strictly ordered")


def validate_allocation_transition(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allocate: list[int],
    retire: list[int],
    reclaim: list[int],
) -> None:
    require(after["checkpoint_generation"] > before["checkpoint_generation"], "allocation transition is not newer")
    require(after["admitted_segments"] == before["admitted_segments"], "allocation transition changes admitted segments")
    require(
        after["cleaner_reserve_segments"] == before["cleaner_reserve_segments"],
        "allocation transition changes cleaner reserve",
    )
    require(
        after["next_segment_generation"] >= before["next_segment_generation"],
        "allocation transition regresses next segment generation",
    )
    require(
        not allocate or after["next_segment_generation"] > before["next_segment_generation"],
        "allocation transition allocates without advancing segment generation",
    )
    admitted = before["admitted_segments"]
    for values, label in ((allocate, "allocate"), (retire, "retire"), (reclaim, "reclaim")):
        _canonical_segments(values, label, admitted)
    require(not (set(allocate) & set(retire)), "allocate and retire lists intersect")
    require(not (set(allocate) & set(reclaim)), "allocate and reclaim lists intersect")
    require(not (set(retire) & set(reclaim)), "retire and reclaim lists intersect")

    expected_states = list(before["states"])
    for values, old_state, new_state, label in (
        (allocate, SEGMENT_FREE, SEGMENT_ALLOCATED, "allocate"),
        (retire, SEGMENT_ALLOCATED, SEGMENT_RETIRED, "retire"),
        (reclaim, SEGMENT_RETIRED, SEGMENT_FREE, "reclaim"),
    ):
        for segment_no in values:
            require(expected_states[segment_no] == old_state, f"{label} segment has the wrong prior state")
            expected_states[segment_no] = new_state
    require(after["states"] == expected_states, "allocation transition contains an undeclared state change")

    reclaimed = set(reclaim)
    expected_retired = [
        (entry["segment_no"], entry["retire_generation"])
        for entry in before["retired"]
        if entry["segment_no"] not in reclaimed
    ]
    expected_retired.extend((segment_no, after["checkpoint_generation"]) for segment_no in retire)
    expected_retired.sort()
    actual_retired = [
        (entry["segment_no"], entry["retire_generation"])
        for entry in after["retired"]
    ]
    require(actual_retired == expected_retired, "allocation transition retirement generations mismatch")


def verify_zeroed_checkpoint_seal(readback: bytes) -> None:
    require(len(readback) == PAGE_SIZE, "old checkpoint seal readback is not exactly one page")
    require(zero(readback), "old checkpoint seal readback is not exact zero")


def validate_partial_blob_extent_transition(
    allocation_g: dict[str, Any],
    allocation_g1: dict[str, Any],
    selected_sources: list[int],
    relocation_targets: list[int],
    live_blob_keys: list[bytes],
    g_extents: list[dict[str, Any]],
    g1_extents: list[dict[str, Any]],
) -> None:
    """Bind the complete live Blob extent table across a partial relocation."""

    require(
        len(g_extents) == len(g1_extents),
        "partial Blob extent table length differs across G and G+1",
    )
    require(
        {item["blob_key_raw"] for item in g_extents} == set(live_blob_keys)
        and {item["blob_key_raw"] for item in g1_extents} == set(live_blob_keys),
        "partial Blob extent table does not exactly cover live_blob_keys",
    )
    selected = set(selected_sources)
    targets = set(relocation_targets)
    for before, after in zip(g_extents, g1_extents):
        identity_fields = (
            "blob_key_raw",
            "encoded_blob_len",
            "extent_index",
            "extent_count",
            "encoded_offset",
            "payload_byte_len",
        )
        require(
            all(before[field] == after[field] for field in identity_fields),
            "partial Blob extent identity differs across G and G+1",
        )
        before_pointer = before["pointer"]
        after_pointer = after["pointer"]
        before_segment = before_pointer["segment_no"]
        after_segment = after_pointer["segment_no"]
        require(
            allocation_g["states"][before_segment] == SEGMENT_ALLOCATED,
            "G Blob extent pointer is not in an Allocated segment",
        )
        require(
            allocation_g1["states"][after_segment] == SEGMENT_ALLOCATED,
            "G+1 Blob extent pointer is not in an Allocated segment",
        )
        if before_segment in selected:
            require(
                before_pointer != after_pointer,
                "selected-source Blob extent pointer was not relocated",
            )
            require(
                after_segment in targets,
                "selected-source Blob extent did not move into a declared G+1 target",
            )
        else:
            require(
                before_pointer == after_pointer,
                "unselected-source Blob extent pointer was unexpectedly rewritten",
            )


def validate_three_state_barrier(
    allocation_g: dict[str, Any],
    allocation_g1: Optional[dict[str, Any]] = None,
    allocation_g2: Optional[dict[str, Any]] = None,
    *,
    g1_allocate: Optional[list[int]] = None,
    g1_retire: Optional[list[int]] = None,
    g2_allocate: Optional[list[int]] = None,
    g2_reclaim: Optional[list[int]] = None,
    old_checkpoint_seal_readback: Optional[bytes] = None,
    pinned_generations: Optional[list[int]] = None,
    live_blob_keys: Optional[list[bytes]] = None,
    g_blob_extent_pointers: Optional[list[dict[str, Any]]] = None,
    g1_blob_extent_pointers: Optional[list[dict[str, Any]]] = None,
) -> str:
    """Validate the recoverable G, G+1, or G+2 state of one cleaner cycle."""

    generation = allocation_g["checkpoint_generation"]
    require(generation <= U64_MAX - 2, "cleaner generation arithmetic overflows u64")
    if allocation_g1 is None:
        require(
            all(
                value is None
                for value in (
                    allocation_g2,
                    old_checkpoint_seal_readback,
                    live_blob_keys,
                    g_blob_extent_pointers,
                    g1_blob_extent_pointers,
                )
            ),
            "base state has later evidence",
        )
        return "G"

    require(
        allocation_g["cleaner_reserve_segments"] >= 2,
        "G+1 cleaner trajectory has fewer than two reserved segments",
    )
    g1_allocate = [] if g1_allocate is None else g1_allocate
    g1_retire = [] if g1_retire is None else g1_retire
    allocated_sources = [
        segment_no
        for segment_no, state in enumerate(allocation_g["states"])
        if state == SEGMENT_ALLOCATED
    ]
    require(g1_allocate, "G+1 relocation allocates no target segments")
    _canonical_segments(g1_retire, "G+1 selected sources", allocation_g["admitted_segments"])
    require(g1_retire, "G+1 selects no Allocated source segments")
    require(
        set(g1_retire).issubset(allocated_sources),
        "G+1 selected source set contains a non-Allocated G segment",
    )
    require(
        allocation_g1["checkpoint_generation"] == generation + 1,
        "relocation checkpoint is not exactly G+1",
    )
    require(
        allocation_g1["next_segment_generation"]
        == allocation_g["next_segment_generation"] + len(g1_allocate),
        "G+1 segment-generation allocation count mismatch",
    )
    validate_allocation_transition(
        allocation_g,
        allocation_g1,
        allocate=g1_allocate,
        retire=g1_retire,
        reclaim=[],
    )
    for segment_no in g1_retire:
        require(
            allocation_g1["states"][segment_no] == SEGMENT_RETIRED,
            "G+1 source segment is not retired",
        )
    unselected_sources = sorted(set(allocated_sources) - set(g1_retire))
    for segment_no in unselected_sources:
        require(
            allocation_g1["states"][segment_no] == SEGMENT_ALLOCATED,
            "G+1 changes an unselected source from Allocated",
        )
    if unselected_sources:
        require(
            live_blob_keys is not None
            and g_blob_extent_pointers is not None
            and g1_blob_extent_pointers is not None,
            "partial relocation lacks complete G/G+1 Blob extent evidence",
        )
        validate_partial_blob_extent_transition(
            allocation_g,
            allocation_g1,
            g1_retire,
            g1_allocate,
            live_blob_keys,
            g_blob_extent_pointers,
            g1_blob_extent_pointers,
        )

    if allocation_g2 is None:
        if old_checkpoint_seal_readback is not None:
            verify_zeroed_checkpoint_seal(old_checkpoint_seal_readback)
            pins = [] if pinned_generations is None else pinned_generations
            require(
                all(
                    isinstance(pin, int)
                    and not isinstance(pin, bool)
                    and pin > generation
                    for pin in pins
                ),
                "cleared G+1 state has a reader pinned through G",
            )
        return "G+1"

    require(old_checkpoint_seal_readback is not None, "G+2 lacks old-checkpoint seal readback")
    verify_zeroed_checkpoint_seal(old_checkpoint_seal_readback)
    pins = [] if pinned_generations is None else pinned_generations
    require(
        all(isinstance(pin, int) and not isinstance(pin, bool) and pin > generation for pin in pins),
        "G+2 has a reader pinned through G",
    )
    g2_allocate = [] if g2_allocate is None else g2_allocate
    g2_reclaim = [] if g2_reclaim is None else g2_reclaim
    require(len(g2_allocate) == 1, "G+2 must allocate exactly one barrier metadata segment")
    require(g2_reclaim == g1_retire, "G+2 does not reclaim exactly this cycle's retired sources")
    require(
        allocation_g2["checkpoint_generation"] == generation + 2,
        "reuse checkpoint is not exactly G+2",
    )
    require(
        allocation_g2["next_segment_generation"]
        == allocation_g1["next_segment_generation"] + 1,
        "G+2 barrier segment-generation allocation count mismatch",
    )
    validate_allocation_transition(
        allocation_g1,
        allocation_g2,
        allocate=g2_allocate,
        retire=[],
        reclaim=g2_reclaim,
    )
    return "G+2"


def _read_relative(directory: Path, name: Any, label: str) -> bytes:
    require(isinstance(name, str) and name != "", f"{label} file name is invalid")
    path = Path(name)
    require(not path.is_absolute() and ".." not in path.parts, f"{label} escapes the fixture directory")
    return (directory / path).read_bytes()


def _hex_bytes(value: Any, exact_len: int, label: str) -> bytes:
    require(isinstance(value, str), f"{label} must be hexadecimal text")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise Violation(f"{label} is not valid hexadecimal") from exc
    require(len(decoded) == exact_len, f"{label} has the wrong length")
    return decoded


def _int_list(value: Any, label: str) -> list[int]:
    require(isinstance(value, list), f"{label} must be an array")
    require(all(isinstance(item, int) and not isinstance(item, bool) for item in value), f"{label} must contain integers")
    return list(value)


def _json_u64(value: Any, label: str, *, nonzero: bool = False) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(0 <= value <= U64_MAX, f"{label} is outside u64")
    if nonzero:
        require(value > 0, f"{label} is zero")
    return value


def _barrier_live_blob_keys(value: Any) -> list[bytes]:
    require(isinstance(value, list), "live_blob_keys must be an array")
    raw_keys = [
        _hex_bytes(item, BLOB_KEY_LEN, f"live_blob_keys[{index}]")
        for index, item in enumerate(value)
    ]
    parsed = [parse_blob_key(raw, f"live_blob_keys[{index}]") for index, raw in enumerate(raw_keys)]
    require(
        all(blob_key_identity(left) < blob_key_identity(right) for left, right in zip(parsed, parsed[1:])),
        "live_blob_keys are not strictly ordered",
    )
    return raw_keys


def _canonical_blob_extent_length(key: dict[str, Any], index: int, count: int) -> int:
    content_count = (key["exact_len"] + CANONICAL_CONTENT_EXTENT_LEN - 1) // CANONICAL_CONTENT_EXTENT_LEN
    require(count == content_count + 2, "Blob extent count is not canonical")
    if index == 0:
        return BLOB_HEADER_LEN
    if index <= content_count:
        return min(
            CANONICAL_CONTENT_EXTENT_LEN,
            key["exact_len"] - (index - 1) * CANONICAL_CONTENT_EXTENT_LEN,
        )
    require(index == count - 1, "Blob extent index is outside its canonical table")
    return canonical_blob_geometry(key["exact_len"])["tree_len"]


def _barrier_blob_extent_list(
    value: Any,
    label: str,
    allocation: dict[str, Any],
    store_uuid: bytes,
) -> list[dict[str, Any]]:
    require(isinstance(value, list), f"{label} must be an array")
    output: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        require(isinstance(item, dict), f"{label}[{index}] must be an object")
        require(
            set(item) == {
                "blob_key",
                "encoded_blob_len",
                "extent_index",
                "extent_count",
                "encoded_offset",
                "payload_byte_len",
                "pointer",
            },
            f"{label}[{index}] fields do not match the frozen partial-GC ABI",
        )
        key_raw = _hex_bytes(item["blob_key"], BLOB_KEY_LEN, f"{label}[{index}] BlobKey")
        key = parse_blob_key(key_raw, f"{label}[{index}] BlobKey")
        encoded_blob_len = _json_u64(item["encoded_blob_len"], f"{label}[{index}] encoded_blob_len", nonzero=True)
        extent_index = _json_u64(item["extent_index"], f"{label}[{index}] extent_index")
        extent_count = _json_u64(item["extent_count"], f"{label}[{index}] extent_count", nonzero=True)
        encoded_offset = _json_u64(item["encoded_offset"], f"{label}[{index}] encoded_offset")
        payload_byte_len = _json_u64(item["payload_byte_len"], f"{label}[{index}] payload_byte_len", nonzero=True)
        require(extent_count <= MAX_BLOB_EXTENTS, f"{label}[{index}] extent_count is too large")
        require(extent_index < extent_count, f"{label}[{index}] extent_index is out of range")
        require(
            encoded_blob_len == canonical_blob_geometry(key["exact_len"])["encoded_len"],
            f"{label}[{index}] encoded_blob_len is not canonical",
        )
        require(
            payload_byte_len == _canonical_blob_extent_length(key, extent_index, extent_count),
            f"{label}[{index}] payload_byte_len is not canonical",
        )
        pointer = validate_current_pointer(
            _hex_bytes(item["pointer"], POINTER_SIZE, f"{label}[{index}] pointer"),
            allocation,
            store_uuid,
            f"{label}[{index}]",
            EXTENT_BLOB,
        )
        require(pointer["exact_byte_len"] == payload_byte_len, f"{label}[{index}] pointer length mismatch")
        output.append(
            {
                "blob_key": key,
                "blob_key_raw": key_raw,
                "encoded_blob_len": encoded_blob_len,
                "extent_index": extent_index,
                "extent_count": extent_count,
                "encoded_offset": encoded_offset,
                "payload_byte_len": payload_byte_len,
                "pointer": pointer,
            }
        )
    require(
        all(
            (blob_key_identity(left["blob_key"]), left["extent_index"])
            < (blob_key_identity(right["blob_key"]), right["extent_index"])
            for left, right in zip(output, output[1:])
        ),
        f"{label} entries are not strictly ordered",
    )
    groups: dict[bytes, list[dict[str, Any]]] = {}
    for item in output:
        groups.setdefault(item["blob_key_raw"], []).append(item)
    for key_raw, group in groups.items():
        count = group[0]["extent_count"]
        require(len(group) == count, f"{label} omits an extent for BlobKey {key_raw.hex()}")
        require(
            [item["extent_index"] for item in group] == list(range(count)),
            f"{label} Blob extent indices are incomplete",
        )
        require(
            all(item["extent_count"] == count for item in group),
            f"{label} Blob extent counts disagree",
        )
        expected_offset = 0
        encoded_blob_len = group[0]["encoded_blob_len"]
        for item in group:
            require(item["encoded_blob_len"] == encoded_blob_len, f"{label} encoded Blob lengths disagree")
            require(item["encoded_offset"] == expected_offset, f"{label} Blob extents leave a gap or overlap")
            expected_offset += item["payload_byte_len"]
        require(expected_offset == encoded_blob_len, f"{label} Blob extents do not cover the canonical Blob")
    return output


def read_abi_fixture(path: str) -> dict[str, Any]:
    directory = Path(path)
    manifest = json.loads((directory / "context.json").read_text(encoding="utf-8"))
    require(manifest.get("format") == "vibeos-storage-v2-gc-abi", "GC ABI fixture format is invalid")
    require(manifest.get("version") == 1, "GC ABI fixture version is invalid")
    store_uuid = _hex_bytes(manifest.get("store_uuid"), 16, "store_uuid")
    require(not zero(store_uuid), "store_uuid is zero")
    typed_reference_kinds = _int_list(
        manifest.get("typed_reference_kinds", []), "typed_reference_kinds"
    )
    require(
        len(typed_reference_kinds) <= MAX_TYPED_REFERENCE_KINDS,
        "typed-reference ObjectKind policy exceeds its fixed bound",
    )
    require(
        all(kind > 0 for kind in typed_reference_kinds)
        and all(left < right for left, right in zip(typed_reference_kinds, typed_reference_kinds[1:])),
        "typed-reference ObjectKind policy is not canonical",
    )

    allocation = parse_allocation_v2(_read_relative(directory, manifest.get("allocation"), "allocation"))
    roots_payload = _read_relative(directory, manifest.get("persistent_roots"), "persistent_roots")
    authority_raw = _hex_bytes(manifest.get("authority_root"), POINTER_SIZE, "authority_root")
    _, roots = admit_gc(authority_raw, roots_payload, allocation, store_uuid)

    pointer_count = 0
    current_pointers = manifest.get("current_pointers", [])
    require(isinstance(current_pointers, list), "current_pointers must be an array")
    for index, item in enumerate(current_pointers):
        require(isinstance(item, dict), f"current_pointers[{index}] must be an object")
        name = item.get("name", f"current_pointers[{index}]")
        expected_kind = item.get("extent_kind")
        require(expected_kind is None or isinstance(expected_kind, int), f"{name} extent_kind is invalid")
        validate_current_pointer(
            _hex_bytes(item.get("pointer"), POINTER_SIZE, f"{name} pointer"),
            allocation,
            store_uuid,
            str(name),
            expected_kind,
        )
        pointer_count += 1

    typed_count = 0
    typed_manifests = manifest.get("typed_manifests", [])
    require(isinstance(typed_manifests, list), "typed_manifests must be an array")
    for index, item in enumerate(typed_manifests):
        require(isinstance(item, dict), f"typed_manifests[{index}] must be an object")
        mapping = parse_object_mapping_v2(
            _read_relative(directory, item.get("object_mapping"), f"typed_manifests[{index}] mapping"),
            allocation["checkpoint_generation"],
        )
        admitted_kind = mapping["object_kind"]
        require(
            admitted_kind in typed_reference_kinds,
            "typed manifest ObjectKind is absent from trusted runtime policy",
        )
        decode_admitted_typed_refs(
            mapping,
            _read_relative(directory, item.get("payload"), f"typed_manifests[{index}] payload"),
            admitted_kind,
        )
        typed_count += 1

    barrier_state: Optional[str] = None
    barrier = manifest.get("barrier")
    if barrier is not None:
        require(isinstance(barrier, dict), "barrier must be an object")
        allocation_g = parse_allocation_v2(_read_relative(directory, barrier.get("g"), "barrier G"))
        allocation_g1 = (
            parse_allocation_v2(_read_relative(directory, barrier.get("g1"), "barrier G+1"))
            if barrier.get("g1") is not None
            else None
        )
        allocation_g2 = (
            parse_allocation_v2(_read_relative(directory, barrier.get("g2"), "barrier G+2"))
            if barrier.get("g2") is not None
            else None
        )
        seal_readback = (
            _read_relative(directory, barrier.get("old_checkpoint_seal"), "old checkpoint seal")
            if barrier.get("old_checkpoint_seal") is not None
            else None
        )
        live_blob_keys = (
            _barrier_live_blob_keys(barrier.get("live_blob_keys"))
            if barrier.get("live_blob_keys") is not None
            else None
        )
        g_pointer_evidence = (
            _barrier_blob_extent_list(
                barrier.get("g_blob_extent_pointers"),
                "g_blob_extent_pointers",
                allocation_g,
                store_uuid,
            )
            if barrier.get("g_blob_extent_pointers") is not None
            else None
        )
        g1_pointer_evidence = (
            _barrier_blob_extent_list(
                barrier.get("g1_blob_extent_pointers"),
                "g1_blob_extent_pointers",
                allocation_g1,
                store_uuid,
            )
            if barrier.get("g1_blob_extent_pointers") is not None and allocation_g1 is not None
            else None
        )
        barrier_state = validate_three_state_barrier(
            allocation_g,
            allocation_g1,
            allocation_g2,
            g1_allocate=_int_list(barrier.get("g1_allocate", []), "g1_allocate"),
            g1_retire=_int_list(barrier.get("g1_retire", []), "g1_retire"),
            g2_allocate=_int_list(barrier.get("g2_allocate", []), "g2_allocate"),
            g2_reclaim=_int_list(barrier.get("g2_reclaim", []), "g2_reclaim"),
            old_checkpoint_seal_readback=seal_readback,
            pinned_generations=_int_list(barrier.get("pinned_generations", []), "pinned_generations"),
            live_blob_keys=live_blob_keys,
            g_blob_extent_pointers=g_pointer_evidence,
            g1_blob_extent_pointers=g1_pointer_evidence,
        )
        selected_barrier = allocation_g2 or allocation_g1 or allocation_g
        require(
            allocation == selected_barrier,
            "selected allocation is not the latest supplied barrier state",
        )

    return {
        "format": "vibeos-storage-v2-gc-abi",
        "status": "ok",
        "checkpoint_generation": allocation["checkpoint_generation"],
        "segments": allocation["counts"],
        "persistent_roots": len(roots["entries"]),
        "current_pointers": pointer_count,
        "typed_manifests": typed_count,
        "barrier_state": barrier_state,
    }


def encode_allocation_fixture(
    generation: int,
    next_segment_generation: int,
    states: list[int],
    retired: list[tuple[int, int]],
    reserve: int = 1,
) -> bytes:
    bitmap = bytearray((len(states) + 3) // 4)
    counts = [0, 0, 0]
    for index, state in enumerate(states):
        bitmap[index // 4] |= state << ((index % 4) * 2)
        counts[state] += 1
    encoded_len = ALLOCATION_HEADER_LEN + len(bitmap) + len(retired) * RETIRED_ENTRY_LEN
    out = bytearray(encoded_len)
    out[0x00:0x08] = ALLOCATION_MAGIC
    put_u16(out, 0x08, ALLOCATION_VERSION)
    put_u16(out, 0x0A, ALLOCATION_HEADER_LEN)
    put_u64(out, 0x10, generation)
    put_u64(out, 0x18, len(states))
    put_u64(out, 0x20, next_segment_generation)
    put_u32(out, 0x28, reserve)
    put_u16(out, 0x2C, SEGMENT_STATE_BITS)
    put_u16(out, 0x2E, RETIRED_ENTRY_LEN)
    put_u64(out, 0x30, ALLOCATION_HEADER_LEN)
    put_u64(out, 0x38, len(bitmap))
    put_u64(out, 0x40, ALLOCATION_HEADER_LEN + len(bitmap))
    put_u64(out, 0x48, len(retired))
    put_u64(out, 0x50, counts[SEGMENT_FREE])
    put_u64(out, 0x58, counts[SEGMENT_ALLOCATED])
    put_u64(out, 0x60, counts[SEGMENT_RETIRED])
    put_u64(out, 0x68, encoded_len)
    out[ALLOCATION_HEADER_LEN : ALLOCATION_HEADER_LEN + len(bitmap)] = bitmap
    for index, (segment_no, retire_generation) in enumerate(retired):
        offset = ALLOCATION_HEADER_LEN + len(bitmap) + index * RETIRED_ENTRY_LEN
        put_u64(out, offset, segment_no)
        put_u64(out, offset + 8, retire_generation)
    return bytes(out)


def encode_root_fixture(generation: int, entries: list[tuple[int, int, int]]) -> bytes:
    out = bytearray(ROOT_HEADER_LEN + len(entries) * ROOT_ENTRY_LEN)
    out[0x00:0x08] = ROOT_MAGIC
    put_u16(out, 0x08, ROOT_VERSION)
    put_u16(out, 0x0A, ROOT_HEADER_LEN)
    put_u64(out, 0x10, generation)
    put_u32(out, 0x18, len(entries))
    put_u32(out, 0x1C, ROOT_ENTRY_LEN)
    put_u64(out, 0x20, ROOT_HEADER_LEN)
    put_u64(out, 0x28, len(out))
    for index, (object_id, commit_generation, object_kind) in enumerate(entries):
        offset = ROOT_HEADER_LEN + index * ROOT_ENTRY_LEN
        out[offset : offset + 16] = object_id.to_bytes(16, "little")
        put_u64(out, offset + 0x10, commit_generation)
        put_u32(out, offset + 0x18, object_kind)
    return bytes(out)


def encode_typed_refs_fixture(
    object_kind: int,
    generation: int,
    references: list[tuple[int, int, int]],
) -> bytes:
    out = bytearray(TYPED_REFS_HEADER_LEN + len(references) * TYPED_REFS_ENTRY_LEN)
    out[0x00:0x08] = TYPED_REFS_MAGIC
    put_u16(out, 0x08, TYPED_REFS_VERSION)
    put_u16(out, 0x0A, TYPED_REFS_HEADER_LEN)
    out[0x10:0x20] = TYPED_REFS_ADMISSION_TAG
    put_u32(out, 0x20, object_kind)
    put_u64(out, 0x28, generation)
    put_u32(out, 0x30, len(references))
    put_u32(out, 0x34, TYPED_REFS_ENTRY_LEN)
    put_u64(out, 0x38, TYPED_REFS_HEADER_LEN)
    put_u64(out, 0x40, len(out))
    for index, (object_id, commit_generation, child_kind) in enumerate(references):
        offset = TYPED_REFS_HEADER_LEN + index * TYPED_REFS_ENTRY_LEN
        out[offset : offset + 16] = object_id.to_bytes(16, "little")
        put_u64(out, offset + 0x10, commit_generation)
        put_u32(out, offset + 0x18, child_kind)
    return bytes(out)


def encode_object_mapping_fixture(
    object_id: int,
    object_kind: int,
    commit_generation: int,
    exact_len: int,
    reference_codec: int,
    payload_sha256: Optional[bytes] = None,
) -> bytes:
    out = bytearray(OBJECT_MAPPING_LEN)
    out[0x00:0x10] = object_id.to_bytes(16, "little")
    put_u16(out, 0x10, HASH_ALGORITHM_SHA256)
    put_u32(out, 0x14, object_kind)
    put_u64(out, 0x18, exact_len)
    out[0x20:0x40] = bytes([0xA5]) * 32 if payload_sha256 is None else payload_sha256
    put_u64(out, 0x50, commit_generation)
    put_u16(out, 0x58, reference_codec)
    return bytes(out)


def encode_pointer_fixture(
    store_uuid: bytes,
    segment_no: int,
    segment_generation: int,
    exact_len: int,
    extent_kind: int,
    payload_sha256: Optional[bytes] = None,
    descriptor_relative_page: int = 2,
    ordinal: int = 1,
) -> bytes:
    out = bytearray(POINTER_SIZE)
    out[0x00:0x10] = store_uuid
    put_u64(out, 0x10, segment_no)
    put_u64(out, 0x18, segment_generation)
    put_u32(out, 0x20, descriptor_relative_page)
    put_u32(out, 0x24, descriptor_relative_page + 2)
    put_u32(out, 0x28, (exact_len + PAGE_SIZE - 1) // PAGE_SIZE)
    put_u32(out, 0x2C, ordinal)
    put_u64(out, 0x30, exact_len)
    put_u16(out, 0x38, extent_kind)
    put_u16(out, 0x3A, HASH_ALGORITHM_SHA256)
    out[0x40:0x60] = bytes([0x5A]) * 32 if payload_sha256 is None else payload_sha256
    return bytes(out)


def expect_violation(action: Callable[[], Any], label: str) -> None:
    try:
        action()
    except Violation:
        return
    raise Violation(f"selftest {label} was accepted")


def mutated_byte(raw: bytes, offset: int, value: Optional[int] = None) -> bytes:
    """Return one deterministic byte mutation without changing the payload length."""

    out = bytearray(raw)
    out[offset] = (out[offset] ^ 1) if value is None else value
    return bytes(out)


def mutated_integer(raw: bytes, offset: int, width: int, value: int) -> bytes:
    out = bytearray(raw)
    out[offset : offset + width] = value.to_bytes(width, "little")
    return bytes(out)


def expect_payload_matrix(
    parser: Callable[[bytes], Any],
    cases: list[tuple[str, bytes]],
) -> int:
    """Require every named closed-field mutation to fail independently."""

    for label, payload in cases:
        expect_violation(lambda payload=payload: parser(payload), label)
    return len(cases)


def run_selftest() -> dict[str, Any]:
    tests: list[str] = []
    mutation_cases = 0
    store_uuid = bytes(range(1, 17))

    allocation_bytes = encode_allocation_fixture(
        9,
        40,
        [SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE],
        [(2, 8)],
    )
    allocation = parse_allocation_v2(allocation_bytes)
    require(allocation["counts"] == {"free": 2, "allocated": 2, "retired": 1}, "allocation golden count failed")
    retired_reserve = parse_allocation_v2(
        encode_allocation_fixture(
            9,
            40,
            [SEGMENT_ALLOCATED, SEGMENT_RETIRED, SEGMENT_ALLOCATED],
            [(1, 9)],
        )
    )
    require(
        retired_reserve["counts"]["free"] == 0
        and retired_reserve["counts"]["retired"] == 1,
        "allocation retired reserve was not admitted",
    )
    tests.append("allocation-v2-golden")

    allocation_matrix = encode_allocation_fixture(
        9,
        40,
        [
            SEGMENT_ALLOCATED,
            SEGMENT_FREE,
            SEGMENT_RETIRED,
            SEGMENT_ALLOCATED,
            SEGMENT_RETIRED,
            SEGMENT_FREE,
            SEGMENT_FREE,
            SEGMENT_FREE,
        ],
        [(2, 8), (4, 9)],
    )
    allocation_retirement_offset = ALLOCATION_HEADER_LEN + 2
    allocation_cases = [
        ("allocation-magic", mutated_byte(allocation_matrix, 0x00)),
        ("allocation-version", mutated_integer(allocation_matrix, 0x08, 2, 0)),
        ("allocation-header-length", mutated_integer(allocation_matrix, 0x0A, 2, 0)),
        ("allocation-flags", mutated_integer(allocation_matrix, 0x0C, 4, 1)),
        ("allocation-checkpoint-generation-min", mutated_integer(allocation_matrix, 0x10, 8, 0)),
        ("allocation-admitted-min", mutated_integer(allocation_matrix, 0x18, 8, 0)),
        (
            "allocation-admitted-max-plus-one",
            mutated_integer(allocation_matrix, 0x18, 8, MAX_ALLOCATION_SEGMENTS + 1),
        ),
        ("allocation-next-generation-min", mutated_integer(allocation_matrix, 0x20, 8, 0)),
        ("allocation-reserve-min", mutated_integer(allocation_matrix, 0x28, 4, 0)),
        ("allocation-reserve-admitted", mutated_integer(allocation_matrix, 0x28, 4, 8)),
        ("allocation-reserve-exhausted", mutated_integer(allocation_matrix, 0x28, 4, 7)),
        ("allocation-state-width", mutated_integer(allocation_matrix, 0x2C, 2, 1)),
        ("allocation-retired-entry-size", mutated_integer(allocation_matrix, 0x2E, 2, 8)),
        ("allocation-bitmap-offset", mutated_integer(allocation_matrix, 0x30, 8, 0)),
        ("allocation-bitmap-length", mutated_integer(allocation_matrix, 0x38, 8, 1)),
        (
            "allocation-retirement-offset",
            mutated_integer(allocation_matrix, 0x40, 8, allocation_retirement_offset + 1),
        ),
        ("allocation-retired-count", mutated_integer(allocation_matrix, 0x48, 8, 1)),
        ("allocation-free-count", mutated_integer(allocation_matrix, 0x50, 8, 3)),
        ("allocation-allocated-count", mutated_integer(allocation_matrix, 0x58, 8, 1)),
        ("allocation-retired-state-count", mutated_integer(allocation_matrix, 0x60, 8, 1)),
        ("allocation-encoded-length", mutated_integer(allocation_matrix, 0x68, 8, len(allocation_matrix) - 1)),
        ("allocation-header-reserved", mutated_byte(allocation_matrix, 0x70)),
        ("allocation-state-3", mutated_byte(allocation_matrix, ALLOCATION_HEADER_LEN, 0x0D)),
        (
            "allocation-retired-segment-out-of-range",
            mutated_integer(allocation_matrix, allocation_retirement_offset, 8, 8),
        ),
        (
            "allocation-retirement-points-to-allocated",
            mutated_integer(allocation_matrix, allocation_retirement_offset, 8, 0),
        ),
        (
            "allocation-retirement-generation-min",
            mutated_integer(allocation_matrix, allocation_retirement_offset + 8, 8, 0),
        ),
        (
            "allocation-retirement-generation-future",
            mutated_integer(allocation_matrix, allocation_retirement_offset + 8, 8, 10),
        ),
        (
            "allocation-retirement-order",
            mutated_integer(allocation_matrix, allocation_retirement_offset, 8, 4),
        ),
        (
            "allocation-retirement-duplicate",
            mutated_integer(allocation_matrix, allocation_retirement_offset + RETIRED_ENTRY_LEN, 8, 2),
        ),
        ("allocation-prefix", bytes([0]) + allocation_matrix),
        ("allocation-suffix", allocation_matrix + bytes([0])),
    ]
    mutation_cases += expect_payload_matrix(parse_allocation_v2, allocation_cases)
    tests.append("allocation-v2-closed-field-matrix")

    free_pointer = encode_pointer_fixture(store_uuid, 1, 10, 64, 1)
    expect_violation(
        lambda: validate_current_pointer(free_pointer, allocation, store_uuid, "free pointer"),
        "free-pointer",
    )
    tests.append("free-pointer")

    retired_pointer = encode_pointer_fixture(store_uuid, 2, 11, 64, 1)
    expect_violation(
        lambda: validate_current_pointer(retired_pointer, allocation, store_uuid, "retired pointer"),
        "retired-current-reference",
    )
    tests.append("retired-current-reference")

    tail = bytearray(allocation_bytes)
    tail[ALLOCATION_HEADER_LEN + 1] |= 0x04
    expect_violation(lambda: parse_allocation_v2(bytes(tail)), "allocation-tail-bits")
    count = bytearray(allocation_bytes)
    put_u64(count, 0x50, u64(count, 0x50) + 1)
    expect_violation(lambda: parse_allocation_v2(bytes(count)), "allocation-count")
    tests.append("tail-bits-and-count")

    roots_payload = encode_root_fixture(9, [(1, 7, 0x44), (5, 9, 0x45)])
    roots = parse_persistent_root_set(roots_payload)
    require(len(roots["entries"]) == 2, "persistent root-set golden count failed")
    empty_roots = parse_persistent_root_set(encode_root_fixture(9, []))
    require(empty_roots["entries"] == [], "canonical empty root set failed")
    authority_pointer = encode_pointer_fixture(
        store_uuid,
        0,
        12,
        len(roots_payload),
        EXTENT_AUTHORITY,
        hashlib.sha256(roots_payload).digest(),
    )
    _, admitted_roots = admit_gc(authority_pointer, roots_payload, allocation, store_uuid)
    require(admitted_roots == roots, "authority-root admission changed the root set")
    later_allocation = parse_allocation_v2(
        encode_allocation_fixture(
            10,
            40,
            [SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE],
            [(2, 8)],
        )
    )
    _, reused_roots = admit_gc(authority_pointer, roots_payload, later_allocation, store_uuid)
    require(reused_roots == roots, "newer checkpoint could not reuse an authenticated root set")
    tests.append("persistent-root-set")

    root_entry = ROOT_HEADER_LEN
    root_cases = [
        ("roots-magic", mutated_byte(roots_payload, 0x00)),
        ("roots-version", mutated_integer(roots_payload, 0x08, 2, 0)),
        ("roots-header-length", mutated_integer(roots_payload, 0x0A, 2, 0)),
        ("roots-flags", mutated_integer(roots_payload, 0x0C, 4, 1)),
        ("roots-checkpoint-generation-min", mutated_integer(roots_payload, 0x10, 8, 0)),
        (
            "roots-entry-count-max-plus-one",
            mutated_integer(roots_payload, 0x18, 4, MAX_ROOT_ENTRIES + 1),
        ),
        ("roots-entry-size", mutated_integer(roots_payload, 0x1C, 4, ROOT_ENTRY_LEN - 1)),
        ("roots-table-offset", mutated_integer(roots_payload, 0x20, 8, ROOT_HEADER_LEN + 1)),
        ("roots-encoded-length", mutated_integer(roots_payload, 0x28, 8, len(roots_payload) - 1)),
        ("roots-header-reserved", mutated_byte(roots_payload, 0x30)),
        ("roots-object-id-min", mutated_integer(roots_payload, root_entry, 16, 0)),
        ("roots-commit-generation-min", mutated_integer(roots_payload, root_entry + 0x10, 8, 0)),
        ("roots-commit-generation-future", mutated_integer(roots_payload, root_entry + 0x10, 8, 10)),
        ("roots-object-kind-min", mutated_integer(roots_payload, root_entry + 0x18, 4, 0)),
        ("roots-entry-flags", mutated_integer(roots_payload, root_entry + 0x1C, 4, 1)),
        ("roots-order-duplicate", mutated_integer(roots_payload, root_entry + ROOT_ENTRY_LEN, 16, 1)),
        ("roots-order-decreasing", mutated_integer(roots_payload, root_entry, 16, 6)),
        ("roots-prefix", bytes([0]) + roots_payload),
        ("roots-suffix", roots_payload + bytes([0])),
    ]
    mutation_cases += expect_payload_matrix(parse_persistent_root_set, root_cases)
    tests.append("persistent-root-closed-field-matrix")

    expect_violation(
        lambda: admit_gc(bytes(POINTER_SIZE), encode_root_fixture(9, []), allocation, store_uuid),
        "null-authority",
    )
    tests.append("null-authority-disables-gc")

    refs_payload = encode_typed_refs_fixture(0x44, 9, [(2, 3, 0x51), (7, 8, 0x52)])
    mapping = parse_object_mapping_v2(
        encode_object_mapping_fixture(
            1,
            0x44,
            9,
            len(refs_payload),
            REFERENCE_CODEC_TYPED_V1,
            canonical_blob_root(0x44, refs_payload),
        ),
        9,
    )
    refs = decode_admitted_typed_refs(mapping, refs_payload, 0x44)
    require(len(refs["references"]) == 2, "refs-v1 golden count failed")
    typed_entry = TYPED_REFS_HEADER_LEN
    typed_cases = [
        ("typed-magic", mutated_byte(refs_payload, 0x00)),
        ("typed-version", mutated_integer(refs_payload, 0x08, 2, 0)),
        ("typed-header-length", mutated_integer(refs_payload, 0x0A, 2, 0)),
        ("typed-header-flags", mutated_integer(refs_payload, 0x0C, 4, 1)),
        ("typed-admission-tag", mutated_byte(refs_payload, 0x10)),
        ("typed-manifest-object-kind-min", mutated_integer(refs_payload, 0x20, 4, 0)),
        ("typed-header-reserved-word", mutated_integer(refs_payload, 0x24, 4, 1)),
        ("typed-manifest-generation-min", mutated_integer(refs_payload, 0x28, 8, 0)),
        (
            "typed-reference-count-max-plus-one",
            mutated_integer(refs_payload, 0x30, 4, MAX_TYPED_REFS + 1),
        ),
        ("typed-entry-size", mutated_integer(refs_payload, 0x34, 4, TYPED_REFS_ENTRY_LEN - 1)),
        ("typed-table-offset", mutated_integer(refs_payload, 0x38, 8, TYPED_REFS_HEADER_LEN + 1)),
        ("typed-encoded-length", mutated_integer(refs_payload, 0x40, 8, len(refs_payload) - 1)),
        ("typed-header-reserved", mutated_byte(refs_payload, 0x48)),
        ("typed-child-object-id-min", mutated_integer(refs_payload, typed_entry, 16, 0)),
        ("typed-child-generation-min", mutated_integer(refs_payload, typed_entry + 0x10, 8, 0)),
        ("typed-child-generation-future", mutated_integer(refs_payload, typed_entry + 0x10, 8, 10)),
        ("typed-child-object-kind-min", mutated_integer(refs_payload, typed_entry + 0x18, 4, 0)),
        ("typed-entry-flags", mutated_integer(refs_payload, typed_entry + 0x1C, 4, 1)),
        ("typed-entry-reserved", mutated_byte(refs_payload, typed_entry + 0x20)),
        (
            "typed-order-duplicate",
            mutated_integer(refs_payload, typed_entry + TYPED_REFS_ENTRY_LEN, 16, 2),
        ),
        ("typed-order-decreasing", mutated_integer(refs_payload, typed_entry, 16, 8)),
        ("typed-prefix", bytes([0]) + refs_payload),
        ("typed-suffix", refs_payload + bytes([0])),
    ]
    mutation_cases += expect_payload_matrix(parse_typed_refs_v1, typed_cases)
    tests.append("typed-reference-closed-field-matrix")

    object_mapping_bytes = encode_object_mapping_fixture(
        1,
        0x44,
        9,
        len(refs_payload),
        REFERENCE_CODEC_TYPED_V1,
        canonical_blob_root(0x44, refs_payload),
    )
    object_cases = [
        ("object-mapping-length-minus-one", object_mapping_bytes[:-1]),
        ("object-mapping-length-plus-one", object_mapping_bytes + bytes([0])),
        ("object-mapping-object-id-min", mutated_integer(object_mapping_bytes, 0x00, 16, 0)),
        ("object-mapping-hash-algorithm", mutated_integer(object_mapping_bytes, 0x10, 2, 0)),
        ("object-mapping-blob-key-reserved-word", mutated_integer(object_mapping_bytes, 0x12, 2, 1)),
        ("object-mapping-object-kind-min", mutated_integer(object_mapping_bytes, 0x14, 4, 0)),
        (
            "object-mapping-content-length-max-plus-one",
            mutated_integer(object_mapping_bytes, 0x18, 8, MAX_BLOB_CONTENT_LEN + 1),
        ),
        ("object-mapping-blob-key-reserved", mutated_byte(object_mapping_bytes, 0x40)),
        ("object-mapping-commit-generation-min", mutated_integer(object_mapping_bytes, 0x50, 8, 0)),
        ("object-mapping-commit-generation-future", mutated_integer(object_mapping_bytes, 0x50, 8, 10)),
        ("object-mapping-reference-codec", mutated_integer(object_mapping_bytes, 0x58, 2, 2)),
        ("object-mapping-reserved", mutated_byte(object_mapping_bytes, 0x5A)),
    ]
    mutation_cases += expect_payload_matrix(
        lambda raw: parse_object_mapping_v2(raw, 9), object_cases
    )
    maximum_length_mapping = parse_object_mapping_v2(
        encode_object_mapping_fixture(
            1,
            0x44,
            9,
            MAX_BLOB_CONTENT_LEN,
            REFERENCE_CODEC_RAW,
        ),
        9,
    )
    require(
        maximum_length_mapping["exact_len"] == MAX_BLOB_CONTENT_LEN,
        "ObjectMapping maximum content length was rejected",
    )
    digest_mutation = bytearray(object_mapping_bytes)
    digest_mutation[0x20] ^= 1
    expect_violation(
        lambda: decode_admitted_typed_refs(
            parse_object_mapping_v2(bytes(digest_mutation), 9), refs_payload, 0x44
        ),
        "object-mapping-content-root-binding",
    )
    wrong_manifest_generation = parse_object_mapping_v2(
        mutated_integer(object_mapping_bytes, 0x50, 8, 8), 9
    )
    expect_violation(
        lambda: decode_admitted_typed_refs(
            wrong_manifest_generation, refs_payload, 0x44
        ),
        "object-mapping-manifest-generation-binding",
    )
    wrong_manifest_kind_bytes = encode_object_mapping_fixture(
        1,
        0x45,
        9,
        len(refs_payload),
        REFERENCE_CODEC_TYPED_V1,
        canonical_blob_root(0x45, refs_payload),
    )
    wrong_manifest_kind = parse_object_mapping_v2(wrong_manifest_kind_bytes, 9)
    expect_violation(
        lambda: decode_admitted_typed_refs(
            wrong_manifest_kind, refs_payload, 0x45
        ),
        "object-mapping-manifest-kind-binding",
    )
    raw_mapping = parse_object_mapping_v2(
        mutated_integer(object_mapping_bytes, 0x58, 2, REFERENCE_CODEC_RAW), 9
    )
    expect_violation(
        lambda: decode_admitted_typed_refs(raw_mapping, refs_payload, 0x44),
        "object-mapping-raw-is-not-typed",
    )
    mutation_cases += 4
    tests.append("object-mapping-closed-field-and-binding-matrix")
    bad_tag = bytearray(refs_payload)
    bad_tag[0x10] ^= 1
    expect_violation(lambda: decode_admitted_typed_refs(mapping, bytes(bad_tag), 0x44), "typed-tag")
    malformed = bytearray(refs_payload)
    malformed[TYPED_REFS_HEADER_LEN + 0x20] = 1
    expect_violation(lambda: decode_admitted_typed_refs(mapping, bytes(malformed), 0x44), "typed-malformed")
    flipped_payload = bytearray(refs_payload)
    flipped_payload[-1] ^= 1
    expect_violation(
        lambda: decode_admitted_typed_refs(mapping, bytes(flipped_payload), 0x44),
        "typed-payload-hash",
    )
    expect_violation(lambda: decode_admitted_typed_refs(mapping, refs_payload, 0x45), "typed-not-admitted")
    wrong_length_mapping = parse_object_mapping_v2(
        encode_object_mapping_fixture(
            1,
            0x44,
            9,
            len(refs_payload) - 1,
            REFERENCE_CODEC_TYPED_V1,
            canonical_blob_root(0x44, refs_payload),
        ),
        9,
    )
    expect_violation(
        lambda: decode_admitted_typed_refs(wrong_length_mapping, refs_payload, 0x44),
        "typed-length-binding",
    )
    bad_mapping = encode_object_mapping_fixture(
        1, 0x44, 9, len(refs_payload), 2, canonical_blob_root(0x44, refs_payload)
    )
    expect_violation(lambda: parse_object_mapping_v2(bad_mapping, 9), "typed-mapping-tag")
    maximum_children = [(index + 1, 9, 0x51) for index in range(GC_CHILD_BUDGET)]
    maximum_payload = encode_typed_refs_fixture(0x44, 9, maximum_children)
    maximum_mapping = parse_object_mapping_v2(
        encode_object_mapping_fixture(
            1,
            0x44,
            9,
            len(maximum_payload),
            REFERENCE_CODEC_TYPED_V1,
            canonical_blob_root(0x44, maximum_payload),
        ),
        9,
    )
    require(
        len(decode_admitted_typed_refs(maximum_mapping, maximum_payload, 0x44)["references"])
        == GC_CHILD_BUDGET,
        "GC child-window maximum was rejected",
    )
    oversized_payload = encode_typed_refs_fixture(
        0x44, 9, maximum_children + [(GC_CHILD_BUDGET + 1, 9, 0x51)]
    )
    oversized_mapping = parse_object_mapping_v2(
        encode_object_mapping_fixture(
            1,
            0x44,
            9,
            len(oversized_payload),
            REFERENCE_CODEC_TYPED_V1,
            canonical_blob_root(0x44, oversized_payload),
        ),
        9,
    )
    expect_violation(
        lambda: decode_admitted_typed_refs(
            oversized_mapping, oversized_payload, 0x44
        ),
        "typed-child-window-max-plus-one",
    )
    tests.append("typed-tag-hash-window-and-malformed")

    persistent_content = b"persistent-root"
    opaque_runtime_content = b"not-a-registered-typed-payload"
    typed_runtime_content = encode_typed_refs_fixture(0x46, 8, [(4, 7, 0x47)])
    typed_child_content = b"typed-child"

    def graph_mapping(
        object_id: int,
        object_kind: int,
        generation: int,
        content: bytes,
        codec: int,
    ) -> dict[str, Any]:
        return parse_object_mapping_v2(
            encode_object_mapping_fixture(
                object_id,
                object_kind,
                generation,
                len(content),
                codec,
                canonical_blob_root(object_kind, content),
            ),
            9,
        )

    retained_objects = {
        1: graph_mapping(1, 0x44, 9, persistent_content, REFERENCE_CODEC_RAW),
        # A tag does not self-admit a parser: this retained runtime object is
        # deliberately malformed refs-v1 but remains an opaque leaf.
        2: graph_mapping(2, 0x45, 8, opaque_runtime_content, REFERENCE_CODEC_TYPED_V1),
        3: graph_mapping(3, 0x46, 8, typed_runtime_content, REFERENCE_CODEC_TYPED_V1),
        4: graph_mapping(4, 0x47, 7, typed_child_content, REFERENCE_CODEC_RAW),
    }
    retained_contents = {
        blob_key_identity(mapping["blob_key"]): content
        for mapping, content in zip(
            retained_objects.values(),
            (
                persistent_content,
                opaque_runtime_content,
                typed_runtime_content,
                typed_child_content,
            ),
        )
    }
    retained_graph = validate_raw_object_graph(
        retained_objects,
        retained_contents,
        [{"object_id": 1, "commit_generation": 9, "object_kind": 0x44}],
        [0x46],
    )
    require(
        retained_graph
        == {"persistent_reachable_objects": 1, "nonpersistent_objects": 3},
        "powered-off runtime-retained graph accounting failed",
    )
    tests.append("powered-off-runtime-retained-extras")

    g = parse_allocation_v2(
        encode_allocation_fixture(
            10,
            20,
            [SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [],
            reserve=2,
        )
    )
    g1 = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            21,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 11)],
            reserve=2,
        )
    )
    g2 = parse_allocation_v2(
        encode_allocation_fixture(
            12,
            22,
            [SEGMENT_FREE, SEGMENT_ALLOCATED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [],
            reserve=2,
        )
    )
    reserve_one_g = parse_allocation_v2(
        encode_allocation_fixture(
            10,
            20,
            [SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE],
            [],
            reserve=1,
        )
    )
    reserve_one_g1 = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            21,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE],
            [(0, 11)],
            reserve=1,
        )
    )
    expect_violation(
        lambda: validate_three_state_barrier(
            reserve_one_g,
            reserve_one_g1,
            g1_allocate=[1],
            g1_retire=[0],
        ),
        "barrier-reserve-one",
    )
    mutation_cases += 1
    require(validate_three_state_barrier(g) == "G", "base barrier state failed")
    require(
        validate_three_state_barrier(g, g1, g1_allocate=[1], g1_retire=[0]) == "G+1",
        "relocated barrier state failed",
    )
    require(
        validate_three_state_barrier(
            g,
            g1,
            g1_allocate=[1],
            g1_retire=[0],
            old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            pinned_generations=[11],
        )
        == "G+1",
        "cleared relocation recovery state failed",
    )
    require(
        validate_three_state_barrier(
            g,
            g1,
            g2,
            g1_allocate=[1],
            g1_retire=[0],
            g2_allocate=[2],
            g2_reclaim=[0],
            old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            pinned_generations=[11, 12],
        )
        == "G+2",
        "reuse barrier state failed",
    )

    partial_g = parse_allocation_v2(
        encode_allocation_fixture(
            20,
            30,
            [
                SEGMENT_ALLOCATED,
                SEGMENT_ALLOCATED,
                SEGMENT_ALLOCATED,
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_FREE,
            ],
            [],
            reserve=2,
        )
    )
    partial_g1 = parse_allocation_v2(
        encode_allocation_fixture(
            21,
            31,
            [
                SEGMENT_RETIRED,
                SEGMENT_RETIRED,
                SEGMENT_ALLOCATED,
                SEGMENT_ALLOCATED,
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_FREE,
            ],
            [(0, 21), (1, 21)],
            reserve=2,
        )
    )
    partial_g2 = parse_allocation_v2(
        encode_allocation_fixture(
            22,
            32,
            [
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_ALLOCATED,
                SEGMENT_ALLOCATED,
                SEGMENT_ALLOCATED,
                SEGMENT_FREE,
                SEGMENT_FREE,
            ],
            [],
            reserve=2,
        )
    )
    partial_blob_key_raw = object_mapping_bytes[0x10:0x50]
    partial_blob_key = parse_blob_key(partial_blob_key_raw, "partial selftest BlobKey")
    partial_geometry = canonical_blob_geometry(partial_blob_key["exact_len"])
    partial_lengths = [BLOB_HEADER_LEN, partial_blob_key["exact_len"], partial_geometry["tree_len"]]
    partial_offsets = [0, BLOB_HEADER_LEN, BLOB_HEADER_LEN + partial_blob_key["exact_len"]]

    def partial_extent_evidence(
        segment_nos: list[int], segment_generations: list[int]
    ) -> list[dict[str, Any]]:
        pointers = [
            storage.parse_pointer(
                encode_pointer_fixture(
                    store_uuid,
                    segment_no,
                    segment_generation,
                    partial_lengths[index],
                    EXTENT_BLOB,
                    descriptor_relative_page=2 + index * 3,
                    ordinal=index + 1,
                )
            )
            for index, (segment_no, segment_generation) in enumerate(
                zip(segment_nos, segment_generations)
            )
        ]
        return [
            {
                "blob_key": partial_blob_key,
                "blob_key_raw": partial_blob_key_raw,
                "encoded_blob_len": partial_geometry["encoded_len"],
                "extent_index": index,
                "extent_count": 3,
                "encoded_offset": partial_offsets[index],
                "payload_byte_len": partial_lengths[index],
                "pointer": pointer,
            }
            for index, pointer in enumerate(pointers)
        ]

    partial_g_pointers = partial_extent_evidence([0, 1, 2], [10, 11, 12])
    partial_g1_pointers = partial_extent_evidence([3, 3, 2], [30, 30, 12])
    require(
        validate_three_state_barrier(
            partial_g,
            partial_g1,
            partial_g2,
            g1_allocate=[3],
            g1_retire=[0, 1],
            g2_allocate=[4],
            g2_reclaim=[0, 1],
            old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            pinned_generations=[21, 22],
            live_blob_keys=[partial_blob_key_raw],
            g_blob_extent_pointers=partial_g_pointers,
            g1_blob_extent_pointers=partial_g1_pointers,
        )
        == "G+2",
        "partial relocation barrier state failed",
    )
    metadata_only_partial_g_pointers = partial_extent_evidence([0, 0, 2], [10, 10, 12])
    metadata_only_partial_g1_pointers = partial_extent_evidence([3, 3, 2], [30, 30, 12])
    require(
        validate_three_state_barrier(
            partial_g,
            partial_g1,
            partial_g2,
            g1_allocate=[3],
            g1_retire=[0, 1],
            g2_allocate=[4],
            g2_reclaim=[0, 1],
            old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            pinned_generations=[21, 22],
            live_blob_keys=[partial_blob_key_raw],
            g_blob_extent_pointers=metadata_only_partial_g_pointers,
            g1_blob_extent_pointers=metadata_only_partial_g1_pointers,
        )
        == "G+2",
        "partial relocation rejected a selected metadata-only source",
    )
    require(
        validate_three_state_barrier(
            partial_g,
            partial_g1,
            partial_g2,
            g1_allocate=[3],
            g1_retire=[0, 1],
            g2_allocate=[4],
            g2_reclaim=[0, 1],
            old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            pinned_generations=[21, 22],
            live_blob_keys=[],
            g_blob_extent_pointers=[],
            g1_blob_extent_pointers=[],
        )
        == "G+2",
        "partial relocation rejected the canonical zero-live table",
    )
    tests.append("partial-three-state-barrier")

    overflow_g = parse_allocation_v2(
        encode_allocation_fixture(
            U64_MAX - 1,
            20,
            [SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE],
            [],
        )
    )
    g1_wrong_generation = parse_allocation_v2(
        encode_allocation_fixture(
            12,
            21,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 12)],
        )
    )
    g1_wrong_next_generation = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            22,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 11)],
        )
    )
    g1_wrong_retirement_generation = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            21,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 10)],
        )
    )
    g1_undeclared_allocation = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            21,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 11)],
        )
    )
    g1_two_targets = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            22,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 11)],
        )
    )
    g1_changed_admission = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            21,
            [
                SEGMENT_RETIRED,
                SEGMENT_ALLOCATED,
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_FREE,
                SEGMENT_FREE,
            ],
            [(0, 11)],
        )
    )
    g1_changed_reserve = parse_allocation_v2(
        encode_allocation_fixture(
            11,
            21,
            [SEGMENT_RETIRED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [(0, 11)],
            reserve=3,
        )
    )
    g2_wrong_generation = parse_allocation_v2(
        encode_allocation_fixture(
            13,
            22,
            [SEGMENT_FREE, SEGMENT_ALLOCATED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [],
        )
    )
    g2_wrong_next_generation = parse_allocation_v2(
        encode_allocation_fixture(
            12,
            23,
            [SEGMENT_FREE, SEGMENT_ALLOCATED, SEGMENT_ALLOCATED, SEGMENT_FREE, SEGMENT_FREE, SEGMENT_FREE],
            [],
        )
    )
    barrier_cases: list[tuple[str, Callable[[], Any]]] = [
        (
            "barrier-generation-overflow",
            lambda: validate_three_state_barrier(overflow_g),
        ),
        (
            "barrier-base-has-g2-evidence",
            lambda: validate_three_state_barrier(g, None, g2),
        ),
        (
            "barrier-base-has-seal-evidence",
            lambda: validate_three_state_barrier(
                g, old_checkpoint_seal_readback=bytes(PAGE_SIZE)
            ),
        ),
        (
            "barrier-g1-no-target",
            lambda: validate_three_state_barrier(
                g, g1, g1_allocate=[], g1_retire=[0]
            ),
        ),
        (
            "barrier-g1-source-set-missing",
            lambda: validate_three_state_barrier(
                g, g1, g1_allocate=[1], g1_retire=[]
            ),
        ),
        (
            "barrier-g1-generation",
            lambda: validate_three_state_barrier(
                g,
                g1_wrong_generation,
                g1_allocate=[1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-next-generation",
            lambda: validate_three_state_barrier(
                g,
                g1_wrong_next_generation,
                g1_allocate=[1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-allocation-bool",
            lambda: validate_three_state_barrier(
                g, g1, g1_allocate=[True], g1_retire=[0]
            ),
        ),
        (
            "barrier-g1-allocation-negative",
            lambda: validate_three_state_barrier(
                g, g1, g1_allocate=[-1], g1_retire=[0]
            ),
        ),
        (
            "barrier-g1-allocation-out-of-range",
            lambda: validate_three_state_barrier(
                g, g1, g1_allocate=[6], g1_retire=[0]
            ),
        ),
        (
            "barrier-g1-allocation-duplicate",
            lambda: validate_three_state_barrier(
                g,
                g1_two_targets,
                g1_allocate=[1, 1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-allocation-order",
            lambda: validate_three_state_barrier(
                g,
                g1_two_targets,
                g1_allocate=[2, 1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-lists-intersect",
            lambda: validate_three_state_barrier(
                g, g1, g1_allocate=[0], g1_retire=[0]
            ),
        ),
        (
            "barrier-g1-undeclared-state-change",
            lambda: validate_three_state_barrier(
                g,
                g1_undeclared_allocation,
                g1_allocate=[1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-retirement-generation",
            lambda: validate_three_state_barrier(
                g,
                g1_wrong_retirement_generation,
                g1_allocate=[1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-admitted-segments",
            lambda: validate_three_state_barrier(
                g,
                g1_changed_admission,
                g1_allocate=[1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-cleaner-reserve",
            lambda: validate_three_state_barrier(
                g,
                g1_changed_reserve,
                g1_allocate=[1],
                g1_retire=[0],
            ),
        ),
        (
            "barrier-g1-cleared-seal-length",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g1_allocate=[1],
                g1_retire=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE - 1),
            ),
        ),
        (
            "barrier-g1-cleared-pin-bool",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g1_allocate=[1],
                g1_retire=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
                pinned_generations=[True],
            ),
        ),
        (
            "barrier-g2-missing-seal",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[2],
                g2_reclaim=[0],
            ),
        ),
        (
            "barrier-g2-no-barrier-segment",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[],
                g2_reclaim=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            ),
        ),
        (
            "barrier-g2-two-barrier-segments",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[2, 3],
                g2_reclaim=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            ),
        ),
        (
            "barrier-g2-reclaim-set-missing",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[2],
                g2_reclaim=[],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            ),
        ),
        (
            "barrier-g2-generation",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2_wrong_generation,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[2],
                g2_reclaim=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            ),
        ),
        (
            "barrier-g2-next-generation",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2_wrong_next_generation,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[2],
                g2_reclaim=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            ),
        ),
        (
            "barrier-g2-allocation-bool",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[True],
                g2_reclaim=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            ),
        ),
        (
            "barrier-g2-pin-at-g",
            lambda: validate_three_state_barrier(
                g,
                g1,
                g2,
                g1_allocate=[1],
                g1_retire=[0],
                g2_allocate=[2],
                g2_reclaim=[0],
                old_checkpoint_seal_readback=bytes(PAGE_SIZE),
                pinned_generations=[10],
            ),
        ),
        (
            "barrier-partial-source-omitted",
            lambda: validate_three_state_barrier(
                partial_g,
                partial_g1,
                g1_allocate=[3],
                g1_retire=[0],
                live_blob_keys=[partial_blob_key_raw],
                g_blob_extent_pointers=partial_g_pointers,
                g1_blob_extent_pointers=partial_g1_pointers,
            ),
        ),
        (
            "barrier-partial-source-extra",
            lambda: validate_three_state_barrier(
                partial_g,
                partial_g1,
                g1_allocate=[3],
                g1_retire=[0, 1, 2],
                live_blob_keys=[partial_blob_key_raw],
                g_blob_extent_pointers=partial_g_pointers,
                g1_blob_extent_pointers=partial_g1_pointers,
            ),
        ),
        (
            "barrier-partial-source-unsorted",
            lambda: validate_three_state_barrier(
                partial_g,
                partial_g1,
                g1_allocate=[3],
                g1_retire=[1, 0],
                live_blob_keys=[partial_blob_key_raw],
                g_blob_extent_pointers=partial_g_pointers,
                g1_blob_extent_pointers=partial_g1_pointers,
            ),
        ),
        (
            "barrier-partial-selected-pointer-not-moved",
            lambda: validate_three_state_barrier(
                partial_g,
                partial_g1,
                g1_allocate=[3],
                g1_retire=[0, 1],
                live_blob_keys=[partial_blob_key_raw],
                g_blob_extent_pointers=partial_g_pointers,
                g1_blob_extent_pointers=[
                    {
                        **partial_g1_pointers[0],
                        "pointer": partial_g_pointers[0]["pointer"],
                    },
                    partial_g1_pointers[1],
                    partial_g1_pointers[2],
                ],
            ),
        ),
        (
            "barrier-partial-selected-pointer-moved-to-unselected-source",
            lambda: validate_three_state_barrier(
                partial_g,
                partial_g1,
                g1_allocate=[3],
                g1_retire=[0, 1],
                live_blob_keys=[partial_blob_key_raw],
                g_blob_extent_pointers=partial_g_pointers,
                g1_blob_extent_pointers=[
                    {
                        **partial_g1_pointers[0],
                        "pointer": storage.parse_pointer(
                            encode_pointer_fixture(
                                store_uuid,
                                2,
                                12,
                                partial_lengths[0],
                                EXTENT_BLOB,
                                descriptor_relative_page=2,
                                ordinal=1,
                            )
                        ),
                    },
                    partial_g1_pointers[1],
                    partial_g1_pointers[2],
                ],
            ),
        ),
        (
            "barrier-partial-unselected-pointer-rewritten",
            lambda: validate_three_state_barrier(
                partial_g,
                partial_g1,
                g1_allocate=[3],
                g1_retire=[0, 1],
                live_blob_keys=[partial_blob_key_raw],
                g_blob_extent_pointers=partial_g_pointers,
                g1_blob_extent_pointers=[
                    partial_g1_pointers[0],
                    partial_g1_pointers[1],
                    {
                        **partial_g1_pointers[2],
                        "pointer": storage.parse_pointer(
                            encode_pointer_fixture(
                                store_uuid,
                                3,
                                30,
                                partial_lengths[2],
                                EXTENT_BLOB,
                                descriptor_relative_page=8,
                                ordinal=3,
                            )
                        ),
                    },
                ],
            ),
        ),
    ]
    for label, action in barrier_cases:
        expect_violation(action, label)
    mutation_cases += len(barrier_cases)
    tests.append("three-state-barrier-closed-field-matrix")
    expect_violation(
        lambda: validate_three_state_barrier(
            g,
            g1,
            g2,
            g1_allocate=[1],
            g1_retire=[0],
            g2_allocate=[2],
            g2_reclaim=[0],
            old_checkpoint_seal_readback=bytes([1]) + bytes(PAGE_SIZE - 1),
        ),
        "uncleared-old-checkpoint",
    )
    expect_violation(
        lambda: validate_three_state_barrier(
            g,
            g1,
            g2,
            g1_allocate=[1],
            g1_retire=[0],
            g2_allocate=[2],
            g2_reclaim=[0],
            old_checkpoint_seal_readback=bytes(PAGE_SIZE),
            pinned_generations=[10],
        ),
        "pinned-through-g",
    )
    tests.append("three-state-barrier")
    return {"selftest": "ok", "mutation_cases": mutation_cases, "tests": tests}


def dump_json(value: dict[str, Any], pretty: bool) -> None:
    print(json.dumps(value, indent=2 if pretty else None, sort_keys=True, separators=None if pretty else (",", ":")))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true", help="run synthetic fail-closed GC ABI fixtures")
    mode.add_argument("--abi-fixture", metavar="DIR", help="verify a Rust-produced M7.5 payload bundle")
    mode.add_argument("--raw-image", metavar="PATH", help="verify a powered-off dense Storage V2 GC image")
    parser.add_argument(
        "--typed-reference-kind",
        metavar="KIND",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="trust one ObjectKind for refs-v1 traversal in --raw-image mode (repeatable)",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args(argv)
    typed_reference_kinds = sorted(set(args.typed_reference_kind))
    if args.raw_image is None and typed_reference_kinds:
        parser.error("--typed-reference-kind is valid only with --raw-image")
    if (
        len(typed_reference_kinds) != len(args.typed_reference_kind)
        or len(typed_reference_kinds) > MAX_TYPED_REFERENCE_KINDS
        or any(kind <= 0 or kind > 0xFFFF_FFFF for kind in typed_reference_kinds)
    ):
        parser.error("--typed-reference-kind values must be unique non-zero u32 values")
    try:
        if args.selftest:
            result = run_selftest()
        elif args.abi_fixture is not None:
            result = read_abi_fixture(args.abi_fixture)
        else:
            with Path(args.raw_image).open("rb") as raw_file:
                with mmap.mmap(raw_file.fileno(), 0, access=mmap.ACCESS_READ) as image:
                    result = verify_raw_image(image, typed_reference_kinds)
        dump_json(result, args.pretty)
        return 0 if result.get("status", "ok") == "ok" else 1
    except (Violation, OSError, ValueError, KeyError, TypeError) as exc:
        if args.selftest:
            status = {"selftest": "failed"}
        elif args.raw_image is not None:
            status = {"format": "vibeos-storage-v2-gc-raw", "version": 1, "status": "corrupt"}
        else:
            status = {"format": "vibeos-storage-v2-gc-abi", "status": "corrupt"}
        status["error"] = str(exc)
        dump_json(status, args.pretty)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
