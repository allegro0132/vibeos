#!/usr/bin/env python3
"""Powered-off, Rust-independent verifier for the Storage V2 Blob CAS.

The frozen record/segment framing is imported from ``storage-v2-image.py``;
all VIBECAS2, VIBEBMF2, BlobKey, manifest coverage, and canonical Blob Merkle
rules are duplicated here directly from the media ABI.  No production Rust
codec is loaded or invoked.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import mmap
import os
import struct
from pathlib import Path
from typing import Any, Optional


def load_storage_v2_parser() -> Any:
    path = Path(__file__).with_name("storage-v2-image.py")
    spec = importlib.util.spec_from_file_location("vibeos_storage_v2_image", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


storage = load_storage_v2_parser()
Violation = storage.FormatViolation

PAGE_SIZE = 4096
MAX_EXTENT_BYTES = 256 * PAGE_SIZE
MAX_BLOB_CONTENT_LEN = 64 * 1024 * 1024
MAX_BLOB_EXTENTS = 66
CANONICAL_CONTENT_EXTENT_LEN = MAX_EXTENT_BYTES
HASH_ALGORITHM_SHA256 = 1

BLOB_KEY_LEN = 0x40
OBJECT_MAPPING_LEN = 0x60
BLOB_MAPPING_LEN = 0xA0
BLOB_MANIFEST_HEADER_LEN = 0x80
MANIFEST_EXTENT_LEN = 0x80
CAS_SNAPSHOT_HEADER_LEN = 0x80
CAS_DELTA_HEADER_LEN = 0xA0
CAS_DELTA_REUSE_LEN = CAS_DELTA_HEADER_LEN + OBJECT_MAPPING_LEN
CAS_DELTA_NEW_BLOB_LEN = CAS_DELTA_REUSE_LEN + BLOB_MAPPING_LEN
MAX_MANIFEST_EXTENTS = (MAX_EXTENT_BYTES - BLOB_MANIFEST_HEADER_LEN) // MANIFEST_EXTENT_LEN

CAS_MAGIC = b"VIBECAS2"
BLOB_MANIFEST_MAGIC = b"VIBEBMF2"
CAS_VERSION = 1
CAS_KIND_SNAPSHOT = 1
CAS_KIND_DELTA = 2
DELTA_FLAG_NEW_BLOB = 1

BLOB_MAGIC = b"VIBEBLB\x00"
BLOB_HEADER_LEN = 128
BLOB_VERSION = 1
BLOB_LEAF_LOG2 = 12
BLOB_LEAF_SIZE = 1 << BLOB_LEAF_LOG2
LEAF_DOMAIN = b"VIBEBLOB-LEAF-v1\x00"
EMPTY_DOMAIN = b"VIBEBLOB-EMPTY-v1\x00"
NODE_DOMAIN = b"VIBEBLOB-NODE-v1\x00"
ROOT_DOMAIN = b"VIBEBLOB-ROOT-v1\x00"

EXTENT_BLOB = 1
EXTENT_CATALOG = 2
EXTENT_CATALOG_DELTA = 5


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


def sha256(data: bytes | memoryview) -> bytes:
    return hashlib.sha256(data).digest()


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


def blob_key_identity(key: dict[str, Any]) -> tuple[int, int, int, bytes]:
    return (
        key["hash_algorithm"],
        key["object_kind"],
        key["exact_len"],
        key["merkle_root"],
    )


def parse_blob_key(raw: bytes | memoryview, label: str = "BlobKey") -> dict[str, Any]:
    require(len(raw) == BLOB_KEY_LEN, f"{label} has a non-canonical length")
    require(u16(raw, 0x02) == 0, f"{label} reserved word must be zero")
    require_zero(raw, 0x30, 0x40, f"{label} reserved bytes")
    key = {
        "hash_algorithm": u16(raw, 0x00),
        "object_kind": u32(raw, 0x04),
        "exact_len": u64(raw, 0x08),
        "merkle_root": bytes(raw[0x10:0x30]),
    }
    require(key["hash_algorithm"] == HASH_ALGORITHM_SHA256, f"{label} hash algorithm is invalid")
    require(key["object_kind"] != 0, f"{label} object kind is zero")
    canonical_blob_geometry(key["exact_len"])
    return key


def context_pointer(
    raw: bytes | memoryview,
    context: dict[str, Any],
    expected_kind: int,
    label: str,
    *,
    allow_null: bool = False,
) -> dict[str, Any]:
    pointer = storage.parse_pointer(bytes(raw))
    if pointer["status"] == "null":
        require(allow_null, f"{label} is null")
        return pointer
    require(pointer["store_uuid"] == context["store_uuid"], f"{label} UUID mismatch")
    require(pointer["segment_no"] < context["admitted_segments"], f"{label} is outside admitted segments")
    require(
        pointer["segment_generation"] < context["next_segment_generation"],
        f"{label} has an uncommitted segment generation",
    )
    require(pointer["extent_kind"] == expected_kind, f"{label} has the wrong extent kind")
    return pointer


def pointer_conflict(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left["store_uuid"] != right["store_uuid"] or left["segment_no"] != right["segment_no"]:
        return False
    if left["segment_generation"] != right["segment_generation"] or left["ordinal"] == right["ordinal"]:
        return True
    left_end = left["payload_relative_page"] + left["payload_pages"]
    right_end = right["payload_relative_page"] + right["payload_pages"]
    return left["descriptor_relative_page"] < right_end and right["descriptor_relative_page"] < left_end


def parse_object_mapping(
    raw: bytes | memoryview,
    checkpoint_generation: int,
    label: str,
) -> dict[str, Any]:
    require(len(raw) == OBJECT_MAPPING_LEN, f"{label} has a non-canonical length")
    require_zero(raw, 0x58, 0x60, f"{label} reserved bytes")
    mapping = {
        "object_id": u128(raw, 0x00),
        "blob_key": parse_blob_key(raw[0x10:0x50], f"{label} BlobKey"),
        "commit_generation": u64(raw, 0x50),
    }
    require(mapping["object_id"] != 0, f"{label} object ID is zero")
    require(
        0 < mapping["commit_generation"] <= checkpoint_generation,
        f"{label} commit generation is invalid",
    )
    return mapping


def parse_blob_mapping(
    raw: bytes | memoryview,
    context: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    require(len(raw) == BLOB_MAPPING_LEN, f"{label} has a non-canonical length")
    key = parse_blob_key(raw[0x00:0x40], f"{label} BlobKey")
    manifest = context_pointer(raw[0x40:0xA0], context, EXTENT_CATALOG, f"{label} manifest")
    manifest_len = manifest["exact_byte_len"]
    require(
        BLOB_MANIFEST_HEADER_LEN < manifest_len <= MAX_EXTENT_BYTES
        and (manifest_len - BLOB_MANIFEST_HEADER_LEN) % MANIFEST_EXTENT_LEN == 0,
        f"{label} manifest pointer length is invalid",
    )
    count = (manifest_len - BLOB_MANIFEST_HEADER_LEN) // MANIFEST_EXTENT_LEN
    require(0 < count <= MAX_MANIFEST_EXTENTS, f"{label} manifest extent count is invalid")
    return {"blob_key": key, "manifest": manifest}


def parse_cas_snapshot(payload: bytes, context: dict[str, Any]) -> dict[str, Any]:
    require(CAS_SNAPSHOT_HEADER_LEN <= len(payload) <= MAX_EXTENT_BYTES, "CAS snapshot length is invalid")
    require(payload[0:8] == CAS_MAGIC, "CAS snapshot magic is invalid")
    require(u16(payload, 0x08) == CAS_VERSION, "CAS snapshot version is invalid")
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
    require(encoded_len <= MAX_EXTENT_BYTES and len(payload) == encoded_len, "CAS snapshot length is non-canonical")

    objects = [
        parse_object_mapping(
            payload[object_offset + index * OBJECT_MAPPING_LEN : object_offset + (index + 1) * OBJECT_MAPPING_LEN],
            generation,
            f"CAS snapshot object[{index}]",
        )
        for index in range(object_count)
    ]
    blobs = [
        parse_blob_mapping(
            payload[blob_offset + index * BLOB_MAPPING_LEN : blob_offset + (index + 1) * BLOB_MAPPING_LEN],
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
        all(blob_key_identity(left["blob_key"]) < blob_key_identity(right["blob_key"]) for left, right in zip(blobs, blobs[1:])),
        "CAS snapshot BlobKeys are not strictly increasing",
    )
    for left_index, left in enumerate(blobs):
        for right in blobs[left_index + 1 :]:
            require(not pointer_conflict(left["manifest"], right["manifest"]), "CAS snapshot manifest pointers overlap")
    available = {blob_key_identity(blob["blob_key"]) for blob in blobs}
    require(
        all(blob_key_identity(obj["blob_key"]) in available for obj in objects),
        "CAS snapshot object has no Blob mapping",
    )
    return {"checkpoint_generation": generation, "objects": objects, "blobs": blobs}


def parse_cas_delta(payload: bytes, context: dict[str, Any]) -> dict[str, Any]:
    require(len(payload) in (CAS_DELTA_REUSE_LEN, CAS_DELTA_NEW_BLOB_LEN), "CAS delta length is invalid")
    require(payload[0:8] == CAS_MAGIC, "CAS delta magic is invalid")
    require(u16(payload, 0x08) == CAS_VERSION, "CAS delta version is invalid")
    require(u16(payload, 0x0A) == CAS_KIND_DELTA, "CAS delta kind is invalid")
    require(u32(payload, 0x0C) == CAS_DELTA_HEADER_LEN, "CAS delta header length is invalid")
    generation = u64(payload, 0x10)
    chain_count = u32(payload, 0x18)
    flags = u32(payload, 0x1C)
    require(generation > 0 and chain_count > 0, "CAS delta generation or chain count is zero")
    require(u32(payload, 0x20) == OBJECT_MAPPING_LEN, "CAS delta object entry size is invalid")
    require(u32(payload, 0x24) == BLOB_MAPPING_LEN, "CAS delta Blob entry size is invalid")
    require_zero(payload, 0x28, 0x30, "CAS delta reserved header bytes")
    require_zero(payload, 0x98, 0xA0, "CAS delta reserved tail bytes")
    require(u64(payload, 0x90) == len(payload), "CAS delta encoded length is invalid")
    has_blob = flags == DELTA_FLAG_NEW_BLOB and len(payload) == CAS_DELTA_NEW_BLOB_LEN
    require(has_blob or (flags == 0 and len(payload) == CAS_DELTA_REUSE_LEN), "CAS delta flags and length disagree")

    if chain_count == 1:
        require_zero(payload, 0x30, 0x90, "first CAS delta previous pointer")
        previous = {"status": "null"}
    else:
        previous = context_pointer(
            payload[0x30:0x90], context, EXTENT_CATALOG_DELTA, "CAS delta previous pointer"
        )
        require(
            previous["exact_byte_len"] in (CAS_DELTA_REUSE_LEN, CAS_DELTA_NEW_BLOB_LEN),
            "CAS delta previous pointer length is invalid",
        )
    obj = parse_object_mapping(payload[0xA0:0x100], generation, "CAS delta object")
    require(obj["commit_generation"] == generation, "CAS delta object generation mismatch")
    new_blob = (
        parse_blob_mapping(payload[0x100:0x1A0], context, "CAS delta new Blob") if has_blob else None
    )
    if new_blob is not None:
        require(blob_key_identity(new_blob["blob_key"]) == blob_key_identity(obj["blob_key"]), "CAS delta new Blob key mismatch")
        if previous["status"] == "value":
            require(not pointer_conflict(previous, new_blob["manifest"]), "CAS delta pointers overlap")
    return {
        "checkpoint_generation": generation,
        "chain_count": chain_count,
        "previous": previous,
        "object": obj,
        "new_blob": new_blob,
    }


def parse_blob_manifest(payload: bytes, context: dict[str, Any]) -> dict[str, Any]:
    require(BLOB_MANIFEST_HEADER_LEN <= len(payload) <= MAX_EXTENT_BYTES, "Blob manifest length is invalid")
    require(payload[0:8] == BLOB_MANIFEST_MAGIC, "Blob manifest magic is invalid")
    require(u16(payload, 0x08) == CAS_VERSION, "Blob manifest version is invalid")
    require(u16(payload, 0x0A) == BLOB_MANIFEST_HEADER_LEN, "Blob manifest header length is invalid")
    require(u16(payload, 0x0C) == MANIFEST_EXTENT_LEN, "Blob manifest entry size is invalid")
    require(u16(payload, 0x0E) == 0, "Blob manifest header flags must be zero")
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
    require(encoded_blob_len == geometry["encoded_len"], "Blob manifest encoded Blob length is not canonical")

    content_extent_count = (key["exact_len"] + CANONICAL_CONTENT_EXTENT_LEN - 1) // CANONICAL_CONTENT_EXTENT_LEN
    require(count == content_extent_count + 2, "Blob manifest extent count is not canonical")

    extents = []
    expected_offset = 0
    pointers = []
    for index in range(count):
        offset = BLOB_MANIFEST_HEADER_LEN + index * MANIFEST_EXTENT_LEN
        raw = payload[offset : offset + MANIFEST_EXTENT_LEN]
        require_zero(raw, 0x78, 0x80, f"Blob manifest extent[{index}] reserved bytes")
        pointer = context_pointer(raw[0x18:0x78], context, EXTENT_BLOB, f"Blob manifest extent[{index}] pointer")
        extent = {
            "extent_index": u32(raw, 0x00),
            "extent_count": u32(raw, 0x04),
            "encoded_offset": u64(raw, 0x08),
            "payload_byte_len": u64(raw, 0x10),
            "pointer": pointer,
        }
        require(extent["extent_index"] == index, f"Blob manifest extent[{index}] index is invalid")
        require(extent["extent_count"] == count, f"Blob manifest extent[{index}] count is invalid")
        require(extent["encoded_offset"] == expected_offset, f"Blob manifest extent[{index}] leaves a gap or overlap")
        if index == 0:
            canonical_len = BLOB_HEADER_LEN
        elif index <= content_extent_count:
            canonical_len = min(
                CANONICAL_CONTENT_EXTENT_LEN,
                key["exact_len"] - (index - 1) * CANONICAL_CONTENT_EXTENT_LEN,
            )
        else:
            canonical_len = geometry["tree_len"]
        require(
            extent["payload_byte_len"] == canonical_len,
            f"Blob manifest extent[{index}] split is not canonical",
        )
        require(pointer["exact_byte_len"] == extent["payload_byte_len"], f"Blob manifest extent[{index}] pointer length mismatch")
        for previous in pointers:
            require(not pointer_conflict(previous, pointer), "Blob manifest physical pointers overlap")
        pointers.append(pointer)
        expected_offset += extent["payload_byte_len"]
        extents.append(extent)
    require(expected_offset == encoded_blob_len, "Blob manifest extents do not exactly cover the canonical Blob")
    return {"blob_key": key, "encoded_blob_len": encoded_blob_len, "extents": extents}


def leaf_hash(object_kind: int, index: int, chunk: bytes) -> bytes:
    return sha256(
        LEAF_DOMAIN
        + struct.pack("<I", object_kind)
        + struct.pack("<I", index)
        + struct.pack("<I", len(chunk))
        + chunk
    )


def empty_hash(object_kind: int, index: int) -> bytes:
    return sha256(EMPTY_DOMAIN + struct.pack("<I", object_kind) + struct.pack("<I", index))


def node_hash(level: int, left: bytes, right: bytes) -> bytes:
    return sha256(NODE_DOMAIN + struct.pack("<I", level) + left + right)


def verify_canonical_blob(encoded: bytes, expected_key: dict[str, Any]) -> dict[str, Any]:
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
    tree_bytes = encoded[geometry["tree_offset"] :]
    tree = []
    for index in range(geometry["padded_leaves"]):
        if index < geometry["leaf_count"]:
            start = index * BLOB_LEAF_SIZE
            chunk = content[start : min(start + BLOB_LEAF_SIZE, len(content))]
            tree.append(leaf_hash(expected_key["object_kind"], index, chunk))
        else:
            tree.append(empty_hash(expected_key["object_kind"], index))
    level_base = 0
    level_width = geometry["padded_leaves"]
    level = 1
    while level_width > 1:
        for offset in range(0, level_width, 2):
            tree.append(node_hash(level, tree[level_base + offset], tree[level_base + offset + 1]))
        level_base += level_width
        level_width //= 2
        level += 1
    expected_tree = b"".join(tree)
    require(tree_bytes == expected_tree, "canonical Blob Merkle tree bytes are invalid")
    root = sha256(
        ROOT_DOMAIN
        + struct.pack("<I", expected_key["object_kind"])
        + struct.pack("<Q", expected_key["exact_len"])
        + struct.pack("<I", BLOB_LEAF_SIZE)
        + struct.pack("<I", geometry["leaf_count"])
        + tree[-1]
    )
    require(root == declared_root, "canonical Blob Merkle root is invalid")
    return {
        "encoded_sha256": sha256(encoded),
        "content_sha256": sha256(content),
        "tree_node_count": geometry["node_count"],
    }


class ImageResolver:
    def __init__(self, image: Any, checkpoint: dict[str, Any], segments: list[dict[str, Any]]):
        self.image = image
        self.checkpoint = checkpoint
        self.segments = segments

    def resolve(self, pointer: dict[str, Any], expected_kind: int, label: str) -> tuple[dict[str, Any], bytes]:
        errors: list[str] = []
        extent = storage.resolve_extent_pointer(self.checkpoint, label, pointer, self.segments, errors)
        require(not errors and extent is not None, errors[0] if errors else f"{label} cannot be resolved")
        require(extent["extent_kind"] == expected_kind, f"{label} resolves to the wrong extent kind")
        payload = storage.read_exact_extent_payload(self.image, extent)
        return extent, payload


def validate_metadata_extent(extent: dict[str, Any], label: str) -> None:
    storage.require_single_extent_payload(extent, label)


def reconstruct_cas(
    checkpoint: dict[str, Any],
    resolver: Any,
    *,
    verify_blob_bytes: bool,
) -> dict[str, Any]:
    cp = checkpoint["record"] if "record" in checkpoint else checkpoint
    generation = cp["binding"]["generation"]
    context = {
        "store_uuid": cp["binding"]["store_uuid"],
        "admitted_segments": cp["admitted_segments"],
        "next_segment_generation": cp["next_segment_generation"],
    }

    objects: dict[int, dict[str, Any]] = {}
    blobs: dict[tuple[int, int, int, bytes], dict[str, Any]] = {}
    snapshot_generation = 0
    snapshot_pointer = cp["catalog_root"]
    if snapshot_pointer["status"] == "value":
        extent, payload = resolver.resolve(snapshot_pointer, EXTENT_CATALOG, "CAS snapshot")
        validate_metadata_extent(extent, "CAS snapshot")
        snapshot = parse_cas_snapshot(payload, context)
        require(snapshot["checkpoint_generation"] <= generation, "CAS snapshot is newer than checkpoint")
        require(
            snapshot["checkpoint_generation"] == extent["binding"]["target_checkpoint_generation"],
            "CAS snapshot generation differs from extent target",
        )
        snapshot_generation = snapshot["checkpoint_generation"]
        for obj in snapshot["objects"]:
            objects[obj["object_id"]] = obj
        for blob in snapshot["blobs"]:
            blobs[blob_key_identity(blob["blob_key"])] = blob

    reverse_deltas = []
    pointer = cp["replay_tail"]
    expected_depth = cp["replay_count"]
    seen = set()
    while expected_depth:
        require(pointer["status"] == "value", "CAS replay chain ended early")
        identity = storage.pointer_identity(pointer)
        require(identity not in seen, "CAS replay chain contains a cycle")
        seen.add(identity)
        extent, payload = resolver.resolve(pointer, EXTENT_CATALOG_DELTA, f"CAS delta[{expected_depth}]")
        validate_metadata_extent(extent, f"CAS delta[{expected_depth}]")
        delta = parse_cas_delta(payload, context)
        require(delta["chain_count"] == expected_depth, "CAS delta chain count disagrees with checkpoint")
        require(delta["checkpoint_generation"] <= generation, "CAS delta is newer than checkpoint")
        require(
            delta["checkpoint_generation"] == extent["binding"]["target_checkpoint_generation"],
            "CAS delta generation differs from extent target",
        )
        reverse_deltas.append(delta)
        pointer = delta["previous"]
        expected_depth -= 1
    require(pointer["status"] == "null", "CAS replay chain exceeds checkpoint replay count")

    previous_generation = snapshot_generation
    previous_object = max(objects, default=0)
    for delta in reversed(reverse_deltas):
        require(delta["checkpoint_generation"] > previous_generation, "CAS delta generations are not increasing")
        previous_generation = delta["checkpoint_generation"]
        obj = delta["object"]
        require(obj["object_id"] > previous_object, "CAS delta object IDs are not increasing")
        require(obj["object_id"] not in objects, "CAS replay duplicates an object ID")
        new_blob = delta["new_blob"]
        key_id = blob_key_identity(obj["blob_key"])
        if new_blob is None:
            require(key_id in blobs, "CAS deduplicated object references a missing Blob")
        else:
            require(key_id not in blobs, "CAS delta republishes an existing BlobKey")
            blobs[key_id] = new_blob
        objects[obj["object_id"]] = obj
        previous_object = obj["object_id"]
    require(
        all(blob_key_identity(obj["blob_key"]) in blobs for obj in objects.values()),
        "CAS object index references a missing Blob",
    )

    physical_pointers: list[dict[str, Any]] = []
    blob_results = []
    for key_id in sorted(blobs):
        mapping = blobs[key_id]
        key = mapping["blob_key"]
        manifest_pointer = mapping["manifest"]
        for previous in physical_pointers:
            require(not pointer_conflict(previous, manifest_pointer), "CAS physical metadata pointers overlap")
        physical_pointers.append(manifest_pointer)
        manifest_extent, manifest_payload = resolver.resolve(manifest_pointer, EXTENT_CATALOG, "Blob manifest")
        validate_metadata_extent(manifest_extent, "Blob manifest")
        manifest = parse_blob_manifest(manifest_payload, context)
        require(blob_key_identity(manifest["blob_key"]) == key_id, "Blob mapping and manifest keys disagree")

        encoded = bytearray()
        for item in manifest["extents"]:
            pointer = item["pointer"]
            for previous in physical_pointers:
                require(not pointer_conflict(previous, pointer), "CAS physical Blob pointers overlap")
            physical_pointers.append(pointer)
            extent, payload = resolver.resolve(pointer, EXTENT_BLOB, "canonical Blob extent")
            expected_shape = (
                key["object_kind"],
                item["extent_index"],
                item["extent_count"],
                key["exact_len"],
                manifest["encoded_blob_len"],
                item["encoded_offset"],
                item["payload_byte_len"],
                key["merkle_root"],
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
            require(len(payload) == item["payload_byte_len"], "canonical Blob extent payload length mismatch")
            encoded.extend(payload)
        require(len(encoded) == manifest["encoded_blob_len"], "reconstructed canonical Blob length mismatch")
        verification = verify_canonical_blob(bytes(encoded), key) if verify_blob_bytes else {}
        blob_results.append(
            {
                "blob_key": key,
                "manifest": manifest_pointer,
                "extent_count": len(manifest["extents"]),
                "extents": manifest["extents"],
                "encoded_blob_len": manifest["encoded_blob_len"],
                **verification,
            }
        )

    object_results = [
        {
            "object_id": obj["object_id"].to_bytes(16, "little"),
            "commit_generation": obj["commit_generation"],
            "blob_key": obj["blob_key"],
        }
        for obj in sorted(objects.values(), key=lambda item: item["object_id"])
    ]
    return {
        "checkpoint_generation": generation,
        "object_count": len(object_results),
        "blob_count": len(blob_results),
        "deduplicated_references": len(object_results) - len(blob_results),
        "objects": object_results,
        "blobs": blob_results,
        "blob_bytes_verified": verify_blob_bytes,
    }


def parse_structural_image(image: Any) -> dict[str, Any]:
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
    selected_super = storage.select_superblock(superblocks, errors)
    selected_checkpoint = storage.select_checkpoint(checkpoints, errors)
    physical_segments = max(0, (page_count - storage.ANCHOR_PAGES) // storage.SEGMENT_PAGES)
    trailing = max(0, page_count - storage.ANCHOR_PAGES) % storage.SEGMENT_PAGES
    if page_count >= storage.ANCHOR_PAGES and trailing:
        errors.append("image has a partial data segment")
    segments = [storage.parse_segment(image, number, errors) for number in range(physical_segments)]
    if selected_super is None:
        errors.append("image has no selected sealed superblock")
    else:
        for checkpoint in (entry for entry in checkpoints if entry["status"] == "sealed"):
            storage.verify_checkpoint_against_superblock(
                checkpoint, selected_super, physical_segments, segments, errors
            )
    if selected_checkpoint is None:
        errors.append("image has no selected sealed checkpoint")
    return {
        "errors": errors,
        "selected_checkpoint": selected_checkpoint,
        "segments": segments,
        "physical_segments": physical_segments,
    }


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, tuple):
        return [json_value(item) for item in value]
    return value


def verify_image(image: Any, verify_blob_bytes: bool = True) -> dict[str, Any]:
    structural = parse_structural_image(image)
    errors = list(structural["errors"])
    cas = None
    checkpoint = structural["selected_checkpoint"]
    if checkpoint is not None:
        try:
            cas = reconstruct_cas(
                checkpoint,
                ImageResolver(image, checkpoint, structural["segments"]),
                verify_blob_bytes=verify_blob_bytes,
            )
        except Violation as exc:
            errors.append(f"CAS: {exc}")
    return json_value(
        {
            "format": "vibeos-storage-v2-cas",
            "version": CAS_VERSION,
            "status": "ok" if not errors else "corrupt",
            "image": {
                "byte_length": len(image),
                "physical_segment_count": structural["physical_segments"],
            },
            "cas": cas,
            "errors": sorted(set(errors)),
        }
    )


def read_abi_fixture(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Parse one Rust-produced payload bundle without requiring a disk image.

    Bundle version 1 is a directory containing ``context.json``,
    ``snapshot.bin``, ``manifest.bin``, ``delta-new.bin`` and
    ``delta-reuse.bin``. Context JSON contains the store UUID as 32 lowercase
    hex digits plus admitted/next-generation integers. It also names the
    expected BlobKey and the expected object IDs, allowing this verifier to
    check relations across independently decoded payloads.
    """

    root = Path(path)
    require(root.is_dir(), "ABI fixture path is not a directory")
    try:
        metadata = json.loads((root / "context.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Violation(f"ABI fixture context cannot be read: {exc}") from exc
    require(metadata.get("format") == "vibeos-storage-v2-cas-abi", "ABI fixture format is invalid")
    require(metadata.get("version") == 1, "ABI fixture version is invalid")
    uuid_hex = metadata.get("store_uuid")
    require(isinstance(uuid_hex, str) and len(uuid_hex) == 32, "ABI fixture UUID is invalid")
    try:
        store_uuid = bytes.fromhex(uuid_hex)
    except ValueError as exc:
        raise Violation("ABI fixture UUID is not hexadecimal") from exc
    require(len(store_uuid) == 16 and not zero(store_uuid), "ABI fixture UUID is invalid")
    context = {
        "store_uuid": store_uuid,
        "admitted_segments": metadata.get("admitted_segments"),
        "next_segment_generation": metadata.get("next_segment_generation"),
    }
    require(
        isinstance(context["admitted_segments"], int) and context["admitted_segments"] > 0,
        "ABI fixture admitted segment count is invalid",
    )
    require(
        isinstance(context["next_segment_generation"], int)
        and context["next_segment_generation"] > 0,
        "ABI fixture next segment generation is invalid",
    )

    def payload(name: str) -> bytes:
        try:
            value = (root / name).read_bytes()
        except OSError as exc:
            raise Violation(f"ABI fixture {name} cannot be read: {exc}") from exc
        require(len(value) <= MAX_EXTENT_BYTES, f"ABI fixture {name} is too large")
        return value

    snapshot = parse_cas_snapshot(payload("snapshot.bin"), context)
    manifest = parse_blob_manifest(payload("manifest.bin"), context)
    delta_new = parse_cas_delta(payload("delta-new.bin"), context)
    delta_reuse = parse_cas_delta(payload("delta-reuse.bin"), context)
    require(delta_new["new_blob"] is not None, "ABI fixture delta-new has no Blob mapping")
    require(delta_reuse["new_blob"] is None, "ABI fixture delta-reuse unexpectedly has a Blob mapping")
    require(delta_new["chain_count"] == 1, "ABI fixture first delta chain count is invalid")
    require(delta_reuse["chain_count"] == 2, "ABI fixture reuse delta chain count is invalid")
    require(
        snapshot["checkpoint_generation"] == delta_new["checkpoint_generation"],
        "ABI fixture snapshot and new delta generations disagree",
    )
    require(
        delta_reuse["checkpoint_generation"] == delta_new["checkpoint_generation"] + 1,
        "ABI fixture delta generations are not contiguous",
    )

    expected_key = parse_blob_key(bytes.fromhex(metadata["blob_key"]), "ABI fixture expected BlobKey")
    expected_id = blob_key_identity(expected_key)
    require(blob_key_identity(manifest["blob_key"]) == expected_id, "ABI fixture manifest key mismatch")
    require(blob_key_identity(delta_new["object"]["blob_key"]) == expected_id, "ABI fixture new object key mismatch")
    require(blob_key_identity(delta_reuse["object"]["blob_key"]) == expected_id, "ABI fixture reuse object key mismatch")
    require(blob_key_identity(delta_new["new_blob"]["blob_key"]) == expected_id, "ABI fixture new Blob key mismatch")
    require(
        blob_key_identity(delta_new["new_blob"]["blob_key"])
        in {blob_key_identity(blob["blob_key"]) for blob in snapshot["blobs"]},
        "ABI fixture snapshot omits the produced Blob",
    )
    require(
        delta_new["new_blob"]["manifest"] == snapshot["blobs"][0]["manifest"],
        "ABI fixture snapshot and new delta manifest pointers disagree",
    )
    require(
        delta_reuse["previous"]["status"] == "value",
        "ABI fixture reuse delta has no previous pointer",
    )
    expected_object_ids = metadata.get("object_ids")
    require(
        isinstance(expected_object_ids, list)
        and len(expected_object_ids) == 2
        and all(isinstance(value, str) and len(value) == 32 for value in expected_object_ids),
        "ABI fixture object IDs are invalid",
    )
    observed_ids = [
        delta_new["object"]["object_id"].to_bytes(16, "little").hex(),
        delta_reuse["object"]["object_id"].to_bytes(16, "little").hex(),
    ]
    require(observed_ids == expected_object_ids, "ABI fixture object IDs disagree with context")
    return json_value(
        {
            "format": "vibeos-storage-v2-cas-abi",
            "version": 1,
            "status": "ok",
            "snapshot": {
                "checkpoint_generation": snapshot["checkpoint_generation"],
                "object_count": len(snapshot["objects"]),
                "blob_count": len(snapshot["blobs"]),
            },
            "manifest": {
                "blob_key": manifest["blob_key"],
                "encoded_blob_len": manifest["encoded_blob_len"],
                "extent_count": len(manifest["extents"]),
            },
            "deltas": {
                "new_object_id": observed_ids[0],
                "reuse_object_id": observed_ids[1],
            },
        }
    )


# Selftest encoders intentionally duplicate literal media offsets as a second
# implementation of the Rust codec.
def encode_blob_key_fixture(key: dict[str, Any]) -> bytes:
    out = bytearray(BLOB_KEY_LEN)
    put_u16(out, 0x00, key["hash_algorithm"])
    put_u32(out, 0x04, key["object_kind"])
    put_u64(out, 0x08, key["exact_len"])
    out[0x10:0x30] = key["merkle_root"]
    return bytes(out)


def encode_pointer_fixture(pointer: dict[str, Any]) -> bytes:
    if pointer["status"] == "null":
        return bytes(storage.POINTER_SIZE)
    out = bytearray(storage.POINTER_SIZE)
    out[0x00:0x10] = pointer["store_uuid"]
    put_u64(out, 0x10, pointer["segment_no"])
    put_u64(out, 0x18, pointer["segment_generation"])
    put_u32(out, 0x20, pointer["descriptor_relative_page"])
    put_u32(out, 0x24, pointer["payload_relative_page"])
    put_u32(out, 0x28, pointer["payload_pages"])
    put_u32(out, 0x2C, pointer["ordinal"])
    put_u64(out, 0x30, pointer["exact_byte_len"])
    put_u16(out, 0x38, pointer["extent_kind"])
    put_u16(out, 0x3A, HASH_ALGORITHM_SHA256)
    out[0x40:0x60] = pointer["payload_sha256"]
    return bytes(out)


def make_pointer(
    context: dict[str, Any], segment: int, generation: int, length: int, kind: int, digest: bytes
) -> dict[str, Any]:
    return {
        "status": "value",
        "store_uuid": context["store_uuid"],
        "segment_no": segment,
        "segment_generation": generation,
        "descriptor_relative_page": 2,
        "payload_relative_page": 4,
        "payload_pages": (length + PAGE_SIZE - 1) // PAGE_SIZE,
        "ordinal": 1,
        "exact_byte_len": length,
        "extent_kind": kind,
        "hash_algorithm": HASH_ALGORITHM_SHA256,
        "payload_sha256": digest,
    }


def encode_canonical_blob_fixture(object_kind: int, content: bytes) -> tuple[dict[str, Any], bytes]:
    geometry = canonical_blob_geometry(len(content))
    tree = []
    for index in range(geometry["padded_leaves"]):
        if index < geometry["leaf_count"]:
            start = index * BLOB_LEAF_SIZE
            tree.append(leaf_hash(object_kind, index, content[start : start + BLOB_LEAF_SIZE]))
        else:
            tree.append(empty_hash(object_kind, index))
    base = 0
    width = geometry["padded_leaves"]
    level = 1
    while width > 1:
        for offset in range(0, width, 2):
            tree.append(node_hash(level, tree[base + offset], tree[base + offset + 1]))
        base += width
        width //= 2
        level += 1
    root = sha256(
        ROOT_DOMAIN
        + struct.pack("<I", object_kind)
        + struct.pack("<Q", len(content))
        + struct.pack("<I", BLOB_LEAF_SIZE)
        + struct.pack("<I", geometry["leaf_count"])
        + tree[-1]
    )
    key = {
        "hash_algorithm": HASH_ALGORITHM_SHA256,
        "object_kind": object_kind,
        "exact_len": len(content),
        "merkle_root": root,
    }
    header = bytearray(BLOB_HEADER_LEN)
    header[0:8] = BLOB_MAGIC
    put_u16(header, 0x08, BLOB_VERSION)
    put_u16(header, 0x0A, BLOB_HEADER_LEN)
    put_u16(header, 0x0C, HASH_ALGORITHM_SHA256)
    header[0x0E] = BLOB_LEAF_LOG2
    put_u32(header, 0x10, object_kind)
    put_u64(header, 0x18, len(content))
    put_u32(header, 0x20, geometry["leaf_count"])
    put_u32(header, 0x24, geometry["node_count"])
    header[0x28:0x48] = root
    put_u64(header, 0x48, BLOB_HEADER_LEN)
    put_u64(header, 0x50, geometry["tree_offset"])
    put_u64(header, 0x58, geometry["encoded_len"])
    return key, bytes(header) + content + b"".join(tree)


def encode_manifest_fixture(key: dict[str, Any], pointers: list[dict[str, Any]]) -> bytes:
    encoded_len = canonical_blob_geometry(key["exact_len"])["encoded_len"]
    out = bytearray(BLOB_MANIFEST_HEADER_LEN + len(pointers) * MANIFEST_EXTENT_LEN)
    out[0:8] = BLOB_MANIFEST_MAGIC
    put_u16(out, 0x08, CAS_VERSION)
    put_u16(out, 0x0A, BLOB_MANIFEST_HEADER_LEN)
    put_u16(out, 0x0C, MANIFEST_EXTENT_LEN)
    out[0x10:0x50] = encode_blob_key_fixture(key)
    put_u64(out, 0x50, encoded_len)
    put_u32(out, 0x58, len(pointers))
    put_u64(out, 0x60, BLOB_MANIFEST_HEADER_LEN)
    put_u64(out, 0x68, len(out))
    offset = 0
    for index, pointer in enumerate(pointers):
        base = BLOB_MANIFEST_HEADER_LEN + index * MANIFEST_EXTENT_LEN
        put_u32(out, base + 0x00, index)
        put_u32(out, base + 0x04, len(pointers))
        put_u64(out, base + 0x08, offset)
        put_u64(out, base + 0x10, pointer["exact_byte_len"])
        out[base + 0x18 : base + 0x78] = encode_pointer_fixture(pointer)
        offset += pointer["exact_byte_len"]
    require(offset == encoded_len, "selftest manifest split is invalid")
    return bytes(out)


def canonical_blob_chunks(key: dict[str, Any], encoded: bytes) -> list[bytes]:
    geometry = canonical_blob_geometry(key["exact_len"])
    chunks = [encoded[:BLOB_HEADER_LEN]]
    content_start = BLOB_HEADER_LEN
    content_end = geometry["tree_offset"]
    for offset in range(content_start, content_end, CANONICAL_CONTENT_EXTENT_LEN):
        chunks.append(encoded[offset : min(offset + CANONICAL_CONTENT_EXTENT_LEN, content_end)])
    chunks.append(encoded[content_end:])
    return chunks


def encode_object_fixture(object_id: int, key: dict[str, Any], generation: int) -> bytes:
    out = bytearray(OBJECT_MAPPING_LEN)
    out[0:16] = object_id.to_bytes(16, "little")
    out[0x10:0x50] = encode_blob_key_fixture(key)
    put_u64(out, 0x50, generation)
    return bytes(out)


def encode_blob_mapping_fixture(key: dict[str, Any], manifest: dict[str, Any]) -> bytes:
    return encode_blob_key_fixture(key) + encode_pointer_fixture(manifest)


def encode_snapshot_fixture(
    generation: int,
    objects: list[tuple[int, dict[str, Any], int]],
    blobs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> bytes:
    blob_offset = CAS_SNAPSHOT_HEADER_LEN + len(objects) * OBJECT_MAPPING_LEN
    out = bytearray(blob_offset + len(blobs) * BLOB_MAPPING_LEN)
    out[0:8] = CAS_MAGIC
    put_u16(out, 0x08, CAS_VERSION)
    put_u16(out, 0x0A, CAS_KIND_SNAPSHOT)
    put_u32(out, 0x0C, CAS_SNAPSHOT_HEADER_LEN)
    put_u64(out, 0x10, generation)
    put_u32(out, 0x18, len(objects))
    put_u32(out, 0x1C, len(blobs))
    put_u32(out, 0x20, OBJECT_MAPPING_LEN)
    put_u32(out, 0x24, BLOB_MAPPING_LEN)
    put_u64(out, 0x28, CAS_SNAPSHOT_HEADER_LEN)
    put_u64(out, 0x30, blob_offset)
    put_u64(out, 0x38, len(out))
    for index, item in enumerate(objects):
        start = CAS_SNAPSHOT_HEADER_LEN + index * OBJECT_MAPPING_LEN
        out[start : start + OBJECT_MAPPING_LEN] = encode_object_fixture(*item)
    for index, (key, pointer) in enumerate(blobs):
        start = blob_offset + index * BLOB_MAPPING_LEN
        out[start : start + BLOB_MAPPING_LEN] = encode_blob_mapping_fixture(key, pointer)
    return bytes(out)


def encode_delta_fixture(
    generation: int,
    chain_count: int,
    previous: dict[str, Any],
    object_id: int,
    key: dict[str, Any],
    new_blob: Optional[dict[str, Any]] = None,
) -> bytes:
    out = bytearray(CAS_DELTA_NEW_BLOB_LEN if new_blob is not None else CAS_DELTA_REUSE_LEN)
    out[0:8] = CAS_MAGIC
    put_u16(out, 0x08, CAS_VERSION)
    put_u16(out, 0x0A, CAS_KIND_DELTA)
    put_u32(out, 0x0C, CAS_DELTA_HEADER_LEN)
    put_u64(out, 0x10, generation)
    put_u32(out, 0x18, chain_count)
    put_u32(out, 0x1C, DELTA_FLAG_NEW_BLOB if new_blob is not None else 0)
    put_u32(out, 0x20, OBJECT_MAPPING_LEN)
    put_u32(out, 0x24, BLOB_MAPPING_LEN)
    if chain_count > 1:
        out[0x30:0x90] = encode_pointer_fixture(previous)
    put_u64(out, 0x90, len(out))
    out[0xA0:0x100] = encode_object_fixture(object_id, key, generation)
    if new_blob is not None:
        out[0x100:0x1A0] = encode_blob_mapping_fixture(key, new_blob)
    return bytes(out)


def fixture_extent(pointer: dict[str, Any], key: Optional[dict[str, Any]], target: int) -> dict[str, Any]:
    extent = {
        "binding": {
            "store_uuid": pointer["store_uuid"],
            "generation": pointer["segment_generation"],
            "segment_no": pointer["segment_no"],
            "ordinal": pointer["ordinal"],
            "target_checkpoint_generation": target,
        },
        "extent_kind": pointer["extent_kind"],
        "object_kind": 0xFFFF0001,
        "extent_index": 0,
        "extent_count": 1,
        "content_byte_len": pointer["exact_byte_len"],
        "encoded_blob_len": pointer["exact_byte_len"],
        "encoded_offset": 0,
        "payload_byte_len": pointer["exact_byte_len"],
        "payload_first_relative_page": pointer["payload_relative_page"],
        "payload_pages": pointer["payload_pages"],
        "merkle_root": pointer["payload_sha256"],
        "payload_sha256": pointer["payload_sha256"],
    }
    if key is not None:
        extent.update(
            {
                "object_kind": key["object_kind"],
                "content_byte_len": key["exact_len"],
                "merkle_root": key["merkle_root"],
            }
        )
    return extent


class FixtureResolver:
    def __init__(self) -> None:
        self.items: dict[tuple[int, int, int, int], tuple[dict[str, Any], bytes]] = {}

    def add(self, pointer: dict[str, Any], payload: bytes, extent: dict[str, Any]) -> None:
        self.items[storage.pointer_identity(pointer)] = (extent, payload)

    def resolve(self, pointer: dict[str, Any], expected_kind: int, label: str) -> tuple[dict[str, Any], bytes]:
        require(pointer["extent_kind"] == expected_kind, f"{label} fixture kind mismatch")
        item = self.items.get(storage.pointer_identity(pointer))
        require(item is not None, f"{label} fixture pointer is missing")
        return item


def make_cas_fixture(*, bad_tree: bool = False) -> tuple[dict[str, Any], FixtureResolver, dict[str, Any]]:
    context = {"store_uuid": bytes([7]) * 16, "admitted_segments": 128, "next_segment_generation": 200}
    content = bytes((index * 37 + 9) % 251 for index in range(BLOB_LEAF_SIZE + 17))
    key, canonical = encode_canonical_blob_fixture(0x424C4F42, content)
    if bad_tree:
        mutated = bytearray(canonical)
        mutated[-1] ^= 1
        canonical = bytes(mutated)
    chunks = canonical_blob_chunks(key, canonical)
    blob_pointers = [
        make_pointer(context, index + 1, index + 10, len(chunk), EXTENT_BLOB, sha256(chunk))
        for index, chunk in enumerate(chunks)
    ]
    manifest_payload = encode_manifest_fixture(key, blob_pointers)
    metadata_segment = len(chunks) + 1
    manifest_pointer = make_pointer(context, metadata_segment, 50, len(manifest_payload), EXTENT_CATALOG, sha256(manifest_payload))
    snapshot_payload = encode_snapshot_fixture(1, [(1, key, 1)], [(key, manifest_pointer)])
    snapshot_pointer = make_pointer(context, metadata_segment + 1, 51, len(snapshot_payload), EXTENT_CATALOG, sha256(snapshot_payload))
    delta_payload = encode_delta_fixture(2, 1, {"status": "null"}, 2, key)
    delta_pointer = make_pointer(context, metadata_segment + 2, 52, len(delta_payload), EXTENT_CATALOG_DELTA, sha256(delta_payload))

    resolver = FixtureResolver()
    encoded_offset = 0
    for pointer, chunk in zip(blob_pointers, chunks):
        extent = fixture_extent(pointer, key, 1)
        extent["extent_index"] = len(resolver.items)
        extent["extent_count"] = len(chunks)
        extent["encoded_offset"] = encoded_offset
        extent["encoded_blob_len"] = len(canonical)
        extent["payload_byte_len"] = len(chunk)
        resolver.add(pointer, chunk, extent)
        encoded_offset += len(chunk)
    resolver.add(manifest_pointer, manifest_payload, fixture_extent(manifest_pointer, None, 1))
    resolver.add(snapshot_pointer, snapshot_payload, fixture_extent(snapshot_pointer, None, 1))
    resolver.add(delta_pointer, delta_payload, fixture_extent(delta_pointer, None, 2))
    checkpoint = {
        "binding": {"store_uuid": context["store_uuid"], "generation": 2},
        "admitted_segments": context["admitted_segments"],
        "next_segment_generation": context["next_segment_generation"],
        "replay_count": 1,
        "catalog_root": snapshot_pointer,
        "replay_tail": delta_pointer,
    }
    return checkpoint, resolver, {"context": context, "manifest": manifest_payload, "snapshot": snapshot_payload}


def expect_violation(action: Any, label: str) -> None:
    try:
        action()
    except Violation:
        return
    raise Violation(f"selftest {label} was accepted")


def run_selftest() -> dict[str, Any]:
    tests = []
    checkpoint, resolver, fixture = make_cas_fixture()
    result = reconstruct_cas(checkpoint, resolver, verify_blob_bytes=True)
    require(result["object_count"] == 2, "dedup selftest lost an object")
    require(result["blob_count"] == 1, "dedup selftest stored a duplicate Blob")
    require(result["deduplicated_references"] == 1, "dedup selftest count is wrong")
    tests.append("duplicate-object-same-blob")

    gap = bytearray(fixture["manifest"])
    second = BLOB_MANIFEST_HEADER_LEN + MANIFEST_EXTENT_LEN
    put_u64(gap, second + 0x08, u64(gap, second + 0x08) + 1)
    expect_violation(lambda: parse_blob_manifest(bytes(gap), fixture["context"]), "manifest-gap")
    tests.append("gap")

    overlap = bytearray(fixture["manifest"])
    second_len = u64(overlap, second + 0x10)
    overlap[second + 0x18 : second + 0x78] = overlap[BLOB_MANIFEST_HEADER_LEN + 0x18 : BLOB_MANIFEST_HEADER_LEN + 0x78]
    put_u64(overlap, second + 0x08, 2300)
    put_u64(overlap, second + 0x10, second_len)
    put_u64(overlap, second + 0x18 + 0x30, second_len)
    put_u32(overlap, second + 0x18 + 0x28, (second_len + PAGE_SIZE - 1) // PAGE_SIZE)
    expect_violation(lambda: parse_blob_manifest(bytes(overlap), fixture["context"]), "pointer-overlap")
    tests.append("overlap")

    noncanonical = bytearray(fixture["manifest"])
    first_content = BLOB_MANIFEST_HEADER_LEN + MANIFEST_EXTENT_LEN
    put_u64(noncanonical, first_content + 0x10, u64(noncanonical, first_content + 0x10) - 1)
    expect_violation(
        lambda: parse_blob_manifest(bytes(noncanonical), fixture["context"]),
        "noncanonical-split",
    )
    tests.append("noncanonical-split")

    reserved = bytearray(fixture["snapshot"])
    reserved[0x40] = 1
    expect_violation(lambda: parse_cas_snapshot(bytes(reserved), fixture["context"]), "reserved")
    tests.append("bad-reserved")

    bad_checkpoint, bad_resolver, _ = make_cas_fixture(bad_tree=True)
    expect_violation(
        lambda: reconstruct_cas(bad_checkpoint, bad_resolver, verify_blob_bytes=True),
        "bad-tree",
    )
    tests.append("bad-tree")
    return {"selftest": "ok", "tests": tests}


def dump_json(value: dict[str, Any], pretty: bool) -> None:
    print(json.dumps(value, indent=2 if pretty else None, sort_keys=True, separators=None if pretty else (",", ":")))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", help="raw Storage V2 image to verify")
    parser.add_argument("--selftest", action="store_true", help="run independent synthetic CAS fixtures")
    parser.add_argument("--abi-fixture", metavar="PATH", help="verify a Rust-produced CAS payload bundle")
    parser.add_argument("--metadata-only", action="store_true", help="skip full canonical Blob Merkle reconstruction")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args(argv)
    if args.selftest:
        if args.image is not None or args.abi_fixture is not None:
            parser.error("--selftest does not accept an image or --abi-fixture")
        try:
            dump_json(run_selftest(), args.pretty)
            return 0
        except (Violation, OSError, ValueError) as exc:
            dump_json({"selftest": "failed", "error": str(exc)}, args.pretty)
            return 1
    if args.abi_fixture is not None:
        if args.image is not None:
            parser.error("--abi-fixture does not accept an image")
        try:
            dump_json(read_abi_fixture(args.abi_fixture), args.pretty)
            return 0
        except (Violation, OSError, ValueError, KeyError) as exc:
            dump_json(
                {"format": "vibeos-storage-v2-cas-abi", "status": "corrupt", "errors": [str(exc)]},
                args.pretty,
            )
            return 1
    if args.image is None:
        parser.error("an image path or --selftest is required")
    try:
        with open(args.image, "rb") as image_file:
            if os.fstat(image_file.fileno()).st_size == 0:
                result = verify_image(b"", not args.metadata_only)
            else:
                with mmap.mmap(image_file.fileno(), 0, access=mmap.ACCESS_READ) as image:
                    result = verify_image(image, not args.metadata_only)
        dump_json(result, args.pretty)
        return 0 if not result["errors"] else 1
    except OSError as exc:
        dump_json({"format": "vibeos-storage-v2-cas", "status": "io_error", "errors": [str(exc)]}, args.pretty)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
