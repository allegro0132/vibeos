#!/usr/bin/env python3
"""Independent, fail-closed inspector for the VibeOS Storage V2 image ABI.

This file intentionally duplicates the on-disk constants and offsets.  It does
not import, parse, or otherwise depend on the Rust implementation, so it can
serve as an independent compatibility oracle in CI and during recovery work.
It validates both the frozen M7.2 structural format and the M7.3 canonical
catalog/allocation payloads, then reconstructs objects only from checkpoint
roots even though powered-off verification hashes every physical extent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import struct
from typing import Any, Callable, Optional


PAGE_SIZE = 4096
ANCHOR_PAGES = 16
SEGMENT_PAGES = 1024
DATA_FIRST_PAGE = 2
DATA_END_PAGE = 1020
SUMMARY_BODY_PAGE = 1020
SUMMARY_SEAL_PAGE = 1021
SEGMENT_SEAL_BODY_PAGE = 1022
SEGMENT_SEAL_PAGE = 1023
MAX_EXTENT_PAYLOAD_PAGES = 256
ANCHOR_SEGMENT_NO = (1 << 64) - 1
U64_MAX = (1 << 64) - 1

FORMAT_VERSION = 1
HEADER_LEN = 0x80
PAYLOAD_OFFSET = 0x80
TRAILER_OFFSET = 0xFD0
POINTER_SIZE = 0x60
HASH_ALGORITHM_SHA256 = 1

BODY_MAGIC = b"VIBESG2\x00"
SEAL_MAGIC = b"VIBESL2\x00"
TERMINAL_MARKER = b"VIBESG2-SEALED!!"
DESCRIPTOR_CHAIN_DOMAIN = b"VIBESG2-DESC-v1"
DATA_CHAIN_DOMAIN = b"VIBESG2-DATA-v1"

CATALOG_MAGIC = b"VIBECAT2"
ALLOCATION_MAGIC = b"VIBEALC2"
CATALOG_VERSION = 1
CATALOG_SNAPSHOT = 1
CATALOG_DELTA = 2
CATALOG_SNAPSHOT_HEADER_SIZE = 0x40
CATALOG_DELTA_HEADER_SIZE = 0xA0
CATALOG_ENTRY_SIZE = 0xB0
ALLOCATION_PAYLOAD_SIZE = 0x40

RECORD_KINDS = {
    1: "superblock",
    2: "checkpoint",
    3: "segment_header",
    4: "extent",
    5: "segment_summary",
    6: "segment_seal",
}
RECORD_PAYLOAD_LENGTHS = {
    1: 0x80,
    2: 0x1C0,
    3: 0x58,
    4: 0x80,
    5: 0xC8,
    6: 0xA0,
}
EXTENT_KINDS = {
    1: "blob",
    2: "catalog",
    3: "authority",
    4: "allocation",
    5: "catalog_delta",
}
EXPECTED_POINTER_KINDS = {
    "catalog_root": 2,
    "authority_root": 3,
    "allocation_root": 4,
    "replay_tail": 5,
}


class FormatViolation(ValueError):
    """A sealed record violates the frozen Storage V2 ABI."""


def u16(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def put_u16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def put_u64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


def all_zero(data: bytes | memoryview) -> bool:
    return not any(data)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FormatViolation(message)


def require_zero(data: bytes | memoryview, start: int, end: int, field: str) -> None:
    require(all_zero(data[start:end]), f"{field} must be zero")


def sha256(data: bytes | memoryview) -> bytes:
    return hashlib.sha256(data).digest()


def crc32c(data: bytes | memoryview) -> int:
    """CRC-32C (Castagnoli), reflected polynomial 0x82f63b78."""

    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def complement32(value: int) -> int:
    return (~value) & 0xFFFFFFFF


def ceil_pages(byte_len: int) -> int:
    require(byte_len > 0, "payload byte length must be non-zero")
    pages = (byte_len + PAGE_SIZE - 1) // PAGE_SIZE
    require(1 <= pages <= MAX_EXTENT_PAYLOAD_PAGES, "payload page count is out of range")
    return pages


def segment_base_page(segment_no: int) -> int:
    return ANCHOR_PAGES + segment_no * SEGMENT_PAGES


def admitted_pages(segment_count: int) -> int:
    return ANCHOR_PAGES + segment_count * SEGMENT_PAGES


def page_at(image: bytes | bytearray | mmap.mmap | memoryview, page_no: int) -> Optional[bytes]:
    start = page_no * PAGE_SIZE
    end = start + PAGE_SIZE
    if page_no < 0 or end > len(image):
        return None
    return bytes(image[start:end])


def binding_json(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "store_uuid": binding["store_uuid"].hex(),
        "generation": binding["generation"],
        "segment_no": binding["segment_no"],
        "ordinal": binding["ordinal"],
        "self_page": binding["self_page"],
        "target_checkpoint_generation": binding["target_checkpoint_generation"],
    }


def parse_body(body: bytes, expected_kind: int) -> dict[str, Any]:
    expected_len = RECORD_PAYLOAD_LENGTHS[expected_kind]
    require(body[0x000:0x008] == BODY_MAGIC, "invalid body magic")
    require(u16(body, 0x008) == FORMAT_VERSION, "invalid body version")
    require(u16(body, 0x00A) == HEADER_LEN, "invalid body header length")
    require(u16(body, 0x00C) == expected_kind, "wrong body record kind")
    require(u16(body, 0x00E) == 0, "body flags must be zero")
    require(u32(body, 0x010) == expected_len, "invalid body payload length")
    require(u32(body, 0x014) == 0, "body header reserved word must be zero")
    store_uuid = body[0x018:0x028]
    require(not all_zero(store_uuid), "store UUID must be non-zero")
    binding = {
        "store_uuid": store_uuid,
        "generation": u64(body, 0x028),
        "segment_no": u64(body, 0x030),
        "ordinal": u32(body, 0x038),
        "self_page": u64(body, 0x040),
        "target_checkpoint_generation": u64(body, 0x048),
    }
    require(binding["generation"] > 0, "record generation must be non-zero")
    require(u32(body, 0x03C) == 0, "body binding reserved word must be zero")
    require_zero(body, 0x050, 0x080, "body header reserved bytes")
    require_zero(body, PAYLOAD_OFFSET + expected_len, TRAILER_OFFSET, "body padding")

    body_crc = u32(body, 0xFD0)
    require(body_crc == crc32c(body[:TRAILER_OFFSET]), "body CRC32C mismatch")
    require(u32(body, 0xFD4) == complement32(body_crc), "body CRC complement mismatch")
    require(u64(body, 0xFD8) == binding["self_page"], "body self-page copy mismatch")
    require(u64(body, 0xFE0) == binding["generation"], "body generation copy mismatch")
    require(u64(body, 0xFE8) == binding["segment_no"], "body segment copy mismatch")
    require(u32(body, 0xFF0) == binding["ordinal"], "body ordinal copy mismatch")
    require(u16(body, 0xFF4) == expected_kind, "body kind copy mismatch")
    require(u16(body, 0xFF6) == FORMAT_VERSION, "body version copy mismatch")
    require(u32(body, 0xFF8) == expected_len, "body payload-length copy mismatch")
    require(u16(body, 0xFFC) == HEADER_LEN, "body header-length copy mismatch")
    require(u16(body, 0xFFE) == 0, "body trailer flags must be zero")
    return {
        "binding": binding,
        "kind": expected_kind,
        "payload_len": expected_len,
        "body_crc32c": body_crc,
        "body_sha256": sha256(body),
    }


def validate_seal(seal: bytes, digest: dict[str, Any]) -> None:
    binding = digest["binding"]
    expected_kind = digest["kind"]
    require(seal[0x000:0x008] == SEAL_MAGIC, "invalid seal magic")
    require(u16(seal, 0x008) == FORMAT_VERSION, "invalid seal version")
    require(u16(seal, 0x00A) == expected_kind, "wrong sealed record kind")
    require(u16(seal, 0x00C) == HEADER_LEN, "invalid seal header length")
    require(u16(seal, 0x00E) == 0, "seal flags must be zero")
    require(seal[0x010:0x020] == binding["store_uuid"], "seal UUID binding mismatch")
    require(u64(seal, 0x020) == binding["generation"], "seal generation binding mismatch")
    require(u64(seal, 0x028) == binding["segment_no"], "seal segment binding mismatch")
    require(u32(seal, 0x030) == binding["ordinal"], "seal ordinal binding mismatch")
    require(u32(seal, 0x034) == 0, "seal binding reserved word must be zero")
    require(u64(seal, 0x038) == binding["self_page"], "seal body-page binding mismatch")
    require(
        u64(seal, 0x040) == binding["target_checkpoint_generation"],
        "seal checkpoint binding mismatch",
    )
    require(u32(seal, 0x048) == digest["body_crc32c"], "seal body CRC binding mismatch")
    require(
        u32(seal, 0x04C) == complement32(digest["body_crc32c"]),
        "seal body CRC complement mismatch",
    )
    require(seal[0x050:0x070] == digest["body_sha256"], "seal body SHA-256 mismatch")
    require(u32(seal, 0x070) == digest["payload_len"], "seal payload length mismatch")
    require_zero(seal, 0x074, TRAILER_OFFSET, "seal padding")
    seal_crc = u32(seal, 0xFD0)
    require(seal_crc == crc32c(seal[:TRAILER_OFFSET]), "seal CRC32C mismatch")
    require(u32(seal, 0xFD4) == complement32(seal_crc), "seal CRC complement mismatch")
    require(u64(seal, 0xFD8) == binding["self_page"], "seal self-page copy mismatch")
    require(u64(seal, 0xFE0) == binding["generation"], "seal generation copy mismatch")
    require(u64(seal, 0xFE8) == binding["segment_no"], "seal segment copy mismatch")
    require(seal[0xFF0:0x1000] == TERMINAL_MARKER, "seal terminal marker mismatch")


def parse_pointer(raw: bytes) -> dict[str, Any]:
    require(len(raw) == POINTER_SIZE, "physical pointer has wrong size")
    if all_zero(raw):
        return {"status": "null"}
    store_uuid = raw[0x00:0x10]
    require(not all_zero(store_uuid), "pointer UUID must be non-zero")
    pointer = {
        "status": "value",
        "store_uuid": store_uuid,
        "segment_no": u64(raw, 0x10),
        "segment_generation": u64(raw, 0x18),
        "descriptor_relative_page": u32(raw, 0x20),
        "payload_relative_page": u32(raw, 0x24),
        "payload_pages": u32(raw, 0x28),
        "ordinal": u32(raw, 0x2C),
        "exact_byte_len": u64(raw, 0x30),
        "extent_kind": u16(raw, 0x38),
        "hash_algorithm": u16(raw, 0x3A),
        "payload_sha256": raw[0x40:0x60],
    }
    require(u32(raw, 0x3C) == 0, "pointer reserved word must be zero")
    require(pointer["segment_generation"] > 0, "pointer segment generation must be non-zero")
    require(pointer["ordinal"] > 0, "pointer ordinal must be non-zero")
    require(pointer["extent_kind"] in EXTENT_KINDS, "pointer extent kind is unknown")
    require(pointer["hash_algorithm"] == HASH_ALGORITHM_SHA256, "pointer hash algorithm is invalid")
    require(pointer["descriptor_relative_page"] >= DATA_FIRST_PAGE, "pointer descriptor precedes append area")
    require(
        pointer["payload_relative_page"] == pointer["descriptor_relative_page"] + 2,
        "pointer payload does not follow descriptor pair",
    )
    require(pointer["payload_pages"] == ceil_pages(pointer["exact_byte_len"]), "pointer page count mismatch")
    require(
        pointer["payload_relative_page"] + pointer["payload_pages"] <= DATA_END_PAGE,
        "pointer extends past append area",
    )
    return pointer


def parse_superblock_payload(body: bytes, digest: dict[str, Any]) -> dict[str, Any]:
    require_zero(body, 0x081, 0x088, "superblock copy padding")
    require_zero(body, 0x0B6, 0x0B8, "superblock hash padding")
    require(u32(body, 0x0F4) == 0, "superblock feature bits must be zero")
    require(u32(body, 0x0FC) == 0, "superblock reserved word must be zero")
    result = {
        "binding": digest["binding"],
        "copy": body[0x080],
        "page_size": u32(body, 0x088),
        "anchor_pages": u32(body, 0x08C),
        "segment_pages": u32(body, 0x090),
        "data_first_page": u32(body, 0x094),
        "data_end_page": u32(body, 0x098),
        "summary_body_page": u32(body, 0x09C),
        "summary_seal_page": u32(body, 0x0A0),
        "segment_seal_body_page": u32(body, 0x0A4),
        "segment_seal_page": u32(body, 0x0A8),
        "max_extent_payload_pages": u32(body, 0x0AC),
        "cleaner_reserve_segments": u32(body, 0x0B0),
        "hash_algorithm": u16(body, 0x0B4),
        "initial_range_pages": u64(body, 0x0B8),
        "first_segment_page": u64(body, 0x0C0),
        "initial_segments": u64(body, 0x0C8),
        "device_id": body[0x0D0:0x0E0],
        "range_first_logical_block": u64(body, 0x0E0),
        "initial_block_count": u64(body, 0x0E8),
        "logical_block_size": u32(body, 0x0F0),
        "max_replay_records": u32(body, 0x0F8),
    }
    frozen = (
        PAGE_SIZE,
        ANCHOR_PAGES,
        SEGMENT_PAGES,
        DATA_FIRST_PAGE,
        DATA_END_PAGE,
        SUMMARY_BODY_PAGE,
        SUMMARY_SEAL_PAGE,
        SEGMENT_SEAL_BODY_PAGE,
        SEGMENT_SEAL_PAGE,
        MAX_EXTENT_PAYLOAD_PAGES,
    )
    observed = tuple(
        result[name]
        for name in (
            "page_size",
            "anchor_pages",
            "segment_pages",
            "data_first_page",
            "data_end_page",
            "summary_body_page",
            "summary_seal_page",
            "segment_seal_body_page",
            "segment_seal_page",
            "max_extent_payload_pages",
        )
    )
    require(observed == frozen, "superblock geometry does not match frozen Storage V2 geometry")
    require(result["hash_algorithm"] == HASH_ALGORITHM_SHA256, "superblock hash algorithm is invalid")
    require(result["cleaner_reserve_segments"] >= 1, "cleaner reserve must be at least one segment")
    require(result["first_segment_page"] == ANCHOR_PAGES, "first segment page is invalid")
    require(
        result["initial_range_pages"] == admitted_pages(result["initial_segments"]),
        "initial admitted page count is inconsistent",
    )
    require(
        result["initial_segments"] > result["cleaner_reserve_segments"],
        "cleaner reserve leaves no usable segment",
    )
    require(result["logical_block_size"] in (512, 1024, 2048, 4096), "logical block size is invalid")
    require(result["initial_block_count"] > 0, "initial logical block count must be non-zero")
    range_first = result["range_first_logical_block"]
    block_count = result["initial_block_count"]
    block_size = result["logical_block_size"]
    range_pages = result["initial_range_pages"]
    require(range_first <= U64_MAX - block_count, "initial logical block range overflows u64")
    require(range_first <= U64_MAX // block_size, "initial logical block byte offset overflows u64")
    require(block_count <= U64_MAX // block_size, "initial logical block byte length overflows u64")
    require(
        range_first + block_count <= U64_MAX // block_size,
        "initial logical block range byte end overflows u64",
    )
    require(range_pages <= U64_MAX // PAGE_SIZE, "initial page range byte length overflows u64")
    require(
        block_count * block_size == range_pages * PAGE_SIZE,
        "initial block range byte length is inconsistent",
    )
    require(result["max_replay_records"] > 0, "maximum replay count must be non-zero")
    return result


def parse_checkpoint_payload(body: bytes, digest: dict[str, Any]) -> dict[str, Any]:
    require_zero(body, 0x081, 0x088, "checkpoint slot padding")
    require(u32(body, 0x0B4) == 0, "checkpoint flags must be zero")
    require_zero(body, 0x0B8, 0x0C0, "checkpoint reserved bytes")
    result = {
        "binding": digest["binding"],
        "slot": body[0x080],
        "previous_generation": u64(body, 0x088),
        "admitted_range_pages": u64(body, 0x090),
        "admitted_segments": u64(body, 0x098),
        "next_segment_generation": u64(body, 0x0A0),
        "replay_count": u32(body, 0x0A8),
        "max_replay_records": u32(body, 0x0AC),
        "cleaner_reserve_segments": u32(body, 0x0B0),
        "catalog_root": parse_pointer(body[0x0C0:0x120]),
        "authority_root": parse_pointer(body[0x120:0x180]),
        "allocation_root": parse_pointer(body[0x180:0x1E0]),
        "replay_tail": parse_pointer(body[0x1E0:0x240]),
    }
    generation = digest["binding"]["generation"]
    require(result["slot"] == ((generation - 1) & 1), "checkpoint generation maps to the wrong slot")
    require(
        result["previous_generation"] == (0 if generation == 1 else generation - 1),
        "checkpoint previous generation is not contiguous",
    )
    require(
        result["admitted_range_pages"] == admitted_pages(result["admitted_segments"]),
        "checkpoint admitted page count is inconsistent",
    )
    require(result["next_segment_generation"] > 0, "next segment generation must be non-zero")
    require(result["max_replay_records"] > 0, "checkpoint replay limit must be non-zero")
    require(result["replay_count"] <= result["max_replay_records"], "checkpoint replay count exceeds limit")
    require(result["cleaner_reserve_segments"] >= 1, "checkpoint cleaner reserve must be non-zero")
    require(
        result["admitted_segments"] > result["cleaner_reserve_segments"],
        "checkpoint cleaner reserve leaves no usable segment",
    )
    tail_is_null = result["replay_tail"]["status"] == "null"
    require((result["replay_count"] == 0) == tail_is_null, "replay count and replay tail disagree")
    for name, expected_kind in EXPECTED_POINTER_KINDS.items():
        pointer = result[name]
        if pointer["status"] == "value":
            require(pointer["extent_kind"] == expected_kind, f"{name} has the wrong extent kind")
    return result


def parse_segment_header_payload(body: bytes, digest: dict[str, Any]) -> dict[str, Any]:
    require(u16(body, 0x0A4) == 1, "segment class is invalid")
    require(u16(body, 0x0A6) == 0, "segment header flags must be zero")
    result = {
        "binding": digest["binding"],
        "base_page": u64(body, 0x080),
        "data_first_page": u32(body, 0x088),
        "data_end_page": u32(body, 0x08C),
        "summary_body_page": u32(body, 0x090),
        "summary_seal_page": u32(body, 0x094),
        "segment_seal_body_page": u32(body, 0x098),
        "segment_seal_page": u32(body, 0x09C),
        "max_extent_payload_pages": u32(body, 0x0A0),
        "segment_class": u16(body, 0x0A4),
        "previous_segment_no": u64(body, 0x0A8),
        "previous_segment_generation": u64(body, 0x0B0),
        "previous_segment_seal_body_sha256": body[0x0B8:0x0D8],
    }
    observed = tuple(
        result[name]
        for name in (
            "data_first_page",
            "data_end_page",
            "summary_body_page",
            "summary_seal_page",
            "segment_seal_body_page",
            "segment_seal_page",
            "max_extent_payload_pages",
        )
    )
    frozen = (
        DATA_FIRST_PAGE,
        DATA_END_PAGE,
        SUMMARY_BODY_PAGE,
        SUMMARY_SEAL_PAGE,
        SEGMENT_SEAL_BODY_PAGE,
        SEGMENT_SEAL_PAGE,
        MAX_EXTENT_PAYLOAD_PAGES,
    )
    require(observed == frozen, "segment header geometry is invalid")
    return result


def parse_extent_payload(body: bytes, digest: dict[str, Any]) -> dict[str, Any]:
    require(u16(body, 0x082) == HASH_ALGORITHM_SHA256, "extent hash algorithm is invalid")
    require(u32(body, 0x084) == 0, "extent flags must be zero")
    result = {
        "binding": digest["binding"],
        "extent_kind": u16(body, 0x080),
        "hash_algorithm": u16(body, 0x082),
        "object_kind": u32(body, 0x088),
        "extent_index": u32(body, 0x08C),
        "extent_count": u32(body, 0x090),
        "payload_pages": u32(body, 0x094),
        "content_byte_len": u64(body, 0x098),
        "encoded_blob_len": u64(body, 0x0A0),
        "encoded_offset": u64(body, 0x0A8),
        "payload_byte_len": u64(body, 0x0B0),
        "payload_first_relative_page": u32(body, 0x0B8),
        "record_span_pages": u32(body, 0x0BC),
        "merkle_root": body[0x0C0:0x0E0],
        "payload_sha256": body[0x0E0:0x100],
    }
    require(result["extent_kind"] in EXTENT_KINDS, "extent kind is unknown")
    require(result["object_kind"] != 0, "extent object kind must be non-zero")
    require(result["extent_count"] > 0, "extent count must be non-zero")
    require(result["extent_index"] < result["extent_count"], "extent index is out of range")
    require(
        result["encoded_offset"] + result["payload_byte_len"] <= result["encoded_blob_len"],
        "extent payload exceeds encoded object",
    )
    expected_pages = ceil_pages(result["payload_byte_len"])
    require(result["payload_pages"] == expected_pages, "extent payload page count mismatch")
    require(result["record_span_pages"] == 2 + expected_pages, "extent record span is invalid")
    return result


def parse_segment_summary_payload(body: bytes, digest: dict[str, Any]) -> dict[str, Any]:
    require(u32(body, 0x08C) == 0, "segment summary reserved word must be zero")
    require(u32(body, 0x11C) == 0, "segment summary kind padding must be zero")
    return {
        "binding": digest["binding"],
        "record_count": u32(body, 0x080),
        "next_free_page": u32(body, 0x084),
        "payload_page_count": u32(body, 0x088),
        "total_payload_bytes": u64(body, 0x090),
        "first_target_checkpoint_generation": u64(body, 0x098),
        "last_target_checkpoint_generation": u64(body, 0x0A0),
        "header_body_sha256": body[0x0A8:0x0C8],
        "descriptor_chain_sha256": body[0x0C8:0x0E8],
        "payload_chain_sha256": body[0x0E8:0x108],
        "kind_counts": [u32(body, 0x108 + index * 4) for index in range(5)],
        "kind_bytes": [u64(body, 0x120 + index * 8) for index in range(5)],
    }


def parse_segment_seal_payload(body: bytes, digest: dict[str, Any]) -> dict[str, Any]:
    require(u32(body, 0x10C) == 0, "final segment seal reserved word must be zero")
    return {
        "binding": digest["binding"],
        "header_body_sha256": body[0x080:0x0A0],
        "summary_body_sha256": body[0x0A0:0x0C0],
        "final_descriptor_chain_sha256": body[0x0C0:0x0E0],
        "final_payload_chain_sha256": body[0x0E0:0x100],
        "record_count": u32(body, 0x100),
        "next_free_page": u32(body, 0x104),
        "payload_page_count": u32(body, 0x108),
        "total_payload_bytes": u64(body, 0x110),
        "target_checkpoint_generation": u64(body, 0x118),
    }


PAYLOAD_PARSERS: dict[int, Callable[[bytes, dict[str, Any]], dict[str, Any]]] = {
    1: parse_superblock_payload,
    2: parse_checkpoint_payload,
    3: parse_segment_header_payload,
    4: parse_extent_payload,
    5: parse_segment_summary_payload,
    6: parse_segment_seal_payload,
}


def decode_pair(
    image: bytes | bytearray | mmap.mmap | memoryview,
    body_page: int,
    seal_page: int,
    kind: int,
    label: str,
    errors: list[str],
    validator: Optional[Callable[[dict[str, Any], dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "body_page": body_page,
        "seal_page": seal_page,
        "record_kind": RECORD_KINDS[kind],
    }
    body = page_at(image, body_page)
    seal = page_at(image, seal_page)
    if body is None or seal is None:
        message = f"{label}: record pair is outside the image"
        errors.append(message)
        entry["status"] = "corrupt"
        entry["error"] = message.split(": ", 1)[1]
        return entry
    if all_zero(body) and all_zero(seal):
        entry["status"] = "empty"
        return entry
    # Until the exact 16-byte publication marker exists, neither page is trusted.
    if seal[0xFF0:0x1000] != TERMINAL_MARKER:
        entry["status"] = "unsealed"
        return entry
    try:
        digest = parse_body(body, kind)
        validate_seal(seal, digest)
        record = PAYLOAD_PARSERS[kind](body, digest)
        if validator is not None:
            validator(record, digest)
        entry.update(
            {
                "status": "sealed",
                "body_crc32c": f"{digest['body_crc32c']:08x}",
                "body_sha256": digest["body_sha256"],
                "record": record,
                "_digest": digest,
                "_body": body,
            }
        )
    except FormatViolation as exc:
        message = f"{label}: {exc}"
        errors.append(message)
        entry["status"] = "corrupt"
        entry["error"] = str(exc)
    return entry


def validate_anchor_binding(record: dict[str, Any], digest: dict[str, Any], page: int, ordinal: int) -> None:
    binding = digest["binding"]
    require(binding["segment_no"] == ANCHOR_SEGMENT_NO, "anchor record segment number is invalid")
    require(binding["self_page"] == page, "anchor record self-page is invalid")
    require(binding["ordinal"] == ordinal, "anchor record ordinal is invalid")


def super_validator(copy: int, page: int) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def validate(record: dict[str, Any], digest: dict[str, Any]) -> None:
        validate_anchor_binding(record, digest, page, copy)
        require(record["copy"] == copy, "superblock copy field is invalid")
        require(digest["binding"]["generation"] == 1, "superblock generation must be one")
        require(digest["binding"]["target_checkpoint_generation"] == 0, "superblock checkpoint target must be zero")

    return validate


def checkpoint_validator(slot: int, page: int) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def validate(record: dict[str, Any], digest: dict[str, Any]) -> None:
        validate_anchor_binding(record, digest, page, slot)
        require(record["slot"] == slot, "checkpoint slot field is invalid")
        require(
            digest["binding"]["target_checkpoint_generation"] == digest["binding"]["generation"],
            "checkpoint target generation must equal its generation",
        )

    return validate


def segment_header_validator(segment_no: int, base_page: int) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def validate(record: dict[str, Any], digest: dict[str, Any]) -> None:
        binding = digest["binding"]
        require(binding["segment_no"] == segment_no, "segment header number is invalid")
        require(binding["ordinal"] == 0, "segment header ordinal must be zero")
        require(binding["self_page"] == base_page, "segment header self-page is invalid")
        require(record["base_page"] == base_page, "segment header base page is invalid")
        require(binding["target_checkpoint_generation"] > 0, "segment header checkpoint target is zero")
        previous_no = record["previous_segment_no"]
        previous_generation = record["previous_segment_generation"]
        previous_hash = record["previous_segment_seal_body_sha256"]
        if previous_no == ANCHOR_SEGMENT_NO:
            require(previous_generation == 0, "first segment predecessor generation must be zero")
            require(all_zero(previous_hash), "first segment predecessor hash must be zero")
        else:
            require(previous_no != segment_no, "segment cannot name itself as predecessor")
            require(previous_generation > 0, "segment predecessor generation must be non-zero")
            require(
                previous_generation < binding["generation"],
                "segment predecessor generation is not older than the segment",
            )
            require(not all_zero(previous_hash), "segment predecessor hash must be non-zero")

    return validate


def extent_validator(
    segment_no: int,
    base_page: int,
    segment_generation: int,
    ordinal: int,
    relative_page: int,
    store_uuid: bytes,
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def validate(record: dict[str, Any], digest: dict[str, Any]) -> None:
        binding = digest["binding"]
        require(binding["store_uuid"] == store_uuid, "extent UUID differs from segment header")
        require(binding["segment_no"] == segment_no, "extent segment number is invalid")
        require(binding["generation"] == segment_generation, "extent segment generation is invalid")
        require(binding["ordinal"] == ordinal, "extent ordinal is not contiguous")
        require(binding["self_page"] == base_page + relative_page, "extent self-page is invalid")
        require(binding["target_checkpoint_generation"] > 0, "extent checkpoint target is zero")
        require(
            record["payload_first_relative_page"] == relative_page + 2,
            "extent payload does not follow descriptor pair",
        )
        require(
            record["payload_first_relative_page"] + record["payload_pages"] <= DATA_END_PAGE,
            "extent payload extends past append area",
        )

    return validate


def summary_validator(
    segment_no: int, base_page: int, segment_generation: int, store_uuid: bytes
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def validate(record: dict[str, Any], digest: dict[str, Any]) -> None:
        binding = digest["binding"]
        require(binding["store_uuid"] == store_uuid, "summary UUID differs from segment header")
        require(binding["segment_no"] == segment_no, "summary segment number is invalid")
        require(binding["generation"] == segment_generation, "summary segment generation is invalid")
        require(binding["self_page"] == base_page + SUMMARY_BODY_PAGE, "summary self-page is invalid")
        require(binding["ordinal"] == record["record_count"] + 1, "summary ordinal is invalid")
        require(
            binding["target_checkpoint_generation"] == record["last_target_checkpoint_generation"],
            "summary checkpoint target is invalid",
        )
        require(DATA_FIRST_PAGE <= record["next_free_page"] <= DATA_END_PAGE, "summary next-free page is invalid")

    return validate


def final_seal_validator(
    segment_no: int, base_page: int, segment_generation: int, store_uuid: bytes
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def validate(record: dict[str, Any], digest: dict[str, Any]) -> None:
        binding = digest["binding"]
        require(binding["store_uuid"] == store_uuid, "final seal UUID differs from segment header")
        require(binding["segment_no"] == segment_no, "final seal segment number is invalid")
        require(binding["generation"] == segment_generation, "final seal segment generation is invalid")
        require(binding["self_page"] == base_page + SEGMENT_SEAL_BODY_PAGE, "final seal self-page is invalid")
        require(binding["ordinal"] == record["record_count"] + 2, "final seal ordinal is invalid")
        require(
            binding["target_checkpoint_generation"] == record["target_checkpoint_generation"],
            "final seal checkpoint target is invalid",
        )

    return validate


def chain_initial(domain: bytes, store_uuid: bytes, segment_no: int, generation: int) -> bytes:
    return sha256(domain + store_uuid + struct.pack("<QQ", segment_no, generation))


def descriptor_chain_update(
    previous: bytes,
    store_uuid: bytes,
    segment_no: int,
    generation: int,
    ordinal: int,
    descriptor_body_sha256: bytes,
    payload_sha256: bytes,
) -> bytes:
    return sha256(
        DESCRIPTOR_CHAIN_DOMAIN
        + store_uuid
        + struct.pack("<QQ", segment_no, generation)
        + previous
        + struct.pack("<I", ordinal)
        + descriptor_body_sha256
        + payload_sha256
    )


def data_chain_update(
    previous: bytes,
    store_uuid: bytes,
    segment_no: int,
    generation: int,
    ordinal: int,
    payload_byte_len: int,
    payload_sha256: bytes,
) -> bytes:
    return sha256(
        DATA_CHAIN_DOMAIN
        + store_uuid
        + struct.pack("<QQ", segment_no, generation)
        + previous
        + struct.pack("<IQ", ordinal, payload_byte_len)
        + payload_sha256
    )


def add_segment_error(segment: dict[str, Any], errors: list[str], message: str) -> None:
    full = f"segment {segment['segment_no']}: {message}"
    errors.append(full)
    segment.setdefault("errors", []).append(message)
    segment["status"] = "corrupt"


def parse_segment(
    image: bytes | bytearray | mmap.mmap | memoryview,
    segment_no: int,
    errors: list[str],
) -> dict[str, Any]:
    base = segment_base_page(segment_no)
    segment: dict[str, Any] = {"segment_no": segment_no, "base_page": base, "extents": []}
    header = decode_pair(
        image,
        base,
        base + 1,
        3,
        f"segment {segment_no} header",
        errors,
        segment_header_validator(segment_no, base),
    )
    segment["header"] = header
    if header["status"] != "sealed":
        # Final publication without a trusted header is a sealed contradiction.
        final_marker_page = page_at(image, base + SEGMENT_SEAL_PAGE)
        if final_marker_page is not None and final_marker_page[0xFF0:] == TERMINAL_MARKER:
            add_segment_error(segment, errors, "published final seal has no trusted segment header")
        elif header["status"] == "corrupt":
            segment["status"] = "corrupt"
        elif header["status"] == "empty" and all_zero(bytes(image[base * PAGE_SIZE : (base + SEGMENT_PAGES) * PAGE_SIZE])):
            segment["status"] = "empty"
        else:
            segment["status"] = "incomplete"
        return segment

    header_record = header["record"]
    header_digest = header["_digest"]
    store_uuid = header_record["binding"]["store_uuid"]
    segment_generation = header_record["binding"]["generation"]
    summary = decode_pair(
        image,
        base + SUMMARY_BODY_PAGE,
        base + SUMMARY_SEAL_PAGE,
        5,
        f"segment {segment_no} summary",
        errors,
        summary_validator(segment_no, base, segment_generation, store_uuid),
    )
    final = decode_pair(
        image,
        base + SEGMENT_SEAL_BODY_PAGE,
        base + SEGMENT_SEAL_PAGE,
        6,
        f"segment {segment_no} final seal",
        errors,
        final_seal_validator(segment_no, base, segment_generation, store_uuid),
    )
    segment["summary"] = summary
    segment["final_seal"] = final
    if summary["status"] == "corrupt" or final["status"] == "corrupt":
        segment["status"] = "corrupt"
        return segment
    if summary["status"] != "sealed" or final["status"] != "sealed":
        if final["status"] == "sealed":
            add_segment_error(segment, errors, "published final seal has no trusted summary")
        else:
            segment["status"] = "incomplete"
        return segment

    summary_record = summary["record"]
    final_record = final["record"]
    descriptor_chain = chain_initial(
        DESCRIPTOR_CHAIN_DOMAIN, store_uuid, segment_no, segment_generation
    )
    payload_chain = chain_initial(DATA_CHAIN_DOMAIN, store_uuid, segment_no, segment_generation)
    relative_page = DATA_FIRST_PAGE
    payload_page_count = 0
    total_payload_bytes = 0
    kind_counts = [0, 0, 0, 0, 0]
    kind_bytes = [0, 0, 0, 0, 0]
    target_generations: list[int] = []
    extent_lookup: dict[tuple[int, int], dict[str, Any]] = {}
    segment["_extent_lookup"] = extent_lookup

    for ordinal in range(1, summary_record["record_count"] + 1):
        if relative_page + 1 >= DATA_END_PAGE:
            add_segment_error(segment, errors, "descriptor count runs past append area")
            return segment
        extent = decode_pair(
            image,
            base + relative_page,
            base + relative_page + 1,
            4,
            f"segment {segment_no} extent {ordinal}",
            errors,
            extent_validator(
                segment_no,
                base,
                segment_generation,
                ordinal,
                relative_page,
                store_uuid,
            ),
        )
        segment["extents"].append(extent)
        if extent["status"] != "sealed":
            add_segment_error(segment, errors, f"sealed segment contains {extent['status']} extent {ordinal}")
            return segment
        record = extent["record"]
        first_payload_page = base + record["payload_first_relative_page"]
        raw_payload = bytearray()
        for page_offset in range(record["payload_pages"]):
            payload_page = page_at(image, first_payload_page + page_offset)
            if payload_page is None:
                add_segment_error(segment, errors, f"extent {ordinal} payload is outside image")
                return segment
            raw_payload.extend(payload_page)
        exact_payload = bytes(raw_payload[: record["payload_byte_len"]])
        observed_payload_sha = sha256(exact_payload)
        if observed_payload_sha != record["payload_sha256"]:
            add_segment_error(segment, errors, f"extent {ordinal} payload SHA-256 mismatch")
            return segment
        descriptor_chain = descriptor_chain_update(
            descriptor_chain,
            store_uuid,
            segment_no,
            segment_generation,
            ordinal,
            extent["_digest"]["body_sha256"],
            observed_payload_sha,
        )
        payload_chain = data_chain_update(
            payload_chain,
            store_uuid,
            segment_no,
            segment_generation,
            ordinal,
            record["payload_byte_len"],
            observed_payload_sha,
        )
        kind_index = record["extent_kind"] - 1
        kind_counts[kind_index] += 1
        kind_bytes[kind_index] += record["payload_byte_len"]
        payload_page_count += record["payload_pages"]
        total_payload_bytes += record["payload_byte_len"]
        target_generations.append(record["binding"]["target_checkpoint_generation"])
        extent_lookup[(relative_page, ordinal)] = record
        relative_page += record["record_span_pages"]

    checks = (
        (relative_page == summary_record["next_free_page"], "summary next-free page mismatch"),
        (payload_page_count == summary_record["payload_page_count"], "summary payload-page count mismatch"),
        (total_payload_bytes == summary_record["total_payload_bytes"], "summary payload byte count mismatch"),
        (kind_counts == summary_record["kind_counts"], "summary extent-kind counts mismatch"),
        (kind_bytes == summary_record["kind_bytes"], "summary extent-kind byte counts mismatch"),
        (header_digest["body_sha256"] == summary_record["header_body_sha256"], "summary header hash mismatch"),
        (descriptor_chain == summary_record["descriptor_chain_sha256"], "summary descriptor chain mismatch"),
        (payload_chain == summary_record["payload_chain_sha256"], "summary payload chain mismatch"),
    )
    for condition, message in checks:
        if not condition:
            add_segment_error(segment, errors, message)

    if target_generations:
        if target_generations != sorted(target_generations):
            add_segment_error(segment, errors, "extent checkpoint targets are not monotonic")
        if summary_record["first_target_checkpoint_generation"] != target_generations[0]:
            add_segment_error(segment, errors, "summary first checkpoint target mismatch")
        if summary_record["last_target_checkpoint_generation"] != target_generations[-1]:
            add_segment_error(segment, errors, "summary last checkpoint target mismatch")

    cross_checks = (
        (final_record["header_body_sha256"] == header_digest["body_sha256"], "final seal header hash mismatch"),
        (final_record["summary_body_sha256"] == summary["_digest"]["body_sha256"], "final seal summary hash mismatch"),
        (final_record["final_descriptor_chain_sha256"] == descriptor_chain, "final descriptor chain mismatch"),
        (final_record["final_payload_chain_sha256"] == payload_chain, "final payload chain mismatch"),
        (final_record["record_count"] == summary_record["record_count"], "final record count mismatch"),
        (final_record["next_free_page"] == summary_record["next_free_page"], "final next-free page mismatch"),
        (final_record["payload_page_count"] == summary_record["payload_page_count"], "final payload-page count mismatch"),
        (final_record["total_payload_bytes"] == summary_record["total_payload_bytes"], "final payload byte count mismatch"),
        (
            final_record["target_checkpoint_generation"]
            == summary_record["last_target_checkpoint_generation"],
            "final checkpoint target mismatch",
        ),
    )
    for condition, message in cross_checks:
        if not condition:
            add_segment_error(segment, errors, message)

    if segment.get("status") != "corrupt":
        segment["status"] = "sealed"
    segment["_generation"] = segment_generation
    segment["_store_uuid"] = store_uuid
    segment["_final_body_sha256"] = final["_digest"]["body_sha256"]
    return segment


def canonical_superblock(record: dict[str, Any]) -> tuple[Any, ...]:
    binding = record["binding"]
    return (
        binding["store_uuid"],
        binding["generation"],
        record["page_size"],
        record["anchor_pages"],
        record["segment_pages"],
        record["data_first_page"],
        record["data_end_page"],
        record["summary_body_page"],
        record["summary_seal_page"],
        record["segment_seal_body_page"],
        record["segment_seal_page"],
        record["max_extent_payload_pages"],
        record["cleaner_reserve_segments"],
        record["hash_algorithm"],
        record["initial_range_pages"],
        record["first_segment_page"],
        record["initial_segments"],
        record["device_id"],
        record["range_first_logical_block"],
        record["initial_block_count"],
        record["logical_block_size"],
        record["max_replay_records"],
    )


def select_superblock(entries: list[dict[str, Any]], errors: list[str]) -> Optional[dict[str, Any]]:
    sealed = [entry for entry in entries if entry["status"] == "sealed"]
    if len(sealed) == 2 and canonical_superblock(sealed[0]["record"]) != canonical_superblock(sealed[1]["record"]):
        errors.append("superblock copies conflict")
        return None
    return sealed[0] if sealed else None


def select_checkpoint(entries: list[dict[str, Any]], errors: list[str]) -> Optional[dict[str, Any]]:
    sealed = [entry for entry in entries if entry["status"] == "sealed"]
    if not sealed:
        return None
    sealed.sort(key=lambda entry: entry["record"]["binding"]["generation"])
    if len(sealed) == 2:
        transition_is_valid = True
        if (
            sealed[0]["record"]["binding"]["store_uuid"]
            != sealed[1]["record"]["binding"]["store_uuid"]
        ):
            errors.append("checkpoint slots have different store UUIDs")
            transition_is_valid = False
        older = sealed[0]["record"]
        newer = sealed[1]["record"]
        low_generation = sealed[0]["record"]["binding"]["generation"]
        high_generation = sealed[1]["record"]["binding"]["generation"]
        if low_generation == high_generation:
            errors.append("checkpoint slots publish the same generation")
            transition_is_valid = False
        elif high_generation != low_generation + 1:
            errors.append("checkpoint generations are not contiguous")
            transition_is_valid = False
        if sealed[1]["record"]["previous_generation"] != low_generation:
            errors.append("newer checkpoint does not name the older checkpoint")
            transition_is_valid = False
        if newer["admitted_segments"] < older["admitted_segments"]:
            errors.append("checkpoint transition decreases admitted segments")
            transition_is_valid = False
        if newer["next_segment_generation"] < older["next_segment_generation"]:
            errors.append("checkpoint transition decreases next segment generation")
            transition_is_valid = False
        if newer["cleaner_reserve_segments"] != older["cleaner_reserve_segments"]:
            errors.append("checkpoint transition changes cleaner reserve")
            transition_is_valid = False
        if newer["max_replay_records"] != older["max_replay_records"]:
            errors.append("checkpoint transition changes replay limit")
            transition_is_valid = False
        if not transition_is_valid:
            return None
    return sealed[-1]


def ranges_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left["status"] != "value" or right["status"] != "value":
        return False
    if (
        left["store_uuid"],
        left["segment_no"],
        left["segment_generation"],
    ) != (
        right["store_uuid"],
        right["segment_no"],
        right["segment_generation"],
    ):
        return False
    left_end = left["payload_relative_page"] + left["payload_pages"]
    right_end = right["payload_relative_page"] + right["payload_pages"]
    return left["descriptor_relative_page"] < right_end and right["descriptor_relative_page"] < left_end


def resolve_extent_pointer(
    checkpoint: dict[str, Any],
    pointer_name: str,
    pointer: dict[str, Any],
    segments: list[dict[str, Any]],
    errors: list[str],
) -> Optional[dict[str, Any]]:
    """Resolve one checkpoint/catalog pointer without trusting an in-memory index.

    The returned extent has already passed the full segment verifier and agrees
    byte-for-byte with the pointer's physical and digest binding.  Callers must
    still apply their payload-specific schema.
    """

    if pointer["status"] == "null":
        return None
    record = checkpoint["record"]
    checkpoint_generation = record["binding"]["generation"]
    prefix = f"checkpoint generation {checkpoint_generation} {pointer_name}"
    if pointer["store_uuid"] != record["binding"]["store_uuid"]:
        errors.append(f"{prefix}: pointer UUID mismatch")
        return None
    if pointer["segment_no"] >= record["admitted_segments"]:
        errors.append(f"{prefix}: pointer references an unadmitted segment")
        return None
    if pointer["segment_generation"] >= record["next_segment_generation"]:
        errors.append(f"{prefix}: pointer segment generation is not committed")
        return None
    segment = next(
        (item for item in segments if item["segment_no"] == pointer["segment_no"]),
        None,
    )
    if segment is None or segment.get("status") != "sealed":
        errors.append(f"{prefix}: pointer does not reference a sealed segment")
        return None
    if segment.get("_generation") != pointer["segment_generation"]:
        errors.append(f"{prefix}: segment generation mismatch")
        return None
    if (
        segment["final_seal"]["record"]["target_checkpoint_generation"]
        > checkpoint_generation
    ):
        errors.append(f"{prefix}: segment was finalized for a newer checkpoint")
        return None
    extent = segment.get("_extent_lookup", {}).get(
        (pointer["descriptor_relative_page"], pointer["ordinal"])
    )
    if extent is None:
        errors.append(f"{prefix}: descriptor was not found")
        return None
    if extent["binding"]["target_checkpoint_generation"] > checkpoint_generation:
        errors.append(f"{prefix}: extent targets a newer checkpoint")
        return None
    expected = (
        extent["extent_kind"],
        extent["payload_first_relative_page"],
        extent["payload_pages"],
        extent["payload_byte_len"],
        extent["payload_sha256"],
    )
    observed = (
        pointer["extent_kind"],
        pointer["payload_relative_page"],
        pointer["payload_pages"],
        pointer["exact_byte_len"],
        pointer["payload_sha256"],
    )
    if observed != expected:
        errors.append(f"{prefix}: pointer and extent descriptor disagree")
        return None
    return extent


def pointer_identity(pointer: dict[str, Any]) -> tuple[int, int, int, int]:
    require(pointer["status"] == "value", "null pointer has no physical identity")
    return (
        pointer["segment_no"],
        pointer["segment_generation"],
        pointer["descriptor_relative_page"],
        pointer["ordinal"],
    )


def read_exact_extent_payload(
    image: bytes | bytearray | mmap.mmap | memoryview,
    extent: dict[str, Any],
) -> bytes:
    base = segment_base_page(extent["binding"]["segment_no"])
    first_page = base + extent["payload_first_relative_page"]
    start = first_page * PAGE_SIZE
    exact_len = extent["payload_byte_len"]
    require(start <= len(image), "extent payload starts outside image")
    require(exact_len <= len(image) - start, "extent payload ends outside image")
    return bytes(image[start : start + exact_len])


def require_single_extent_payload(extent: dict[str, Any], label: str) -> None:
    payload_len = extent["payload_byte_len"]
    require(extent["extent_index"] == 0, f"{label} extent index must be zero")
    require(extent["extent_count"] == 1, f"{label} extent count must be one")
    require(extent["content_byte_len"] == payload_len, f"{label} content length mismatch")
    require(extent["encoded_blob_len"] == payload_len, f"{label} encoded length mismatch")
    require(extent["encoded_offset"] == 0, f"{label} encoded offset must be zero")
    require(extent["merkle_root"] == extent["payload_sha256"], f"{label} content root mismatch")


def parse_catalog_entry(
    payload: bytes,
    offset: int,
    catalog_generation: int,
    catalog_kind: int,
    store_uuid: bytes,
) -> dict[str, Any]:
    require(offset <= len(payload), "catalog entry offset exceeds payload")
    require(len(payload) - offset >= CATALOG_ENTRY_SIZE, "catalog entry is truncated")
    raw = payload[offset : offset + CATALOG_ENTRY_SIZE]
    object_id = raw[0x00:0x10]
    exact_payload_len = u64(raw, 0x18)
    commit_generation = u64(raw, 0x20)
    blob = parse_pointer(raw[0x48:0xA8])
    require(not all_zero(object_id), "catalog object ID must be non-zero")
    require(u32(raw, 0x10) != 0, "catalog object kind must be non-zero")
    require(u32(raw, 0x14) == 0, "catalog entry flags must be zero")
    require(commit_generation > 0, "catalog commit generation must be non-zero")
    require(
        commit_generation <= catalog_generation,
        "catalog entry commits after its metadata record",
    )
    if catalog_kind == CATALOG_DELTA:
        require(
            commit_generation == catalog_generation,
            "catalog delta entry has the wrong commit generation",
        )
    require_zero(raw, 0xA8, 0xB0, "catalog entry reserved bytes")
    if exact_payload_len == 0:
        require(blob["status"] == "null", "empty catalog object has a Blob pointer")
        require(raw[0x28:0x48] == sha256(b""), "empty catalog object has the wrong content root")
    else:
        require(blob["status"] == "value", "non-empty catalog object has no Blob pointer")
        require(blob["store_uuid"] == store_uuid, "catalog Blob pointer UUID mismatch")
        require(blob["extent_kind"] == 1, "catalog object pointer is not a Blob pointer")
        require(
            blob["exact_byte_len"] == exact_payload_len,
            "catalog object length differs from its Blob pointer",
        )
        require(
            blob["payload_sha256"] == raw[0x28:0x48],
            "catalog content root differs from its Blob pointer",
        )
    return {
        "object_id": object_id,
        "object_kind": u32(raw, 0x10),
        "exact_payload_len": exact_payload_len,
        "commit_generation": commit_generation,
        "content_root": raw[0x28:0x48],
        "blob": blob,
    }


def parse_catalog_payload(
    payload: bytes,
    extent: dict[str, Any],
    expected_kind: int,
) -> dict[str, Any]:
    require(len(payload) >= CATALOG_SNAPSHOT_HEADER_SIZE, "catalog payload is shorter than its header")
    require(payload[0x00:0x08] == CATALOG_MAGIC, "invalid catalog magic")
    require(u16(payload, 0x08) == CATALOG_VERSION, "invalid catalog version")
    require(u16(payload, 0x0A) == expected_kind, "catalog payload has the wrong kind")
    header_size = CATALOG_SNAPSHOT_HEADER_SIZE if expected_kind == CATALOG_SNAPSHOT else CATALOG_DELTA_HEADER_SIZE
    require(u32(payload, 0x0C) == header_size, "invalid catalog header length")
    catalog_generation = u64(payload, 0x10)
    entry_count = u32(payload, 0x18)
    require(
        catalog_generation == extent["binding"]["target_checkpoint_generation"],
        "catalog generation differs from its extent target",
    )
    require(u32(payload, 0x1C) == CATALOG_ENTRY_SIZE, "invalid catalog entry size")
    chain_count = u64(payload, 0x20)
    require(entry_count > 0, "catalog payload must contain at least one entry")
    if expected_kind == CATALOG_SNAPSHOT:
        require_zero(payload, 0x28, 0x40, "catalog snapshot reserved bytes")
        previous = {"status": "null"}
        require(chain_count == entry_count, "catalog snapshot chain count is inconsistent")
    else:
        require(entry_count == 1, "catalog delta must contain exactly one entry")
        require(len(payload) >= CATALOG_DELTA_HEADER_SIZE, "catalog delta header is truncated")
        previous = parse_pointer(payload[0x28:0x88])
        require_zero(payload, 0x88, 0xA0, "catalog delta reserved bytes")
        require(chain_count > 0, "catalog delta chain count must be non-zero")
        require(
            (chain_count == 1) == (previous["status"] == "null"),
            "catalog delta chain count and previous pointer disagree",
        )
        if previous["status"] == "value":
            require(previous["extent_kind"] == 5, "catalog delta previous pointer has the wrong kind")
            require(
                previous["store_uuid"] == extent["binding"]["store_uuid"],
                "catalog delta previous pointer UUID mismatch",
            )
            require(
                previous["exact_byte_len"] == CATALOG_DELTA_HEADER_SIZE + CATALOG_ENTRY_SIZE,
                "catalog delta previous pointer has the wrong length",
            )
    expected_len = header_size + entry_count * CATALOG_ENTRY_SIZE
    require(len(payload) == expected_len, "catalog payload has a non-canonical length")
    entries = [
        parse_catalog_entry(
            payload,
            header_size + index * CATALOG_ENTRY_SIZE,
            catalog_generation,
            expected_kind,
            extent["binding"]["store_uuid"],
        )
        for index in range(entry_count)
    ]
    if expected_kind == CATALOG_SNAPSHOT:
        object_ids = [int.from_bytes(entry["object_id"], "little") for entry in entries]
        require(
            all(left < right for left, right in zip(object_ids, object_ids[1:])),
            "catalog snapshot object IDs are not strictly increasing",
        )
    return {
        "kind": "snapshot" if expected_kind == CATALOG_SNAPSHOT else "delta",
        "checkpoint_generation": catalog_generation,
        "entry_count": entry_count,
        "chain_count": chain_count,
        "previous": previous,
        "entries": entries,
    }


def parse_allocation_payload(payload: bytes, extent: dict[str, Any]) -> dict[str, Any]:
    require(len(payload) == ALLOCATION_PAYLOAD_SIZE, "allocation payload has a non-canonical length")
    require(payload[0x00:0x08] == ALLOCATION_MAGIC, "invalid allocation magic")
    require(u16(payload, 0x08) == 1, "invalid allocation version")
    require(u16(payload, 0x0A) == ALLOCATION_PAYLOAD_SIZE, "invalid allocation header length")
    require(u32(payload, 0x0C) == 0, "allocation flags must be zero")
    checkpoint_generation = u64(payload, 0x10)
    require(
        checkpoint_generation == extent["binding"]["target_checkpoint_generation"],
        "allocation generation differs from its extent target",
    )
    require_zero(payload, 0x34, 0x40, "allocation reserved bytes")
    return {
        "checkpoint_generation": checkpoint_generation,
        "admitted_segments": u64(payload, 0x18),
        "allocated_prefix_segments": u64(payload, 0x20),
        "next_segment_generation": u64(payload, 0x28),
        "cleaner_reserve_segments": u32(payload, 0x30),
    }


def verify_checkpoint_pointers(
    checkpoint: dict[str, Any],
    segments: list[dict[str, Any]],
    errors: list[str],
) -> None:
    record = checkpoint["record"]
    pointers = [(name, record[name]) for name in EXPECTED_POINTER_KINDS]
    for name, pointer in pointers:
        resolve_extent_pointer(checkpoint, name, pointer, segments, errors)
    for left_index, (left_name, left) in enumerate(pointers):
        for right_name, right in pointers[left_index + 1 :]:
            if ranges_overlap(left, right):
                errors.append(
                    f"checkpoint generation {record['binding']['generation']} pointers "
                    f"{left_name} and {right_name} overlap"
                )


def verify_checkpoint_against_superblock(
    checkpoint: dict[str, Any],
    superblock: dict[str, Any],
    physical_segments: int,
    segments: list[dict[str, Any]],
    errors: list[str],
) -> None:
    record = checkpoint["record"]
    super_record = superblock["record"]
    generation = record["binding"]["generation"]
    prefix = f"checkpoint generation {generation}"
    if record["binding"]["store_uuid"] != super_record["binding"]["store_uuid"]:
        errors.append(f"{prefix}: store UUID differs from superblock")
    if record["cleaner_reserve_segments"] != super_record["cleaner_reserve_segments"]:
        errors.append(f"{prefix}: cleaner reserve differs from superblock")
    if record["max_replay_records"] != super_record["max_replay_records"]:
        errors.append(f"{prefix}: replay limit differs from superblock")
    if generation == 1:
        if record["admitted_segments"] != super_record["initial_segments"]:
            errors.append(f"{prefix}: initial admitted segments do not match superblock")
        if record["admitted_range_pages"] != super_record["initial_range_pages"]:
            errors.append(f"{prefix}: initial admitted pages do not match superblock")
    elif record["admitted_segments"] < super_record["initial_segments"]:
        errors.append(f"{prefix}: admits fewer than the initial segments")
    if record["admitted_segments"] > physical_segments:
        errors.append(f"{prefix}: admits segments beyond the image")
    verify_checkpoint_pointers(checkpoint, segments, errors)


def verify_store_checkpoint(
    image: bytes | bytearray | mmap.mmap | memoryview,
    checkpoint: Optional[dict[str, Any]],
    segments: list[dict[str, Any]],
    errors: list[str],
) -> dict[str, Any]:
    """Reconstruct the committed object set from roots, never from Blob scans."""

    if checkpoint is None:
        return {
            "status": "unavailable",
            "object_count": 0,
            "objects": [],
            "orphan_extents": [],
        }

    error_count = len(errors)
    cp = checkpoint["record"]
    cp_generation = cp["binding"]["generation"]
    reachable: set[tuple[int, int, int, int]] = set()

    def resolve(name: str, pointer: dict[str, Any], expected_extent_kind: int) -> Optional[dict[str, Any]]:
        if pointer["status"] == "null":
            return None
        reachable.add(pointer_identity(pointer))
        extent = resolve_extent_pointer(checkpoint, name, pointer, segments, errors)
        if extent is not None and extent["extent_kind"] != expected_extent_kind:
            errors.append(
                f"checkpoint generation {cp_generation} {name}: "
                "resolved descriptor has the wrong extent kind"
            )
            return None
        return extent

    catalog_entries: list[dict[str, Any]] = []
    catalog_root = cp["catalog_root"]
    if catalog_root["status"] == "value":
        extent = resolve("catalog_root", catalog_root, 2)
        if extent is not None:
            try:
                require_single_extent_payload(extent, "catalog snapshot")
                snapshot = parse_catalog_payload(
                    read_exact_extent_payload(image, extent),
                    extent,
                    CATALOG_SNAPSHOT,
                )
                require(
                    snapshot["checkpoint_generation"] <= cp_generation,
                    "catalog snapshot targets a newer checkpoint",
                )
                catalog_entries.extend(snapshot["entries"])
            except FormatViolation as exc:
                errors.append(f"checkpoint generation {cp_generation} catalog_root payload: {exc}")

    replay_nodes: list[dict[str, Any]] = []
    replay_pointer = cp["replay_tail"]
    expected_chain_count = cp["replay_count"]
    seen_replay: set[tuple[int, int, int, int]] = set()
    while expected_chain_count > 0:
        if replay_pointer["status"] != "value":
            errors.append(
                f"checkpoint generation {cp_generation} replay chain ended before "
                f"{cp['replay_count']} records"
            )
            break
        identity = pointer_identity(replay_pointer)
        if identity in seen_replay:
            errors.append(f"checkpoint generation {cp_generation} replay chain contains a cycle")
            break
        seen_replay.add(identity)
        extent = resolve(f"replay[{expected_chain_count}]", replay_pointer, 5)
        if extent is None:
            break
        try:
            require_single_extent_payload(extent, "catalog delta")
            delta = parse_catalog_payload(
                read_exact_extent_payload(image, extent),
                extent,
                CATALOG_DELTA,
            )
            require(
                delta["checkpoint_generation"] <= cp_generation,
                "catalog delta targets a newer checkpoint",
            )
            require(
                delta["chain_count"] == expected_chain_count,
                "catalog delta chain count does not match checkpoint replay count",
            )
        except FormatViolation as exc:
            errors.append(
                f"checkpoint generation {cp_generation} replay[{expected_chain_count}] payload: {exc}"
            )
            break
        replay_nodes.append(delta)
        replay_pointer = delta["previous"]
        expected_chain_count -= 1
    if expected_chain_count == 0 and replay_pointer["status"] != "null":
        errors.append(f"checkpoint generation {cp_generation} replay chain exceeds replay_count")
    for delta in reversed(replay_nodes):
        catalog_entries.extend(delta["entries"])

    allocation: Optional[dict[str, Any]] = None
    allocation_pointer = cp["allocation_root"]
    if allocation_pointer["status"] == "value":
        extent = resolve("allocation_root", allocation_pointer, 4)
        if extent is not None:
            try:
                require_single_extent_payload(extent, "allocation")
                allocation = parse_allocation_payload(
                    read_exact_extent_payload(image, extent),
                    extent,
                )
                require(
                    allocation["checkpoint_generation"] == cp_generation,
                    "allocation payload is not for the selected checkpoint",
                )
                require(
                    allocation["admitted_segments"] == cp["admitted_segments"],
                    "allocation admitted segment count differs from checkpoint",
                )
                require(
                    allocation["next_segment_generation"] == cp["next_segment_generation"],
                    "allocation next generation differs from checkpoint",
                )
                require(
                    allocation["cleaner_reserve_segments"] == cp["cleaner_reserve_segments"],
                    "allocation cleaner reserve differs from checkpoint",
                )
                require(
                    allocation["allocated_prefix_segments"] <= allocation["admitted_segments"],
                    "allocation prefix exceeds admitted segments",
                )
                require(
                    allocation["allocated_prefix_segments"] > 0,
                    "allocation root declares an empty allocated prefix",
                )
                require(
                    allocation_pointer["segment_no"] + 1
                    == allocation["allocated_prefix_segments"],
                    "allocation root is not in the final allocated segment",
                )
                require(
                    allocation["allocated_prefix_segments"]
                    + allocation["cleaner_reserve_segments"]
                    <= allocation["admitted_segments"],
                    "allocation prefix consumes cleaner reserve",
                )
            except FormatViolation as exc:
                errors.append(f"checkpoint generation {cp_generation} allocation_root payload: {exc}")
                allocation = None

    authority = cp["authority_root"]
    if authority["status"] == "value":
        resolve("authority_root", authority, 3)

    objects: list[dict[str, Any]] = []
    seen_objects: set[bytes] = set()
    previous_object_id = 0
    for entry_index, entry in enumerate(catalog_entries):
        object_label = entry["object_id"].hex()
        object_id_value = int.from_bytes(entry["object_id"], "little")
        if entry["object_id"] in seen_objects:
            errors.append(
                f"checkpoint generation {cp_generation} catalog entry {entry_index}: "
                f"duplicate object ID {object_label}"
            )
            continue
        if object_id_value <= previous_object_id:
            errors.append(
                f"checkpoint generation {cp_generation} catalog entry {entry_index}: "
                "object IDs are not strictly increasing"
            )
        seen_objects.add(entry["object_id"])
        previous_object_id = object_id_value
        object_result = {
            "object_id": entry["object_id"],
            "object_kind": entry["object_kind"],
            "exact_payload_len": entry["exact_payload_len"],
            "commit_generation": entry["commit_generation"],
            "content_root": entry["content_root"],
            "blob": entry["blob"],
        }
        if entry["blob"]["status"] == "value":
            blob = resolve(f"object {object_label} Blob", entry["blob"], 1)
            if blob is not None:
                raw_shape = (
                    blob["object_kind"],
                    blob["extent_index"],
                    blob["extent_count"],
                    blob["content_byte_len"],
                    blob["encoded_blob_len"],
                    blob["encoded_offset"],
                    blob["payload_byte_len"],
                    blob["merkle_root"],
                    blob["payload_sha256"],
                )
                expected_shape = (
                    entry["object_kind"],
                    0,
                    1,
                    entry["exact_payload_len"],
                    entry["exact_payload_len"],
                    0,
                    entry["exact_payload_len"],
                    entry["content_root"],
                    entry["content_root"],
                )
                if raw_shape != expected_shape:
                    errors.append(
                        f"checkpoint generation {cp_generation} object {object_label}: "
                        "Blob descriptor does not encode the canonical M7.3 object"
                    )
                if blob["binding"]["target_checkpoint_generation"] != entry["commit_generation"]:
                    errors.append(
                        f"checkpoint generation {cp_generation} object {object_label}: "
                        "Blob target differs from object commit generation"
                    )
                if sha256(read_exact_extent_payload(image, blob)) != entry["content_root"]:
                    errors.append(
                        f"checkpoint generation {cp_generation} object {object_label}: "
                        "reconstructed payload content root mismatch"
                    )
        objects.append(object_result)

    if catalog_entries and allocation_pointer["status"] == "null":
        errors.append(f"checkpoint generation {cp_generation}: committed objects have no allocation root")
    if allocation is not None:
        allocated_prefix = allocation["allocated_prefix_segments"]
        for identity in sorted(reachable):
            if identity[0] >= allocated_prefix:
                errors.append(
                    f"checkpoint generation {cp_generation}: reachable extent in segment "
                    f"{identity[0]} lies outside allocated prefix {allocated_prefix}"
                )

    orphan_extents: list[dict[str, Any]] = []
    for segment in segments:
        if segment.get("status") != "sealed":
            continue
        for extent_entry in segment["extents"]:
            if extent_entry.get("status") != "sealed":
                continue
            extent = extent_entry["record"]
            relative_page = extent["binding"]["self_page"] - segment["base_page"]
            identity = (
                segment["segment_no"],
                segment["_generation"],
                relative_page,
                extent["binding"]["ordinal"],
            )
            if identity not in reachable:
                orphan_extents.append(
                    {
                        "segment_no": segment["segment_no"],
                        "segment_generation": segment["_generation"],
                        "descriptor_relative_page": relative_page,
                        "ordinal": extent["binding"]["ordinal"],
                        "extent_kind": EXTENT_KINDS[extent["extent_kind"]],
                        "exact_byte_len": extent["payload_byte_len"],
                        "payload_sha256": extent["payload_sha256"],
                        "within_admitted_range": segment["segment_no"] < cp["admitted_segments"],
                    }
                )

    return {
        "status": "verified" if len(errors) == error_count else "corrupt",
        "checkpoint_generation": cp_generation,
        "object_count": len(objects),
        "objects": objects,
        "allocation": allocation,
        "orphan_extents": orphan_extents,
    }


def public_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: public_value(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [public_value(item) for item in value]
    if isinstance(value, tuple):
        return [public_value(item) for item in value]
    return value


def parse_image(image: bytes | bytearray | mmap.mmap | memoryview) -> dict[str, Any]:
    errors: list[str] = []
    byte_len = len(image)
    page_count = byte_len // PAGE_SIZE
    trailing_bytes = byte_len % PAGE_SIZE
    if trailing_bytes:
        errors.append("image length is not a multiple of 4096 bytes")
    if page_count < ANCHOR_PAGES:
        errors.append("image is shorter than the 16-page anchor")

    superblocks = [
        decode_pair(image, 0, 1, 1, "superblock copy A", errors, super_validator(0, 0)),
        decode_pair(image, 2, 3, 1, "superblock copy B", errors, super_validator(1, 2)),
    ]
    checkpoints = [
        decode_pair(image, 4, 5, 2, "checkpoint slot A", errors, checkpoint_validator(0, 4)),
        decode_pair(image, 6, 7, 2, "checkpoint slot B", errors, checkpoint_validator(1, 6)),
    ]
    # The remainder of the anchor is permanently reserved in V2.
    for page_no in range(8, min(ANCHOR_PAGES, page_count)):
        page = page_at(image, page_no)
        if page is not None and not all_zero(page):
            errors.append(f"anchor reserved page {page_no} is non-zero")

    selected_super = select_superblock(superblocks, errors)
    selected_checkpoint = select_checkpoint(checkpoints, errors)

    physical_segments = max(0, (page_count - ANCHOR_PAGES) // SEGMENT_PAGES)
    trailing_segment_pages = max(0, page_count - ANCHOR_PAGES) % SEGMENT_PAGES
    if page_count >= ANCHOR_PAGES and trailing_segment_pages:
        errors.append("image has a partial data segment")
    segments = [parse_segment(image, segment_no, errors) for segment_no in range(physical_segments)]

    sealed_checkpoints = [entry for entry in checkpoints if entry["status"] == "sealed"]
    if selected_super is not None:
        for checkpoint in sealed_checkpoints:
            verify_checkpoint_against_superblock(
                checkpoint,
                selected_super,
                physical_segments,
                segments,
                errors,
            )

    selected_store: Optional[dict[str, Any]] = None
    for checkpoint in sealed_checkpoints:
        verified_store = verify_store_checkpoint(image, checkpoint, segments, errors)
        if checkpoint is selected_checkpoint:
            selected_store = verified_store
    store = (
        selected_store
        if selected_store is not None
        else verify_store_checkpoint(image, None, segments, errors)
    )

    any_unsealed = any(
        entry["status"] == "unsealed" for entry in superblocks + checkpoints
    ) or any(segment.get("status") == "incomplete" for segment in segments)
    any_metadata = any(entry["status"] != "empty" for entry in superblocks + checkpoints) or any(
        segment.get("status") != "empty" for segment in segments
    )
    complete_image = (
        trailing_bytes == 0
        and page_count >= ANCHOR_PAGES
        and trailing_segment_pages == 0
    )
    if complete_image and any_metadata and selected_super is None:
        errors.append("non-empty image has no sealed superblock")
    if errors:
        status = "corrupt"
        store["status"] = "corrupt"
    elif not any_metadata:
        status = "empty"
    elif selected_super is not None and selected_checkpoint is None:
        status = "recoverable"
    elif any_unsealed:
        status = "recoverable"
    else:
        status = "ok"

    result = {
        "format": "vibeos-storage-v2",
        "version": FORMAT_VERSION,
        "status": status,
        "image": {
            "byte_length": byte_len,
            "page_count": page_count,
            "physical_segment_count": physical_segments,
        },
        "superblocks": superblocks,
        "selected_superblock": (
            None
            if selected_super is None
            else {
                "copy": selected_super["record"]["copy"],
                "generation": selected_super["record"]["binding"]["generation"],
            }
        ),
        "checkpoints": checkpoints,
        "selected_checkpoint": (
            None
            if selected_checkpoint is None
            else {
                "slot": selected_checkpoint["record"]["slot"],
                "generation": selected_checkpoint["record"]["binding"]["generation"],
            }
        ),
        "store": store,
        "segments": segments,
        "errors": sorted(set(errors)),
    }
    return public_value(result)


# The following fixture encoder is selftest-only.  It also uses literal offsets,
# which keeps the parser independent from the production Rust codec.
def make_body(kind: int, binding: dict[str, Any], payload: bytes) -> tuple[bytes, dict[str, Any]]:
    require(len(payload) == RECORD_PAYLOAD_LENGTHS[kind], "selftest payload has wrong length")
    page = bytearray(PAGE_SIZE)
    page[0:8] = BODY_MAGIC
    put_u16(page, 0x008, FORMAT_VERSION)
    put_u16(page, 0x00A, HEADER_LEN)
    put_u16(page, 0x00C, kind)
    put_u32(page, 0x010, len(payload))
    page[0x018:0x028] = binding["store_uuid"]
    put_u64(page, 0x028, binding["generation"])
    put_u64(page, 0x030, binding["segment_no"])
    put_u32(page, 0x038, binding["ordinal"])
    put_u64(page, 0x040, binding["self_page"])
    put_u64(page, 0x048, binding["target_checkpoint_generation"])
    page[PAYLOAD_OFFSET : PAYLOAD_OFFSET + len(payload)] = payload
    body_crc = crc32c(page[:TRAILER_OFFSET])
    put_u32(page, 0xFD0, body_crc)
    put_u32(page, 0xFD4, complement32(body_crc))
    put_u64(page, 0xFD8, binding["self_page"])
    put_u64(page, 0xFE0, binding["generation"])
    put_u64(page, 0xFE8, binding["segment_no"])
    put_u32(page, 0xFF0, binding["ordinal"])
    put_u16(page, 0xFF4, kind)
    put_u16(page, 0xFF6, FORMAT_VERSION)
    put_u32(page, 0xFF8, len(payload))
    put_u16(page, 0xFFC, HEADER_LEN)
    result = bytes(page)
    return result, {
        "binding": binding,
        "kind": kind,
        "payload_len": len(payload),
        "body_crc32c": body_crc,
        "body_sha256": sha256(result),
    }


def make_seal(digest: dict[str, Any]) -> bytes:
    binding = digest["binding"]
    page = bytearray(PAGE_SIZE)
    page[0:8] = SEAL_MAGIC
    put_u16(page, 0x008, FORMAT_VERSION)
    put_u16(page, 0x00A, digest["kind"])
    put_u16(page, 0x00C, HEADER_LEN)
    page[0x010:0x020] = binding["store_uuid"]
    put_u64(page, 0x020, binding["generation"])
    put_u64(page, 0x028, binding["segment_no"])
    put_u32(page, 0x030, binding["ordinal"])
    put_u64(page, 0x038, binding["self_page"])
    put_u64(page, 0x040, binding["target_checkpoint_generation"])
    put_u32(page, 0x048, digest["body_crc32c"])
    put_u32(page, 0x04C, complement32(digest["body_crc32c"]))
    page[0x050:0x070] = digest["body_sha256"]
    put_u32(page, 0x070, digest["payload_len"])
    seal_crc = crc32c(page[:TRAILER_OFFSET])
    put_u32(page, 0xFD0, seal_crc)
    put_u32(page, 0xFD4, complement32(seal_crc))
    put_u64(page, 0xFD8, binding["self_page"])
    put_u64(page, 0xFE0, binding["generation"])
    put_u64(page, 0xFE8, binding["segment_no"])
    page[0xFF0:0x1000] = TERMINAL_MARKER
    return bytes(page)


def write_page(image: bytearray, page_no: int, page: bytes) -> None:
    image[page_no * PAGE_SIZE : (page_no + 1) * PAGE_SIZE] = page


def write_pair(image: bytearray, body_page: int, kind: int, binding: dict[str, Any], payload: bytes) -> dict[str, Any]:
    body, digest = make_body(kind, binding, payload)
    write_page(image, body_page, body)
    write_page(image, body_page + 1, make_seal(digest))
    return digest


def make_pointer_bytes(pointer: Optional[dict[str, Any]]) -> bytes:
    if pointer is None:
        return bytes(POINTER_SIZE)
    raw = bytearray(POINTER_SIZE)
    raw[0x00:0x10] = pointer["store_uuid"]
    put_u64(raw, 0x10, pointer["segment_no"])
    put_u64(raw, 0x18, pointer["segment_generation"])
    put_u32(raw, 0x20, pointer["descriptor_relative_page"])
    put_u32(raw, 0x24, pointer["payload_relative_page"])
    put_u32(raw, 0x28, pointer["payload_pages"])
    put_u32(raw, 0x2C, pointer["ordinal"])
    put_u64(raw, 0x30, pointer["exact_byte_len"])
    put_u16(raw, 0x38, pointer["extent_kind"])
    put_u16(raw, 0x3A, HASH_ALGORITHM_SHA256)
    raw[0x40:0x60] = pointer["payload_sha256"]
    return bytes(raw)


def selftest_image(
    *,
    segment_count: int = 2,
    data_segment_no: int = 0,
    segment_generation: int = 1,
    target_checkpoint: int = 1,
    previous_segment_no: int = ANCHOR_SEGMENT_NO,
    previous_segment_generation: int = 0,
    previous_segment_seal_body_sha256: bytes = bytes(32),
    catalog_mode: str = "snapshot",
    blob_pointer_segment_no: Optional[int] = None,
    catalog_chain_count: int = 1,
    allocated_prefix_segments: int = 1,
    catalog_magic: bytes = CATALOG_MAGIC,
) -> bytearray:
    # The fixture always leaves at least the mandatory cleaner reserve.
    require(segment_count >= 2, "selftest image needs a usable segment and cleaner reserve")
    require(0 <= data_segment_no < segment_count, "selftest data segment is out of range")
    total_pages = admitted_pages(segment_count)
    image = bytearray(total_pages * PAGE_SIZE)
    store_uuid = bytes(range(1, 17))
    device_id = bytes(range(0x21, 0x31))
    base = segment_base_page(data_segment_no)

    for copy, page_no in ((0, 0), (1, 2)):
        payload = bytearray(0x80)
        payload[0] = copy
        put_u32(payload, 0x08, PAGE_SIZE)
        put_u32(payload, 0x0C, ANCHOR_PAGES)
        put_u32(payload, 0x10, SEGMENT_PAGES)
        put_u32(payload, 0x14, DATA_FIRST_PAGE)
        put_u32(payload, 0x18, DATA_END_PAGE)
        put_u32(payload, 0x1C, SUMMARY_BODY_PAGE)
        put_u32(payload, 0x20, SUMMARY_SEAL_PAGE)
        put_u32(payload, 0x24, SEGMENT_SEAL_BODY_PAGE)
        put_u32(payload, 0x28, SEGMENT_SEAL_PAGE)
        put_u32(payload, 0x2C, MAX_EXTENT_PAYLOAD_PAGES)
        put_u32(payload, 0x30, 1)
        put_u16(payload, 0x34, HASH_ALGORITHM_SHA256)
        put_u64(payload, 0x38, total_pages)
        put_u64(payload, 0x40, ANCHOR_PAGES)
        put_u64(payload, 0x48, segment_count)
        payload[0x50:0x60] = device_id
        put_u64(payload, 0x60, 0)
        put_u64(payload, 0x68, total_pages * (PAGE_SIZE // 512))
        put_u32(payload, 0x70, 512)
        put_u32(payload, 0x78, 64)
        binding = {
            "store_uuid": store_uuid,
            "generation": 1,
            "segment_no": ANCHOR_SEGMENT_NO,
            "ordinal": copy,
            "self_page": page_no,
            "target_checkpoint_generation": 0,
        }
        write_pair(image, page_no, 1, binding, bytes(payload))

    header_payload = bytearray(0x58)
    put_u64(header_payload, 0x00, base)
    put_u32(header_payload, 0x08, DATA_FIRST_PAGE)
    put_u32(header_payload, 0x0C, DATA_END_PAGE)
    put_u32(header_payload, 0x10, SUMMARY_BODY_PAGE)
    put_u32(header_payload, 0x14, SUMMARY_SEAL_PAGE)
    put_u32(header_payload, 0x18, SEGMENT_SEAL_BODY_PAGE)
    put_u32(header_payload, 0x1C, SEGMENT_SEAL_PAGE)
    put_u32(header_payload, 0x20, MAX_EXTENT_PAYLOAD_PAGES)
    put_u16(header_payload, 0x24, 1)
    put_u64(header_payload, 0x28, previous_segment_no)
    put_u64(header_payload, 0x30, previous_segment_generation)
    header_payload[0x38:0x58] = previous_segment_seal_body_sha256
    header_binding = {
        "store_uuid": store_uuid,
        "generation": segment_generation,
        "segment_no": data_segment_no,
        "ordinal": 0,
        "self_page": base,
        "target_checkpoint_generation": target_checkpoint,
    }
    header_digest = write_pair(image, base, 3, header_binding, bytes(header_payload))

    descriptor_chain = chain_initial(
        DESCRIPTOR_CHAIN_DOMAIN, store_uuid, data_segment_no, segment_generation
    )
    payload_chain = chain_initial(
        DATA_CHAIN_DOMAIN, store_uuid, data_segment_no, segment_generation
    )
    relative_page = DATA_FIRST_PAGE
    ordinal = 1
    payload_page_count = 0
    total_payload_bytes = 0
    kind_counts = [0, 0, 0, 0, 0]
    kind_bytes = [0, 0, 0, 0, 0]

    def append_extent(extent_kind: int, object_kind: int, payload_bytes: bytes) -> dict[str, Any]:
        nonlocal descriptor_chain, payload_chain, relative_page, ordinal
        nonlocal payload_page_count, total_payload_bytes
        payload_sha = sha256(payload_bytes)
        pages = ceil_pages(len(payload_bytes))
        for page_index in range(pages):
            payload_page = bytearray(PAGE_SIZE)
            chunk = payload_bytes[page_index * PAGE_SIZE : (page_index + 1) * PAGE_SIZE]
            payload_page[: len(chunk)] = chunk
            write_page(image, base + relative_page + 2 + page_index, bytes(payload_page))
        extent_payload = bytearray(0x80)
        put_u16(extent_payload, 0x00, extent_kind)
        put_u16(extent_payload, 0x02, HASH_ALGORITHM_SHA256)
        put_u32(extent_payload, 0x08, object_kind)
        put_u32(extent_payload, 0x0C, 0)
        put_u32(extent_payload, 0x10, 1)
        put_u32(extent_payload, 0x14, pages)
        put_u64(extent_payload, 0x18, len(payload_bytes))
        put_u64(extent_payload, 0x20, len(payload_bytes))
        put_u64(extent_payload, 0x28, 0)
        put_u64(extent_payload, 0x30, len(payload_bytes))
        put_u32(extent_payload, 0x38, relative_page + 2)
        put_u32(extent_payload, 0x3C, 2 + pages)
        extent_payload[0x40:0x60] = payload_sha
        extent_payload[0x60:0x80] = payload_sha
        binding = {
            "store_uuid": store_uuid,
            "generation": segment_generation,
            "segment_no": data_segment_no,
            "ordinal": ordinal,
            "self_page": base + relative_page,
            "target_checkpoint_generation": target_checkpoint,
        }
        digest = write_pair(image, base + relative_page, 4, binding, bytes(extent_payload))
        descriptor_chain = descriptor_chain_update(
            descriptor_chain,
            store_uuid,
            data_segment_no,
            segment_generation,
            ordinal,
            digest["body_sha256"],
            payload_sha,
        )
        payload_chain = data_chain_update(
            payload_chain,
            store_uuid,
            data_segment_no,
            segment_generation,
            ordinal,
            len(payload_bytes),
            payload_sha,
        )
        pointer = {
            "store_uuid": store_uuid,
            "segment_no": data_segment_no,
            "segment_generation": segment_generation,
            "descriptor_relative_page": relative_page,
            "payload_relative_page": relative_page + 2,
            "payload_pages": pages,
            "ordinal": ordinal,
            "exact_byte_len": len(payload_bytes),
            "extent_kind": extent_kind,
            "payload_sha256": payload_sha,
        }
        kind_counts[extent_kind - 1] += 1
        kind_bytes[extent_kind - 1] += len(payload_bytes)
        payload_page_count += pages
        total_payload_bytes += len(payload_bytes)
        relative_page += 2 + pages
        ordinal += 1
        return pointer

    object_payload = b"storage-v2-independent-parser-selftest"
    object_root = sha256(object_payload)
    blob_pointer = append_extent(1, 1, object_payload)
    catalog_blob_pointer = dict(blob_pointer)
    catalog_blob_pointer["segment_no"] = (
        data_segment_no if blob_pointer_segment_no is None else blob_pointer_segment_no
    )
    catalog_entry = bytearray(CATALOG_ENTRY_SIZE)
    catalog_entry[0x00:0x10] = bytes(range(0x41, 0x51))
    put_u32(catalog_entry, 0x10, 1)
    put_u64(catalog_entry, 0x18, len(object_payload))
    put_u64(catalog_entry, 0x20, target_checkpoint)
    catalog_entry[0x28:0x48] = object_root
    catalog_entry[0x48:0xA8] = make_pointer_bytes(catalog_blob_pointer)

    require(catalog_mode in ("snapshot", "delta"), "invalid selftest catalog mode")
    require(len(catalog_magic) == 8, "selftest catalog magic must be eight bytes")
    if catalog_mode == "snapshot":
        catalog_payload = bytearray(CATALOG_SNAPSHOT_HEADER_SIZE + CATALOG_ENTRY_SIZE)
        catalog_payload[0x00:0x08] = catalog_magic
        put_u16(catalog_payload, 0x08, CATALOG_VERSION)
        put_u16(catalog_payload, 0x0A, CATALOG_SNAPSHOT)
        put_u32(catalog_payload, 0x0C, CATALOG_SNAPSHOT_HEADER_SIZE)
        put_u64(catalog_payload, 0x10, target_checkpoint)
        put_u32(catalog_payload, 0x18, 1)
        put_u32(catalog_payload, 0x1C, CATALOG_ENTRY_SIZE)
        put_u64(catalog_payload, 0x20, catalog_chain_count)
        catalog_payload[CATALOG_SNAPSHOT_HEADER_SIZE:] = catalog_entry
        catalog_pointer = append_extent(2, 2, bytes(catalog_payload))
    else:
        catalog_payload = bytearray(CATALOG_DELTA_HEADER_SIZE + CATALOG_ENTRY_SIZE)
        catalog_payload[0x00:0x08] = catalog_magic
        put_u16(catalog_payload, 0x08, CATALOG_VERSION)
        put_u16(catalog_payload, 0x0A, CATALOG_DELTA)
        put_u32(catalog_payload, 0x0C, CATALOG_DELTA_HEADER_SIZE)
        put_u64(catalog_payload, 0x10, target_checkpoint)
        put_u32(catalog_payload, 0x18, 1)
        put_u32(catalog_payload, 0x1C, CATALOG_ENTRY_SIZE)
        put_u64(catalog_payload, 0x20, catalog_chain_count)
        catalog_payload[CATALOG_DELTA_HEADER_SIZE:] = catalog_entry
        catalog_pointer = append_extent(5, 5, bytes(catalog_payload))

    allocation_payload = bytearray(ALLOCATION_PAYLOAD_SIZE)
    allocation_payload[0x00:0x08] = ALLOCATION_MAGIC
    put_u16(allocation_payload, 0x08, 1)
    put_u16(allocation_payload, 0x0A, ALLOCATION_PAYLOAD_SIZE)
    put_u64(allocation_payload, 0x10, target_checkpoint)
    put_u64(allocation_payload, 0x18, segment_count)
    put_u64(allocation_payload, 0x20, allocated_prefix_segments)
    put_u64(allocation_payload, 0x28, segment_generation + 1)
    put_u32(allocation_payload, 0x30, 1)
    allocation_pointer = append_extent(4, 4, bytes(allocation_payload))

    summary_payload = bytearray(0xC8)
    put_u32(summary_payload, 0x00, ordinal - 1)
    put_u32(summary_payload, 0x04, relative_page)
    put_u32(summary_payload, 0x08, payload_page_count)
    put_u64(summary_payload, 0x10, total_payload_bytes)
    put_u64(summary_payload, 0x18, target_checkpoint)
    put_u64(summary_payload, 0x20, target_checkpoint)
    summary_payload[0x28:0x48] = header_digest["body_sha256"]
    summary_payload[0x48:0x68] = descriptor_chain
    summary_payload[0x68:0x88] = payload_chain
    for kind_index, count in enumerate(kind_counts):
        put_u32(summary_payload, 0x88 + kind_index * 4, count)
    for kind_index, byte_count in enumerate(kind_bytes):
        put_u64(summary_payload, 0xA0 + kind_index * 8, byte_count)
    summary_binding = {
        "store_uuid": store_uuid,
        "generation": segment_generation,
        "segment_no": data_segment_no,
        "ordinal": ordinal,
        "self_page": base + SUMMARY_BODY_PAGE,
        "target_checkpoint_generation": target_checkpoint,
    }
    summary_digest = write_pair(
        image, base + SUMMARY_BODY_PAGE, 5, summary_binding, bytes(summary_payload)
    )

    final_payload = bytearray(0xA0)
    final_payload[0x00:0x20] = header_digest["body_sha256"]
    final_payload[0x20:0x40] = summary_digest["body_sha256"]
    final_payload[0x40:0x60] = descriptor_chain
    final_payload[0x60:0x80] = payload_chain
    put_u32(final_payload, 0x80, ordinal - 1)
    put_u32(final_payload, 0x84, relative_page)
    put_u32(final_payload, 0x88, payload_page_count)
    put_u64(final_payload, 0x90, total_payload_bytes)
    put_u64(final_payload, 0x98, target_checkpoint)
    final_binding = {
        "store_uuid": store_uuid,
        "generation": segment_generation,
        "segment_no": data_segment_no,
        "ordinal": ordinal + 1,
        "self_page": base + SEGMENT_SEAL_BODY_PAGE,
        "target_checkpoint_generation": target_checkpoint,
    }
    write_pair(image, base + SEGMENT_SEAL_BODY_PAGE, 6, final_binding, bytes(final_payload))

    checkpoint_payload = bytearray(0x1C0)
    checkpoint_payload[0] = 0
    put_u64(checkpoint_payload, 0x08, 0)
    put_u64(checkpoint_payload, 0x10, total_pages)
    put_u64(checkpoint_payload, 0x18, segment_count)
    put_u64(checkpoint_payload, 0x20, segment_generation + 1)
    put_u32(checkpoint_payload, 0x28, 0 if catalog_mode == "snapshot" else 1)
    put_u32(checkpoint_payload, 0x2C, 64)
    put_u32(checkpoint_payload, 0x30, 1)
    if catalog_mode == "snapshot":
        checkpoint_payload[0x40:0xA0] = make_pointer_bytes(catalog_pointer)
    else:
        checkpoint_payload[0x160:0x1C0] = make_pointer_bytes(catalog_pointer)
    checkpoint_payload[0x100:0x160] = make_pointer_bytes(allocation_pointer)
    checkpoint_binding = {
        "store_uuid": store_uuid,
        "generation": 1,
        "segment_no": ANCHOR_SEGMENT_NO,
        "ordinal": 0,
        "self_page": 4,
        "target_checkpoint_generation": 1,
    }
    write_pair(image, 4, 2, checkpoint_binding, bytes(checkpoint_payload))
    return image


def rewrite_selftest_pair(
    image: bytearray,
    body_page: int,
    kind: int,
    mutate_payload: Callable[[bytearray], None],
    binding_updates: Optional[dict[str, Any]] = None,
) -> None:
    body = page_at(image, body_page)
    require(body is not None, "selftest pair body is outside image")
    digest = parse_body(body, kind)
    payload = bytearray(body[PAYLOAD_OFFSET : PAYLOAD_OFFSET + RECORD_PAYLOAD_LENGTHS[kind]])
    mutate_payload(payload)
    binding = dict(digest["binding"])
    if binding_updates:
        binding.update(binding_updates)
    write_pair(image, body_page, kind, binding, bytes(payload))


def publish_selftest_checkpoint(image: bytearray, generation: int) -> None:
    source = page_at(image, 4)
    require(source is not None, "selftest checkpoint source is outside image")
    source_digest = parse_body(source, 2)
    payload = bytearray(source[PAYLOAD_OFFSET : PAYLOAD_OFFSET + RECORD_PAYLOAD_LENGTHS[2]])
    slot = (generation - 1) & 1
    body_page = 4 + slot * 2
    payload[0] = slot
    put_u64(payload, 0x08, 0 if generation == 1 else generation - 1)
    binding = dict(source_digest["binding"])
    binding.update(
        {
            "generation": generation,
            "ordinal": slot,
            "self_page": body_page,
            "target_checkpoint_generation": generation,
        }
    )
    write_pair(image, body_page, 2, binding, bytes(payload))


def run_selftest() -> dict[str, Any]:
    tests: list[str] = []
    image = selftest_image()
    valid = parse_image(image)
    require(valid["status"] == "ok", f"valid image rejected: {valid['errors']}")
    require(valid["selected_checkpoint"] == {"slot": 0, "generation": 1}, "checkpoint selection failed")
    require(valid["segments"][0]["status"] == "sealed", "sealed segment was not accepted")
    require(valid["store"]["status"] == "verified", "store roots were not verified")
    require(valid["store"]["object_count"] == 1, "catalog object was not reconstructed")
    require(not valid["store"]["orphan_extents"], "reachable extents were reported as orphans")
    tests.append("valid")

    committed_with_room = selftest_image(segment_count=3)
    predecessor_body = page_at(
        committed_with_room,
        segment_base_page(0) + SEGMENT_SEAL_BODY_PAGE,
    )
    require(predecessor_body is not None, "selftest predecessor body is outside image")
    orphan_source = selftest_image(
        segment_count=3,
        data_segment_no=1,
        segment_generation=2,
        target_checkpoint=2,
        previous_segment_no=0,
        previous_segment_generation=1,
        previous_segment_seal_body_sha256=sha256(predecessor_body),
        allocated_prefix_segments=2,
    )
    orphan_start = segment_base_page(1) * PAGE_SIZE
    orphan_end = orphan_start + SEGMENT_PAGES * PAGE_SIZE
    committed_with_room[orphan_start:orphan_end] = orphan_source[orphan_start:orphan_end]
    sealed_orphan = parse_image(committed_with_room)
    require(
        sealed_orphan["status"] == "ok",
        f"fully sealed crash orphan rejected: {sealed_orphan['errors']}",
    )
    require(
        sealed_orphan["selected_checkpoint"] == {"slot": 0, "generation": 1},
        "sealed orphan advanced the checkpoint",
    )
    require(sealed_orphan["store"]["object_count"] == 1, "sealed orphan published its object")
    require(
        len(sealed_orphan["store"]["orphan_extents"]) == 3,
        "sealed orphan extents were not reported",
    )
    tests.append("sealed_orphan_may_use_next_generation")

    reachable_at_next_generation = bytearray(image)

    def roll_back_next_generation(payload: bytearray) -> None:
        put_u64(payload, 0x20, 1)

    rewrite_selftest_pair(
        reachable_at_next_generation,
        4,
        2,
        roll_back_next_generation,
    )
    reachable_at_next_result = parse_image(reachable_at_next_generation)
    require(
        reachable_at_next_result["status"] == "corrupt",
        "reachable segment at next generation was accepted",
    )
    require(
        any("pointer segment generation is not committed" in error
            for error in reachable_at_next_result["errors"]),
        "reachable next-generation pointer was not diagnosed",
    )
    tests.append("next_generation_applies_only_to_reachable_extents")

    delta_result = parse_image(selftest_image(catalog_mode="delta"))
    require(delta_result["status"] == "ok", f"valid delta rejected: {delta_result['errors']}")
    require(delta_result["store"]["object_count"] == 1, "delta replay did not reconstruct object")
    tests.append("catalog_delta_replay")

    bad_delta_count = parse_image(selftest_image(catalog_mode="delta", catalog_chain_count=2))
    require(bad_delta_count["status"] == "corrupt", "wrong delta chain count was accepted")
    require(
        any("chain count and previous pointer disagree" in error for error in bad_delta_count["errors"]),
        "wrong delta chain count was not diagnosed",
    )
    tests.append("catalog_delta_bound")

    old_malformed = selftest_image(catalog_magic=b"BADCAT!!")
    publish_selftest_checkpoint(old_malformed, 2)

    def make_new_checkpoint_empty(payload: bytearray) -> None:
        put_u32(payload, 0x28, 0)
        payload[0x40:0x1C0] = bytes(0x180)

    rewrite_selftest_pair(old_malformed, 6, 2, make_new_checkpoint_empty)
    old_malformed_result = parse_image(old_malformed)
    require(
        old_malformed_result["selected_checkpoint"] == {"slot": 1, "generation": 2},
        "new structurally valid checkpoint was not selected",
    )
    require(old_malformed_result["status"] == "corrupt", "malformed old sealed metadata was ignored")
    require(old_malformed_result["store"]["status"] == "corrupt", "store status did not fail closed")
    require(
        any("checkpoint generation 1 catalog_root payload: invalid catalog magic" in error
            for error in old_malformed_result["errors"]),
        "malformed old sealed metadata was not diagnosed",
    )
    tests.append("every_sealed_checkpoint_metadata")

    outside_blob = parse_image(selftest_image(blob_pointer_segment_no=2))
    require(outside_blob["status"] == "corrupt", "out-of-range committed Blob was accepted")
    require(
        any("pointer references an unadmitted segment" in error for error in outside_blob["errors"]),
        "out-of-range committed Blob was not diagnosed",
    )
    tests.append("committed_blob_range")

    outside_prefix = parse_image(selftest_image(allocated_prefix_segments=0))
    require(outside_prefix["status"] == "corrupt", "reachable extent outside allocation was accepted")
    require(
        any("empty allocated prefix" in error for error in outside_prefix["errors"]),
        "allocation prefix escape was not diagnosed",
    )
    tests.append("allocation_prefix")

    orphan = bytearray(image)

    def drop_catalog_root(payload: bytearray) -> None:
        payload[0x40:0xA0] = bytes(POINTER_SIZE)

    rewrite_selftest_pair(orphan, 4, 2, drop_catalog_root)
    orphan_result = parse_image(orphan)
    require(orphan_result["status"] == "ok", f"orphan tail was rejected: {orphan_result['errors']}")
    require(orphan_result["store"]["object_count"] == 0, "orphan Blob became a committed object")
    require(
        any(item["extent_kind"] == "blob" for item in orphan_result["store"]["orphan_extents"]),
        "orphan Blob was not reported",
    )
    tests.append("catalog_only_discovery_and_orphans")

    pair_errors: list[str] = []
    empty_pair = decode_pair(bytes(PAGE_SIZE * 2), 0, 1, 1, "empty", pair_errors)
    require(empty_pair["status"] == "empty" and not pair_errors, "empty pair classification failed")
    tests.append("empty")

    unsealed_image = bytearray(PAGE_SIZE * 2)
    unsealed_image[0:PAGE_SIZE] = image[0:PAGE_SIZE]
    unsealed_pair = decode_pair(unsealed_image, 0, 1, 1, "unsealed", pair_errors)
    require(unsealed_pair["status"] == "unsealed" and not pair_errors, "unsealed pair classification failed")
    tests.append("unsealed")

    # Every strict prefix of a seal page, including every prefix of the final
    # publication marker, remains untrusted.  The complete page alone seals it.
    valid_body = bytes(image[0:PAGE_SIZE])
    valid_seal = bytes(image[PAGE_SIZE : 2 * PAGE_SIZE])
    for prefix_len in range(PAGE_SIZE):
        prefix_image = bytearray(PAGE_SIZE * 2)
        prefix_image[0:PAGE_SIZE] = valid_body
        prefix_image[PAGE_SIZE : PAGE_SIZE + prefix_len] = valid_seal[:prefix_len]
        prefix_errors: list[str] = []
        prefix_pair = decode_pair(
            prefix_image,
            0,
            1,
            1,
            "seal prefix",
            prefix_errors,
            super_validator(0, 0),
        )
        require(prefix_pair["status"] == "unsealed", f"seal prefix {prefix_len} was trusted")
        require(not prefix_errors, f"seal prefix {prefix_len} was treated as corruption")
    complete_pair_errors: list[str] = []
    complete_pair = decode_pair(
        valid_body + valid_seal,
        0,
        1,
        1,
        "complete seal",
        complete_pair_errors,
        super_validator(0, 0),
    )
    require(complete_pair["status"] == "sealed" and not complete_pair_errors, "complete seal rejected")
    tests.append("all_seal_page_prefixes")

    checkpoint_seal_offset = 5 * PAGE_SIZE
    for marker_prefix_len in range(len(TERMINAL_MARKER) + 1):
        marker_image = bytearray(image)
        marker_start = checkpoint_seal_offset + 0xFF0
        marker_image[marker_start : marker_start + len(TERMINAL_MARKER)] = bytes(
            len(TERMINAL_MARKER)
        )
        marker_image[marker_start : marker_start + marker_prefix_len] = TERMINAL_MARKER[
            :marker_prefix_len
        ]
        marker_result = parse_image(marker_image)
        expected_status = "ok" if marker_prefix_len == len(TERMINAL_MARKER) else "recoverable"
        require(
            marker_result["status"] == expected_status,
            f"full-image marker prefix {marker_prefix_len} classified as {marker_result['status']}",
        )
    tests.append("full_image_strict_marker_prefixes")

    empty_image = bytes(admitted_pages(2) * PAGE_SIZE)
    empty_result = parse_image(empty_image)
    require(empty_result["status"] == "empty" and not empty_result["errors"], "empty image rejected")

    no_super = bytearray(image)
    no_super[0 : 4 * PAGE_SIZE] = bytes(4 * PAGE_SIZE)
    no_super_result = parse_image(no_super)
    require(no_super_result["status"] == "corrupt", "metadata without a superblock was accepted")
    require(
        "non-empty image has no sealed superblock" in no_super_result["errors"],
        "missing superblock was not diagnosed",
    )

    no_checkpoint = bytearray(image)
    no_checkpoint[4 * PAGE_SIZE : 8 * PAGE_SIZE] = bytes(4 * PAGE_SIZE)
    no_checkpoint_result = parse_image(no_checkpoint)
    require(
        no_checkpoint_result["status"] == "recoverable" and not no_checkpoint_result["errors"],
        "superblock without checkpoint was not recoverable",
    )
    tests.append("empty_no_super_no_checkpoint_statuses")

    gap = bytearray(image)
    publish_selftest_checkpoint(gap, 4)
    gap_result = parse_image(gap)
    require(gap_result["status"] == "corrupt", "checkpoint generation gap was accepted")
    require(
        "checkpoint generations are not contiguous" in gap_result["errors"],
        "checkpoint generation gap was not diagnosed",
    )
    tests.append("checkpoint_gap")

    foreign_pointer = bytearray(image)
    publish_selftest_checkpoint(foreign_pointer, 2)

    def make_catalog_pointer_foreign(payload: bytearray) -> None:
        payload[0x40:0x50] = bytes([0xA5]) * 16

    rewrite_selftest_pair(foreign_pointer, 4, 2, make_catalog_pointer_foreign)
    foreign_result = parse_image(foreign_pointer)
    require(foreign_result["status"] == "corrupt", "foreign checkpoint pointer was accepted")
    require(
        any(
            "checkpoint generation 1 catalog_root: pointer UUID mismatch" in error
            for error in foreign_result["errors"]
        ),
        "non-selected checkpoint pointer was not validated",
    )
    tests.append("every_checkpoint_foreign_pointer")

    amplified = bytearray(image)

    def amplify_allocation(payload: bytearray) -> None:
        put_u64(payload, 0x10, admitted_pages(3))
        put_u64(payload, 0x18, 3)

    rewrite_selftest_pair(amplified, 4, 2, amplify_allocation)
    amplified_result = parse_image(amplified)
    require(amplified_result["status"] == "corrupt", "allocation amplification was accepted")
    require(
        any("admits segments beyond the image" in error for error in amplified_result["errors"]),
        "allocation amplification was not diagnosed",
    )
    tests.append("allocation_amplification")

    overlap = bytearray(image)

    def overlap_checkpoint_roots(payload: bytearray) -> None:
        payload[0xA0:0x100] = payload[0x40:0xA0]
        put_u16(payload, 0xA0 + 0x38, 3)

    rewrite_selftest_pair(overlap, 4, 2, overlap_checkpoint_roots)
    overlap_result = parse_image(overlap)
    require(overlap_result["status"] == "corrupt", "overlapping roots were accepted")
    require(
        any("pointers catalog_root and authority_root overlap" in error for error in overlap_result["errors"]),
        "overlapping roots were not diagnosed",
    )
    tests.append("pointer_overlap")

    payload_corruption = bytearray(image)
    payload_corruption[(segment_base_page(0) + 4) * PAGE_SIZE] ^= 0x01
    payload_result = parse_image(payload_corruption)
    require(payload_result["status"] == "corrupt", "payload corruption was accepted")
    require(
        any("payload SHA-256 mismatch" in error for error in payload_result["errors"]),
        "payload corruption was not diagnosed",
    )
    tests.append("payload_corruption")

    invalid_predecessor = bytearray(image)

    def make_predecessor_not_older(payload: bytearray) -> None:
        put_u64(payload, 0x28, 1)
        put_u64(payload, 0x30, 1)
        payload[0x38:0x58] = bytes([0x5A]) * 32

    rewrite_selftest_pair(
        invalid_predecessor,
        segment_base_page(0),
        3,
        make_predecessor_not_older,
    )
    predecessor_result = parse_image(invalid_predecessor)
    require(predecessor_result["status"] == "corrupt", "invalid predecessor tuple was accepted")
    require(
        any("predecessor generation is not older" in error for error in predecessor_result["errors"]),
        "invalid predecessor generation was not diagnosed",
    )

    # A crash orphan may consume physical segment zero before any segment is
    # finalized.  The first finalized chain member is therefore allowed to
    # start at any admitted physical segment, while the anchor predecessor
    # fields must still appear as one exact all-or-nothing tuple.
    first_nonzero_segment = 1
    first_nonzero_base = segment_base_page(first_nonzero_segment)
    first_nonzero_binding = {
        "store_uuid": bytes(range(1, 17)),
        "generation": 1,
        "segment_no": first_nonzero_segment,
        "ordinal": 0,
        "self_page": first_nonzero_base,
        "target_checkpoint_generation": 1,
    }
    first_nonzero_record = {
        "base_page": first_nonzero_base,
        "previous_segment_no": ANCHOR_SEGMENT_NO,
        "previous_segment_generation": 0,
        "previous_segment_seal_body_sha256": bytes(32),
    }
    segment_header_validator(first_nonzero_segment, first_nonzero_base)(
        first_nonzero_record,
        {"binding": first_nonzero_binding},
    )

    reused = selftest_image(
        segment_generation=2,
        previous_segment_no=1,
        previous_segment_generation=1,
        previous_segment_seal_body_sha256=sha256(b"retired predecessor seal body"),
    )
    reused_result = parse_image(reused)
    require(
        reused_result["status"] == "ok" and not reused_result["errors"],
        f"reused segment zero was rejected: {reused_result['errors']}",
    )
    tests.append("predecessor_shape_first_finalized_and_reused_segment")

    overflowing_range = bytearray(image)

    def overflow_logical_range(payload: bytearray) -> None:
        put_u64(payload, 0x60, U64_MAX)

    rewrite_selftest_pair(overflowing_range, 0, 1, overflow_logical_range)
    rewrite_selftest_pair(overflowing_range, 2, 1, overflow_logical_range)
    overflow_result = parse_image(overflowing_range)
    require(overflow_result["status"] == "corrupt", "overflowing logical range was accepted")
    require(
        any("logical block range overflows u64" in error for error in overflow_result["errors"]),
        "logical range overflow was not diagnosed",
    )
    tests.append("logical_range_overflow")

    corrupt = bytearray(image)
    corrupt[0x088] ^= 0x01
    corrupt_result = parse_image(corrupt)
    require(corrupt_result["status"] == "corrupt", "sealed corruption was not rejected")
    require(any("superblock copy A" in error for error in corrupt_result["errors"]), "corruption was not reported")
    tests.append("corrupt")
    return {"selftest": "ok", "tests": tests}


def dump_json(value: dict[str, Any], pretty: bool) -> None:
    if pretty:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", help="raw Storage V2 image to inspect")
    parser.add_argument("--selftest", action="store_true", help="run independent in-memory parser tests")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args(argv)
    if args.selftest:
        if args.image is not None:
            parser.error("--selftest does not accept an image")
        try:
            dump_json(run_selftest(), args.pretty)
            return 0
        except FormatViolation as exc:
            dump_json({"selftest": "failed", "error": str(exc)}, args.pretty)
            return 1
    if args.image is None:
        parser.error("an image path or --selftest is required")
    try:
        with open(args.image, "rb") as image_file:
            if os.fstat(image_file.fileno()).st_size == 0:
                result = parse_image(b"")
            else:
                with mmap.mmap(image_file.fileno(), 0, access=mmap.ACCESS_READ) as image:
                    result = parse_image(image)
        dump_json(result, args.pretty)
        return 0 if not result["errors"] else 1
    except OSError as exc:
        dump_json({"format": "vibeos-storage-v2", "status": "io_error", "errors": [str(exc)]}, args.pretty)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
