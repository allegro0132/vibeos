#!/usr/bin/env python3
"""Powered-off verifier for Storage V2 M7.6 growth and anonymous scrub.

The verifier reuses the frozen physical parser and the independent M7.5 CAS /
Blob verifier.  Its public JSON is intentionally a closed, anonymous schema:
it contains aggregate counts only and never emits store UUIDs, ObjectIds,
BlobKeys, ObjectKinds, physical pointers, paths, or error locations.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import mmap
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional


def load_gc_verifier() -> Any:
    path = Path(__file__).with_name("verify-storage-v2-gc.py")
    spec = importlib.util.spec_from_file_location(
        "vibeos_storage_v2_maintenance_gc", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("the frozen Storage V2 GC verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gc = load_gc_verifier()
storage = gc.storage
Violation = storage.FormatViolation

U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
SEGMENT_BYTES = storage.SEGMENT_PAGES * storage.PAGE_SIZE

DOMAIN_NAMES = (
    "input",
    "anchor",
    "segment_metadata",
    "allocation_or_mapping",
    "blob_data_or_tree",
    "authority_graph",
    "device_io",
)

RESULT_KEYS = frozenset(("format", "version", "status", "growth", "scrub"))
GROWTH_KEYS = frozenset(
    (
        "state",
        "verified",
        "previous_generation",
        "selected_generation",
        "previous_admitted_segments",
        "admitted_segments",
        "added_segments",
        "metadata_carriers",
        "new_free_segments",
    )
)
SCRUB_KEYS = frozenset(
    (
        "schema_version",
        "status",
        "device_health",
        "checkpoint_generation",
        "verified_checkpoint_copies",
        "checkpoint_fallback_verified",
        "admitted_segments",
        "allocated_segments",
        "retired_segments",
        "free_segments",
        "verified_segments",
        "live_objects",
        "unique_blobs",
        "logical_live_bytes",
        "unique_blob_bytes",
        "deduplicated_bytes_saved",
        "physical_capacity_bytes",
        "physical_allocated_bytes",
        "physical_high_water_ppm",
        "gc_pressure_ppm",
        "device_io_failures",
        "quota_logical_high_water_bytes",
        "quota_physical_high_water_bytes",
        "verified_record_pairs",
        "verified_payload_bytes",
        "corruption_signals",
        "corruption_domains",
    )
)
DOMAIN_KEYS = frozenset((*DOMAIN_NAMES, "saturated"))
PUBLIC_STRING_VALUES = frozenset(
    (
        "vibeos-storage-v2-maintenance-raw",
        "ok",
        "corrupt",
        "healthy",
        "readable",
        "io-error",
        "not-observed",
        "verified",
    )
)
FORBIDDEN_PUBLIC_KEY_FRAGMENTS = (
    "store_uuid",
    "device_id",
    "object_id",
    "blob_key",
    "object_kind",
    "digest",
    "hash",
    "sha",
    "pointer",
    "segment_no",
    "page_no",
    "logical_block",
    "physical_block",
    "offset",
    "address",
    "path",
    "error_message",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Violation(message)


def require_exact_keys(value: Any, keys: frozenset[str], label: str) -> None:
    require(type(value) is dict, f"{label} is not an object")
    require(set(value) == keys, f"{label} schema is not closed")


def require_public_counter(value: Any, label: str) -> None:
    require(
        type(value) is int and 0 <= value <= U64_MAX,
        f"{label} is not an anonymous u64 counter",
    )


def require_optional_public_counter(value: Any, label: str) -> None:
    if value is not None:
        require_public_counter(value, label)


def require_closed_public_result(value: Any) -> None:
    """Recursively enforce the exact anonymous wire schema.

    This is deliberately stricter than checking the serialized text for a few
    known identities.  Public strings are an enum, all leaves are scalar, and
    every object has an exact key set, so bytes, arrays, identifiers, hashes,
    paths, or a newly-added diagnostic field cannot escape by accident.
    """

    require_exact_keys(value, RESULT_KEYS, "maintenance result")
    require(
        value["format"] == "vibeos-storage-v2-maintenance-raw",
        "maintenance result format is invalid",
    )
    require(
        type(value["version"]) is int and value["version"] == 1,
        "maintenance result version is invalid",
    )
    require(value["status"] in ("ok", "corrupt"), "maintenance status is invalid")

    growth = value["growth"]
    require_exact_keys(growth, GROWTH_KEYS, "growth result")
    require(
        growth["state"] in ("not-observed", "verified", "corrupt"),
        "growth state is invalid",
    )
    require(type(growth["verified"]) is bool, "growth verified flag is invalid")
    for key in (
        "previous_generation",
        "selected_generation",
        "previous_admitted_segments",
        "admitted_segments",
    ):
        require_optional_public_counter(growth[key], f"growth {key}")
    for key in ("added_segments", "metadata_carriers", "new_free_segments"):
        require_public_counter(growth[key], f"growth {key}")

    scrub = value["scrub"]
    require_exact_keys(scrub, SCRUB_KEYS, "scrub result")
    require(
        type(scrub["schema_version"]) is int and scrub["schema_version"] == 1,
        "scrub schema version is invalid",
    )
    require(scrub["status"] in ("healthy", "corrupt"), "scrub status is invalid")
    require(
        scrub["device_health"] in ("readable", "io-error"),
        "scrub device health is invalid",
    )
    require(
        type(scrub["checkpoint_fallback_verified"]) is bool,
        "scrub fallback flag is invalid",
    )
    require_optional_public_counter(
        scrub["checkpoint_generation"], "scrub checkpoint_generation"
    )
    for key in SCRUB_KEYS - {
        "schema_version",
        "status",
        "device_health",
        "checkpoint_generation",
        "checkpoint_fallback_verified",
        "corruption_domains",
    }:
        require_public_counter(scrub[key], f"scrub {key}")

    domains = scrub["corruption_domains"]
    require_exact_keys(domains, DOMAIN_KEYS, "corruption domains")
    for key in DOMAIN_NAMES:
        require_public_counter(domains[key], f"corruption domain {key}")
    require(type(domains["saturated"]) is bool, "corruption saturation flag is invalid")

    def reject_sensitive(node: Any) -> None:
        if type(node) is dict:
            for key, child in node.items():
                lowered = key.lower()
                require(
                    not any(fragment in lowered for fragment in FORBIDDEN_PUBLIC_KEY_FRAGMENTS),
                    "public schema contains a sensitive key",
                )
                reject_sensitive(child)
        elif type(node) is str:
            require(node in PUBLIC_STRING_VALUES, "public schema contains free-form text")
        else:
            require(
                node is None or type(node) in (bool, int),
                "public schema contains a non-scalar or opaque value",
            )

    reject_sensitive(value)


def public_schema_shape(value: Any) -> Any:
    """Return a value-free recursive schema shape for CLI regression tests."""

    if type(value) is dict:
        return {key: public_schema_shape(value[key]) for key in sorted(value)}
    if value is None:
        return "counter"
    if type(value) is bool:
        return "bool"
    if type(value) is int:
        return "counter"
    if type(value) is str:
        return "enum-string"
    return type(value).__name__


class AnonymousIssues:
    """Internal detailed failures collapse into fixed public counters."""

    def __init__(self) -> None:
        self.counts = {name: 0 for name in DOMAIN_NAMES}
        self.saturated = False

    def add(self, domain: str, count: int = 1) -> None:
        require(domain in self.counts, "unknown anonymous corruption domain")
        require(count >= 0, "anonymous corruption count is negative")
        remaining = U32_MAX - self.counts[domain]
        if count > remaining:
            self.counts[domain] = U32_MAX
            self.saturated = True
        else:
            self.counts[domain] += count

    def any(self) -> bool:
        return any(self.counts.values())

    def public(self) -> dict[str, Any]:
        return {**self.counts, "saturated": self.saturated}


def null_growth() -> dict[str, Any]:
    return {
        "state": "not-observed",
        "verified": False,
        "previous_generation": None,
        "selected_generation": None,
        "previous_admitted_segments": None,
        "admitted_segments": None,
        "added_segments": 0,
        "metadata_carriers": 0,
        "new_free_segments": 0,
    }


def empty_scrub(issues: AnonymousIssues) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "corrupt" if issues.any() else "healthy",
        "device_health": "io-error" if issues.counts["device_io"] else "readable",
        "checkpoint_generation": None,
        "verified_checkpoint_copies": 0,
        "checkpoint_fallback_verified": False,
        "admitted_segments": 0,
        "allocated_segments": 0,
        "retired_segments": 0,
        "free_segments": 0,
        "verified_segments": 0,
        "live_objects": 0,
        "unique_blobs": 0,
        "logical_live_bytes": 0,
        "unique_blob_bytes": 0,
        "deduplicated_bytes_saved": 0,
        "physical_capacity_bytes": 0,
        "physical_allocated_bytes": 0,
        "physical_high_water_ppm": 0,
        "gc_pressure_ppm": 0,
        "device_io_failures": 0,
        "quota_logical_high_water_bytes": 0,
        "quota_physical_high_water_bytes": 0,
        "verified_record_pairs": 0,
        "verified_payload_bytes": 0,
        "corruption_signals": 0,
        "corruption_domains": issues.public(),
    }


def closed_result(
    issues: AnonymousIssues,
    growth: Optional[dict[str, Any]] = None,
    scrub: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    growth = null_growth() if growth is None else growth
    scrub = empty_scrub(issues) if scrub is None else scrub
    scrub["status"] = "corrupt" if issues.any() else "healthy"
    scrub["device_health"] = (
        "io-error" if issues.counts["device_io"] else "readable"
    )
    scrub["device_io_failures"] = issues.counts["device_io"]
    scrub["corruption_signals"] = min(U32_MAX, sum(issues.counts.values()))
    scrub["corruption_domains"] = issues.public()
    if growth["state"] == "corrupt":
        growth["verified"] = False
    result = {
        "format": "vibeos-storage-v2-maintenance-raw",
        "version": 1,
        "status": "corrupt" if issues.any() else "ok",
        "growth": growth,
        "scrub": scrub,
    }
    require_closed_public_result(result)
    return result


def require_allocation_within_physical_segments(
    allocation: dict[str, Any], physical_segments: int, label: str
) -> None:
    """Validate every allocation index before any list access."""

    require(
        type(physical_segments) is int and physical_segments >= 0,
        f"{label} physical size is invalid",
    )
    admitted = allocation["admitted_segments"]
    states = allocation["states"]
    retired = allocation["retired"]
    counts = allocation["counts"]
    require(
        type(admitted) is int and 0 < admitted <= physical_segments,
        f"{label} admits unavailable physical segments",
    )
    require(
        type(states) is list and len(states) == admitted,
        f"{label} state map does not exactly cover admission",
    )
    require(
        all(
            state in (gc.SEGMENT_FREE, gc.SEGMENT_ALLOCATED, gc.SEGMENT_RETIRED)
            for state in states
        ),
        f"{label} state map contains an invalid state",
    )
    require(type(retired) is list, f"{label} retirement table is invalid")
    for entry in retired:
        segment_no = entry["segment_no"]
        require(
            type(segment_no) is int and 0 <= segment_no < admitted,
            f"{label} retirement index is outside admission",
        )
        require(
            states[segment_no] == gc.SEGMENT_RETIRED,
            f"{label} retirement index is not retired",
        )
    require(type(counts) is dict, f"{label} counters are invalid")
    observed = {
        "free": states.count(gc.SEGMENT_FREE),
        "allocated": states.count(gc.SEGMENT_ALLOCATED),
        "retired": states.count(gc.SEGMENT_RETIRED),
    }
    require(counts == observed, f"{label} counters do not match the state map")


def pointer_equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("status") != right.get("status"):
        return False
    if left.get("status") == "null":
        return True
    fields = (
        "store_uuid",
        "segment_no",
        "segment_generation",
        "descriptor_relative_page",
        "payload_relative_page",
        "payload_pages",
        "ordinal",
        "exact_byte_len",
        "extent_kind",
        "hash_algorithm",
        "payload_sha256",
    )
    return all(left.get(field) == right.get(field) for field in fields)


def decode_checkpoint_allocation(
    image: Any,
    checkpoint: dict[str, Any],
    segments: list[dict[str, Any]],
) -> dict[str, Any]:
    record = checkpoint["record"]
    generation = record["binding"]["generation"]
    pointer = record["allocation_root"]
    admitted = record["admitted_segments"]
    require(
        type(admitted) is int and 0 < admitted <= len(segments),
        "checkpoint admission exceeds physical segments",
    )
    if pointer["status"] == "null":
        require(generation == 1, "only the initial checkpoint may omit allocation-v2")
        allocation = {
            "checkpoint_generation": generation,
            "admitted_segments": admitted,
            "next_segment_generation": record["next_segment_generation"],
            "cleaner_reserve_segments": record["cleaner_reserve_segments"],
            "states": [gc.SEGMENT_FREE] * admitted,
            "retired": [],
            "counts": {"free": admitted, "allocated": 0, "retired": 0},
        }
        require_allocation_within_physical_segments(
            allocation, len(segments), "initial allocation"
        )
        return allocation

    require(pointer["status"] == "value", "allocation root status is invalid")
    require(
        type(pointer["segment_no"]) is int
        and 0 <= pointer["segment_no"] < admitted
        and pointer["segment_no"] < len(segments),
        "allocation root is outside physical admission",
    )

    resolver = gc.RawImageResolver(image, checkpoint, segments)
    extent, payload = resolver.resolve(
        pointer,
        gc.EXTENT_ALLOCATION,
        "allocation root",
        metadata=True,
        current=False,
    )
    if len(payload) == storage.ALLOCATION_PAYLOAD_SIZE:
        legacy = storage.parse_allocation_payload(payload, extent)
        legacy_admitted = legacy["admitted_segments"]
        allocated_prefix = legacy["allocated_prefix_segments"]
        require(
            type(legacy_admitted) is int
            and 0 < legacy_admitted <= len(segments)
            and type(allocated_prefix) is int
            and 0 <= allocated_prefix <= legacy_admitted,
            "legacy allocation prefix is outside physical admission",
        )
        require(
            0 < legacy["cleaner_reserve_segments"] < legacy_admitted
            and legacy_admitted - allocated_prefix
            >= legacy["cleaner_reserve_segments"],
            "legacy allocation cleaner reserve is invalid",
        )
        states = [gc.SEGMENT_ALLOCATED] * allocated_prefix + [
            gc.SEGMENT_FREE
        ] * (legacy_admitted - allocated_prefix)
        allocation = {
            "checkpoint_generation": legacy["checkpoint_generation"],
            "admitted_segments": legacy_admitted,
            "next_segment_generation": legacy["next_segment_generation"],
            "cleaner_reserve_segments": legacy["cleaner_reserve_segments"],
            "states": states,
            "retired": [],
            "counts": {
                "free": legacy_admitted - allocated_prefix,
                "allocated": allocated_prefix,
                "retired": 0,
            },
        }
    else:
        allocation = gc.parse_allocation_v2(payload)
    require(
        allocation["checkpoint_generation"] == generation,
        "allocation generation differs from checkpoint",
    )
    require(
        allocation["checkpoint_generation"]
        == extent["binding"]["target_checkpoint_generation"],
        "allocation generation differs from extent target",
    )
    require(
        allocation["admitted_segments"] == record["admitted_segments"],
        "allocation admitted count differs from checkpoint",
    )
    require(
        allocation["next_segment_generation"]
        == record["next_segment_generation"],
        "allocation segment-generation high-water differs from checkpoint",
    )
    require(
        allocation["cleaner_reserve_segments"]
        == record["cleaner_reserve_segments"],
        "allocation cleaner reserve differs from checkpoint",
    )
    require_allocation_within_physical_segments(
        allocation, len(segments), "checkpoint allocation"
    )
    require(
        allocation["states"][pointer["segment_no"]] == gc.SEGMENT_ALLOCATED,
        "allocation root carrier is not allocated",
    )
    return allocation


def find_segment(
    segments: list[dict[str, Any]], segment_no: int
) -> dict[str, Any]:
    segment = next(
        (candidate for candidate in segments if candidate["segment_no"] == segment_no),
        None,
    )
    require(segment is not None, "segment is absent")
    return segment


def validate_growth_transition(
    older: dict[str, Any],
    newer: dict[str, Any],
    older_allocation: dict[str, Any],
    newer_allocation: dict[str, Any],
    segments: list[dict[str, Any]],
    physical_segments: int,
) -> dict[str, Any]:
    old = older["record"]
    new = newer["record"]
    require(
        physical_segments == len(segments),
        "growth physical segment evidence is inconsistent",
    )
    require_allocation_within_physical_segments(
        older_allocation, physical_segments, "older growth allocation"
    )
    require_allocation_within_physical_segments(
        newer_allocation, physical_segments, "newer growth allocation"
    )
    old_generation = old["binding"]["generation"]
    new_generation = new["binding"]["generation"]
    require(new_generation == old_generation + 1, "growth is not exactly G+1")
    require(new["previous_generation"] == old_generation, "growth predecessor is not G")
    require(
        new["binding"]["store_uuid"] == old["binding"]["store_uuid"],
        "growth changes store binding",
    )
    require(
        new["admitted_segments"] > old["admitted_segments"],
        "checkpoint pair does not enlarge the range",
    )
    require(
        new["admitted_segments"] <= physical_segments,
        "growth admits unavailable physical segments",
    )
    require(
        old["admitted_range_pages"]
        == storage.admitted_pages(old["admitted_segments"])
        and new["admitted_range_pages"]
        == storage.admitted_pages(new["admitted_segments"]),
        "growth admitted page count is non-canonical",
    )
    require(
        new["cleaner_reserve_segments"] == old["cleaner_reserve_segments"]
        and new["max_replay_records"] == old["max_replay_records"],
        "growth changes immutable limits",
    )
    require(
        new["replay_count"] == old["replay_count"],
        "growth changes replay count",
    )
    for field in ("catalog_root", "authority_root", "replay_tail"):
        require(pointer_equal(new[field], old[field]), "growth changes a preserved root")

    require(
        older_allocation["checkpoint_generation"] == old_generation
        and newer_allocation["checkpoint_generation"] == new_generation,
        "growth allocation generations are inconsistent",
    )
    require(
        older_allocation["admitted_segments"] == old["admitted_segments"]
        and newer_allocation["admitted_segments"] == new["admitted_segments"],
        "growth allocation admission is inconsistent",
    )
    require(
        older_allocation["cleaner_reserve_segments"]
        == newer_allocation["cleaner_reserve_segments"]
        == old["cleaner_reserve_segments"],
        "growth allocation changes cleaner reserve",
    )
    require(
        not older_allocation["retired"] and not newer_allocation["retired"],
        "growth overlaps a retirement barrier",
    )
    require(
        newer_allocation["next_segment_generation"]
        == older_allocation["next_segment_generation"] + 1,
        "growth consumes the wrong segment generation",
    )

    carriers: list[int] = []
    for segment_no in range(old["admitted_segments"]):
        before = older_allocation["states"][segment_no]
        after = newer_allocation["states"][segment_no]
        if before == after:
            continue
        require(
            before == gc.SEGMENT_FREE and after == gc.SEGMENT_ALLOCATED,
            "growth changes an old state other than Free to Allocated",
        )
        carriers.append(segment_no)
    require(len(carriers) == 1, "growth must allocate exactly one old carrier")
    carrier = carriers[0]
    suffix = newer_allocation["states"][old["admitted_segments"] :]
    require(suffix, "growth suffix is empty")
    require(
        all(state == gc.SEGMENT_FREE for state in suffix),
        "growth suffix contains a non-Free segment",
    )
    require(
        newer_allocation["counts"]["allocated"]
        == older_allocation["counts"]["allocated"] + 1,
        "growth allocated count is not exact",
    )
    require(
        newer_allocation["counts"]["free"]
        == older_allocation["counts"]["free"] + len(suffix) - 1,
        "growth free count is not exact",
    )
    require(
        newer_allocation["counts"]["free"]
        >= newer_allocation["cleaner_reserve_segments"] + 1,
        "growth consumes cleaner reserve or root-policy headroom",
    )

    allocation_root = new["allocation_root"]
    require(allocation_root["status"] == "value", "growth has no allocation root")
    require(
        not pointer_equal(allocation_root, old["allocation_root"]),
        "growth reuses the old allocation root",
    )
    require(
        allocation_root["segment_no"] == carrier,
        "growth allocation root is not in its unique carrier",
    )
    require(
        allocation_root["segment_generation"]
        == older_allocation["next_segment_generation"],
        "growth carrier has the wrong generation",
    )
    require(
        allocation_root["extent_kind"] == gc.EXTENT_ALLOCATION,
        "growth root is not allocation metadata",
    )

    carrier_segment = find_segment(segments, carrier)
    require(carrier_segment.get("status") == "sealed", "growth carrier is not sealed")
    require(
        carrier_segment.get("_generation")
        == older_allocation["next_segment_generation"],
        "growth carrier segment generation is not exact",
    )
    header = carrier_segment["header"]["record"]
    summary = carrier_segment["summary"]["record"]
    final = carrier_segment["final_seal"]["record"]
    require(
        header["binding"]["store_uuid"] == new["binding"]["store_uuid"],
        "growth carrier changes store binding",
    )
    require(
        header["binding"]["target_checkpoint_generation"] == new_generation
        and summary["first_target_checkpoint_generation"] == new_generation
        and summary["last_target_checkpoint_generation"] == new_generation
        and final["target_checkpoint_generation"] == new_generation,
        "growth carrier target chain is not exactly G+1",
    )
    require(
        len(carrier_segment["extents"]) == 1
        and carrier_segment["extents"][0]["status"] == "sealed",
        "growth carrier does not contain exactly one sealed extent",
    )
    sole_extent = carrier_segment["extents"][0]["record"]
    require(
        sole_extent["extent_kind"] == gc.EXTENT_ALLOCATION
        and allocation_root["descriptor_relative_page"] == storage.DATA_FIRST_PAGE
        and allocation_root["ordinal"] == 1
        and storage.pointer_identity(allocation_root)
        == (
            sole_extent["binding"]["segment_no"],
            sole_extent["binding"]["generation"],
            allocation_root["descriptor_relative_page"],
            sole_extent["binding"]["ordinal"],
        ),
        "growth carrier extent does not bind the allocation root",
    )

    old_root = old["allocation_root"]
    if old_root["status"] == "null":
        expected_previous = (
            storage.ANCHOR_SEGMENT_NO,
            0,
            bytes(32),
        )
    else:
        old_segment = find_segment(segments, old_root["segment_no"])
        require(old_segment.get("status") == "sealed", "old allocation carrier is not sealed")
        require(
            old_segment.get("_generation") == old_root["segment_generation"],
            "old allocation carrier generation differs from its root",
        )
        expected_previous = (
            old_root["segment_no"],
            old_root["segment_generation"],
            old_segment["final_seal"]["_digest"]["body_sha256"],
        )
    actual_previous = (
        header["previous_segment_no"],
        header["previous_segment_generation"],
        header["previous_segment_seal_body_sha256"],
    )
    require(actual_previous == expected_previous, "growth carrier predecessor chain is invalid")

    added = new["admitted_segments"] - old["admitted_segments"]
    return {
        "state": "verified",
        "verified": True,
        "previous_generation": old_generation,
        "selected_generation": new_generation,
        "previous_admitted_segments": old["admitted_segments"],
        "admitted_segments": new["admitted_segments"],
        "added_segments": added,
        "metadata_carriers": 1,
        "new_free_segments": added,
    }


def validate_regular_transition(
    older: dict[str, Any],
    newer: dict[str, Any],
    older_allocation: dict[str, Any],
    newer_allocation: dict[str, Any],
) -> None:
    old = older["record"]
    new = newer["record"]
    require(
        older_allocation["admitted_segments"] == len(older_allocation["states"]),
        "older ordinary allocation state map is truncated",
    )
    require(
        newer_allocation["admitted_segments"] == len(newer_allocation["states"]),
        "newer ordinary allocation state map is truncated",
    )
    require(
        len(older_allocation["states"]) == len(newer_allocation["states"]),
        "ordinary allocation state maps have different lengths",
    )
    old_generation = old["binding"]["generation"]
    new_generation = new["binding"]["generation"]
    require(new_generation == old_generation + 1, "checkpoint transition is not G+1")
    require(new["previous_generation"] == old_generation, "checkpoint predecessor is invalid")
    require(
        new["admitted_segments"] == old["admitted_segments"],
        "ordinary checkpoint transition changes admission",
    )
    require(
        new["cleaner_reserve_segments"] == old["cleaner_reserve_segments"],
        "ordinary checkpoint transition changes cleaner reserve",
    )
    allocate: list[int] = []
    retire: list[int] = []
    reclaim: list[int] = []
    for segment_no, (before, after) in enumerate(
        zip(older_allocation["states"], newer_allocation["states"])
    ):
        if before == after:
            continue
        if before == gc.SEGMENT_FREE and after == gc.SEGMENT_ALLOCATED:
            allocate.append(segment_no)
        elif before == gc.SEGMENT_ALLOCATED and after == gc.SEGMENT_RETIRED:
            retire.append(segment_no)
        elif before == gc.SEGMENT_RETIRED and after == gc.SEGMENT_FREE:
            reclaim.append(segment_no)
        else:
            raise Violation("ordinary checkpoint contains an invalid state transition")
    gc.validate_allocation_transition(
        older_allocation,
        newer_allocation,
        allocate=allocate,
        retire=retire,
        reclaim=reclaim,
    )
    require(
        newer_allocation["next_segment_generation"]
        == older_allocation["next_segment_generation"] + len(allocate),
        "ordinary transition consumes the wrong segment generations",
    )
    old_retired = older_allocation["retired"]
    if retire:
        require(
            not reclaim and not old_retired and allocate,
            "relocation overlaps another retirement barrier",
        )
    elif reclaim:
        require(
            len(reclaim) == len(old_retired)
            and all(
                entry["retire_generation"] == old_generation
                for entry in old_retired
            )
            and not newer_allocation["retired"]
            and len(allocate) == 1,
            "reuse barrier is not exact",
        )
    else:
        require(not old_retired, "ordinary commit advances a pending reuse barrier")


def validate_relevant_segment_set(
    image: Any,
    checkpoint: dict[str, Any],
    allocation: dict[str, Any],
    segments: list[dict[str, Any]],
    segment_errors: list[list[str]],
) -> None:
    record = checkpoint["record"]
    require(
        len(segments) == len(segment_errors),
        "segment diagnostics do not cover the physical image",
    )
    require_allocation_within_physical_segments(
        allocation, len(segments), "relevant segment allocation"
    )
    for segment_no, state in enumerate(allocation["states"]):
        if state == gc.SEGMENT_FREE:
            continue
        segment = segments[segment_no]
        require(
            segment.get("status") == "sealed" and not segment_errors[segment_no],
            "authoritative segment is not structurally sealed",
        )
        require(
            segment.get("_generation", U64_MAX)
            < allocation["next_segment_generation"],
            "authoritative segment generation is not committed",
        )
        require(
            segment["header"]["record"]["binding"]["store_uuid"]
            == record["binding"]["store_uuid"],
            "authoritative segment changes store binding",
        )
        require(
            segment["final_seal"]["record"]["target_checkpoint_generation"]
            <= record["binding"]["generation"],
            "authoritative segment targets a newer checkpoint",
        )
        for extent in segment["extents"]:
            extent_record = extent["record"]
            used = extent_record["payload_byte_len"] % storage.PAGE_SIZE
            if used == 0:
                continue
            final_payload_page = (
                storage.segment_base_page(segment_no)
                + extent_record["payload_first_relative_page"]
                + extent_record["payload_pages"]
                - 1
            )
            page = storage.page_at(image, final_payload_page)
            require(
                page is not None and storage.all_zero(page[used:]),
                "authoritative extent has non-zero page padding",
            )


def classify_gc_violation(message: str) -> str:
    lowered = message.lower()
    if any(word in lowered for word in ("persistent root", "typed", "reference", "authority")):
        return "authority_graph"
    if any(
        word in lowered
        for word in ("blob", "manifest", "merkle", "content", "tree", "payload sha")
    ):
        return "blob_data_or_tree"
    return "allocation_or_mapping"


def ratio_ppm(numerator: int, denominator: int) -> int:
    if denominator == 0:
        return 0
    return min(1_000_000, numerator * 1_000_000 // denominator)


def reconstruct_raw_cas_for_scrub(
    image: Any,
    checkpoint: dict[str, Any],
    segments: list[dict[str, Any]],
    allocation: dict[str, Any],
    typed_reference_kinds: list[int],
) -> dict[str, int]:
    """Verify a compact CAS snapshot, with or without persistent roots.

    The M7.5 GC verifier intentionally requires a non-Null authority root
    because GC itself is disabled without one.  Scrub has no such authority
    prerequisite: a pre-GC M7.4/M7.6 CAS snapshot with only runtime roots is a
    valid state and must still have all catalog, manifest, Blob, and typed-edge
    bytes verified.
    """

    record = checkpoint["record"]
    generation = record["binding"]["generation"]
    require(
        record["cleaner_reserve_segments"] >= 2,
        "CAS snapshot has fewer than two reserved segments",
    )
    require(
        record["replay_count"] == 0 and record["replay_tail"]["status"] == "null",
        "CAS snapshot has an uncompacted replay tail",
    )
    require(
        record["allocation_root"]["status"] == "value",
        "CAS snapshot has no allocation-v2 root",
    )
    require(
        record["catalog_root"]["status"] == "value",
        "CAS snapshot has no catalog root",
    )
    require_allocation_within_physical_segments(
        allocation, len(segments), "CAS allocation"
    )

    resolver = gc.RawImageResolver(image, checkpoint, segments, allocation)
    allocation_pointer = record["allocation_root"]
    require(
        allocation["states"][allocation_pointer["segment_no"]]
        == gc.SEGMENT_ALLOCATED,
        "allocation root points into a non-Allocated segment",
    )
    resolver.current_identities.add(storage.pointer_identity(allocation_pointer))

    authority = record["authority_root"]
    root_entries: list[dict[str, int]] = []
    physical_pointers = [allocation_pointer, record["catalog_root"]]
    if authority["status"] == "value":
        authority_extent, authority_payload = resolver.resolve(
            authority,
            gc.EXTENT_AUTHORITY,
            "authority root",
            metadata=True,
        )
        roots = gc.parse_persistent_root_set(authority_payload)
        require(
            roots["checkpoint_generation"] <= generation,
            "persistent root-set is newer than checkpoint",
        )
        require(
            roots["checkpoint_generation"]
            == authority_extent["binding"]["target_checkpoint_generation"],
            "persistent root-set generation differs from extent target",
        )
        root_entries = roots["entries"]
        physical_pointers.append(authority)
    else:
        require(authority["status"] == "null", "authority root status is invalid")

    catalog_extent, catalog_payload = resolver.resolve(
        record["catalog_root"],
        gc.EXTENT_CATALOG,
        "catalog root",
        metadata=True,
    )
    context = {
        "store_uuid": record["binding"]["store_uuid"],
        "admitted_segments": record["admitted_segments"],
        "next_segment_generation": record["next_segment_generation"],
    }
    snapshot = gc.parse_cas_snapshot_v2(catalog_payload, context)
    require(
        snapshot["checkpoint_generation"] <= generation,
        "CAS snapshot is newer than checkpoint",
    )
    require(
        snapshot["checkpoint_generation"]
        == catalog_extent["binding"]["target_checkpoint_generation"],
        "CAS snapshot generation differs from extent target",
    )

    contents: dict[tuple[int, int, int, bytes], bytes] = {}
    for blob in snapshot["blobs"]:
        key_id = gc.blob_key_identity(blob["blob_key"])
        manifest_pointer = blob["manifest"]
        require(
            all(
                not storage.ranges_overlap(previous, manifest_pointer)
                for previous in physical_pointers
            ),
            "current physical pointers overlap",
        )
        physical_pointers.append(manifest_pointer)
        manifest_extent, manifest_payload = resolver.resolve(
            manifest_pointer,
            gc.EXTENT_CATALOG,
            "Blob manifest",
            metadata=True,
        )
        require(
            manifest_pointer["payload_sha256"]
            == hashlib.sha256(manifest_payload).digest(),
            "Blob manifest pointer SHA-256 mismatch",
        )
        require(
            manifest_extent["binding"]["target_checkpoint_generation"] <= generation,
            "Blob manifest targets a newer checkpoint",
        )
        manifest = gc.parse_blob_manifest_v2(manifest_payload, context)
        require(
            gc.blob_key_identity(manifest["blob_key"]) == key_id,
            "Blob mapping and manifest keys disagree",
        )
        encoded = bytearray()
        for item in manifest["extents"]:
            pointer = item["pointer"]
            require(
                all(
                    not storage.ranges_overlap(previous, pointer)
                    for previous in physical_pointers
                ),
                "current physical pointers overlap",
            )
            physical_pointers.append(pointer)
            extent, payload = resolver.resolve(
                pointer, gc.EXTENT_BLOB, "canonical Blob extent"
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
            require(
                actual_shape == expected_shape,
                "canonical Blob extent descriptor binding mismatch",
            )
            require(
                hashlib.sha256(payload).digest() == pointer["payload_sha256"],
                "canonical Blob extent payload SHA-256 mismatch",
            )
            encoded.extend(payload)
        require(
            len(encoded) == manifest["encoded_blob_len"],
            "reconstructed canonical Blob length mismatch",
        )
        contents[key_id] = gc.verify_canonical_blob(
            bytes(encoded), blob["blob_key"]
        )

    objects = {item["object_id"]: item for item in snapshot["objects"]}
    gc.validate_raw_object_graph(
        objects, contents, root_entries, typed_reference_kinds
    )
    return {
        "objects": len(objects),
        "blobs": len(contents),
        "persistent_roots": len(root_entries),
    }


def anonymous_cas_totals(
    image: Any,
    checkpoint: dict[str, Any],
    segments: list[dict[str, Any]],
    allocation: dict[str, Any],
    typed_reference_kinds: list[int],
) -> dict[str, int]:
    record = checkpoint["record"]
    if record["catalog_root"]["status"] == "null":
        require(
            record["authority_root"]["status"] == "null"
            and record["replay_tail"]["status"] == "null"
            and record["replay_count"] == 0,
            "empty CAS checkpoint has non-empty authority or replay state",
        )
        return {
            "live_objects": 0,
            "unique_blobs": 0,
            "logical_live_bytes": 0,
            "unique_blob_bytes": 0,
            "deduplicated_bytes_saved": 0,
            "persistent_roots": 0,
        }

    reconstructed = reconstruct_raw_cas_for_scrub(
        image,
        checkpoint,
        segments,
        allocation,
        typed_reference_kinds,
    )
    resolver = gc.RawImageResolver(image, checkpoint, segments, allocation)
    _, payload = resolver.resolve(
        record["catalog_root"],
        gc.EXTENT_CATALOG,
        "catalog root",
        metadata=True,
    )
    context = {
        "store_uuid": record["binding"]["store_uuid"],
        "admitted_segments": record["admitted_segments"],
        "next_segment_generation": record["next_segment_generation"],
    }
    snapshot = gc.parse_cas_snapshot_v2(payload, context)
    logical = sum(item["exact_len"] for item in snapshot["objects"])
    unique = sum(item["blob_key"]["exact_len"] for item in snapshot["blobs"])
    require(logical <= U64_MAX and unique <= U64_MAX, "anonymous byte total overflows u64")
    return {
        "live_objects": reconstructed["objects"],
        "unique_blobs": reconstructed["blobs"],
        "logical_live_bytes": logical,
        "unique_blob_bytes": unique,
        "deduplicated_bytes_saved": max(0, logical - unique),
        "persistent_roots": reconstructed["persistent_roots"],
    }


def _verify_raw_image(
    image: Any, typed_reference_kinds: Optional[list[int]] = None
) -> dict[str, Any]:
    typed_reference_kinds = (
        [] if typed_reference_kinds is None else typed_reference_kinds
    )
    issues = AnonymousIssues()
    growth = null_growth()
    scrub = empty_scrub(issues)
    byte_length = len(image)
    if byte_length < storage.ANCHOR_PAGES * storage.PAGE_SIZE:
        issues.add("input")
        return closed_result(issues, growth, scrub)
    if byte_length % storage.PAGE_SIZE:
        issues.add("input")
        return closed_result(issues, growth, scrub)
    page_count = byte_length // storage.PAGE_SIZE
    tail_pages = max(0, page_count - storage.ANCHOR_PAGES)
    if tail_pages % storage.SEGMENT_PAGES:
        issues.add("input")
        return closed_result(issues, growth, scrub)
    physical_segments = tail_pages // storage.SEGMENT_PAGES

    anchor_errors: list[str] = []
    superblocks = [
        storage.decode_pair(
            image,
            0,
            1,
            1,
            "superblock copy A",
            anchor_errors,
            storage.super_validator(0, 0),
        ),
        storage.decode_pair(
            image,
            2,
            3,
            1,
            "superblock copy B",
            anchor_errors,
            storage.super_validator(1, 2),
        ),
    ]
    checkpoints = [
        storage.decode_pair(
            image,
            4,
            5,
            2,
            "checkpoint slot A",
            anchor_errors,
            storage.checkpoint_validator(0, 4),
        ),
        storage.decode_pair(
            image,
            6,
            7,
            2,
            "checkpoint slot B",
            anchor_errors,
            storage.checkpoint_validator(1, 6),
        ),
    ]
    for page_no in range(8, storage.ANCHOR_PAGES):
        page = storage.page_at(image, page_no)
        if page is None or not storage.all_zero(page):
            anchor_errors.append("reserved anchor page is invalid")
    selected_superblock = storage.select_superblock(superblocks, anchor_errors)
    selected_checkpoint = storage.select_checkpoint(checkpoints, anchor_errors)
    if any(entry["status"] != "sealed" for entry in superblocks):
        anchor_errors.append("both immutable superblock copies must remain sealed")
    if selected_superblock is None or selected_checkpoint is None:
        anchor_errors.append("selected anchor state is unavailable")
    if anchor_errors:
        issues.add("anchor", len(set(anchor_errors)))

    segment_errors: list[list[str]] = []
    segments: list[dict[str, Any]] = []
    for segment_no in range(physical_segments):
        local: list[str] = []
        segments.append(storage.parse_segment(image, segment_no, local))
        segment_errors.append(local)

    if selected_checkpoint is None or selected_superblock is None:
        return closed_result(issues, growth, scrub)

    selected_errors: list[str] = []
    storage.verify_checkpoint_against_superblock(
        selected_checkpoint,
        selected_superblock,
        physical_segments,
        segments,
        selected_errors,
    )
    if selected_errors:
        issues.add("anchor", len(set(selected_errors)))

    allocation: Optional[dict[str, Any]] = None
    try:
        allocation = decode_checkpoint_allocation(image, selected_checkpoint, segments)
    except Violation:
        issues.add("allocation_or_mapping")

    sealed_checkpoints = sorted(
        (entry for entry in checkpoints if entry["status"] == "sealed"),
        key=lambda entry: entry["record"]["binding"]["generation"],
    )
    fallback_verified = False
    if len(sealed_checkpoints) == 2:
        try:
            older, newer = sealed_checkpoints
            old_errors: list[str] = []
            storage.verify_checkpoint_against_superblock(
                older,
                selected_superblock,
                physical_segments,
                segments,
                old_errors,
            )
            require(not old_errors, "older checkpoint is not independently recoverable")
            older_allocation = decode_checkpoint_allocation(image, older, segments)
            newer_allocation = decode_checkpoint_allocation(image, newer, segments)
            validate_relevant_segment_set(
                image, older, older_allocation, segments, segment_errors
            )
            anonymous_cas_totals(
                image,
                older,
                segments,
                older_allocation,
                typed_reference_kinds,
            )
            if (
                newer["record"]["admitted_segments"]
                > older["record"]["admitted_segments"]
            ):
                growth = validate_growth_transition(
                    older,
                    newer,
                    older_allocation,
                    newer_allocation,
                    segments,
                    physical_segments,
                )
            else:
                validate_regular_transition(
                    older, newer, older_allocation, newer_allocation
                )
            fallback_verified = True
        except Violation:
            issues.add("allocation_or_mapping")
            if (
                sealed_checkpoints[1]["record"]["admitted_segments"]
                > sealed_checkpoints[0]["record"]["admitted_segments"]
            ):
                growth = null_growth()
                growth["state"] = "corrupt"

    record = selected_checkpoint["record"]
    scrub["checkpoint_generation"] = record["binding"]["generation"]
    scrub["verified_checkpoint_copies"] = len(sealed_checkpoints)
    scrub["checkpoint_fallback_verified"] = fallback_verified
    scrub["admitted_segments"] = record["admitted_segments"]
    scrub["physical_capacity_bytes"] = min(
        U64_MAX, record["admitted_segments"] * SEGMENT_BYTES
    )

    if allocation is not None:
        counts = allocation["counts"]
        scrub["allocated_segments"] = counts["allocated"]
        scrub["retired_segments"] = counts["retired"]
        scrub["free_segments"] = counts["free"]
        unavailable = counts["allocated"] + counts["retired"]
        scrub["physical_allocated_bytes"] = min(U64_MAX, unavailable * SEGMENT_BYTES)
        scrub["physical_high_water_ppm"] = ratio_ppm(
            unavailable, allocation["admitted_segments"]
        )
        reserve = allocation["cleaner_reserve_segments"]
        scrub["gc_pressure_ppm"] = (
            1_000_000
            if counts["free"] <= reserve
            else ratio_ppm(reserve, counts["free"])
        )

        verified_segments = 0
        verified_record_pairs = 0
        verified_payload_bytes = 0
        try:
            validate_relevant_segment_set(
                image,
                selected_checkpoint,
                allocation,
                segments,
                segment_errors,
            )
        except Violation:
            issues.add("segment_metadata")
        for segment_no, state in enumerate(allocation["states"]):
            if state == gc.SEGMENT_FREE:
                continue
            segment = segments[segment_no]
            local_errors = segment_errors[segment_no]
            if segment.get("status") != "sealed" or local_errors:
                issues.add("segment_metadata", max(1, len(set(local_errors))))
                continue
            if (
                segment.get("_generation", U64_MAX)
                >= allocation["next_segment_generation"]
                or segment["header"]["record"]["binding"]["store_uuid"]
                != record["binding"]["store_uuid"]
                or segment["final_seal"]["record"]["target_checkpoint_generation"]
                > record["binding"]["generation"]
            ):
                issues.add("segment_metadata")
                continue
            verified_segments += 1
            verified_record_pairs += 3 + len(segment["extents"])
            verified_payload_bytes += segment["summary"]["record"]["total_payload_bytes"]
        scrub["verified_segments"] = min(U64_MAX, verified_segments)
        scrub["verified_record_pairs"] = min(U64_MAX, verified_record_pairs)
        scrub["verified_payload_bytes"] = min(U64_MAX, verified_payload_bytes)

        try:
            totals = anonymous_cas_totals(
                image,
                selected_checkpoint,
                segments,
                allocation,
                typed_reference_kinds,
            )
            for key in (
                "live_objects",
                "unique_blobs",
                "logical_live_bytes",
                "unique_blob_bytes",
                "deduplicated_bytes_saved",
            ):
                scrub[key] = totals[key]
        except Violation as exc:
            issues.add(classify_gc_violation(str(exc)))

    return closed_result(issues, growth, scrub)


def verify_raw_image(
    image: Any, typed_reference_kinds: Optional[list[int]] = None
) -> dict[str, Any]:
    """Fail closed for every non-system parser failure.

    The detailed frozen parsers primarily raise ``FormatViolation``, but this
    boundary also contains malformed-input ``IndexError``, ``struct.error``,
    arithmetic errors, and other ordinary exceptions.  None of their text or
    traceback is part of the public diagnostic ABI.
    """

    try:
        result = _verify_raw_image(image, typed_reference_kinds)
        require_closed_public_result(result)
        return result
    except OSError:
        issues = AnonymousIssues()
        issues.add("device_io")
        return closed_result(issues)
    except Exception:
        issues = AnonymousIssues()
        issues.add("input")
        return closed_result(issues)


def synthetic_pointer(segment_no: int, generation: int, extent_kind: int) -> dict[str, Any]:
    return {
        "status": "value",
        "store_uuid": bytes(range(1, 17)),
        "segment_no": segment_no,
        "segment_generation": generation,
        "descriptor_relative_page": storage.DATA_FIRST_PAGE,
        "payload_relative_page": storage.DATA_FIRST_PAGE + 2,
        "payload_pages": 1,
        "ordinal": 1,
        "exact_byte_len": 130,
        "extent_kind": extent_kind,
        "hash_algorithm": 1,
        "payload_sha256": bytes([segment_no + 1]) * 32,
    }


def synthetic_growth_fixture() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]], int
]:
    store_uuid = bytes(range(1, 17))
    null = {"status": "null"}
    old_allocation_root = synthetic_pointer(0, 10, gc.EXTENT_ALLOCATION)
    new_allocation_root = synthetic_pointer(2, 20, gc.EXTENT_ALLOCATION)
    old_record = {
        "binding": {"generation": 7, "store_uuid": store_uuid},
        "previous_generation": 6,
        "admitted_range_pages": storage.admitted_pages(4),
        "admitted_segments": 4,
        "next_segment_generation": 20,
        "replay_count": 0,
        "max_replay_records": 4,
        "cleaner_reserve_segments": 2,
        "catalog_root": null,
        "authority_root": null,
        "allocation_root": old_allocation_root,
        "replay_tail": null,
    }
    new_record = copy.deepcopy(old_record)
    new_record.update(
        {
            "binding": {"generation": 8, "store_uuid": store_uuid},
            "previous_generation": 7,
            "admitted_range_pages": storage.admitted_pages(6),
            "admitted_segments": 6,
            "next_segment_generation": 21,
            "allocation_root": new_allocation_root,
        }
    )
    old_allocation = {
        "checkpoint_generation": 7,
        "admitted_segments": 4,
        "next_segment_generation": 20,
        "cleaner_reserve_segments": 2,
        "states": [gc.SEGMENT_ALLOCATED, gc.SEGMENT_ALLOCATED, gc.SEGMENT_FREE, gc.SEGMENT_FREE],
        "retired": [],
        "counts": {"free": 2, "allocated": 2, "retired": 0},
    }
    new_allocation = {
        "checkpoint_generation": 8,
        "admitted_segments": 6,
        "next_segment_generation": 21,
        "cleaner_reserve_segments": 2,
        "states": [
            gc.SEGMENT_ALLOCATED,
            gc.SEGMENT_ALLOCATED,
            gc.SEGMENT_ALLOCATED,
            gc.SEGMENT_FREE,
            gc.SEGMENT_FREE,
            gc.SEGMENT_FREE,
        ],
        "retired": [],
        "counts": {"free": 3, "allocated": 3, "retired": 0},
    }
    predecessor_hash = bytes([0x70]) * 32
    old_segment = {
        "segment_no": 0,
        "status": "sealed",
        "_generation": 10,
        "final_seal": {"_digest": {"body_sha256": predecessor_hash}},
    }
    extent_record = {
        "extent_kind": gc.EXTENT_ALLOCATION,
        "binding": {"segment_no": 2, "generation": 20, "ordinal": 1},
    }
    carrier = {
        "segment_no": 2,
        "status": "sealed",
        "_generation": 20,
        "header": {
            "record": {
                "binding": {
                    "store_uuid": store_uuid,
                    "target_checkpoint_generation": 8,
                },
                "previous_segment_no": 0,
                "previous_segment_generation": 10,
                "previous_segment_seal_body_sha256": predecessor_hash,
            }
        },
        "summary": {
            "record": {
                "first_target_checkpoint_generation": 8,
                "last_target_checkpoint_generation": 8,
            }
        },
        "final_seal": {"record": {"target_checkpoint_generation": 8}},
        "extents": [{"status": "sealed", "record": extent_record}],
    }
    filler = [
        {"segment_no": number, "status": "empty"} for number in range(6)
    ]
    filler[0] = old_segment
    filler[2] = carrier
    return (
        {"record": old_record},
        {"record": new_record},
        old_allocation,
        new_allocation,
        filler,
        6,
    )


def expect_violation(action: Callable[[], Any]) -> None:
    try:
        action()
    except Violation:
        return
    raise AssertionError("mutation was accepted")


def malformed_raw_fixtures() -> list[tuple[str, bytes]]:
    """Build sealed raw inputs whose trusted indexes exceed the image."""

    amplified = bytearray(storage.selftest_image())

    def amplify_admission(payload: bytearray) -> None:
        storage.put_u64(payload, 0x10, storage.admitted_pages(3))
        storage.put_u64(payload, 0x18, 3)

    storage.rewrite_selftest_pair(amplified, 4, 2, amplify_admission)

    outside_allocation = bytearray(storage.selftest_image())

    def move_allocation_root_outside_image(payload: bytearray) -> None:
        # checkpoint allocation_root begins at 0x100; segment_no is +0x10.
        storage.put_u64(payload, 0x110, 2)

    storage.rewrite_selftest_pair(
        outside_allocation, 4, 2, move_allocation_root_outside_image
    )
    return [
        ("admission-beyond-image", bytes(amplified)),
        ("allocation-root-beyond-image", bytes(outside_allocation)),
    ]


def verify_negative_raw_cli(
    label: str, raw: bytes, expected_shape: Any
) -> dict[str, Any]:
    """Exercise the real CLI and require one anonymous stdout document."""

    with tempfile.TemporaryDirectory(prefix="vibeos-maintenance-selftest-") as directory:
        path = Path(directory) / f"{label}.img"
        path.write_bytes(raw)
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(Path(__file__).resolve()),
                "--raw-image",
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    require(completed.returncode == 1, "corrupt raw CLI exit status is not one")
    require(completed.stderr == b"", "corrupt raw CLI wrote diagnostic text to stderr")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Violation("corrupt raw CLI did not emit exactly one JSON document") from exc
    require_closed_public_result(result)
    require(result["status"] == "corrupt", "corrupt raw CLI reported success")
    require(
        public_schema_shape(result) == expected_shape,
        "corrupt raw CLI changed the closed anonymous schema",
    )
    return result


def run_selftest() -> dict[str, Any]:
    base = synthetic_growth_fixture()
    growth = validate_growth_transition(*base)
    require(growth["verified"] and growth["added_segments"] == 2, "valid growth rejected")

    mutations: list[Callable[[tuple[Any, ...]], None]] = [
        lambda value: value[1]["record"]["binding"].__setitem__("generation", 9),
        lambda value: value[1]["record"].__setitem__("previous_generation", 6),
        lambda value: value[1]["record"].__setitem__("admitted_segments", 4),
        lambda value: value[1]["record"].__setitem__("admitted_range_pages", storage.admitted_pages(5)),
        lambda value: value[1]["record"].__setitem__("cleaner_reserve_segments", 3),
        lambda value: value[1]["record"].__setitem__("replay_count", 1),
        lambda value: value[1]["record"].__setitem__("catalog_root", synthetic_pointer(1, 11, gc.EXTENT_CATALOG)),
        lambda value: value[1]["record"].__setitem__("authority_root", synthetic_pointer(1, 11, gc.EXTENT_AUTHORITY)),
        lambda value: value[1]["record"].__setitem__("replay_tail", synthetic_pointer(1, 11, 5)),
        lambda value: value[2]["retired"].append({"segment_no": 1, "retire_generation": 6}),
        lambda value: value[3]["retired"].append({"segment_no": 1, "retire_generation": 8}),
        lambda value: value[3]["states"].__setitem__(2, gc.SEGMENT_FREE),
        lambda value: value[3]["states"].__setitem__(3, gc.SEGMENT_ALLOCATED),
        lambda value: value[3]["states"].__setitem__(4, gc.SEGMENT_ALLOCATED),
        lambda value: value[3].__setitem__("next_segment_generation", 22),
        lambda value: value[1]["record"].__setitem__("allocation_root", {"status": "null"}),
        lambda value: value[1]["record"]["allocation_root"].__setitem__("segment_no", 3),
        lambda value: value[1]["record"]["allocation_root"].__setitem__("segment_generation", 19),
        lambda value: value[1]["record"]["allocation_root"].__setitem__("extent_kind", gc.EXTENT_CATALOG),
        lambda value: value[4][2].__setitem__("status", "incomplete"),
        lambda value: value[4][2].__setitem__("_generation", 19),
        lambda value: value[4][2]["header"]["record"]["binding"].__setitem__("store_uuid", bytes(16)),
        lambda value: value[4][2]["header"]["record"]["binding"].__setitem__("target_checkpoint_generation", 9),
        lambda value: value[4][2]["header"]["record"].__setitem__("previous_segment_no", 1),
        lambda value: value[4][2]["header"]["record"].__setitem__("previous_segment_generation", 9),
        lambda value: value[4][2]["header"]["record"].__setitem__("previous_segment_seal_body_sha256", bytes(32)),
        lambda value: value[4][2]["extents"].append(copy.deepcopy(value[4][2]["extents"][0])),
        lambda value: value[4][2]["extents"][0]["record"].__setitem__("extent_kind", gc.EXTENT_CATALOG),
        lambda value: value[4][2]["extents"][0]["record"]["binding"].__setitem__("ordinal", 2),
        lambda value: value.__setitem__(5, 5),
    ]
    for mutate in mutations:
        fixture = copy.deepcopy(base)
        mutable = list(fixture)
        mutate(mutable)
        expect_violation(lambda value=tuple(mutable): validate_growth_transition(*value))

    issues = AnonymousIssues()
    issues.add("blob_data_or_tree")
    result = closed_result(issues)
    require_closed_public_result(result)
    schema_shape = public_schema_shape(result)

    leaky = copy.deepcopy(result)
    leaky["scrub"]["corruption_domains"]["store_uuid"] = "00" * 16
    expect_violation(lambda: require_closed_public_result(leaky))
    free_form = copy.deepcopy(result)
    free_form["scrub"]["status"] = "/private/device/raw.img"
    expect_violation(lambda: require_closed_public_result(free_form))

    impossible_allocation = {
        "admitted_segments": 3,
        "states": [gc.SEGMENT_ALLOCATED, gc.SEGMENT_FREE, gc.SEGMENT_FREE],
        "retired": [],
        "counts": {"free": 2, "allocated": 1, "retired": 0},
    }
    expect_violation(
        lambda: require_allocation_within_physical_segments(
            impossible_allocation, 2, "selftest allocation"
        )
    )

    raw_cases = malformed_raw_fixtures()
    for label, raw in raw_cases:
        direct = verify_raw_image(raw)
        require_closed_public_result(direct)
        require(direct["status"] == "corrupt", "malformed raw input was accepted")
        require(
            public_schema_shape(direct) == schema_shape,
            "direct malformed parser changed the closed schema",
        )
        cli = verify_negative_raw_cli(label, raw, schema_shape)
        require(
            public_schema_shape(cli) == public_schema_shape(direct),
            "CLI and direct parser schemas differ",
        )

    class IndexFailureImage:
        def __len__(self) -> int:
            return storage.ANCHOR_PAGES * storage.PAGE_SIZE

        def __getitem__(self, key: Any) -> bytes:
            raise IndexError("synthetic parser index failure")

    contained = verify_raw_image(IndexFailureImage())
    require_closed_public_result(contained)
    require(
        contained["status"] == "corrupt"
        and contained["scrub"]["corruption_domains"]["input"] == 1,
        "non-system parser exception did not map to anonymous input corruption",
    )
    return {
        "format": "vibeos-storage-v2-maintenance-selftest",
        "version": 1,
        "status": "ok",
        "mutation_cases": len(mutations) + len(raw_cases),
    }


def dump_json(value: dict[str, Any], pretty: bool) -> None:
    print(
        json.dumps(
            value,
            indent=2 if pretty else None,
            sort_keys=True,
            separators=None if pretty else (",", ":"),
        )
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true", help="run fail-closed maintenance mutations")
    mode.add_argument("--raw-image", metavar="PATH", help="verify one powered-off Storage V2 image")
    parser.add_argument(
        "--typed-reference-kind",
        metavar="KIND",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="trust one refs-v1 ObjectKind while scrubbing (never emitted; repeatable)",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args(argv)

    typed_reference_kinds = sorted(set(args.typed_reference_kind))
    valid_typed_policy = (
        args.raw_image is not None
        and len(typed_reference_kinds) == len(args.typed_reference_kind)
        and len(typed_reference_kinds) <= gc.MAX_TYPED_REFERENCE_KINDS
        and all(0 < kind <= U32_MAX for kind in typed_reference_kinds)
    )
    if args.typed_reference_kind and not valid_typed_policy:
        issues = AnonymousIssues()
        issues.add("input")
        result = closed_result(issues)
        dump_json(result, args.pretty)
        return 1

    if args.selftest:
        try:
            result = run_selftest()
        except Exception:
            result = {
                "format": "vibeos-storage-v2-maintenance-selftest",
                "version": 1,
                "status": "corrupt",
                "mutation_cases": 0,
            }
        dump_json(result, args.pretty)
        return 0 if result["status"] == "ok" else 1

    issues = AnonymousIssues()
    try:
        with Path(args.raw_image).open("rb") as raw_file:
            with mmap.mmap(raw_file.fileno(), 0, access=mmap.ACCESS_READ) as image:
                result = verify_raw_image(image, typed_reference_kinds)
    except OSError:
        issues.add("device_io")
        result = closed_result(issues)
    except Exception:
        issues.add("input")
        result = closed_result(issues)
    dump_json(result, args.pretty)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
