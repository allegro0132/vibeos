#!/usr/bin/env python3
"""Independently verify and summarize C8.3 target-owned raw samples.

This parser deliberately shares no code with the Rust producer.  It treats the
UART/QEMU transcript as hostile input, checks a closed schema and the checked-in
workload manifest, recomputes the rolling end accumulator, and derives every
published statistic from retained raw samples.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Any, Callable


ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "benchmarks/wasm-runtime/workloads-v1.json"
SCHEMA_PATH = ROOT / "benchmarks/wasm-runtime/schema-v1.json"
META_PREFIX = "VIBE_WASM_COST_META "
SAMPLE_PREFIX = "VIBE_WASM_COST_SAMPLE "
END_PREFIX = "VIBE_WASM_COST_END "
FAILURE_MARKERS = (
    "vibe_wasm_cost_failed",
    "panic",
    "fatal",
)
U64_MAX = (1 << 64) - 1
EXPECTED_MANIFEST_SHA256 = "8b5bec7eacd2fd706b716b005af3a5a085730afdeb20839e905cf9177e70aeb4"
EXPECTED_SCHEMA_SHA256 = "4d36975acde2de015ef75e6ed402201da3d70f516d6d9f620adde08f3e11ed8d"
TEST_ONLY_SOURCE_COMMIT = "1" * 40
TEST_ONLY_CHALLENGE = "2" * 64

META_KEYS = {
    "schema",
    "version",
    "suite_id",
    "workload_revision",
    "source_commit",
    "challenge",
    "run_id",
    "manifest_sha256",
    "transcript_schema_sha256",
    "platform",
    "target",
    "clock",
    "timebase_hz",
    "sync_profile_stage",
    "async_scope",
    "composition_scope",
    "sync_component_sha256",
    "sync_component_bytes",
    "route_component_sha256",
    "route_component_bytes",
    "core_module_sha256",
    "core_module_bytes",
    "workloads",
}
SAMPLE_KEYS = {
    "schema",
    "version",
    "run_id",
    "challenge",
    "sequence",
    "workload_id",
    "category",
    "sample_index",
    "warmup",
    "ticks",
    "operations",
    "bytes",
    "fuel_consumed",
    "poll_quanta",
    "heap_before",
    "heap_peak",
    "heap_after",
    "logical_live_after",
    "result",
}
END_KEYS = {
    "schema",
    "version",
    "run_id",
    "challenge",
    "records",
    "workloads",
    "accumulator",
}
MANIFEST_KEYS = {
    "schema",
    "version",
    "suite_id",
    "workload_revision",
    "scope",
    "fixtures",
    "platforms",
    "sampling",
    "statistics",
    "workloads",
    "publication_gates",
}
WORKLOAD_KEYS = {
    "id",
    "category",
    "sampling",
    "batch",
    "bytes",
    "expected_result",
}
WORKLOAD_OPTIONAL_KEYS = {"scope_note", "minimum_heap_peak_delta_bytes"}


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifiedTranscript:
    metadata: dict[str, Any]
    samples: list[dict[str, Any]]
    end: dict[str, Any]
    raw_sha256: str
    raw_bytes: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def strict_json_loads(value: str, label: str) -> Any:
    try:
        return json.loads(value, object_pairs_hook=reject_duplicate_json_members)
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid {label} JSON: {error}") from error


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    require(not missing and not extra, f"{label} keys differ: missing={missing}, extra={extra}")
    return value


def integer(value: Any, label: str, *, minimum: int = 0, maximum: int = U64_MAX) -> int:
    require(type(value) is int, f"{label} must be an integer, not {type(value).__name__}")
    require(minimum <= value <= maximum, f"{label} is outside [{minimum}, {maximum}]")
    return value


def boolean(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be a boolean")
    return value


def text(value: Any, label: str) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    return value


def canonical_hex(value: Any, length: int, label: str, *, nonzero: bool = True) -> str:
    value = text(value, label)
    require(len(value) == length, f"{label} has the wrong length")
    require(all(char in "0123456789abcdef" for char in value), f"{label} is not lowercase hex")
    if nonzero:
        require(any(char != "0" for char in value), f"{label} is the all-zero sentinel")
    return value


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path: pathlib.Path = MANIFEST_PATH) -> dict[str, Any]:
    require(file_sha256(path) == EXPECTED_MANIFEST_SHA256, "manifest byte identity differs")
    require(file_sha256(SCHEMA_PATH) == EXPECTED_SCHEMA_SHA256, "schema byte identity differs")
    try:
        manifest = strict_json_loads(path.read_text(encoding="utf-8"), "manifest")
    except OSError as error:
        raise VerificationError(f"cannot load manifest {path}: {error}") from error
    exact_keys(manifest, MANIFEST_KEYS, "manifest")
    require(manifest["schema"] == "vibeos.wasm-runtime-costs.manifest", "manifest schema differs")
    require(manifest["version"] == 1, "manifest version differs")
    require(manifest["suite_id"] == "vibeos.c83.runtime-costs", "manifest suite differs")
    require(manifest["workload_revision"] == 1, "manifest workload revision differs")
    require(isinstance(manifest["fixtures"], list) and len(manifest["fixtures"]) == 3, "fixture set differs")
    fixture_ids: set[str] = set()
    for index, fixture in enumerate(manifest["fixtures"]):
        keys = {"id", "path", "source_sha256", "compiled_sha256", "byte_len", "profile", "stage"}
        exact_keys(fixture, keys, f"fixture[{index}]")
        fixture_id = text(fixture["id"], f"fixture[{index}].id")
        require(fixture_id not in fixture_ids, f"duplicate fixture {fixture_id}")
        fixture_ids.add(fixture_id)
        relative = pathlib.PurePosixPath(text(fixture["path"], f"fixture[{index}].path"))
        require(not relative.is_absolute() and ".." not in relative.parts, "fixture path escapes repository")
        source = ROOT.joinpath(*relative.parts)
        require(source.is_file(), f"fixture source is missing: {relative}")
        require(file_sha256(source) == canonical_hex(fixture["source_sha256"], 64, "fixture source digest"), f"fixture source drifted: {relative}")
        canonical_hex(fixture["compiled_sha256"], 64, "fixture compiled digest")
        integer(fixture["byte_len"], "fixture byte_len", minimum=1)
        text(fixture["profile"], "fixture profile")
        text(fixture["stage"], "fixture stage")
    require(set(manifest["platforms"]) == {"qemu-virt", "milkv-duo-cv1800b"}, "platform set differs")
    require(isinstance(manifest["sampling"], dict), "sampling must be an object")
    for name in ("heavy", "hot", "fuel"):
        exact_keys(manifest["sampling"].get(name), {"warmup", "samples"}, f"sampling.{name}")
        integer(manifest["sampling"][name]["warmup"], f"sampling.{name}.warmup", minimum=1)
        integer(manifest["sampling"][name]["samples"], f"sampling.{name}.samples", minimum=1)
    integer(manifest["sampling"].get("minimum_batch_ticks_divisor"), "minimum tick divisor", minimum=1)
    require(isinstance(manifest["workloads"], list) and len(manifest["workloads"]) == 10, "workload set differs")
    ids: set[str] = set()
    categories: set[str] = set()
    for index, workload in enumerate(manifest["workloads"]):
        require(isinstance(workload, dict), f"workload[{index}] must be an object")
        workload_keys = set(workload)
        require(
            WORKLOAD_KEYS <= workload_keys <= WORKLOAD_KEYS | WORKLOAD_OPTIONAL_KEYS,
            f"workload[{index}] keys differ",
        )
        workload_id = text(workload["id"], f"workload[{index}].id")
        require(workload_id not in ids, f"duplicate workload {workload_id}")
        ids.add(workload_id)
        categories.add(text(workload["category"], f"workload[{index}].category"))
        require(workload["sampling"] in {"heavy", "hot", "fuel"}, f"workload {workload_id} sampling differs")
        integer(workload["batch"], f"workload {workload_id} batch", minimum=1)
        integer(workload["bytes"], f"workload {workload_id} bytes")
        integer(workload["expected_result"], f"workload {workload_id} result")
        if "scope_note" in workload:
            text(workload["scope_note"], f"workload {workload_id} scope_note")
        if "minimum_heap_peak_delta_bytes" in workload:
            integer(
                workload["minimum_heap_peak_delta_bytes"],
                f"workload {workload_id} minimum heap peak delta",
                minimum=1,
            )
    require(
        categories
        == {"validation", "startup", "lift-lower", "async", "composition", "host-call", "memory", "fuel", "cancellation", "revocation"},
        "required runtime-cost categories differ",
    )
    # The schema document is checked in as reviewable documentation even though
    # this verifier intentionally implements the closed shape itself.
    try:
        schema = strict_json_loads(SCHEMA_PATH.read_text(encoding="utf-8"), "schema")
    except OSError as error:
        raise VerificationError(f"cannot load schema: {error}") from error
    require(schema.get("$id") == "https://vibeos.invalid/schemas/wasm-runtime-costs-v1.json", "schema identity differs")
    return manifest


def parse_record(line: str, prefix: str, label: str) -> dict[str, Any] | None:
    position = line.find(prefix)
    if position < 0:
        return None
    require(position == 0, f"{label} marker must begin at column zero")
    payload = line[len(prefix) :].strip()
    value = strict_json_loads(payload, label)
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def rotate_left(value: int, amount: int) -> int:
    value &= U64_MAX
    return ((value << amount) | (value >> (64 - amount))) & U64_MAX


def accumulator(samples: list[dict[str, Any]]) -> int:
    value = 0
    for sample in samples:
        value = (
            rotate_left(value, 7)
            + sample["sequence"]
            + rotate_left(sample["ticks"], 11)
            + rotate_left(sample["operations"], 19)
            + rotate_left(sample["fuel_consumed"], 29)
            + rotate_left(sample["result"], 37)
        ) & U64_MAX
    return value


def expected_run_id(meta: dict[str, Any]) -> str:
    payload = "\0".join(
        [
            "vibeos.c83.runtime-costs.v1",
            meta["source_commit"],
            meta["challenge"],
            meta["sync_component_sha256"],
            meta["route_component_sha256"],
            meta["core_module_sha256"],
            meta["manifest_sha256"],
            meta["transcript_schema_sha256"],
        ]
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def verify_meta(
    meta: dict[str, Any],
    manifest: dict[str, Any],
    platform: str,
    expect_source: str | None,
    publication: bool,
) -> None:
    exact_keys(meta, META_KEYS, "metadata")
    require(meta["schema"] == "vibeos.wasm-runtime-cost.meta", "metadata schema differs")
    integer(meta["version"], "metadata version")
    require(meta["version"] == 1, "metadata version differs")
    require(meta["suite_id"] == manifest["suite_id"], "metadata suite differs")
    integer(meta["workload_revision"], "metadata workload revision")
    require(meta["workload_revision"] == manifest["workload_revision"], "metadata workload revision differs")
    source = canonical_hex(meta["source_commit"], 40, "source commit")
    if expect_source is not None:
        require(source == canonical_hex(expect_source, 40, "expected source commit"), "source commit differs")
    challenge = canonical_hex(meta["challenge"], 64, "challenge")
    if publication:
        require(source != TEST_ONLY_SOURCE_COMMIT, "publication used the documented test-only source sentinel")
        require(challenge != TEST_ONLY_CHALLENGE, "publication used the documented test-only challenge sentinel")
    canonical_hex(meta["run_id"], 64, "run id")
    require(meta["manifest_sha256"] == EXPECTED_MANIFEST_SHA256, "manifest digest differs")
    require(meta["transcript_schema_sha256"] == EXPECTED_SCHEMA_SHA256, "schema digest differs")
    require(meta["run_id"] == expected_run_id(meta), "run id does not bind source/challenge/workloads")
    require(meta["platform"] == platform, "metadata platform differs")
    contract = manifest["platforms"][platform]
    require(meta["target"] == contract["target"], "target differs")
    require(meta["clock"] == "riscv.rdtime", "clock differs")
    integer(meta["timebase_hz"], "metadata timebase", minimum=1)
    require(meta["timebase_hz"] == contract["timebase_hz"], "timebase differs")
    require(meta["sync_profile_stage"] == "executable", "sync stage differs")
    require(meta["async_scope"] == manifest["scope"]["async"], "async scope differs")
    require(meta["composition_scope"] == manifest["scope"]["composition"], "composition scope differs")
    fixtures = {fixture["id"]: fixture for fixture in manifest["fixtures"]}
    bindings = [
        ("sync_component", fixtures["sync-rich-component"]),
        ("route_component", fixtures["async-route-component"]),
        ("core_module", fixtures["core-host-fuel-module"]),
    ]
    for prefix, fixture in bindings:
        require(meta[f"{prefix}_sha256"] == fixture["compiled_sha256"], f"{prefix} digest differs")
        integer(meta[f"{prefix}_bytes"], f"{prefix} length", minimum=1)
        require(meta[f"{prefix}_bytes"] == fixture["byte_len"], f"{prefix} length differs")
    integer(meta["workloads"], "metadata workload count", minimum=1)
    require(meta["workloads"] == len(manifest["workloads"]), "metadata workload count differs")


def verify_sample_shape(sample: dict[str, Any], label: str) -> None:
    exact_keys(sample, SAMPLE_KEYS, label)
    require(sample["schema"] == "vibeos.wasm-runtime-cost.sample", f"{label} schema differs")
    integer(sample["version"], f"{label}.version")
    require(sample["version"] == 1, f"{label} version differs")
    canonical_hex(sample["run_id"], 64, f"{label}.run_id")
    canonical_hex(sample["challenge"], 64, f"{label}.challenge")
    for field in (
        "sequence",
        "sample_index",
        "ticks",
        "operations",
        "bytes",
        "fuel_consumed",
        "poll_quanta",
        "heap_before",
        "heap_peak",
        "heap_after",
        "logical_live_after",
        "result",
    ):
        integer(sample[field], f"{label}.{field}", minimum=1 if field in {"ticks", "operations"} else 0)
    text(sample["workload_id"], f"{label}.workload_id")
    text(sample["category"], f"{label}.category")
    boolean(sample["warmup"], f"{label}.warmup")


def verify_samples(samples: list[dict[str, Any]], meta: dict[str, Any], manifest: dict[str, Any], publication: bool) -> None:
    expected_records = 0
    position = 0
    for workload in manifest["workloads"]:
        sampling = manifest["sampling"][workload["sampling"]]
        total = sampling["warmup"] + sampling["samples"]
        expected_records += total
        fuel_values: set[int] = set()
        poll_values: set[int] = set()
        retained_ticks: list[int] = []
        for sample_index in range(total):
            require(position < len(samples), f"missing sample for {workload['id']}[{sample_index}]")
            sample = samples[position]
            label = f"sample[{position}]"
            verify_sample_shape(sample, label)
            require(sample["sequence"] == position, f"{label} sequence differs")
            require(sample["run_id"] == meta["run_id"], f"{label} run id differs")
            require(sample["challenge"] == meta["challenge"], f"{label} challenge differs")
            require(sample["workload_id"] == workload["id"], f"{label} workload differs")
            require(sample["category"] == workload["category"], f"{label} category differs")
            require(sample["sample_index"] == sample_index, f"{label} sample index differs")
            require(sample["warmup"] is (sample_index < sampling["warmup"]), f"{label} warmup flag differs")
            require(sample["operations"] == workload["batch"], f"{label} batch differs")
            require(sample["bytes"] == workload["bytes"], f"{label} byte count differs")
            require(sample["result"] == workload["expected_result"], f"{label} result differs")
            require(sample["heap_after"] == sample["heap_before"], f"{label} heap did not return")
            require(sample["heap_peak"] >= sample["heap_before"], f"{label} heap peak is below baseline")
            require(sample["heap_peak"] >= sample["heap_after"], f"{label} heap peak is below final")
            require(
                sample["heap_peak"] - sample["heap_before"]
                >= workload.get("minimum_heap_peak_delta_bytes", 0),
                f"{label} heap peak omitted the workload's required live allocation",
            )
            require(sample["logical_live_after"] == 0, f"{label} leaked logical state")
            if workload["category"] in {"host-call", "fuel"}:
                require(sample["fuel_consumed"] > 0, f"{label} omitted fuel")
                require(sample["poll_quanta"] > 0, f"{label} omitted poll count")
                fuel_values.add(sample["fuel_consumed"])
                poll_values.add(sample["poll_quanta"])
            else:
                require(sample["fuel_consumed"] == 0, f"{label} has unexpected fuel")
                expected_polls = {
                    "async": workload["batch"] * 2,
                    "cancellation": workload["batch"],
                }.get(workload["category"], 0)
                require(sample["poll_quanta"] == expected_polls, f"{label} poll count differs")
            if not sample["warmup"]:
                retained_ticks.append(sample["ticks"])
            if publication:
                minimum_ticks = meta["timebase_hz"] // manifest["sampling"]["minimum_batch_ticks_divisor"]
                require(sample["ticks"] >= minimum_ticks, f"{label} timed batch is below 1 ms")
            position += 1
        if workload["category"] in {"host-call", "fuel"}:
            require(len(fuel_values) == 1, f"{workload['id']} fuel is not deterministic")
            require(len(poll_values) == 1, f"{workload['id']} poll count is not deterministic")
        if publication:
            # Every record for a workload has the same fixed operation count,
            # so raw batch ticks preserve the exact stability ratio. Rounding
            # to integer ticks/operation here could collapse a 2x spread to
            # 1/1 for large batches and falsely accept an unstable run.
            ordered = sorted(retained_ticks)
            p50 = nearest_rank(ordered, 50)
            p95 = nearest_rank(ordered, 95)
            ratio_limit = 110 if meta["platform"] == "qemu-virt" else 150
            require(p95 * 100 <= p50 * ratio_limit, f"{workload['id']} stability gate is inconclusive")
    require(len(samples) == expected_records, f"sample count differs: {len(samples)} != {expected_records}")


def verify_end(end: dict[str, Any], samples: list[dict[str, Any]], meta: dict[str, Any], manifest: dict[str, Any]) -> None:
    exact_keys(end, END_KEYS, "end")
    require(end["schema"] == "vibeos.wasm-runtime-cost", "end schema differs")
    integer(end["version"], "end version")
    require(end["version"] == 1, "end version differs")
    require(end["run_id"] == meta["run_id"], "end run id differs")
    require(end["challenge"] == meta["challenge"], "end challenge differs")
    integer(end["records"], "end record count", minimum=1)
    require(end["records"] == len(samples), "end record count differs")
    integer(end["workloads"], "end workload count", minimum=1)
    require(end["workloads"] == len(manifest["workloads"]), "end workload count differs")
    integer(end["accumulator"], "end accumulator")
    require(end["accumulator"] == accumulator(samples), "end accumulator differs")


def verify_transcript_bytes(
    raw: bytes,
    *,
    platform: str,
    manifest: dict[str, Any],
    expect_source: str | None = None,
    publication: bool = False,
) -> VerifiedTranscript:
    require(platform in manifest["platforms"], f"unknown platform {platform}")
    text_data = raw.decode("utf-8", errors="strict")
    lowered = text_data.lower()
    for marker in FAILURE_MARKERS:
        require(marker not in lowered, f"transcript contains terminal failure marker {marker!r}")
    metadata: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    endings: list[dict[str, Any]] = []
    for line in text_data.splitlines():
        if (record := parse_record(line, META_PREFIX, "metadata")) is not None:
            metadata.append(record)
        if (record := parse_record(line, SAMPLE_PREFIX, "sample")) is not None:
            samples.append(record)
        if (record := parse_record(line, END_PREFIX, "end")) is not None:
            endings.append(record)
    require(len(metadata) == 1, f"expected one metadata record, found {len(metadata)}")
    require(len(endings) == 1, f"expected one end record, found {len(endings)}")
    meta = metadata[0]
    end = endings[0]
    verify_meta(meta, manifest, platform, expect_source, publication)
    verify_samples(samples, meta, manifest, publication)
    verify_end(end, samples, meta, manifest)
    return VerifiedTranscript(
        metadata=meta,
        samples=samples,
        end=end,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_bytes=len(raw),
    )


def nearest_rank(ordered: list[int], percentile: int) -> int:
    require(ordered, "cannot summarize an empty sample set")
    index = ((percentile * len(ordered) + 99) // 100) - 1
    return ordered[index]


def summary(values: list[int]) -> dict[str, int]:
    require(values, "cannot summarize an empty distribution")
    ordered = sorted(values)
    return {
        "samples": len(values),
        "min": ordered[0],
        "p50": nearest_rank(ordered, 50),
        "p95": nearest_rank(ordered, 95),
        "max": ordered[-1],
        "mean": sum(values) // len(values),
    }


def derive_summary(verified: VerifiedTranscript, manifest: dict[str, Any], *, boot_index: int) -> dict[str, Any]:
    integer(boot_index, "boot index", maximum=0xffff)
    groups: dict[str, list[dict[str, Any]]] = {workload["id"]: [] for workload in manifest["workloads"]}
    for sample in verified.samples:
        if not sample["warmup"]:
            groups[sample["workload_id"]].append(sample)
    metrics: list[dict[str, Any]] = []
    by_id = {workload["id"]: workload for workload in manifest["workloads"]}
    for workload_id in [workload["id"] for workload in manifest["workloads"]]:
        records = groups[workload_id]
        workload = by_id[workload_id]
        ticks_per_operation = [
            (record["ticks"] + record["operations"] - 1) // record["operations"]
            for record in records
        ]
        metric: dict[str, Any] = {
            "workload_id": workload_id,
            "category": workload["category"],
            "unit": "ticks_per_operation",
            "batch_operations": workload["batch"],
            "batch_ticks": summary([record["ticks"] for record in records]),
            "ticks_per_operation": summary(ticks_per_operation),
            "heap_peak_delta_bytes": summary(
                [record["heap_peak"] - record["heap_before"] for record in records]
            ),
        }
        if workload["bytes"]:
            metric["bytes_per_second"] = summary(
                [record["bytes"] * verified.metadata["timebase_hz"] // record["ticks"] for record in records]
            )
        if workload["category"] in {"host-call", "fuel"}:
            metric["fuel_per_second"] = summary(
                [record["fuel_consumed"] * verified.metadata["timebase_hz"] // record["ticks"] for record in records]
            )
            metric["fuel_consumed_per_sample"] = records[0]["fuel_consumed"]
            metric["poll_quanta_per_sample"] = records[0]["poll_quanta"]
        metrics.append(metric)
    return {
        "schema": "vibeos.wasm-runtime-cost.summary",
        "version": 1,
        "suite_id": manifest["suite_id"],
        "workload_revision": manifest["workload_revision"],
        "source_commit": verified.metadata["source_commit"],
        "challenge": verified.metadata["challenge"],
        "run_id": verified.metadata["run_id"],
        "manifest_sha256": verified.metadata["manifest_sha256"],
        "transcript_schema_sha256": verified.metadata["transcript_schema_sha256"],
        "platform": verified.metadata["platform"],
        "boot_index": boot_index,
        "timebase_hz": verified.metadata["timebase_hz"],
        "raw_transcript_sha256": verified.raw_sha256,
        "raw_transcript_bytes": verified.raw_bytes,
        "metrics": metrics,
    }


def verify_derived_summary(value: Any, expected: dict[str, Any]) -> None:
    require(isinstance(value, dict), "checked summary must be an object")
    require(value == expected, "checked summary differs from independently derived statistics")


def synthetic_transcript(manifest: dict[str, Any]) -> bytes:
    source = "a" * 40
    challenge = "b" * 64
    fixtures = {fixture["id"]: fixture for fixture in manifest["fixtures"]}
    meta = {
        "schema": "vibeos.wasm-runtime-cost.meta",
        "version": 1,
        "suite_id": manifest["suite_id"],
        "workload_revision": 1,
        "source_commit": source,
        "challenge": challenge,
        "run_id": "0" * 64,
        "manifest_sha256": file_sha256(MANIFEST_PATH),
        "transcript_schema_sha256": file_sha256(SCHEMA_PATH),
        "platform": "qemu-virt",
        "target": "riscv64imac-unknown-none-elf",
        "clock": "riscv.rdtime",
        "timebase_hz": 10_000_000,
        "sync_profile_stage": "executable",
        "async_scope": "validation-candidate-primitives",
        "composition_scope": "validation-only-plan",
        "sync_component_sha256": fixtures["sync-rich-component"]["compiled_sha256"],
        "sync_component_bytes": fixtures["sync-rich-component"]["byte_len"],
        "route_component_sha256": fixtures["async-route-component"]["compiled_sha256"],
        "route_component_bytes": fixtures["async-route-component"]["byte_len"],
        "core_module_sha256": fixtures["core-host-fuel-module"]["compiled_sha256"],
        "core_module_bytes": fixtures["core-host-fuel-module"]["byte_len"],
        "workloads": 10,
    }
    meta["run_id"] = expected_run_id(meta)
    records: list[dict[str, Any]] = []
    sequence = 0
    for workload in manifest["workloads"]:
        sampling = manifest["sampling"][workload["sampling"]]
        total = sampling["warmup"] + sampling["samples"]
        for index in range(total):
            fuel = 777 if workload["category"] == "host-call" else 88_888 if workload["category"] == "fuel" else 0
            polls = workload["batch"] * 2 if workload["category"] == "async" else workload["batch"] if workload["category"] == "cancellation" else 128 if workload["category"] == "host-call" else 9 if workload["category"] == "fuel" else 0
            records.append(
                {
                    "schema": "vibeos.wasm-runtime-cost.sample",
                    "version": 1,
                    "run_id": meta["run_id"],
                    "challenge": challenge,
                    "sequence": sequence,
                    "workload_id": workload["id"],
                    "category": workload["category"],
                    "sample_index": index,
                    "warmup": index < sampling["warmup"],
                    "ticks": 10_000 + index,
                    "operations": workload["batch"],
                    "bytes": workload["bytes"],
                    "fuel_consumed": fuel,
                    "poll_quanta": polls,
                    "heap_before": 1000,
                    "heap_peak": 1000
                    + max(200, workload.get("minimum_heap_peak_delta_bytes", 0)),
                    "heap_after": 1000,
                    "logical_live_after": 0,
                    "result": workload["expected_result"],
                }
            )
            sequence += 1
    end = {
        "schema": "vibeos.wasm-runtime-cost",
        "version": 1,
        "run_id": meta["run_id"],
        "challenge": challenge,
        "records": len(records),
        "workloads": 10,
        "accumulator": accumulator(records),
    }
    lines = [META_PREFIX + json.dumps(meta, sort_keys=True, separators=(",", ":"))]
    lines.extend(SAMPLE_PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records)
    lines.append(END_PREFIX + json.dumps(end, sort_keys=True, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode()


def decoded_synthetic(manifest: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    raw = synthetic_transcript(manifest).decode()
    meta: dict[str, Any] | None = None
    samples: list[dict[str, Any]] = []
    end: dict[str, Any] | None = None
    for line in raw.splitlines():
        if line.startswith(META_PREFIX):
            meta = strict_json_loads(line[len(META_PREFIX) :], "synthetic metadata")
        elif line.startswith(SAMPLE_PREFIX):
            samples.append(strict_json_loads(line[len(SAMPLE_PREFIX) :], "synthetic sample"))
        elif line.startswith(END_PREFIX):
            end = strict_json_loads(line[len(END_PREFIX) :], "synthetic end")
    assert meta is not None and end is not None
    return meta, samples, end


def encode_synthetic(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any], *, trailer: str = "") -> bytes:
    lines = [META_PREFIX + json.dumps(meta, separators=(",", ":"))]
    lines.extend(SAMPLE_PREFIX + json.dumps(record, separators=(",", ":")) for record in samples)
    lines.append(END_PREFIX + json.dumps(end, separators=(",", ":")))
    if trailer:
        lines.append(trailer)
    return ("\n".join(lines) + "\n").encode()


def selftest(manifest: dict[str, Any]) -> None:
    good = synthetic_transcript(manifest)
    verified = verify_transcript_bytes(good, platform="qemu-virt", manifest=manifest, expect_source="a" * 40, publication=True)
    derived = derive_summary(verified, manifest, boot_index=0)
    require(len(derived["metrics"]) == 10, "selftest summary metric count differs")
    composition_metric = next(
        metric for metric in derived["metrics"] if metric["category"] == "composition"
    )
    require(
        "bytes_per_second" not in composition_metric,
        "selftest exposed composition byte throughput for an already-decoded plan",
    )
    memory_metric = next(
        metric for metric in derived["metrics"] if metric["category"] == "memory"
    )
    memory_contract = next(
        workload for workload in manifest["workloads"] if workload["category"] == "memory"
    )
    require(
        memory_metric["heap_peak_delta_bytes"]["min"]
        >= memory_contract["minimum_heap_peak_delta_bytes"],
        "selftest memory summary omitted the required live allocation",
    )
    verify_derived_summary(copy.deepcopy(derived), derived)
    changed_summary = copy.deepcopy(derived)
    changed_summary["metrics"][0]["ticks_per_operation"]["p95"] += 1
    try:
        verify_derived_summary(changed_summary, derived)
    except VerificationError:
        pass
    else:
        raise VerificationError("selftest accepted a changed derived summary")

    mutations: list[tuple[str, Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], bytes]]] = []

    def mutate(name: str, action: Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], None]) -> None:
        def build(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]) -> bytes:
            action(meta, samples, end)
            return encode_synthetic(meta, samples, end)
        mutations.append((name, build))

    mutate("missing-meta-key", lambda meta, samples, end: meta.pop("clock"))
    mutate("extra-meta-key", lambda meta, samples, end: meta.update(extra=1))
    mutate("zero-source", lambda meta, samples, end: meta.update(source_commit="0" * 40))
    mutate("wrong-platform", lambda meta, samples, end: meta.update(platform="milkv-duo-cv1800b"))
    mutate("wrong-timebase", lambda meta, samples, end: meta.update(timebase_hz=25_000_000))
    mutate("wrong-fixture", lambda meta, samples, end: meta.update(sync_component_sha256="3" * 64))
    mutate("wrong-manifest-binding", lambda meta, samples, end: meta.update(manifest_sha256="3" * 64))
    mutate("wrong-schema-binding", lambda meta, samples, end: meta.update(transcript_schema_sha256="3" * 64))
    mutate("wrong-run-id", lambda meta, samples, end: meta.update(run_id="3" * 64))

    def bind_test_only_challenge(
        meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]
    ) -> None:
        meta["challenge"] = TEST_ONLY_CHALLENGE
        meta["run_id"] = expected_run_id(meta)
        for sample in samples:
            sample["challenge"] = TEST_ONLY_CHALLENGE
            sample["run_id"] = meta["run_id"]
        end["challenge"] = TEST_ONLY_CHALLENGE
        end["run_id"] = meta["run_id"]

    mutate("publication-test-only-challenge", bind_test_only_challenge)
    mutate("missing-sample", lambda meta, samples, end: samples.pop())
    mutate("duplicate-sample", lambda meta, samples, end: samples.append(copy.deepcopy(samples[-1])))
    mutate("sequence-gap", lambda meta, samples, end: samples[3].update(sequence=99))
    mutate("bool-as-integer", lambda meta, samples, end: samples[0].update(ticks=True))
    mutate("bool-as-version", lambda meta, samples, end: samples[0].update(version=True))
    mutate("zero-ticks", lambda meta, samples, end: samples[0].update(ticks=0))
    mutate("overflow-ticks", lambda meta, samples, end: samples[0].update(ticks=1 << 64))
    mutate("warmup-flip", lambda meta, samples, end: samples[0].update(warmup=False))
    mutate("wrong-workload", lambda meta, samples, end: samples[0].update(workload_id="other"))
    mutate("wrong-category", lambda meta, samples, end: samples[0].update(category="memory"))
    mutate("wrong-batch", lambda meta, samples, end: samples[0].update(operations=2))
    mutate("wrong-bytes", lambda meta, samples, end: samples[0].update(bytes=0))
    mutate("wrong-result", lambda meta, samples, end: samples[0].update(result=0))
    mutate("heap-leak", lambda meta, samples, end: samples[0].update(heap_after=1001))
    memory_position = next(
        index
        for index, sample in enumerate(decoded_synthetic(manifest)[1])
        if sample["category"] == "memory"
    )
    mutate(
        "memory-peak-omitted",
        lambda meta, samples, end: samples[memory_position].update(
            heap_peak=samples[memory_position]["heap_before"]
        ),
    )
    mutate("logical-leak", lambda meta, samples, end: samples[0].update(logical_live_after=1))
    host_position = next(index for index, sample in enumerate(decoded_synthetic(manifest)[1]) if sample["category"] == "host-call")
    mutate("missing-fuel", lambda meta, samples, end: samples[host_position].update(fuel_consumed=0))
    mutate("wrong-challenge", lambda meta, samples, end: samples[0].update(challenge="3" * 64))
    mutate("wrong-end-count", lambda meta, samples, end: end.update(records=end["records"] - 1))
    mutate("wrong-accumulator", lambda meta, samples, end: end.update(accumulator=end["accumulator"] ^ 1))
    mutate("extra-sample-key", lambda meta, samples, end: samples[0].update(extra=1))

    def hide_batch_instability(
        meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]
    ) -> None:
        retained = [
            sample
            for sample in samples
            if sample["category"] == "fuel" and not sample["warmup"]
        ]
        require(len(retained) == 21, "selftest fuel retained count differs")
        for index, sample in enumerate(retained):
            sample["ticks"] = 10_000 if index < 11 else 20_000
        end["accumulator"] = accumulator(samples)

    mutate("rounded-per-operation-hides-instability", hide_batch_instability)

    def no_meta(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]) -> bytes:
        encoded = encode_synthetic(meta, samples, end).decode().splitlines()
        return ("\n".join(encoded[1:]) + "\n").encode()

    def duplicate_meta(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]) -> bytes:
        encoded = encode_synthetic(meta, samples, end).decode()
        line = META_PREFIX + json.dumps(meta, separators=(",", ":")) + "\n"
        return (line + encoded).encode()

    def no_end(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]) -> bytes:
        encoded = encode_synthetic(meta, samples, end).decode().splitlines()
        return ("\n".join(encoded[:-1]) + "\n").encode()

    def duplicate_end(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]) -> bytes:
        encoded = encode_synthetic(meta, samples, end).decode()
        line = END_PREFIX + json.dumps(end, separators=(",", ":")) + "\n"
        return (encoded + line).encode()

    def fatal(meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]) -> bytes:
        return encode_synthetic(meta, samples, end, trailer="[!] fatal trap")

    def kernel_panic_after_end(
        meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]
    ) -> bytes:
        return encode_synthetic(meta, samples, end, trailer="kernel panic: late target failure")

    def prefixed_sample_marker(
        meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]
    ) -> bytes:
        return encode_synthetic(meta, samples, end).replace(
            SAMPLE_PREFIX.encode(), b"junk " + SAMPLE_PREFIX.encode(), 1
        )

    def duplicate_sample_member(
        meta: dict[str, Any], samples: list[dict[str, Any]], end: dict[str, Any]
    ) -> bytes:
        encoded = encode_synthetic(meta, samples, end)
        needle = f'"ticks":{samples[0]["ticks"]}'.encode()
        require(needle in encoded, "duplicate-member selftest fixture is absent")
        return encoded.replace(needle, needle + b"," + needle, 1)

    mutations.extend(
        [
            ("missing-meta", no_meta),
            ("duplicate-meta", duplicate_meta),
            ("missing-end", no_end),
            ("duplicate-end", duplicate_end),
            ("fatal-trailer", fatal),
            ("kernel-panic-after-end", kernel_panic_after_end),
            ("prefixed-sample-marker", prefixed_sample_marker),
            ("duplicate-sample-member", duplicate_sample_member),
        ]
    )

    rejected = 0
    for name, builder in mutations:
        meta, samples, end = decoded_synthetic(manifest)
        candidate = builder(meta, samples, end)
        try:
            verify_transcript_bytes(candidate, platform="qemu-virt", manifest=manifest, expect_source="a" * 40, publication=True)
        except (VerificationError, UnicodeDecodeError):
            rejected += 1
        else:
            raise VerificationError(f"selftest mutation was accepted: {name}")
    print(f"verify-c83-runtime-costs.py selftest: PASS ({rejected} mutations rejected)")


def write_json_atomic(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, default=MANIFEST_PATH)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--check-manifest", action="store_true")
    parser.add_argument("--transcript", type=pathlib.Path)
    parser.add_argument("--platform", choices=("qemu-virt", "milkv-duo-cv1800b"))
    parser.add_argument("--expect-source")
    parser.add_argument("--publication", action="store_true")
    parser.add_argument("--boot-index", type=int, default=0)
    parser.add_argument("--summary-out", type=pathlib.Path)
    parser.add_argument(
        "--summary-in",
        type=pathlib.Path,
        help="require this checked-in summary to exactly match fresh derivation",
    )
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        if args.selftest:
            selftest(manifest)
        if args.transcript is not None:
            require(args.platform is not None, "--platform is required with --transcript")
            raw = args.transcript.read_bytes()
            verified = verify_transcript_bytes(
                raw,
                platform=args.platform,
                manifest=manifest,
                expect_source=args.expect_source,
                publication=args.publication,
            )
            derived = derive_summary(verified, manifest, boot_index=args.boot_index)
            if args.summary_in is not None:
                try:
                    checked_summary = strict_json_loads(
                        args.summary_in.read_text(encoding="utf-8"), "checked summary"
                    )
                except OSError as error:
                    raise VerificationError(f"cannot load checked summary {args.summary_in}: {error}") from error
                verify_derived_summary(checked_summary, derived)
            if args.summary_out is not None:
                write_json_atomic(args.summary_out, derived)
            print(
                f"PASS {args.platform} source={verified.metadata['source_commit']} "
                f"records={len(verified.samples)} sha256={verified.raw_sha256}"
            )
        elif args.summary_out is not None or args.summary_in is not None or args.platform is not None or args.expect_source is not None or args.publication:
            raise VerificationError("transcript-only options require --transcript")
        elif not args.selftest and not args.check_manifest:
            parser.error("choose --selftest, --check-manifest, or --transcript")
        if args.check_manifest:
            print(f"PASS manifest {args.manifest}")
        return 0
    except (OSError, UnicodeDecodeError, VerificationError) as error:
        print(f"FAIL verify-c83-runtime-costs: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
