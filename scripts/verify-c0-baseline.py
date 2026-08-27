#!/usr/bin/env python3
"""Verify the closed C0.7 baseline contract without recollecting timings."""

from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import math
import pathlib
import re
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "wasm-candidates/evidence/baseline-v1.json"
MANIFEST = ROOT / "wasm-candidates/evidence/workloads-v1.json"
STATIC_TARGET = "riscv64imac-unknown-none-elf"
STATIC_PROFILE = (
    "workspace release (opt-level=z,lto=true,debug=true); "
    "debug sections excluded by SHF_ALLOC classification"
)
PROBE_HEAP_BYTES = 256 * 1024
CONTROL_PROBE = "c0_static_control"
SUBJECTS = {
    "wasmi=1.1.0": {"kind": "core-engine", "probe": "c0_static_wasmi"},
    "dlr-wasm-interpreter=0.2.0": {"kind": "core-engine", "probe": "c0_static_dlr"},
    "component-frontend=0.255.0": {
        "kind": "component-frontend",
        "probe": "c0_static_frontend",
    },
}
METRICS = {
    "code-static-size",
    "validator-peak-memory",
    "empty-instance-cost",
    "startup",
    "core-fuel-throughput",
    "canonical-lift-lower",
}
STATIC_SOURCE_INPUTS = {
    "rust-toolchain.toml",
    "Cargo.toml",
    "Cargo.lock",
    "wasm-candidates/Cargo.toml",
    "wasm-candidates/build.rs",
    "wasm-candidates/examples/c0_baseline.rs",
    "wasm-candidates/fixtures/empty.wat",
    "wasm-candidates/fixtures/fuel.wat",
    "component-format/Cargo.toml",
    "component-runtime/Cargo.toml",
    "wasm-runtime/Cargo.toml",
    "component-format/tests/corpus/component/typed.component.wat",
    "component-format/tests/corpus/wit/world.wit",
    "wasm-candidates/evidence/workloads-v1.json",
    "scripts/collect-c0-baseline.py",
    "scripts/verify-c0-baseline.py",
}
SOURCE_TREES = (
    "wasm-candidates/src",
    "component-format/src",
    "component-runtime/src",
    "wasm-runtime/src",
)
EXPECTED_SAMPLING = {
    "timing_samples": 9,
    "startup_operations_per_sample": 256,
    "fuel_operations_per_sample": 32,
    "frontend_operations_per_sample": 256,
    "canonical_operations_per_sample": 512,
    "startup_input": 1,
    "fuel_input": 32_768,
    "fuel_budget": 10_000_000,
    "canonical_text_bytes": 256,
    "canonical_list_elements": 64,
}
EXPECTED_STATISTICS = {
    "mean": "integer floor of sum divided by sample count",
    "p50": "nearest-rank index ceil(0.50*n)-1",
    "p95": "nearest-rank index ceil(0.95*n)-1",
    "thresholds": "none; every baseline change requires explicit review",
}
EXPECTED_BUILD_ENVIRONMENT = {
    "cargo_home": "isolated cache-only",
    "target_dir": "fresh temporary directory",
    "cargo_net_offline": True,
    "cargo_incremental": False,
    "rustflags": [],
    "rustdocflags": [],
    "rustc_wrapper": None,
    "source_date_epoch": "0",
    "locale": "C",
}
EXPECTED_FIXTURES = {
    "empty-core-v1": ("wasm-candidates/fixtures/empty.wat", True),
    "fuel-core-v1": ("wasm-candidates/fixtures/fuel.wat", True),
    "typed-component-v1": (
        "component-format/tests/corpus/component/typed.component.wat",
        True,
    ),
    "typed-world-v1": ("component-format/tests/corpus/wit/world.wit", False),
}
HOST_CONTRACT = {
    ("wasmi=1.1.0", "validator-accepted-peak"): ("memory", "fuel-core-v1"),
    ("wasmi=1.1.0", "validator-rejected-peak"): ("memory", "malformed-core-v1"),
    ("wasmi=1.1.0", "empty-instance"): ("memory", "empty-core-v1"),
    ("wasmi=1.1.0", "cold-startup"): ("timing", "fuel-core-first-call-v1"),
    ("wasmi=1.1.0", "core-fuel-throughput"): ("fuel", "burn-{fuel_input}-v1"),
    ("dlr-wasm-interpreter=0.2.0", "validator-accepted-peak"): (
        "memory",
        "fuel-core-v1",
    ),
    ("dlr-wasm-interpreter=0.2.0", "validator-rejected-peak"): (
        "memory",
        "malformed-core-v1",
    ),
    ("dlr-wasm-interpreter=0.2.0", "empty-instance"): ("memory", "empty-core-v1"),
    ("dlr-wasm-interpreter=0.2.0", "cold-startup"): (
        "timing",
        "fuel-core-first-call-v1",
    ),
    ("dlr-wasm-interpreter=0.2.0", "core-fuel-throughput"): (
        "fuel",
        "burn-{fuel_input}-v1",
    ),
    ("component-frontend=0.255.0", "component-validator-accepted-peak"): (
        "memory",
        "typed-component-v1",
    ),
    ("component-frontend=0.255.0", "component-validator-rejected-peak"): (
        "memory",
        "malformed-component-v1",
    ),
    ("component-frontend=0.255.0", "wit-validator-peak"): ("memory", "typed-world-v1"),
    ("component-frontend=0.255.0", "frontend-prepare"): (
        "timing",
        "typed-component-world-v1",
    ),
    ("component-frontend=0.255.0", "canonical-lift-lower-peak"): (
        "memory",
        "canonical-{canonical_text_bytes}b-{canonical_list_elements}u32-v1",
    ),
    ("component-frontend=0.255.0", "canonical-lift-lower"): (
        "timing",
        "canonical-{canonical_text_bytes}b-{canonical_list_elements}u32-v1",
    ),
}
EXPECTED_APPLICABILITY_IDS = {
    ("wasmi=1.1.0", "code-static-size"): ("riscv64-linked-probe",),
    ("wasmi=1.1.0", "validator-peak-memory"): (
        "validator-accepted-peak",
        "validator-rejected-peak",
    ),
    ("wasmi=1.1.0", "empty-instance-cost"): ("empty-instance",),
    ("wasmi=1.1.0", "startup"): ("cold-startup",),
    ("wasmi=1.1.0", "core-fuel-throughput"): ("core-fuel-throughput",),
    ("wasmi=1.1.0", "canonical-lift-lower"): None,
    ("dlr-wasm-interpreter=0.2.0", "code-static-size"): ("riscv64-linked-probe",),
    ("dlr-wasm-interpreter=0.2.0", "validator-peak-memory"): (
        "validator-accepted-peak",
        "validator-rejected-peak",
    ),
    ("dlr-wasm-interpreter=0.2.0", "empty-instance-cost"): ("empty-instance",),
    ("dlr-wasm-interpreter=0.2.0", "startup"): ("cold-startup",),
    ("dlr-wasm-interpreter=0.2.0", "core-fuel-throughput"): ("core-fuel-throughput",),
    ("dlr-wasm-interpreter=0.2.0", "canonical-lift-lower"): None,
    ("component-frontend=0.255.0", "code-static-size"): ("riscv64-linked-probe",),
    ("component-frontend=0.255.0", "validator-peak-memory"): (
        "component-validator-accepted-peak",
        "component-validator-rejected-peak",
        "wit-validator-peak",
    ),
    ("component-frontend=0.255.0", "empty-instance-cost"): None,
    ("component-frontend=0.255.0", "startup"): ("frontend-prepare",),
    ("component-frontend=0.255.0", "core-fuel-throughput"): None,
    ("component-frontend=0.255.0", "canonical-lift-lower"): (
        "canonical-lift-lower-peak",
        "canonical-lift-lower",
    ),
}
TOP_LEVEL_KEYS = {
    "schema",
    "version",
    "epoch",
    "update_policy",
    "threshold_policy",
    "toolchain",
    "host",
    "build_environment",
    "static_target",
    "fixtures",
    "applicability",
    "sampling",
    "host_measurements",
    "source_inputs",
    "workload_manifest_sha256",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    require(isinstance(value, dict), f"{label} is not an object")
    require(
        set(value) == expected, f"{label} keys differ: {sorted(set(value) ^ expected)}"
    )


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_positive(value: Any, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value > 0,
        f"{label} is not a positive integer",
    )
    return value


def exact_nonnegative(value: Any, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0,
        f"{label} is not a nonnegative integer",
    )
    return value


def exact_sha256(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and HEX64.fullmatch(value) is not None,
        f"{label} is malformed",
    )
    require(value != "0" * 64, f"{label} is the all-zero sentinel")
    return value


def exact_typed_mapping(value: Any, expected: dict[str, Any], label: str) -> None:
    exact_keys(value, set(expected), label)
    for key, expected_value in expected.items():
        actual = value[key]
        require(
            type(actual) is type(expected_value) and actual == expected_value,
            f"{label}.{key} differs",
        )


def expected_source_inputs() -> list[str]:
    paths = set(STATIC_SOURCE_INPUTS)
    for tree in SOURCE_TREES:
        root = ROOT / tree
        require(root.is_dir(), f"source input tree is missing: {tree}")
        paths.update(
            path.relative_to(ROOT).as_posix()
            for path in root.rglob("*.rs")
            if path.is_file()
        )
    for relative in (".cargo/config", ".cargo/config.toml"):
        if (ROOT / relative).is_file():
            paths.add(relative)
    return sorted(paths)


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def expected_statistics(values: list[int]) -> dict[str, int]:
    return {
        "min": min(values),
        "mean": sum(values) // len(values),
        "p50": nearest_rank(values, 0.50),
        "p95": nearest_rank(values, 0.95),
        "max": max(values),
    }


def verify_manifest_fixtures(fixtures: Any) -> None:
    require(isinstance(fixtures, list), "manifest fixtures is not an array")
    identifiers = [
        fixture.get("id") if isinstance(fixture, dict) else None for fixture in fixtures
    ]
    require(
        identifiers == list(EXPECTED_FIXTURES),
        "manifest fixture identities or order differ",
    )
    for fixture in fixtures:
        identifier = fixture["id"]
        source, compiled = EXPECTED_FIXTURES[identifier]
        keys = {"id", "source", "source_sha256"}
        if compiled:
            keys |= {"compiled_sha256", "compiled_bytes"}
        exact_keys(fixture, keys, f"manifest fixture {identifier}")
        require(
            fixture["source"] == source,
            f"manifest fixture source differs: {identifier}",
        )
        source_path = ROOT / source
        require(source_path.is_file(), f"fixture source is missing: {identifier}")
        source_hash = exact_sha256(
            fixture["source_sha256"], f"{identifier}.source_sha256"
        )
        require(
            source_hash == sha256_file(source_path),
            f"fixture source drifted: {identifier}",
        )
        if compiled:
            exact_sha256(fixture["compiled_sha256"], f"{identifier}.compiled_sha256")
            exact_positive(fixture["compiled_bytes"], f"{identifier}.compiled_bytes")


def verify_manifest(manifest: dict[str, Any]) -> None:
    exact_keys(
        manifest,
        {
            "schema",
            "version",
            "epoch",
            "static_target",
            "probe_heap_bytes",
            "subjects",
            "applicability",
            "fixtures",
            "sampling",
            "statistics",
        },
        "workload manifest",
    )
    require(
        manifest["schema"] == "vibeos.c07.workloads", "workload manifest schema differs"
    )
    require(
        type(manifest["version"]) is int and manifest["version"] == 1,
        "workload manifest version differs",
    )
    require(
        isinstance(manifest["epoch"], str), "workload manifest epoch is not a string"
    )
    try:
        datetime.date.fromisoformat(manifest["epoch"])
    except ValueError as error:
        raise VerificationError("workload manifest epoch is not an ISO date") from error
    require(
        manifest["static_target"] == STATIC_TARGET, "manifest static target differs"
    )
    require(
        exact_positive(manifest["probe_heap_bytes"], "manifest probe heap")
        == PROBE_HEAP_BYTES,
        "manifest probe heap differs",
    )
    expected_subjects = [
        {"id": subject, "kind": identity["kind"], "probe": identity["probe"]}
        for subject, identity in SUBJECTS.items()
    ]
    require(
        manifest["subjects"] == expected_subjects,
        "manifest subjects or probe identities differ",
    )
    exact_typed_mapping(manifest["sampling"], EXPECTED_SAMPLING, "manifest sampling")
    exact_typed_mapping(
        manifest["statistics"], EXPECTED_STATISTICS, "manifest statistics"
    )
    verify_manifest_fixtures(manifest["fixtures"])


def verify_source_inputs(document: dict[str, Any]) -> None:
    inputs = document["source_inputs"]
    require(isinstance(inputs, list), "source_inputs is not an array")
    paths = [entry.get("path") if isinstance(entry, dict) else None for entry in inputs]
    expected = expected_source_inputs()
    require(paths == expected, "source_inputs paths differ or are not sorted")
    for entry in inputs:
        exact_keys(entry, {"path", "sha256"}, f"source input {entry.get('path')}")
        source_hash = exact_sha256(entry["sha256"], f"source hash for {entry['path']}")
        path = ROOT / entry["path"]
        require(path.is_file(), f"source input is missing: {entry['path']}")
        require(
            sha256_file(path) == source_hash, f"source input drifted: {entry['path']}"
        )


def verify_fixtures(document: dict[str, Any], manifest: dict[str, Any]) -> None:
    require(
        document["fixtures"] == manifest["fixtures"],
        "baseline fixtures differ from the workload manifest",
    )


def verify_sections(
    record: dict[str, Any],
    probe_heap: int,
    control_code: int | None,
    *,
    expected_artifact: str,
    expected_subject: str | None,
) -> None:
    common = {
        "artifact",
        "probe_heap_symbol",
        "sections",
        "executable_bytes",
        "read_only_bytes",
        "writable_file_bytes",
        "zero_fill_bytes",
        "code_static_bytes",
        "static_ram_bytes_excluding_probe_heap",
    }
    extras = (
        set()
        if expected_subject is None
        else {
            "subject",
            "measurement",
            "incremental_code_static_bytes_over_control",
        }
    )
    exact_keys(
        record,
        common | extras,
        "static control" if expected_subject is None else "static measurement",
    )
    require(record["artifact"] == expected_artifact, "static artifact path differs")
    exact_keys(
        record["probe_heap_symbol"], {"name", "bytes", "section"}, "probe heap symbol"
    )
    require(
        record["probe_heap_symbol"]
        == {"name": "C0_PROBE_HEAP", "bytes": probe_heap, "section": ".bss"},
        "probe heap symbol identity differs",
    )
    sections = record["sections"]
    require(isinstance(sections, list) and sections, "allocated section list is empty")
    indexes: set[int] = set()
    totals = {"executable": 0, "read-only": 0, "writable-file": 0, "zero-fill": 0}
    for section in sections:
        exact_keys(
            section,
            {"index", "name", "type", "flags", "category", "bytes"},
            "allocated section",
        )
        index = exact_nonnegative(section["index"], "section index")
        require(index not in indexes, "allocated section index is duplicated")
        indexes.add(index)
        require(
            isinstance(section["name"], str) and section["name"],
            "allocated section name is invalid",
        )
        require(
            isinstance(section["type"], str) and section["type"],
            "allocated section type is invalid",
        )
        flags = section["flags"]
        require(
            isinstance(flags, list)
            and flags
            and all(isinstance(flag, str) and flag for flag in flags)
            and flags == sorted(set(flags)),
            "allocated section flags are invalid",
        )
        require("SHF_ALLOC" in flags, "recorded section is not allocated")
        if "SHF_EXECINSTR" in flags:
            expected_category = "executable"
        elif "SHF_WRITE" in flags and section["type"] == "SHT_NOBITS":
            expected_category = "zero-fill"
        elif "SHF_WRITE" in flags:
            expected_category = "writable-file"
        else:
            expected_category = "read-only"
        require(
            section["category"] == expected_category,
            "allocated section category differs from ELF flags",
        )
        totals[section["category"]] += exact_positive(section["bytes"], "section bytes")
    for field in (
        "executable_bytes",
        "read_only_bytes",
        "writable_file_bytes",
        "zero_fill_bytes",
        "code_static_bytes",
        "static_ram_bytes_excluding_probe_heap",
    ):
        exact_nonnegative(record[field], field)
    require(
        record["executable_bytes"] == totals["executable"],
        "executable section total differs",
    )
    require(
        record["read_only_bytes"] == totals["read-only"],
        "read-only section total differs",
    )
    require(
        record["writable_file_bytes"] == totals["writable-file"],
        "writable-file section total differs",
    )
    require(
        record["zero_fill_bytes"] == totals["zero-fill"],
        "zero-fill section total differs",
    )
    require(record["zero_fill_bytes"] >= probe_heap, "static probe heap is absent")
    code_static = totals["executable"] + totals["read-only"] + totals["writable-file"]
    static_ram = totals["writable-file"] + totals["zero-fill"] - probe_heap
    require(record["code_static_bytes"] == code_static, "code/static aggregate differs")
    require(
        record["static_ram_bytes_excluding_probe_heap"] == static_ram,
        "static RAM aggregate differs",
    )
    if expected_subject is not None:
        require(control_code is not None, "static measurement has no control aggregate")
        require(
            record["subject"] == expected_subject, "static measurement subject differs"
        )
        require(
            record["measurement"] == "riscv64-linked-probe",
            "static measurement identity differs",
        )
        require(
            exact_positive(
                record["incremental_code_static_bytes_over_control"],
                "incremental code/static bytes",
            )
            == code_static - control_code,
            "incremental code/static aggregate differs",
        )
        require(
            code_static > control_code, "candidate code was not retained over control"
        )


def verify_static(document: dict[str, Any], manifest: dict[str, Any]) -> None:
    static = document["static_target"]
    exact_keys(
        static,
        {
            "triple",
            "profile",
            "probe_heap_bytes",
            "control",
            "measurements",
        },
        "static_target",
    )
    require(
        static["triple"] == STATIC_TARGET == manifest["static_target"],
        "static target differs",
    )
    require(static["profile"] == STATIC_PROFILE, "static profile identity differs")
    probe_heap = exact_positive(static["probe_heap_bytes"], "probe_heap_bytes")
    require(
        probe_heap == manifest["probe_heap_bytes"], "probe heap differs from manifest"
    )
    artifact_root = f"target/{STATIC_TARGET}/release"
    verify_sections(
        static["control"],
        probe_heap,
        None,
        expected_artifact=f"{artifact_root}/{CONTROL_PROBE}",
        expected_subject=None,
    )
    control_code = static["control"]["code_static_bytes"]
    measurements = static["measurements"]
    require(
        isinstance(measurements, list) and len(measurements) == len(SUBJECTS),
        "static measurement count differs",
    )
    subjects = [measurement.get("subject") for measurement in measurements]
    require(
        len(subjects) == len(set(subjects)) and set(subjects) == set(SUBJECTS),
        "static subject set differs",
    )
    records = {measurement["subject"]: measurement for measurement in measurements}
    for subject, identity in SUBJECTS.items():
        verify_sections(
            records[subject],
            probe_heap,
            control_code,
            expected_artifact=f"{artifact_root}/{identity['probe']}",
            expected_subject=subject,
        )


def timing_operations(metric: str, sampling: dict[str, Any]) -> int:
    return {
        "cold-startup": sampling["startup_operations_per_sample"],
        "core-fuel-throughput": sampling["fuel_operations_per_sample"],
        "frontend-prepare": sampling["frontend_operations_per_sample"],
        "canonical-lift-lower": sampling["canonical_operations_per_sample"],
    }[metric]


def expected_workload(key: tuple[str, str], sampling: dict[str, Any]) -> str:
    template = HOST_CONTRACT[key][1]
    return template.format(**sampling)


def expected_result_per_operation(metric: str, sampling: dict[str, Any]) -> int:
    canonical_result = (
        sampling["canonical_text_bytes"] + sampling["canonical_list_elements"]
    )
    return {
        "cold-startup": 0,
        "core-fuel-throughput": 0,
        "frontend-prepare": 2,
        "canonical-lift-lower": canonical_result,
    }[metric]


def expected_results(
    metric: str, operations: int, sampling: dict[str, Any]
) -> list[int]:
    result = expected_result_per_operation(metric, sampling) * operations
    return [result] * sampling["timing_samples"]


def verify_memory(record: dict[str, Any], sampling: dict[str, Any]) -> None:
    exact_keys(
        record,
        {
            "kind",
            "subject",
            "metric",
            "workload",
            "operations",
            "baseline_bytes",
            "peak_delta_bytes",
            "retained_bytes",
            "after_bytes",
            "result",
        },
        "memory measurement",
    )
    require(
        exact_positive(record["operations"], "memory measurement operation count") == 1,
        "memory measurement operation count differs",
    )
    exact_nonnegative(record["baseline_bytes"], "memory baseline")
    exact_positive(record["peak_delta_bytes"], "memory peak delta")
    exact_nonnegative(record["retained_bytes"], "memory retained bytes")
    exact_positive(record["result"], "memory semantic result")
    require(
        record["after_bytes"] == record["baseline_bytes"],
        "memory measurement did not return to baseline",
    )
    if record["metric"] == "empty-instance":
        exact_positive(record["retained_bytes"], "empty instance retained bytes")
        require(record["result"] == 1, "empty instance semantic result differs")
    else:
        require(record["retained_bytes"] == 0, "transient measurement retained bytes")
        expected_result = (
            sampling["canonical_text_bytes"] + sampling["canonical_list_elements"]
            if record["metric"] == "canonical-lift-lower-peak"
            else 1
        )
        require(record["result"] == expected_result, "memory semantic result differs")


def verify_timing(record: dict[str, Any], sampling: dict[str, Any], fuel: bool) -> None:
    keys = {
        "kind",
        "subject",
        "metric",
        "workload",
        "operations_per_sample",
        "samples_ns",
        "results",
        "ns_per_operation",
        "operations_per_second",
        "ns_per_operation_statistics",
        "operations_per_second_statistics",
    }
    if fuel:
        keys |= {
            "fuel_samples",
            "fuel_per_operation",
            "fuel_per_second",
            "fuel_per_second_statistics",
        }
    exact_keys(record, keys, f"{record.get('metric')} measurement")
    operations = exact_positive(
        record["operations_per_sample"], "timing operation count"
    )
    require(
        operations == timing_operations(record["metric"], sampling),
        "timing operation count differs from manifest",
    )
    sample_count = sampling["timing_samples"]
    samples = record["samples_ns"]
    require(
        isinstance(samples, list) and len(samples) == sample_count,
        "timing sample count differs",
    )
    for value in samples:
        exact_positive(value, "elapsed sample")
    results = record["results"]
    require(
        isinstance(results, list) and len(results) == sample_count,
        "timing result count differs",
    )
    for value in results:
        exact_nonnegative(value, "timing semantic result")
    require(
        results == expected_results(record["metric"], operations, sampling),
        "timing semantic results differ",
    )
    normalized = [value // operations for value in samples]
    throughput = [operations * 1_000_000_000 // value for value in samples]
    require(
        record["ns_per_operation"] == normalized, "normalized timing samples differ"
    )
    require(
        record["operations_per_second"] == throughput,
        "operation throughput samples differ",
    )
    require(
        record["ns_per_operation_statistics"] == expected_statistics(normalized),
        "timing statistics differ",
    )
    require(
        record["operations_per_second_statistics"] == expected_statistics(throughput),
        "throughput statistics differ",
    )
    if fuel:
        fuel_per_operation = exact_positive(
            record["fuel_per_operation"], "fuel per operation"
        )
        fuel_samples = [fuel_per_operation * operations] * sample_count
        require(
            record["fuel_samples"] == fuel_samples,
            "fuel samples are not exact and deterministic",
        )
        fuel_throughput = [
            value * 1_000_000_000 // elapsed
            for value, elapsed in zip(fuel_samples, samples, strict=True)
        ]
        require(
            record["fuel_per_second"] == fuel_throughput,
            "fuel throughput samples differ",
        )
        require(
            record["fuel_per_second_statistics"]
            == expected_statistics(fuel_throughput),
            "fuel throughput statistics differ",
        )


def verify_host(document: dict[str, Any], manifest: dict[str, Any]) -> None:
    records = document["host_measurements"]
    require(isinstance(records, list), "host_measurements is not an array")
    keys = [(record.get("subject"), record.get("metric")) for record in records]
    require(len(keys) == len(set(keys)), "host measurement is duplicated")
    require(set(keys) == set(HOST_CONTRACT), "host measurement set differs")
    for record in records:
        key = (record["subject"], record["metric"])
        kind = HOST_CONTRACT[key][0]
        require(record["kind"] == kind, f"host measurement kind differs: {key}")
        require(
            record["workload"] == expected_workload(key, manifest["sampling"]),
            f"host measurement workload differs: {key}",
        )
        if kind == "memory":
            verify_memory(record, manifest["sampling"])
        else:
            verify_timing(record, manifest["sampling"], kind == "fuel")


def verify_applicability(document: dict[str, Any], manifest: dict[str, Any]) -> None:
    applicability = document["applicability"]
    require(
        applicability == manifest["applicability"],
        "applicability matrix differs from manifest",
    )
    coordinates = [(entry["subject"], entry["metric"]) for entry in applicability]
    require(
        len(coordinates) == len(set(coordinates)),
        "applicability coordinate is duplicated",
    )
    require(
        set(coordinates) == set(EXPECTED_APPLICABILITY_IDS),
        "applicability matrix is not closed",
    )
    for entry in applicability:
        coordinate = (entry["subject"], entry["metric"])
        expected_ids = EXPECTED_APPLICABILITY_IDS[coordinate]
        if expected_ids is not None:
            exact_keys(
                entry,
                {"subject", "metric", "status", "measurement_ids"},
                "measured applicability entry",
            )
            require(
                entry["status"] == "measured", "measured applicability status differs"
            )
            require(
                entry["measurement_ids"] == list(expected_ids),
                "applicability measurement IDs differ",
            )
        else:
            exact_keys(
                entry, {"subject", "metric", "status", "reason"}, "not-applicable entry"
            )
            require(
                entry["status"] == "not-applicable", "not-applicable status differs"
            )
            require(
                isinstance(entry["reason"], str) and entry["reason"].strip(),
                "not-applicable reason is empty",
            )


def required_capture(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    require(match is not None, f"{label} is missing")
    return match.group(1)


def llvm_release(text: str, label: str) -> str:
    return required_capture(r"LLVM version:?\s+([0-9]+\.[0-9]+\.[0-9]+)", text, label)


def current_pinned_rustc_verbose(channel: str) -> str:
    result = subprocess.run(
        ["rustup", "run", channel, "rustc", "-vV"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(
        result.returncode == 0,
        f"failed to inspect pinned rustc ({result.returncode}): {result.stderr.strip()}",
    )
    return result.stdout.strip()


def verify_toolchain(document: dict[str, Any], *, check_current: bool) -> str:
    toolchain = document["toolchain"]
    exact_keys(
        toolchain,
        {
            "channel",
            "rustc_commit",
            "rustc_verbose",
            "cargo_version",
            "llvm_readobj_version",
            "rustc_sha256",
            "rustdoc_sha256",
            "cargo_sha256",
            "llvm_readobj_sha256",
        },
        "toolchain",
    )
    toolchain_file = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    channel = re.search(r'^channel = "([^"]+)"$', toolchain_file, re.MULTILINE)
    commit = re.search(
        r"^# rustc-commit: ([0-9a-f]{40})$", toolchain_file, re.MULTILINE
    )
    require(
        channel is not None and toolchain["channel"] == channel.group(1),
        "toolchain channel differs",
    )
    require(
        commit is not None and toolchain["rustc_commit"] == commit.group(1),
        "rustc commit differs",
    )
    require(
        HEX40.fullmatch(toolchain["rustc_commit"]) is not None,
        "rustc commit is malformed",
    )
    for field in ("rustc_verbose", "cargo_version", "llvm_readobj_version"):
        require(
            isinstance(toolchain[field], str) and toolchain[field].strip(),
            f"{field} is empty",
        )
    recorded_rustc_commit = required_capture(
        r"^commit-hash: ([0-9a-f]{40})$",
        toolchain["rustc_verbose"],
        "rustc verbose commit",
    )
    require(
        recorded_rustc_commit == toolchain["rustc_commit"],
        "rustc verbose commit differs",
    )
    rustc_header = re.search(
        r"^rustc (\S+) \(([0-9a-f]{9}) [^)]+\)$",
        toolchain["rustc_verbose"],
        re.MULTILINE,
    )
    require(rustc_header is not None, "rustc version header differs")
    rustc_release = required_capture(
        r"^release: (\S+)$", toolchain["rustc_verbose"], "rustc release"
    )
    rustc_host = required_capture(
        r"^host: (\S+)$", toolchain["rustc_verbose"], "rustc host"
    )
    rustc_llvm = llvm_release(toolchain["rustc_verbose"], "rustc LLVM release")
    require(rustc_header.group(1) == rustc_release, "rustc header release differs")
    require(
        recorded_rustc_commit.startswith(rustc_header.group(2)),
        "rustc header commit differs",
    )
    cargo_header = re.search(
        r"^cargo (\S+) \(([0-9a-f]{9}) [^)]+\)$",
        toolchain["cargo_version"],
        re.MULTILINE,
    )
    require(cargo_header is not None, "cargo version header differs")
    cargo_release = required_capture(
        r"^release: (\S+)$", toolchain["cargo_version"], "cargo release"
    )
    cargo_commit = required_capture(
        r"^commit-hash: ([0-9a-f]{40})$",
        toolchain["cargo_version"],
        "cargo commit",
    )
    cargo_host = required_capture(
        r"^host: (\S+)$", toolchain["cargo_version"], "cargo host"
    )
    require(cargo_header.group(1) == cargo_release, "cargo header release differs")
    require(
        cargo_commit.startswith(cargo_header.group(2)), "cargo header commit differs"
    )
    require(cargo_release == rustc_release, "cargo and rustc releases differ")
    require(cargo_host == rustc_host, "cargo and rustc hosts differ")
    require(
        llvm_release(toolchain["llvm_readobj_version"], "llvm-readobj release")
        == rustc_llvm,
        "llvm-readobj and rustc LLVM releases differ",
    )
    for field in (
        "rustc_sha256",
        "rustdoc_sha256",
        "cargo_sha256",
        "llvm_readobj_sha256",
    ):
        exact_sha256(toolchain[field], field)
    if check_current:
        current = current_pinned_rustc_verbose(toolchain["channel"])
        current_commit = required_capture(
            r"^commit-hash: ([0-9a-f]{40})$", current, "current rustc commit"
        )
        require(
            current_commit == toolchain["rustc_commit"],
            "current pinned rustc commit differs",
        )
        require(
            llvm_release(current, "current rustc LLVM release") == rustc_llvm,
            "current pinned LLVM release differs",
        )
    return rustc_host


def verify(
    document: dict[str, Any], manifest: dict[str, Any], *, check_toolchain: bool = False
) -> None:
    verify_manifest(manifest)
    exact_keys(document, TOP_LEVEL_KEYS, "baseline")
    require(document["schema"] == "vibeos.c07.baseline", "baseline schema differs")
    require(
        type(document["version"]) is int and document["version"] == 1,
        "baseline version differs",
    )
    require(document["epoch"] == manifest["epoch"], "baseline epoch differs")
    require(
        "explicit --update" in document["update_policy"],
        "baseline update policy is not explicit",
    )
    require(
        document["threshold_policy"].startswith("none;"),
        "C0 baseline invented a threshold",
    )
    manifest_hash = exact_sha256(
        document["workload_manifest_sha256"], "workload manifest hash"
    )
    require(manifest_hash == sha256_file(MANIFEST), "workload manifest hash differs")
    toolchain_host = verify_toolchain(document, check_current=check_toolchain)
    exact_keys(
        document["host"], {"triple", "system", "release", "machine", "python"}, "host"
    )
    require(
        all(isinstance(value, str) and value for value in document["host"].values()),
        "host identity is incomplete",
    )
    require(
        document["host"]["triple"] == toolchain_host,
        "host triple differs from recorded toolchain",
    )
    exact_typed_mapping(
        document["build_environment"], EXPECTED_BUILD_ENVIRONMENT, "build environment"
    )
    require(document["sampling"] == manifest["sampling"], "sampling contract differs")
    verify_source_inputs(document)
    verify_fixtures(document, manifest)
    verify_static(document, manifest)
    verify_host(document, manifest)
    verify_applicability(document, manifest)


def expect_failure(
    document: dict[str, Any], manifest: dict[str, Any], label: str
) -> None:
    try:
        verify(document, manifest)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation was accepted: {label}")


def selftest(document: dict[str, Any], manifest: dict[str, Any]) -> int:
    mutations: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    def host_record(value: dict[str, Any], subject: str, metric: str) -> dict[str, Any]:
        matches = [
            record
            for record in value["host_measurements"]
            if record.get("subject") == subject and record.get("metric") == metric
        ]
        require(
            len(matches) == 1, f"selftest host selector differs: {(subject, metric)}"
        )
        return matches[0]

    def static_record(value: dict[str, Any], subject: str) -> dict[str, Any]:
        matches = [
            record
            for record in value["static_target"]["measurements"]
            if record.get("subject") == subject
        ]
        require(len(matches) == 1, f"selftest static selector differs: {subject}")
        return matches[0]

    def applicability_entry(
        value: dict[str, Any], subject: str, metric: str
    ) -> dict[str, Any]:
        matches = [
            entry
            for entry in value["applicability"]
            if entry.get("subject") == subject and entry.get("metric") == metric
        ]
        require(
            len(matches) == 1,
            f"selftest applicability selector differs: {(subject, metric)}",
        )
        return matches[0]

    def fixture(value: dict[str, Any], identifier: str) -> dict[str, Any]:
        matches = [
            entry for entry in value["fixtures"] if entry.get("id") == identifier
        ]
        require(len(matches) == 1, f"selftest fixture selector differs: {identifier}")
        return matches[0]

    def source_input(value: dict[str, Any], path: str) -> dict[str, Any]:
        matches = [
            entry for entry in value["source_inputs"] if entry.get("path") == path
        ]
        require(len(matches) == 1, f"selftest source selector differs: {path}")
        return matches[0]

    def mutate_document(label: str, edit: Any) -> None:
        candidate = copy.deepcopy(document)
        edit(candidate)
        mutations.append((label, candidate, manifest))

    def mutate_manifest(label: str, edit: Any) -> None:
        candidate = copy.deepcopy(manifest)
        edit(candidate)
        mutations.append((label, document, candidate))

    def mutate_both(label: str, edit_document: Any, edit_manifest: Any) -> None:
        candidate_document = copy.deepcopy(document)
        candidate_manifest = copy.deepcopy(manifest)
        edit_document(candidate_document)
        edit_manifest(candidate_manifest)
        mutations.append((label, candidate_document, candidate_manifest))

    reordered = copy.deepcopy(document)
    reordered["host_measurements"].reverse()
    reordered["static_target"]["measurements"].reverse()
    verify(reordered, manifest)

    mutate_document("extra-top-level", lambda value: value.update(extra=True))
    mutate_document(
        "removed-schema-field", lambda value: value.update(schema_sha256="0" * 64)
    )
    mutate_document(
        "source-drift",
        lambda value: source_input(value, "Cargo.toml").update(sha256="0" * 64),
    )
    mutate_document("source-order", lambda value: value["source_inputs"].reverse())
    mutate_document(
        "fixture-drift",
        lambda value: fixture(value, "fuel-core-v1").update(source_sha256="0" * 64),
    )
    mutate_document(
        "missing-host-row",
        lambda value: value["host_measurements"].remove(
            host_record(value, "wasmi=1.1.0", "validator-accepted-peak")
        ),
    )
    mutate_document(
        "workload",
        lambda value: host_record(value, "wasmi=1.1.0", "cold-startup").update(
            workload="wrong-v1"
        ),
    )
    mutate_document(
        "heap-leak",
        lambda value: host_record(
            value, "wasmi=1.1.0", "validator-accepted-peak"
        ).update(
            after_bytes=host_record(value, "wasmi=1.1.0", "validator-accepted-peak")[
                "after_bytes"
            ]
            + 1
        ),
    )
    mutate_document(
        "timing-sample",
        lambda value: host_record(value, "wasmi=1.1.0", "cold-startup")[
            "samples_ns"
        ].__setitem__(0, 0),
    )
    mutate_document(
        "derived-stat",
        lambda value: host_record(value, "wasmi=1.1.0", "cold-startup")[
            "ns_per_operation_statistics"
        ].update(p50=1),
    )
    mutate_document(
        "fuel",
        lambda value: host_record(value, "wasmi=1.1.0", "core-fuel-throughput").update(
            fuel_per_operation=host_record(
                value, "wasmi=1.1.0", "core-fuel-throughput"
            )["fuel_per_operation"]
            + 1
        ),
    )
    mutate_document(
        "static-section",
        lambda value: static_record(value, "wasmi=1.1.0")["sections"][0].update(
            bytes=1
        ),
    )
    mutate_document(
        "artifact-path",
        lambda value: static_record(value, "wasmi=1.1.0").update(
            artifact="target/wrong-probe"
        ),
    )
    mutate_document(
        "heap-symbol",
        lambda value: static_record(value, "wasmi=1.1.0")["probe_heap_symbol"].update(
            bytes=1
        ),
    )
    mutate_both(
        "applicability-ids",
        lambda value: applicability_entry(
            value, "wasmi=1.1.0", "code-static-size"
        ).update(measurement_ids=["cold-startup"]),
        lambda value: applicability_entry(
            value, "wasmi=1.1.0", "code-static-size"
        ).update(measurement_ids=["cold-startup"]),
    )
    mutate_document(
        "toolchain-internal",
        lambda value: value["toolchain"].update(
            rustc_verbose=value["toolchain"]["rustc_verbose"].replace(
                value["toolchain"]["rustc_commit"],
                "0" * 40,
            )
        ),
    )
    mutate_document(
        "build-environment",
        lambda value: value["build_environment"].update(cargo_incremental=True),
    )
    mutate_manifest(
        "manifest-schema",
        lambda value: value.update(schema="vibeos.c07.workloads.invalid"),
    )
    mutate_manifest(
        "manifest-subject-probe",
        lambda value: value["subjects"][0].update(probe="wrong-probe"),
    )
    mutate_manifest(
        "manifest-sampling",
        lambda value: value["sampling"].update(canonical_text_bytes=255),
    )
    mutate_manifest(
        "manifest-statistics",
        lambda value: value["statistics"].update(p95="wrong"),
    )
    mutate_manifest(
        "manifest-fixture",
        lambda value: fixture(value, "fuel-core-v1").update(source="wrong.wat"),
    )

    for label, candidate_document, candidate_manifest in mutations:
        expect_failure(candidate_document, candidate_manifest, label)
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest", action="store_true", help="also reject representative mutations"
    )
    parser.add_argument(
        "--check-toolchain",
        action="store_true",
        help="compare the currently installed pinned rustc commit and LLVM release",
    )
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    document = json.loads(BASELINE.read_text(encoding="utf-8"))
    verify(document, manifest, check_toolchain=args.check_toolchain)
    mutations = selftest(document, manifest) if args.selftest else 0
    print(
        f"C0.7 baseline verified: {len(document['host_measurements'])} host measurements, {len(document['static_target']['measurements'])} target probes, {mutations} mutations"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, VerificationError) as error:
        print(f"C0.7 baseline verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
