#!/usr/bin/env python3
"""Collect the explicit, unthresholded C0.7 candidate baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import subprocess
import sys
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "wasm-candidates/evidence/workloads-v1.json"
BASELINE = ROOT / "wasm-candidates/evidence/baseline-v1.json"
STATIC_TARGET = "riscv64imac-unknown-none-elf"
STATIC_PROFILE = (
    "workspace release (opt-level=z,lto=true,debug=true); "
    "debug sections excluded by SHF_ALLOC classification"
)
PACKAGE = "vibeos-wasm-candidates"
CONTROL = "c0_static_control"
PROBES = {
    "wasmi=1.1.0": "c0_static_wasmi",
    "dlr-wasm-interpreter=0.2.0": "c0_static_dlr",
    "component-frontend=0.255.0": "c0_static_frontend",
}
STATIC_SOURCE_INPUTS = (
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
)
SOURCE_DIRECTORIES = (
    "wasm-candidates/src",
    "component-format/src",
    "component-runtime/src",
    "wasm-runtime/src",
)
OPTIONAL_SOURCE_INPUTS = (".cargo/config.toml", ".cargo/config")
BUILD_ENVIRONMENT = {
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
HOST_WORKLOADS = {
    ("wasmi=1.1.0", "validator-accepted-peak"): ("memory", "fuel-core-v1"),
    ("wasmi=1.1.0", "validator-rejected-peak"): ("memory", "malformed-core-v1"),
    ("wasmi=1.1.0", "empty-instance"): ("memory", "empty-core-v1"),
    ("wasmi=1.1.0", "cold-startup"): ("timing", "fuel-core-first-call-v1"),
    ("wasmi=1.1.0", "core-fuel-throughput"): ("fuel", "burn-32768-v1"),
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
    ("dlr-wasm-interpreter=0.2.0", "core-fuel-throughput"): ("fuel", "burn-32768-v1"),
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
        "canonical-256b-64u32-v1",
    ),
    ("component-frontend=0.255.0", "canonical-lift-lower"): (
        "timing",
        "canonical-256b-64u32-v1",
    ),
}


class CollectionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectionError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def source_input_paths() -> list[str]:
    paths = set(STATIC_SOURCE_INPUTS)
    for directory in SOURCE_DIRECTORIES:
        paths.update(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / directory).rglob("*.rs")
        )
    paths.update(
        relative for relative in OPTIONAL_SOURCE_INPUTS if (ROOT / relative).is_file()
    )
    return sorted(paths)


def run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: pathlib.Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise CollectionError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def toolchain_channel() -> str:
    text = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    match = re.search(r'^channel = "([^"]+)"$', text, re.MULTILINE)
    require(match is not None, "rust-toolchain.toml has no exact channel")
    return match.group(1)


def toolchain_commit() -> str:
    text = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    match = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", text, re.MULTILINE)
    require(match is not None, "rust-toolchain.toml has no exact rustc commit")
    return match.group(1)


def exact_tool(path: str, channel: str) -> pathlib.Path:
    result = run(["rustup", "which", "--toolchain", channel, path])
    resolved = pathlib.Path(result.stdout.strip()).resolve()
    require(resolved.is_file(), f"rustup did not resolve {path}")
    return resolved


def pinned_environment(
    channel: str, work_root: pathlib.Path
) -> tuple[dict[str, str], pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    rustc = exact_tool("rustc", channel)
    rustdoc = exact_tool("rustdoc", channel)
    cargo = exact_tool("cargo", channel)
    source_cargo_home = pathlib.Path(
        os.environ.get("CARGO_HOME", pathlib.Path.home() / ".cargo")
    ).expanduser()
    isolated_cargo_home = work_root / "cargo-home"
    isolated_cargo_home.mkdir()
    for cache in ("registry", "git"):
        source = source_cargo_home / cache
        if source.exists():
            (isolated_cargo_home / cache).symlink_to(
                source.resolve(), target_is_directory=True
            )
    environment = os.environ.copy()
    exact_build_variables = {
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
    }
    build_prefixes = ("CARGO_BUILD_", "CARGO_PROFILE_", "CARGO_TARGET_")
    for key in list(environment):
        if key in exact_build_variables or key.startswith(build_prefixes):
            environment.pop(key)
    environment.update(
        {
            "CARGO_HOME": str(isolated_cargo_home),
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(work_root / "target"),
            "LANG": "C",
            "LC_ALL": "C",
            "RUSTC": str(rustc),
            "RUSTDOC": str(rustdoc),
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        }
    )
    return environment, rustc, rustdoc, cargo, work_root / "target"


def cargo_command(cargo: pathlib.Path, action: str) -> list[str]:
    return [str(cargo), action, "--manifest-path", str(ROOT / "Cargo.toml")]


def build_static_probes(
    cargo: pathlib.Path, environment: dict[str, str], work_root: pathlib.Path
) -> None:
    command = cargo_command(cargo, "build") + [
        "--locked",
        "--offline",
        "--release",
        "--target",
        STATIC_TARGET,
        "-p",
        PACKAGE,
        "--features",
        "c0-static-probes",
    ]
    for binary in (CONTROL, *PROBES.values()):
        command.extend(["--bin", binary])
    run(command, env=environment, cwd=work_root)


def check_host_collector(
    cargo: pathlib.Path, environment: dict[str, str], work_root: pathlib.Path
) -> None:
    run(
        cargo_command(cargo, "check")
        + [
            "--locked",
            "--offline",
            "--release",
            "-p",
            PACKAGE,
            "--features",
            "c0-baseline",
            "--example",
            "c0_baseline",
        ],
        env=environment,
        cwd=work_root,
    )


def classify_elf(
    readobj: pathlib.Path, elf: pathlib.Path, probe_heap_bytes: int
) -> dict[str, Any]:
    payload = json.loads(
        run([str(readobj), "--elf-output-style=JSON", "--sections", str(elf)]).stdout
    )
    require(
        isinstance(payload, list) and len(payload) == 1,
        f"unexpected llvm-readobj output for {elf}",
    )
    sections: list[dict[str, Any]] = []
    totals = {
        "executable_bytes": 0,
        "read_only_bytes": 0,
        "writable_file_bytes": 0,
        "zero_fill_bytes": 0,
    }
    for wrapper in payload[0]["Sections"]:
        section = wrapper["Section"]
        flags = {entry["Name"] for entry in section["Flags"]["Flags"]}
        if "SHF_ALLOC" not in flags or section["Size"] == 0:
            continue
        kind = section["Type"]["Name"]
        if "SHF_EXECINSTR" in flags:
            category = "executable"
            total = "executable_bytes"
        elif "SHF_WRITE" in flags and kind == "SHT_NOBITS":
            category = "zero-fill"
            total = "zero_fill_bytes"
        elif "SHF_WRITE" in flags:
            category = "writable-file"
            total = "writable_file_bytes"
        else:
            category = "read-only"
            total = "read_only_bytes"
        size = int(section["Size"])
        totals[total] += size
        sections.append(
            {
                "index": int(section["Index"]),
                "name": section["Name"]["Name"],
                "type": kind,
                "flags": sorted(flags),
                "category": category,
                "bytes": size,
            }
        )
    symbols_payload = json.loads(
        run([str(readobj), "--elf-output-style=JSON", "--symbols", str(elf)]).stdout
    )
    require(
        isinstance(symbols_payload, list) and len(symbols_payload) == 1,
        f"unexpected llvm-readobj symbol output for {elf}",
    )
    heap_symbols = [
        wrapper["Symbol"]
        for wrapper in symbols_payload[0]["Symbols"]
        if wrapper["Symbol"]["Name"]["Name"] == "C0_PROBE_HEAP"
    ]
    require(
        len(heap_symbols) == 1, f"{elf.name} does not expose exactly one C0_PROBE_HEAP"
    )
    heap_symbol = heap_symbols[0]
    require(
        int(heap_symbol["Size"]) == probe_heap_bytes,
        f"{elf.name} probe heap size differs",
    )
    require(
        heap_symbol["Section"]["Name"] == ".bss",
        f"{elf.name} probe heap is not zero-fill",
    )
    require(
        totals["zero_fill_bytes"] >= probe_heap_bytes,
        f"{elf.name} lost the fixed probe heap",
    )
    code_static = (
        totals["executable_bytes"]
        + totals["read_only_bytes"]
        + totals["writable_file_bytes"]
    )
    static_ram = (
        totals["writable_file_bytes"] + totals["zero_fill_bytes"] - probe_heap_bytes
    )
    return {
        "artifact": f"target/{STATIC_TARGET}/release/{elf.name}",
        "probe_heap_symbol": {
            "name": "C0_PROBE_HEAP",
            "bytes": int(heap_symbol["Size"]),
            "section": heap_symbol["Section"]["Name"],
        },
        "sections": sections,
        **totals,
        "code_static_bytes": code_static,
        "static_ram_bytes_excluding_probe_heap": static_ram,
    }


def generated_fixture(target_root: pathlib.Path, name: str) -> bytes:
    matches = sorted(
        {
            *target_root.glob(f"**/build/vibeos-wasm-candidates/*/out/{name}"),
            *target_root.glob(f"**/build/vibeos-wasm-candidates-*/out/{name}"),
        }
    )
    require(matches, f"Cargo did not leave generated fixture {name}")
    payloads = {path.read_bytes() for path in matches}
    require(
        len(payloads) == 1, f"generated fixture {name} differs between build contexts"
    )
    return payloads.pop()


def verify_fixtures(
    manifest: dict[str, Any], target_root: pathlib.Path
) -> list[dict[str, Any]]:
    generated = {
        "empty-core-v1": generated_fixture(target_root, "c0_empty.wasm"),
        "fuel-core-v1": generated_fixture(target_root, "c0_fuel.wasm"),
        "typed-component-v1": generated_fixture(target_root, "c0_typed_component.wasm"),
    }
    fixtures = manifest["fixtures"]
    for fixture in fixtures:
        source = ROOT / fixture["source"]
        require(source.is_file(), f"fixture source is missing: {fixture['source']}")
        require(
            sha256_file(source) == fixture["source_sha256"],
            f"fixture source drifted: {fixture['id']}",
        )
        if fixture["id"] in generated:
            data = generated[fixture["id"]]
            require(
                sha256_bytes(data) == fixture["compiled_sha256"],
                f"compiled fixture drifted: {fixture['id']}",
            )
            require(
                len(data) == fixture["compiled_bytes"],
                f"compiled fixture length drifted: {fixture['id']}",
            )
    return fixtures


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def statistics(values: list[int]) -> dict[str, int]:
    require(
        values and all(value > 0 for value in values), "timing sample vector is invalid"
    )
    return {
        "min": min(values),
        "mean": sum(values) // len(values),
        "p50": nearest_rank(values, 0.50),
        "p95": nearest_rank(values, 0.95),
        "max": max(values),
    }


def parse_host_records(stdout: str, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    keys = [(record["subject"], record["metric"]) for record in records]
    require(
        len(keys) == len(set(keys)), "host collector emitted duplicate measurements"
    )
    require(set(keys) == set(HOST_WORKLOADS), "host collector measurement set differs")
    timing_samples = manifest["sampling"]["timing_samples"]
    for record in records:
        expected_kind, expected_workload = HOST_WORKLOADS[
            (record["subject"], record["metric"])
        ]
        kind = record["kind"]
        require(kind == expected_kind, "host collector measurement kind differs")
        require(
            record["workload"] == expected_workload, "host collector workload differs"
        )
        if kind == "memory":
            require(
                record["operations"] == 1, "memory observation operation count differs"
            )
            require(
                record["after_bytes"] == record["baseline_bytes"],
                "heap did not return to baseline",
            )
            require(
                record["peak_delta_bytes"] > 0,
                "memory observation has no positive peak",
            )
            if record["metric"] == "empty-instance":
                require(
                    record["retained_bytes"] > 0, "empty instance has no retained cost"
                )
            else:
                require(
                    record["retained_bytes"] == 0, "transient measurement retained heap"
                )
        elif kind in {"timing", "fuel"}:
            samples = record["samples_ns"]
            operations = record["operations_per_sample"]
            require(len(samples) == timing_samples, "timing sample count differs")
            require(
                len(record["results"]) == timing_samples, "result sample count differs"
            )
            record["ns_per_operation"] = [value // operations for value in samples]
            record["operations_per_second"] = [
                operations * 1_000_000_000 // value for value in samples
            ]
            record["ns_per_operation_statistics"] = statistics(
                record["ns_per_operation"]
            )
            record["operations_per_second_statistics"] = statistics(
                record["operations_per_second"]
            )
            if kind == "fuel":
                expected_fuel = record["fuel_per_operation"] * operations
                require(
                    record["fuel_samples"] == [expected_fuel] * timing_samples,
                    "fuel is not deterministic",
                )
                record["fuel_per_second"] = [
                    value * 1_000_000_000 // elapsed
                    for value, elapsed in zip(
                        record["fuel_samples"], samples, strict=True
                    )
                ]
                record["fuel_per_second_statistics"] = statistics(
                    record["fuel_per_second"]
                )
        else:
            raise CollectionError(f"unknown host measurement kind: {kind}")
    return records


def resolve_readobj(rustc: pathlib.Path) -> tuple[str, str, str, pathlib.Path]:
    rustc_vv = run([str(rustc), "-vV"]).stdout.strip()
    host_match = re.search(r"^host: (.+)$", rustc_vv, re.MULTILINE)
    commit_match = re.search(r"^commit-hash: ([0-9a-f]{40})$", rustc_vv, re.MULTILINE)
    require(
        host_match is not None and commit_match is not None,
        "rustc verbose identity is incomplete",
    )
    host_triple = host_match.group(1)
    commit = commit_match.group(1)
    require(
        commit == toolchain_commit(),
        "installed rustc commit differs from rust-toolchain.toml",
    )
    sysroot = pathlib.Path(run([str(rustc), "--print", "sysroot"]).stdout.strip())
    readobj = sysroot / "lib/rustlib" / host_triple / "bin/llvm-readobj"
    require(readobj.is_file(), "pinned llvm-readobj is missing")
    return rustc_vv, host_triple, commit, readobj


def collect() -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(
        manifest["schema"] == "vibeos.c07.workloads" and manifest["version"] == 1,
        "workload manifest identity differs",
    )
    channel = toolchain_channel()
    with tempfile.TemporaryDirectory(prefix="vibeos-c07-") as temporary:
        work_root = pathlib.Path(temporary)
        environment, rustc, rustdoc, cargo, target_root = pinned_environment(
            channel, work_root
        )
        build_static_probes(cargo, environment, work_root)
        rustc_vv, host_triple, commit, readobj = resolve_readobj(rustc)

        probe_heap = manifest["probe_heap_bytes"]
        static_root = target_root / STATIC_TARGET / "release"
        control = classify_elf(readobj, static_root / CONTROL, probe_heap)
        static_measurements: list[dict[str, Any]] = []
        for subject, probe in PROBES.items():
            measurement = classify_elf(readobj, static_root / probe, probe_heap)
            require(
                measurement["code_static_bytes"] > control["code_static_bytes"],
                f"{subject} probe did not retain candidate code",
            )
            measurement.update(
                {
                    "subject": subject,
                    "measurement": "riscv64-linked-probe",
                    "incremental_code_static_bytes_over_control": measurement[
                        "code_static_bytes"
                    ]
                    - control["code_static_bytes"],
                }
            )
            static_measurements.append(measurement)

        host_run = run(
            cargo_command(cargo, "run")
            + [
                "--locked",
                "--offline",
                "--release",
                "-p",
                PACKAGE,
                "--features",
                "c0-baseline",
                "--example",
                "c0_baseline",
            ],
            env=environment,
            cwd=work_root,
        )
        host_measurements = parse_host_records(host_run.stdout, manifest)
        fixtures = verify_fixtures(manifest, target_root)

        source_inputs = []
        for relative in source_input_paths():
            path = ROOT / relative
            require(path.is_file(), f"source input is missing: {relative}")
            source_inputs.append({"path": relative, "sha256": sha256_file(path)})

        return {
            "schema": "vibeos.c07.baseline",
            "version": 1,
            "epoch": manifest["epoch"],
            "update_policy": "explicit --update only; ordinary tests and verification never rewrite this file",
            "threshold_policy": "none; this records measurements before any budget is selected",
            "build_environment": BUILD_ENVIRONMENT,
            "toolchain": {
                "channel": channel,
                "rustc_commit": commit,
                "rustc_verbose": rustc_vv,
                "cargo_version": run(
                    [str(cargo), "-Vv"], env=environment, cwd=work_root
                ).stdout.strip(),
                "llvm_readobj_version": run([str(readobj), "--version"]).stdout.strip(),
                "rustc_sha256": sha256_file(rustc),
                "rustdoc_sha256": sha256_file(rustdoc),
                "cargo_sha256": sha256_file(cargo),
                "llvm_readobj_sha256": sha256_file(readobj),
            },
            "host": {
                "triple": host_triple,
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "static_target": {
                "triple": STATIC_TARGET,
                "profile": STATIC_PROFILE,
                "probe_heap_bytes": probe_heap,
                "control": control,
                "measurements": static_measurements,
            },
            "fixtures": fixtures,
            "applicability": manifest["applicability"],
            "sampling": manifest["sampling"],
            "host_measurements": host_measurements,
            "source_inputs": source_inputs,
            "workload_manifest_sha256": sha256_file(MANIFEST),
        }


def check_build() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    channel = toolchain_channel()
    with tempfile.TemporaryDirectory(prefix="vibeos-c07-check-") as temporary:
        work_root = pathlib.Path(temporary)
        environment, rustc, _rustdoc, cargo, target_root = pinned_environment(
            channel, work_root
        )
        build_static_probes(cargo, environment, work_root)
        check_host_collector(cargo, environment, work_root)
        _rustc_vv, _host_triple, _commit, readobj = resolve_readobj(rustc)
        probe_heap = manifest["probe_heap_bytes"]
        static_root = target_root / STATIC_TARGET / "release"
        control = classify_elf(readobj, static_root / CONTROL, probe_heap)
        measurements: list[dict[str, Any]] = []
        for subject, probe in PROBES.items():
            measurement = classify_elf(readobj, static_root / probe, probe_heap)
            require(
                measurement["code_static_bytes"] > control["code_static_bytes"],
                f"{subject} probe did not retain candidate code",
            )
            measurement.update(
                {
                    "subject": subject,
                    "measurement": "riscv64-linked-probe",
                    "incremental_code_static_bytes_over_control": measurement[
                        "code_static_bytes"
                    ]
                    - control["code_static_bytes"],
                }
            )
            measurements.append(measurement)
        rebuilt_static = {
            "triple": STATIC_TARGET,
            "profile": STATIC_PROFILE,
            "probe_heap_bytes": probe_heap,
            "control": control,
            "measurements": measurements,
        }
        require(
            rebuilt_static == baseline["static_target"],
            "fresh RISC-V allocated-section measurements differ from baseline",
        )
        verify_fixtures(manifest, target_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--update",
        action="store_true",
        help="explicitly replace wasm-candidates/evidence/baseline-v1.json",
    )
    mode.add_argument(
        "--check-build",
        action="store_true",
        help="compile the host collector and RISC-V probes and verify generated fixtures",
    )
    args = parser.parse_args()
    if args.check_build:
        check_build()
        print(
            "C0.7 build contract verified: host collector, 4 target probes, 3 generated fixtures"
        )
        return 0
    evidence = collect()
    encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.update:
        BASELINE.write_text(encoded, encoding="utf-8")
        print(f"updated {BASELINE.relative_to(ROOT)}", file=sys.stderr)
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CollectionError as error:
        print(f"C0.7 collection failed: {error}", file=sys.stderr)
        raise SystemExit(1)
