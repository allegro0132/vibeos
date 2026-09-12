#!/usr/bin/env python3
"""Guest-path storage benchmark runner, validator, and baseline gate.

The runner deliberately treats the guest line as untrusted input. It adds the
experiment coordinates outside the timed region, validates every record, and
never substitutes zero for an unsupported or failed measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import selectors
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

PREFIX = "VIBE_STORAGE_BENCH "
RECORD_SCHEMA = "vibeos.storage-bench.record"
RECORD_VERSION = 1
STATUSES = {"ok", "unsupported", "failed-closed", "inconclusive"}
BACKENDS = {"m4", "storage-v2", "linux-ext4"}
LAYERS = {"block", "object", "file-tree"}
TIMED_METRICS = {
    "put_latency_ns",
    "get_latency_ns",
    "latency_ns",
    "throughput_bytes_per_second",
    "throughput_objects_per_second",
}


class ValidationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def nonnegative_map(record: dict[str, Any], key: str, integer: bool) -> None:
    value = record.get(key)
    require(isinstance(value, dict), f"{key} must be an object")
    for name, item in value.items():
        require(isinstance(name, str) and name, f"{key} has an invalid name")
        valid_type = isinstance(item, int) if integer else isinstance(item, (int, float))
        require(valid_type and not isinstance(item, bool), f"{key}.{name} has an invalid type")
        require(math.isfinite(float(item)) and item >= 0, f"{key}.{name} must be finite and non-negative")


def validate_record(record: dict[str, Any]) -> None:
    required = {
        "schema", "version", "run_id", "backend", "layer", "workload", "status",
        "vm_index", "sample_index", "warmup", "seed", "queue_depth", "metrics",
        "counters", "phases", "environment",
    }
    missing = required - record.keys()
    require(not missing, f"missing fields: {', '.join(sorted(missing))}")
    require(record["schema"] == RECORD_SCHEMA, "unknown record schema")
    require(record["version"] == RECORD_VERSION, "unknown record version")
    require(isinstance(record["run_id"], str) and record["run_id"], "run_id is empty")
    require(record["backend"] in BACKENDS, "unknown backend")
    require(record["layer"] in LAYERS, "unknown layer")
    require(isinstance(record["workload"], str) and record["workload"], "workload is empty")
    require(record["status"] in STATUSES, "invalid status")
    for key in ("vm_index", "sample_index", "seed"):
        require(isinstance(record[key], int) and not isinstance(record[key], bool) and record[key] >= 0,
                f"{key} must be a non-negative integer")
    require(type(record["warmup"]) is bool, "warmup must be boolean")
    require(isinstance(record["queue_depth"], int) and record["queue_depth"] >= 1,
            "queue_depth must be positive")
    for key in ("object_bytes", "object_count"):
        if key in record:
            require(isinstance(record[key], int) and record[key] >= 0, f"{key} must be non-negative")
    nonnegative_map(record, "metrics", integer=False)
    nonnegative_map(record, "counters", integer=True)
    nonnegative_map(record, "phases", integer=True)
    environment = record["environment"]
    require(isinstance(environment, dict), "environment must be an object")
    for key in ("git_commit", "qemu_version", "qemu_args", "cache_state"):
        require(key in environment, f"environment.{key} is missing")
    require(isinstance(environment["qemu_args"], list), "environment.qemu_args must be an array")
    if "memory_mib" in environment:
        require(type(environment["memory_mib"]) is int and environment["memory_mib"] > 0,
                "invalid guest memory size")
    if "storage_v2_provisioned_segments" in environment:
        value = environment["storage_v2_provisioned_segments"]
        require(type(value) is int and value > 0, "invalid storage geometry")
    if "storage_throttle" in environment:
        profile = environment["storage_throttle"]
        require(isinstance(profile, dict) and set(profile) <= set(THROTTLE_FIELDS),
                "invalid storage throttle profile")
        require(all(type(value) is int and value >= 0 for value in profile.values()),
                "invalid storage throttle rate")
    if "latency_scope" in environment:
        require(environment["latency_scope"] == "workload", "invalid latency scope")
    if "content_pattern" in environment:
        require(environment["content_pattern"] in ("legacy", "splitmix64-offset-v1"),
                "invalid content pattern")
    if record["status"] == "ok":
        require(any(name in record["metrics"] for name in TIMED_METRICS),
                "ok record has no timed metric")
        require(all(value > 0 for value in record["metrics"].values()),
                "ok metrics must be positive; zero is not an unsupported sentinel")
    else:
        require(not (set(record["metrics"]) & TIMED_METRICS),
                "non-ok record must not publish timed metrics")
        require(isinstance(record.get("reason"), str) and record["reason"],
                "non-ok record requires a reason")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                require(isinstance(record, dict), "record must be an object")
                validate_record(record)
            except (json.JSONDecodeError, ValidationError) as error:
                raise ValidationError(f"{path}:{line_number}: {error}") from error
            coordinate = (
                record["run_id"], record["backend"], record["workload"],
                record.get("object_bytes"), record.get("object_count"),
                record["queue_depth"], record["vm_index"], record["sample_index"],
                record["warmup"],
            )
            require(coordinate not in seen, f"{path}:{line_number}: duplicate coordinate")
            seen.add(coordinate)
            records.append(record)
    require(bool(records), f"{path}: no records")
    return records


def read_jsonls(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    coordinates: set[tuple[Any, ...]] = set()
    for path in paths:
        for record in read_jsonl(path):
            coordinate = (
                record["run_id"], record["backend"], record["workload"],
                record.get("object_bytes"), record.get("object_count"),
                record["queue_depth"], record["vm_index"], record["sample_index"],
                record["warmup"],
            )
            require(coordinate not in coordinates,
                    f"duplicate coordinate across input files: {coordinate}")
            coordinates.add(coordinate)
            records.append(record)
    return records


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


THROTTLE_FIELDS = {"read_bps": "bps_rd", "write_bps": "bps_wr",
                   "read_iops": "iops_rd", "write_iops": "iops_wr"}


def storage_throttle(args: argparse.Namespace) -> dict[str, int]:
    profile = {name: getattr(args, name, 0) for name in THROTTLE_FIELDS}
    require(all(type(value) is int and value >= 0 for value in profile.values()),
            "storage bandwidth/IOPS limits must be non-negative integers")
    return profile


def throttle_drive_options(args: argparse.Namespace) -> str:
    return "".join(f",{THROTTLE_FIELDS[name]}={value}"
                   for name, value in storage_throttle(args).items() if value)


def environment(qemu_args: list[str], qemu_version: str) -> dict[str, Any]:
    def command(*args: str) -> str:
        result = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        return result.stdout.strip().splitlines()[0]
    status = subprocess.run(["git", "status", "--short"], check=True, text=True,
                            stdout=subprocess.PIPE).stdout
    diff = subprocess.run(["git", "diff", "--binary", "HEAD"], check=True,
                          stdout=subprocess.PIPE).stdout
    return {
        "git_commit": command("git", "rev-parse", "HEAD"),
        "git_dirty": bool(status),
        "git_status": status.splitlines(),
        "git_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "rust_version": command("rustc", "--version"),
        "qemu_version": qemu_version,
        "host_cpu": platform.processor() or platform.machine(),
        "host_os": platform.platform(),
        "qemu_args": qemu_args,
        "cache_state": "unknown",
    }


def convert_guest_sample(sample: dict[str, Any], *, run_id: str, vm_index: int,
                         sample_index: int, warmup: bool, seed: int,
                         env: dict[str, Any]) -> dict[str, Any]:
    require(sample.get("schema") == "vibeos.storage-bench.sample", "bad guest schema")
    require(sample.get("version") == 1, "bad guest schema version")
    require(sample.get("status") in STATUSES, "bad guest status")
    require(sample.get("backend") in BACKENDS, "bad guest backend")
    require(sample.get("seed", seed) == seed, "guest seed mismatch")
    hz = sample.get("timebase_hz")
    if sample["status"] == "ok":
        require(isinstance(hz, int) and hz > 0, "bad guest timebase")
    metrics: dict[str, float] = {}
    counters: dict[str, int] = {}
    phases: dict[str, int] = {}
    if sample["status"] == "ok":
        if "latency_ticks" in sample:
            ticks = sample["latency_ticks"]
            require(isinstance(ticks, int) and ticks > 0, "missing latency_ticks")
            metrics["latency_ns"] = ticks * 1_000_000_000 / hz
            phases["latency_total_ns"] = round(metrics["latency_ns"])
        for source, target in (("put_ticks", "put_latency_ns"), ("get_ticks", "get_latency_ns")):
            if source in sample:
                ticks = sample[source]
                require(isinstance(ticks, int) and ticks > 0, f"missing {source}")
                metrics[target] = ticks * 1_000_000_000 / hz
                phases[target.removesuffix("_latency_ns") + "_total_ns"] = round(metrics[target])
        if "elapsed_ticks" in sample:
            elapsed = sample["elapsed_ticks"]
            transferred = sample.get("transferred_bytes")
            require(isinstance(elapsed, int) and elapsed > 0, "bad elapsed_ticks")
            require(isinstance(transferred, int) and transferred >= 0, "bad transferred_bytes")
            if transferred > 0:
                metrics["throughput_bytes_per_second"] = transferred * hz / elapsed
            phases["elapsed_ticks"] = elapsed
            phases["transferred_bytes"] = transferred
        for name in ("operations", "transferred_bytes", "elapsed_ticks"):
            if name in sample and name not in phases:
                value = sample[name]
                require(isinstance(value, int) and value >= 0, f"bad {name}")
                phases[name] = value
        for name in ("block_requests", "block_read_requests", "block_write_requests",
                     "block_flush_requests", "block_read_bytes", "block_write_bytes",
                     "block_used_interrupts"):
            value = sample.get(name)
            if value is not None:
                require(isinstance(value, int) and value >= 0, f"bad {name}")
                counters[name.removeprefix("block_")] = value
        file_phase_names = ("stage", "publish", "verify", "remove")
        if any(name.startswith(tuple(f"file_{phase}_" for phase in file_phase_names))
               for name in sample):
            require(sample.get("workload") == "file-sequential", "file phases on another workload")
            for metric in ("requests", "read_requests", "write_requests", "flush_requests",
                           "read_bytes", "write_bytes", "used_interrupts"):
                total = 0
                for phase in file_phase_names:
                    name = f"file_{phase}_{metric}"
                    value = sample.get(name)
                    require(type(value) is int and value >= 0, f"bad or missing {name}")
                    phases[name] = value
                    total += value
                require(total == counters.get(metric), f"file phase sum differs for {metric}")
        time_names = [f"file_{phase}_elapsed_ticks" for phase in file_phase_names]
        if any(name in sample for name in time_names):
            require(sample.get("workload") == "file-sequential", "file times on another workload")
            for name in time_names:
                value = sample.get(name)
                require(type(value) is int and value >= 0, f"bad or missing {name}")
                phases[name] = value
            require(type(sample.get("elapsed_ticks")) is int, "missing elapsed_ticks for file times")
            require(sum(phases[name] for name in time_names) == sample["elapsed_ticks"],
                    "file time sum differs from elapsed_ticks")
        stage_names = [f"file_stage_{part}_ticks" for part in ("pattern", "push", "finish", "other")]
        if any(name in sample for name in stage_names):
            require("file_stage_elapsed_ticks" in phases, "missing file phase times for staging details")
            for name in stage_names:
                value = sample.get(name)
                require(type(value) is int and value >= 0, f"bad or missing {name}")
                phases[name] = value
            require(sum(phases[name] for name in stage_names) == phases["file_stage_elapsed_ticks"],
                    "staging detail sum differs from stage elapsed_ticks")
        verify_names = [f"file_verify_{part}_ticks" for part in ("reader", "pattern", "other")]
        if any(name in sample for name in verify_names):
            require("file_verify_elapsed_ticks" in phases, "missing file phase times for verification details")
            for name in verify_names:
                value = sample.get(name)
                require(type(value) is int and value >= 0, f"bad or missing {name}")
                phases[name] = value
            require(sum(phases[name] for name in verify_names) == phases["file_verify_elapsed_ticks"],
                    "verification detail sum differs from verify elapsed_ticks")
        if "put_block_requests" in sample:
            for name in ("put_block_requests", "put_block_read_requests",
                         "put_block_write_requests", "put_block_flush_requests",
                         "put_block_read_bytes", "put_block_write_bytes",
                         "put_block_used_interrupts"):
                value = sample.get(name)
                require(isinstance(value, int) and value >= 0, f"missing {name}")
                phases["put_" + name.removeprefix("put_block_")] = value
                total_name = name.removeprefix("put_")
                if total_name in sample:
                    total = sample[total_name]
                    require(isinstance(total, int) and total >= value,
                            f"{total_name} is smaller than its put phase")
                    phases["get_" + name.removeprefix("put_block_")] = total - value
        for name in ("authority_objects", "authority_records", "cas_payloads_verified",
                     "allocated_segments", "free_segments", "cleaner_reserved_segments"):
            if name in sample:
                value = sample[name]
                require(isinstance(value, int) and value >= 0, f"bad {name}")
                phases[name] = value
    result: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "version": RECORD_VERSION,
        "run_id": run_id,
        "backend": sample["backend"],
        "layer": sample["layer"],
        "workload": sample["workload"],
        "status": sample["status"],
        "vm_index": vm_index,
        "sample_index": sample_index,
        "warmup": warmup,
        "seed": seed,
        "queue_depth": sample.get("queue_depth", 1),
        "object_bytes": sample.get("object_bytes", 0),
        "metrics": metrics,
        "counters": counters,
        "phases": phases,
        "environment": env,
    }
    if sample["status"] != "ok":
        result["reason"] = sample.get("reason", "guest reported " + sample["status"])
    if "object_count" in sample:
        result["object_count"] = sample["object_count"]
    if "content_class" in sample:
        result["content_class"] = sample["content_class"]
    for name in ("content_pattern", "latency_scope"):
        if name in sample:
            result["environment"] = {**result["environment"], name: sample[name]}
    validate_record(result)
    return result


def convert_linux_sample(sample: dict[str, Any], *, run_id: str, vm_index: int,
                         env: dict[str, Any]) -> dict[str, Any]:
    require(sample.get("schema") == "vibeos.storage-bench.sample", "bad Linux guest schema")
    require(sample.get("version") == 1 and sample.get("backend") == "linux-ext4",
            "bad Linux guest identity")
    status = sample.get("status")
    require(status in STATUSES, "bad Linux guest status")
    metrics: dict[str, float] = {}
    counters: dict[str, int] = {}
    phases: dict[str, int] = {}
    if status == "ok":
        if "latency_ns" in sample:
            value = sample["latency_ns"]
            require(isinstance(value, int) and value > 0, "missing latency_ns")
            metrics["latency_ns"] = float(value)
            phases["latency_total_ns"] = value
        if "latency_ns" not in sample or "put_ns" in sample or "get_ns" in sample:
            for source, target in (("put_ns", "put_latency_ns"), ("get_ns", "get_latency_ns")):
                value = sample.get(source)
                require(isinstance(value, int) and value > 0, f"missing {source}")
                metrics[target] = float(value)
                phases[target.removesuffix("_latency_ns") + "_total_ns"] = value
        if "elapsed_ns" in sample:
            elapsed = sample["elapsed_ns"]
            transferred = sample.get("transferred_bytes")
            require(isinstance(elapsed, int) and elapsed > 0, "bad elapsed_ns")
            require(isinstance(transferred, int) and transferred >= 0, "bad transferred_bytes")
            if transferred > 0:
                metrics["throughput_bytes_per_second"] = transferred * 1_000_000_000 / elapsed
            phases["elapsed_ns"] = elapsed
            phases["transferred_bytes"] = transferred
        for name in ("operations", "transferred_bytes", "elapsed_ns"):
            if name in sample and name not in phases:
                value = sample[name]
                require(isinstance(value, int) and value >= 0, f"bad {name}")
                phases[name] = value
        for name in ("block_requests", "block_read_requests", "block_write_requests",
                     "block_flush_requests", "block_read_bytes", "block_write_bytes"):
            value = sample.get(name)
            if value is not None:
                require(isinstance(value, int) and value >= 0, f"bad {name}")
                counters[name.removeprefix("block_")] = value
    result: dict[str, Any] = {
        "schema": RECORD_SCHEMA, "version": RECORD_VERSION, "run_id": run_id,
        "backend": "linux-ext4", "layer": sample["layer"],
        "workload": sample["workload"], "status": status, "vm_index": vm_index,
        "sample_index": sample["sample_index"], "warmup": sample["warmup"],
        "seed": sample["seed"], "queue_depth": sample.get("queue_depth", 1),
        "object_bytes": sample.get("object_bytes", 0), "metrics": metrics,
        "counters": counters, "phases": phases, "environment": env,
    }
    if status != "ok":
        result["reason"] = sample.get("reason", "Linux guest reported " + status)
    if "object_count" in sample:
        result["object_count"] = sample["object_count"]
    if "content_class" in sample:
        result["content_class"] = sample["content_class"]
    for name in ("content_pattern", "latency_scope"):
        if name in sample:
            result["environment"] = {**result["environment"], name: sample[name]}
    validate_record(result)
    return result


def wait_for(stream: Any, process: subprocess.Popen[bytes], marker: bytes,
             timeout: float, transcript: Any = None) -> bytes:
    selector = selectors.DefaultSelector()
    selector.register(stream, selectors.EVENT_READ)
    collected = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while marker not in collected:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                tail = bytes(collected[-4096:]).decode("utf-8", errors="replace").replace("\r", "\n")
                raise TimeoutError(f"timed out waiting for {marker!r}; serial tail:\n{tail}")
            events = selector.select(min(remaining, 1.0))
            if not events:
                if process.poll() is not None:
                    raise RuntimeError(f"guest exited with {process.returncode}")
                continue
            chunk = os.read(stream.fileno(), 65536)
            if not chunk:
                raise RuntimeError("guest serial closed")
            if transcript is not None:
                transcript.write(chunk)
                transcript.flush()
            collected.extend(chunk)
        return bytes(collected)
    finally:
        selector.close()


def guest_record_from(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace").replace("\r", "\n")
    candidates = [line.split(PREFIX, 1)[1] for line in text.splitlines() if PREFIX in line]
    require(len(candidates) == 1, f"expected one guest record, found {len(candidates)}")
    value = json.loads(candidates[0])
    require(isinstance(value, dict), "guest record must be an object")
    return value


def guest_storage_geometry(boot: bytes) -> dict[str, int]:
    prefix = b"VIBE_STORAGE_BENCH_GEOMETRY "
    lines = [line.split(prefix, 1)[1] for line in boot.splitlines() if prefix in line]
    require(len(lines) <= 1, "multiple guest storage geometry records")
    if not lines:
        return {} # Older benchmark ELFs do not report their provisioned geometry.
    value = json.loads(lines[0])
    require(isinstance(value, dict), "invalid guest storage geometry")
    segments = value.get("provisioned_segments")
    require(type(segments) is int and segments > 0, "invalid guest storage geometry")
    return {"storage_v2_provisioned_segments": segments}


def run_vibeos(args: argparse.Namespace) -> int:
    require(args.memory_mib > 0, "memory-mib must be positive")
    throttle_options = throttle_drive_options(args)
    kernel = args.kernel.resolve()
    require(kernel.is_file(), f"kernel not found: {kernel}")
    qemu_version = subprocess.run([args.qemu, "--version"], check=True, text=True,
                                  stdout=subprocess.PIPE).stdout.splitlines()[0]
    artifact_hashes = {"kernel_sha256": file_sha256(kernel),
                       "data_image_template_sha256": file_sha256(args.data_image)}
    run_id = args.run_id or str(uuid.uuid4())
    total = args.warmups + args.samples
    output = args.output.open("x" if not args.overwrite else "w", encoding="utf-8")
    transcript = None
    failed = False
    try:
        if args.serial_log is not None:
            transcript = args.serial_log.open("wb" if args.overwrite else "xb")
        for vm_index in range(args.vms):
            with tempfile.TemporaryDirectory(prefix="vibeos-storage-bench-") as temporary:
                disk = Path(temporary) / "data.raw"
                shutil.copyfile(args.data_image, disk)
                with disk.open("r+b") as target:
                    target.truncate(1024 * 1024 * 1024)
                qemu_args = [
                    args.qemu, "-machine", "virt", "-cpu", "rv64", "-smp", "1", "-m", f"{args.memory_mib}M",
                    "-accel", "tcg,thread=single", "-nographic", "-bios", "default",
                    "-kernel", str(kernel), "-drive",
                    f"if=none,id=bench-disk,format=raw,file={disk},cache=none,aio=threads{throttle_options}",
                    "-device", "virtio-blk-device,drive=bench-disk,bus=virtio-mmio-bus.0,queue-size=128",
                    "-global", "virtio-mmio.force-legacy=false",
                ]
                env = environment(qemu_args, qemu_version)
                env["storage_throttle"] = storage_throttle(args)
                env["memory_mib"] = args.memory_mib
                env.update(artifact_hashes)
                process = subprocess.Popen(qemu_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT)
                try:
                    assert process.stdin is not None and process.stdout is not None
                    boot = wait_for(process.stdout, process, b"VibeOS shell ready", args.boot_timeout, transcript)
                    env.update(guest_storage_geometry(boot))
                    # The shell-ready banner is emitted before the async
                    # virtio task has necessarily published its online
                    # session. Keep this bootstrap wait outside the timed
                    # operation and probe the block command once.
                    time.sleep(1.0)
                    process.stdin.write(b"blk info\n")
                    process.stdin.flush()
                    wait_for(process.stdout, process, b"vibe> ", args.sample_timeout, transcript)
                    process.stdin.write(b"quiet\n")
                    process.stdin.flush()
                    # Wait for the shell to finish the quiet command before
                    # submitting the timed workload. Sending both lines in
                    # one UART burst can otherwise race the legacy parser and
                    # produce a valid but failed-closed guest record.
                    wait_for(process.stdout, process, b"vibe> ", args.sample_timeout, transcript)
                    for index in range(total):
                        seed = (args.seed + vm_index * total + index) & ((1 << 64) - 1)
                        if args.workload.startswith("block-"):
                            command = f"blk bench {args.workload} {seed} {args.queue_depth}\n".encode()
                        else:
                            extra = ""
                            if args.workload.startswith("file-"):
                                extra = f" {args.workload} {args.object_count}"
                            else:
                                extra = f" {args.workload}"
                                if getattr(args, "content_class", None):
                                    extra += f" {args.content_class}"
                            command = f"storage bench {args.object_bytes} {seed}{extra}\n".encode()
                        process.stdin.write(command)
                        process.stdin.flush()
                        data = wait_for(process.stdout, process, PREFIX.encode(), args.sample_timeout, transcript)
                        prefix_at = data.rfind(PREFIX.encode())
                        if b"\n" not in data[prefix_at:]:
                            data += wait_for(process.stdout, process, b"\n", args.sample_timeout, transcript)
                        sample = guest_record_from(data)
                        require(sample.get("backend") == args.backend,
                                f"expected {args.backend}, guest selected {sample.get('backend')}")
                        record = convert_guest_sample(
                            sample, run_id=run_id, vm_index=vm_index,
                            sample_index=index if index < args.warmups else index - args.warmups,
                            warmup=index < args.warmups, seed=seed, env=env,
                        )
                        output.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                        output.flush()
                        if args.stop_on_failure and record["status"] != "ok":
                            failed = True
                            break
                    process.stdin.write(b"halt\n")
                    process.stdin.flush()
                finally:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=5)
                if args.retain_images is not None:
                    args.retain_images.mkdir(parents=True, exist_ok=True)
                    retained = args.retain_images / f"vm-{vm_index:03d}.raw"
                    # Only copy after QEMU has stopped. Never replace a prior
                    # fixture, even when overwriting benchmark result logs.
                    with retained.open("xb") as destination, disk.open("rb") as source:
                        shutil.copyfileobj(source, destination)
                if failed:
                    return 1
    finally:
        if transcript is not None:
            transcript.close()
        output.close()
    return 0


def run_linux(args: argparse.Namespace) -> int:
    require(args.memory_mib > 0, "memory-mib must be positive")
    throttle_options = throttle_drive_options(args)
    for path in (args.root_image, args.firmware_code, args.firmware_vars,
                 args.agent, args.data_image):
        require(path.is_file(), f"guest artifact not found: {path}")
    qemu_version = subprocess.run([args.qemu, "--version"], check=True, text=True,
                                  stdout=subprocess.PIPE).stdout.splitlines()[0]
    artifact_hashes = {
        "debian_root_sha256": file_sha256(args.root_image),
        "firmware_code_sha256": file_sha256(args.firmware_code),
        "firmware_vars_sha256": file_sha256(args.firmware_vars),
        "agent_sha256": file_sha256(args.agent),
        "data_image_template_sha256": file_sha256(args.data_image),
    }
    run_id = args.run_id or str(uuid.uuid4())
    mode = "x" if not args.overwrite else "w"
    with args.output.open(mode, encoding="utf-8") as output:
        for vm_index in range(args.vms):
            with tempfile.TemporaryDirectory(prefix="linux-storage-bench-") as temporary:
                root = Path(temporary) / "root.qcow2"
                variables = Path(temporary) / "vars.fd"
                disk = Path(temporary) / "data.raw"
                shutil.copyfile(args.root_image, root)
                shutil.copyfile(args.firmware_vars, variables)
                shutil.copyfile(args.data_image, disk)
                require(disk.stat().st_size == 1024 * 1024 * 1024,
                        "Linux ext4 template must be exactly 1 GiB")
                seed = (args.seed + vm_index * (args.warmups + args.samples)) & ((1 << 64) - 1)
                qemu_args = [
                    args.qemu, "-machine", "virt", "-cpu", "rv64", "-smp", "1", "-m", f"{args.memory_mib}M",
                    "-accel", "tcg,thread=single", "-nographic", "-drive",
                    f"if=pflash,format=raw,unit=0,readonly=on,file={args.firmware_code.resolve()}",
                    "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
                    "-drive", f"if=none,id=root,format=qcow2,file={root},cache=none,aio=threads",
                    "-device", "virtio-blk-device,drive=root,queue-size=128,serial=debian-root",
                    "-drive", f"if=none,id=bench-disk,format=raw,file={disk},cache=none,aio=threads{throttle_options}",
                    "-device", "virtio-blk-device,drive=bench-disk,queue-size=128,serial=vibeos-bench-data",
                    "-virtfs", f"local,path={args.agent.resolve().parent},mount_tag=bench,security_model=none,readonly=on",
                ]
                env = environment(qemu_args, qemu_version)
                env["storage_throttle"] = storage_throttle(args)
                env["memory_mib"] = args.memory_mib
                env.update({"linux_version": args.linux_version,
                            "debian_release": args.debian_release})
                env.update(artifact_hashes)
                process = subprocess.Popen(qemu_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT)
                try:
                    assert process.stdin is not None and process.stdout is not None
                    wait_for(process.stdout, process, b"localhost login:", args.boot_timeout)
                    process.stdin.write(b"root\n")
                    process.stdin.flush()
                    wait_for(process.stdout, process, b"Password:", 30)
                    process.stdin.write((args.password + "\n").encode())
                    process.stdin.flush()
                    wait_for(process.stdout, process, b"root@localhost:", 30)
                    process.stdin.write(b"stty -echo\n")
                    process.stdin.flush()
                    wait_for(process.stdout, process, b"root@localhost:", 30)
                    block_mode = args.workload.startswith("block-")
                    setup = (
                        ("mkdir -p /mnt/host; " if block_mode else "mkdir -p /mnt/data /mnt/host; ")
                        + "data_device=$(readlink -f /dev/disk/by-id/virtio-vibeos-bench-data); "
                        + "block_name=$(basename \"$data_device\"); "
                        + ("" if block_mode else
                           "mount -t ext4 -o data=ordered,barrier=1 \"$data_device\" /mnt/data && ")
                        + "mount -t 9p -o trans=virtio,version=9p2000.L bench /mnt/host && "
                        + f"test -x /mnt/host/{args.agent.name} && echo BENCH_SETUP_READY\n"
                    )
                    process.stdin.write(setup.encode())
                    process.stdin.flush()
                    wait_for(process.stdout, process, b"BENCH_SETUP_READY", 60)
                    command = (
                        f"/mnt/host/{args.agent.name} "
                        + (f"--workload {args.workload} --queue-depth {args.queue_depth} --block-device \"$data_device\" "
                           if block_mode else
                           f"--directory /mnt/data --bytes {args.object_bytes} "
                           f"--object-count {args.object_count} --workload {args.workload} "
                           + (f"--content-class {args.content_class} "
                              if args.content_class else ""))
                        + ' --block-stat "/sys/class/block/$block_name/stat" '
                        + f"--seed {seed} --warmups {args.warmups} --samples {args.samples}; "
                        "echo BENCH_RUN_DONE\n"
                    )
                    process.stdin.write(command.encode())
                    process.stdin.flush()
                    data = wait_for(process.stdout, process, b"BENCH_RUN_DONE", args.sample_timeout)
                    serial = data.decode("utf-8", errors="replace").replace("\r", "\n")
                    samples = [json.loads(line.split(PREFIX, 1)[1])
                               for line in serial.splitlines() if PREFIX in line]
                    require(len(samples) == args.warmups + args.samples,
                            f"Linux guest emitted {len(samples)} samples; expected {args.warmups + args.samples}")
                    for index, sample in enumerate(samples):
                        require(sample.get("seed") == seed + index, "Linux guest seed mismatch")
                        require(sample.get("warmup") == (index < args.warmups),
                                "Linux guest warmup coordinate mismatch")
                        record = convert_linux_sample(sample, run_id=run_id,
                                                      vm_index=vm_index, env=env)
                        output.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                    output.flush()
                    verify_command = (
                        ("sync; umount /mnt/data; " if not block_mode else "sync; ")
                        + 'if e2fsck -fn "$data_device" >/dev/null 2>&1; '
                        + "then echo BENCH_FSCK_OK; else echo BENCH_FSCK_FAILED; fi\n"
                    )
                    process.stdin.write(verify_command.encode())
                    process.stdin.flush()
                    check = wait_for(process.stdout, process, b"BENCH_FSCK_", 120)
                    check += wait_for(process.stdout, process, b"root@localhost:", 30)
                    require(b"BENCH_FSCK_OK" in check, "powered-off ext4 verification failed")
                    process.stdin.write(b"poweroff\n")
                    process.stdin.flush()
                finally:
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=5)
    return 0


def provision_debian(args: argparse.Namespace) -> int:
    for path in (args.base_image, args.firmware_code, args.firmware_vars):
        require(path.is_file(), f"provisioning artifact not found: {path}")
    require(not args.output_root.exists(), f"refusing to overwrite {args.output_root}")
    require(not args.output_vars.exists(), f"refusing to overwrite {args.output_vars}")
    args.output_root.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        args.qemu_img, "create", "-q", "-f", "qcow2", "-F", "qcow2",
        "-b", str(args.base_image.resolve()), str(args.output_root.resolve()),
    ], check=True)
    shutil.copyfile(args.firmware_vars, args.output_vars)
    qemu_args = [
        args.qemu, "-machine", "virt", "-cpu", "rv64", "-smp", "1", "-m", "512M",
        "-accel", "tcg,thread=single", "-nographic", "-drive",
        f"if=pflash,format=raw,unit=0,readonly=on,file={args.firmware_code.resolve()}",
        "-drive", f"if=pflash,format=raw,unit=1,file={args.output_vars.resolve()}",
        "-drive", f"if=none,id=root,format=qcow2,file={args.output_root.resolve()},cache=none,aio=threads",
        "-device", "virtio-blk-device,drive=root,queue-size=128,serial=debian-root",
    ]
    process = subprocess.Popen(qemu_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    try:
        assert process.stdin is not None and process.stdout is not None
        wait_for(process.stdout, process, b"-- Press any key to proceed --", args.timeout)
        process.stdin.write(b"\n")
        process.stdin.flush()
        wait_for(process.stdout, process, b"Please enter the new timezone", 30)
        process.stdin.write(b"\n")
        process.stdin.flush()
        wait_for(process.stdout, process, b"Please enter the new root password", 30)
        process.stdin.write((args.password + "\n").encode())
        process.stdin.flush()
        wait_for(process.stdout, process, b"Please enter the new root password again", 30)
        process.stdin.write((args.password + "\n").encode())
        process.stdin.flush()
        wait_for(process.stdout, process, b"localhost login:", 60)
        process.stdin.write(b"root\n")
        process.stdin.flush()
        wait_for(process.stdout, process, b"Password:", 30)
        process.stdin.write((args.password + "\n").encode())
        process.stdin.flush()
        wait_for(process.stdout, process, b"root@localhost:", 30)
        process.stdin.write(b"poweroff\n")
        process.stdin.flush()
        process.wait(timeout=60)
        require(process.returncode == 0, f"provisioning QEMU exited with {process.returncode}")
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    return 0


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def coordinate(record: dict[str, Any], metric: str) -> tuple[Any, ...]:
    return (record["backend"], record["layer"], record["workload"],
            record.get("object_bytes"), record.get("object_count"),
            record.get("content_class"), record["queue_depth"], metric)


def summaries(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[float]] = defaultdict(list)
    profiles: dict[tuple[Any, ...], tuple[int, ...]] = {}
    memories: dict[tuple[Any, ...], int] = {}
    geometries: dict[tuple[Any, ...], int | None] = {}
    patterns: dict[tuple[Any, ...], str] = {}
    scopes: dict[tuple[Any, ...], str] = {}
    for record in records:
        if record["warmup"] or record["status"] != "ok":
            continue
        for metric, value in record["metrics"].items():
            key = coordinate(record, metric)
            profile = record["environment"].get("storage_throttle", {})
            require(isinstance(profile, dict), "invalid storage throttle profile")
            signature = tuple(profile.get(name, 0) for name in THROTTLE_FIELDS)
            require(all(type(value) is int and value >= 0 for value in signature),
                    "invalid storage throttle profile")
            # Exclude backend so Linux/VibeOS comparisons also require the
            # same limits for an otherwise identical workload coordinate.
            shared_key = key[1:]
            memory = record["environment"].get("memory_mib", 512)
            require(type(memory) is int and memory > 0, "invalid guest memory size")
            require(memories.setdefault(shared_key, memory) == memory,
                    "incompatible guest memory sizes for the same coordinate")
            require(profiles.setdefault(shared_key, signature) == signature,
                    "incompatible storage throttle profiles for the same coordinate")
            pattern = record["environment"].get("content_pattern", "legacy")
            require(patterns.setdefault(shared_key, pattern) == pattern,
                    "incompatible content patterns for the same coordinate")
            scope = record["environment"].get("latency_scope", "legacy")
            require(scopes.setdefault(shared_key, scope) == scope,
                    "incompatible latency scopes for the same coordinate")
            if record["backend"] == "storage-v2" and record["layer"] != "block":
                geometry = record["environment"].get("storage_v2_provisioned_segments")
                require(geometry is None or (type(geometry) is int and geometry > 0),
                        "invalid storage geometry")
                require(geometries.setdefault(key, geometry) == geometry,
                        "incompatible storage geometries for the same coordinate")
            groups[key].append(float(value))
    result = []
    for key, values in sorted(groups.items(), key=lambda item: str(item[0])):
        mean = statistics.fmean(values)
        cv = statistics.pstdev(values) / mean if len(values) > 1 and mean else 0.0
        result.append({
            "backend": key[0], "layer": key[1], "workload": key[2],
            "object_bytes": key[3], "object_count": key[4], "content_class": key[5],
            "queue_depth": key[6], "metric": key[7], "samples": len(values),
            "min": min(values), "p50": percentile(values, 0.50),
            "p95": percentile(values, 0.95), "p99": percentile(values, 0.99),
            "max": max(values), "mean": mean, "coefficient_of_variation": cv,
            "status": "inconclusive" if cv > 0.10 else "ok",
        })
    return result


def compare(records: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
    indexed = {(item["backend"], item["layer"], item["workload"], item["object_bytes"],
                item["object_count"], item["content_class"], item["queue_depth"], item["metric"]): item
               for item in summaries(records)}
    results = []
    passed = True
    for key, vibe in indexed.items():
        if key[0] not in {"m4", "storage-v2"} or key[6] != 1:
            continue
        linux_key = ("linux-ext4",) + key[1:]
        linux = indexed.get(linux_key)
        if linux is None:
            continue
        inconclusive = vibe["status"] != "ok" or linux["status"] != "ok"
        if "throughput" in key[7]:
            ratio = vibe["mean"] / linux["mean"]
            gate = ratio >= 0.70
        else:
            ratio = max(vibe["p50"] / linux["p50"], vibe["p95"] / linux["p95"])
            gate = ratio <= 2.0
        status = "inconclusive" if inconclusive else ("ok" if gate else "failed")
        passed &= status == "ok"
        results.append({"coordinate": key, "ratio": ratio, "status": status})
    require(bool(results), "no comparable VibeOS/Linux coordinates")
    return passed, results


def require_baseline_evidence(records: list[dict[str, Any]], manifest_path: Path,
                              evidence_path: Path) -> None:
    require(all(not any(record["environment"].get("storage_throttle", {}).values())
                for record in records),
            "rate-limited exploratory runs cannot replace the unthrottled v1 baseline")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    require(isinstance(evidence, dict) and evidence.get("status") == "ok",
            "correctness evidence is not ok")
    require(evidence.get("vibeos_verifier", {}).get("status") == "ok",
            "powered-off VibeOS verifier evidence is missing")
    require(evidence.get("linux_fsck", {}).get("status") == "ok",
            "Linux fsck evidence is missing")
    require(all(not record["environment"].get("git_dirty", True) for record in records),
            "formal baseline update requires a clean recorded worktree")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("schema") == "vibeos.storage-bench.manifest" and
            manifest.get("version") == 1, "unknown workload manifest")
    expected = set()
    for workload in manifest["workloads"]:
        for backend in workload.get("backends", []):
            for size in workload.get("sizes", [None]):
                for queue_depth in workload.get("queue_depths", [1]):
                    expected.add((backend, workload["id"], size, queue_depth))
    observed = {(record["backend"], record["workload"], record.get("object_bytes"),
                 record["queue_depth"]) for record in records if not record["warmup"]}
    missing = expected - observed
    require(not missing, f"baseline is missing {len(missing)} manifest coordinates")


def selftest() -> None:
    base = {
        "schema": RECORD_SCHEMA, "version": 1, "run_id": "test", "backend": "storage-v2",
        "layer": "object", "workload": "durable-put-get", "status": "ok", "vm_index": 0,
        "sample_index": 0, "warmup": False, "seed": 1, "queue_depth": 1,
        "object_bytes": 4096, "metrics": {"put_latency_ns": 1.0}, "counters": {},
        "phases": {}, "environment": {"git_commit": "1234567", "qemu_version": "qemu",
        "qemu_args": [], "cache_state": "unknown"},
    }
    validate_record(base)
    for mutation in (
        lambda item: item.pop("seed"),
        lambda item: item.update(status="unsupported"),
        lambda item: item.update(metrics={"put_latency_ns": 0}),
        lambda item: item.update(backend="host-prototype"),
    ):
        candidate = json.loads(json.dumps(base))
        mutation(candidate)
        try:
            validate_record(candidate)
        except ValidationError:
            pass
        else:
            raise AssertionError("validator accepted a malformed record")

    guest = {"schema": "vibeos.storage-bench.sample", "version": 1,
             "backend": "storage-v2", "layer": "file-tree", "workload": "file-sequential",
             "status": "ok", "seed": 1, "timebase_hz": 1000, "latency_ticks": 1}
    metrics = ("requests", "read_requests", "write_requests", "flush_requests",
               "read_bytes", "write_bytes", "used_interrupts")
    for metric in metrics:
        guest["block_" + metric] = 10
        for value, phase in enumerate(("stage", "publish", "verify", "remove"), 1):
            guest[f"file_{phase}_{metric}"] = value
    def convert(item):
        return convert_guest_sample(item, run_id="test", vm_index=0, sample_index=0,
                                    warmup=False, seed=1, env=base["environment"])
    assert convert(guest)["phases"]["file_remove_read_bytes"] == 4
    for mutate in (
        lambda item: item.pop("file_verify_read_bytes"),
        lambda item: item.update(file_stage_read_bytes=-1),
        lambda item: item.update(file_stage_read_bytes=True),
        lambda item: item.update(block_read_bytes=11),
        lambda item: item.update(workload="object-range-get"),
    ):
        candidate = dict(guest)
        mutate(candidate)
        try:
            convert(candidate)
        except ValidationError:
            pass
        else:
            raise AssertionError("converter accepted inconsistent file phases")
    timed = dict(guest, elapsed_ticks=10, transferred_bytes=0)
    for value, phase in enumerate(("stage", "publish", "verify", "remove"), 1):
        timed[f"file_{phase}_elapsed_ticks"] = value
    assert convert(timed)["phases"]["file_verify_elapsed_ticks"] == 3
    for mutate in (
        lambda item: item.pop("file_verify_elapsed_ticks"),
        lambda item: item.update(file_stage_elapsed_ticks=-1),
        lambda item: item.update(file_stage_elapsed_ticks=True),
        lambda item: item.update(elapsed_ticks=11),
        lambda item: item.pop("elapsed_ticks"),
    ):
        candidate = dict(timed)
        mutate(candidate)
        try:
            convert(candidate)
        except ValidationError:
            pass
        else:
            raise AssertionError("converter accepted inconsistent file phase times")
    detailed = dict(timed, file_stage_pattern_ticks=0, file_stage_push_ticks=1,
                    file_stage_finish_ticks=0, file_stage_other_ticks=0)
    assert convert(detailed)["phases"]["file_stage_push_ticks"] == 1
    for mutate in (
        lambda item: item.pop("file_stage_finish_ticks"),
        lambda item: item.update(file_stage_other_ticks=True),
        lambda item: item.update(file_stage_push_ticks=-1),
        lambda item: item.update(file_stage_push_ticks=2),
        lambda item: item.pop("file_stage_elapsed_ticks"),
    ):
        candidate = dict(detailed)
        mutate(candidate)
        try:
            convert(candidate)
        except ValidationError:
            pass
        else:
            raise AssertionError("converter accepted inconsistent staging details")
    verify_details = dict(timed, file_verify_reader_ticks=1,
                          file_verify_pattern_ticks=1, file_verify_other_ticks=1)
    assert convert(verify_details)["phases"]["file_verify_reader_ticks"] == 1
    for mutate in (
        lambda item: item.pop("file_verify_pattern_ticks"),
        lambda item: item.update(file_verify_other_ticks=True),
        lambda item: item.update(file_verify_reader_ticks=-1),
        lambda item: item.update(file_verify_reader_ticks=2),
        lambda item: item.pop("file_verify_elapsed_ticks"),
    ):
        candidate = dict(verify_details)
        mutate(candidate)
        try:
            convert(candidate)
        except ValidationError:
            pass
        else:
            raise AssertionError("converter accepted inconsistent verification details")
    legacy = {name: value for name, value in guest.items() if not name.startswith("file_")}
    assert "file_stage_read_bytes" not in convert(legacy)["phases"]


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    summarize = subparsers.add_parser("summarize")
    summarize.add_argument("input", type=Path)
    summarize.add_argument("--output", type=Path)
    gate = subparsers.add_parser("compare")
    gate.add_argument("input", type=Path, nargs="+")
    update = subparsers.add_parser("update-baseline")
    update.add_argument("input", type=Path)
    update.add_argument("baseline", type=Path)
    update.add_argument("--manifest", type=Path,
                        default=Path("benchmarks/storage/workloads-v1.json"))
    update.add_argument("--correctness-evidence", type=Path, required=True)
    update.add_argument("--update", action="store_true", required=True)
    subparsers.add_parser("selftest")
    run = subparsers.add_parser("run-vibeos")
    run.add_argument("--kernel", type=Path, required=True)
    run.add_argument("--data-image", type=Path, required=True,
                     help="powered-off verified backend template; cloned once per VM")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--retain-images", type=Path,
                     help="retain stopped per-VM images without overwriting existing files; verify independently before reuse")
    run.add_argument("--object-bytes", type=int, required=True)
    run.add_argument("--object-count", type=int, default=1)
    run.add_argument("--content-class", choices=("unique", "half-duplicate", "all-duplicate"))
    run.add_argument("--queue-depth", type=int, default=1)
    run.add_argument("--workload", default="object-durable-put-get")
    run.add_argument("--backend", choices=("storage-v2", "m4"), default="storage-v2")
    run.add_argument("--vms", type=int, default=5)
    run.add_argument("--warmups", type=int, default=5)
    run.add_argument("--samples", type=int, default=20)
    run.add_argument("--seed", type=int, default=14476452505690153217)
    run.add_argument("--run-id")
    run.add_argument("--qemu", default="qemu-system-riscv64")
    run.add_argument("--boot-timeout", type=float, default=180)
    run.add_argument("--sample-timeout", type=float, default=300)
    run.add_argument("--serial-log", type=Path,
                     help="save raw guest serial output, including diagnostic lines")
    run.add_argument("--stop-on-failure", action="store_true",
                     help="stop after the first non-ok sample and return exit status 1")
    run.add_argument("--overwrite", action="store_true")
    linux = subparsers.add_parser("run-linux")
    linux.add_argument("--root-image", type=Path, required=True)
    linux.add_argument("--firmware-code", type=Path, required=True)
    linux.add_argument("--firmware-vars", type=Path, required=True)
    linux.add_argument("--agent", type=Path, required=True)
    linux.add_argument("--data-image", type=Path, required=True)
    linux.add_argument("--output", type=Path, required=True)
    linux.add_argument("--object-bytes", type=int, required=True)
    linux.add_argument("--object-count", type=int, default=1)
    linux.add_argument("--content-class", choices=("unique", "half-duplicate", "all-duplicate"))
    linux.add_argument("--queue-depth", type=int, default=1)
    linux.add_argument("--workload", default="object-durable-put-get")
    linux.add_argument("--vms", type=int, default=5)
    linux.add_argument("--warmups", type=int, default=5)
    linux.add_argument("--samples", type=int, default=20)
    linux.add_argument("--seed", type=int, default=14476452505690153217)
    linux.add_argument("--run-id")
    linux.add_argument("--qemu", default="qemu-system-riscv64")
    linux.add_argument("--linux-version", default="6.12.101+deb13-riscv64")
    linux.add_argument("--debian-release", default="13")
    linux.add_argument("--password", default="vibeosbench")
    linux.add_argument("--boot-timeout", type=float, default=300)
    linux.add_argument("--sample-timeout", type=float, default=900)
    linux.add_argument("--overwrite", action="store_true")
    for runner in (run, linux):
        runner.add_argument("--memory-mib", type=int, default=512,
                            help="guest RAM in MiB (default: 512)")
        for flag in THROTTLE_FIELDS:
            runner.add_argument("--" + flag.replace("_", "-"), type=int, default=0,
                                help="benchmark disk rate limit; 0 leaves it unlimited")
    provision = subparsers.add_parser("provision-debian")
    provision.add_argument("--base-image", type=Path, required=True)
    provision.add_argument("--firmware-code", type=Path, required=True)
    provision.add_argument("--firmware-vars", type=Path, required=True)
    provision.add_argument("--output-root", type=Path, required=True)
    provision.add_argument("--output-vars", type=Path, required=True)
    provision.add_argument("--password", default="vibeosbench")
    provision.add_argument("--qemu", default="qemu-system-riscv64")
    provision.add_argument("--qemu-img", default="qemu-img")
    provision.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    try:
        if args.command == "selftest":
            selftest()
        elif args.command == "validate":
            read_jsonl(args.input)
        elif args.command == "summarize":
            data = json.dumps(summaries(read_jsonl(args.input)), indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(data, encoding="utf-8")
            else:
                sys.stdout.write(data)
        elif args.command == "compare":
            passed, result = compare(read_jsonls(args.input))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if passed else 1
        elif args.command == "update-baseline":
            records = read_jsonl(args.input)
            require_baseline_evidence(records, args.manifest, args.correctness_evidence)
            payload = json.dumps({"schema": "vibeos.storage-bench.baseline", "version": 1,
                                  "source_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
                                  "summaries": summaries(records)}, indent=2, sort_keys=True) + "\n"
            args.baseline.parent.mkdir(parents=True, exist_ok=True)
            args.baseline.write_text(payload, encoding="utf-8")
        elif args.command == "run-vibeos":
            require(args.object_bytes >= 0, "object size must be non-negative")
            require(args.vms > 0 and args.warmups >= 0 and args.samples > 0, "invalid sample counts")
            require(args.data_image.is_file(), "data image template does not exist")
            return run_vibeos(args)
        elif args.command == "run-linux":
            require(args.object_bytes >= 0, "object size must be non-negative")
            require(args.vms > 0 and args.warmups >= 0 and args.samples > 0, "invalid sample counts")
            return run_linux(args)
        elif args.command == "provision-debian":
            return provision_debian(args)
    except (OSError, subprocess.SubprocessError, ValidationError, TimeoutError, RuntimeError) as error:
        print(f"storage-bench: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
