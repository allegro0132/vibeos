#!/usr/bin/env python3
"""Collect and check the deterministic QEMU/TCG VibeOS benchmark baseline.

The guest owns the measurements and emits one JSON object per ``VIBE_BENCH``
line.  This driver owns the execution environment, schema validation, and the
explicitly versioned regression policy.  It never updates a baseline unless
``--update`` is present.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL = ROOT / "target/riscv64imac-unknown-none-elf/release/vibeos-kernel"
BASELINE = ROOT / "benchmarks/qemu-tcg-rv64.json"
TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"
SCHEMA = "vibeos.bench"
SCHEMA_VERSION = 1
METRIC_PREFIX = "VIBE_BENCH "
META_PREFIX = "VIBE_BENCH_META "
END_MARKER = "VIBE_BENCH_END"
SMP_SCALE_PREFIX = "VIBE_SMP_SCALE "
SMP_SCALE_FAILURE = "VIBE_SMP_SCALE_FAILED"
SMP_SCALE_WORKERS = 4
SMP_SCALE_ACCEL = "tcg,thread=multi"
SMP_SCALE_MIN_SPEEDUP_MILLI = 1_250

QEMU_MACHINE = "virt"
QEMU_CPU = "rv64"
QEMU_SMP = 1
QEMU_MEMORY = "128M"
QEMU_ACCEL = "tcg,thread=single"
QEMU_ICOUNT = "shift=0,align=off,sleep=off"

# The statistic and direction are part of the policy, rather than something a
# guest can choose.  A small absolute allowance keeps timer quantisation from
# making a near-zero result look like a large relative regression.
POLICY: dict[str, dict[str, Any]] = {
    "ipc_roundtrip_ticks": {"stat": "p95", "direction": "lower", "ratio": 1.40, "absolute": 32},
    "irq_to_poll_ticks": {"stat": "p95", "direction": "lower", "ratio": 1.75, "absolute": 8},
    "cap_lookup_depth_0_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "cap_lookup_depth_1_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "cap_lookup_depth_2_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "cap_lookup_depth_4_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "cap_lookup_depth_8_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "cap_lookup_depth_16_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "cap_lookup_depth_32_ticks": {"stat": "p50", "direction": "lower", "ratio": 1.30, "absolute": 1},
    "heap_peak_bytes": {"stat": "max", "direction": "lower", "ratio": 1.10, "absolute": 65536},
    "compile_bytes_per_second": {"stat": "p50", "direction": "higher", "ratio": 0.70, "absolute": 1024},
    "generated_code_bytes": {"stat": "p50", "direction": "lower", "ratio": 1.02, "absolute": 64},
    "generated_data_bytes": {"stat": "p50", "direction": "lower", "ratio": 1.00, "absolute": 16},
    "generated_runtime_ticks": {"stat": "p95", "direction": "lower", "ratio": 1.40, "absolute": 64},
}

SUMMARY_FIELDS = ("samples", "warmup", "min", "p50", "p95", "max", "mean")


class BenchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Parsed:
    guest_metadata: dict[str, Any]
    metrics: dict[str, dict[str, Any]]


def first_line(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BenchError(f"cannot run {' '.join(command)}: {exc}") from exc
    return result.stdout.splitlines()[0] if result.stdout else "unknown"


def toolchain_pin() -> tuple[str, str]:
    try:
        manifest = TOOLCHAIN_FILE.read_text()
    except OSError as exc:
        raise BenchError(f"cannot read {TOOLCHAIN_FILE}: {exc}") from exc
    channel_match = re.search(r'^channel = "([^"]+)"$', manifest, re.MULTILINE)
    commit_match = re.search(r"^# rustc-commit: ([0-9a-f]+)$", manifest, re.MULTILINE)
    if channel_match is None or commit_match is None:
        raise BenchError("rust-toolchain.toml has no exact channel/commit pin")
    return channel_match.group(1), commit_match.group(1)


def pinned_rustc_version() -> str:
    channel, expected_commit = toolchain_pin()
    command = ["rustup", "run", channel, "rustc", "-Vv"]
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BenchError(
            f"cannot run pinned compiler via rustup ({channel}): {exc}"
        ) from exc
    commit_match = re.search(r"^commit-hash: ([0-9a-f]+)$", result.stdout, re.MULTILINE)
    actual_commit = commit_match.group(1) if commit_match is not None else "unavailable"
    if actual_commit != expected_commit:
        raise BenchError(
            f"rustc commit {actual_commit} does not match pinned {expected_commit}"
        )
    return result.stdout.splitlines()[0] if result.stdout else "unknown"


def rustup_which(channel: str, executable: str) -> str:
    path = first_line(["rustup", "which", "--toolchain", channel, executable])
    if path == "unknown" or not pathlib.Path(path).is_file():
        raise BenchError(f"rustup returned no {executable} path for {channel}")
    return path


def host_metadata() -> dict[str, Any]:
    return {
        "qemu": first_line(["qemu-system-riscv64", "--version"]),
        "toolchain": pinned_rustc_version(),
        "machine": QEMU_MACHINE,
        "cpu": QEMU_CPU,
        "smp": QEMU_SMP,
        "memory": QEMU_MEMORY,
        "accelerator": QEMU_ACCEL,
        "icount": QEMU_ICOUNT,
        "profile": "release",
    }


def parse_transcript(text: str) -> Parsed:
    metric_objects: list[dict[str, Any]] = []
    metadata_objects: list[dict[str, Any]] = []
    end_record: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip().replace("\r", "")
        prefix = None
        destination = None
        if (pos := line.find(META_PREFIX)) >= 0:
            prefix = META_PREFIX
            destination = metadata_objects
        elif (pos := line.find(METRIC_PREFIX)) >= 0:
            prefix = METRIC_PREFIX
            destination = metric_objects
        if prefix is not None and destination is not None:
            payload = line[pos + len(prefix) :]
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise BenchError(f"invalid benchmark JSON: {payload!r}: {exc}") from exc
            if not isinstance(obj, dict):
                raise BenchError("benchmark records must be JSON objects")
            destination.append(obj)
        if (pos := line.find(END_MARKER)) >= 0:
            if end_record is not None:
                raise BenchError("duplicate benchmark end record")
            payload = line[pos + len(END_MARKER) :].strip()
            if payload:
                try:
                    decoded_end = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise BenchError(f"invalid benchmark end record: {payload!r}: {exc}") from exc
                if not isinstance(decoded_end, dict):
                    raise BenchError("benchmark end record must be a JSON object")
                end_record = decoded_end
            else:
                end_record = {}

    if end_record is None:
        raise BenchError(f"guest did not emit {END_MARKER}")
    if not end_record:
        raise BenchError("benchmark end record is missing its JSON schema")

    if len(metadata_objects) != 1:
        raise BenchError(f"expected one metadata record, found {len(metadata_objects)}")
    metadata = metadata_objects[0]
    if metadata.get("schema") != "vibeos.bench.meta" or metadata.get("version") != SCHEMA_VERSION:
        raise BenchError(
            f"unsupported guest schema {metadata.get('schema')!r} version {metadata.get('version')!r}"
        )
    if (
        end_record.get("schema") != SCHEMA
        or end_record.get("version") != SCHEMA_VERSION
    ):
        raise BenchError("unsupported benchmark end schema")

    metrics: dict[str, dict[str, Any]] = {}
    for obj in metric_objects:
        if obj.get("schema") != "vibeos.bench.metric" or obj.get("version") != SCHEMA_VERSION:
            raise BenchError(f"unsupported metric schema in {obj!r}")
        name = obj.get("name")
        if not isinstance(name, str) or not name:
            raise BenchError("metric record has no string name")
        if name in metrics:
            raise BenchError(f"duplicate metric {name}")
        for field in SUMMARY_FIELDS:
            value = obj.get(field)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                raise BenchError(f"metric {name} has invalid {field}: {value!r}")
        if int(obj["samples"]) <= 0:
            raise BenchError(f"metric {name} has no measured samples")
        if not isinstance(obj.get("unit"), str) or not obj["unit"]:
            raise BenchError(f"metric {name} has no unit")
        if obj.get("direction") not in ("lower", "higher"):
            raise BenchError(f"metric {name} has invalid direction")
        if not (obj["min"] <= obj["p50"] <= obj["p95"] <= obj["max"]):
            raise BenchError(f"metric {name} summary is not monotonic")
        metrics[name] = obj

    if end_record.get("metrics") != len(metrics):
        raise BenchError(
            f"end record says {end_record.get('metrics')} metrics, parsed {len(metrics)}"
        )

    missing = sorted(set(POLICY) - set(metrics))
    extra = sorted(set(metrics) - set(POLICY))
    if missing or extra:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("unexpected: " + ", ".join(extra))
        raise BenchError("metric schema mismatch (" + "; ".join(details) + ")")
    return Parsed(metadata, metrics)


def build_kernel() -> None:
    channel, _ = toolchain_pin()
    # `rustup run cargo` selects Cargo itself, but Cargo may still resolve a
    # non-proxy `rustc` earlier on PATH. Absolute compiler paths close that gap.
    pinned_rustc_version()
    env = os.environ.copy()
    # The repository pins a real nightly. Never let an ambient compatibility
    # escape hatch turn a stable compiler into an unrecorded pseudo-nightly.
    env.pop("RUSTC_BOOTSTRAP", None)
    env["RUSTC"] = rustup_which(channel, "rustc")
    env["RUSTDOC"] = rustup_which(channel, "rustdoc")
    try:
        subprocess.run(
            ["rustup", "run", channel, "cargo", "build", "--release"],
            # Cargo discovers target/build-std settings from the invocation
            # directory; the bare-metal configuration lives under kernel/.
            cwd=ROOT / "kernel",
            env=env,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BenchError(f"pinned kernel build failed ({channel}): {exc}") from exc


def capture_qemu(
    timeout: float,
    *,
    smp: int = QEMU_SMP,
    accelerator: str = QEMU_ACCEL,
    icount: str | None = QEMU_ICOUNT,
    guest_command: bytes = b"bench\n",
    end_pattern: str = rf"{END_MARKER} \{{[^\r\n]*\}}[\r\n]",
) -> str:
    command = [
        "qemu-system-riscv64",
        "-machine",
        QEMU_MACHINE,
        "-cpu",
        QEMU_CPU,
        "-smp",
        str(smp),
        "-m",
        QEMU_MEMORY,
        "-accel",
        accelerator,
        "-nographic",
        "-bios",
        "default",
        "-kernel",
        str(KERNEL),
    ]
    if icount is not None:
        command[command.index("-nographic"):command.index("-nographic")] = ["-icount", icount]
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
        )
    except OSError as exc:
        raise BenchError(f"cannot start QEMU: {exc}") from exc

    output = bytearray()
    deadline = time.monotonic() + timeout
    sent = False
    try:
        assert process.stdout is not None
        assert process.stdin is not None
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        while time.monotonic() < deadline:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                chunk = b""
            if chunk:
                output.extend(chunk)
            decoded = output.decode("utf-8", errors="replace")
            if not sent and "VibeOS shell ready" in decoded:
                process.stdin.write(b"quiet\n")
                process.stdin.flush()
                time.sleep(0.25)
                process.stdin.write(guest_command)
                process.stdin.flush()
                sent = True
            # Wait for the complete newline-terminated end record. Merely
            # seeing its prefix can happen between pipe writes and must not
            # truncate the JSON payload.
            if re.search(end_pattern, decoded):
                process.stdin.write(b"halt\n")
                process.stdin.flush()
                break
            if process.poll() is not None:
                break
            time.sleep(0.01)
        else:
            raise BenchError(f"QEMU benchmark timed out after {timeout:.0f}s")

        # Drain the final prompt/shutdown output without making successful
        # collection depend on firmware's exit status convention.
        end = time.monotonic() + 2.0
        while time.monotonic() < end:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                chunk = b""
            if chunk:
                output.extend(chunk)
            elif process.poll() is not None:
                # A zero-byte read after exit is EOF; all buffered pipe data
                # has now been consumed.
                break
            time.sleep(0.01)
        return output.decode("utf-8", errors="replace")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def parse_smp_scale(text: str) -> dict[str, int]:
    if SMP_SCALE_FAILURE in text:
        failure = next(
            (line.strip() for line in text.splitlines() if SMP_SCALE_FAILURE in line),
            SMP_SCALE_FAILURE,
        )
        raise BenchError(f"guest rejected SMP scaling: {failure}")

    records: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip().replace("\r", "")
        position = line.find(SMP_SCALE_PREFIX)
        if position < 0:
            continue
        payload = line[position + len(SMP_SCALE_PREFIX) :]
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise BenchError(f"invalid SMP scaling JSON: {payload!r}: {exc}") from exc
        if not isinstance(decoded, dict):
            raise BenchError("SMP scaling record must be a JSON object")
        records.append(decoded)
    if len(records) != 1:
        raise BenchError(f"expected one SMP scaling record, found {len(records)}")

    record = records[0]
    version = record.get("version")
    if (
        record.get("schema") != "vibeos.smp-scale"
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version != 1
    ):
        raise BenchError("unsupported SMP scaling schema")
    fields = ("workers", "serial_ticks", "parallel_ticks", "speedup_milli", "checksum")
    result: dict[str, int] = {}
    for field in fields:
        value = record.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BenchError(f"SMP scaling record has invalid {field}: {value!r}")
        result[field] = value
    if result["workers"] != SMP_SCALE_WORKERS:
        raise BenchError(
            f"SMP scaling used {result['workers']} workers, expected {SMP_SCALE_WORKERS}"
        )
    if result["serial_ticks"] == 0 or result["parallel_ticks"] == 0:
        raise BenchError("SMP scaling durations must be nonzero")
    calculated = result["serial_ticks"] * 1_000 // result["parallel_ticks"]
    if result["speedup_milli"] != calculated:
        raise BenchError(
            f"guest speedup {result['speedup_milli']} disagrees with durations ({calculated})"
        )
    return result


def selftest_smp_scale_parser() -> int:
    good = (
        'noise\r\nVIBE_SMP_SCALE {"schema":"vibeos.smp-scale","version":1,'
        '"workers":4,"serial_ticks":5000,"parallel_ticks":2000,'
        '"speedup_milli":2500,"checksum":7}\r\n'
    )
    parsed = parse_smp_scale(good)
    if parsed["speedup_milli"] != 2_500:
        raise BenchError("SMP parser self-test lost the valid speedup")

    rejected = (
        "VIBE_SMP_SCALE_FAILED remote_preflight\n",
        good + good,
        'VIBE_SMP_SCALE {"schema":"vibeos.smp-scale","version":1,'
        '"workers":4,"serial_ticks":5000,"parallel_ticks":2000,'
        '"speedup_milli":2499,"checksum":7}\n',
        'VIBE_SMP_SCALE {"schema":"vibeos.smp-scale","version":true,'
        '"workers":4,"serial_ticks":5000,"parallel_ticks":2000,'
        '"speedup_milli":2500,"checksum":7}\n',
    )
    for transcript in rejected:
        try:
            parse_smp_scale(transcript)
        except BenchError:
            continue
        raise BenchError("SMP parser self-test accepted a malformed transcript")
    print("ok   smp_scale_parser (valid, failure, duplicate, schema, and consistency checks)")
    return 0


def run_smp_scaling(args: argparse.Namespace) -> int:
    if args.update:
        raise BenchError("--smp-scaling has no mutable baseline; --update is invalid")
    if args.input:
        transcript = args.input.read_text(errors="replace")
    else:
        if not args.no_build:
            build_kernel()
        if not KERNEL.is_file():
            raise BenchError(f"kernel image does not exist: {KERNEL}")
        transcript = capture_qemu(
            args.timeout,
            smp=SMP_SCALE_WORKERS,
            accelerator=SMP_SCALE_ACCEL,
            icount=None,
            guest_command=b"smp scale\n",
            end_pattern=r"VIBE_SMP_SCALE(?:_FAILED)?[^\r\n]*[\r\n]",
        )
    result = parse_smp_scale(transcript)
    speedup = result["speedup_milli"] / 1_000
    ok = result["speedup_milli"] >= SMP_SCALE_MIN_SPEEDUP_MILLI
    print(
        f"{'ok  ' if ok else 'FAIL'} smp_scale: workers={result['workers']} "
        f"serial_ticks={result['serial_ticks']} parallel_ticks={result['parallel_ticks']} "
        f"speedup={speedup:.3f}x >= {SMP_SCALE_MIN_SPEEDUP_MILLI / 1_000:.3f}x"
    )
    if not ok:
        print("SMP throughput did not demonstrate the committed minimum scaling", file=sys.stderr)
        return 1
    return 0


def baseline_document(parsed: Parsed, metadata: dict[str, Any]) -> dict[str, Any]:
    metrics = {}
    for name, rule in POLICY.items():
        metrics[name] = {
            "policy": rule,
            "baseline": parsed.metrics[name],
        }
    return {
        "schema": "vibeos.bench-baseline",
        "version": 1,
        "environment": metadata,
        "guest": parsed.guest_metadata,
        "metrics": metrics,
    }


def load_baseline(path: pathlib.Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise BenchError(f"baseline does not exist: {path}; use --update intentionally") from exc
    except json.JSONDecodeError as exc:
        raise BenchError(f"invalid baseline JSON {path}: {exc}") from exc
    if doc.get("schema") != "vibeos.bench-baseline" or doc.get("version") != 1:
        raise BenchError("unsupported baseline schema")
    if set(doc.get("metrics", {})) != set(POLICY):
        raise BenchError("baseline metric set does not match this checker's policy")
    for name, rule in POLICY.items():
        if doc["metrics"][name].get("policy") != rule:
            raise BenchError(f"baseline policy for {name} differs from the checked-in policy")
    return doc


def compare(
    parsed: Parsed,
    baseline: dict[str, Any],
    metadata: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    if metadata is not None:
        baseline_environment = baseline.get("environment", {})
        for key in ("machine", "cpu", "smp", "memory", "accelerator", "icount", "profile"):
            if metadata.get(key) != baseline_environment.get(key):
                failures.append(f"environment:{key}")
                print(
                    f"FAIL host environment {key}: {metadata.get(key)!r} "
                    f"!= {baseline_environment.get(key)!r}"
                )
        for key in ("qemu", "toolchain"):
            if metadata.get(key) != baseline_environment.get(key):
                # These revisions are provenance and are printed on every run.
                # M3.14 pins Rust exactly; distro QEMU revisions remain allowed
                # because icount plus the fixed machine contract is the metric
                # comparison boundary.
                print(
                    f"note environment {key} differs from baseline: "
                    f"{metadata.get(key)!r} != {baseline_environment.get(key)!r}"
                )
    for key in ("clock", "timebase_hz", "target", "profile"):
        if parsed.guest_metadata.get(key) != baseline.get("guest", {}).get(key):
            failures.append(f"metadata:{key}")
            print(
                f"FAIL guest metadata {key}: {parsed.guest_metadata.get(key)!r} "
                f"!= {baseline.get('guest', {}).get(key)!r}"
            )
    for name, rule in POLICY.items():
        candidate_metric = parsed.metrics[name]
        reference_metric = baseline["metrics"][name]["baseline"]
        for field in ("unit", "direction", "samples", "warmup"):
            if candidate_metric.get(field) != reference_metric.get(field):
                failures.append(f"{name}:{field}")
                print(
                    f"FAIL {name}: {field}={candidate_metric.get(field)!r} "
                    f"!= baseline {reference_metric.get(field)!r}"
                )
        if candidate_metric["direction"] != rule["direction"]:
            failures.append(f"{name}:direction-policy")
            print(
                f"FAIL {name}: guest direction {candidate_metric['direction']!r} "
                f"!= policy {rule['direction']!r}"
            )
        candidate = float(candidate_metric[rule["stat"]])
        reference = float(reference_metric[rule["stat"]])
        absolute = float(rule["absolute"])
        if rule["direction"] == "lower":
            limit = max(reference * float(rule["ratio"]), reference + absolute)
            ok = candidate <= limit
            relation = "<="
        else:
            # For throughput, tolerate both the agreed proportional drop and a
            # small absolute quantisation/noise band.
            limit = min(reference * float(rule["ratio"]), max(0.0, reference - absolute))
            ok = candidate >= limit
            relation = ">="
        print(
            f"{'ok  ' if ok else 'FAIL'} {name}: {rule['stat']}={candidate:g} "
            f"{relation} {limit:g} (baseline {reference:g})"
        )
        if not ok:
            failures.append(name)
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=pathlib.Path, default=BASELINE)
    parser.add_argument("--input", type=pathlib.Path, help="parse a saved QEMU transcript instead of booting")
    parser.add_argument("--update", action="store_true", help="replace the baseline explicitly")
    parser.add_argument("--no-build", action="store_true", help="reuse the existing release kernel")
    parser.add_argument("--timeout", type=float, default=180.0, help="QEMU collection timeout in seconds")
    parser.add_argument(
        "--smp-scaling",
        action="store_true",
        help="run the four-hart equal-work scaling acceptance instead of the latency baseline",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="exercise the SMP transcript parser without booting QEMU",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            if args.smp_scaling or args.input or args.update:
                raise BenchError("--selftest cannot be combined with run/input/update modes")
            return selftest_smp_scale_parser()
        if args.smp_scaling:
            return run_smp_scaling(args)
        if args.input:
            if args.update:
                raise BenchError("--update requires a fresh controlled QEMU run, not --input")
            transcript = args.input.read_text(errors="replace")
            metadata = None
        else:
            if not args.no_build:
                build_kernel()
            if not KERNEL.is_file():
                raise BenchError(f"kernel image does not exist: {KERNEL}")
            transcript = capture_qemu(args.timeout)
            metadata = host_metadata()
        parsed = parse_transcript(transcript)
        if args.update:
            assert metadata is not None
            document = baseline_document(parsed, metadata)
            args.baseline.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
            temporary: pathlib.Path | None = None
            try:
                fd, name = tempfile.mkstemp(
                    dir=args.baseline.parent,
                    prefix=f".{args.baseline.name}.",
                    suffix=".tmp",
                    text=True,
                )
                temporary = pathlib.Path(name)
                with os.fdopen(fd, "w") as output:
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, args.baseline)
                temporary = None
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            print(f"updated {args.baseline}")
            return 0
        if metadata is not None:
            print(
                f"environment: {metadata['qemu']}; {metadata['toolchain']}; "
                f"{metadata['machine']}/{metadata['cpu']} smp={metadata['smp']} "
                f"{metadata['accelerator']} icount={metadata['icount']}"
            )
        baseline = load_baseline(args.baseline)
        failures = compare(parsed, baseline, metadata)
        if failures:
            print("benchmark regressions: " + ", ".join(failures), file=sys.stderr)
            return 1
        return 0
    except (BenchError, OSError) as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
