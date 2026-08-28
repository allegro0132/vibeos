#!/usr/bin/env python3
"""Drive one mode-bound C8.4 fixed-QEMU AOT-decision SSH campaign.

This peer deliberately reuses the maintained C8.4 OpenSSH request fixtures,
but it accepts only the new formal ``VIBE_WASM_AOT_*`` record stream.  The
older ``AUDIT_*`` collector receipts are diagnostic-only and are rejected so
they cannot be relabelled as decision evidence. The required expected mode is
checked against the image's compile-time META marker and eligibility bit.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import types
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
COLLECTOR_PEER_PATH = (
    ROOT / "scripts/c84-ssh-managed-child-single-boot-collector-peer.py"
)

META_PREFIX = "VIBE_WASM_AOT_META "
SAMPLE_PREFIX = "VIBE_WASM_AOT_SAMPLE "
END_PREFIX = "VIBE_WASM_AOT_END "
FORMAL_PREFIXES = (META_PREFIX, SAMPLE_PREFIX, END_PREFIX)

PLATFORM = "qemu-virt-rv64-tcg-icount-v1"
SUITE_ID = "vibeos.c84.qemu-aot-decision"
WORKLOAD_ID = "ssh-case-filter-12k-v1"
TIMEBASE_HZ = 10_000_000
BUDGET_TICKS = 1_000_000
SAMPLE_COUNT = 24
WARMUP_COUNT = 3
RETAINED_COUNT = 21
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CAPTURE_MODES = {
    "formal-publication": True,
    "dirty-smoke-not-publication": False,
}
SOURCE_CLOSURE_PREFIX = "VIBEOS_C84_EXECUTED_PYTHON_SOURCES "


def load_source_module(name: str, path: Path) -> types.ModuleType:
    """Compile one stable UTF-8 source snapshot without consulting ``.pyc``."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise RuntimeError(f"source helper is not one regular file: {path}")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 16 * 1024 * 1024:
                    raise RuntimeError(f"source helper exceeds 16 MiB: {path}")
                chunks.append(chunk)
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = path.lstat()
    except OSError as error:
        raise RuntimeError(f"cannot read source helper {path}: {error}") from error
    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    if identity(opened) != identity(closed) or identity(closed) != identity(current):
        raise RuntimeError(f"source helper changed while reading: {path}")
    raw = b"".join(chunks)
    if len(raw) != opened.st_size:
        raise RuntimeError(f"source helper byte length changed: {path}")
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"source helper is not strict UTF-8: {path}") from error
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition(".")[0]
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        code = compile(source, str(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    executed_identity = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    executed_closure: dict[str, dict[str, object]] = {str(path): executed_identity}
    for value in tuple(module.__dict__.values()):
        nested = getattr(value, "__vibeos_executed_source_closure__", None)
        if not isinstance(nested, dict):
            continue
        for nested_path, nested_identity in nested.items():
            prior = executed_closure.get(nested_path)
            if prior is not None and prior != nested_identity:
                raise RuntimeError(f"conflicting executed source identity: {nested_path}")
            executed_closure[nested_path] = nested_identity
    module.__vibeos_executed_source_identity__ = executed_identity
    module.__vibeos_executed_source_closure__ = executed_closure
    return module


def load_collector_peer() -> types.ModuleType:
    return load_source_module(
        "vibeos_c84_qemu_decision_collector_peer", COLLECTOR_PEER_PATH
    )


COLLECTOR = load_collector_peer()
PHASE = COLLECTOR.PHASE


def executed_source_closure() -> dict[str, dict[str, object]]:
    """Return the stable source bytes actually used by the nested peer chain."""

    own_path = Path(__file__).resolve()
    own_raw = COLLECTOR.stable_regular_file_bytes(own_path)
    closure: dict[str, dict[str, object]] = {
        str(own_path): {
            "sha256": hashlib.sha256(own_raw).hexdigest(),
            "bytes": len(own_raw),
        }
    }
    nested = getattr(COLLECTOR, "__vibeos_executed_source_closure__", None)
    require(isinstance(nested, dict), "collector did not expose executed source closure")
    for path, identity in nested.items():
        prior = closure.get(path)
        require(
            prior is None or prior == identity,
            f"conflicting executed source identity: {path}",
        )
        closure[path] = identity
    return dict(sorted(closure.items()))


class DriverError(RuntimeError):
    """The live SSH campaign or its formal UART closure was invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"formal UART JSON repeats member {key!r}")
        result[key] = value
    return result


def strict_json(value: str, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value, object_pairs_hook=reject_duplicate_members)
    except json.JSONDecodeError as error:
        raise DriverError(f"{label} is not strict JSON: {error}") from error
    require(isinstance(decoded, dict), f"{label} is not a JSON object")
    return decoded


@dataclass(frozen=True)
class FormalSnapshot:
    meta: tuple[dict[str, Any], ...]
    samples: tuple[dict[str, Any], ...]
    ending: tuple[dict[str, Any], ...]


def normalized_complete_lines(path: Path, *, frozen: bool) -> list[str]:
    raw = (
        COLLECTOR.stable_regular_file_bytes(path)
        if frozen
        else COLLECTOR.live_regular_file_bytes(path)
    )
    if frozen:
        require(
            not raw or raw[-1:] in (b"\n", b"\r"),
            "frozen QEMU UART ends with a partial line",
        )
    try:
        text = raw.decode("utf-8", errors="strict").replace("\r", "\n")
    except UnicodeDecodeError as error:
        raise DriverError("QEMU UART is not strict UTF-8") from error
    require(
        re.search(r"\bWASM_[A-Z0-9_]+ FAIL\b", text) is None,
        "guest reported a WASM failure",
    )
    lowered = text.lower()
    require(
        "panicked at" not in lowered
        and "[!] fatal" not in lowered
        and "[!] panic" not in lowered,
        "guest reported a panic or fatal error",
    )
    lines = text.splitlines()
    if not frozen and raw and raw[-1:] not in (b"\n", b"\r") and lines:
        lines.pop()
    return [PHASE.normalize_serial_line(line) for line in lines]


def formal_snapshot(path: Path, *, frozen: bool = False) -> FormalSnapshot:
    tagged: list[tuple[str, dict[str, Any]]] = []
    for line in normalized_complete_lines(path, frozen=frozen):
        require(
            re.search(r"\bAUDIT_[A-Z0-9_]+\b", line) is None,
            "diagnostic AUDIT record appeared in a formal QEMU campaign",
        )
        for kind, prefix in (
            ("meta", META_PREFIX),
            ("sample", SAMPLE_PREFIX),
            ("end", END_PREFIX),
        ):
            if prefix not in line:
                continue
            require(
                line.startswith(prefix),
                f"formal {kind} marker does not begin at UART column zero",
            )
            require(
                line.count(prefix) == 1,
                f"formal {kind} line repeats its marker prefix",
            )
            tagged.append((kind, strict_json(line[len(prefix) :], f"formal {kind}")))

    meta = tuple(record for kind, record in tagged if kind == "meta")
    samples = tuple(record for kind, record in tagged if kind == "sample")
    ending = tuple(record for kind, record in tagged if kind == "end")
    require(len(meta) <= 1, f"formal UART emitted {len(meta)} META records")
    require(
        len(samples) <= SAMPLE_COUNT, "formal UART emitted more than 24 SAMPLE records"
    )
    require(len(ending) <= 1, f"formal UART emitted {len(ending)} END records")
    expected_kinds = (
        ["meta"] * len(meta) + ["sample"] * len(samples) + ["end"] * len(ending)
    )
    require(
        [kind for kind, _ in tagged] == expected_kinds,
        "formal META/SAMPLE/END records are out of order",
    )
    return FormalSnapshot(meta, samples, ending)


def validate_snapshot(
    snapshot: FormalSnapshot,
    *,
    source: str,
    challenge: str,
    mode: str,
) -> None:
    require(mode in CAPTURE_MODES, "expected capture mode differs")
    if not snapshot.meta:
        require(
            not snapshot.samples and not snapshot.ending, "SAMPLE/END preceded META"
        )
        return
    meta = snapshot.meta[0]
    expected_meta = {
        "schema": "vibeos.wasm-aot-decision.meta",
        "version": 1,
        "suite_id": SUITE_ID,
        "platform": PLATFORM,
        "platform_class": "emulator",
        "physical_provenance": "not-claimed",
        "source_commit": source,
        "challenge": challenge,
        "capture_mode": mode,
        "decision_eligible": CAPTURE_MODES[mode],
        "required_qemu_boots": 1,
        "samples_per_boot": SAMPLE_COUNT,
        "warmup_per_boot": WARMUP_COUNT,
        "retained_per_boot": RETAINED_COUNT,
        "timebase_hz": TIMEBASE_HZ,
        "budget_ticks": BUDGET_TICKS,
        "workload_id": WORKLOAD_ID,
    }
    for field, value in expected_meta.items():
        require(meta.get(field) == value, f"formal META {field} differs")
    run_id = meta.get("run_id")
    require(
        isinstance(run_id, str) and HEX64.fullmatch(run_id) is not None,
        "formal META run_id differs",
    )

    for index, sample in enumerate(snapshot.samples):
        expected_sample = {
            "schema": "vibeos.wasm-aot-decision.sample",
            "version": 1,
            "sequence": index,
            "sample_index": index,
            "warmup": index < WARMUP_COUNT,
            "run_id": run_id,
            "workload_id": WORKLOAD_ID,
        }
        for field, value in expected_sample.items():
            require(
                sample.get(field) == value, f"formal SAMPLE {index} {field} differs"
            )

    if snapshot.ending:
        require(
            len(snapshot.samples) == SAMPLE_COUNT,
            "formal END preceded all 24 SAMPLE records",
        )
        ending = snapshot.ending[0]
        expected_end = {
            "schema": "vibeos.wasm-aot-decision.end",
            "version": 1,
            "run_id": run_id,
            "challenge": challenge,
            "samples": SAMPLE_COUNT,
            "warmups": WARMUP_COUNT,
            "retained": RETAINED_COUNT,
        }
        for field, value in expected_end.items():
            require(ending.get(field) == value, f"formal END {field} differs")


def wait_for_counts(
    path: Path,
    *,
    meta: int,
    samples: int,
    ending: int,
    source: str,
    challenge: str,
    mode: str,
    timeout: float,
) -> FormalSnapshot:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = formal_snapshot(path)
        validate_snapshot(snapshot, source=source, challenge=challenge, mode=mode)
        observed = (len(snapshot.meta), len(snapshot.samples), len(snapshot.ending))
        expected = (meta, samples, ending)
        require(
            all(actual <= limit for actual, limit in zip(observed, expected)),
            f"formal UART advanced past expected counts {expected}: {observed}",
        )
        if observed == expected:
            return snapshot
        time.sleep(0.05)
    raise DriverError(
        "timed out waiting for formal UART counts "
        f"META={meta} SAMPLE={samples} END={ending}"
    )


def profiled_request(arguments: argparse.Namespace, ssh: str, epoch: int) -> None:
    # Reuse the collector peer's thoroughly exercised request path.  Its epoch-2
    # delayed-stdin helper scans for diagnostic-only UART and therefore cannot
    # be used once a formal META exists; epoch 2 uses the same maintained SSH
    # invocation and exact input/output fixture directly.
    if epoch != 2:
        COLLECTOR.normal_profiled_request(arguments, ssh, epoch)
        return
    PHASE.wait_ready(arguments, ssh)
    result = PHASE.invoke(
        arguments,
        ssh,
        "C8.4 fixed-QEMU AOT decision case-filter epoch 2",
        arguments.accepted_key,
        ["case-filter"],
        input_bytes=PHASE.PEER.CASE_FILTER_INPUT,
    )
    PHASE.PEER.require_result(
        "C8.4 fixed-QEMU AOT decision case-filter epoch 2",
        result,
        {0},
        PHASE.PEER.CASE_FILTER_OUTPUT,
        stderr_exact=b"",
    )


def resolve_ssh_bin(value: Path | None) -> str:
    require(value is not None, "--ssh-bin is required for a live campaign")
    require(value.is_absolute(), "--ssh-bin must be an absolute attested path")
    try:
        metadata = value.lstat()
    except OSError as error:
        raise DriverError(f"cannot inspect --ssh-bin {value}: {error}") from error
    require(
        stat.S_ISREG(metadata.st_mode) and not value.is_symlink(),
        "--ssh-bin must be a regular non-symlink attested file",
    )
    require(metadata.st_nlink == 1, "--ssh-bin must have exactly one hard link")
    require(os.access(value, os.X_OK), "--ssh-bin must be executable")
    return str(value)


def drive(arguments: argparse.Namespace) -> FormalSnapshot:
    require(
        arguments.port is not None and 1 <= arguments.port <= 65535,
        "--port must be in 1..65535",
    )
    require(
        HEX40.fullmatch(arguments.expect_source or "") is not None,
        "--expect-source must be canonical 40-hex",
    )
    require(
        HEX64.fullmatch(arguments.expect_challenge or "") is not None,
        "--expect-challenge must be canonical 64-hex",
    )
    require(
        arguments.expect_mode in CAPTURE_MODES,
        "--expect-mode must be formal-publication or dirty-smoke-not-publication",
    )
    for label, value in (
        ("--accepted-key", arguments.accepted_key),
        ("--rejected-key", arguments.rejected_key),
        ("--known-hosts", arguments.known_hosts),
        ("--host-key-output", arguments.host_key_output),
        ("--qemu-log", arguments.qemu_log),
    ):
        require(value is not None, f"{label} is required")
    for label, timeout in (
        ("--ready-timeout", arguments.ready_timeout),
        ("--command-timeout", arguments.command_timeout),
        ("--marker-timeout", arguments.marker_timeout),
    ):
        require(
            math.isfinite(timeout) and timeout > 0,
            f"{label} must be finite and positive",
        )

    ssh = resolve_ssh_bin(arguments.ssh_bin)
    PHASE.PEER.write_expected_known_hosts(
        arguments.known_hosts, arguments.host, arguments.port
    )
    PHASE.wait_ready(arguments, ssh)
    PHASE.PEER.write_host_key_evidence(arguments.host_key_output)
    wait_for_counts(
        arguments.qemu_log,
        meta=1,
        samples=0,
        ending=0,
        source=arguments.expect_source,
        challenge=arguments.expect_challenge,
        mode=arguments.expect_mode,
        timeout=arguments.marker_timeout,
    )

    for epoch in range(1, SAMPLE_COUNT + 1):
        profiled_request(arguments, ssh, epoch)
        wait_for_counts(
            arguments.qemu_log,
            meta=1,
            samples=epoch,
            ending=int(epoch == SAMPLE_COUNT),
            source=arguments.expect_source,
            challenge=arguments.expect_challenge,
            mode=arguments.expect_mode,
            timeout=arguments.marker_timeout,
        )

    COLLECTOR.rejected_profiled_request(
        arguments, ssh, "C8.4 fixed-QEMU closed collector rejection"
    )
    closed = wait_for_counts(
        arguments.qemu_log,
        meta=1,
        samples=SAMPLE_COUNT,
        ending=1,
        source=arguments.expect_source,
        challenge=arguments.expect_challenge,
        mode=arguments.expect_mode,
        timeout=arguments.marker_timeout,
    )
    time.sleep(0.3)
    after = formal_snapshot(arguments.qemu_log)
    validate_snapshot(
        after,
        source=arguments.expect_source,
        challenge=arguments.expect_challenge,
        mode=arguments.expect_mode,
    )
    require(after == closed, "formal UART changed after the closed-state SSH rejection")
    return after


def synthetic_records(source: str, challenge: str, mode: str) -> bytes:
    require(mode in CAPTURE_MODES, "synthetic capture mode differs")
    run_id = "3" * 64
    meta = {
        "schema": "vibeos.wasm-aot-decision.meta",
        "version": 1,
        "suite_id": SUITE_ID,
        "platform": PLATFORM,
        "platform_class": "emulator",
        "physical_provenance": "not-claimed",
        "source_commit": source,
        "challenge": challenge,
        "capture_mode": mode,
        "decision_eligible": CAPTURE_MODES[mode],
        "required_qemu_boots": 1,
        "samples_per_boot": SAMPLE_COUNT,
        "warmup_per_boot": WARMUP_COUNT,
        "retained_per_boot": RETAINED_COUNT,
        "timebase_hz": TIMEBASE_HZ,
        "budget_ticks": BUDGET_TICKS,
        "workload_id": WORKLOAD_ID,
        "run_id": run_id,
    }
    records = [META_PREFIX + json.dumps(meta, separators=(",", ":"), sort_keys=True)]
    for index in range(SAMPLE_COUNT):
        sample = {
            "schema": "vibeos.wasm-aot-decision.sample",
            "version": 1,
            "sequence": index,
            "sample_index": index,
            "warmup": index < WARMUP_COUNT,
            "run_id": run_id,
            "workload_id": WORKLOAD_ID,
        }
        records.append(
            SAMPLE_PREFIX + json.dumps(sample, separators=(",", ":"), sort_keys=True)
        )
    ending = {
        "schema": "vibeos.wasm-aot-decision.end",
        "version": 1,
        "run_id": run_id,
        "challenge": challenge,
        "samples": SAMPLE_COUNT,
        "warmups": WARMUP_COUNT,
        "retained": RETAINED_COUNT,
    }
    records.append(
        END_PREFIX + json.dumps(ending, separators=(",", ":"), sort_keys=True)
    )
    return ("\n".join(records) + "\n").encode("utf-8")


def selftest() -> int:
    source = "1" * 40
    challenge = "2" * 64
    mutations = 0
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-qemu-decision-peer-"
    ) as directory:
        temporary = Path(directory).resolve(strict=True)
        path = temporary / "uart.log"
        for mode in CAPTURE_MODES:
            raw = synthetic_records(source, challenge, mode)
            path.write_bytes(raw)
            snapshot = formal_snapshot(path, frozen=True)
            validate_snapshot(snapshot, source=source, challenge=challenge, mode=mode)
            require(
                len(snapshot.samples) == SAMPLE_COUNT and len(snapshot.ending) == 1,
                "valid fixture did not close",
            )
            opposite_mode = next(value for value in CAPTURE_MODES if value != mode)
            candidates = (
                raw
                + b"WASM_C84_SSH_MANAGED_CHILD_SINGLE_BOOT_COLLECTOR AUDIT_END formal_uart=0\n",
                raw.replace(b'"warmup":true', b'"warmup":false', 1),
                raw.replace(
                    META_PREFIX.encode(), (META_PREFIX + META_PREFIX).encode(), 1
                ),
                raw.replace(
                    b'"platform":"qemu-virt-rv64-tcg-icount-v1"',
                    b'"platform":"milkv-duo-cv1800b"',
                    1,
                ),
                raw.replace(
                    json.dumps(mode).encode(), json.dumps(opposite_mode).encode(), 1
                ),
                raw.replace(
                    (
                        b'"decision_eligible":true'
                        if CAPTURE_MODES[mode]
                        else b'"decision_eligible":false'
                    ),
                    (
                        b'"decision_eligible":false'
                        if CAPTURE_MODES[mode]
                        else b'"decision_eligible":true'
                    ),
                    1,
                ),
            )
            for mutation in candidates:
                path.write_bytes(mutation)
                try:
                    mutated = formal_snapshot(path, frozen=True)
                    validate_snapshot(
                        mutated, source=source, challenge=challenge, mode=mode
                    )
                except (DriverError, COLLECTOR.DriverError):
                    mutations += 1
                else:
                    raise DriverError(
                        "peer selftest accepted a mutated mode-bound transcript"
                    )
            path.write_bytes(raw)
            try:
                validate_snapshot(
                    formal_snapshot(path, frozen=True),
                    source=source,
                    challenge=challenge,
                    mode=opposite_mode,
                )
            except DriverError:
                mutations += 1
            else:
                raise DriverError("peer selftest accepted a cross-mode transcript")
        ssh = temporary / "ssh"
        ssh.write_bytes(b"synthetic explicit ssh\n")
        ssh.chmod(0o500)
        require(resolve_ssh_bin(ssh) == str(ssh), "valid explicit ssh was rejected")
        relative = Path("relative-ssh")
        nonexec = temporary / "nonexec-ssh"
        nonexec.write_bytes(b"not executable\n")
        nonexec.chmod(0o400)
        symlink = temporary / "symlink-ssh"
        symlink.symlink_to(ssh)
        for candidate in (None, relative, nonexec, symlink):
            try:
                resolve_ssh_bin(candidate)
            except DriverError:
                mutations += 1
            else:
                raise DriverError("peer selftest accepted an unsafe explicit ssh path")
    require(mutations == 18, "peer selftest mutation count differs")
    return mutations


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--selftest", action="store_true")
    value.add_argument("--verify-log-only", action="store_true")
    value.add_argument("--host", default="127.0.0.1")
    value.add_argument("--port", type=int)
    value.add_argument("--user", default="vibe")
    value.add_argument("--accepted-key", type=Path)
    value.add_argument("--rejected-key", type=Path)
    value.add_argument("--known-hosts", type=Path)
    value.add_argument("--host-key-output", type=Path)
    value.add_argument("--qemu-log", type=Path)
    value.add_argument("--ssh-bin", type=Path)
    value.add_argument("--expect-source")
    value.add_argument("--expect-challenge")
    value.add_argument("--expect-mode", choices=tuple(CAPTURE_MODES))
    value.add_argument("--ready-timeout", type=float, default=60.0)
    value.add_argument("--command-timeout", type=float, default=30.0)
    value.add_argument("--marker-timeout", type=float, default=30.0)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        require(
            not (arguments.selftest and arguments.verify_log_only),
            "--selftest and --verify-log-only are mutually exclusive",
        )
        if arguments.selftest:
            mutations = selftest()
            print(f"PASS c84-qemu-aot-decision-peer selftest mutations={mutations}")
            return 0
        if arguments.verify_log_only:
            require(
                arguments.ssh_bin is None,
                "--verify-log-only must not accept a live --ssh-bin",
            )
            require(
                arguments.qemu_log is not None,
                "--qemu-log is required with --verify-log-only",
            )
            require(
                HEX40.fullmatch(arguments.expect_source or "") is not None,
                "--expect-source must be canonical 40-hex",
            )
            require(
                HEX64.fullmatch(arguments.expect_challenge or "") is not None,
                "--expect-challenge must be canonical 64-hex",
            )
            require(
                arguments.expect_mode in CAPTURE_MODES,
                "--expect-mode is required with --verify-log-only",
            )
            snapshot = formal_snapshot(arguments.qemu_log, frozen=True)
            validate_snapshot(
                snapshot,
                source=arguments.expect_source,
                challenge=arguments.expect_challenge,
                mode=arguments.expect_mode,
            )
            require(
                len(snapshot.meta) == 1
                and len(snapshot.samples) == SAMPLE_COUNT
                and len(snapshot.ending) == 1,
                "frozen formal transcript is not closed",
            )
        else:
            snapshot = drive(arguments)
        print(
            SOURCE_CLOSURE_PREFIX
            + json.dumps(
                executed_source_closure(),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        print(
            "PASS c84-qemu-aot-decision-peer: "
            f"META=1 SAMPLE={len(snapshot.samples)} END={len(snapshot.ending)} "
            f"mode={arguments.expect_mode} "
            "fresh_qemu_processes=1 physical_provenance=not-claimed"
        )
        return 0
    except Exception as error:
        print(f"FAIL c84-qemu-aot-decision-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
