#!/usr/bin/env python3
"""Drive and verify the C8.4 private single-cold-boot collector QEMU audit."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import importlib.util
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
TRUSTED_PEER_PATH = ROOT / "scripts/c84-ssh-managed-child-trusted-sample-peer.py"

FAMILY = "WASM_C84_SSH_MANAGED_CHILD_SINGLE_BOOT_COLLECTOR"
TRUSTED_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE"
FINISH_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY"
IRQ_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"
ALLOWED_FAMILIES = frozenset(
    (
        FAMILY,
        TRUSTED_FAMILY,
        FINISH_FAMILY,
        IRQ_FAMILY,
        PHASE_FAMILY,
        CORE_FAMILY,
        REQUEST_FAMILY,
    )
)
FORMAL_PREFIXES = (
    b"VIBE_WASM_AOT_META ",
    b"VIBE_WASM_AOT_SAMPLE ",
    b"VIBE_WASM_AOT_END ",
)
FORMAL_SCHEMA_PAYLOADS = (
    b"vibeos.wasm-aot-decision.meta",
    b"vibeos.wasm-aot-decision.sample",
    b"vibeos.wasm-aot-decision.end",
)

NUMBER = r"(?:0|[1-9][0-9]*)"
POSITIVE = r"(?:[1-9][0-9]*)"
LOWER_SHA256 = r"[0-9a-f]{64}"
U64_MAX = (1 << 64) - 1
MAX_FORMAL_FUEL = 500_000
SAMPLE_COUNT = 24
WARMUP_COUNT = 3
RETAINED_COUNT = 21
SUCCESS_AUDIT_COMMITS = 26
MAX_QEMU_LOG_BYTES = 16 * 1024 * 1024
EXPECTED_META_BYTES = 1157
EXPECTED_META_SHA256 = "6d46aa52ca9155cfed4eae230a00175f4247d950a8a686a8bdb3657dc6954b4b"
COLLECTOR_SUFFIX = "finish=1 verify=1 bundle=trusted collector=consumed ack=0"
TRUSTED_TERMINAL_SUFFIX = "bundle=trusted finish=1 verify=1 collector=consumed ack=0"


def load_trusted_peer():
    spec = importlib.util.spec_from_file_location(
        "vibeos_c84_single_boot_collector_trusted_peer", TRUSTED_PEER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the trusted-sample predecessor peer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TRUSTED = load_trusted_peer()
FINISH = TRUSTED.FINISH
IRQ = TRUSTED.IRQ
PHASE = TRUSTED.PHASE
CORE = PHASE.CORE
REQUEST = TRUSTED.REQUEST


class DriverError(Exception):
    pass


@dataclass(frozen=True)
class AuditMeta:
    bytes_count: int
    sha256: str


@dataclass(frozen=True)
class AuditSample:
    commit: int
    epoch: int
    sequence: int
    warmup: int
    bytes_count: int
    sha256: str
    accumulator: int
    next_sequence: int
    recycled_ready_epoch: int


@dataclass(frozen=True)
class AuditEnd:
    bytes_count: int
    sha256: str
    accumulator: int


@dataclass(frozen=True)
class TrustedObservation:
    epoch: int
    fuel_consumed: int
    poll_quanta: int


@dataclass(frozen=True)
class CoreObservation:
    epoch: int
    core_polls: int
    typed_polls: int


@dataclass(frozen=True)
class SuccessObservation:
    meta: AuditMeta
    samples: tuple[AuditSample, ...]
    ending: AuditEnd


@dataclass(frozen=True)
class FailureObservation:
    meta: AuditMeta
    drop_observer_pairs: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


META_PATTERN = re.compile(
    rf"^{FAMILY} AUDIT_META commit=1 bytes=(?P<bytes>{POSITIVE}) "
    rf"sha256=(?P<sha>{LOWER_SHA256}) next_sequence=0 state=collecting "
    rf"ready_epoch=1 decision_eligible=0 formal_uart=0$"
)

SAMPLE_PATTERN = re.compile(
    rf"^{FAMILY} AUDIT_SAMPLE commit=(?P<commit>{NUMBER}) "
    rf"epoch=(?P<epoch>{NUMBER}) sequence=(?P<sequence>{NUMBER}) "
    rf"warmup=(?P<warmup>[01]) bytes=(?P<bytes>{POSITIVE}) "
    rf"sha256=(?P<sha>{LOWER_SHA256}) accumulator=(?P<accumulator>{NUMBER}) "
    rf"next_sequence=(?P<next_sequence>{NUMBER}) "
    rf"recycled_ready_epoch=(?P<ready>{NUMBER}) state=collecting "
    rf"decision_eligible=0 formal_uart=0$"
)

END_PATTERN = re.compile(
    rf"^{FAMILY} AUDIT_END commit=26 samples=24 warmups=3 retained=21 "
    rf"bytes=(?P<bytes>{POSITIVE}) sha256=(?P<sha>{LOWER_SHA256}) "
    rf"accumulator=(?P<accumulator>{NUMBER}) recycled_ready_epoch=25 "
    rf"state=closed decision_eligible=0 formal_uart=0$"
)

SUCCESS_REJECT_PATTERN = re.compile(
    rf"^{FAMILY} REJECT epoch=25 attempt=25 next_sequence=24 status=126 "
    rf"reason=collector_closed target_started=0 audit_commits=26 state=closed "
    rf"ready_epoch=25 decision_eligible=0 formal_uart=0$"
)

FAILED_PATTERN = re.compile(
    rf"^{FAMILY} FAILED epoch=1 sequence=0 reason=active_target_disconnected "
    rf"target_started=1 sample_committed=0 end_committed=0 audit_commits=1 "
    rf"recycled_ready_epoch=2 state=failed decision_eligible=0 formal_uart=0$"
)

FAILED_REJECT_PATTERN = re.compile(
    rf"^{FAMILY} REJECT epoch=2 attempt=2 next_sequence=0 status=126 "
    rf"reason=collector_failed target_started=0 audit_commits=1 state=failed "
    rf"ready_epoch=2 decision_eligible=0 formal_uart=0$"
)

CORE_RESPONSE = re.compile(
    rf"^{CORE_FAMILY} RESPONSE epoch=(?P<epoch>{NUMBER}) status=0 claim=1 "
    rf"release=1 detach=exited clean=1 core_polls=(?P<core>{NUMBER}) "
    rf"observer_pairs=(?P<pairs>{NUMBER}) typed_polls=(?P<typed>{NUMBER}) "
    rf"observer_closed=1 {re.escape(COLLECTOR_SUFFIX)} "
    rf"ready_epoch=(?P<ready>{NUMBER})$"
)

TRUSTED_RESPONSE = re.compile(
    rf"^{TRUSTED_FAMILY} RESPONSE epoch=(?P<epoch>{NUMBER}) status=0 "
    rf"exact_success=1 full_drain=1 read_chunks=13 write_chunks=13 "
    rf"stdout_bytes=12325 stdout_sha256={TRUSTED.FORMAL_STDOUT_SHA256} "
    rf"fuel_consumed=(?P<fuel>{NUMBER}) poll_quanta=(?P<polls>{NUMBER}) "
    rf"poll_exact=1 logical_live_after=0 timed_out=0 "
    rf"{re.escape(TRUSTED_TERMINAL_SUFFIX)} ready_epoch=(?P<ready>{NUMBER})$"
)


def checked_u64(value: str, label: str, *, positive: bool = False) -> int:
    parsed = int(value)
    minimum = 1 if positive else 0
    require(minimum <= parsed <= U64_MAX, f"{label} is outside canonical u64 range")
    return parsed


def normalized_snapshot(
    raw: bytes, *, ignore_incomplete_tail: bool = False
) -> list[str]:
    for prefix in FORMAL_PREFIXES:
        require(
            prefix not in raw,
            f"QEMU UART leaked formal prefix {prefix.decode().strip()}",
        )
    for payload in FORMAL_SCHEMA_PAYLOADS:
        require(
            payload not in raw,
            f"QEMU UART leaked formal schema payload {payload.decode()}",
        )
    if not ignore_incomplete_tail:
        require(
            not raw or raw[-1:] in (b"\n", b"\r"),
            "frozen UART log ends with a partial line",
        )
    try:
        value = raw.decode("utf-8").replace("\r", "\n")
    except UnicodeDecodeError as error:
        raise DriverError("QEMU UART log is not strict UTF-8") from error
    require(
        re.search(r"\bWASM_[A-Z0-9_]+ FAIL\b", value) is None,
        "guest reported a WASM acceptance failure",
    )
    require(
        "panicked at" not in value
        and "[!] fatal" not in value
        and "[!] panic" not in value,
        "guest reported a panic or fatal error",
    )
    families = frozenset(re.findall(r"\bWASM_[A-Z0-9_]+\b", value))
    foreign = sorted(families - ALLOWED_FAMILIES)
    require(not foreign, f"collector image emitted foreign WASM families: {foreign!r}")
    lines = [PHASE.normalize_serial_line(line) for line in value.splitlines()]
    if ignore_incomplete_tail and raw and raw[-1:] not in (b"\n", b"\r") and lines:
        lines.pop()
    return lines


def stable_regular_file_bytes(path: Path) -> bytes:
    """Read one immutable regular-file snapshot without following a symlink."""

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

    before_path = os.lstat(path)
    require(
        stat.S_ISREG(before_path.st_mode), f"UART log is not a regular file: {path}"
    )
    require(
        before_path.st_size <= MAX_QEMU_LOG_BYTES,
        f"UART log exceeds the {MAX_QEMU_LOG_BYTES}-byte bound: {path}",
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before_fd = os.fstat(descriptor)
        require(
            stat.S_ISREG(before_fd.st_mode), f"opened UART log is not regular: {path}"
        )
        require(
            identity(before_path) == identity(before_fd),
            f"UART log changed between lstat and open: {path}",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, MAX_QEMU_LOG_BYTES - total + 1)
            )
            if not chunk:
                break
            total += len(chunk)
            require(
                total <= MAX_QEMU_LOG_BYTES,
                f"UART log exceeds the {MAX_QEMU_LOG_BYTES}-byte bound: {path}",
            )
            chunks.append(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    require(
        identity(before_fd) == identity(after_fd) == identity(after_path),
        f"UART log changed during stable read: {path}",
    )
    raw = b"".join(chunks)
    require(len(raw) == after_fd.st_size, f"UART log size changed during read: {path}")
    return raw


def live_regular_file_bytes(path: Path) -> bytes:
    """Read one bounded append-in-progress UART snapshot without symlinks."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode), f"UART log is not regular: {path}")
        require(
            opened.st_size <= MAX_QEMU_LOG_BYTES,
            f"UART log exceeds the {MAX_QEMU_LOG_BYTES}-byte bound: {path}",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, MAX_QEMU_LOG_BYTES - total + 1)
            )
            if not chunk:
                break
            total += len(chunk)
            require(
                total <= MAX_QEMU_LOG_BYTES,
                f"UART log exceeds the {MAX_QEMU_LOG_BYTES}-byte bound: {path}",
            )
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def normalized_lines(
    path: Path,
    *,
    ignore_incomplete_tail: bool = False,
    stable: bool = False,
) -> list[str]:
    raw = stable_regular_file_bytes(path) if stable else live_regular_file_bytes(path)
    return normalized_snapshot(raw, ignore_incomplete_tail=ignore_incomplete_tail)


def family_markers(
    path: Path,
    family: str = FAMILY,
    *,
    ignore_incomplete_tail: bool = False,
) -> list[str]:
    return [
        line
        for line in normalized_lines(
            path, ignore_incomplete_tail=ignore_incomplete_tail
        )
        if family in line
    ]


def markers_for(lines: list[str], family: str) -> list[str]:
    return [line for line in lines if family in line]


def parse_meta(line: str) -> AuditMeta:
    match = META_PATTERN.fullmatch(line)
    require(match is not None, f"collector AUDIT_META differs: {line!r}")
    assert match is not None
    observation = AuditMeta(
        checked_u64(match.group("bytes"), "AUDIT_META bytes", positive=True),
        match.group("sha"),
    )
    require(
        observation
        == AuditMeta(EXPECTED_META_BYTES, EXPECTED_META_SHA256),
        "AUDIT_META differs from the frozen QEMU sentinel known-answer record",
    )
    return observation


def parse_sample(line: str, sequence: int) -> AuditSample:
    match = SAMPLE_PATTERN.fullmatch(line)
    require(match is not None, f"collector sample {sequence} audit differs: {line!r}")
    assert match is not None
    observation = AuditSample(
        checked_u64(match.group("commit"), f"sample {sequence} commit"),
        checked_u64(match.group("epoch"), f"sample {sequence} epoch"),
        checked_u64(match.group("sequence"), f"sample {sequence} sequence"),
        int(match.group("warmup")),
        checked_u64(match.group("bytes"), f"sample {sequence} bytes", positive=True),
        match.group("sha"),
        checked_u64(match.group("accumulator"), f"sample {sequence} accumulator"),
        checked_u64(match.group("next_sequence"), f"sample {sequence} next sequence"),
        checked_u64(match.group("ready"), f"sample {sequence} Ready epoch"),
    )
    epoch = sequence + 1
    require(
        observation.commit == sequence + 2, f"sample {sequence} commit chain differs"
    )
    require(observation.epoch == epoch, f"sample {sequence} epoch differs")
    require(observation.sequence == sequence, f"sample {sequence} sequence differs")
    require(
        observation.warmup == int(sequence < WARMUP_COUNT),
        f"sample {sequence} warmup classification differs",
    )
    require(
        observation.next_sequence == sequence + 1,
        f"sample {sequence} next sequence differs",
    )
    require(
        observation.recycled_ready_epoch == epoch + 1,
        f"sample {sequence} Ready reuse differs",
    )
    return observation


def parse_end(line: str, final_accumulator: int) -> AuditEnd:
    match = END_PATTERN.fullmatch(line)
    require(match is not None, f"collector AUDIT_END differs: {line!r}")
    assert match is not None
    ending = AuditEnd(
        checked_u64(match.group("bytes"), "AUDIT_END bytes", positive=True),
        match.group("sha"),
        checked_u64(match.group("accumulator"), "AUDIT_END accumulator"),
    )
    require(
        ending.accumulator == final_accumulator,
        "AUDIT_END accumulator differs from sample 23",
    )
    return ending


def parse_core_response(line: str, epoch: int) -> CoreObservation:
    match = CORE_RESPONSE.fullmatch(line)
    require(
        match is not None, f"collector Core epoch {epoch} RESPONSE differs: {line!r}"
    )
    assert match is not None
    observed_epoch = checked_u64(match.group("epoch"), f"Core epoch {epoch}")
    core_polls = checked_u64(
        match.group("core"), f"Core epoch {epoch} polls", positive=True
    )
    pairs = checked_u64(
        match.group("pairs"), f"Core epoch {epoch} observer pairs", positive=True
    )
    typed = checked_u64(
        match.group("typed"), f"Core epoch {epoch} typed polls", positive=True
    )
    ready = checked_u64(match.group("ready"), f"Core epoch {epoch} Ready epoch")
    require(observed_epoch == epoch, f"Core epoch {epoch} RESPONSE epoch differs")
    require(ready == epoch + 1, f"Core epoch {epoch} Ready reuse differs")
    require(
        core_polls == pairs <= typed < U64_MAX,
        f"Core epoch {epoch} poll relation differs",
    )
    return CoreObservation(epoch, core_polls, typed)


def parse_trusted_response(line: str, epoch: int) -> TrustedObservation:
    match = TRUSTED_RESPONSE.fullmatch(line)
    require(
        match is not None, f"collector trusted epoch {epoch} RESPONSE differs: {line!r}"
    )
    assert match is not None
    observed_epoch = checked_u64(match.group("epoch"), f"trusted epoch {epoch}")
    fuel = checked_u64(
        match.group("fuel"), f"trusted epoch {epoch} fuel", positive=True
    )
    polls = checked_u64(
        match.group("polls"), f"trusted epoch {epoch} polls", positive=True
    )
    ready = checked_u64(match.group("ready"), f"trusted epoch {epoch} Ready epoch")
    require(observed_epoch == epoch, f"trusted epoch {epoch} RESPONSE epoch differs")
    require(
        fuel <= MAX_FORMAL_FUEL, f"trusted epoch {epoch} fuel exceeds formal budget"
    )
    require(polls < U64_MAX, f"trusted epoch {epoch} poll count is saturated")
    require(ready == epoch + 1, f"trusted epoch {epoch} Ready reuse differs")
    return TrustedObservation(epoch, fuel, polls)


def collector_to_verified(line: str) -> str:
    require(
        line.count(COLLECTOR_SUFFIX) == 1,
        f"collector predecessor success suffix differs: {line!r}",
    )
    return line.replace(COLLECTOR_SUFFIX, TRUSTED.VERIFIED_SUFFIX, 1)


def request_start_line(epoch: int) -> str:
    return f"{REQUEST_FAMILY} START epoch={epoch}"


def request_response_line(epoch: int) -> str:
    return (
        f"{REQUEST_FAMILY} RESPONSE epoch={epoch} status=0 {COLLECTOR_SUFFIX} "
        f"ready_epoch={epoch + 1}"
    )


def irq_response_line(epoch: int) -> str:
    first = int(epoch == 1)
    return (
        f"{IRQ_FAMILY} RESPONSE epoch={epoch} status=0 parent_pair={first} "
        f"child_pair={first} terminal_inactive=1 paired=2 inactive={epoch} "
        f"active_epoch=0 {COLLECTOR_SUFFIX} ready_epoch={epoch + 1}"
    )


def finish_response_line(epoch: int) -> str:
    return (
        f"{FINISH_FAMILY} RESPONSE epoch={epoch} status=0 {COLLECTOR_SUFFIX} "
        f"ready_epoch={epoch + 1}"
    )


def trusted_response_line(epoch: int, fuel: int, polls: int) -> str:
    return (
        f"{TRUSTED_FAMILY} RESPONSE epoch={epoch} status=0 exact_success=1 "
        "full_drain=1 read_chunks=13 write_chunks=13 stdout_bytes=12325 "
        f"stdout_sha256={TRUSTED.FORMAL_STDOUT_SHA256} fuel_consumed={fuel} "
        f"poll_quanta={polls} poll_exact=1 logical_live_after=0 timed_out=0 "
        f"{TRUSTED_TERMINAL_SUFFIX} ready_epoch={epoch + 1}"
    )


def meta_line(bytes_count: int, sha256: str) -> str:
    return (
        f"{FAMILY} AUDIT_META commit=1 bytes={bytes_count} sha256={sha256} "
        "next_sequence=0 state=collecting ready_epoch=1 decision_eligible=0 formal_uart=0"
    )


def sample_line(
    sequence: int,
    *,
    bytes_count: int,
    sha256: str,
    accumulator: int,
) -> str:
    epoch = sequence + 1
    return (
        f"{FAMILY} AUDIT_SAMPLE commit={sequence + 2} epoch={epoch} "
        f"sequence={sequence} warmup={int(sequence < WARMUP_COUNT)} "
        f"bytes={bytes_count} sha256={sha256} accumulator={accumulator} "
        f"next_sequence={sequence + 1} recycled_ready_epoch={epoch + 1} "
        "state=collecting decision_eligible=0 formal_uart=0"
    )


def end_line(bytes_count: int, sha256: str, accumulator: int) -> str:
    return (
        f"{FAMILY} AUDIT_END commit=26 samples=24 warmups=3 retained=21 "
        f"bytes={bytes_count} sha256={sha256} accumulator={accumulator} "
        "recycled_ready_epoch=25 state=closed decision_eligible=0 formal_uart=0"
    )


def success_reject_line() -> str:
    return (
        f"{FAMILY} REJECT epoch=25 attempt=25 next_sequence=24 status=126 "
        "reason=collector_closed target_started=0 audit_commits=26 state=closed "
        "ready_epoch=25 decision_eligible=0 formal_uart=0"
    )


def failed_line() -> str:
    return (
        f"{FAMILY} FAILED epoch=1 sequence=0 reason=active_target_disconnected "
        "target_started=1 sample_committed=0 end_committed=0 audit_commits=1 "
        "recycled_ready_epoch=2 state=failed decision_eligible=0 formal_uart=0"
    )


def failed_reject_line() -> str:
    return (
        f"{FAMILY} REJECT epoch=2 attempt=2 next_sequence=0 status=126 "
        "reason=collector_failed target_started=0 audit_commits=1 state=failed "
        "ready_epoch=2 decision_eligible=0 formal_uart=0"
    )


def require_unique_order(lines: list[str], needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [
            index
            for index, line in enumerate(lines)
            if (line.startswith(needle) if needle.endswith(" ") else line == needle)
        ]
        require(
            len(matches) == 1, f"{label} count differs for {needle!r}: {len(matches)}"
        )
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs")


def verify_success_predecessors(
    lines: list[str], samples: tuple[AuditSample, ...]
) -> tuple[CoreObservation, ...]:
    phase_markers = markers_for(lines, PHASE_FAMILY)
    core_markers = markers_for(lines, CORE_FAMILY)
    request_markers = markers_for(lines, REQUEST_FAMILY)
    irq_markers = markers_for(lines, IRQ_FAMILY)
    finish_markers = markers_for(lines, FINISH_FAMILY)
    trusted_markers = markers_for(lines, TRUSTED_FAMILY)

    require(len(phase_markers) == 169, "success phase predecessor count differs")
    require(len(core_markers) == 120, "success Core predecessor count differs")
    require(len(request_markers) == 48, "success request predecessor count differs")
    require(len(irq_markers) == 26, "success IRQ predecessor count differs")
    require(len(finish_markers) == 24, "success finish predecessor count differs")
    require(len(trusted_markers) == 24, "success trusted predecessor count differs")

    phase_cursor = 0
    core_cursor = 0
    core_observations: list[CoreObservation] = []
    trusted_observations: list[TrustedObservation] = []
    for epoch in range(1, SAMPLE_COUNT + 1):
        phase_count = 8 if epoch == 2 else 7
        phase = PHASE.parse_normal_transaction(
            [
                collector_to_verified(line)
                if line.startswith(f"{PHASE_FAMILY} RESPONSE ")
                else line
                for line in phase_markers[phase_cursor : phase_cursor + phase_count]
            ],
            epoch,
            TRUSTED.PREDECESSOR_MODE,
        )
        phase_cursor += phase_count

        core = core_markers[core_cursor : core_cursor + 5]
        expected_core_prefix = [
            f"{CORE_FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
            f"{CORE_FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
            f"{CORE_FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
            f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
        ]
        require(
            core[:4] == expected_core_prefix,
            f"success Core epoch {epoch} sequence differs",
        )
        core_observation = parse_core_response(core[4], epoch)
        core_observations.append(core_observation)
        core_cursor += 5
        require(
            phase.counters.child_core_starts == core_observation.core_polls
            and phase.counters.child_core_finishes == core_observation.core_polls,
            f"success phase/Core epoch {epoch} counts diverge",
        )

        expected_request = [request_start_line(epoch), request_response_line(epoch)]
        require(
            request_markers[(epoch - 1) * 2 : epoch * 2] == expected_request,
            f"success request epoch {epoch} sequence differs",
        )
        trusted = parse_trusted_response(trusted_markers[epoch - 1], epoch)
        trusted_observations.append(trusted)
        require(
            trusted.poll_quanta == core_observation.typed_polls,
            f"success trusted/Core epoch {epoch} polls diverge",
        )
        require(
            finish_markers[epoch - 1] == finish_response_line(epoch),
            f"success finish epoch {epoch} differs",
        )

    require(phase_cursor == len(phase_markers), "late success phase markers")
    require(core_cursor == len(core_markers), "late success Core markers")
    expected_irq = [
        f"{IRQ_FAMILY} PARENT_SSIP epoch=1 causal=1 paired=1 inactive=0 active_epoch=1",
        f"{IRQ_FAMILY} CHILD_SSIP epoch=1 causal=1 paired=2 inactive=0 active_epoch=1",
        *(irq_response_line(epoch) for epoch in range(1, SAMPLE_COUNT + 1)),
    ]
    require(irq_markers == expected_irq, "success IRQ predecessor sequence differs")

    for epoch in range(1, SAMPLE_COUNT + 1):
        sample = samples[epoch - 1]
        require_unique_order(
            lines,
            [
                f"{PHASE_FAMILY} CHILD_PHASE epoch={epoch} phase=cleanup",
                f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
                f"{PHASE_FAMILY} EXITED epoch={epoch} detach=exited release=1",
                f"{PHASE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                core_markers[(epoch - 1) * 5 + 4],
                request_response_line(epoch),
                irq_response_line(epoch),
                finish_response_line(epoch),
                trusted_markers[epoch - 1],
                sample_line(
                    sample.sequence,
                    bytes_count=sample.bytes_count,
                    sha256=sample.sha256,
                    accumulator=sample.accumulator,
                ),
            ],
            f"success epoch {epoch} terminal chain",
        )
        if epoch < SAMPLE_COUNT:
            require_unique_order(
                lines,
                [
                    sample_line(
                        sample.sequence,
                        bytes_count=sample.bytes_count,
                        sha256=sample.sha256,
                        accumulator=sample.accumulator,
                    ),
                    request_start_line(epoch + 1),
                ],
                f"success epoch {epoch} collector closure before reuse",
            )

    require_unique_order(
        lines,
        [
            request_start_line(1),
            expected_irq[0],
            f"{CORE_FAMILY} CLAIM epoch=1 child_index=0 first_poll=1",
            f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=abi",
            expected_irq[1],
            f"{CORE_FAMILY} CORE epoch=1 ordinary=1 first_pair=1",
            f"{PHASE_FAMILY} CHILD_WAIT epoch=1 state=open first=1",
        ],
        "success epoch-1 causal SSIP",
    )
    return tuple(core_observations)


def verify_failure_predecessors(lines: list[str]) -> int:
    phase_markers = markers_for(lines, PHASE_FAMILY)
    core_markers = markers_for(lines, CORE_FAMILY)
    request_markers = markers_for(lines, REQUEST_FAMILY)
    irq_markers = markers_for(lines, IRQ_FAMILY)
    finish_markers = markers_for(lines, FINISH_FAMILY)
    trusted_markers = markers_for(lines, TRUSTED_FAMILY)

    require(len(phase_markers) in (5, 6), "failure phase predecessor count differs")
    require(len(core_markers) == 4, "failure Core predecessor count differs")
    require(len(request_markers) == 2, "failure request predecessor count differs")
    require(len(irq_markers) == 3, "failure IRQ predecessor count differs")
    require(len(finish_markers) == 1, "failure finish predecessor count differs")
    require(len(trusted_markers) == 1, "failure trusted predecessor count differs")

    phase = PHASE.parse_drop_transaction(phase_markers, 1)
    core = CORE.parse_drop_transaction(core_markers, 1)
    require(
        phase.counters.child_core_starts == core.observer_pairs
        and phase.counters.child_core_finishes == core.observer_pairs,
        "failure phase/Core observer counts diverge",
    )
    require(
        request_markers
        == [
            request_start_line(1),
            f"{REQUEST_FAMILY} DROP epoch=1 cancel=1 ack=1 ready_epoch=2",
        ],
        "failure request predecessor sequence differs",
    )
    expected_irq = [
        f"{IRQ_FAMILY} PARENT_SSIP epoch=1 causal=1 paired=1 inactive=0 active_epoch=1",
        f"{IRQ_FAMILY} CHILD_SSIP epoch=1 causal=1 paired=2 inactive=0 active_epoch=1",
        IRQ.drop_line(1),
    ]
    require(irq_markers == expected_irq, "failure IRQ predecessor sequence differs")
    require(
        finish_markers == [FINISH.drop_line(1)], "failure finish predecessor differs"
    )
    require(
        trusted_markers == [TRUSTED.drop_line(1)], "failure trusted predecessor differs"
    )

    require_unique_order(
        lines,
        [
            request_start_line(1),
            expected_irq[0],
            f"{CORE_FAMILY} CLAIM epoch=1 child_index=0 first_poll=1",
            f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=abi",
            expected_irq[1],
            f"{CORE_FAMILY} CORE epoch=1 ordinary=1 first_pair=1",
            f"{PHASE_FAMILY} CHILD_WAIT epoch=1 state=open first=1",
            phase_markers[-1],
            core_markers[-1],
            request_markers[-1],
            irq_markers[-1],
            finish_markers[-1],
            trusted_markers[-1],
            failed_line(),
            failed_reject_line(),
        ],
        "failure terminal chain",
    )
    return core.observer_pairs


def verify_success(path: Path) -> SuccessObservation:
    lines = normalized_lines(path, stable=True)
    collector = markers_for(lines, FAMILY)
    require(
        len(collector) == 27,
        f"success collector marker count differs: {len(collector)}",
    )
    meta = parse_meta(collector[0])
    samples = tuple(
        parse_sample(collector[index + 1], index) for index in range(SAMPLE_COUNT)
    )
    ending = parse_end(collector[25], samples[-1].accumulator)
    record_digests = [meta.sha256, *(sample.sha256 for sample in samples), ending.sha256]
    require(
        len(set(record_digests)) == len(record_digests),
        "META, 24 ordered SAMPLE records, and END must have distinct audit digests",
    )
    require(
        SUCCESS_REJECT_PATTERN.fullmatch(collector[26]) is not None,
        f"success closed rejection differs: {collector[26]!r}",
    )
    verify_success_predecessors(lines, samples)
    require_unique_order(
        lines,
        [
            collector[0],
            request_start_line(1),
            collector[24],
            collector[25],
            collector[26],
        ],
        "success META/last-sample/END/closed order",
    )
    return SuccessObservation(meta, samples, ending)


def verify_failure(path: Path) -> FailureObservation:
    lines = normalized_lines(path, stable=True)
    collector = markers_for(lines, FAMILY)
    require(
        len(collector) == 3, f"failure collector marker count differs: {len(collector)}"
    )
    meta = parse_meta(collector[0])
    require(
        FAILED_PATTERN.fullmatch(collector[1]) is not None,
        f"FAILED marker differs: {collector[1]!r}",
    )
    require(
        FAILED_REJECT_PATTERN.fullmatch(collector[2]) is not None,
        f"failed-state rejection differs: {collector[2]!r}",
    )
    pairs = verify_failure_predecessors(lines)
    require_unique_order(
        lines,
        [collector[0], request_start_line(1), collector[1], collector[2]],
        "failure META/fail/reject order",
    )
    return FailureObservation(meta, pairs)


def verify_pair(
    failure_path: Path, success_path: Path
) -> tuple[FailureObservation, SuccessObservation]:
    failure = verify_failure(failure_path)
    success = verify_success(success_path)
    require(
        failure.meta == success.meta,
        "same-image failure/success boots emitted different META audit receipts",
    )
    return failure, success


def wait_for_collector_count(path: Path, expected: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = family_markers(path, ignore_incomplete_tail=True)
        require(
            len(observed) <= expected,
            f"collector emitted an early marker: {observed!r}",
        )
        if len(observed) == expected:
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for collector marker {expected}")


def normal_profiled_request(
    arguments: argparse.Namespace,
    ssh: str,
    epoch: int,
) -> None:
    PHASE.wait_ready(arguments, ssh)
    if epoch == 2:
        result = PHASE.delayed_stdin_request(arguments, ssh, epoch)
    else:
        result = PHASE.invoke(
            arguments,
            ssh,
            f"C8.4 single-boot collector case-filter epoch {epoch}",
            arguments.accepted_key,
            ["case-filter"],
            input_bytes=PHASE.PEER.CASE_FILTER_INPUT,
            verbose=epoch == 1,
        )
    PHASE.PEER.require_result(
        f"C8.4 single-boot collector case-filter epoch {epoch}",
        result,
        {0},
        PHASE.PEER.CASE_FILTER_OUTPUT,
        stderr_exact=None if epoch == 1 else b"",
    )
    if epoch == 1:
        PHASE.PEER.require_negotiated_profile(result)
        PHASE.PEER.require_expected_host_identity(result)


def rejected_profiled_request(
    arguments: argparse.Namespace,
    ssh: str,
    label: str,
) -> None:
    PHASE.wait_ready(arguments, ssh)
    result = PHASE.invoke(
        arguments,
        ssh,
        label,
        arguments.accepted_key,
        ["case-filter"],
        input_bytes=PHASE.PEER.CASE_FILTER_INPUT,
    )
    PHASE.PEER.require_result(label, result, {126}, b"", stderr_exact=b"")


def drive(arguments: argparse.Namespace) -> None:
    require(arguments.scenario in ("success", "failure"), "--scenario is required")
    require(
        arguments.port is not None and 1 <= arguments.port <= 65535,
        "--port must be in 1..65535",
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
    ssh = shutil.which("ssh")
    require(ssh is not None, "OpenSSH ssh is required")
    PHASE.PEER.write_expected_known_hosts(
        arguments.known_hosts, arguments.host, arguments.port
    )
    PHASE.wait_ready(arguments, ssh)
    PHASE.PEER.write_host_key_evidence(arguments.host_key_output)
    wait_for_collector_count(arguments.qemu_log, 1, arguments.marker_timeout)
    require(
        all(
            not family_markers(arguments.qemu_log, family)
            for family in (
                PHASE_FAMILY,
                CORE_FAMILY,
                REQUEST_FAMILY,
                IRQ_FAMILY,
                FINISH_FAMILY,
                TRUSTED_FAMILY,
            )
        ),
        "readiness armed a collector predecessor",
    )
    before_inert = family_markers(arguments.qemu_log)
    PHASE.inert_probes(arguments, ssh)
    require(
        family_markers(arguments.qemu_log) == before_inert,
        "inert probes changed collector audit",
    )

    if arguments.scenario == "failure":
        PHASE.active_drop_request(arguments, ssh, 1)
        wait_for_collector_count(arguments.qemu_log, 2, arguments.marker_timeout)
        predecessor_before = {
            family: family_markers(arguments.qemu_log, family)
            for family in ALLOWED_FAMILIES - {FAMILY}
        }
        rejected_profiled_request(
            arguments,
            ssh,
            "C8.4 failed single-boot collector rejection",
        )
        wait_for_collector_count(arguments.qemu_log, 3, arguments.marker_timeout)
        for family, before in predecessor_before.items():
            require(
                family_markers(arguments.qemu_log, family) == before,
                f"failed rejection re-entered predecessor {family}",
            )
        time.sleep(0.3)
        verify_failure(arguments.qemu_log)
        return

    for epoch in range(1, SAMPLE_COUNT + 1):
        normal_profiled_request(arguments, ssh, epoch)
        expected = 1 + epoch + int(epoch == SAMPLE_COUNT)
        wait_for_collector_count(arguments.qemu_log, expected, arguments.marker_timeout)
    predecessor_before = {
        family: family_markers(arguments.qemu_log, family)
        for family in ALLOWED_FAMILIES - {FAMILY}
    }
    rejected_profiled_request(
        arguments,
        ssh,
        "C8.4 closed single-boot collector rejection",
    )
    wait_for_collector_count(arguments.qemu_log, 27, arguments.marker_timeout)
    for family, before in predecessor_before.items():
        require(
            family_markers(arguments.qemu_log, family) == before,
            f"closed rejection re-entered predecessor {family}",
        )
    time.sleep(0.3)
    verify_success(arguments.qemu_log)


def collector_core_line(epoch: int, core_polls: int, typed_polls: int) -> str:
    return (
        f"{CORE_FAMILY} RESPONSE epoch={epoch} status=0 claim=1 release=1 "
        f"detach=exited clean=1 core_polls={core_polls} observer_pairs={core_polls} "
        f"typed_polls={typed_polls} observer_closed=1 {COLLECTOR_SUFFIX} "
        f"ready_epoch={epoch + 1}"
    )


def collector_phase_lines(epoch: int, core_polls: int) -> list[str]:
    baseline = PHASE.DELAYED_CORE_POLLS if epoch == 2 else CORE.EXPECTED_CORE_POLLS
    line = PHASE.response_line(epoch, TRUSTED.PREDECESSOR_MODE)
    old = f"child_core_starts={baseline} child_core_finishes={baseline}"
    new = f"child_core_starts={core_polls} child_core_finishes={core_polls}"
    require(line.count(old) == 1, "synthetic phase baseline differs")
    line = line.replace(old, new, 1)
    line = line.replace(TRUSTED.VERIFIED_SUFFIX, COLLECTOR_SUFFIX, 1)
    output = PHASE.normal_lines(epoch, TRUSTED.PREDECESSOR_MODE)
    output[-1] = line
    return output


def synthetic_success_lines(
    *,
    meta_sha: str = EXPECTED_META_SHA256,
    final_accumulator: int = U64_MAX,
) -> list[str]:
    output = [meta_line(EXPECTED_META_BYTES, meta_sha)]
    for epoch in range(1, SAMPLE_COUNT + 1):
        sequence = epoch - 1
        typed_polls = 1 if epoch == 1 else (U64_MAX - 1 if epoch == 2 else 900 + epoch)
        baseline = PHASE.DELAYED_CORE_POLLS if epoch == 2 else CORE.EXPECTED_CORE_POLLS
        core_polls = min(baseline, typed_polls)
        phase = collector_phase_lines(epoch, core_polls)
        core = [
            f"{CORE_FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
            f"{CORE_FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
            f"{CORE_FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
            f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
            collector_core_line(epoch, core_polls, typed_polls),
        ]
        output.append(request_start_line(epoch))
        if epoch == 1:
            output.append(
                f"{IRQ_FAMILY} PARENT_SSIP epoch=1 causal=1 paired=1 inactive=0 active_epoch=1"
            )
        output.extend(core[:2])
        output.extend(phase[:3])
        if epoch == 1:
            output.append(
                f"{IRQ_FAMILY} CHILD_SSIP epoch=1 causal=1 paired=2 inactive=0 active_epoch=1"
            )
        output.append(core[2])
        phase_prefix = 5 if epoch == 2 else 4
        output.extend(phase[3:phase_prefix])
        output.append(phase[phase_prefix])
        output.append(core[3])
        output.extend(phase[phase_prefix + 1 :])
        output.append(core[4])
        output.append(request_response_line(epoch))
        output.append(irq_response_line(epoch))
        output.append(finish_response_line(epoch))
        output.append(
            trusted_response_line(epoch, min(epoch, MAX_FORMAL_FUEL), typed_polls)
        )
        accumulator = (
            final_accumulator if sequence == SAMPLE_COUNT - 1 else sequence * 17
        )
        output.append(
            sample_line(
                sequence,
                bytes_count=1300 + sequence,
                sha256=f"{sequence + 1:064x}",
                accumulator=accumulator,
            )
        )
    output.append(end_line(311, "b" * 64, final_accumulator))
    output.append(success_reject_line())
    return output


def synthetic_failure_lines(
    *,
    meta_sha: str = EXPECTED_META_SHA256,
    drop_observer_pairs: int = 14,
    cleanup: bool = False,
) -> list[str]:
    phase = [
        f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=validation",
        f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=instantiation",
        f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=abi",
        f"{PHASE_FAMILY} CHILD_WAIT epoch=1 state=open first=1",
    ]
    if cleanup:
        phase.append(f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=cleanup")
    phase_terminal = PHASE.drop_line(1, drop_observer_pairs)
    if cleanup:
        phase_terminal = phase_terminal.replace("cleanup_count=0", "cleanup_count=1", 1)
    phase.append(phase_terminal)
    core = [
        f"{CORE_FAMILY} BIND epoch=1 child_index=0 before_publish=1",
        f"{CORE_FAMILY} CLAIM epoch=1 child_index=0 first_poll=1",
        f"{CORE_FAMILY} CORE epoch=1 ordinary=1 first_pair=1",
        CORE.drop_response_line(1, drop_observer_pairs),
    ]
    output = [
        meta_line(EXPECTED_META_BYTES, meta_sha),
        request_start_line(1),
        f"{IRQ_FAMILY} PARENT_SSIP epoch=1 causal=1 paired=1 inactive=0 active_epoch=1",
        *core[:2],
        *phase[:3],
        f"{IRQ_FAMILY} CHILD_SSIP epoch=1 causal=1 paired=2 inactive=0 active_epoch=1",
        core[2],
        phase[3],
        *phase[4:],
        core[3],
        f"{REQUEST_FAMILY} DROP epoch=1 cancel=1 ack=1 ready_epoch=2",
        IRQ.drop_line(1),
        FINISH.drop_line(1),
        TRUSTED.drop_line(1),
        failed_line(),
        failed_reject_line(),
    ]
    return output


EXPECTED_EXCEPTIONS = (
    DriverError,
    TRUSTED.DriverError,
    FINISH.DriverError,
    IRQ.DriverError,
    PHASE.DriverError,
    CORE.DriverError,
    REQUEST.VerificationError,
)


def run_parser_selftest() -> int:
    success = synthetic_success_lines()
    failure = synthetic_failure_lines()
    mutations = 0
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-single-boot-collector-peer-"
    ) as directory:
        success_log = Path(directory) / "success.log"
        failure_log = Path(directory) / "failure.log"

        def write(path: Path, lines: list[str]) -> None:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        write(success_log, success)
        write(failure_log, failure)
        verified_failure, verified_success = verify_pair(failure_log, success_log)
        require(
            verified_failure.meta == verified_success.meta,
            "synthetic pair META differs",
        )
        require(
            verify_failure_from_lines(synthetic_failure_lines(cleanup=True)),
            "optional failure cleanup was rejected",
        )

        partial = sample_line(0, bytes_count=1300, sha256=f"{1:064x}", accumulator=0)[
            :-9
        ]
        live = normalized_snapshot(
            (meta_line(877, "a" * 64) + "\n" + partial).encode(),
            ignore_incomplete_tail=True,
        )
        require(
            markers_for(live, FAMILY) == [meta_line(877, "a" * 64)],
            "live parser admitted partial audit",
        )

        def rejected_raw(label: str, raw: bytes) -> None:
            nonlocal mutations
            mutations += 1
            try:
                normalized_snapshot(raw)
            except DriverError:
                return
            raise DriverError(f"raw-log selftest mutation was accepted: {label}")

        rejected_raw("partial frozen tail", meta_line(877, "a" * 64).encode())
        rejected_raw("invalid UTF-8", b"boot \xff\n")
        for payload in FORMAL_SCHEMA_PAYLOADS:
            rejected_raw("formal schema payload", b"noise " + payload + b"\n")

        symlink_log = Path(directory) / "symlink.log"
        symlink_log.symlink_to(success_log.name)
        mutations += 1
        try:
            stable_regular_file_bytes(symlink_log)
        except DriverError:
            pass
        else:
            raise DriverError("stable reader followed a UART-log symlink")
        mutations += 1
        try:
            stable_regular_file_bytes(Path(directory))
        except DriverError:
            pass
        else:
            raise DriverError("stable reader accepted a special UART-log path")

        oversized_log = Path(directory) / "oversized.log"
        with oversized_log.open("wb") as stream:
            stream.truncate(MAX_QEMU_LOG_BYTES + 1)
        for label, reader in (
            ("stable", stable_regular_file_bytes),
            ("live", live_regular_file_bytes),
        ):
            mutations += 1
            try:
                reader(oversized_log)
            except DriverError:
                pass
            else:
                raise DriverError(f"{label} reader accepted an oversized UART log")

        def rejected_success(label: str, candidate: list[str]) -> None:
            nonlocal mutations
            mutations += 1
            write(success_log, candidate)
            try:
                verify_success(success_log)
            except EXPECTED_EXCEPTIONS:
                return
            raise DriverError(f"success selftest mutation was accepted: {label}")

        def rejected_failure(label: str, candidate: list[str]) -> None:
            nonlocal mutations
            mutations += 1
            write(failure_log, candidate)
            try:
                verify_failure(failure_log)
            except EXPECTED_EXCEPTIONS:
                return
            raise DriverError(f"failure selftest mutation was accepted: {label}")

        def replace_success(label: str, old: str, new: str) -> None:
            candidate = list(success)
            require(
                candidate.count(old) == 1, f"success selftest seed differs for {label}"
            )
            candidate[candidate.index(old)] = new
            rejected_success(label, candidate)

        def replace_failure(label: str, old: str, new: str) -> None:
            candidate = list(failure)
            require(
                candidate.count(old) == 1, f"failure selftest seed differs for {label}"
            )
            candidate[candidate.index(old)] = new
            rejected_failure(label, candidate)

        meta = meta_line(EXPECTED_META_BYTES, EXPECTED_META_SHA256)
        first = sample_line(0, bytes_count=1300, sha256=f"{1:064x}", accumulator=0)
        second = sample_line(1, bytes_count=1301, sha256=f"{2:064x}", accumulator=17)
        fourth = sample_line(3, bytes_count=1303, sha256=f"{4:064x}", accumulator=51)
        last = sample_line(
            23, bytes_count=1323, sha256=f"{24:064x}", accumulator=U64_MAX
        )
        ending = end_line(311, "b" * 64, U64_MAX)
        epoch_five_irq = irq_response_line(5)

        rejected_success(
            "post-epoch-4 IRQ truncation",
            success[: success.index(epoch_five_irq)],
        )
        replace_success(
            "epoch-5 terminal gate failure",
            epoch_five_irq,
            f"{IRQ_FAMILY} FAIL stage=irq-response-terminal epoch=5",
        )
        replace_success(
            "epoch-5 inactive counter stalled",
            epoch_five_irq,
            epoch_five_irq.replace("inactive=5", "inactive=4", 1),
        )

        rejected_success("missing META", success[1:])
        rejected_success("duplicate META", [meta, *success])
        replace_success("META commit", meta, meta.replace("commit=1", "commit=2", 1))
        replace_success(
            "META zero bytes",
            meta,
            meta.replace(f"bytes={EXPECTED_META_BYTES}", "bytes=0", 1),
        )
        replace_success(
            "META leading-zero bytes",
            meta,
            meta.replace(
                f"bytes={EXPECTED_META_BYTES}", f"bytes=0{EXPECTED_META_BYTES}", 1
            ),
        )
        replace_success(
            "META byte-count overflow",
            meta,
            meta.replace(
                f"bytes={EXPECTED_META_BYTES}", f"bytes={U64_MAX + 1}", 1
            ),
        )
        replace_success(
            "META uppercase digest",
            meta,
            meta.replace(EXPECTED_META_SHA256, EXPECTED_META_SHA256.upper(), 1),
        )
        replace_success(
            "META state", meta, meta.replace("state=collecting", "state=closed", 1)
        )
        replace_success(
            "META decision eligibility",
            meta,
            meta.replace("decision_eligible=0", "decision_eligible=1", 1),
        )
        replace_success(
            "META formal UART", meta, meta.replace("formal_uart=0", "formal_uart=1", 1)
        )

        rejected_success("missing sample", [line for line in success if line != fourth])
        rejected_success("duplicate sample", [*success, fourth])
        replace_success(
            "sample commit", fourth, fourth.replace("commit=5", "commit=4", 1)
        )
        replace_success("sample epoch", fourth, fourth.replace("epoch=4", "epoch=3", 1))
        replace_success(
            "sample sequence", fourth, fourth.replace("sequence=3", "sequence=4", 1)
        )
        replace_success(
            "warmup boundary", fourth, fourth.replace("warmup=0", "warmup=1", 1)
        )
        replace_success(
            "sample zero bytes", fourth, fourth.replace("bytes=1303", "bytes=0", 1)
        )
        replace_success(
            "sample leading-zero bytes",
            fourth,
            fourth.replace("bytes=1303", "bytes=01303", 1),
        )
        replace_success(
            "sample short digest", fourth, fourth.replace(f"{4:064x}", "4" * 63, 1)
        )
        replace_success(
            "sample uppercase digest", fourth, fourth.replace(f"{4:064x}", "F" * 64, 1)
        )
        replace_success(
            "sample digest replay",
            second,
            second.replace(f"{2:064x}", f"{1:064x}", 1),
        )
        replace_success(
            "accumulator leading zero",
            fourth,
            fourth.replace("accumulator=51", "accumulator=051", 1),
        )
        replace_success(
            "accumulator overflow",
            last,
            last.replace(f"accumulator={U64_MAX}", f"accumulator={U64_MAX + 1}", 1),
        )
        replace_success(
            "next sequence",
            fourth,
            fourth.replace("next_sequence=4", "next_sequence=3", 1),
        )
        replace_success(
            "Ready rollback",
            fourth,
            fourth.replace("recycled_ready_epoch=5", "recycled_ready_epoch=4", 1),
        )
        replace_success(
            "sample closed early",
            fourth,
            fourth.replace("state=collecting", "state=closed", 1),
        )
        replace_success(
            "sample decision eligible",
            fourth,
            fourth.replace("decision_eligible=0", "decision_eligible=1", 1),
        )
        replace_success(
            "sample formal UART",
            fourth,
            fourth.replace("formal_uart=0", "formal_uart=1", 1),
        )

        rejected_success("missing END", [line for line in success if line != ending])
        replace_success(
            "END commit", ending, ending.replace("commit=26", "commit=25", 1)
        )
        replace_success(
            "END sample count", ending, ending.replace("samples=24", "samples=23", 1)
        )
        replace_success(
            "END warmup count", ending, ending.replace("warmups=3", "warmups=2", 1)
        )
        replace_success(
            "END retained count",
            ending,
            ending.replace("retained=21", "retained=22", 1),
        )
        replace_success(
            "END accumulator",
            ending,
            ending.replace(f"accumulator={U64_MAX}", "accumulator=0", 1),
        )
        replace_success(
            "END Ready epoch",
            ending,
            ending.replace("recycled_ready_epoch=25", "recycled_ready_epoch=24", 1),
        )
        replace_success(
            "END open state",
            ending,
            ending.replace("state=closed", "state=collecting", 1),
        )
        replace_success(
            "END formal UART",
            ending,
            ending.replace("formal_uart=0", "formal_uart=1", 1),
        )

        reject = success_reject_line()
        replace_success(
            "closed reject epoch", reject, reject.replace("epoch=25", "epoch=24", 1)
        )
        replace_success(
            "closed reject attempt",
            reject,
            reject.replace("attempt=25", "attempt=24", 1),
        )
        replace_success(
            "closed reject status", reject, reject.replace("status=126", "status=0", 1)
        )
        replace_success(
            "closed reject target start",
            reject,
            reject.replace("target_started=0", "target_started=1", 1),
        )
        replace_success(
            "closed reject commit count",
            reject,
            reject.replace("audit_commits=26", "audit_commits=25", 1),
        )

        old_trusted = trusted_response_line(4, 4, 904)
        replace_success(
            "old trusted discard suffix",
            old_trusted,
            old_trusted.replace(
                TRUSTED_TERMINAL_SUFFIX,
                "bundle=trusted finish=1 verify=1 discard=trusted_sample_abandoned emitted=0 stored=1 ack=1",
                1,
            ),
        )
        core_four = collector_core_line(4, min(CORE.EXPECTED_CORE_POLLS, 904), 904)
        replace_success(
            "Core poll mismatch",
            core_four,
            core_four.replace("typed_polls=904", "typed_polls=905", 1),
        )
        request_four = request_response_line(4)
        replace_success(
            "request old suffix",
            request_four,
            request_four.replace(
                "collector=consumed ack=0", "discard=trusted_sample_abandoned ack=1", 1
            ),
        )
        finish_four = finish_response_line(4)
        replace_success(
            "finish old suffix",
            finish_four,
            finish_four.replace(
                "collector=consumed ack=0", "discard=trusted_sample_abandoned ack=1", 1
            ),
        )

        reordered = list(success)
        trusted_index = reordered.index(old_trusted)
        sample_index = reordered.index(fourth)
        reordered[trusted_index], reordered[sample_index] = (
            reordered[sample_index],
            reordered[trusted_index],
        )
        rejected_success("sample marker before trusted terminal", reordered)
        reused = list(success)
        first_index = reused.index(first)
        next_start_index = reused.index(request_start_line(2))
        reused[first_index], reused[next_start_index] = (
            reused[next_start_index],
            reused[first_index],
        )
        rejected_success("next request before sample audit", reused)
        premature_end = list(success)
        last_index = premature_end.index(last)
        end_index = premature_end.index(ending)
        premature_end[last_index], premature_end[end_index] = (
            premature_end[end_index],
            premature_end[last_index],
        )
        rejected_success("END before sample 23", premature_end)
        rejected_success("late collector marker", [*success, first])

        failed = failed_line()
        failed_reject = failed_reject_line()
        replace_failure(
            "failure reason",
            failed,
            failed.replace("active_target_disconnected", "lease_cancelled", 1),
        )
        replace_failure(
            "failure target not started",
            failed,
            failed.replace("target_started=1", "target_started=0", 1),
        )
        replace_failure(
            "failure sample committed",
            failed,
            failed.replace("sample_committed=0", "sample_committed=1", 1),
        )
        replace_failure(
            "failure END committed",
            failed,
            failed.replace("end_committed=0", "end_committed=1", 1),
        )
        replace_failure(
            "failure audit commits",
            failed,
            failed.replace("audit_commits=1", "audit_commits=2", 1),
        )
        replace_failure(
            "failure Ready epoch",
            failed,
            failed.replace("recycled_ready_epoch=2", "recycled_ready_epoch=1", 1),
        )
        replace_failure(
            "failure state",
            failed,
            failed.replace("state=failed", "state=collecting", 1),
        )
        replace_failure(
            "failure reject reason",
            failed_reject,
            failed_reject.replace("collector_failed", "collector_closed", 1),
        )
        replace_failure(
            "failure reject status",
            failed_reject,
            failed_reject.replace("status=126", "status=0", 1),
        )
        replace_failure(
            "failure reject target",
            failed_reject,
            failed_reject.replace("target_started=0", "target_started=1", 1),
        )
        replace_failure(
            "failure reject formal UART",
            failed_reject,
            failed_reject.replace("formal_uart=0", "formal_uart=1", 1),
        )
        rejected_failure("failure emitted sample", [*failure[:-1], first, failure[-1]])
        rejected_failure(
            "missing trusted Drop",
            [line for line in failure if line != TRUSTED.drop_line(1)],
        )
        phase_drop = PHASE.drop_line(1, 14)
        replace_failure("phase/Core count mismatch", phase_drop, PHASE.drop_line(1, 15))

        for prefix in FORMAL_PREFIXES:
            mutations += 1
            success_log.write_bytes(
                ("\n".join(success) + "\n").encode() + b"noise " + prefix + b"{}\n"
            )
            try:
                verify_success(success_log)
            except EXPECTED_EXCEPTIONS:
                pass
            else:
                raise DriverError(f"formal-prefix leak was accepted: {prefix!r}")

        write(success_log, synthetic_success_lines(meta_sha="c" * 64))
        write(failure_log, failure)
        mutations += 1
        try:
            verify_pair(failure_log, success_log)
        except EXPECTED_EXCEPTIONS:
            pass
        else:
            raise DriverError("pair parser accepted different META receipts")

        write(success_log, synthetic_success_lines(meta_sha="c" * 64))
        write(failure_log, synthetic_failure_lines(meta_sha="c" * 64))
        mutations += 1
        try:
            verify_pair(failure_log, success_log)
        except EXPECTED_EXCEPTIONS:
            pass
        else:
            raise DriverError("pair parser accepted a shared forged META receipt")

        write(success_log, synthetic_success_lines(final_accumulator=0))
        verify_success(success_log)
        write(success_log, synthetic_success_lines(final_accumulator=U64_MAX))
        verify_success(success_log)
    return mutations + 6


def verify_failure_from_lines(lines: list[str]) -> bool:
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-collector-failure-fixture-"
    ) as directory:
        path = Path(directory) / "failure.log"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verify_failure(path)
    return True


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--selftest", action="store_true")
    value.add_argument("--verify-log-only", action="store_true")
    value.add_argument("--verify-pair", action="store_true")
    value.add_argument("--scenario", choices=("success", "failure"))
    value.add_argument("--failure-log", type=Path)
    value.add_argument("--success-log", type=Path)
    value.add_argument("--host", default="localhost")
    value.add_argument("--port", type=int)
    value.add_argument("--user", default="vibe")
    value.add_argument("--accepted-key", type=Path)
    value.add_argument("--rejected-key", type=Path)
    value.add_argument("--known-hosts", type=Path)
    value.add_argument("--host-key-output", type=Path)
    value.add_argument("--qemu-log", type=Path)
    value.add_argument("--ready-timeout", type=float, default=45.0)
    value.add_argument("--command-timeout", type=float, default=20.0)
    value.add_argument("--marker-timeout", type=float, default=20.0)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        modes = sum(
            (arguments.selftest, arguments.verify_log_only, arguments.verify_pair)
        )
        require(
            modes <= 1,
            "--selftest, --verify-log-only, and --verify-pair are mutually exclusive",
        )
        if arguments.selftest:
            mutations = run_parser_selftest()
            print(
                "PASS c84-ssh-managed-child-single-boot-collector-peer "
                f"parser mutations={mutations}"
            )
            return 0
        if arguments.verify_pair:
            require(
                arguments.failure_log is not None,
                "--failure-log is required with --verify-pair",
            )
            require(
                arguments.success_log is not None,
                "--success-log is required with --verify-pair",
            )
            failure, success = verify_pair(arguments.failure_log, arguments.success_log)
            print(
                "PASS c84-ssh-managed-child-single-boot-collector-peer frozen pair: "
                f"same_meta_sha256={success.meta.sha256} failure_drop_pairs={failure.drop_observer_pairs} "
                "success_commits=26 samples=24 retained=21"
            )
            return 0
        if arguments.verify_log_only:
            require(
                arguments.qemu_log is not None,
                "--qemu-log is required with --verify-log-only",
            )
            require(
                arguments.scenario is not None,
                "--scenario is required with --verify-log-only",
            )
            if arguments.scenario == "success":
                observation = verify_success(arguments.qemu_log)
                print(
                    "PASS c84-ssh-managed-child-single-boot-collector-peer frozen success: "
                    f"meta_sha256={observation.meta.sha256} commits=26 samples=24 retained=21"
                )
            else:
                observation = verify_failure(arguments.qemu_log)
                print(
                    "PASS c84-ssh-managed-child-single-boot-collector-peer frozen failure: "
                    f"meta_sha256={observation.meta.sha256} drop_pairs={observation.drop_observer_pairs} "
                    "audit_commits=1"
                )
            return 0
        drive(arguments)
        print(
            "PASS c84-ssh-managed-child-single-boot-collector-peer: "
            f"{arguments.scenario} boot closed with exact private audit and predecessor transcript"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        DriverError,
        TRUSTED.DriverError,
        FINISH.DriverError,
        IRQ.DriverError,
        PHASE.DriverError,
        CORE.DriverError,
        PHASE.PEER.PeerError,
        REQUEST.VerificationError,
        subprocess.SubprocessError,
    ) as error:
        print(
            f"FAIL c84-ssh-managed-child-single-boot-collector-peer: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
