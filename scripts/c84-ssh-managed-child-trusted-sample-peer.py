#!/usr/bin/env python3
"""Drive and verify the C8.4 SSH managed-child trusted-sample successor."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
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
import types


ROOT = Path(__file__).resolve().parent.parent
FINISH_PEER_PATH = ROOT / "scripts/c84-ssh-managed-child-finish-verify-peer.py"

FAMILY = "WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE"
FINISH_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY"
IRQ_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"
PREDECESSOR_FAMILIES = (
    PHASE_FAMILY,
    CORE_FAMILY,
    REQUEST_FAMILY,
    IRQ_FAMILY,
    FINISH_FAMILY,
)
NUMBER = r"(?:0|[1-9][0-9]*)"
U64_MAX = (1 << 64) - 1
MAX_FORMAL_FUEL = 500_000
FORMAL_STDOUT_SHA256 = "791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27"
VERIFIED_SUFFIX = "finish=1 verify=1 stream=complete ack=0"
TRUSTED_SUFFIX = (
    "finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1"
)


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


def load_finish_peer() -> types.ModuleType:
    return load_source_module(
        "vibeos_c84_trusted_sample_finish_peer", FINISH_PEER_PATH
    )


FINISH = load_finish_peer()
IRQ = FINISH.IRQ
PHASE = FINISH.PHASE
REQUEST = FINISH.REQUEST
PREDECESSOR_MODE = FINISH.VERIFIED_STREAM


class DriverError(Exception):
    pass


@dataclass(frozen=True)
class TrustedObservation:
    epoch: int
    fuel_consumed: int
    poll_quanta: int
    ready_epoch: int


@dataclass(frozen=True)
class DropObservation:
    epoch: int
    ready_epoch: int


@dataclass(frozen=True)
class CoreObservation:
    epoch: int
    core_polls: int
    typed_polls: int
    ready_epoch: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


NORMAL_RESPONSE = re.compile(
    rf"^{FAMILY} RESPONSE epoch=(?P<epoch>{NUMBER}) status=0 exact_success=1 "
    rf"full_drain=1 read_chunks=13 write_chunks=13 stdout_bytes=12325 "
    rf"stdout_sha256={FORMAL_STDOUT_SHA256} fuel_consumed=(?P<fuel>{NUMBER}) "
    rf"poll_quanta=(?P<polls>{NUMBER}) poll_exact=1 logical_live_after=0 "
    rf"timed_out=0 bundle=trusted finish=1 verify=1 "
    rf"discard=trusted_sample_abandoned emitted=0 stored=1 ack=1 "
    rf"ready_epoch=(?P<ready_epoch>{NUMBER})$"
)

DROP_RESPONSE = re.compile(
    rf"^{FAMILY} DROP epoch=(?P<epoch>{NUMBER}) cancel=lease_cancelled bundle=0 "
    rf"finish=0 verify=0 discard=0 emitted=0 stored=1 ack=1 "
    rf"ready_epoch=(?P<ready_epoch>{NUMBER})$"
)

CORE_RESPONSE = re.compile(
    rf"^{CORE_FAMILY} RESPONSE epoch=(?P<epoch>{NUMBER}) status=0 claim=1 release=1 "
    rf"detach=exited clean=1 core_polls=(?P<core>{NUMBER}) "
    rf"observer_pairs=(?P<pairs>{NUMBER}) typed_polls=(?P<typed>{NUMBER}) "
    rf"observer_closed=1 {TRUSTED_SUFFIX} ready_epoch=(?P<ready_epoch>{NUMBER})$"
)


def response_line(epoch: int, fuel_consumed: int, poll_quanta: int) -> str:
    return (
        f"{FAMILY} RESPONSE epoch={epoch} status=0 exact_success=1 full_drain=1 "
        "read_chunks=13 write_chunks=13 stdout_bytes=12325 "
        f"stdout_sha256={FORMAL_STDOUT_SHA256} fuel_consumed={fuel_consumed} "
        f"poll_quanta={poll_quanta} poll_exact=1 logical_live_after=0 timed_out=0 "
        "bundle=trusted finish=1 verify=1 discard=trusted_sample_abandoned "
        f"emitted=0 stored=1 ack=1 ready_epoch={epoch + 1}"
    )


def drop_line(epoch: int) -> str:
    return (
        f"{FAMILY} DROP epoch={epoch} cancel=lease_cancelled bundle=0 finish=0 "
        "verify=0 discard=0 emitted=0 stored=1 ack=1 "
        f"ready_epoch={epoch + 1}"
    )


def parse_response(line: str, epoch: int) -> TrustedObservation:
    response = NORMAL_RESPONSE.fullmatch(line)
    require(response is not None, f"trusted-sample epoch {epoch} RESPONSE differs: {line!r}")
    assert response is not None
    observed_epoch = int(response.group("epoch"))
    fuel = int(response.group("fuel"))
    polls = int(response.group("polls"))
    ready_epoch = int(response.group("ready_epoch"))
    require(observed_epoch == epoch, f"trusted-sample epoch {epoch} RESPONSE epoch differs")
    require(ready_epoch == epoch + 1, f"trusted-sample epoch {epoch} Ready reuse differs")
    require(
        1 <= fuel <= MAX_FORMAL_FUEL,
        f"trusted-sample epoch {epoch} fuel is outside the formal budget",
    )
    require(
        1 <= polls < U64_MAX,
        f"trusted-sample epoch {epoch} poll count is empty or saturated",
    )
    return TrustedObservation(epoch, fuel, polls, ready_epoch)


def parse_drop(line: str, epoch: int) -> DropObservation:
    response = DROP_RESPONSE.fullmatch(line)
    require(response is not None, f"trusted-sample epoch {epoch} DROP differs: {line!r}")
    assert response is not None
    observed_epoch = int(response.group("epoch"))
    ready_epoch = int(response.group("ready_epoch"))
    require(observed_epoch == epoch, f"trusted-sample epoch {epoch} DROP epoch differs")
    require(ready_epoch == epoch + 1, f"trusted-sample epoch {epoch} DROP reuse differs")
    return DropObservation(epoch, ready_epoch)


def parse_core_response(line: str, epoch: int) -> CoreObservation:
    response = CORE_RESPONSE.fullmatch(line)
    require(response is not None, f"trusted Core epoch {epoch} RESPONSE differs: {line!r}")
    assert response is not None
    observed_epoch = int(response.group("epoch"))
    core_polls = int(response.group("core"))
    observer_pairs = int(response.group("pairs"))
    typed_polls = int(response.group("typed"))
    ready_epoch = int(response.group("ready_epoch"))
    require(observed_epoch == epoch, f"trusted Core epoch {epoch} RESPONSE epoch differs")
    require(ready_epoch == epoch + 1, f"trusted Core epoch {epoch} Ready reuse differs")
    require(
        1 <= core_polls == observer_pairs <= typed_polls < U64_MAX,
        f"trusted Core epoch {epoch} poll relation differs",
    )
    return CoreObservation(epoch, core_polls, typed_polls, ready_epoch)


def normalized_lines(path: Path, *, ignore_incomplete_tail: bool = False) -> list[str]:
    return IRQ.normalized_lines(path, ignore_incomplete_tail=ignore_incomplete_tail)


def family_markers(path: Path, *, ignore_incomplete_tail: bool = False) -> list[str]:
    return [
        line
        for line in normalized_lines(path, ignore_incomplete_tail=ignore_incomplete_tail)
        if FAMILY in line
    ]


def parse_marker_sequence(
    markers: list[str],
) -> tuple[list[TrustedObservation], DropObservation]:
    require(len(markers) == 4, f"trusted-sample marker count differs: {markers!r}")
    normal = [parse_response(markers[0], 1), parse_response(markers[1], 2)]
    dropped = parse_drop(markers[2], 3)
    normal.append(parse_response(markers[3], 4))
    return normal, dropped


def to_trusted_predecessor(line: str) -> str:
    if any(line.startswith(f"{family} RESPONSE ") for family in PREDECESSOR_FAMILIES):
        require(
            line.count(VERIFIED_SUFFIX) == 1,
            f"synthetic predecessor success suffix differs: {line!r}",
        )
        return line.replace(VERIFIED_SUFFIX, TRUSTED_SUFFIX, 1)
    return line


def to_verified_predecessor(line: str) -> str:
    if any(line.startswith(f"{family} RESPONSE ") for family in PREDECESSOR_FAMILIES):
        require(
            line.count(TRUSTED_SUFFIX) == 1,
            f"trusted predecessor success suffix differs: {line!r}",
        )
        return line.replace(TRUSTED_SUFFIX, VERIFIED_SUFFIX, 1)
    return line


def trusted_core_response_line(epoch: int, core_polls: int, typed_polls: int) -> str:
    return to_trusted_predecessor(
        PHASE.CORE.normal_response_line(
            epoch,
            PREDECESSOR_MODE,
            core_polls=core_polls,
            typed_polls=typed_polls,
        )
    )


def to_trusted_control_counts(
    line: str, metrics: dict[int, tuple[int, int]]
) -> str:
    """Adapt only synthetic predecessor fixtures to the trusted stdin shape."""
    for epoch in (1, 2, 4):
        predecessor_core_polls = (
            PHASE.DELAYED_CORE_POLLS if epoch == 2 else PHASE.CORE.EXPECTED_CORE_POLLS
        )
        predecessor_typed_polls = (
            PHASE.DELAYED_TYPED_POLLS if epoch == 2 else PHASE.CORE.EXPECTED_TYPED_POLLS
        )
        trusted_typed_polls = metrics[epoch][1]
        trusted_core_polls = min(predecessor_core_polls, trusted_typed_polls)
        if line.startswith(f"{CORE_FAMILY} RESPONSE epoch={epoch} "):
            old = (
                f"core_polls={predecessor_core_polls} "
                f"observer_pairs={predecessor_core_polls} "
                f"typed_polls={predecessor_typed_polls}"
            )
            new = (
                f"core_polls={trusted_core_polls} "
                f"observer_pairs={trusted_core_polls} "
                f"typed_polls={trusted_typed_polls}"
            )
            require(line.count(old) == 1, f"synthetic Core control counts differ: {line!r}")
            return line.replace(old, new, 1)
        if line.startswith(f"{PHASE_FAMILY} RESPONSE epoch={epoch} "):
            old = (
                f"child_core_starts={predecessor_core_polls} "
                f"child_core_finishes={predecessor_core_polls}"
            )
            new = (
                f"child_core_starts={trusted_core_polls} "
                f"child_core_finishes={trusted_core_polls}"
            )
            require(line.count(old) == 1, f"synthetic phase/Core counts differ: {line!r}")
            return line.replace(old, new, 1)
    return line


def verify_predecessor(path: Path) -> dict[int, CoreObservation]:
    lines = normalized_lines(path)
    phase_markers = [line for line in lines if PHASE_FAMILY in line]
    phase_cursor = 0
    phase_normal = []
    for epoch, count in ((1, 7), (2, 8)):
        transaction = phase_markers[phase_cursor : phase_cursor + count]
        phase_normal.append(
            PHASE.parse_normal_transaction(
                [to_verified_predecessor(line) for line in transaction],
                epoch,
                PREDECESSOR_MODE,
            )
        )
        phase_cursor += count
    drop_count = (
        6
        if phase_markers[phase_cursor + 4 : phase_cursor + 5]
        == [f"{PHASE_FAMILY} CHILD_PHASE epoch=3 phase=cleanup"]
        else 5
    )
    phase_drop = PHASE.parse_drop_transaction(
        phase_markers[phase_cursor : phase_cursor + drop_count], 3
    )
    phase_cursor += drop_count
    transaction = phase_markers[phase_cursor : phase_cursor + 7]
    phase_normal.append(
        PHASE.parse_normal_transaction(
            [to_verified_predecessor(line) for line in transaction],
            4,
            PREDECESSOR_MODE,
        )
    )
    phase_cursor += 7
    require(
        phase_cursor == len(phase_markers),
        f"late trusted phase markers followed epoch 4: {phase_markers[phase_cursor:]!r}",
    )

    core_markers = [line for line in lines if CORE_FAMILY in line]
    core_cursor = 0
    core_observations: dict[int, CoreObservation] = {}
    for epoch in (1, 2):
        expected_prefix = [
            f"{CORE_FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
            f"{CORE_FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
            f"{CORE_FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
            f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
        ]
        require(
            core_markers[core_cursor : core_cursor + 4] == expected_prefix,
            f"trusted Core epoch {epoch} transaction differs: "
            f"{core_markers[core_cursor : core_cursor + 5]!r}",
        )
        require(
            core_cursor + 4 < len(core_markers),
            f"trusted Core epoch {epoch} RESPONSE is missing",
        )
        core_observations[epoch] = parse_core_response(core_markers[core_cursor + 4], epoch)
        core_cursor += 5
    core_drop = PHASE.CORE.parse_drop_transaction(core_markers[core_cursor : core_cursor + 4], 3)
    core_cursor += 4
    expected_prefix = [
        f"{CORE_FAMILY} BIND epoch=4 child_index=0 before_publish=1",
        f"{CORE_FAMILY} CLAIM epoch=4 child_index=0 first_poll=1",
        f"{CORE_FAMILY} CORE epoch=4 ordinary=1 first_pair=1",
        f"{CORE_FAMILY} RELEASE epoch=4 normal_driver=1",
    ]
    require(
        core_markers[core_cursor : core_cursor + 4] == expected_prefix,
        f"trusted Core epoch 4 transaction differs: {core_markers[core_cursor : core_cursor + 5]!r}",
    )
    require(core_cursor + 4 < len(core_markers), "trusted Core epoch 4 RESPONSE is missing")
    core_observations[4] = parse_core_response(core_markers[core_cursor + 4], 4)
    core_cursor += 5
    require(
        core_cursor == len(core_markers),
        f"late trusted Core markers followed epoch 4: {core_markers[core_cursor:]!r}",
    )
    for phase in phase_normal:
        core = core_observations[phase.epoch]
        require(
            phase.counters.child_core_starts == core.core_polls
            and phase.counters.child_core_finishes == core.core_polls,
            f"trusted epoch {phase.epoch} phase/Core counts diverge",
        )
    require(
        phase_drop.counters.child_core_starts == core_drop.observer_pairs
        and phase_drop.counters.child_core_finishes == core_drop.observer_pairs,
        "trusted Drop phase/Core counts diverge",
    )

    expected_families = (
        (
            REQUEST_FAMILY,
            [
                to_trusted_predecessor(line)
                for line in REQUEST.expected_qemu_markers(PREDECESSOR_MODE)
            ],
        ),
        (
            IRQ_FAMILY,
            [
                to_trusted_predecessor(line)
                for line in IRQ.expected_irq_markers(PREDECESSOR_MODE)
            ],
        ),
        (
            FINISH_FAMILY,
            [
                to_trusted_predecessor(line)
                for line in FINISH.expected_finish_markers(PREDECESSOR_MODE)
            ],
        ),
    )
    for family, expected in expected_families:
        observed = [line for line in lines if family in line]
        require(observed == expected, f"trusted {family} sequence differs: {observed!r}")
    for epoch in (1, 2, 4):
        PHASE.require_global_normal_order(path, epoch)
    return core_observations


def require_unique_order(lines: list[str], needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [index for index, line in enumerate(lines) if needle in line]
        require(len(matches) == 1, f"{label} marker count differs for {needle!r}: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} marker order differs: {needles!r}")


def verify_global_order(path: Path, normal: list[TrustedObservation]) -> None:
    lines = normalized_lines(path)
    request = [to_trusted_predecessor(line) for line in REQUEST.expected_qemu_markers(PREDECESSOR_MODE)]
    irq = [to_trusted_predecessor(line) for line in IRQ.expected_irq_markers(PREDECESSOR_MODE)]
    finish = [to_trusted_predecessor(line) for line in FINISH.expected_finish_markers(PREDECESSOR_MODE)]
    request_responses = {1: request[1], 2: request[3], 4: request[7]}
    irq_responses = {1: irq[2], 2: irq[3], 4: irq[5]}
    finish_responses = {1: finish[0], 2: finish[1], 4: finish[3]}
    by_epoch = {observation.epoch: observation for observation in normal}
    for epoch in (1, 2, 4):
        observation = by_epoch[epoch]
        require_unique_order(
            lines,
            [
                f"{PHASE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                f"{CORE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                request_responses[epoch],
                irq_responses[epoch],
                finish_responses[epoch],
                response_line(epoch, observation.fuel_consumed, observation.poll_quanta),
            ],
            f"trusted-sample normal epoch {epoch} terminal chain",
        )
    require_unique_order(
        lines,
        [
            f"{PHASE_FAMILY} DROP epoch=3 ",
            f"{CORE_FAMILY} DROP epoch=3 ",
            request[5],
            IRQ.drop_line(3),
            FINISH.drop_line(3),
            drop_line(3),
        ],
        "trusted-sample Drop epoch 3 terminal chain",
    )
    for epoch in (1, 2, 3):
        terminal = (
            drop_line(3)
            if epoch == 3
            else response_line(
                epoch,
                by_epoch[epoch].fuel_consumed,
                by_epoch[epoch].poll_quanta,
            )
        )
        require_unique_order(
            lines,
            [terminal, f"{REQUEST_FAMILY} START epoch={epoch + 1}"],
            f"trusted-sample epoch {epoch} closure before reuse",
        )


def verify_closed_sequence(path: Path):
    core_observations = verify_predecessor(path)
    normal, dropped = parse_marker_sequence(family_markers(path))
    for observation in normal:
        require(
            observation.poll_quanta == core_observations[observation.epoch].typed_polls,
            f"trusted-sample epoch {observation.epoch} poll count differs from Core profile",
        )
    verify_global_order(path, normal)
    return normal, dropped


def wait_for_trusted_prefix(path: Path, expected_count: int, timeout: float) -> None:
    expected_epochs = (1, 2, 3, 4)[:expected_count]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = family_markers(path, ignore_incomplete_tail=True)
        require(
            len(observed) <= expected_count,
            f"trusted-sample emitted an early marker: observed={observed!r}",
        )
        for line, epoch in zip(observed, expected_epochs[: len(observed)], strict=True):
            parse_drop(line, epoch) if epoch == 3 else parse_response(line, epoch)
        if len(observed) == expected_count:
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for trusted-sample marker {expected_count}")


def synthetic_closed_lines(
    metrics: dict[int, tuple[int, int]], *, drop_observer_pairs: int
) -> list[str]:
    predecessor = [
        to_trusted_control_counts(to_trusted_predecessor(line), metrics)
        for line in FINISH.synthetic_closed_lines(
            PREDECESSOR_MODE, drop_observer_pairs=drop_observer_pairs
        )
    ]
    finish_terminals = {
        to_trusted_predecessor(FINISH.response_line(1, PREDECESSOR_MODE)): response_line(1, *metrics[1]),
        to_trusted_predecessor(FINISH.response_line(2, PREDECESSOR_MODE)): response_line(2, *metrics[2]),
        FINISH.drop_line(3): drop_line(3),
        to_trusted_predecessor(FINISH.response_line(4, PREDECESSOR_MODE)): response_line(4, *metrics[4]),
    }
    output: list[str] = []
    for line in predecessor:
        output.append(line)
        if line in finish_terminals:
            output.append(finish_terminals[line])
    return output


def run_parser_selftest() -> int:
    metrics = {1: (1, 1), 2: (MAX_FORMAL_FUEL, U64_MAX - 1), 4: (123_456, 999)}
    valid = synthetic_closed_lines(metrics, drop_observer_pairs=14)
    with tempfile.TemporaryDirectory(prefix="vibeos-c84-trusted-sample-peer-") as directory:
        log = Path(directory) / "frozen.log"

        partial = response_line(1, *metrics[1])[:-11]
        normalized = IRQ.normalized_snapshot(partial.encode(), ignore_incomplete_tail=True)
        require(
            [line for line in normalized if FAMILY in line] == [],
            "live parser admitted a partially written trusted-sample record",
        )

        def accepted(lines: list[str]) -> bool:
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                verify_closed_sequence(log)
            except (
                DriverError,
                FINISH.DriverError,
                IRQ.DriverError,
                PHASE.DriverError,
                PHASE.CORE.DriverError,
                REQUEST.VerificationError,
            ):
                return False
            return True

        require(accepted(valid), "synthetic trusted-sample transcript was rejected")
        require(
            accepted(
                synthetic_closed_lines(
                    {1: (2, 3), 2: (499_999, 77), 4: (8, 9)},
                    drop_observer_pairs=15,
                )
            ),
            "dynamic trusted metrics or matching Drop counts were frozen",
        )

        mutations: list[tuple[str, list[str]]] = []

        def replace_line(label: str, old: str, new: str) -> None:
            mutated = list(valid)
            require(mutated.count(old) == 1, f"selftest seed count differs for {label}")
            mutated[mutated.index(old)] = new
            mutations.append((label, mutated))

        first = response_line(1, *metrics[1])
        second = response_line(2, *metrics[2])
        fourth = response_line(4, *metrics[4])
        mutations.append(("missing response", [line for line in valid if line != first]))
        mutations.append(("duplicate response", valid + [fourth]))
        replace_line("noncanonical epoch", first, first.replace("epoch=1", "epoch=01", 1))
        replace_line("status-only alias", first, first.replace("exact_success=1", "exact_success=0", 1))
        replace_line("incomplete drain", first, first.replace("full_drain=1", "full_drain=0", 1))
        replace_line("read count", first, first.replace("read_chunks=13", "read_chunks=12", 1))
        replace_line("write count", first, first.replace("write_chunks=13", "write_chunks=14", 1))
        replace_line("stdout length", first, first.replace("stdout_bytes=12325", "stdout_bytes=12324", 1))
        replace_line("stdout digest", first, first.replace(FORMAL_STDOUT_SHA256, "0" * 64, 1))
        replace_line("zero fuel", first, first.replace("fuel_consumed=1", "fuel_consumed=0", 1))
        replace_line(
            "oversized fuel",
            second,
            second.replace("fuel_consumed=500000", "fuel_consumed=500001", 1),
        )
        replace_line("zero polls", first, first.replace("poll_quanta=1", "poll_quanta=0", 1))
        replace_line(
            "trusted/Core poll mismatch",
            first,
            first.replace("poll_quanta=1", "poll_quanta=2", 1),
        )
        replace_line(
            "saturated polls",
            second,
            second.replace(f"poll_quanta={U64_MAX - 1}", f"poll_quanta={U64_MAX}", 1),
        )
        replace_line("poll assertion", fourth, fourth.replace("poll_exact=1", "poll_exact=0", 1))
        replace_line("live resource", fourth, fourth.replace("logical_live_after=0", "logical_live_after=1", 1))
        replace_line("timeout", fourth, fourth.replace("timed_out=0", "timed_out=1", 1))
        replace_line("bundle kind", fourth, fourth.replace("bundle=trusted", "bundle=copied", 1))
        replace_line("discard cause", fourth, fourth.replace("trusted_sample_abandoned", "stream_abandoned", 1))
        replace_line("emitted", fourth, fourth.replace("emitted=0", "emitted=1", 1))
        replace_line("stored", fourth, fourth.replace("stored=1", "stored=0", 1))
        replace_line("ack", fourth, fourth.replace("ack=1", "ack=0", 1))
        replace_line("Ready reuse", fourth, fourth.replace("ready_epoch=5", "ready_epoch=4", 1))
        replace_line("Drop bundle", drop_line(3), drop_line(3).replace("bundle=0", "bundle=trusted", 1))

        core_first = next(
            line
            for line in valid
            if line.startswith(f"{CORE_FAMILY} RESPONSE epoch=1 ")
        )
        core_observation = parse_core_response(core_first, 1)
        replace_line(
            "trusted Core polls",
            core_first,
            core_first.replace(
                f"core_polls={core_observation.core_polls}",
                f"core_polls={core_observation.core_polls + 1}",
                1,
            ),
        )
        replace_line(
            "trusted typed polls",
            core_first,
            core_first.replace(
                f"typed_polls={core_observation.typed_polls}",
                f"typed_polls={core_observation.typed_polls + 1}",
                1,
            ),
        )
        phase_first = next(
            line
            for line in valid
            if line.startswith(f"{PHASE_FAMILY} RESPONSE epoch=1 ")
        )
        replace_line(
            "trusted phase/Core polls",
            phase_first,
            phase_first.replace(
                f"child_core_starts={core_observation.core_polls}",
                f"child_core_starts={core_observation.core_polls + 1}",
                1,
            ),
        )
        phase_drop_line = next(
            line
            for line in valid
            if line.startswith(f"{PHASE_FAMILY} DROP epoch=3 ")
        )
        replace_line(
            "trusted Drop phase/Core mismatch",
            phase_drop_line,
            phase_drop_line.replace(
                "child_core_starts=14 child_core_finishes=14",
                "child_core_starts=15 child_core_finishes=15",
                1,
            ),
        )

        mixed = list(valid)
        old = to_trusted_predecessor(FINISH.response_line(2, PREDECESSOR_MODE))
        mixed[mixed.index(old)] = FINISH.response_line(2, PREDECESSOR_MODE)
        mutations.append(("mixed predecessor suffix", mixed))

        reordered = list(valid)
        trusted_index = reordered.index(first)
        finish_index = reordered.index(to_trusted_predecessor(FINISH.response_line(1, PREDECESSOR_MODE)))
        reordered[trusted_index], reordered[finish_index] = reordered[finish_index], reordered[trusted_index]
        mutations.append(("trusted terminal before finish", reordered))

        next_start = list(valid)
        trusted_index = next_start.index(first)
        start_index = next_start.index(REQUEST.expected_qemu_markers(PREDECESSOR_MODE)[2])
        next_start[trusted_index], next_start[start_index] = next_start[start_index], next_start[trusted_index]
        mutations.append(("reuse before trusted terminal", next_start))

        mutations.append(("late trusted marker", valid + [fourth]))
        for label, mutated in mutations:
            require(not accepted(mutated), f"parser selftest mutation was accepted: {label}")
    return len(mutations) + 3


def parser() -> argparse.ArgumentParser:
    value = FINISH.parser()
    value.description = __doc__
    return value


def normal_profiled_request(
    arguments: argparse.Namespace,
    ssh: str,
    epoch: int,
    *,
    await_readiness: bool = True,
) -> None:
    if await_readiness:
        PHASE.wait_ready(arguments, ssh)
    if epoch == 2:
        result = PHASE.delayed_stdin_request(arguments, ssh, epoch)
    else:
        result = PHASE.invoke(
            arguments,
            ssh,
            f"C8.4 trusted-sample case-filter epoch {epoch}",
            arguments.accepted_key,
            ["case-filter"],
            input_bytes=PHASE.PEER.CASE_FILTER_INPUT,
            verbose=epoch == 1,
        )
    PHASE.PEER.require_result(
        f"C8.4 trusted-sample case-filter epoch {epoch}",
        result,
        {0},
        PHASE.PEER.CASE_FILTER_OUTPUT,
        stderr_exact=None if epoch == 1 else b"",
    )
    if epoch == 1:
        PHASE.PEER.require_negotiated_profile(result)
        PHASE.PEER.require_expected_host_identity(result)


def main() -> int:
    arguments = parser().parse_args()
    try:
        require(
            not (arguments.selftest and arguments.verify_log_only),
            "--selftest and --verify-log-only are mutually exclusive",
        )
        if arguments.selftest:
            mutations = run_parser_selftest()
            print(f"PASS c84-ssh-managed-child-trusted-sample-peer parser mutations={mutations}")
            return 0
        if arguments.verify_log_only:
            require(arguments.qemu_log is not None, "--qemu-log is required with --verify-log-only")
            normal, dropped = verify_closed_sequence(arguments.qemu_log)
            print(
                "PASS c84-ssh-managed-child-trusted-sample-peer frozen log: "
                f"metrics={[(item.epoch, item.fuel_consumed, item.poll_quanta) for item in normal]} "
                f"drop_epoch={dropped.epoch}; four trusted terminals and every predecessor are exact"
            )
            return 0

        require(arguments.port is not None and 1 <= arguments.port <= 65535, "--port must be in 1..65535")
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
            require(math.isfinite(timeout) and timeout > 0, f"{label} must be finite and positive")
        ssh = shutil.which("ssh")
        require(ssh is not None, "OpenSSH ssh is required")
        PHASE.PEER.write_expected_known_hosts(arguments.known_hosts, arguments.host, arguments.port)
        PHASE.wait_ready(arguments, ssh)
        PHASE.PEER.write_host_key_evidence(arguments.host_key_output)
        require(family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "readiness armed trusted sample")

        PHASE.inert_probes(arguments, ssh)
        require(family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "inert probes armed trusted sample")

        for epoch, terminal_count in ((1, 1), (2, 2)):
            normal_profiled_request(arguments, ssh, epoch)
            wait_for_trusted_prefix(arguments.qemu_log, terminal_count, arguments.marker_timeout)

        PHASE.active_drop_request(arguments, ssh, 3)
        wait_for_trusted_prefix(arguments.qemu_log, 3, arguments.marker_timeout)
        before_readiness = family_markers(arguments.qemu_log)
        PHASE.post_drop_readiness(arguments, ssh)
        require(family_markers(arguments.qemu_log) == before_readiness, "post-Drop readiness changed trusted markers")

        normal_profiled_request(arguments, ssh, 4, await_readiness=False)
        wait_for_trusted_prefix(arguments.qemu_log, 4, arguments.marker_timeout)

        time.sleep(0.3)
        normal, dropped = verify_closed_sequence(arguments.qemu_log)
        print(
            "c84-ssh-managed-child-trusted-sample-peer: controlled observation "
            f"metrics={[(item.epoch, item.fuel_consumed, item.poll_quanta) for item in normal]} "
            f"drop_epoch={dropped.epoch}"
        )
        print(
            "PASS c84-ssh-managed-child-trusted-sample-peer: epochs 1/2/4 minted one opaque "
            "trusted bundle then discarded/acknowledged it; epoch 3 minted no bundle"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        DriverError,
        FINISH.DriverError,
        IRQ.DriverError,
        PHASE.DriverError,
        PHASE.CORE.DriverError,
        PHASE.PEER.PeerError,
        REQUEST.VerificationError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL c84-ssh-managed-child-trusted-sample-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
