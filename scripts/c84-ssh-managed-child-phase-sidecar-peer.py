#!/usr/bin/env python3
"""Drive the single-hart C8.4 SSH managed-child phase sidecar with OpenSSH."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import importlib.util
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
CORE_PEER_PATH = ROOT / "scripts/c84-ssh-managed-child-core-peer.py"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_PARENT_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"
NUMBER = r"(?:0|[1-9][0-9]*)"
FORMAL_PUBLISHER_MARKERS = (
    "WASM_C48_ACCEPTANCE",
    "WASM_C53_NATIVE_SSH_ACCEPTANCE",
    "WASM_C84_PROFILE_SLOT",
    "WASM_C84_CORE_POLL",
    "WASM_C84_PROFILE_CHILD_DELEGATION",
    "WASM_C84_PROFILE_IRQ_OVERLAY",
)


def load_core_peer():
    spec = importlib.util.spec_from_file_location("vibeos_c84_managed_child_core_peer", CORE_PEER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the predecessor managed-child/Core peer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CORE = load_core_peer()
PEER = CORE.PEER
DELAYED_CORE_POLLS = CORE.EXPECTED_CORE_POLLS + 4
DELAYED_TYPED_POLLS = CORE.EXPECTED_TYPED_POLLS + 10
LEGACY_CANCEL = CORE.LEGACY_CANCEL
FINISH_VERIFY = CORE.FINISH_VERIFY
VERIFIED_STREAM = CORE.VERIFIED_STREAM


class DriverError(Exception):
    pass


@dataclass(frozen=True)
class PhaseCounters:
    child_core_starts: int
    child_core_finishes: int
    child_host_starts: int
    child_host_finishes: int
    child_wait_starts: int
    child_wait_finishes: int
    cleanup_count: int
    parent_host_starts: int
    parent_host_finishes: int
    parent_wait_starts: int
    parent_wait_finishes: int


@dataclass(frozen=True)
class NormalObservation:
    epoch: int
    counters: PhaseCounters


@dataclass(frozen=True)
class DropObservation:
    epoch: int
    counters: PhaseCounters


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


def normalized_log(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace").replace("\r", "\n")


def normalize_serial_line(line: str) -> str:
    clear = "\x1b[2K"
    return line[len(clear) :] if line.startswith(clear) else line


def fail_fast_log(path: Path) -> str:
    value = normalized_log(path)
    if re.search(r"\bWASM_[A-Z0-9_]+ FAIL\b", value):
        raise DriverError("guest reported a WASM acceptance failure")
    if "panicked at" in value or "[!] fatal" in value or "[!] panic" in value:
        raise DriverError("guest reported a panic or fatal error")
    for marker in FORMAL_PUBLISHER_MARKERS:
        if marker in value:
            raise DriverError(f"diagnostic image published forbidden marker: {marker}")
    return value


def family_markers(path: Path, family: str = FAMILY) -> list[str]:
    lines = (normalize_serial_line(line) for line in fail_fast_log(path).splitlines())
    return [line for line in lines if family in line]


def require_unchanged_families(
    path: Path,
    phase_before: list[str],
    core_before: list[str],
    label: str,
) -> None:
    phase_after = family_markers(path)
    core_after = family_markers(path, CORE_FAMILY)
    require(phase_after == phase_before, f"{label} changed phase markers: {phase_after!r}")
    require(core_after == core_before, f"{label} changed Core markers: {core_after!r}")


def wait_for_marker(path: Path, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in fail_fast_log(path):
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for guest marker: {marker}")


def wait_for_family_line(path: Path, pattern: re.Pattern[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(pattern.fullmatch(line) is not None for line in family_markers(path)):
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for complete guest marker: {pattern.pattern}")


def wait_ready(arguments: argparse.Namespace, ssh: str) -> None:
    CORE.wait_ready(arguments, ssh)


def invoke(
    arguments: argparse.Namespace,
    ssh: str,
    label: str,
    identity: Path,
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    verbose: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    return CORE.invoke(
        arguments,
        ssh,
        label,
        identity,
        command,
        input_bytes=input_bytes,
        verbose=verbose,
    )


def inert_probes(arguments: argparse.Namespace, ssh: str) -> None:
    phase_before = family_markers(arguments.qemu_log)
    core_before = family_markers(arguments.qemu_log, CORE_FAMILY)

    builtin = invoke(arguments, ssh, "C8.4 inert builtin", arguments.accepted_key, ["true"])
    PEER.require_result("C8.4 inert builtin", builtin, {0}, b"")

    native = invoke(
        arguments,
        ssh,
        "C8.4 inert native Component",
        arguments.accepted_key,
        ["native-case-filter"],
        input_bytes=PEER.NATIVE_CASE_FILTER_INPUT,
    )
    require(native.returncode != 0 and native.stdout == b"", "native inert probe changed")

    parameterized = invoke(
        arguments,
        ssh,
        "C8.4 inert parameterized case-filter",
        arguments.accepted_key,
        ["case-filter", "unexpected-argument"],
        input_bytes=PEER.CASE_FILTER_INPUT,
    )
    require(
        parameterized.returncode != 0 and parameterized.stdout == b"",
        "parameterized inert probe changed",
    )

    rejected = invoke(
        arguments,
        ssh,
        "C8.4 rejected public key",
        arguments.rejected_key,
        ["case-filter"],
        input_bytes=PEER.CASE_FILTER_INPUT,
    )
    PEER.require_result(
        "C8.4 rejected public key",
        rejected,
        {255},
        b"",
        r"permission denied.*publickey",
    )
    time.sleep(0.2)
    require_unchanged_families(
        arguments.qemu_log,
        phase_before,
        core_before,
        "inert SSH probes",
    )


def counters_from_match(match: re.Match[str]) -> PhaseCounters:
    values = {name: int(value) for name, value in match.groupdict().items()}
    return PhaseCounters(
        **{
            name: values[name]
            for name in PhaseCounters.__dataclass_fields__
        }
    )


def require_normal_counters(counters: PhaseCounters, epoch: int) -> None:
    require(
        counters.child_core_starts == counters.child_core_finishes > 0,
        f"normal epoch {epoch} has an unpaired or empty child Core boundary",
    )
    require(
        counters.child_host_starts == counters.child_host_finishes > 0,
        f"normal epoch {epoch} has an unpaired or empty child Host boundary",
    )
    require(
        counters.child_wait_starts == counters.child_wait_finishes > 0,
        f"normal epoch {epoch} has an unpaired or empty child Wait boundary",
    )
    require(counters.cleanup_count == 1, f"normal epoch {epoch} cleanup count differs")
    require(
        counters.parent_host_starts == counters.parent_host_finishes > 0,
        f"normal epoch {epoch} has an unpaired or empty parent Host boundary",
    )
    require(
        counters.parent_wait_starts == counters.parent_wait_finishes > 0,
        f"normal epoch {epoch} has an unpaired or empty parent Wait boundary",
    )


def normal_response_pattern(terminal_mode: str = LEGACY_CANCEL) -> re.Pattern[str]:
    suffix = re.escape(CORE.response_terminal_suffix(terminal_mode))
    return re.compile(
        rf"^{FAMILY} RESPONSE epoch=(?P<epoch>{NUMBER}) status=0 "
        rf"child_core_starts=(?P<child_core_starts>{NUMBER}) "
        rf"child_core_finishes=(?P<child_core_finishes>{NUMBER}) "
        rf"child_host_starts=(?P<child_host_starts>{NUMBER}) "
        rf"child_host_finishes=(?P<child_host_finishes>{NUMBER}) "
        rf"child_wait_starts=(?P<child_wait_starts>{NUMBER}) "
        rf"child_wait_finishes=(?P<child_wait_finishes>{NUMBER}) "
        rf"cleanup_count=(?P<cleanup_count>{NUMBER}) "
        rf"parent_host_starts=(?P<parent_host_starts>{NUMBER}) "
        rf"parent_host_finishes=(?P<parent_host_finishes>{NUMBER}) "
        rf"parent_wait_starts=(?P<parent_wait_starts>{NUMBER}) "
        rf"parent_wait_finishes=(?P<parent_wait_finishes>{NUMBER}) "
        rf"child_wait_open=0 parent_wait_open=0 late=0 clean=1 {suffix} "
        rf"ready_epoch=(?P<ready_epoch>{NUMBER})$"
    )


# Compatibility export used by predecessor callers.
NORMAL_RESPONSE = normal_response_pattern()


DROP_RESPONSE = re.compile(
    rf"^{FAMILY} DROP epoch=(?P<epoch>{NUMBER}) release=0 detach=exited clean=0 "
    rf"child_faults=abandoned\+detached "
    rf"child_core_starts=(?P<child_core_starts>{NUMBER}) "
    rf"child_core_finishes=(?P<child_core_finishes>{NUMBER}) "
    rf"child_host_starts=(?P<child_host_starts>{NUMBER}) "
    rf"child_host_finishes=(?P<child_host_finishes>{NUMBER}) "
    rf"child_wait_starts=(?P<child_wait_starts>{NUMBER}) "
    rf"child_wait_finishes=(?P<child_wait_finishes>{NUMBER}) "
    rf"cleanup_count=(?P<cleanup_count>{NUMBER}) "
    rf"parent_host_starts=(?P<parent_host_starts>{NUMBER}) "
    rf"parent_host_finishes=(?P<parent_host_finishes>{NUMBER}) "
    rf"parent_wait_starts=(?P<parent_wait_starts>{NUMBER}) "
    rf"parent_wait_finishes=(?P<parent_wait_finishes>{NUMBER}) "
    rf"child_wait_open_at_cancel=1 parent_wait_open_at_cancel=(?P<parent_wait_open_at_cancel>[01]) "
    rf"late=0 cancel=1 ack=1 "
    rf"ready_epoch=(?P<ready_epoch>{NUMBER})$"
)


def parse_normal_transaction(
    lines: list[str],
    epoch: int,
    terminal_mode: str = LEGACY_CANCEL,
) -> NormalObservation:
    expected_prefix = [
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=validation",
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=instantiation",
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=abi",
        f"{FAMILY} CHILD_WAIT epoch={epoch} state=open first=1",
    ]
    if epoch == 2:
        expected_prefix.append(
            f"{FAMILY} CHILD_HOST_PENDING epoch=2 state=open delayed_stdin=1"
        )
    expected_prefix.extend(
        [
            f"{FAMILY} CHILD_PHASE epoch={epoch} phase=cleanup",
            f"{FAMILY} EXITED epoch={epoch} detach=exited release=1",
        ]
    )
    require(
        len(lines) == len(expected_prefix) + 1,
        f"normal epoch {epoch} marker count differs: {lines!r}",
    )
    require(lines[:-1] == expected_prefix, f"normal epoch {epoch} phase sequence differs: {lines!r}")
    response = normal_response_pattern(terminal_mode).fullmatch(lines[-1])
    require(response is not None, f"normal epoch {epoch} RESPONSE differs: {lines[-1]!r}")
    assert response is not None
    require(int(response.group("epoch")) == epoch, f"normal epoch {epoch} RESPONSE epoch differs")
    require(int(response.group("ready_epoch")) == epoch + 1, f"normal epoch {epoch} reuse differs")
    counters = counters_from_match(response)
    require_normal_counters(counters, epoch)
    return NormalObservation(epoch, counters)


def parse_drop_transaction(lines: list[str], epoch: int) -> DropObservation:
    expected_prefix = [
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=validation",
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=instantiation",
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=abi",
        f"{FAMILY} CHILD_WAIT epoch={epoch} state=open first=1",
    ]
    require(len(lines) in (5, 6), f"Drop epoch {epoch} marker count differs: {lines!r}")
    require(lines[:4] == expected_prefix, f"Drop epoch {epoch} phase sequence differs: {lines!r}")
    cleanup_marker = f"{FAMILY} CHILD_PHASE epoch={epoch} phase=cleanup"
    if len(lines) == 6:
        require(lines[4] == cleanup_marker, f"Drop epoch {epoch} optional cleanup marker differs")
    response = DROP_RESPONSE.fullmatch(lines[-1])
    require(response is not None, f"Drop epoch {epoch} marker differs: {lines[-1]!r}")
    assert response is not None
    require(int(response.group("epoch")) == epoch, f"Drop epoch {epoch} marker epoch differs")
    require(int(response.group("ready_epoch")) == epoch + 1, f"Drop epoch {epoch} reuse differs")
    counters = counters_from_match(response)
    require(
        counters.child_core_starts == counters.child_core_finishes,
        f"Drop epoch {epoch} has an unpaired child Core boundary",
    )
    require(
        1 <= counters.child_core_starts <= CORE.U64_MAX,
        f"Drop epoch {epoch} child Core count is not a positive u64",
    )
    require(
        counters.child_host_starts == counters.child_host_finishes,
        f"Drop epoch {epoch} has an open child Host boundary",
    )
    require(
        counters.child_wait_starts == counters.child_wait_finishes + 1,
        f"Drop epoch {epoch} did not cancel one exact open child Wait",
    )
    require(
        counters.parent_host_starts == counters.parent_host_finishes > 0,
        f"Drop epoch {epoch} has an unpaired or empty parent Host boundary",
    )
    parent_wait_open = int(response.group("parent_wait_open_at_cancel"))
    require(counters.parent_wait_starts > 0, f"Drop epoch {epoch} has no parent Wait")
    require(
        counters.parent_wait_starts
        == counters.parent_wait_finishes + parent_wait_open,
        f"Drop epoch {epoch} parent Wait count/open state differs",
    )
    require(
        counters.cleanup_count == (1 if len(lines) == 6 else 0),
        f"Drop epoch {epoch} cleanup observation and marker differ",
    )
    return DropObservation(epoch, counters)


def parse_core_normal_transaction(
    lines: list[str],
    epoch: int,
    terminal_mode: str = LEGACY_CANCEL,
):
    if epoch != 2:
        return CORE.parse_normal_transaction(lines, epoch, terminal_mode)
    fixed = [
        f"{CORE_FAMILY} BIND epoch=2 child_index=0 before_publish=1",
        f"{CORE_FAMILY} CLAIM epoch=2 child_index=0 first_poll=1",
        f"{CORE_FAMILY} CORE epoch=2 ordinary=1 first_pair=1",
        f"{CORE_FAMILY} RELEASE epoch=2 normal_driver=1",
    ]
    require(len(lines) == 5, f"delayed epoch 2 Core marker count differs: {lines!r}")
    require(lines[:4] == fixed, f"delayed epoch 2 Core sequence differs: {lines!r}")
    expected_response = CORE.normal_response_line(
        2,
        terminal_mode,
        core_polls=DELAYED_CORE_POLLS,
        typed_polls=DELAYED_TYPED_POLLS,
    )
    require(lines[4] == expected_response, f"delayed epoch 2 Core RESPONSE differs: {lines[4]!r}")
    return CORE.NormalObservation(2, DELAYED_CORE_POLLS, DELAYED_CORE_POLLS, DELAYED_TYPED_POLLS)


def verify_combined_core_sequence(path: Path, terminal_mode: str = LEGACY_CANCEL):
    markers = family_markers(path, CORE_FAMILY)
    cursor = 0
    normal = []
    for epoch in (1, 2):
        normal.append(
            parse_core_normal_transaction(
                markers[cursor : cursor + 5], epoch, terminal_mode
            )
        )
        cursor += 5
    dropped = CORE.parse_drop_transaction(markers[cursor : cursor + 4], 3)
    cursor += 4
    normal.append(
        parse_core_normal_transaction(markers[cursor : cursor + 5], 4, terminal_mode)
    )
    cursor += 5
    require(
        cursor == len(markers),
        f"late or unexpected combined Core markers followed epoch 4: {markers[cursor:]!r}",
    )
    return normal, dropped


def require_global_normal_order(path: Path, epoch: int) -> None:
    value = fail_fast_log(path)
    needles = [
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=cleanup",
        f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
        f"{FAMILY} EXITED epoch={epoch} detach=exited release=1",
        f"{FAMILY} RESPONSE epoch={epoch} status=0 ",
    ]
    positions = []
    for needle in needles:
        require(value.count(needle) == 1, f"normal epoch {epoch} global marker count differs: {needle}")
        positions.append(value.index(needle))
    require(positions == sorted(positions), f"normal epoch {epoch} cleanup/release/exit/response order differs")


def start_ssh_process(arguments: argparse.Namespace, ssh: str) -> subprocess.Popen[bytes]:
    time.sleep(0.2)
    connect_timeout = max(1, min(10, math.ceil(arguments.command_timeout)))
    command = PEER._base_ssh_command(
        ssh,
        arguments.host,
        arguments.port,
        arguments.user,
        arguments.accepted_key,
        arguments.known_hosts,
        connect_timeout,
        None,
    )
    destination = command.pop()
    command.extend(("-oLogLevel=ERROR", "-T", destination, "case-filter"))
    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def delayed_stdin_request(
    arguments: argparse.Namespace,
    ssh: str,
    epoch: int,
) -> subprocess.CompletedProcess[bytes]:
    process = start_ssh_process(arguments, ssh)
    prefix = PEER.CASE_FILTER_INPUT[:257]
    suffix = PEER.CASE_FILTER_INPUT[257:]
    try:
        assert process.stdin is not None
        process.stdin.write(prefix)
        process.stdin.flush()
        marker = f"{FAMILY} CHILD_HOST_PENDING epoch={epoch} state=open delayed_stdin=1"
        wait_for_marker(arguments.qemu_log, marker, arguments.marker_timeout)
        require(process.poll() is None, "delayed-stdin request exited before HostPending")
        process.stdin.write(suffix)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=arguments.command_timeout)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.communicate()
        raise
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def normal_profiled_request(
    arguments: argparse.Namespace,
    ssh: str,
    epoch: int,
    *,
    await_readiness: bool = True,
    terminal_mode: str = LEGACY_CANCEL,
) -> NormalObservation:
    if await_readiness:
        wait_ready(arguments, ssh)
    phase_before = family_markers(arguments.qemu_log)
    core_before = family_markers(arguments.qemu_log, CORE_FAMILY)
    if epoch == 2:
        result = delayed_stdin_request(arguments, ssh, epoch)
    else:
        result = invoke(
            arguments,
            ssh,
            f"C8.4 phase-sidecar case-filter epoch {epoch}",
            arguments.accepted_key,
            ["case-filter"],
            input_bytes=PEER.CASE_FILTER_INPUT,
            verbose=epoch == 1,
        )
    PEER.require_result(
        f"C8.4 phase-sidecar case-filter epoch {epoch}",
        result,
        {0},
        PEER.CASE_FILTER_OUTPUT,
        stderr_exact=None if epoch == 1 else b"",
    )
    if epoch == 1:
        PEER.require_negotiated_profile(result)
        PEER.require_expected_host_identity(result)
    wait_for_family_line(
        arguments.qemu_log,
        re.compile(
            rf"^{FAMILY} RESPONSE epoch={epoch} status=0 .* ready_epoch={epoch + 1}$"
        ),
        arguments.marker_timeout,
    )
    phase_after = family_markers(arguments.qemu_log)
    core_after = family_markers(arguments.qemu_log, CORE_FAMILY)
    require(phase_after[: len(phase_before)] == phase_before, f"normal epoch {epoch} rewrote phase markers")
    require(core_after[: len(core_before)] == core_before, f"normal epoch {epoch} rewrote Core markers")
    observation = parse_normal_transaction(
        phase_after[len(phase_before) :], epoch, terminal_mode
    )
    parse_core_normal_transaction(
        core_after[len(core_before) :], epoch, terminal_mode
    )
    require_global_normal_order(arguments.qemu_log, epoch)
    return observation


def active_drop_request(arguments: argparse.Namespace, ssh: str, epoch: int) -> DropObservation:
    wait_ready(arguments, ssh)
    phase_before = family_markers(arguments.qemu_log)
    core_before = family_markers(arguments.qemu_log, CORE_FAMILY)
    process = start_ssh_process(arguments, ssh)
    held_input = PEER.CASE_FILTER_INPUT[:257]
    try:
        assert process.stdin is not None
        process.stdin.write(held_input)
        process.stdin.flush()
        wait_for_marker(
            arguments.qemu_log,
            f"{FAMILY} CHILD_WAIT epoch={epoch} state=open first=1",
            arguments.marker_timeout,
        )
        require(process.poll() is None, "active case-filter exited before exact child Wait-open")
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.communicate()
        raise

    require(process.returncode != 0, "killed OpenSSH process unexpectedly reported success")
    require(len(stdout) <= len(held_input), "killed request returned more bytes than admitted")
    require(
        stdout == bytes(byte ^ 0x20 for byte in held_input[: len(stdout)]),
        "killed request returned a non-canonical stdout prefix",
    )
    require(stderr == b"", f"killed request returned unexpected stderr: {stderr!r}")
    wait_for_family_line(
        arguments.qemu_log,
        re.compile(rf"^{FAMILY} DROP epoch={epoch} .* ready_epoch={epoch + 1}$"),
        arguments.marker_timeout,
    )
    phase_after = family_markers(arguments.qemu_log)
    core_after = family_markers(arguments.qemu_log, CORE_FAMILY)
    require(phase_after[: len(phase_before)] == phase_before, f"Drop epoch {epoch} rewrote phase markers")
    require(core_after[: len(core_before)] == core_before, f"Drop epoch {epoch} rewrote Core markers")
    observation = parse_drop_transaction(phase_after[len(phase_before) :], epoch)
    CORE.parse_drop_transaction(core_after[len(core_before) :], epoch)
    return observation


def post_drop_readiness(arguments: argparse.Namespace, ssh: str) -> None:
    phase_before = family_markers(arguments.qemu_log)
    core_before = family_markers(arguments.qemu_log, CORE_FAMILY)
    wait_ready(arguments, ssh)
    time.sleep(0.1)
    require_unchanged_families(arguments.qemu_log, phase_before, core_before, "post-Drop readiness")


def verify_closed_sequence(
    path: Path,
    terminal_mode: str = LEGACY_CANCEL,
) -> tuple[list[NormalObservation], DropObservation]:
    markers = family_markers(path)
    cursor = 0
    normal: list[NormalObservation] = []
    for epoch, count in ((1, 7), (2, 8)):
        normal.append(
            parse_normal_transaction(
                markers[cursor : cursor + count], epoch, terminal_mode
            )
        )
        cursor += count
    drop_count = 6 if markers[cursor + 4 : cursor + 5] == [f"{FAMILY} CHILD_PHASE epoch=3 phase=cleanup"] else 5
    dropped = parse_drop_transaction(markers[cursor : cursor + drop_count], 3)
    cursor += drop_count
    normal.append(
        parse_normal_transaction(markers[cursor : cursor + 7], 4, terminal_mode)
    )
    cursor += 7
    require(cursor == len(markers), f"late or unexpected phase markers followed epoch 4: {markers[cursor:]!r}")
    core_normal, core_dropped = verify_combined_core_sequence(path, terminal_mode)
    for phase, core in zip(normal, core_normal, strict=True):
        require(
            phase.counters.child_core_starts == core.core_polls
            and phase.counters.child_core_finishes == core.observer_pairs,
            f"epoch {phase.epoch} phase/Core family counts diverge",
        )
    require(
        dropped.counters.child_core_starts == core_dropped.observer_pairs
        and dropped.counters.child_core_finishes == core_dropped.observer_pairs,
        "Drop phase/Core family counts diverge",
    )
    for epoch in (1, 2, 4):
        require_global_normal_order(path, epoch)
    return normal, dropped


def response_line(
    epoch: int,
    terminal_mode: str = LEGACY_CANCEL,
    *,
    skew: str = "",
) -> str:
    core_polls = DELAYED_CORE_POLLS if epoch == 2 else CORE.EXPECTED_CORE_POLLS
    return (
        f"{FAMILY} RESPONSE epoch={epoch} status=0 "
        f"child_core_starts={core_polls} "
        f"child_core_finishes={core_polls} "
        f"child_host_starts=3 child_host_finishes=3 child_wait_starts=2 child_wait_finishes=2 "
        f"cleanup_count=1 parent_host_starts=9 parent_host_finishes=9 "
        f"parent_wait_starts=4 parent_wait_finishes=4 child_wait_open=0 parent_wait_open=0 "
        f"late={skew or '0'} clean=1 {CORE.response_terminal_suffix(terminal_mode)} "
        f"ready_epoch={epoch + 1}"
    )


def drop_line(epoch: int, child_core_pairs: int) -> str:
    return (
        f"{FAMILY} DROP epoch={epoch} release=0 detach=exited clean=0 "
        f"child_faults=abandoned+detached "
        f"child_core_starts={child_core_pairs} "
        f"child_core_finishes={child_core_pairs} "
        f"child_host_starts=1 child_host_finishes=1 child_wait_starts=2 child_wait_finishes=1 "
        f"cleanup_count=0 parent_host_starts=6 parent_host_finishes=6 "
        f"parent_wait_starts=3 parent_wait_finishes=3 child_wait_open_at_cancel=1 "
        f"parent_wait_open_at_cancel=0 late=0 cancel=1 ack=1 ready_epoch={epoch + 1}"
    )


def normal_lines(epoch: int, terminal_mode: str = LEGACY_CANCEL) -> list[str]:
    lines = [
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=validation",
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=instantiation",
        f"{FAMILY} CHILD_PHASE epoch={epoch} phase=abi",
        f"{FAMILY} CHILD_WAIT epoch={epoch} state=open first=1",
    ]
    if epoch == 2:
        lines.append(f"{FAMILY} CHILD_HOST_PENDING epoch=2 state=open delayed_stdin=1")
    lines.extend(
        [
            f"{FAMILY} CHILD_PHASE epoch={epoch} phase=cleanup",
            f"{FAMILY} EXITED epoch={epoch} detach=exited release=1",
            response_line(epoch, terminal_mode),
        ]
    )
    return lines


def run_parser_selftest() -> int:
    drop_observer_pairs = 14
    normal = normal_lines(1)
    dropped = [
        f"{FAMILY} CHILD_PHASE epoch=3 phase=validation",
        f"{FAMILY} CHILD_PHASE epoch=3 phase=instantiation",
        f"{FAMILY} CHILD_PHASE epoch=3 phase=abi",
        f"{FAMILY} CHILD_WAIT epoch=3 state=open first=1",
        drop_line(3, drop_observer_pairs),
    ]
    parse_normal_transaction(normal, 1)
    parse_normal_transaction(normal_lines(2), 2)
    parse_drop_transaction(dropped, 3)
    mutations: list[tuple[list[str], bool]] = [
        (normal[:1] + [normal[2], normal[1]] + normal[3:], False),
        (
            normal[:-1]
            + [
                normal[-1].replace(
                    f"child_core_finishes={CORE.EXPECTED_CORE_POLLS}",
                    f"child_core_finishes={CORE.EXPECTED_CORE_POLLS - 1}",
                )
            ],
            False,
        ),
        (normal[:-1] + [normal[-1].replace("child_host_starts=3", "child_host_starts=0")], False),
        (normal[:-1] + [normal[-1].replace("child_wait_finishes=2", "child_wait_finishes=1")], False),
        (normal[:-1] + [normal[-1].replace("cleanup_count=1", "cleanup_count=0")], False),
        (normal[:-1] + [normal[-1].replace("parent_wait_finishes=4", "parent_wait_finishes=3")], False),
        (normal[:-1] + [response_line(1, skew="1")], False),
        (dropped[:-1] + [dropped[-1].replace("child_wait_finishes=1", "child_wait_finishes=2")], True),
        (dropped[:-1] + [dropped[-1].replace("release=0", "release=1")], True),
        (dropped[:-1] + [dropped[-1].replace("ready_epoch=4", "ready_epoch=04")], True),
        (
            dropped[:-1]
            + [
                dropped[-1]
                .replace(
                    f"child_core_starts={drop_observer_pairs}",
                    "child_core_starts=0",
                    1,
                )
                .replace(
                    f"child_core_finishes={drop_observer_pairs}",
                    "child_core_finishes=0",
                    1,
                )
            ],
            True,
        ),
        (
            dropped[:-1]
            + [
                dropped[-1]
                .replace(
                    f"child_core_starts={drop_observer_pairs}",
                    f"child_core_starts={CORE.U64_MAX + 1}",
                    1,
                )
                .replace(
                    f"child_core_finishes={drop_observer_pairs}",
                    f"child_core_finishes={CORE.U64_MAX + 1}",
                    1,
                )
            ],
            True,
        ),
    ]
    for index, (lines, is_drop) in enumerate(mutations, start=1):
        try:
            if is_drop:
                parse_drop_transaction(lines, 3)
            else:
                parse_normal_transaction(lines, 1)
        except DriverError:
            continue
        raise DriverError(f"parser selftest mutation {index} was accepted")

    successor = normal_lines(1, FINISH_VERIFY)
    parse_normal_transaction(successor, 1, FINISH_VERIFY)
    successor_mutations = [
        successor[:-1] + [successor[-1].replace("verify=1", "verify=0", 1)],
        successor[:-1]
        + [successor[-1].replace("discard=stream_abandoned", "discard=complete", 1)],
        normal,
    ]
    for index, lines in enumerate(successor_mutations, start=1):
        try:
            parse_normal_transaction(lines, 1, FINISH_VERIFY)
        except DriverError:
            continue
        raise DriverError(f"successor parser selftest mutation {index} was accepted")
    try:
        parse_normal_transaction(successor, 1, LEGACY_CANCEL)
    except DriverError:
        pass
    else:
        raise DriverError("legacy phase terminal mode accepted the successor RESPONSE")

    stream_successor = normal_lines(1, VERIFIED_STREAM)
    parse_normal_transaction(stream_successor, 1, VERIFIED_STREAM)
    stream_mutations = [
        stream_successor[:-1]
        + [stream_successor[-1].replace("stream=complete", "stream=partial", 1)],
        stream_successor[:-1] + [stream_successor[-1].replace("ack=0", "ack=1", 1)],
        successor,
    ]
    for index, lines in enumerate(stream_mutations, start=1):
        try:
            parse_normal_transaction(lines, 1, VERIFIED_STREAM)
        except DriverError:
            continue
        raise DriverError(f"verified-stream parser selftest mutation {index} was accepted")
    for wrong_mode in (LEGACY_CANCEL, FINISH_VERIFY):
        try:
            parse_normal_transaction(stream_successor, 1, wrong_mode)
        except DriverError:
            continue
        raise DriverError(f"{wrong_mode} accepted the verified-stream phase RESPONSE")

    def core_normal_lines(epoch: int) -> list[str]:
        core_polls = DELAYED_CORE_POLLS if epoch == 2 else CORE.EXPECTED_CORE_POLLS
        typed_polls = DELAYED_TYPED_POLLS if epoch == 2 else CORE.EXPECTED_TYPED_POLLS
        return [
            f"{CORE_FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
            f"{CORE_FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
            f"{CORE_FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
            f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
            f"{CORE_FAMILY} RESPONSE epoch={epoch} status=0 claim=1 release=1 "
            f"detach=exited clean=1 core_polls={core_polls} "
            f"observer_pairs={core_polls} typed_polls={typed_polls} "
            f"observer_closed=1 cancel=1 ack=1 ready_epoch={epoch + 1}",
        ]

    core_drop = [
        f"{CORE_FAMILY} BIND epoch=3 child_index=0 before_publish=1",
        f"{CORE_FAMILY} CLAIM epoch=3 child_index=0 first_poll=1",
        f"{CORE_FAMILY} CORE epoch=3 ordinary=1 first_pair=1",
        CORE.drop_response_line(3, drop_observer_pairs),
    ]
    frozen: list[str] = []
    for epoch in (1, 2):
        phase = normal_lines(epoch)
        core = core_normal_lines(epoch)
        prefix = 5 if epoch == 2 else 4
        frozen.extend(phase[:prefix])
        frozen.extend(core[:3])
        frozen.append(phase[prefix])
        frozen.append(core[3])
        frozen.extend(phase[prefix + 1 :])
        frozen.append(core[4])
    frozen.extend(dropped[:4])
    frozen.extend(core_drop[:3])
    frozen.append(dropped[4])
    frozen.append(core_drop[3])
    phase = normal_lines(4)
    core = core_normal_lines(4)
    frozen.extend(phase[:4])
    frozen.extend(core[:3])
    frozen.append(phase[4])
    frozen.append(core[3])
    frozen.extend(phase[5:])
    frozen.append(core[4])
    with tempfile.TemporaryDirectory(prefix="vibeos-c84-phase-peer-") as directory:
        log = Path(directory) / "frozen.log"
        log.write_text("\n".join(frozen) + "\n", encoding="utf-8")
        verify_closed_sequence(log)

        varied_drop_pairs = drop_observer_pairs + 1
        varied_drop = list(frozen)
        phase_drop_index = varied_drop.index(drop_line(3, drop_observer_pairs))
        core_drop_index = varied_drop.index(CORE.drop_response_line(3, drop_observer_pairs))
        varied_drop[phase_drop_index] = drop_line(3, varied_drop_pairs)
        varied_drop[core_drop_index] = CORE.drop_response_line(3, varied_drop_pairs)
        log.write_text("\n".join(varied_drop) + "\n", encoding="utf-8")
        verify_closed_sequence(log)

        frozen_mutations: list[tuple[str, list[str]]] = []

        cross_family = list(frozen)
        response_index = next(
            index
            for index, line in enumerate(cross_family)
            if line.startswith(f"{FAMILY} RESPONSE epoch=1 ")
        )
        cross_family[response_index] = cross_family[response_index].replace(
            f"child_core_starts={CORE.EXPECTED_CORE_POLLS} "
            f"child_core_finishes={CORE.EXPECTED_CORE_POLLS}",
            f"child_core_starts={CORE.EXPECTED_CORE_POLLS - 1} "
            f"child_core_finishes={CORE.EXPECTED_CORE_POLLS - 1}",
            1,
        )
        frozen_mutations.append(("phase/Core paired-count mismatch", cross_family))

        drop_cross_family = list(frozen)
        drop_response_index = drop_cross_family.index(drop_line(3, drop_observer_pairs))
        drop_cross_family[drop_response_index] = drop_line(3, drop_observer_pairs + 1)
        frozen_mutations.append(("Drop phase/Core paired-count mismatch", drop_cross_family))

        host_pending = f"{FAMILY} CHILD_HOST_PENDING epoch=2 state=open delayed_stdin=1"
        frozen_mutations.append(
            ("epoch-2 HostPending omission", [line for line in frozen if line != host_pending])
        )
        widened_pending = list(frozen)
        pending_index = widened_pending.index(host_pending)
        widened_pending[pending_index] = host_pending.replace("delayed_stdin=1", "delayed_stdin=0")
        frozen_mutations.append(("epoch-2 HostPending widening", widened_pending))

        wrong_delayed_typed = list(frozen)
        delayed_response_index = next(
            index
            for index, line in enumerate(wrong_delayed_typed)
            if line.startswith(f"{CORE_FAMILY} RESPONSE epoch=2 ")
        )
        wrong_delayed_typed[delayed_response_index] = wrong_delayed_typed[
            delayed_response_index
        ].replace(
            f"typed_polls={DELAYED_TYPED_POLLS}",
            f"typed_polls={DELAYED_TYPED_POLLS - 1}",
            1,
        )
        frozen_mutations.append(("epoch-2 exact delayed typed-poll delta", wrong_delayed_typed))

        wrong_global_order = list(frozen)
        cleanup_index = wrong_global_order.index(f"{FAMILY} CHILD_PHASE epoch=1 phase=cleanup")
        release_index = wrong_global_order.index(f"{CORE_FAMILY} RELEASE epoch=1 normal_driver=1")
        wrong_global_order[cleanup_index], wrong_global_order[release_index] = (
            wrong_global_order[release_index],
            wrong_global_order[cleanup_index],
        )
        frozen_mutations.append(("cleanup/release global order", wrong_global_order))

        late_epoch_four = list(frozen)
        late_epoch_four.append(f"{FAMILY} CHILD_WAIT epoch=4 state=open first=1")
        frozen_mutations.append(("late epoch-4 marker", late_epoch_four))

        predecessor_short = list(frozen)
        predecessor_short.remove(f"{CORE_FAMILY} RELEASE epoch=4 normal_driver=1")
        frozen_mutations.append(("predecessor exact-19 transcript", predecessor_short))

        for label, mutated in frozen_mutations:
            log.write_text("\n".join(mutated) + "\n", encoding="utf-8")
            try:
                verify_closed_sequence(log)
            except (DriverError, CORE.DriverError):
                continue
            raise DriverError(f"frozen-log {label} mutation was accepted")
    return (
        len(mutations)
        + len(successor_mutations)
        + len(stream_mutations)
        + 3
        + len(frozen_mutations)
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--selftest", action="store_true")
    value.add_argument(
        "--verify-log-only",
        action="store_true",
        help="strictly parse one already-frozen UART log without opening SSH",
    )
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
        require(
            not (arguments.selftest and arguments.verify_log_only),
            "--selftest and --verify-log-only are mutually exclusive",
        )
        if arguments.selftest:
            mutations = run_parser_selftest()
            print(f"PASS c84-ssh-managed-child-phase-sidecar-peer parser mutations={mutations}")
            return 0
        if arguments.verify_log_only:
            require(arguments.qemu_log is not None, "--qemu-log is required with --verify-log-only")
            normal, dropped = verify_closed_sequence(arguments.qemu_log)
            print(
                "PASS c84-ssh-managed-child-phase-sidecar-peer frozen log: "
                f"normal_epochs={[item.epoch for item in normal]} drop_epoch={dropped.epoch} "
                "phase transcript and predecessor 19-marker transcript are exact"
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
        PEER.write_expected_known_hosts(arguments.known_hosts, arguments.host, arguments.port)
        wait_ready(arguments, ssh)
        PEER.write_host_key_evidence(arguments.host_key_output)
        require(family_markers(arguments.qemu_log) == [], "authenticated readiness armed phase sidecar")
        require(family_markers(arguments.qemu_log, CORE_FAMILY) == [], "authenticated readiness armed child Core")

        inert_probes(arguments, ssh)
        normal_profiled_request(arguments, ssh, 1)
        normal_profiled_request(arguments, ssh, 2)
        active_drop_request(arguments, ssh, 3)
        post_drop_readiness(arguments, ssh)
        normal_profiled_request(arguments, ssh, 4, await_readiness=False)

        time.sleep(0.3)
        normal, dropped = verify_closed_sequence(arguments.qemu_log)
        print(
            "c84-ssh-managed-child-phase-sidecar-peer: controlled observation "
            f"normal_child_host_pairs={[item.counters.child_host_finishes for item in normal]} "
            f"normal_child_wait_pairs={[item.counters.child_wait_finishes for item in normal]} "
            f"normal_parent_host={[item.counters.parent_host_finishes for item in normal]} "
            f"normal_parent_wait={[item.counters.parent_wait_finishes for item in normal]} "
            f"drop_child_wait={dropped.counters.child_wait_starts}/{dropped.counters.child_wait_finishes}"
        )
        print(
            "PASS c84-ssh-managed-child-phase-sidecar-peer: exact child phases, paired Core/Host/Wait, "
            "real delayed-stdin HostPending, cleanup-before-release, WAIT-open active Drop, immediate "
            "post-Drop readiness, replacement reuse, and predecessor 19-marker transcript passed"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        DriverError,
        CORE.DriverError,
        PEER.PeerError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL c84-ssh-managed-child-phase-sidecar-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
