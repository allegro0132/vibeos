#!/usr/bin/env python3
"""Drive the single-hart C8.4 managed-child/Core QEMU image with OpenSSH."""

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
import time
import types


ROOT = Path(__file__).resolve().parent.parent
OPENSSH_PEER = ROOT / "scripts/openssh-peer.py"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_PARENT_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"
NUMBER = r"(?:0|[1-9][0-9]*)"
U64_MAX = (1 << 64) - 1
FORMAL_PUBLISHER_MARKERS = (
    "WASM_C48_ACCEPTANCE PASS",
    "WASM_C53_NATIVE_SSH_ACCEPTANCE PASS",
    "WASM_C84_PROFILE_SLOT PASS",
    "WASM_C84_CORE_POLL PASS",
    "WASM_C84_PROFILE_CHILD_DELEGATION PASS",
    "WASM_C84_PROFILE_IRQ_OVERLAY PASS",
)
# Frozen from repeated isolated SMP1 runs of the exact 12 KiB fixture. These
# are control-flow counts only; QEMU tick values remain non-evidence.
EXPECTED_CORE_POLLS = 1167
EXPECTED_TYPED_POLLS = 1241
EXPECTED_DROP_DETACH = "exited"
LEGACY_CANCEL = "legacy-cancel"
FINISH_VERIFY = "finish-verify"
VERIFIED_STREAM = "verified-stream"


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


def load_peer() -> types.ModuleType:
    return load_source_module("vibeos_openssh_peer", OPENSSH_PEER)


PEER = load_peer()


class DriverError(Exception):
    pass


@dataclass(frozen=True)
class NormalObservation:
    epoch: int
    core_polls: int
    observer_pairs: int
    typed_polls: int


@dataclass(frozen=True)
class DropObservation:
    epoch: int
    detach: str
    observer_pairs: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


def response_terminal_suffix(terminal_mode: str) -> str:
    require(
        terminal_mode in (LEGACY_CANCEL, FINISH_VERIFY, VERIFIED_STREAM),
        f"unknown managed-child/Core terminal mode: {terminal_mode!r}",
    )
    if terminal_mode == LEGACY_CANCEL:
        return "cancel=1 ack=1"
    if terminal_mode == FINISH_VERIFY:
        return "finish=1 verify=1 discard=stream_abandoned ack=1"
    return "finish=1 verify=1 stream=complete ack=0"


def normal_response_line(
    epoch: int,
    terminal_mode: str = LEGACY_CANCEL,
    *,
    core_polls: int = EXPECTED_CORE_POLLS,
    typed_polls: int = EXPECTED_TYPED_POLLS,
) -> str:
    return (
        f"{FAMILY} RESPONSE epoch={epoch} status=0 claim=1 release=1 "
        f"detach=exited clean=1 core_polls={core_polls} "
        f"observer_pairs={core_polls} typed_polls={typed_polls} "
        f"observer_closed=1 {response_terminal_suffix(terminal_mode)} "
        f"ready_epoch={epoch + 1}"
    )


def drop_response_line(epoch: int, observer_pairs: int) -> str:
    return (
        f"{FAMILY} DROP epoch={epoch} claim=1 release=0 "
        f"detach={EXPECTED_DROP_DETACH} clean=0 child_faults=abandoned+detached "
        f"observer_pairs={observer_pairs} observer_closed=1 "
        f"cancel=1 ack=1 ready_epoch={epoch + 1}"
    )


DROP_RESPONSE = re.compile(
    rf"^{FAMILY} DROP epoch=(?P<epoch>{NUMBER}) claim=1 release=0 "
    rf"detach={EXPECTED_DROP_DETACH} clean=0 child_faults=abandoned\+detached "
    rf"observer_pairs=(?P<observer_pairs>{NUMBER}) observer_closed=1 "
    rf"cancel=1 ack=1 ready_epoch=(?P<ready_epoch>{NUMBER})$"
)


def normalized_log(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace").replace("\r", "\n")


def normalize_serial_line(line: str) -> str:
    clear = "\x1b[2K"
    return line[len(clear) :] if line.startswith(clear) else line


def fail_fast_log(path: Path) -> str:
    value = normalized_log(path)
    if re.search(r"\bWASM_[A-Z0-9_]+ FAIL\b", value):
        raise DriverError("guest reported a WASM acceptance failure")
    if f"{REQUEST_PARENT_FAMILY} FAIL" in value or f"{FAMILY} FAIL" in value:
        raise DriverError("guest reported a managed-child request failure")
    if "panicked at" in value or "[!] fatal" in value or "[!] panic" in value:
        raise DriverError("guest reported a panic or fatal error")
    for marker in FORMAL_PUBLISHER_MARKERS:
        if marker in value:
            raise DriverError(f"diagnostic image published forbidden marker: {marker}")
    return value


def family_markers(path: Path) -> list[str]:
    lines = (
        normalize_serial_line(line)
        for line in fail_fast_log(path).splitlines()
    )
    return [line for line in lines if FAMILY in line]


def require_unchanged_family(path: Path, before: list[str], label: str) -> None:
    after = family_markers(path)
    require(after == before, f"{label} changed managed-child marker sequence: observed={after!r}")


def wait_for_marker(path: Path, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in fail_fast_log(path):
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for guest marker: {marker}")


def wait_ready(arguments: argparse.Namespace, ssh: str) -> None:
    PEER.wait_for_strict_ready_ssh(
        ssh,
        arguments.host,
        arguments.port,
        arguments.user,
        arguments.accepted_key,
        arguments.known_hosts,
        None,
        arguments.ready_timeout,
        arguments.command_timeout,
    )


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
    # The guest deliberately owns one passive socket. Give its bounded network
    # poll time to consume the previous FIN/RST and return to LISTEN.
    time.sleep(0.1)
    return PEER.run_ssh(
        label,
        ssh,
        arguments.host,
        arguments.port,
        arguments.user,
        identity,
        arguments.known_hosts,
        None,
        arguments.command_timeout,
        ["-T"],
        command,
        verbose=verbose,
        input_bytes=input_bytes,
    )


def inert_probes(arguments: argparse.Namespace, ssh: str) -> None:
    before = family_markers(arguments.qemu_log)

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
    require(native.returncode != 0, "native Component unexpectedly became executable")
    require(native.stdout == b"", "native inert probe returned stdout")

    parameterized = invoke(
        arguments,
        ssh,
        "C8.4 inert parameterized case-filter",
        arguments.accepted_key,
        ["case-filter", "unexpected-argument"],
        input_bytes=PEER.CASE_FILTER_INPUT,
    )
    require(parameterized.returncode != 0, "parameterized case-filter unexpectedly succeeded")
    require(parameterized.stdout == b"", "parameterized inert probe returned stdout")

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
    require_unchanged_family(arguments.qemu_log, before, "inert SSH probes")


def parse_normal_transaction(
    lines: list[str],
    epoch: int,
    terminal_mode: str = LEGACY_CANCEL,
) -> NormalObservation:
    fixed = [
        f"{FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
        f"{FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
        f"{FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
        f"{FAMILY} RELEASE epoch={epoch} normal_driver=1",
    ]
    require(len(lines) == 5, f"normal epoch {epoch} marker count differs: {lines!r}")
    require(lines[:4] == fixed, f"normal epoch {epoch} transition sequence differs: {lines!r}")
    expected_response = normal_response_line(epoch, terminal_mode)
    require(
        lines[4] == expected_response,
        f"normal epoch {epoch} RESPONSE marker differs: {lines[4]!r}",
    )
    return NormalObservation(
        epoch,
        EXPECTED_CORE_POLLS,
        EXPECTED_CORE_POLLS,
        EXPECTED_TYPED_POLLS,
    )


def parse_drop_transaction(lines: list[str], epoch: int) -> DropObservation:
    fixed = [
        f"{FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
        f"{FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
        f"{FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
    ]
    require(len(lines) == 4, f"Drop epoch {epoch} marker count differs: {lines!r}")
    require(lines[:3] == fixed, f"Drop epoch {epoch} transition sequence differs: {lines!r}")
    response = DROP_RESPONSE.fullmatch(lines[3])
    require(response is not None, f"Drop epoch {epoch} marker differs: {lines[3]!r}")
    assert response is not None
    require(int(response.group("epoch")) == epoch, f"Drop epoch {epoch} marker epoch differs")
    require(
        int(response.group("ready_epoch")) == epoch + 1,
        f"Drop epoch {epoch} reuse differs",
    )
    observer_pairs = int(response.group("observer_pairs"))
    require(
        1 <= observer_pairs <= U64_MAX,
        f"Drop epoch {epoch} observer-pair count is not a positive u64",
    )
    return DropObservation(epoch, EXPECTED_DROP_DETACH, observer_pairs)


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
    before = family_markers(arguments.qemu_log)
    result = invoke(
        arguments,
        ssh,
        f"C8.4 managed-child case-filter epoch {epoch}",
        arguments.accepted_key,
        ["case-filter"],
        input_bytes=PEER.CASE_FILTER_INPUT,
        verbose=epoch == 1,
    )
    PEER.require_result(
        f"C8.4 managed-child case-filter epoch {epoch}",
        result,
        {0},
        PEER.CASE_FILTER_OUTPUT,
        stderr_exact=None if epoch == 1 else b"",
    )
    if epoch == 1:
        PEER.require_negotiated_profile(result)
        PEER.require_expected_host_identity(result)
    wait_for_marker(
        arguments.qemu_log,
        f"{FAMILY} RESPONSE epoch={epoch} status=0 ",
        arguments.marker_timeout,
    )
    after = family_markers(arguments.qemu_log)
    require(after[: len(before)] == before, f"normal epoch {epoch} rewrote prior markers")
    return parse_normal_transaction(after[len(before) :], epoch, terminal_mode)


def active_drop_request(
    arguments: argparse.Namespace,
    ssh: str,
    epoch: int,
) -> DropObservation:
    wait_ready(arguments, ssh)
    before = family_markers(arguments.qemu_log)
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
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    held_input = PEER.CASE_FILTER_INPUT[:257]
    try:
        assert process.stdin is not None
        process.stdin.write(held_input)
        process.stdin.flush()
        # START alone proves only request-parent ownership. The cancellation is
        # authoritative only after the ordinary managed child emits its first
        # fully paired Core observer edge.
        wait_for_marker(
            arguments.qemu_log,
            f"{FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
            arguments.marker_timeout,
        )
        require(process.poll() is None, "active case-filter exited before first Core pair")
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
    wait_for_marker(
        arguments.qemu_log,
        f"{FAMILY} DROP epoch={epoch} ",
        arguments.marker_timeout,
    )
    after = family_markers(arguments.qemu_log)
    require(after[: len(before)] == before, f"Drop epoch {epoch} rewrote prior markers")
    return parse_drop_transaction(after[len(before) :], epoch)


def post_drop_readiness(arguments: argparse.Namespace, ssh: str) -> None:
    before = family_markers(arguments.qemu_log)
    wait_ready(arguments, ssh)
    time.sleep(0.1)
    require_unchanged_family(arguments.qemu_log, before, "post-Drop readiness")


def verify_closed_sequence(
    path: Path,
    terminal_mode: str = LEGACY_CANCEL,
) -> tuple[list[NormalObservation], DropObservation]:
    markers = family_markers(path)
    cursor = 0
    normal: list[NormalObservation] = []
    for epoch in (1, 2):
        normal.append(
            parse_normal_transaction(markers[cursor : cursor + 5], epoch, terminal_mode)
        )
        cursor += 5
    dropped = parse_drop_transaction(markers[cursor : cursor + 4], 3)
    cursor += 4
    normal.append(
        parse_normal_transaction(markers[cursor : cursor + 5], 4, terminal_mode)
    )
    cursor += 5
    require(
        cursor == len(markers),
        f"late or unexpected managed-child markers followed epoch 4: {markers[cursor:]!r}",
    )
    core_polls = {observation.core_polls for observation in normal}
    require(
        len(core_polls) == 1,
        f"identical normal workloads changed Core poll count: {sorted(core_polls)!r}",
    )
    return normal, dropped


def run_parser_selftest() -> int:
    drop_observer_pairs = 14
    normal = [
        f"{FAMILY} BIND epoch=1 child_index=0 before_publish=1",
        f"{FAMILY} CLAIM epoch=1 child_index=0 first_poll=1",
        f"{FAMILY} CORE epoch=1 ordinary=1 first_pair=1",
        f"{FAMILY} RELEASE epoch=1 normal_driver=1",
        f"{FAMILY} RESPONSE epoch=1 status=0 claim=1 release=1 detach=exited clean=1 "
        f"core_polls={EXPECTED_CORE_POLLS} observer_pairs={EXPECTED_CORE_POLLS} "
        f"typed_polls={EXPECTED_TYPED_POLLS} observer_closed=1 cancel=1 ack=1 ready_epoch=2",
    ]
    dropped = [
        f"{FAMILY} BIND epoch=3 child_index=0 before_publish=1",
        f"{FAMILY} CLAIM epoch=3 child_index=0 first_poll=1",
        f"{FAMILY} CORE epoch=3 ordinary=1 first_pair=1",
        drop_response_line(3, drop_observer_pairs),
    ]
    parse_normal_transaction(normal, 1)
    parse_drop_transaction(dropped, 3)
    varied_drop = [*dropped[:-1], drop_response_line(3, drop_observer_pairs + 1)]
    require(
        parse_drop_transaction(varied_drop, 3).observer_pairs == drop_observer_pairs + 1,
        "Drop parser froze a scheduler-dependent partial-run count",
    )
    mutations = [
        (normal[:-1] + [normal[-1].replace("epoch=1", "epoch=01", 1)], False),
        (normal[:-1] + [normal[-1].replace("core_polls=1167", "core_polls=1166", 1)], False),
        (normal[:-1] + [normal[-1].replace("typed_polls=1241", "typed_polls=01241", 1)], False),
        (dropped[:-1] + [dropped[-1].replace("detach=exited", "detach=faulted", 1)], True),
        (
            dropped[:-1]
            + [
                dropped[-1].replace(
                    f"observer_pairs={drop_observer_pairs}",
                    f"observer_pairs=0{drop_observer_pairs}",
                    1,
                )
            ],
            True,
        ),
        (
            dropped[:-1]
            + [dropped[-1].replace(f"observer_pairs={drop_observer_pairs}", "observer_pairs=0", 1)],
            True,
        ),
        (
            dropped[:-1]
            + [
                dropped[-1].replace(
                    f"observer_pairs={drop_observer_pairs}",
                    f"observer_pairs={U64_MAX + 1}",
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
    successor = [*normal[:-1], normal_response_line(1, FINISH_VERIFY)]
    parse_normal_transaction(successor, 1, FINISH_VERIFY)
    successor_mutations = [
        [*successor[:-1], successor[-1].replace("verify=1", "verify=0", 1)],
        [*successor[:-1], successor[-1].replace("discard=stream_abandoned", "discard=complete", 1)],
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
        raise DriverError("legacy Core terminal mode accepted the successor RESPONSE")

    stream_successor = [*normal[:-1], normal_response_line(1, VERIFIED_STREAM)]
    parse_normal_transaction(stream_successor, 1, VERIFIED_STREAM)
    stream_mutations = [
        [
            *stream_successor[:-1],
            stream_successor[-1].replace("stream=complete", "stream=partial", 1),
        ],
        [*stream_successor[:-1], stream_successor[-1].replace("ack=0", "ack=1", 1)],
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
        raise DriverError(f"{wrong_mode} accepted the verified-stream Core RESPONSE")
    return len(mutations) + len(successor_mutations) + len(stream_mutations) + 3


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--selftest", action="store_true")
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
        if arguments.selftest:
            mutations = run_parser_selftest()
            print(f"PASS c84-ssh-managed-child-core-peer parser mutations={mutations}")
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
        require(family_markers(arguments.qemu_log) == [], "authenticated readiness armed the slot")

        inert_probes(arguments, ssh)
        normal_profiled_request(arguments, ssh, 1)
        normal_profiled_request(arguments, ssh, 2)
        active_drop_request(arguments, ssh, 3)
        post_drop_readiness(arguments, ssh)
        normal_profiled_request(arguments, ssh, 4, await_readiness=False)

        # Observe beyond the final TCP turnover so a detached epoch-3 task or
        # delayed epoch-4 transition cannot hide behind the last SSH exit.
        time.sleep(0.3)
        normal, dropped = verify_closed_sequence(arguments.qemu_log)
        print(
            "c84-ssh-managed-child-core-peer: controlled observation "
            f"normal_core_polls={[item.core_polls for item in normal]} "
            f"normal_typed_polls={[item.typed_polls for item in normal]} "
            f"drop_detach={dropped.detach} drop_observer_pairs={dropped.observer_pairs}"
        )
        print(
            "PASS c84-ssh-managed-child-core-peer: inert requests stayed unarmed; "
            "epochs 1,2 released cleanly, epoch 3 dropped after CORE first_pair, "
            "post-Drop readiness succeeded, and epoch 4 reused the slot"
        )
        return 0
    except (OSError, RuntimeError, DriverError, PEER.PeerError, subprocess.SubprocessError) as error:
        print(f"FAIL c84-ssh-managed-child-core-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
