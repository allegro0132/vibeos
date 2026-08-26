#!/usr/bin/env python3
"""Drive and verify the C8.4 SSH managed-child IRQ-overlay composition."""

from __future__ import annotations

import argparse
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
PHASE_PEER_PATH = ROOT / "scripts/c84-ssh-managed-child-phase-sidecar-peer.py"
REQUEST_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-profile-request-parent.py"

FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PHASE = load_module("vibeos_c84_managed_child_irq_phase_peer", PHASE_PEER_PATH)
REQUEST = load_module("vibeos_c84_managed_child_irq_request_verifier", REQUEST_VERIFIER_PATH)
LEGACY_CANCEL = REQUEST.LEGACY_CANCEL
FINISH_VERIFY = REQUEST.FINISH_VERIFY


class DriverError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


def response_line(epoch: int, terminal_mode: str = LEGACY_CANCEL) -> str:
    first = int(epoch == 1)
    return (
        f"{FAMILY} RESPONSE epoch={epoch} status=0 "
        f"parent_pair={first} child_pair={first} terminal_inactive=1 "
        f"paired=2 inactive={epoch} active_epoch=0 "
        f"{REQUEST.response_terminal_suffix(terminal_mode)} "
        f"ready_epoch={epoch + 1}"
    )


def drop_line(epoch: int) -> str:
    return (
        f"{FAMILY} DROP epoch={epoch} parent_pair=0 child_pair=0 "
        f"terminal_inactive=1 paired=2 inactive={epoch} active_epoch=0 "
        f"cancel=1 ack=1 ready_epoch={epoch + 1}"
    )


def expected_irq_markers(terminal_mode: str = LEGACY_CANCEL) -> list[str]:
    return [
        f"{FAMILY} PARENT_SSIP epoch=1 causal=1 paired=1 inactive=0 active_epoch=1",
        f"{FAMILY} CHILD_SSIP epoch=1 causal=1 paired=2 inactive=0 active_epoch=1",
        response_line(1, terminal_mode),
        response_line(2, terminal_mode),
        drop_line(3),
        response_line(4, terminal_mode),
    ]


# Frozen compatibility export for the committed IRQ-overlay gate.
EXPECTED_IRQ_MARKERS = expected_irq_markers()


def normalized_snapshot(raw: bytes, *, ignore_incomplete_tail: bool = False) -> list[str]:
    value = raw.decode("utf-8", errors="replace").replace("\r", "\n")
    if re.search(r"\bWASM_[A-Z0-9_]+ FAIL\b", value):
        raise DriverError("guest reported a WASM acceptance failure")
    if "panicked at" in value or "[!] fatal" in value or "[!] panic" in value:
        raise DriverError("guest reported a panic or fatal error")
    for marker in PHASE.FORMAL_PUBLISHER_MARKERS:
        if marker in value:
            raise DriverError(f"diagnostic image published forbidden marker: {marker}")
    lines = [PHASE.normalize_serial_line(line) for line in value.splitlines()]
    if ignore_incomplete_tail and raw and raw[-1:] not in (b"\n", b"\r") and lines:
        lines.pop()
    return lines


def normalized_lines(path: Path, *, ignore_incomplete_tail: bool = False) -> list[str]:
    # One snapshot controls both decoding and the incomplete-tail decision.
    # Reading twice would let UART append a newline between reads and admit the
    # first snapshot's partial family marker as if it had been complete.
    return normalized_snapshot(path.read_bytes(), ignore_incomplete_tail=ignore_incomplete_tail)


def family_markers(path: Path, *, ignore_incomplete_tail: bool = False) -> list[str]:
    return [
        line
        for line in normalized_lines(path, ignore_incomplete_tail=ignore_incomplete_tail)
        if FAMILY in line
    ]


def require_unique_order(lines: list[str], needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [index for index, line in enumerate(lines) if needle in line]
        require(len(matches) == 1, f"{label} marker count differs for {needle!r}: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} marker order differs: {needles!r}")


def verify_global_order(path: Path, terminal_mode: str = LEGACY_CANCEL) -> None:
    lines = normalized_lines(path)
    require_unique_order(
        lines,
        [
            f"{REQUEST_FAMILY} START epoch=1",
            EXPECTED_IRQ_MARKERS[0],
            f"{CORE_FAMILY} CLAIM epoch=1 child_index=0 first_poll=1",
            f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=abi",
            EXPECTED_IRQ_MARKERS[1],
            f"{CORE_FAMILY} CORE epoch=1 ordinary=1 first_pair=1",
            f"{PHASE_FAMILY} CHILD_WAIT epoch=1 state=open first=1",
        ],
        "epoch-1 parent/child causal SSIP",
    )

    for epoch in (1, 2, 4):
        require_unique_order(
            lines,
            [
                f"{PHASE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                f"{CORE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                f"{REQUEST_FAMILY} RESPONSE epoch={epoch} status=0 ",
                response_line(epoch, terminal_mode),
            ],
            f"normal epoch {epoch} terminal chain",
        )
    require_unique_order(
        lines,
        [
            f"{PHASE_FAMILY} DROP epoch=3 ",
            f"{CORE_FAMILY} DROP epoch=3 ",
            f"{REQUEST_FAMILY} DROP epoch=3 ",
            drop_line(3),
        ],
        "Drop epoch 3 terminal chain",
    )
    for epoch in (1, 2, 3):
        terminal = (
            response_line(epoch, terminal_mode) if epoch != 3 else drop_line(epoch)
        )
        require_unique_order(
            lines,
            [terminal, f"{REQUEST_FAMILY} START epoch={epoch + 1}"],
            f"epoch {epoch} closure before reuse",
        )


def verify_closed_sequence(path: Path, terminal_mode: str = LEGACY_CANCEL):
    phase = PHASE.verify_closed_sequence(path, terminal_mode)
    REQUEST.verify_qemu_transcript(path.read_bytes(), terminal_mode)
    observed = family_markers(path)
    expected = expected_irq_markers(terminal_mode)
    require(
        observed == expected,
        f"IRQ-overlay marker sequence differs: observed={observed!r}",
    )
    verify_global_order(path, terminal_mode)
    return phase


def wait_for_irq_prefix(
    path: Path,
    expected_count: int,
    timeout: float,
    terminal_mode: str = LEGACY_CANCEL,
) -> None:
    expected = expected_irq_markers(terminal_mode)[:expected_count]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = family_markers(path, ignore_incomplete_tail=True)
        require(
            observed == expected[: len(observed)],
            f"IRQ-overlay live prefix differs: observed={observed!r}",
        )
        require(
            len(observed) <= expected_count,
            f"IRQ-overlay emitted an early marker: observed={observed!r}",
        )
        if observed == expected:
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for IRQ-overlay marker {expected_count}")


def core_normal_lines(epoch: int, terminal_mode: str = LEGACY_CANCEL) -> list[str]:
    core_polls = PHASE.DELAYED_CORE_POLLS if epoch == 2 else PHASE.CORE.EXPECTED_CORE_POLLS
    typed_polls = PHASE.DELAYED_TYPED_POLLS if epoch == 2 else PHASE.CORE.EXPECTED_TYPED_POLLS
    return [
        f"{CORE_FAMILY} BIND epoch={epoch} child_index=0 before_publish=1",
        f"{CORE_FAMILY} CLAIM epoch={epoch} child_index=0 first_poll=1",
        f"{CORE_FAMILY} CORE epoch={epoch} ordinary=1 first_pair=1",
        f"{CORE_FAMILY} RELEASE epoch={epoch} normal_driver=1",
        PHASE.CORE.normal_response_line(
            epoch,
            terminal_mode,
            core_polls=core_polls,
            typed_polls=typed_polls,
        ),
    ]


def synthetic_closed_lines(terminal_mode: str = LEGACY_CANCEL) -> list[str]:
    output: list[str] = []
    request = REQUEST.expected_qemu_markers(terminal_mode)
    irq = expected_irq_markers(terminal_mode)
    request_cursor = 0
    irq_cursor = 0
    for epoch in (1, 2):
        phase = PHASE.normal_lines(epoch, terminal_mode)
        core = core_normal_lines(epoch, terminal_mode)
        output.append(request[request_cursor])
        request_cursor += 1
        if epoch == 1:
            output.append(irq[irq_cursor])
            irq_cursor += 1
        output.extend(core[:2])
        prefix = 5 if epoch == 2 else 4
        output.extend(phase[:3])
        if epoch == 1:
            output.append(irq[irq_cursor])
            irq_cursor += 1
        output.append(core[2])
        output.extend(phase[3:prefix])
        output.append(phase[prefix])
        output.append(core[3])
        output.extend(phase[prefix + 1 :])
        output.append(core[4])
        output.append(request[request_cursor])
        request_cursor += 1
        output.append(irq[irq_cursor])
        irq_cursor += 1

    output.append(request[request_cursor])
    request_cursor += 1
    drop_phase = [
        f"{PHASE_FAMILY} CHILD_PHASE epoch=3 phase=validation",
        f"{PHASE_FAMILY} CHILD_PHASE epoch=3 phase=instantiation",
        f"{PHASE_FAMILY} CHILD_PHASE epoch=3 phase=abi",
        f"{PHASE_FAMILY} CHILD_WAIT epoch=3 state=open first=1",
        PHASE.drop_line(3),
    ]
    core_drop = [
        f"{CORE_FAMILY} BIND epoch=3 child_index=0 before_publish=1",
        f"{CORE_FAMILY} CLAIM epoch=3 child_index=0 first_poll=1",
        f"{CORE_FAMILY} CORE epoch=3 ordinary=1 first_pair=1",
        f"{CORE_FAMILY} DROP epoch=3 claim=1 release=0 detach=exited clean=0 "
        f"child_faults=abandoned+detached observer_pairs={PHASE.CORE.EXPECTED_DROP_OBSERVER_PAIRS} "
        "observer_closed=1 cancel=1 ack=1 ready_epoch=4",
    ]
    output.extend(core_drop[:2])
    output.extend(drop_phase[:3])
    output.append(core_drop[2])
    output.append(drop_phase[3])
    output.append(drop_phase[4])
    output.append(core_drop[3])
    output.append(request[request_cursor])
    request_cursor += 1
    output.append(irq[irq_cursor])
    irq_cursor += 1

    epoch = 4
    phase = PHASE.normal_lines(epoch, terminal_mode)
    core = core_normal_lines(epoch, terminal_mode)
    output.append(request[request_cursor])
    request_cursor += 1
    output.extend(core[:2])
    output.extend(phase[:3])
    output.append(core[2])
    output.append(phase[3])
    output.append(phase[4])
    output.append(core[3])
    output.extend(phase[5:])
    output.append(core[4])
    output.append(request[request_cursor])
    output.append(irq[irq_cursor])
    return output


def run_parser_selftest() -> int:
    valid = synthetic_closed_lines()
    with tempfile.TemporaryDirectory(prefix="vibeos-c84-irq-peer-") as directory:
        log = Path(directory) / "frozen.log"

        partial = EXPECTED_IRQ_MARKERS[1][:-7]
        partial_raw = (EXPECTED_IRQ_MARKERS[0] + "\n" + partial).encode()
        require(
            [line for line in normalized_snapshot(partial_raw, ignore_incomplete_tail=True) if FAMILY in line]
            == EXPECTED_IRQ_MARKERS[:1],
            "live parser admitted a partially written IRQ UART record",
        )
        complete_raw = ("\n".join(EXPECTED_IRQ_MARKERS[:2]) + "\n").encode()
        require(
            [line for line in normalized_snapshot(complete_raw, ignore_incomplete_tail=True) if FAMILY in line]
            == EXPECTED_IRQ_MARKERS[:2],
            "live parser discarded a complete IRQ UART record",
        )

        def accepted(
            lines: list[str], terminal_mode: str = LEGACY_CANCEL
        ) -> bool:
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                verify_closed_sequence(log, terminal_mode)
            except (DriverError, PHASE.DriverError, PHASE.CORE.DriverError, REQUEST.VerificationError):
                return False
            return True

        require(accepted(valid), "synthetic closed transcript was rejected")
        mutations: list[tuple[str, list[str]]] = []

        def replace_line(label: str, old: str, new: str) -> None:
            mutated = list(valid)
            require(mutated.count(old) == 1, f"selftest seed count differs for {label}")
            mutated[mutated.index(old)] = new
            mutations.append((label, mutated))

        mutations.append(("missing parent SSIP", [line for line in valid if line != EXPECTED_IRQ_MARKERS[0]]))
        mutations.append(("missing child SSIP", [line for line in valid if line != EXPECTED_IRQ_MARKERS[1]]))
        mutations.append(("duplicate child SSIP", valid + [EXPECTED_IRQ_MARKERS[1]]))
        replace_line("parent inactive delta", EXPECTED_IRQ_MARKERS[0], EXPECTED_IRQ_MARKERS[0].replace("inactive=0", "inactive=1"))
        replace_line("child paired total", EXPECTED_IRQ_MARKERS[1], EXPECTED_IRQ_MARKERS[1].replace("paired=2", "paired=1"))
        replace_line("child inactive epoch", EXPECTED_IRQ_MARKERS[1], EXPECTED_IRQ_MARKERS[1].replace("active_epoch=1", "active_epoch=0"))
        replace_line("epoch-1 terminal active", response_line(1), response_line(1).replace("active_epoch=0", "active_epoch=1"))
        replace_line("epoch-2 active parent leak", response_line(2), response_line(2).replace("parent_pair=0", "parent_pair=1"))
        replace_line("epoch-2 inactive total", response_line(2), response_line(2).replace("inactive=2", "inactive=1"))
        replace_line("Drop terminal kind", drop_line(3), drop_line(3).replace(" DROP ", " RESPONSE epoch=3 status=0 ").replace("epoch=3 epoch=3 ", "epoch=3 "))
        replace_line("epoch-4 ready reuse", response_line(4), response_line(4).replace("ready_epoch=5", "ready_epoch=4"))

        wrong_parent_child = list(valid)
        parent_index = wrong_parent_child.index(EXPECTED_IRQ_MARKERS[0])
        child_index = wrong_parent_child.index(EXPECTED_IRQ_MARKERS[1])
        wrong_parent_child[parent_index], wrong_parent_child[child_index] = (
            wrong_parent_child[child_index],
            wrong_parent_child[parent_index],
        )
        mutations.append(("parent/child causal order", wrong_parent_child))

        child_before_abi = list(valid)
        child_index = child_before_abi.index(EXPECTED_IRQ_MARKERS[1])
        abi_index = child_before_abi.index(f"{PHASE_FAMILY} CHILD_PHASE epoch=1 phase=abi")
        child_before_abi[child_index], child_before_abi[abi_index] = (
            child_before_abi[abi_index],
            child_before_abi[child_index],
        )
        mutations.append(("child SSIP before ABI", child_before_abi))

        terminal_before_request = list(valid)
        irq_index = terminal_before_request.index(response_line(1))
        request_index = terminal_before_request.index(REQUEST.EXPECTED_QEMU_MARKERS[1])
        terminal_before_request[irq_index], terminal_before_request[request_index] = (
            terminal_before_request[request_index],
            terminal_before_request[irq_index],
        )
        mutations.append(("IRQ terminal before request terminal", terminal_before_request))

        next_start_before_terminal = list(valid)
        irq_index = next_start_before_terminal.index(response_line(1))
        start_index = next_start_before_terminal.index(REQUEST.EXPECTED_QEMU_MARKERS[2])
        next_start_before_terminal[irq_index], next_start_before_terminal[start_index] = (
            next_start_before_terminal[start_index],
            next_start_before_terminal[irq_index],
        )
        mutations.append(("reuse before IRQ terminal", next_start_before_terminal))

        predecessor_short = list(valid)
        predecessor_short.remove(f"{CORE_FAMILY} RELEASE epoch=4 normal_driver=1")
        mutations.append(("predecessor 19-marker omission", predecessor_short))
        request_short = list(valid)
        request_short.remove(REQUEST.EXPECTED_QEMU_MARKERS[7])
        mutations.append(("predecessor request omission", request_short))
        mutations.append(("late IRQ marker", valid + [response_line(4)]))

        for label, mutated in mutations:
            require(not accepted(mutated), f"parser selftest mutation was accepted: {label}")

        successor = synthetic_closed_lines(FINISH_VERIFY)
        require(
            accepted(successor, FINISH_VERIFY),
            "synthetic finish/verify IRQ transcript was rejected",
        )
        require(
            not accepted(successor, LEGACY_CANCEL),
            "legacy IRQ mode accepted the finish/verify transcript",
        )
        mixed = list(successor)
        successor_irq = expected_irq_markers(FINISH_VERIFY)
        mixed[mixed.index(successor_irq[3])] = EXPECTED_IRQ_MARKERS[3]
        require(
            not accepted(mixed, FINISH_VERIFY),
            "finish/verify IRQ mode accepted a legacy epoch-2 terminal",
        )
    return len(mutations) + 5


def parser() -> argparse.ArgumentParser:
    value = PHASE.parser()
    value.description = __doc__
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
            print(f"PASS c84-ssh-managed-child-irq-overlay-peer parser mutations={mutations}")
            return 0
        if arguments.verify_log_only:
            require(arguments.qemu_log is not None, "--qemu-log is required with --verify-log-only")
            normal, dropped = verify_closed_sequence(arguments.qemu_log)
            print(
                "PASS c84-ssh-managed-child-irq-overlay-peer frozen log: "
                f"normal_epochs={[item.epoch for item in normal]} drop_epoch={dropped.epoch} "
                "phase, predecessor 19-marker/request, and six-marker IRQ transcripts are exact"
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
        require(PHASE.family_markers(arguments.qemu_log) == [], "authenticated readiness armed phase sidecar")
        require(PHASE.family_markers(arguments.qemu_log, CORE_FAMILY) == [], "authenticated readiness armed child Core")
        require(
            family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [],
            "authenticated readiness armed IRQ overlay",
        )

        PHASE.inert_probes(arguments, ssh)
        require(
            family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [],
            "inert SSH probes armed IRQ overlay",
        )
        PHASE.normal_profiled_request(arguments, ssh, 1)
        wait_for_irq_prefix(arguments.qemu_log, 3, arguments.marker_timeout)
        PHASE.normal_profiled_request(arguments, ssh, 2)
        wait_for_irq_prefix(arguments.qemu_log, 4, arguments.marker_timeout)
        PHASE.active_drop_request(arguments, ssh, 3)
        wait_for_irq_prefix(arguments.qemu_log, 5, arguments.marker_timeout)
        PHASE.post_drop_readiness(arguments, ssh)
        require(
            family_markers(arguments.qemu_log, ignore_incomplete_tail=True)
            == EXPECTED_IRQ_MARKERS[:5],
            "post-Drop readiness changed IRQ markers",
        )
        PHASE.normal_profiled_request(arguments, ssh, 4, await_readiness=False)
        wait_for_irq_prefix(arguments.qemu_log, 6, arguments.marker_timeout)

        time.sleep(0.3)
        normal, dropped = verify_closed_sequence(arguments.qemu_log)
        print(
            "c84-ssh-managed-child-irq-overlay-peer: controlled observation "
            f"normal_epochs={[item.epoch for item in normal]} drop_epoch={dropped.epoch} "
            "paired=2 terminal_inactive=4 active_epoch=0"
        )
        print(
            "PASS c84-ssh-managed-child-irq-overlay-peer: epoch-1 parent/child causal self-SSIP, "
            "epochs 2-4 isolation, terminal inactive SSIP closure, exact phase/Core/request "
            "predecessors, Drop reuse, and six-marker transcript passed"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        DriverError,
        PHASE.DriverError,
        PHASE.CORE.DriverError,
        PHASE.PEER.PeerError,
        REQUEST.VerificationError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL c84-ssh-managed-child-irq-overlay-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
