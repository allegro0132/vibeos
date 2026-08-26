#!/usr/bin/env python3
"""Drive and verify the C8.4 SSH managed-child finish/verify successor."""

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
IRQ_PEER_PATH = ROOT / "scripts/c84-ssh-managed-child-irq-overlay-peer.py"

FAMILY = "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY"
IRQ_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"


def load_irq_peer():
    spec = importlib.util.spec_from_file_location(
        "vibeos_c84_finish_verify_irq_peer", IRQ_PEER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the managed-child IRQ predecessor peer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


IRQ = load_irq_peer()
PHASE = IRQ.PHASE
REQUEST = IRQ.REQUEST
TERMINAL_MODE = IRQ.FINISH_VERIFY
VERIFIED_STREAM = IRQ.VERIFIED_STREAM


class DriverError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


def response_line(epoch: int, terminal_mode: str = TERMINAL_MODE) -> str:
    require(
        terminal_mode in (TERMINAL_MODE, VERIFIED_STREAM),
        f"unknown finish/verify terminal mode: {terminal_mode!r}",
    )
    if terminal_mode == TERMINAL_MODE:
        return (
            f"{FAMILY} RESPONSE epoch={epoch} status=0 finish=1 verify=1 cursor=0 "
            "discard=stream_abandoned emitted=0 stored=1 ack=1 "
            f"ready_epoch={epoch + 1}"
        )
    return (
        f"{FAMILY} RESPONSE epoch={epoch} status=0 "
        "finish=1 verify=1 stream=complete ack=0 "
        f"ready_epoch={epoch + 1}"
    )


def drop_line(epoch: int) -> str:
    return (
        f"{FAMILY} DROP epoch={epoch} cancel=lease_cancelled finish=0 verify=0 "
        "stream=0 emitted=0 stored=1 ack=1 "
        f"ready_epoch={epoch + 1}"
    )


def expected_finish_markers(terminal_mode: str = TERMINAL_MODE) -> list[str]:
    return [
        response_line(1, terminal_mode),
        response_line(2, terminal_mode),
        drop_line(3),
        response_line(4, terminal_mode),
    ]


EXPECTED_FINISH_MARKERS = expected_finish_markers()


def normalized_lines(path: Path, *, ignore_incomplete_tail: bool = False) -> list[str]:
    return IRQ.normalized_lines(path, ignore_incomplete_tail=ignore_incomplete_tail)


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


def verify_global_order(path: Path, terminal_mode: str = TERMINAL_MODE) -> None:
    lines = normalized_lines(path)
    request = REQUEST.expected_qemu_markers(terminal_mode)
    request_responses = {1: request[1], 2: request[3], 4: request[7]}
    irq = IRQ.expected_irq_markers(terminal_mode)
    irq_responses = {1: irq[2], 2: irq[3], 4: irq[5]}
    for epoch in (1, 2, 4):
        require_unique_order(
            lines,
            [
                f"{PHASE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                f"{CORE_FAMILY} RESPONSE epoch={epoch} status=0 ",
                request_responses[epoch],
                irq_responses[epoch],
                response_line(epoch, terminal_mode),
            ],
            f"finish/verify normal epoch {epoch} terminal chain",
        )
    require_unique_order(
        lines,
        [
            f"{PHASE_FAMILY} DROP epoch=3 ",
            f"{CORE_FAMILY} DROP epoch=3 ",
            request[5],
            IRQ.drop_line(3),
            drop_line(3),
        ],
        "finish/verify Drop epoch 3 terminal chain",
    )
    for epoch in (1, 2, 3):
        terminal = response_line(epoch, terminal_mode) if epoch != 3 else drop_line(epoch)
        require_unique_order(
            lines,
            [terminal, f"{REQUEST_FAMILY} START epoch={epoch + 1}"],
            f"finish/verify epoch {epoch} closure before reuse",
        )


def verify_closed_sequence(path: Path, terminal_mode: str = TERMINAL_MODE):
    predecessor = IRQ.verify_closed_sequence(path, terminal_mode)
    observed = family_markers(path)
    expected = expected_finish_markers(terminal_mode)
    require(
        observed == expected,
        f"finish/verify marker sequence differs: observed={observed!r}",
    )
    verify_global_order(path, terminal_mode)
    return predecessor


def wait_for_finish_prefix(
    path: Path,
    expected_count: int,
    timeout: float,
    terminal_mode: str = TERMINAL_MODE,
) -> None:
    expected = expected_finish_markers(terminal_mode)[:expected_count]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = family_markers(path, ignore_incomplete_tail=True)
        require(
            observed == expected[: len(observed)],
            f"finish/verify live prefix differs: observed={observed!r}",
        )
        require(
            len(observed) <= expected_count,
            f"finish/verify emitted an early marker: observed={observed!r}",
        )
        if observed == expected:
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for finish/verify marker {expected_count}")


def synthetic_closed_lines(
    terminal_mode: str = TERMINAL_MODE,
    *,
    drop_observer_pairs: int,
) -> list[str]:
    predecessor = IRQ.synthetic_closed_lines(
        terminal_mode,
        drop_observer_pairs=drop_observer_pairs,
    )
    irq_terminals = {
        IRQ.response_line(1, terminal_mode): response_line(1, terminal_mode),
        IRQ.response_line(2, terminal_mode): response_line(2, terminal_mode),
        IRQ.drop_line(3): drop_line(3),
        IRQ.response_line(4, terminal_mode): response_line(4, terminal_mode),
    }
    output: list[str] = []
    for line in predecessor:
        output.append(line)
        if line in irq_terminals:
            output.append(irq_terminals[line])
    return output


def run_parser_selftest() -> int:
    drop_observer_pairs = 14
    valid = synthetic_closed_lines(drop_observer_pairs=drop_observer_pairs)
    with tempfile.TemporaryDirectory(prefix="vibeos-c84-finish-peer-") as directory:
        log = Path(directory) / "frozen.log"

        partial = EXPECTED_FINISH_MARKERS[0][:-9]
        partial_raw = (partial).encode()
        normalized = IRQ.normalized_snapshot(partial_raw, ignore_incomplete_tail=True)
        require(
            [line for line in normalized if FAMILY in line] == [],
            "live parser admitted a partially written finish/verify UART record",
        )
        complete_raw = (EXPECTED_FINISH_MARKERS[0] + "\n").encode()
        normalized = IRQ.normalized_snapshot(complete_raw, ignore_incomplete_tail=True)
        require(
            [line for line in normalized if FAMILY in line] == EXPECTED_FINISH_MARKERS[:1],
            "live parser discarded a complete finish/verify UART record",
        )

        def accepted(lines: list[str], terminal_mode: str = TERMINAL_MODE) -> bool:
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                verify_closed_sequence(log, terminal_mode)
            except (
                DriverError,
                IRQ.DriverError,
                PHASE.DriverError,
                PHASE.CORE.DriverError,
                REQUEST.VerificationError,
            ):
                return False
            return True

        require(accepted(valid), "synthetic finish/verify transcript was rejected")
        require(
            accepted(
                synthetic_closed_lines(
                    drop_observer_pairs=drop_observer_pairs + 1
                )
            ),
            "matching dynamic predecessor Drop counts were rejected",
        )
        mutations: list[tuple[str, list[str]]] = []

        def replace_line(label: str, old: str, new: str) -> None:
            mutated = list(valid)
            require(mutated.count(old) == 1, f"selftest seed count differs for {label}")
            mutated[mutated.index(old)] = new
            mutations.append((label, mutated))

        mutations.append(
            ("missing finish response", [line for line in valid if line != response_line(1)])
        )
        mutations.append(("duplicate finish response", valid + [response_line(4)]))
        replace_line("finish bit", response_line(1), response_line(1).replace("finish=1", "finish=0"))
        replace_line("verify bit", response_line(1), response_line(1).replace("verify=1", "verify=0"))
        replace_line("verified cursor", response_line(1), response_line(1).replace("cursor=0", "cursor=1"))
        replace_line(
            "discard cause",
            response_line(2),
            response_line(2).replace("discard=stream_abandoned", "discard=complete"),
        )
        replace_line("emitted cursor", response_line(2), response_line(2).replace("emitted=0", "emitted=1"))
        replace_line("stored rejection", response_line(4), response_line(4).replace("stored=1", "stored=0"))
        replace_line("ack count", response_line(4), response_line(4).replace("ack=1", "ack=2"))
        replace_line("ready reuse", response_line(4), response_line(4).replace("ready_epoch=5", "ready_epoch=4"))
        replace_line(
            "Drop cause",
            drop_line(3),
            drop_line(3).replace("cancel=lease_cancelled", "cancel=stream_abandoned"),
        )
        replace_line("Drop finish", drop_line(3), drop_line(3).replace("finish=0", "finish=1"))
        replace_line(
            "Drop terminal kind",
            drop_line(3),
            drop_line(3).replace(" DROP ", " RESPONSE epoch=3 status=0 ").replace(
                "epoch=3 epoch=3 ", "epoch=3 "
            ),
        )

        before_irq = list(valid)
        finish_index = before_irq.index(response_line(1))
        irq_index = before_irq.index(IRQ.response_line(1, TERMINAL_MODE))
        before_irq[finish_index], before_irq[irq_index] = (
            before_irq[irq_index],
            before_irq[finish_index],
        )
        mutations.append(("finish terminal before IRQ", before_irq))

        next_start = list(valid)
        finish_index = next_start.index(response_line(1))
        start_index = next_start.index(REQUEST.expected_qemu_markers(TERMINAL_MODE)[2])
        next_start[finish_index], next_start[start_index] = (
            next_start[start_index],
            next_start[finish_index],
        )
        mutations.append(("reuse before finish terminal", next_start))

        mixed_irq = list(valid)
        successor_irq = IRQ.response_line(2, TERMINAL_MODE)
        mixed_irq[mixed_irq.index(successor_irq)] = IRQ.response_line(2, IRQ.LEGACY_CANCEL)
        mutations.append(("mixed legacy IRQ terminal", mixed_irq))

        predecessor_short = list(valid)
        predecessor_short.remove(f"{CORE_FAMILY} RELEASE epoch=4 normal_driver=1")
        mutations.append(("predecessor transcript omission", predecessor_short))
        mutations.append(("late finish marker", valid + [response_line(4)]))

        for label, mutated in mutations:
            require(not accepted(mutated), f"parser selftest mutation was accepted: {label}")

        stream = synthetic_closed_lines(
            VERIFIED_STREAM,
            drop_observer_pairs=drop_observer_pairs,
        )
        require(
            accepted(stream, VERIFIED_STREAM),
            "synthetic verified-stream predecessor transcript was rejected",
        )
        require(
            accepted(
                synthetic_closed_lines(
                    VERIFIED_STREAM,
                    drop_observer_pairs=drop_observer_pairs + 1,
                ),
                VERIFIED_STREAM,
            ),
            "matching dynamic Drop counts were rejected in verified-stream mode",
        )
        for wrong_mode in (IRQ.LEGACY_CANCEL, TERMINAL_MODE):
            require(
                not accepted(stream, wrong_mode),
                f"{wrong_mode} accepted the verified-stream predecessor transcript",
            )
        mixed_stream = list(stream)
        stream_response = response_line(2, VERIFIED_STREAM)
        mixed_stream[mixed_stream.index(stream_response)] = response_line(2, TERMINAL_MODE)
        require(
            not accepted(mixed_stream, VERIFIED_STREAM),
            "verified-stream mode accepted a finish/discard predecessor terminal",
        )
    return len(mutations) + 7


def parser() -> argparse.ArgumentParser:
    value = IRQ.parser()
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
            print(f"PASS c84-ssh-managed-child-finish-verify-peer parser mutations={mutations}")
            return 0
        if arguments.verify_log_only:
            require(arguments.qemu_log is not None, "--qemu-log is required with --verify-log-only")
            normal, dropped = verify_closed_sequence(arguments.qemu_log)
            print(
                "PASS c84-ssh-managed-child-finish-verify-peer frozen log: "
                f"normal_epochs={[item.epoch for item in normal]} drop_epoch={dropped.epoch} "
                "four finish markers and phase/19-Core/8-request/six-IRQ predecessors are exact"
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
        require(PHASE.family_markers(arguments.qemu_log) == [], "readiness armed phase sidecar")
        require(PHASE.family_markers(arguments.qemu_log, CORE_FAMILY) == [], "readiness armed child Core")
        require(
            IRQ.family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [],
            "readiness armed IRQ overlay",
        )
        require(
            family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [],
            "readiness armed finish/verify terminal",
        )

        PHASE.inert_probes(arguments, ssh)
        require(
            IRQ.family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [],
            "inert SSH probes armed IRQ overlay",
        )
        require(
            family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [],
            "inert SSH probes armed finish/verify terminal",
        )

        PHASE.normal_profiled_request(arguments, ssh, 1, terminal_mode=TERMINAL_MODE)
        IRQ.wait_for_irq_prefix(arguments.qemu_log, 3, arguments.marker_timeout, TERMINAL_MODE)
        wait_for_finish_prefix(arguments.qemu_log, 1, arguments.marker_timeout)

        PHASE.normal_profiled_request(arguments, ssh, 2, terminal_mode=TERMINAL_MODE)
        IRQ.wait_for_irq_prefix(arguments.qemu_log, 4, arguments.marker_timeout, TERMINAL_MODE)
        wait_for_finish_prefix(arguments.qemu_log, 2, arguments.marker_timeout)

        PHASE.active_drop_request(arguments, ssh, 3)
        IRQ.wait_for_irq_prefix(arguments.qemu_log, 5, arguments.marker_timeout, TERMINAL_MODE)
        wait_for_finish_prefix(arguments.qemu_log, 3, arguments.marker_timeout)
        PHASE.post_drop_readiness(arguments, ssh)
        require(
            family_markers(arguments.qemu_log, ignore_incomplete_tail=True)
            == EXPECTED_FINISH_MARKERS[:3],
            "post-Drop readiness changed finish/verify markers",
        )

        PHASE.normal_profiled_request(
            arguments,
            ssh,
            4,
            await_readiness=False,
            terminal_mode=TERMINAL_MODE,
        )
        IRQ.wait_for_irq_prefix(arguments.qemu_log, 6, arguments.marker_timeout, TERMINAL_MODE)
        wait_for_finish_prefix(arguments.qemu_log, 4, arguments.marker_timeout)

        time.sleep(0.3)
        normal, dropped = verify_closed_sequence(arguments.qemu_log)
        print(
            "c84-ssh-managed-child-finish-verify-peer: controlled observation "
            f"normal_epochs={[item.epoch for item in normal]} drop_epoch={dropped.epoch} "
            "finish=3 verify=3 discarded_zero_cursor=3 cancelled=1"
        )
        print(
            "PASS c84-ssh-managed-child-finish-verify-peer: exact response finish/verify/"
            "StreamAbandoned closure, epoch-3 cancel, Ready reuse, and all predecessor "
            "transcripts passed"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        DriverError,
        IRQ.DriverError,
        PHASE.DriverError,
        PHASE.CORE.DriverError,
        PHASE.PEER.PeerError,
        REQUEST.VerificationError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL c84-ssh-managed-child-finish-verify-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
