#!/usr/bin/env python3
"""Drive and verify the C8.4 SSH managed-child verified-stream successor."""

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
FINISH_PEER_PATH = ROOT / "scripts/c84-ssh-managed-child-finish-verify-peer.py"

FAMILY = "WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM"
FINISH_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY"
IRQ_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"
NUMBER = r"(?:0|[1-9][0-9]*)"
U64_MAX = (1 << 64) - 1
INTERVAL_CAPACITY = 65_536


def load_finish_peer():
    spec = importlib.util.spec_from_file_location(
        "vibeos_c84_verified_stream_finish_peer", FINISH_PEER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the finish/verify predecessor peer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FINISH = load_finish_peer()
IRQ = FINISH.IRQ
PHASE = FINISH.PHASE
REQUEST = FINISH.REQUEST
TERMINAL_MODE = FINISH.VERIFIED_STREAM


class DriverError(Exception):
    pass


@dataclass(frozen=True)
class StreamObservation:
    epoch: int
    total_ticks: int
    interval_count: int
    emitted: int
    cursor: int
    ready_epoch: int


@dataclass(frozen=True)
class DropObservation:
    epoch: int
    ready_epoch: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


NORMAL_RESPONSE = re.compile(
    rf"^{FAMILY} RESPONSE epoch=(?P<epoch>{NUMBER}) status=0 finish=1 verify=1 "
    rf"summary=1 initial_cursor=0 total_ticks=(?P<total_ticks>{NUMBER}) "
    rf"interval_capacity=65536 interval_count=(?P<interval_count>{NUMBER}) "
    rf"intervals_complete=1 emitted=(?P<emitted>{NUMBER}) cursor=(?P<cursor>{NUMBER}) "
    rf"sequence=exact contiguous=1 nonempty=1 adjacent_distinct=1 "
    rf"phase_sum=total_ticks phase_rescan=summary final_end=total_ticks "
    rf"stream=complete stored=0 ack=0 ready_epoch=(?P<ready_epoch>{NUMBER})$"
)

DROP_RESPONSE = re.compile(
    rf"^{FAMILY} DROP epoch=(?P<epoch>{NUMBER}) cancel=lease_cancelled "
    rf"finish=0 verify=0 summary=0 stream=0 emitted=0 stored=1 ack=1 "
    rf"ready_epoch=(?P<ready_epoch>{NUMBER})$"
)


def response_line(epoch: int, total_ticks: int, interval_count: int) -> str:
    return (
        f"{FAMILY} RESPONSE epoch={epoch} status=0 finish=1 verify=1 "
        f"summary=1 initial_cursor=0 total_ticks={total_ticks} "
        f"interval_capacity=65536 interval_count={interval_count} intervals_complete=1 "
        f"emitted={interval_count} cursor={interval_count} sequence=exact contiguous=1 "
        "nonempty=1 adjacent_distinct=1 phase_sum=total_ticks phase_rescan=summary "
        "final_end=total_ticks stream=complete stored=0 ack=0 "
        f"ready_epoch={epoch + 1}"
    )


def drop_line(epoch: int) -> str:
    return (
        f"{FAMILY} DROP epoch={epoch} cancel=lease_cancelled finish=0 verify=0 "
        "summary=0 stream=0 emitted=0 stored=1 ack=1 "
        f"ready_epoch={epoch + 1}"
    )


def parse_response(line: str, epoch: int) -> StreamObservation:
    response = NORMAL_RESPONSE.fullmatch(line)
    require(response is not None, f"verified-stream epoch {epoch} RESPONSE differs: {line!r}")
    assert response is not None
    observed_epoch = int(response.group("epoch"))
    ready_epoch = int(response.group("ready_epoch"))
    total_ticks = int(response.group("total_ticks"))
    interval_count = int(response.group("interval_count"))
    emitted = int(response.group("emitted"))
    cursor = int(response.group("cursor"))
    require(observed_epoch == epoch, f"verified-stream epoch {epoch} RESPONSE epoch differs")
    require(ready_epoch == epoch + 1, f"verified-stream epoch {epoch} Ready reuse differs")
    require(
        1 <= total_ticks <= U64_MAX,
        f"verified-stream epoch {epoch} total_ticks is not a positive u64",
    )
    require(
        1 <= interval_count <= INTERVAL_CAPACITY,
        f"verified-stream epoch {epoch} interval_count is out of range",
    )
    require(
        interval_count <= total_ticks,
        f"verified-stream epoch {epoch} nonempty contiguous intervals exceed total ticks",
    )
    require(
        interval_count == emitted == cursor,
        f"verified-stream epoch {epoch} count/emitted/cursor differ",
    )
    return StreamObservation(
        epoch,
        total_ticks,
        interval_count,
        emitted,
        cursor,
        ready_epoch,
    )


def parse_drop(line: str, epoch: int) -> DropObservation:
    response = DROP_RESPONSE.fullmatch(line)
    require(response is not None, f"verified-stream epoch {epoch} DROP differs: {line!r}")
    assert response is not None
    observed_epoch = int(response.group("epoch"))
    ready_epoch = int(response.group("ready_epoch"))
    require(observed_epoch == epoch, f"verified-stream epoch {epoch} DROP epoch differs")
    require(ready_epoch == epoch + 1, f"verified-stream epoch {epoch} DROP reuse differs")
    return DropObservation(epoch, ready_epoch)


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
) -> tuple[list[StreamObservation], DropObservation]:
    require(len(markers) == 4, f"verified-stream marker count differs: {markers!r}")
    normal = [parse_response(markers[0], 1), parse_response(markers[1], 2)]
    dropped = parse_drop(markers[2], 3)
    normal.append(parse_response(markers[3], 4))
    return normal, dropped


def require_unique_order(lines: list[str], needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [index for index, line in enumerate(lines) if needle in line]
        require(len(matches) == 1, f"{label} marker count differs for {needle!r}: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} marker order differs: {needles!r}")


def verify_global_order(path: Path, normal: list[StreamObservation]) -> None:
    lines = normalized_lines(path)
    request = REQUEST.expected_qemu_markers(TERMINAL_MODE)
    request_responses = {1: request[1], 2: request[3], 4: request[7]}
    irq = IRQ.expected_irq_markers(TERMINAL_MODE)
    irq_responses = {1: irq[2], 2: irq[3], 4: irq[5]}
    finish = FINISH.expected_finish_markers(TERMINAL_MODE)
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
                response_line(epoch, observation.total_ticks, observation.interval_count),
            ],
            f"verified-stream normal epoch {epoch} terminal chain",
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
        "verified-stream Drop epoch 3 terminal chain",
    )
    for epoch in (1, 2, 3):
        if epoch == 3:
            terminal = drop_line(3)
        else:
            observation = by_epoch[epoch]
            terminal = response_line(epoch, observation.total_ticks, observation.interval_count)
        require_unique_order(
            lines,
            [terminal, f"{REQUEST_FAMILY} START epoch={epoch + 1}"],
            f"verified-stream epoch {epoch} closure before reuse",
        )


def verify_closed_sequence(path: Path):
    predecessor = FINISH.verify_closed_sequence(path, TERMINAL_MODE)
    normal, dropped = parse_marker_sequence(family_markers(path))
    verify_global_order(path, normal)
    return predecessor, normal, dropped


def wait_for_verified_prefix(path: Path, expected_count: int, timeout: float) -> None:
    expected_epochs = (1, 2, 3, 4)[:expected_count]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = family_markers(path, ignore_incomplete_tail=True)
        require(
            len(observed) <= expected_count,
            f"verified-stream emitted an early marker: observed={observed!r}",
        )
        for line, epoch in zip(
            observed,
            expected_epochs[: len(observed)],
            strict=True,
        ):
            if epoch == 3:
                parse_drop(line, epoch)
            else:
                parse_response(line, epoch)
        if len(observed) == expected_count:
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for verified-stream marker {expected_count}")


def synthetic_closed_lines(
    totals: dict[int, int],
    counts: dict[int, int],
    *,
    drop_observer_pairs: int,
) -> list[str]:
    predecessor = FINISH.synthetic_closed_lines(
        TERMINAL_MODE,
        drop_observer_pairs=drop_observer_pairs,
    )
    finish_terminals = {
        FINISH.response_line(1, TERMINAL_MODE): response_line(1, totals[1], counts[1]),
        FINISH.response_line(2, TERMINAL_MODE): response_line(2, totals[2], counts[2]),
        FINISH.drop_line(3): drop_line(3),
        FINISH.response_line(4, TERMINAL_MODE): response_line(4, totals[4], counts[4]),
    }
    output: list[str] = []
    for line in predecessor:
        output.append(line)
        if line in finish_terminals:
            output.append(finish_terminals[line])
    return output


def run_parser_selftest() -> int:
    drop_observer_pairs = 14
    totals = {1: 101, 2: U64_MAX, 4: 303}
    counts = {1: 1, 2: INTERVAL_CAPACITY, 4: 17}
    valid = synthetic_closed_lines(
        totals,
        counts,
        drop_observer_pairs=drop_observer_pairs,
    )
    with tempfile.TemporaryDirectory(prefix="vibeos-c84-verified-stream-peer-") as directory:
        log = Path(directory) / "frozen.log"

        for label, prefix, expected_count in (
            ("empty", "", 1),
            ("partial", response_line(1, totals[1], counts[1]) + "\n", 2),
        ):
            log.write_text(prefix, encoding="utf-8")
            try:
                wait_for_verified_prefix(log, expected_count, 0.02)
            except DriverError:
                pass
            else:
                raise DriverError(f"{label} live prefix unexpectedly completed")

        partial = response_line(1, totals[1], counts[1])[:-11]
        normalized = IRQ.normalized_snapshot(partial.encode(), ignore_incomplete_tail=True)
        require(
            [line for line in normalized if FAMILY in line] == [],
            "live parser admitted a partially written verified-stream record",
        )
        complete = (response_line(1, totals[1], counts[1]) + "\n").encode()
        normalized = IRQ.normalized_snapshot(complete, ignore_incomplete_tail=True)
        require(
            [line for line in normalized if FAMILY in line]
            == [response_line(1, totals[1], counts[1])],
            "live parser discarded a complete verified-stream record",
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

        require(accepted(valid), "synthetic verified-stream transcript was rejected")
        require(
            accepted(
                synthetic_closed_lines(
                    {1: 7, 2: 9, 4: 11},
                    {1: 3, 2: 5, 4: 7},
                    drop_observer_pairs=drop_observer_pairs + 1,
                )
            ),
            "dynamic stream or matching Drop counts were frozen",
        )

        mutations: list[tuple[str, list[str]]] = []

        def replace_line(label: str, old: str, new: str) -> None:
            mutated = list(valid)
            require(mutated.count(old) == 1, f"selftest seed count differs for {label}")
            mutated[mutated.index(old)] = new
            mutations.append((label, mutated))

        first = response_line(1, totals[1], counts[1])
        second = response_line(2, totals[2], counts[2])
        fourth = response_line(4, totals[4], counts[4])
        mutations.append(("missing response", [line for line in valid if line != first]))
        mutations.append(("duplicate response", valid + [fourth]))
        replace_line("noncanonical epoch", first, first.replace("epoch=1", "epoch=01", 1))
        replace_line("zero total", first, first.replace("total_ticks=101", "total_ticks=0", 1))
        replace_line(
            "more nonempty intervals than ticks",
            first,
            response_line(1, 1, 2),
        )
        replace_line(
            "oversized total",
            second,
            second.replace(f"total_ticks={U64_MAX}", f"total_ticks={U64_MAX + 1}", 1),
        )
        replace_line("zero interval count", first, first.replace("interval_count=1", "interval_count=0", 1))
        replace_line(
            "oversized interval count",
            second,
            second.replace("interval_count=65536", "interval_count=65537", 1),
        )
        replace_line(
            "noncanonical interval count",
            second,
            second.replace("interval_count=65536", "interval_count=065536", 1),
        )
        replace_line("emitted mismatch", fourth, fourth.replace("emitted=17", "emitted=16", 1))
        replace_line("cursor mismatch", fourth, fourth.replace("cursor=17", "cursor=16", 1))
        replace_line("initial cursor", fourth, fourth.replace("initial_cursor=0", "initial_cursor=1", 1))
        replace_line("capacity", fourth, fourth.replace("interval_capacity=65536", "interval_capacity=65535", 1))
        replace_line("completeness", fourth, fourth.replace("intervals_complete=1", "intervals_complete=0", 1))
        replace_line("sequence", fourth, fourth.replace("sequence=exact", "sequence=forged", 1))
        replace_line("contiguity", fourth, fourth.replace("contiguous=1", "contiguous=0", 1))
        replace_line("nonempty", fourth, fourth.replace("nonempty=1", "nonempty=0", 1))
        replace_line(
            "adjacent phase",
            fourth,
            fourth.replace("adjacent_distinct=1", "adjacent_distinct=0", 1),
        )
        replace_line("phase sum", fourth, fourth.replace("phase_sum=total_ticks", "phase_sum=partial", 1))
        replace_line("phase rescan", fourth, fourth.replace("phase_rescan=summary", "phase_rescan=forged", 1))
        replace_line("final endpoint", fourth, fourth.replace("final_end=total_ticks", "final_end=partial", 1))
        replace_line("stream completion", fourth, fourth.replace("stream=complete", "stream=partial", 1))
        replace_line("stored rejection", fourth, fourth.replace("stored=0", "stored=1", 1))
        replace_line("success acknowledgement", fourth, fourth.replace("ack=0", "ack=1", 1))
        replace_line("Ready reuse", fourth, fourth.replace("ready_epoch=5", "ready_epoch=4", 1))
        replace_line("Drop finish", drop_line(3), drop_line(3).replace("finish=0", "finish=1", 1))
        replace_line("Drop summary", drop_line(3), drop_line(3).replace("summary=0", "summary=1", 1))
        replace_line("Drop stream", drop_line(3), drop_line(3).replace("stream=0", "stream=complete", 1))
        replace_line(
            "Drop terminal kind",
            drop_line(3),
            drop_line(3).replace(" DROP ", " RESPONSE epoch=3 status=0 ").replace(
                "epoch=3 epoch=3 ", "epoch=3 "
            ),
        )

        before_finish = list(valid)
        verified_index = before_finish.index(first)
        finish_index = before_finish.index(FINISH.response_line(1, TERMINAL_MODE))
        before_finish[verified_index], before_finish[finish_index] = (
            before_finish[finish_index],
            before_finish[verified_index],
        )
        mutations.append(("verified terminal before finish", before_finish))

        next_start = list(valid)
        verified_index = next_start.index(first)
        start_index = next_start.index(REQUEST.expected_qemu_markers(TERMINAL_MODE)[2])
        next_start[verified_index], next_start[start_index] = (
            next_start[start_index],
            next_start[verified_index],
        )
        mutations.append(("reuse before verified terminal", next_start))

        mixed_finish = list(valid)
        stream_finish = FINISH.response_line(2, TERMINAL_MODE)
        mixed_finish[mixed_finish.index(stream_finish)] = FINISH.response_line(2)
        mutations.append(("mixed discard predecessor", mixed_finish))

        predecessor_short = list(valid)
        predecessor_short.remove(f"{CORE_FAMILY} RELEASE epoch=4 normal_driver=1")
        mutations.append(("predecessor transcript omission", predecessor_short))
        mutations.append(("late verified marker", valid + [fourth]))

        for label, mutated in mutations:
            require(not accepted(mutated), f"parser selftest mutation was accepted: {label}")
    return len(mutations) + 6


def parser() -> argparse.ArgumentParser:
    value = FINISH.parser()
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
            print(f"PASS c84-ssh-managed-child-verified-stream-peer parser mutations={mutations}")
            return 0
        if arguments.verify_log_only:
            require(arguments.qemu_log is not None, "--qemu-log is required with --verify-log-only")
            _, normal, dropped = verify_closed_sequence(arguments.qemu_log)
            print(
                "PASS c84-ssh-managed-child-verified-stream-peer frozen log: "
                f"streams={[(item.epoch, item.total_ticks, item.interval_count) for item in normal]} "
                f"drop_epoch={dropped.epoch}; four verified-stream terminals and all predecessors are exact"
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
        require(IRQ.family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "readiness armed IRQ overlay")
        require(FINISH.family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "readiness armed finish terminal")
        require(family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "readiness armed verified stream")

        PHASE.inert_probes(arguments, ssh)
        require(IRQ.family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "inert probes armed IRQ overlay")
        require(FINISH.family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "inert probes armed finish terminal")
        require(family_markers(arguments.qemu_log, ignore_incomplete_tail=True) == [], "inert probes armed verified stream")

        for epoch, irq_count, terminal_count in ((1, 3, 1), (2, 4, 2)):
            PHASE.normal_profiled_request(arguments, ssh, epoch, terminal_mode=TERMINAL_MODE)
            IRQ.wait_for_irq_prefix(arguments.qemu_log, irq_count, arguments.marker_timeout, TERMINAL_MODE)
            FINISH.wait_for_finish_prefix(arguments.qemu_log, terminal_count, arguments.marker_timeout, TERMINAL_MODE)
            wait_for_verified_prefix(arguments.qemu_log, terminal_count, arguments.marker_timeout)

        PHASE.active_drop_request(arguments, ssh, 3)
        IRQ.wait_for_irq_prefix(arguments.qemu_log, 5, arguments.marker_timeout, TERMINAL_MODE)
        FINISH.wait_for_finish_prefix(arguments.qemu_log, 3, arguments.marker_timeout, TERMINAL_MODE)
        wait_for_verified_prefix(arguments.qemu_log, 3, arguments.marker_timeout)
        before_readiness = family_markers(arguments.qemu_log)
        PHASE.post_drop_readiness(arguments, ssh)
        require(family_markers(arguments.qemu_log) == before_readiness, "post-Drop readiness changed verified-stream markers")

        PHASE.normal_profiled_request(
            arguments,
            ssh,
            4,
            await_readiness=False,
            terminal_mode=TERMINAL_MODE,
        )
        IRQ.wait_for_irq_prefix(arguments.qemu_log, 6, arguments.marker_timeout, TERMINAL_MODE)
        FINISH.wait_for_finish_prefix(arguments.qemu_log, 4, arguments.marker_timeout, TERMINAL_MODE)
        wait_for_verified_prefix(arguments.qemu_log, 4, arguments.marker_timeout)

        time.sleep(0.3)
        _, normal, dropped = verify_closed_sequence(arguments.qemu_log)
        print(
            "c84-ssh-managed-child-verified-stream-peer: controlled observation "
            f"streams={[(item.epoch, item.total_ticks, item.interval_count) for item in normal]} "
            f"drop_epoch={dropped.epoch}"
        )
        print(
            "PASS c84-ssh-managed-child-verified-stream-peer: epochs 1/2/4 streamed every "
            "verified interval and completed to Ready; epoch 3 retained LeaseCancelled Drop"
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
        print(f"FAIL c84-ssh-managed-child-verified-stream-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
