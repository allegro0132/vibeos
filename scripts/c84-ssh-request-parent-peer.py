#!/usr/bin/env python3
"""Drive the single-hart C8.4 SSH request-parent QEMU image with OpenSSH."""

from __future__ import annotations

import argparse
import importlib.util
import math
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
OPENSSH_PEER = ROOT / "scripts/openssh-peer.py"
FAMILY = "WASM_C84_SSH_REQUEST_PARENT"


def load_peer():
    spec = importlib.util.spec_from_file_location("vibeos_openssh_peer", OPENSSH_PEER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the maintained OpenSSH peer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PEER = load_peer()


class DriverError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DriverError(message)


def normalized_log(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace").replace("\r", "\n")


def fail_fast_log(path: Path) -> str:
    value = normalized_log(path)
    if f"{FAMILY} FAIL" in value:
        raise DriverError("guest reported a request-parent failure")
    if "panicked at" in value or "[!] fatal" in value or "[!] panic" in value:
        raise DriverError("guest reported a panic or fatal error")
    return value


def wait_for_marker(path: Path, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in fail_fast_log(path):
            return
        time.sleep(0.05)
    raise DriverError(f"timed out waiting for guest marker: {marker}")


def family_count(path: Path) -> int:
    return sum(1 for line in fail_fast_log(path).splitlines() if FAMILY in line)


def require_family_count(path: Path, expected: int, label: str) -> None:
    observed = family_count(path)
    require(observed == expected, f"{label} changed request-parent marker count: observed={observed} expected={expected}")


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
    before = family_count(arguments.qemu_log)

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
    require_family_count(arguments.qemu_log, before, "inert SSH probes")


def normal_profiled_request(
    arguments: argparse.Namespace,
    ssh: str,
    epoch: int,
) -> None:
    wait_ready(arguments, ssh)
    before = family_count(arguments.qemu_log)
    result = invoke(
        arguments,
        ssh,
        f"C8.4 profiled case-filter epoch {epoch}",
        arguments.accepted_key,
        ["case-filter"],
        input_bytes=PEER.CASE_FILTER_INPUT,
        verbose=epoch == 1,
    )
    PEER.require_result(
        f"C8.4 profiled case-filter epoch {epoch}",
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
        f"{FAMILY} RESPONSE epoch={epoch} status=0 cancel=1 ack=1 ready_epoch={epoch + 1}",
        arguments.marker_timeout,
    )
    require_family_count(arguments.qemu_log, before + 2, f"normal epoch {epoch}")


def active_drop_request(arguments: argparse.Namespace, ssh: str, epoch: int) -> None:
    wait_ready(arguments, ssh)
    before = family_count(arguments.qemu_log)
    # The guest owns one bounded passive socket. Let it observe the readiness
    # probe's final FIN and return to LISTEN before opening the held-stdin run.
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
    try:
        assert process.stdin is not None
        process.stdin.write(PEER.CASE_FILTER_INPUT[:257])
        process.stdin.flush()
        wait_for_marker(
            arguments.qemu_log,
            f"{FAMILY} START epoch={epoch}",
            arguments.marker_timeout,
        )
        require(process.poll() is None, "active case-filter exited before its START could be interrupted")
        process.kill()
        process.communicate(timeout=5)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.communicate()
        raise

    wait_for_marker(
        arguments.qemu_log,
        f"{FAMILY} DROP epoch={epoch} cancel=1 ack=1 ready_epoch={epoch + 1}",
        arguments.marker_timeout,
    )
    require_family_count(arguments.qemu_log, before + 2, f"active Drop epoch {epoch}")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--host", default="localhost")
    value.add_argument("--port", type=int, required=True)
    value.add_argument("--user", default="vibe")
    value.add_argument("--accepted-key", type=Path, required=True)
    value.add_argument("--rejected-key", type=Path, required=True)
    value.add_argument("--known-hosts", type=Path, required=True)
    value.add_argument("--host-key-output", type=Path, required=True)
    value.add_argument("--qemu-log", type=Path, required=True)
    value.add_argument("--ready-timeout", type=float, default=45.0)
    value.add_argument("--command-timeout", type=float, default=20.0)
    value.add_argument("--marker-timeout", type=float, default=20.0)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        require(1 <= arguments.port <= 65535, "--port must be in 1..65535")
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
        require_family_count(arguments.qemu_log, 0, "authenticated readiness")

        inert_probes(arguments, ssh)
        normal_profiled_request(arguments, ssh, 1)
        normal_profiled_request(arguments, ssh, 2)
        active_drop_request(arguments, ssh, 3)
        normal_profiled_request(arguments, ssh, 4)

        print(
            "PASS c84-ssh-request-parent-peer: inert requests stayed unarmed; "
            "epochs 1,2 responded, epoch 3 dropped, and epoch 4 reused the slot"
        )
        return 0
    except (OSError, RuntimeError, DriverError, PEER.PeerError, subprocess.SubprocessError) as error:
        print(f"FAIL c84-ssh-request-parent-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
