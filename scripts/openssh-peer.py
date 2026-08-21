#!/usr/bin/env python3
"""Drive an explicit VibeOS SSH acceptance image with real OpenSSH.

The peer preloads the exact Ed25519 test host key, waits for a strict,
authenticated ``true`` exec, and then exercises the deliberately small SSH
surface, including its PTY-backed interactive VSH. It never weakens host-key
checking during readiness or acceptance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import math
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time


KEY_TYPE = "ssh-ed25519"
TEST_HOST_PUBLIC = bytes.fromhex(
    "29e5833a915a6429a4e3a7948475c338ef436eb82be89c92f059704403db9d55"
)
KEX_ALGORITHM = "curve25519-sha256"
CIPHER = "chacha20-poly1305@openssh.com"
ECHO_PAYLOAD = "vibeos-ssh-acceptance"
CASE_FILTER_INPUT = bytes(
    (index * 17 + 3) % 251 for index in range(12 * 1024 + 37)
)
CASE_FILTER_OUTPUT = bytes(byte ^ 0x20 for byte in CASE_FILTER_INPUT)
NATIVE_CASE_FILTER_INPUT = bytes(
    (index * 29 + 11) & 0xFF for index in range(13 * 1024 + 73)
)
NATIVE_CASE_FILTER_OUTPUT = bytes(byte ^ 0x20 for byte in NATIVE_CASE_FILTER_INPUT)
INTERACTIVE_INPUT = b"discard\x03echo vibeos-vsh-interactivX\x7fe\r\x04"
INTERACTIVE_OUTPUT = (
    b"vsh> discard^C\r\n"
    b"vsh> echo vibeos-vsh-interactivX\x08 \x08e\r\n"
    b"vibeos-vsh-interactive\r\n"
    b"vsh> "
)
TEST_HOST_FINGERPRINT = "SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8"


class PeerError(RuntimeError):
    pass


def pick_loopback_port() -> int:
    """Return a currently unused IPv4 loopback port for QEMU host forwarding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _expected_host_blob() -> bytes:
    key_type = KEY_TYPE.encode("ascii")
    return _ssh_string(key_type) + _ssh_string(TEST_HOST_PUBLIC)


def _expected_host_base64() -> str:
    return base64.b64encode(_expected_host_blob()).decode("ascii")


def _fingerprint(blob: bytes) -> str:
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def write_expected_known_hosts(known_hosts: Path, host: str, port: int) -> None:
    host_field = host if port == 22 else f"[{host}]:{port}"
    known_hosts.write_text(
        f"{host_field} {KEY_TYPE} {_expected_host_base64()}\n", encoding="ascii"
    )
    os.chmod(known_hosts, 0o600)


def write_host_key_evidence(host_key_output: Path) -> None:
    host_key_output.write_text(
        f"{KEY_TYPE} {_expected_host_base64()}\n", encoding="ascii"
    )
    os.chmod(host_key_output, 0o600)


def _base_ssh_command(
    ssh: str,
    host: str,
    port: int,
    user: str,
    identity: Path,
    known_hosts: Path,
    connect_timeout: int,
    bind_address: str | None,
) -> list[str]:
    command = [
        ssh,
        "-4",
        "-F",
        "/dev/null",
        "-p",
        str(port),
        "-i",
        os.fspath(identity),
        "-oBatchMode=yes",
        "-oIdentitiesOnly=yes",
        "-oIdentityAgent=none",
        "-oPreferredAuthentications=publickey",
        "-oPasswordAuthentication=no",
        "-oKbdInteractiveAuthentication=no",
        "-oNumberOfPasswordPrompts=0",
        "-oStrictHostKeyChecking=yes",
        f"-oUserKnownHostsFile={known_hosts}",
        "-oGlobalKnownHostsFile=/dev/null",
        "-oUpdateHostKeys=no",
        "-oVerifyHostKeyDNS=no",
        "-oCheckHostIP=no",
        "-oForwardAgent=no",
        "-oClearAllForwardings=yes",
        "-oCompression=no",
        "-oHostKeyAlgorithms=ssh-ed25519",
        "-oPubkeyAcceptedAlgorithms=ssh-ed25519",
        "-oKexAlgorithms=curve25519-sha256",
        "-oCiphers=chacha20-poly1305@openssh.com",
        "-oConnectionAttempts=1",
        f"-oConnectTimeout={connect_timeout}",
        "-oServerAliveInterval=2",
        "-oServerAliveCountMax=1",
    ]
    if bind_address is not None:
        command.extend(("-b", bind_address))
    command.append(f"{user}@{host}")
    return command


def run_ssh(
    label: str,
    ssh: str,
    host: str,
    port: int,
    user: str,
    identity: Path,
    known_hosts: Path,
    bind_address: str | None,
    command_timeout: float,
    before_destination: list[str],
    remote_command: list[str],
    verbose: bool = False,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    connect_timeout = max(1, min(10, math.ceil(command_timeout)))
    command = _base_ssh_command(
        ssh, host, port, user, identity, known_hosts, connect_timeout, bind_address
    )
    destination = command.pop()
    if verbose:
        command.append("-vv")
    else:
        command.append("-oLogLevel=ERROR")
    command.extend(before_destination)
    command.append(destination)
    command.extend(remote_command)
    try:
        if input_bytes is not None:
            return subprocess.run(
                command,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=command_timeout,
            )
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=command_timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise PeerError(f"{label} timed out after {command_timeout:.1f}s") from error


def _display_failure(label: str, result: subprocess.CompletedProcess[bytes]) -> str:
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    return (
        f"{label} exited {result.returncode}; "
        f"stdout={stdout!r}; stderr tail={stderr[-800:]!r}"
    )


def require_result(
    label: str,
    result: subprocess.CompletedProcess[bytes],
    returncodes: set[int],
    stdout: bytes | None = None,
    stderr_pattern: str | None = None,
    stderr_exact: bytes | None = None,
) -> None:
    if result.returncode not in returncodes:
        raise PeerError(_display_failure(label, result))
    if stdout is not None and result.stdout != stdout:
        raise PeerError(_display_failure(label, result))
    if stderr_exact is not None and result.stderr != stderr_exact:
        raise PeerError(_display_failure(label, result))
    if stderr_pattern is not None:
        stderr = result.stderr.decode("utf-8", errors="replace")
        if re.search(stderr_pattern, stderr, flags=re.IGNORECASE) is None:
            raise PeerError(
                f"{label} did not report the required rejection; "
                + _display_failure(label, result)
            )


def require_negotiated_profile(result: subprocess.CompletedProcess[bytes]) -> None:
    debug = result.stderr.decode("utf-8", errors="replace")
    required = {
        "KEX": rf"kex: algorithm: {re.escape(KEX_ALGORITHM)}(?:\r?\n|$)",
        "host key": rf"kex: host key algorithm: {re.escape(KEY_TYPE)}(?:\r?\n|$)",
        "server cipher": rf"server->client cipher: {re.escape(CIPHER)}\b",
        "client cipher": rf"client->server cipher: {re.escape(CIPHER)}\b",
        "strict KEX": (
            r"(?:will use|enabled) strict KEX ordering|"
            r"kex-strict-s-v00@openssh\.com"
        ),
    }
    for label, pattern in required.items():
        if re.search(pattern, debug) is None:
            raise PeerError(
                f"OpenSSH debug log did not prove the forced {label} profile"
            )


def require_expected_host_identity(
    result: subprocess.CompletedProcess[bytes],
) -> None:
    debug = result.stderr.decode("utf-8", errors="replace")
    fingerprints = set(
        re.findall(r"Server host key: ssh-ed25519 (SHA256:[^\s]+)", debug)
    )
    if fingerprints != {TEST_HOST_FINGERPRINT}:
        raise PeerError(
            "OpenSSH debug log did not prove the exact expected host identity; "
            f"observed={sorted(fingerprints)!r}"
        )


def wait_for_strict_ready_ssh(
    ssh: str,
    host: str,
    port: int,
    user: str,
    accepted_key: Path,
    known_hosts: Path,
    bind_address: str | None,
    ready_timeout: float,
    command_timeout: float,
) -> None:
    deadline = time.monotonic() + ready_timeout
    retry_delay = 0.1
    last_error = "no SSH response"
    fatal_markers = (
        "host key verification failed",
        "remote host identification has changed",
        "permission denied",
        "no matching key exchange method found",
        "no matching host key type found",
        "no matching cipher found",
    )
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PeerError(
                f"timed out after {ready_timeout:.1f}s waiting for strict authenticated "
                f"SSH readiness ({last_error})"
            )
        attempt_timeout = min(command_timeout, 5.0, max(1.0, remaining))
        try:
            result = run_ssh(
                "readiness true",
                ssh,
                host,
                port,
                user,
                accepted_key,
                known_hosts,
                bind_address,
                attempt_timeout,
                ["-T"],
                ["true"],
                verbose=True,
            )
        except PeerError as error:
            last_error = str(error)
        else:
            if result.returncode == 0:
                require_result("readiness true", result, {0}, b"")
                require_negotiated_profile(result)
                require_expected_host_identity(result)
                return
            stderr = result.stderr.decode("utf-8", errors="replace")
            lower_stderr = stderr.lower()
            if any(marker in lower_stderr for marker in fatal_markers):
                raise PeerError(_display_failure("readiness true", result))
            lines = stderr.strip().splitlines()
            last_error = (
                lines[-1]
                if lines
                else f"OpenSSH readiness probe exited {result.returncode}"
            )

        delay = min(retry_delay, max(0.0, deadline - time.monotonic()))
        if delay > 0:
            time.sleep(delay)
        retry_delay = min(1.0, retry_delay * 2)


def run_acceptance(
    ssh: str,
    host: str,
    port: int,
    user: str,
    accepted_key: Path,
    rejected_key: Path,
    known_hosts: Path,
    bind_address: str | None,
    command_timeout: float,
    native_case_filter_enabled: bool,
) -> None:
    def invoke(
        label: str,
        identity: Path,
        before_destination: list[str],
        remote_command: list[str],
        verbose: bool = False,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        # The guest deliberately owns one socket. Give its bounded network poll
        # a moment to observe the preceding FIN/RST and re-enter LISTEN before
        # opening the next independent policy probe.
        time.sleep(0.1)
        return run_ssh(
            label,
            ssh,
            host,
            port,
            user,
            identity,
            known_hosts,
            bind_address,
            command_timeout,
            before_destination,
            remote_command,
            verbose=verbose,
            input_bytes=input_bytes,
        )

    echo = invoke(
        "authorized echo",
        accepted_key,
        ["-T"],
        ["echo", ECHO_PAYLOAD],
        verbose=True,
    )
    require_result("authorized echo", echo, {0}, f"{ECHO_PAYLOAD}\n".encode())
    require_negotiated_profile(echo)

    true_result = invoke("authorized true", accepted_key, ["-T"], ["true"])
    require_result("authorized true", true_result, {0}, b"")

    if native_case_filter_enabled:
        # subprocess closes the pipe after this complete binary fixture. Exact
        # stdout length/content plus status zero therefore proves native EOF and
        # output drain over the real OpenSSH channel, not merely command admission.
        native_case_filter = invoke(
            "authorized native async case-filter",
            accepted_key,
            ["-T"],
            ["native-case-filter"],
            input_bytes=NATIVE_CASE_FILTER_INPUT,
        )
        require_result(
            "authorized native async case-filter",
            native_case_filter,
            {0},
            NATIVE_CASE_FILTER_OUTPUT,
            stderr_exact=b"",
        )

    case_filter = invoke(
        "authorized WASM case-filter",
        accepted_key,
        ["-T"],
        ["case-filter"],
        input_bytes=CASE_FILTER_INPUT,
    )
    require_result(
        "authorized WASM case-filter",
        case_filter,
        {0},
        CASE_FILTER_OUTPUT,
        stderr_exact=b"",
    )

    false_result = invoke("authorized false", accepted_key, ["-T"], ["false"])
    require_result("authorized false", false_result, {1}, b"")

    interactive = invoke(
        "interactive PTY shell",
        accepted_key,
        ["-tt"],
        [],
        input_bytes=INTERACTIVE_INPUT,
    )
    require_result("interactive PTY shell", interactive, {0}, INTERACTIVE_OUTPUT)

    post_shell_true = invoke(
        "post-shell authorized true", accepted_key, ["-T"], ["true"]
    )
    require_result("post-shell authorized true", post_shell_true, {0}, b"")

    rejected = invoke("rejected public key", rejected_key, ["-T"], ["true"])
    require_result(
        "rejected public key", rejected, {255}, b"", r"permission denied.*publickey"
    )

    shell = invoke("shell without PTY", accepted_key, ["-T"], [])
    require_result(
        "shell without PTY", shell, {255}, b"", r"shell request failed.*channel"
    )

    pty_exec = invoke("exec with PTY", accepted_key, ["-tt"], ["true"])
    require_result(
        "exec with PTY",
        pty_exec,
        {255},
        b"",
        r"exec request failed.*channel",
    )

    subsystem = invoke("subsystem request", accepted_key, ["-T", "-s"], ["sftp"])
    require_result(
        "subsystem request",
        subsystem,
        {255},
        b"",
        r"subsystem request failed.*channel",
    )


def selftest() -> None:
    if _fingerprint(_expected_host_blob()) != TEST_HOST_FINGERPRINT:
        raise PeerError("host-key fixture fingerprint changed")
    if (
        _expected_host_base64()
        != "AAAAC3NzaC1lZDI1NTE5AAAAICnlgzqRWmQppOOnlIR1wzjvQ264K+ickvBZcEQD251V"
    ):
        raise PeerError("host-key fixture OpenSSH blob changed")
    if len(CASE_FILTER_INPUT) != 12 * 1024 + 37:
        raise PeerError("WASM stream fixture length changed")
    if CASE_FILTER_OUTPUT[-37:] != bytes(
        byte ^ 0x20 for byte in CASE_FILTER_INPUT[-37:]
    ):
        raise PeerError("WASM stream fixture lost its exact final 37-byte chunk")
    if bytes(byte ^ 0x20 for byte in CASE_FILTER_OUTPUT) != CASE_FILTER_INPUT:
        raise PeerError("WASM stream fixture transform is not the pinned XOR")
    if len(NATIVE_CASE_FILTER_INPUT) != 13 * 1024 + 73:
        raise PeerError("native async stream fixture length changed")
    if NATIVE_CASE_FILTER_OUTPUT[-73:] != bytes(
        byte ^ 0x20 for byte in NATIVE_CASE_FILTER_INPUT[-73:]
    ):
        raise PeerError("native async stream fixture lost its exact final 73-byte chunk")
    if (
        bytes(byte ^ 0x20 for byte in NATIVE_CASE_FILTER_OUTPUT)
        != NATIVE_CASE_FILTER_INPUT
    ):
        raise PeerError("native async stream fixture transform is not the pinned XOR")
    if NATIVE_CASE_FILTER_INPUT == CASE_FILTER_INPUT:
        raise PeerError("sync and native async stream fixtures unexpectedly alias")
    command = _base_ssh_command(
        "ssh",
        "localhost",
        2222,
        "vibe",
        Path("accepted"),
        Path("known_hosts"),
        3,
        None,
    )
    for required in (
        "-oHostKeyAlgorithms=ssh-ed25519",
        "-oPubkeyAcceptedAlgorithms=ssh-ed25519",
        "-oKexAlgorithms=curve25519-sha256",
        "-oCiphers=chacha20-poly1305@openssh.com",
    ):
        if required not in command:
            raise PeerError(f"OpenSSH command omitted {required}")
    bound_command = _base_ssh_command(
        "ssh",
        "192.0.2.1",
        2222,
        "vibe",
        Path("accepted"),
        Path("known_hosts"),
        3,
        "192.0.2.2",
    )
    if bound_command[-3:] != ["-b", "192.0.2.2", "vibe@192.0.2.1"]:
        raise PeerError("OpenSSH command omitted the explicit source address")

    debug = "\n".join(
        (
            f"debug1: kex: algorithm: {KEX_ALGORITHM}",
            f"debug1: kex: host key algorithm: {KEY_TYPE}",
            f"debug1: kex: server->client cipher: {CIPHER} MAC: <implicit>",
            f"debug1: kex: client->server cipher: {CIPHER} MAC: <implicit>",
            "debug3: kex_choose_conf: will use strict KEX ordering",
            f"debug1: Server host key: {KEY_TYPE} {TEST_HOST_FINGERPRINT}",
            "",
        )
    ).encode("ascii")
    synthetic = subprocess.CompletedProcess(
        args=["ssh"], returncode=0, stdout=b"", stderr=debug
    )
    require_negotiated_profile(synthetic)
    require_expected_host_identity(synthetic)
    require_result(
        "empty WASM command",
        subprocess.CompletedProcess(
            args=["ssh"], returncode=0, stdout=b"", stderr=b""
        ),
        {0},
        b"",
        stderr_exact=b"",
    )
    try:
        require_result(
            "noisy WASM command",
            subprocess.CompletedProcess(
                args=["ssh"], returncode=0, stdout=b"", stderr=b"unexpected"
            ),
            {0},
            b"",
            stderr_exact=b"",
        )
    except PeerError:
        pass
    else:
        raise PeerError("strict WASM stderr check accepted unexpected output")
    parser = _parser()
    if parser.parse_args([]).native_case_filter:
        raise PeerError("native async probe unexpectedly enabled by default")
    if not parser.parse_args(["--native-case-filter"]).native_case_filter:
        raise PeerError("native async probe opt-in was not retained")
    for incompatible in (
        ["--scan-only", "--native-case-filter"],
        ["--pick-port", "--native-case-filter"],
        ["--selftest", "--native-case-filter"],
    ):
        try:
            _validate_operation_modes(parser.parse_args(incompatible))
        except PeerError:
            pass
        else:
            raise PeerError(f"incompatible peer modes were accepted: {incompatible!r}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="vibe")
    parser.add_argument("--accepted-key", type=Path)
    parser.add_argument("--rejected-key", type=Path)
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--host-key-output", type=Path)
    parser.add_argument(
        "--bind-address",
        help="force OpenSSH to use this local IPv4 source address",
    )
    parser.add_argument("--ready-timeout", type=float, default=45.0)
    parser.add_argument("--command-timeout", type=float, default=15.0)
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="run only the strict authenticated readiness probe",
    )
    parser.add_argument(
        "--native-case-filter",
        action="store_true",
        help="add the QEMU formal managed native-case-filter acceptance probe",
    )
    parser.add_argument(
        "--pick-port",
        action="store_true",
        help="print a currently unused IPv4 loopback port and exit",
    )
    parser.add_argument("--selftest", action="store_true")
    return parser


def _validate_operation_modes(arguments: argparse.Namespace) -> None:
    if arguments.selftest and (
        arguments.pick_port or arguments.scan_only or arguments.native_case_filter
    ):
        raise PeerError("--selftest cannot be combined with another operation")
    if arguments.pick_port and (arguments.scan_only or arguments.native_case_filter):
        raise PeerError("--pick-port cannot be combined with another operation")
    if arguments.scan_only and arguments.native_case_filter:
        raise PeerError("--native-case-filter requires functional acceptance")


def main() -> int:
    arguments = _parser().parse_args()
    try:
        _validate_operation_modes(arguments)
        if arguments.pick_port:
            print(pick_loopback_port())
            return 0
        if arguments.selftest:
            selftest()
            print("openssh-peer selftest: ok")
            return 0

        if not 1 <= arguments.port <= 65535:
            raise PeerError("--port must be in the range 1..65535")
        for label, value in (
            ("--ready-timeout", arguments.ready_timeout),
            ("--command-timeout", arguments.command_timeout),
        ):
            if not math.isfinite(value) or value <= 0:
                raise PeerError(f"{label} must be a finite positive number")
        if arguments.known_hosts is None or arguments.host_key_output is None:
            raise PeerError("--known-hosts and --host-key-output are required")
        if arguments.bind_address is not None:
            try:
                bind_address = ipaddress.IPv4Address(arguments.bind_address)
            except ipaddress.AddressValueError as error:
                raise PeerError("--bind-address must be an IPv4 address") from error
            if (
                bind_address.is_loopback
                or bind_address.is_unspecified
                or bind_address.is_multicast
                or bind_address.is_reserved
            ):
                raise PeerError("--bind-address must be a non-loopback unicast IPv4 address")
        if arguments.accepted_key is None:
            raise PeerError("strict readiness requires --accepted-key")
        if not arguments.scan_only and arguments.rejected_key is None:
            raise PeerError("functional acceptance requires --rejected-key")

        ssh = shutil.which("ssh")
        if ssh is None:
            raise PeerError("OpenSSH ssh is required")

        write_expected_known_hosts(
            arguments.known_hosts,
            arguments.host,
            arguments.port,
        )
        wait_for_strict_ready_ssh(
            ssh,
            arguments.host,
            arguments.port,
            arguments.user,
            arguments.accepted_key,
            arguments.known_hosts,
            arguments.bind_address,
            arguments.ready_timeout,
            arguments.command_timeout,
        )
        write_host_key_evidence(arguments.host_key_output)
        print(
            "openssh-peer: strict authenticated readiness with host key "
            f"{TEST_HOST_FINGERPRINT} on {arguments.host}:{arguments.port}"
        )

        if arguments.scan_only:
            print("PASS openssh-peer: strict host-key/auth/crypto readiness probe")
        else:
            assert arguments.rejected_key is not None
            run_acceptance(
                ssh,
                arguments.host,
                arguments.port,
                arguments.user,
                arguments.accepted_key,
                arguments.rejected_key,
                arguments.known_hosts,
                arguments.bind_address,
                arguments.command_timeout,
                arguments.native_case_filter,
            )
            component_label = (
                "native async and WASM case-filter"
                if arguments.native_case_filter
                else "WASM case-filter"
            )
            print(
                "PASS openssh-peer: forced crypto, authorized exec statuses including "
                f"{component_label}, interactive PTY/shell, rejected key, and invalid "
                "request denial"
            )
        return 0
    except (OSError, PeerError, subprocess.SubprocessError) as error:
        print(f"FAIL openssh-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
