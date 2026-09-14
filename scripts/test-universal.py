#!/usr/bin/env python3
"""Boot one unchanged universal image at two physical addresses under QEMU."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import subprocess
import os
import select
import socket
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def drive(qemu, commands, log, ssh_port=None):
    public_key = None
    process = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    observed = bytearray()
    with log.open("wb") as stream:
        def collect(timeout):
            ready, _, _ = select.select([process.stdout], [], [], max(0, timeout))
            if ready:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError("QEMU exited while waiting for output")
                observed.extend(chunk); stream.write(chunk); stream.flush()
        def until(marker, start=0, timeout=90):
            deadline = time.monotonic() + timeout
            while marker not in observed[start:]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f"timed out waiting for {marker!r}; see {log}")
                collect(remaining)
        try:
            until(b"vsh> ")
            for command in commands:
                if command == "@quit": break
                if command.startswith("@expect "):
                    until(command.removeprefix("@expect ").encode())
                elif command.startswith("@sleep "):
                    deadline = time.monotonic() + float(command.removeprefix("@sleep "))
                    while time.monotonic() < deadline: collect(deadline - time.monotonic())
                else:
                    start = len(observed)
                    process.stdin.write(command.encode() + b"\n"); process.stdin.flush()
                    until(command.encode(), start)
                    echoed = observed.find(command.encode(), start) + len(command)
                    until(b"vsh> ", echoed)
            if ssh_port is not None:
                until(b"sshd listening on ")
                # Sunset requires strict KEX, which ssh-keyscan does not offer.
                # A credential-free client validates the transport signature and
                # stops at authentication, retaining only the public host key.
                known = log.with_suffix(".known-hosts")
                known.write_text("")
                scan = subprocess.run([
                    "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known}",
                    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HashKnownHosts=no",
                    "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "PreferredAuthentications=none",
                    "-o", "IdentityAgent=none", "-o", "IdentityFile=none", "-o", "ConnectTimeout=5",
                    "-o", "ConnectionAttempts=1", "-p", str(ssh_port), "vibe@127.0.0.1"],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
                log.with_suffix(".handshake.log").write_text(scan.stderr + scan.stdout)
                lines = [line.split()[1:3] for line in known.read_text().splitlines() if not line.startswith("#")]
                if scan.returncode != 255 or "Permission denied" not in scan.stderr or len(lines) != 1 or lines[0][0] != "ssh-ed25519":
                    raise RuntimeError(f"SSH transport check failed; inspect {log.with_suffix('.handshake.log')}")
                public_key = " ".join(lines[0])
            process.stdin.write(b"\x01x"); process.stdin.flush()
            rest, _ = process.communicate(timeout=10)
            stream.write(rest)
            if process.returncode: raise RuntimeError(f"QEMU exited with {process.returncode}")
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()

    return public_key

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--minimal", action="store_true")
    parser.add_argument("--ssh", action="store_true", help="exercise virtio entropy and persistent SSH identity")
    parser.add_argument("--jitter", action="store_true", help="exercise configured jitterentropy without a VirtIO RNG")
    parser.add_argument("--entropy-unavailable", action="store_true", help="with --jitter, require fail-closed rejection on an unsuitable timer")
    parser.add_argument("--usb", action="store_true", help="attach XHCI and a USB keyboard")
    parser.add_argument("--output", type=Path, default=ROOT / "target/universal-smoke")
    args = parser.parse_args()
    if args.entropy_unavailable and not args.jitter: parser.error("--entropy-unavailable requires --jitter")
    args.ssh |= args.jitter
    if args.minimal and (args.ssh or args.usb): parser.error("minimal cannot test optional components")
    image = args.image.resolve()
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    disk = out / "data.raw"
    # Isolated disposable media: never reuse a user's configured data disk.
    with disk.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024)
    # AUIPC t0, 0x200; JALR zero, 0(t0). OpenSBI enters at 0x80200000;
    # this test-only shim preserves a0/a1 and jumps to the unchanged image.
    shim = out / "jump-804.bin"
    shim.write_bytes(struct.pack("<II", 0x00200297, 0x00028067))
    records = []
    for index, address in enumerate((0x80200000, 0x80400000)):
        case = out / f"boot{index}.case"
        commands = ["quiet", "echo UNIVERSAL_CONSOLE_OK"]
        if not args.minimal:
            if index == 0:
                commands.append("echo UNIVERSAL_STORAGE_OK | write @home/universal-smoke")
            commands.extend(["cat @home/universal-smoke", "ip link show", "@sleep 2", "ip addr show"])
        if args.ssh:
            if args.entropy_unavailable:
                commands.extend(["ssh-keygen", "@expect ssh-keygen failed: entropy Offline"])
            elif index == 0:
                commands.extend(["@expect SSH host identity verified", "ssh-keygen", "@expect client keypair persisted"])
            else:
                commands.append("@expect SSH host identity verified")
        if args.usb:
            commands.append("usb")
        commands.append("@quit")
        case.write_text("\n".join(commands) + "\n")
        log = out / f"boot-{address:x}.log"
        port = None
        if args.ssh and not args.entropy_unavailable:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
        qemu = ["qemu-system-riscv64", "-machine", "virt", "-cpu", "rv64", "-smp", "4", "-m", "128M",
                "-nographic", "-bios", "default", "-kernel", str(image if index == 0 else shim)]
        if index:
            qemu += ["-device", f"loader,file={image},addr={address:#x},force-raw=on"]
        if not args.minimal:
            qemu += ["-drive", f"if=none,id=data,format=raw,file={disk}", "-device",
                     "virtio-blk-device,drive=data,bus=virtio-mmio-bus.0,queue-size=8",
                     "-netdev", "user,id=net0" + (f",hostfwd=tcp:127.0.0.1:{port}-:22" if port else ""), "-device", "virtio-net-device,netdev=net0"]
        if args.ssh and not args.jitter:
            qemu += ["-object", "rng-random,filename=/dev/urandom,id=rng0", "-device", "virtio-rng-device,rng=rng0"]
        if args.usb:
            qemu += ["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0"]
        qemu += ["-global", "virtio-mmio.force-legacy=false"]
        public_key = drive(qemu, commands, log, port)
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", log.read_text(errors="replace")).replace("\r", "")
        assert "4 hart(s) online" in text, text[-4000:]
        assert "\nUNIVERSAL_CONSOLE_OK\n" in text, text[-4000:]
        assert not re.search(r"fatal trap|\[!\] panic|panicked at", text), text[-4000:]
        if not args.minimal:
            assert "\nUNIVERSAL_STORAGE_OK\n" in text, text[-4000:]
            assert "net0" in text and "10.0.2.15" in text, text[-4000:]
        if args.entropy_unavailable:
            assert "ssh-keygen failed: entropy Offline" in text, text[-5000:]
            assert "SSH host identity verified" not in text, text[-5000:]
        elif args.ssh:
            assert "SSH host identity verified" in text, text[-5000:]
            if index == 0:
                assert "client keypair persisted" in text, text[-5000:]
        if args.usb:
            assert "XHCI" in text and "keyboard" in text.lower(), text[-5000:]
        assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
        if args.ssh and not args.entropy_unavailable and records and public_key != records[0]["ssh_public_key"]:
            raise RuntimeError("SSH host identity changed across boots")
        records.append({"load_address": address, "sha256": digest, "log": log.name, "passed": True, "ssh_public_key": public_key})
        print(f"PASS universal image at {address:#x}: console, SMP" + ("" if args.minimal else ", persisted storage, DHCP") + (", entropy rejected safely" if args.entropy_unavailable else ", SSH identity" if args.ssh else "") + (", XHCI keyboard" if args.usb else ""))
    (out / "result.json").write_text(json.dumps({"image": str(image), "boots": records, "physical_boards_verified": False}, indent=2) + "\n")

if __name__ == "__main__":
    main()
