#!/usr/bin/env python3
"""Real OpenSSH PTY gate for vtop, using the explicit QEMU test identity."""
import argparse
import fcntl
import importlib.util
import os
from pathlib import Path
import pty
import selectors
import signal
import struct
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("openssh_peer", ROOT / "scripts/openssh-peer.py")
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)


class Terminal:
    def __init__(self, command):
        self.master, slave = pty.openpty()
        self.resize(80, 24)
        self.process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.master, selectors.EVENT_READ)
        self.data = bytearray()

    def resize(self, cols, rows):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        # This harness owns the PTY without a foreground process group. Tell
        # OpenSSH to read the new size just as a real terminal's SIGWINCH does.
        if hasattr(self, "process"):
            self.process.send_signal(signal.SIGWINCH)

    def send(self, data):
        start = len(self.data)
        os.write(self.master, data)
        return start

    def expect(self, needle, start=0, timeout=20):
        deadline = time.monotonic() + timeout
        while needle not in self.data[start:]:
            if time.monotonic() > deadline or self.process.poll() is not None:
                raise AssertionError(f"missing {needle!r}\n{bytes(self.data[-3000:])!r}")
            for _, _ in self.selector.select(0.1):
                self.data.extend(os.read(self.master, 65536))

    def command(self, text):
        start = self.send(text.encode() + b"\r")
        self.expect(b"vsh> ", start)
        return bytes(self.data[start:])

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.selector.close()
        os.close(self.master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, help="existing QEMU ssh-test image; skip build")
    args = parser.parse_args()
    output = ROOT / "target/vtop"
    output.mkdir(parents=True, exist_ok=True)
    if args.kernel:
        kernel = args.kernel.resolve()
    else:
        with (output / "ssh-build.log").open("wb") as log:
            subprocess.run(["cargo", "build", "--locked", "--offline", "--release", "--features", "ssh-test"],
                           cwd=ROOT / "firmware/qemu-virt", stdout=log, stderr=subprocess.STDOUT, check=True)
        kernel = ROOT / "target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt"
    with tempfile.TemporaryDirectory(prefix="vtop-ssh-") as temporary:
        work = Path(temporary)
        key = work / "id_ed25519"
        subprocess.run(["python3", "-B", str(ROOT / "scripts/openssh-test-key.py"),
                        "--fixture", "accepted", "--output", str(key)], check=True, stdout=subprocess.DEVNULL)
        port = peer.pick_loopback_port()
        known_hosts = work / "known_hosts"
        peer.write_expected_known_hosts(known_hosts, "127.0.0.1", port)
        log_path = output / "ssh-uart.log"
        with log_path.open("wb") as log:
            vm = subprocess.Popen([
                "qemu-system-riscv64", "-machine", "virt", "-cpu", "rv64", "-smp", "4", "-m", "128M",
                "-accel", "tcg,thread=multi", "-nographic", "-bios", "default", "-kernel", str(kernel),
                "-object", "rng-random,id=rng,filename=/dev/urandom",
                "-device", "virtio-rng-device,rng=rng,bus=virtio-mmio-bus.1",
                "-netdev", f"user,id=net,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:2222",
                "-device", "virtio-net-device,netdev=net,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01",
                "-global", "virtio-mmio.force-legacy=false",
            ], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            terminal = None
            try:
                peer.wait_for_vsh(log_path, vm, timeout=90)
                deadline = time.monotonic() + 30
                while b"ssh-test listening" not in log_path.read_bytes():
                    if time.monotonic() > deadline or vm.poll() is not None:
                        raise AssertionError(log_path.read_text(errors="replace")[-4000:])
                    time.sleep(0.1)
                base = peer.vsh_ssh_command(port, work)
                shell = base[:-1] + ["-tt", base[-1]]
                terminal = Terminal(shell)
                terminal.expect(b"vsh> ")
                assert b"CPU " in terminal.command("vtop --once")
                denied = terminal.command("vtop stop ssh-test")
                assert b"protected:" in denied and b"Returned(1)" in denied, denied
                start = terminal.send(b"vtop\r")
                terminal.expect(b"\x1b[?1049h", start)
                terminal.expect(b"CPU per service: one core = 100%", start)
                start = terminal.send(b"/ssh-test\r")
                terminal.expect(b"SSH transport dependency", start)
                terminal.send(b"x")
                start = len(terminal.data)
                terminal.resize(40, 10)
                terminal.expect(b"Resize to at least", start)
                start = len(terminal.data)
                terminal.resize(100, 30)
                terminal.expect(b"non-WFI residency", start)
                start = terminal.send(b"q")
                terminal.expect(b"\x1b[?1049l", start)
                terminal.expect(b"vsh> ", start)
                assert b"SSH_VTOP_RESTORED" in terminal.command("echo SSH_VTOP_RESTORED")
                start = terminal.send(b"vtop\r")
                terminal.expect(b"\x1b[?1049h", start)
                start = terminal.send(b"\x03")
                terminal.expect(b"\x1b[?1049l", start)
                terminal.expect(b"vsh> ", start)
                assert b"SSH_VTOP_CTRL_C" in terminal.command("echo SSH_VTOP_CTRL_C")
                terminal.send(b"exit\r")
                deadline = time.monotonic() + 20
                while terminal.process.poll() is None:
                    if time.monotonic() > deadline:
                        raise AssertionError(f"SSH exit timed out: {bytes(terminal.data[-1000:])!r}")
                    for _, _ in terminal.selector.select(0.1):
                        try:
                            terminal.data.extend(os.read(terminal.master, 65536))
                        except OSError:
                            terminal.process.wait(timeout=2)
                assert terminal.process.returncode == 0, bytes(terminal.data[-1000:])
                # A fresh authenticated session proves the previous view did
                # not consume or poison the server's single-session resources.
                result = subprocess.run(base + ["true"], capture_output=True, timeout=20)
                assert result.returncode == 0, result.stderr
                print("PASS vtop SSH: real PTY, interval refresh, dependency protection, resize, q/Ctrl-C, reconnect")
            finally:
                if terminal:
                    (output / "ssh-pty.log").write_bytes(terminal.data)
                    terminal.close()
                vm.terminate()
                try:
                    vm.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait()


if __name__ == "__main__":
    main()
