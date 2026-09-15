#!/usr/bin/env python3
"""Exercise the real UART vtop, sampling and service lifecycle on 1/4 harts."""
import argparse
from pathlib import Path
import re
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


class Guest:
    def __init__(self, kernel, harts):
        self.process = subprocess.Popen([
            "qemu-system-riscv64", "-machine", "virt", "-cpu", "rv64",
            "-smp", str(harts), "-m", "128M", "-accel", "tcg,thread=multi",
            "-nographic", "-bios", "default", "-kernel", str(kernel),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.data = bytearray()

    def send(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def expect(self, needle, start=0, timeout=15):
        deadline = time.monotonic() + timeout
        while needle not in self.data[start:]:
            if time.monotonic() >= deadline or self.process.poll() is not None:
                raise AssertionError(f"missing {needle!r}\n{bytes(self.data[-4000:])!r}")
            for key, _ in self.selector.select(0.1):
                chunk = key.fileobj.read1(65536)
                if chunk:
                    self.data.extend(chunk)
        return bytes(self.data[start:])

    def command(self, source):
        start = len(self.data)
        self.send(source.encode() + b"\r")
        data = self.expect(b"\x1b[2Kvsh> ", start)
        return ANSI.sub(b"", data).decode(errors="replace")

    def close(self, path):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.selector.close()
        path.write_bytes(self.data)


def check(kernel, harts, output):
    guest = Guest(kernel, harts)
    try:
        guest.expect(b"\x1b[2Kvsh> ")
        guest.command("quiet")
        once = guest.command("vtop --once")
        assert f"{harts} CPUs" in once, once
        assert re.search(r"CPU \d+\.\d%", once), once
        assert "heap" in once and "SERVICE" in once and "guest" in once, once
        assert "guest: stop complete" in guest.command("vtop stop guest")
        assert re.search(r"guest\s+cancelled", guest.command("vtop --once"))
        assert "guest: start complete" in guest.command("vtop start guest")
        assert "guest: restart complete" in guest.command("vtop restart guest")
        denied = guest.command("vtop stop vsh")
        assert "protected:" in denied and "Returned(1)" in denied, denied
        start = len(guest.data)
        guest.send(b"vtop\r")
        guest.expect(b"\x1b[?1049h", start)
        guest.expect(b"non-WFI residency", start)
        # Wait for a real interval, then select one service with raw input.
        guest.expect(b"CPU per service: one core = 100%", start)
        guest.send(b"/guest\r")
        filtered = len(guest.data)
        guest.expect(b"Showing 1-1 / 1", filtered)
        guest.send(b"x")
        confirm = len(guest.data)
        guest.expect(b"stop guest?", confirm)
        guest.send(b"n")
        cancel = len(guest.data)
        guest.expect(b"Showing 1-1 / 1", cancel)
        guest.send(b"r")
        confirm = len(guest.data)
        guest.expect(b"restart guest?", confirm)
        guest.send(b"y")
        guest.expect(b"guest: restart complete", confirm)
        start = len(guest.data)
        guest.send(b"q")
        guest.expect(b"\x1b[?1049l", start)
        guest.expect(b"\x1b[2Kvsh> ", start)
        assert "VTOP_RESTORED" in guest.command("echo VTOP_RESTORED")
        start = len(guest.data)
        guest.send(b"vtop\r")
        guest.expect(b"\x1b[?1049h", start)
        guest.send(b"\x03")
        guest.expect(b"\x1b[?1049l", start)
        guest.expect(b"\x1b[2Kvsh> ", start)
        assert "VTOP_CTRL_C" in guest.command("echo VTOP_CTRL_C")
        assert b"KERNEL PANIC" not in guest.data and b"panicked" not in guest.data
        print(f"PASS vtop: {harts} hart(s), CPU interval, stop/start/restart, protection, TUI confirmation, q/Ctrl-C")
    finally:
        guest.close(output / f"uart-{harts}.log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, help="use an existing normal QEMU VSH image; skip build")
    args = parser.parse_args()
    output = ROOT / "target" / "vtop"
    output.mkdir(parents=True, exist_ok=True)
    if args.kernel:
        kernel = args.kernel.resolve()
    else:
        with (output / "build.log").open("wb") as log:
            subprocess.run(["cargo", "build", "--locked", "--offline", "--release"],
                           cwd=ROOT / "firmware" / "qemu-virt", stdout=log, stderr=subprocess.STDOUT, check=True)
        kernel = ROOT / "target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt"
    for harts in (1, 4):
        check(kernel, harts, output)


if __name__ == "__main__":
    main()
