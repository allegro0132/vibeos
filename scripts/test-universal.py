#!/usr/bin/env python3
"""Boot one unchanged universal image at two physical addresses under QEMU."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--minimal", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "target/universal-smoke")
    args = parser.parse_args()
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
        commands.append("@quit")
        case.write_text("\n".join(commands) + "\n")
        log = out / f"boot-{address:x}.log"
        qemu = ["qemu-system-riscv64", "-machine", "virt", "-cpu", "rv64", "-smp", "4", "-m", "128M",
                "-nographic", "-bios", "default", "-kernel", str(image if index == 0 else shim)]
        if index:
            qemu += ["-device", f"loader,file={image},addr={address:#x},force-raw=on"]
        if not args.minimal:
            qemu += ["-drive", f"if=none,id=data,format=raw,file={disk}", "-device",
                     "virtio-blk-device,drive=data,bus=virtio-mmio-bus.0,queue-size=8",
                     "-netdev", "user,id=net0", "-device", "virtio-net-device,netdev=net0"]
        qemu += ["-global", "virtio-mmio.force-legacy=false"]
        subprocess.run(["python3", "-B", str(ROOT / "scripts/qemu-vsh-driver.py"), "--case", str(case),
                        "--log", str(log), "--", *qemu], check=True, timeout=180)
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", log.read_text(errors="replace")).replace("\r", "")
        assert "4 hart(s) online" in text, text[-4000:]
        assert "\nUNIVERSAL_CONSOLE_OK\n" in text, text[-4000:]
        assert not re.search(r"fatal trap|\[!\] panic|panicked at", text), text[-4000:]
        if not args.minimal:
            assert "\nUNIVERSAL_STORAGE_OK\n" in text, text[-4000:]
            assert "net0" in text and "10.0.2.15" in text, text[-4000:]
        assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
        records.append({"load_address": address, "sha256": digest, "log": log.name, "passed": True})
        print(f"PASS universal image at {address:#x}: console, SMP" + ("" if args.minimal else ", persisted storage, DHCP"))
    (out / "result.json").write_text(json.dumps({"image": str(image), "boots": records, "physical_boards_verified": False}, indent=2) + "\n")

if __name__ == "__main__":
    main()
