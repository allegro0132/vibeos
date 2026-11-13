#!/usr/bin/env python3
"""Assemble/check regular SD image files; never opens a block device for writing.

Host checks cover GPT geometry/CRCs and embedded bytes, not ROM/SD execution.
Blank data partition uses VibeOS's existing on-device initialization format.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import uuid
import zlib

SECTOR = 512
MIB = 1024 * 1024
IMAGE_BYTES = 641 * MIB
# Match the pinned Mars SDK's `spl_tool -i` post-genimage operation.
# These bytes are outside the protective partition entry and GPT header CRC.
ROM_BACKUP_OFFSET = 0x04
ROM_CRC_OFFSET = 0x290
ROM_FAILED_CRC = 0x5A5A5A5A
PARTITIONS = [
    ("spl", 2 * MIB, 2 * MIB, "2E54B353-1271-4842-806F-E436D6AF6985", "u-boot-spl.bin.normal.out"),
    ("uboot", 4 * MIB, 4 * MIB, "5B193300-FC78-40CD-8002-E86C45580B47", "firmware.itb"),
    ("boot", 8 * MIB, 120 * MIB, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "boot.fat"),
    ("vibeos-data", 128 * MIB, 512 * MIB, "0FC63DAF-8483-4772-8E79-3D69D8477DE4", None),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def header(current, backup, entries_lba, entries_crc):
    end = IMAGE_BYTES // SECTOR - 1
    h = bytearray(SECTOR)
    struct.pack_into("<8sIIIIQQQQ16sQIII", h, 0, b"EFI PART", 0x10000, 92, 0, 0,
                     current, backup, 34, end - 33,
                     uuid.UUID("a788c583-4049-5739-b720-c9d272426d52").bytes_le,
                     entries_lba, 128, 128, entries_crc)
    struct.pack_into("<I", h, 16, zlib.crc32(h[:92]))
    return h


def assemble(output, artifacts):
    # Validate every input before creating output. O_EXCL rejects existing files,
    # symlinks and device nodes, including /dev/sdX; no flash operation is exposed.
    inputs = []
    for name, start, size, kind, filename in PARTITIONS:
        if filename:
            p = artifacts / filename
            require(p.is_file() and 0 < p.stat().st_size <= size, "invalid payload: " + filename)
            inputs.append((start, p))
    entries = bytearray(128 * 128)
    for i, (name, start, size, kind, _) in enumerate(PARTITIONS):
        identity = uuid.uuid5(uuid.NAMESPACE_URL, "https://vibeos/mars/" + name)
        struct.pack_into("<16s16sQQQ72s", entries, i * 128,
                         uuid.UUID(kind).bytes_le, identity.bytes_le,
                         start // SECTOR, (start + size) // SECTOR - 1, 0,
                         name.encode("utf-16-le"))
    crc = zlib.crc32(entries)
    end = IMAGE_BYTES // SECTOR - 1
    mbr = bytearray(SECTOR)
    struct.pack_into("<I", mbr, ROM_BACKUP_OFFSET, PARTITIONS[0][1])
    struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\0\2\0", 0xEE,
                     b"\xff\xff\xff", 1, end)
    mbr[510:] = b"\x55\xaa"
    primary = header(1, end, 2, crc)
    struct.pack_into("<I", primary, ROM_CRC_OFFSET - SECTOR, ROM_FAILED_CRC)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.truncate(IMAGE_BYTES)
        for offset, blob in [(0, mbr), (SECTOR, primary),
                             (2 * SECTOR, entries), ((end - 32) * SECTOR, entries),
                             (end * SECTOR, header(end, 1, end - 32, crc))]:
            f.seek(offset)
            f.write(blob)
        for start, p in inputs:
            f.seek(start)
            with p.open("rb") as source:
                while chunk := source.read(MIB):
                    f.write(chunk)
        f.flush()
        os.fsync(f.fileno())
    return inspect(output, artifacts)


def inspect(path, artifacts=None):
    require(path.is_file() and path.stat().st_size == IMAGE_BYTES, "image size/type")
    end = IMAGE_BYTES // SECTOR - 1
    with path.open("rb") as f:
        mbr = f.read(SECTOR)
        require(mbr[510:] == b"\x55\xaa" and mbr[450] == 0xEE, "protective MBR")
        require(struct.unpack_from("<II", mbr, 454) == (1, end), "MBR range")
        require(struct.unpack_from("<I", mbr, ROM_BACKUP_OFFSET)[0] == PARTITIONS[0][1],
                "ROM backup SPL address")
        f.seek(ROM_CRC_OFFSET)
        require(struct.unpack("<I", f.read(4))[0] == ROM_FAILED_CRC, "ROM fallback CRC marker")
        tables = []
        for current, backup, table_lba in [(1, end, 2), (end, 1, end - 32)]:
            f.seek(current * SECTOR)
            h = bytearray(f.read(SECTOR))
            fields = struct.unpack_from("<8sIIIIQQQQ16sQIII", h)
            require(fields[:3] == (b"EFI PART", 0x10000, 92), "GPT signature/version/size")
            checksum = fields[3]
            struct.pack_into("<I", h, 16, 0)
            require(zlib.crc32(h[:92]) == checksum, "GPT header CRC")
            require(fields[4] == 0 and fields[5:9] == (current, backup, 34, end - 33), "GPT range")
            require(fields[9] == uuid.UUID("a788c583-4049-5739-b720-c9d272426d52").bytes_le, "GPT disk identity")
            require(fields[10:13] == (table_lba, 128, 128), "GPT entries geometry")
            f.seek(table_lba * SECTOR)
            entries = f.read(128 * 128)
            require(zlib.crc32(entries) == fields[13], "GPT entries CRC")
            tables.append(entries)
        require(tables[0] == tables[1], "GPT copies disagree")
        require(not any(tables[0][4 * 128:]), "unexpected extra partitions")
        for i, (name, start, size, kind, filename) in enumerate(PARTITIONS):
            p = struct.unpack_from("<16s16sQQQ72s", tables[0], i * 128)
            identity = uuid.uuid5(uuid.NAMESPACE_URL, "https://vibeos/mars/" + name)
            require(p[0] == uuid.UUID(kind).bytes_le and p[1] == identity.bytes_le, "partition type/identity")
            require(p[2:5] == (start // SECTOR, (start + size) // SECTOR - 1, 0), "partition bounds/attributes")
            require(p[5].decode("utf-16-le").rstrip("\0") == name, "partition name")
            if artifacts and filename:
                source = artifacts / filename
                require(0 < source.stat().st_size <= size, "payload size")
                f.seek(start)
                with source.open("rb") as original:
                    while chunk := original.read(MIB):
                        require(f.read(len(chunk)) == chunk, "embedded payload mismatch: " + filename)
            if not filename:
                f.seek(start)
                for _ in range(size // MIB):
                    require(not any(f.read(MIB)), "initial data partition must be blank")
    digest_state = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(MIB):
            digest_state.update(chunk)
    digest = digest_state.hexdigest()
    return {"status": "sd-layout-passed", "bytes": IMAGE_BYTES, "sha256": digest,
            "rom_backup_spl_offset": PARTITIONS[0][1], "rom_fallback_crc": ROM_FAILED_CRC,
            "physical_acceptance": False, "ssh_enabled": False,
            "partitions": [{"name": n, "first_sector": s // SECTOR, "sector_count": z // SECTOR}
                           for n, s, z, _, _ in PARTITIONS]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["assemble", "check"])
    parser.add_argument("image", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.operation == "assemble" and not args.artifacts:
        parser.error("assemble requires --artifacts")
    result = assemble(args.image, args.artifacts) if args.operation == "assemble" else inspect(args.image, args.artifacts)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.report:
        args.report.write_text(rendered)
    print(rendered, end="")
